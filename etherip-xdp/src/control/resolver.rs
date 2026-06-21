//! Outer-endpoint resolution: source address selection and next-hop MAC.
//!
//! Resolves the route to the remote tunnel endpoint and, from the same lookup,
//! derives both the outer source address and the next-hop MAC. Every route
//! lookup is constrained to the external interface (`oif`), since encap always
//! egresses there, and carries no `iif` so the kernel routes it as the
//! locally-originated packet it is (`iif lo`). The `oif` constraint is enforced
//! even against the kernel quirk where a `from`+`oif` lookup ignores `oif` (see
//! [`route_get_oif_pinned`]).
//!
//! - **Source address.** When a tunnel configures an explicit `src`, it is used
//!   verbatim (and passed as the route lookup's source hint so policy routing and
//!   source-address selection behave as if the packet originated there). When
//!   `src` is omitted, the kernel's preferred source for the route (`RTA_PREFSRC`,
//!   i.e. its RFC 6724 selection) is adopted; if a sourceless lookup yields none
//!   — which happens when policy routing is source-keyed, so no table is reached
//!   until a source is known — the source is instead seeded from the external
//!   interface's own global addresses, supplying the `from` the source rule needs
//!   to match. If neither resolves, the source is left unresolved and the tunnel
//!   stays pending.
//! - **Next-hop MAC.** The next hop's link-layer address is looked up in the
//!   neighbour table. If the entry is missing or unusable, an active UDP probe is
//!   sent out the external interface to trigger kernel neighbour discovery — so no
//!   manual "ping the peer first" is required.

const PROBE_ATTEMPTS: usize = 10;
const PROBE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Policy for treating the remote endpoint as its own next hop ("on-link") when
/// the route lookup returns no gateway. The on-link assumption is dangerous when
/// the peer is actually reached via a router, so it must be chosen explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NextHopOnLink {
    /// On-link only when the routing table actually returns a gatewayless
    /// (connected) route for the destination. No route -> not resolved. (default)
    #[default]
    Maybe,
    /// Always treat the destination as its own next hop when no gateway is found,
    /// even if no matching route exists.
    Always,
    /// Never assume on-link; a gateway from the route lookup is required.
    Never,
}

/// Decide the next hop for `dst` from a route lookup result and the on-link
/// policy. An explicit IPv6 gateway always wins; otherwise the policy decides
/// whether `dst` itself is the next hop. `None` means "no next hop yet" (the
/// caller leaves the tunnel unresolved and retries on netlink changes). Pure so
/// it can be unit-tested.
pub fn choose_next_hop(
    mode: NextHopOnLink,
    info: Option<crate::control::netlink::RouteInfo>,
    dst: std::net::Ipv6Addr,
) -> Option<std::net::Ipv6Addr> {
    if let Some(crate::control::netlink::RouteInfo {
        gateway: Some(std::net::IpAddr::V6(gw)),
        ..
    }) = info
    {
        return Some(gw);
    }
    match mode {
        NextHopOnLink::Always => Some(dst),
        NextHopOnLink::Never => None,
        // On-link only if the kernel actually returned a route for `dst`
        // (a gatewayless route means it is directly connected).
        NextHopOnLink::Maybe => info.map(|_| dst),
    }
}

fn is_link_local(addr: std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// The resolved outer endpoint state for a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Resolved {
    /// Effective outer source address. `None` when `src` is auto and no preferred
    /// source could be determined yet (no route); the tunnel stays pending.
    pub src: Option<std::net::Ipv6Addr>,
    /// Next-hop link-layer address. `None` when unresolved (e.g. peer unreachable
    /// or no next hop under the on-link policy).
    pub dst_mac: Option<[u8; 6]>,
    /// The chosen next hop: the gateway, or the remote itself when on-link.
    /// `None` when no next hop resolved under the on-link policy.
    pub next_hop: Option<std::net::Ipv6Addr>,
    /// Whether the next hop is the remote endpoint itself (on-link) rather than a
    /// gateway.
    pub on_link: bool,
    /// Observed kernel neighbour state for the next hop, if one was looked up.
    /// Captured regardless of usability (an `incomplete`/`failed` state is itself
    /// useful diagnostic information).
    pub neigh_state: Option<crate::control::netlink::NeighState>,
}

/// Pick the effective outer source address. An explicit configuration always
/// wins; otherwise the route's preferred source (`RTA_PREFSRC`) is adopted, if
/// the kernel returned one for an IPv6 route. Pure so it can be unit-tested.
pub fn choose_src(
    configured: Option<std::net::Ipv6Addr>,
    info: Option<crate::control::netlink::RouteInfo>,
) -> Option<std::net::Ipv6Addr> {
    configured.or_else(|| match info.and_then(|i| i.prefsrc) {
        Some(std::net::IpAddr::V6(v6)) => Some(v6),
        _ => None,
    })
}

/// How hard `resolve_endpoint` should drive neighbour discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Initial bring-up: probe and retry up to `PROBE_ATTEMPTS` to resolve the
    /// MAC synchronously. Used when a tunnel is created or its endpoints change.
    Bringup,
    /// Periodic keep-fresh: read the table and send a single probe so a usable
    /// entry does not decay — XDP egress writes the destination MAC itself and
    /// redirects via the devmap, so it never marks the kernel neighbour used.
    /// Used on the periodic re-resolve tick.
    Refresh,
    /// Reactive: read the table only, never probe. Used when re-resolving in
    /// response to a netlink event, where a probe would just feed back into more
    /// events.
    Passive,
}

/// One route lookup, with its error logged and folded into `None` (a missing
/// route is not fatal — resolution is retried later). The lookup is always
/// constrained to `external_ifindex`, matching the fact that encap egresses
/// there unconditionally.
async fn route_get_oif(
    nl: &crate::control::netlink::Netlink,
    dst: std::net::Ipv6Addr,
    src: Option<std::net::Ipv6Addr>,
    external_ifindex: u32,
) -> Option<crate::control::netlink::RouteInfo> {
    match nl.route_get(dst, src, Some(external_ifindex)).await {
        Ok(info) => info,
        Err(e) => {
            log::debug!("route lookup for {dst} (src {src:?}) failed: {e}");
            None
        }
    }
}

/// Whether a route's output interface (`RTA_OIF`) honours the interface the
/// lookup was pinned to. A `from`+`oif` lookup can silently ignore `oif` when
/// another interface has a better-metric matching route (the kernel takes an
/// input-route path against the global FIB); the returned `RTA_OIF` then points at
/// the wrong link. A route reporting no output interface is treated as honouring
/// the pin — there is nothing contradicting it to act on. Pure so it can be
/// unit-tested.
fn route_honours_oif(route_oif: Option<u32>, external_ifindex: u32) -> bool {
    match route_oif {
        Some(got) => got == external_ifindex,
        None => true,
    }
}

/// Route lookup pinned to `external_ifindex`, working around the kernel quirk
/// where a `from`+`oif` lookup ignores `oif` and resolves the gateway on whichever
/// interface owns the better-metric default — fatal for an encap path that always
/// egresses the uplink. When a source hint is supplied and the result egresses a
/// different interface, the `oif` was ignored, so the lookup is redone sourcelessly
/// (which the kernel routes as locally-originated and honours `oif`). The source
/// hint is dropped only for gateway selection; the caller keeps the configured or
/// preferred source for the outer header.
async fn route_get_oif_pinned(
    nl: &crate::control::netlink::Netlink,
    dst: std::net::Ipv6Addr,
    src: Option<std::net::Ipv6Addr>,
    external_ifindex: u32,
) -> Option<crate::control::netlink::RouteInfo> {
    let info = route_get_oif(nl, dst, src, external_ifindex).await;
    let got_oif = info.and_then(|i| i.oif);
    if src.is_some() && !route_honours_oif(got_oif, external_ifindex) {
        log::debug!(
            "route lookup for {dst} (src {src:?}) egressed ifindex {got_oif:?}, not the uplink \
             {external_ifindex}; redoing sourcelessly to honour oif"
        );
        return route_get_oif(nl, dst, None, external_ifindex).await;
    }
    info
}

/// Resolve the route to `dst` and the effective outer source together, applying
/// policy routing accurately. Returns `(src, route_info)`; either may be `None`
/// when unresolved. The source hint is chosen so source-keyed `ip rule`s match:
///
/// - **Explicit `src`:** used as the hint verbatim, subject to the `oif` pin (see
///   [`route_get_oif_pinned`]): if the `from`+`oif` lookup egresses another
///   interface, the gateway is re-resolved sourcelessly while the configured
///   source is still adopted for the outer header.
/// - **Auto `src`, kernel-selected:** a sourceless lookup lets the kernel apply
///   destination-keyed rules and its own RFC 6724 selection (`RTA_PREFSRC`).
/// - **Auto `src`, seeded:** when that yields no source — the host's policy
///   routing is source-keyed, so a sourceless lookup reaches no usable table —
///   the external interface's own global addresses are tried as the hint, the
///   first that yields a route winning. This supplies the `from` the source rule
///   needs, which the kernel cannot bootstrap on its own.
async fn resolve_route_and_src(
    nl: &crate::control::netlink::Netlink,
    external_ifindex: u32,
    configured_src: Option<std::net::Ipv6Addr>,
    dst: std::net::Ipv6Addr,
) -> (
    Option<std::net::Ipv6Addr>,
    Option<crate::control::netlink::RouteInfo>,
) {
    if configured_src.is_some() {
        let info = route_get_oif_pinned(nl, dst, configured_src, external_ifindex).await;
        return (choose_src(configured_src, info), info);
    }

    let info = route_get_oif(nl, dst, None, external_ifindex).await;
    if let Some(src) = choose_src(None, info) {
        return (Some(src), info);
    }

    match nl.interface_global_addrs(external_ifindex).await {
        Ok(addrs) => {
            for cand in addrs {
                let info = route_get_oif_pinned(nl, dst, Some(cand), external_ifindex).await;
                if info.is_some() {
                    return (Some(cand), info);
                }
            }
        }
        Err(e) => log::warn!(
            "could not list source addresses on ifindex {external_ifindex} to resolve a \
             source for {dst}: {e}"
        ),
    }
    (None, None)
}

/// Resolve a tunnel's outer endpoint: the effective source address and the
/// next-hop MAC. Failure to resolve either is reported as `None` in the
/// respective field (not an error), since resolution is retried on netlink
/// changes and periodically. `probe` controls how hard neighbour discovery is
/// driven (see [`Probe`]).
pub async fn resolve_endpoint(
    nl: &crate::control::netlink::Netlink,
    external_ifindex: u32,
    external_name: &str,
    configured_src: Option<std::net::Ipv6Addr>,
    dst: std::net::Ipv6Addr,
    on_link: NextHopOnLink,
    probe: Probe,
) -> anyhow::Result<Resolved> {
    // Resolve the route and the effective outer source together, applying policy
    // routing accurately (see `resolve_route_and_src`). A failed lookup is not
    // fatal: it leaves the relevant field `None` and resolution is retried on
    // netlink changes.
    let (src, info) = resolve_route_and_src(nl, external_ifindex, configured_src, dst).await;
    let Some(next_hop) = choose_next_hop(on_link, info, dst) else {
        log::debug!(
            "no next hop for {dst} (no gateway and on-link policy is {on_link:?}); \
             leaving unresolved until a route appears"
        );
        return Ok(Resolved {
            src,
            dst_mac: None,
            next_hop: None,
            on_link: false,
            neigh_state: None,
        });
    };
    // On-link iff the chosen next hop is the destination itself (no gateway).
    let on_link = next_hop == dst;

    // Read the neighbour entry once: its state is reported regardless of
    // usability, while only a usable entry yields a MAC for the data path.
    let entry = nl.neighbour_mac(external_ifindex, next_hop).await?;
    let neigh_state = entry.map(|e| e.neigh_state());
    let current = entry
        .filter(crate::control::netlink::NeighEntry::is_usable)
        .map(|e| e.mac);

    match probe {
        // Read only; the caller keeps its last-known MAC on `None`.
        Probe::Passive => Ok(Resolved {
            src,
            dst_mac: current,
            next_hop: Some(next_hop),
            on_link,
            neigh_state,
        }),
        // One probe to keep a usable entry fresh (or nudge a missing one); the
        // periodic cadence retries and the neighbour monitor picks up the result.
        Probe::Refresh => {
            probe_once(external_ifindex, external_name, next_hop).await;
            Ok(Resolved {
                src,
                dst_mac: current,
                next_hop: Some(next_hop),
                on_link,
                neigh_state,
            })
        }
        // Synchronous bring-up: probe and re-check up to PROBE_ATTEMPTS.
        Probe::Bringup => {
            if current.is_some() {
                return Ok(Resolved {
                    src,
                    dst_mac: current,
                    next_hop: Some(next_hop),
                    on_link,
                    neigh_state,
                });
            }
            for _ in 0..PROBE_ATTEMPTS {
                probe_once(external_ifindex, external_name, next_hop).await;
                tokio::time::sleep(PROBE_RETRY_DELAY).await;
                if let Some(entry) = nl.neighbour_mac(external_ifindex, next_hop).await?
                    && entry.is_usable()
                {
                    return Ok(Resolved {
                        src,
                        dst_mac: Some(entry.mac),
                        next_hop: Some(next_hop),
                        on_link,
                        neigh_state: Some(entry.neigh_state()),
                    });
                }
            }
            Ok(Resolved {
                src,
                dst_mac: None,
                next_hop: Some(next_hop),
                on_link,
                neigh_state,
            })
        }
    }
}

/// Run a single ND probe off the async runtime, logging (not failing) on error.
/// `probe_next_hop` does blocking socket syscalls, so it must not run on a tokio
/// worker thread directly.
async fn probe_once(external_ifindex: u32, external_name: &str, next_hop: std::net::Ipv6Addr) {
    let probe_name = external_name.to_string();
    match tokio::task::spawn_blocking(move || {
        probe_next_hop(external_ifindex, &probe_name, next_hop)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::debug!("nd probe to {next_hop} via {external_name} failed: {e}"),
        Err(e) => log::debug!("nd probe task failed to join: {e}"),
    }
}

/// Send a 1-byte UDP datagram to the next hop, bound to the external interface,
/// to trigger kernel neighbour discovery.
///
/// **Blocking:** this issues synchronous `socket`/`setsockopt`/`sendto` syscalls,
/// so callers on the async runtime must run it via `tokio::task::spawn_blocking`.
fn probe_next_hop(
    external_ifindex: u32,
    external_name: &str,
    next_hop: std::net::Ipv6Addr,
) -> anyhow::Result<()> {
    let fd = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Inet6,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::empty(),
        None,
    )?;
    nix::sys::socket::setsockopt(
        &fd,
        nix::sys::socket::sockopt::BindToDevice,
        &std::ffi::OsString::from(external_name),
    )?;
    let scope_id = if is_link_local(next_hop) {
        external_ifindex
    } else {
        0
    };
    // Port 9 (discard); the datagram is never delivered, it only forces ND.
    let addr =
        nix::sys::socket::SockaddrIn6::from(std::net::SocketAddrV6::new(next_hop, 9, 0, scope_id));
    nix::sys::socket::sendto(
        std::os::fd::AsRawFd::as_raw_fd(&fd),
        &[0u8],
        &addr,
        nix::sys::socket::MsgFlags::empty(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw_route(gw: std::net::Ipv6Addr) -> Option<crate::control::netlink::RouteInfo> {
        Some(crate::control::netlink::RouteInfo {
            gateway: Some(std::net::IpAddr::V6(gw)),
            prefsrc: None,
            oif: None,
        })
    }

    fn onlink_route() -> Option<crate::control::netlink::RouteInfo> {
        Some(crate::control::netlink::RouteInfo {
            gateway: None,
            prefsrc: None,
            oif: None,
        })
    }

    fn route_with_prefsrc(
        prefsrc: std::net::Ipv6Addr,
    ) -> Option<crate::control::netlink::RouteInfo> {
        Some(crate::control::netlink::RouteInfo {
            gateway: None,
            prefsrc: Some(std::net::IpAddr::V6(prefsrc)),
            oif: None,
        })
    }

    #[test]
    fn gateway_always_wins_regardless_of_policy() {
        let gw: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        for mode in [
            NextHopOnLink::Maybe,
            NextHopOnLink::Always,
            NextHopOnLink::Never,
        ] {
            assert_eq!(choose_next_hop(mode, gw_route(gw), dst), Some(gw));
        }
    }

    #[test]
    fn maybe_is_onlink_only_with_a_route() {
        let dst: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        // Gatewayless (connected) route -> on-link.
        assert_eq!(
            choose_next_hop(NextHopOnLink::Maybe, onlink_route(), dst),
            Some(dst)
        );
        // No route at all -> not resolved (the key safety property).
        assert_eq!(choose_next_hop(NextHopOnLink::Maybe, None, dst), None);
    }

    #[test]
    fn always_assumes_onlink_even_without_a_route() {
        let dst: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(choose_next_hop(NextHopOnLink::Always, None, dst), Some(dst));
        assert_eq!(
            choose_next_hop(NextHopOnLink::Always, onlink_route(), dst),
            Some(dst)
        );
    }

    #[test]
    fn never_requires_a_gateway() {
        let dst: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(
            choose_next_hop(NextHopOnLink::Never, onlink_route(), dst),
            None
        );
        assert_eq!(choose_next_hop(NextHopOnLink::Never, None, dst), None);
    }

    #[test]
    fn oif_pin_detects_ignored_oif() {
        // The lookup egressed the uplink we pinned to: honoured.
        assert!(route_honours_oif(Some(7), 7));
        // The kernel ignored `oif` and resolved on another interface (the
        // `from`+`oif` quirk): not honoured, so the caller re-resolves sourcelessly.
        assert!(!route_honours_oif(Some(9), 7));
        // No output interface reported: nothing contradicts the pin.
        assert!(route_honours_oif(None, 7));
    }

    #[test]
    fn link_local_detection() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(!is_link_local("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn explicit_src_always_wins() {
        let cfg: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let pref: std::net::Ipv6Addr = "2001:db8::ff".parse().unwrap();
        // Configured source is used verbatim, even when the route offers a
        // different preferred source.
        assert_eq!(choose_src(Some(cfg), route_with_prefsrc(pref)), Some(cfg));
        assert_eq!(choose_src(Some(cfg), None), Some(cfg));
    }

    #[test]
    fn auto_src_adopts_route_prefsrc() {
        let pref: std::net::Ipv6Addr = "2001:db8::ff".parse().unwrap();
        assert_eq!(choose_src(None, route_with_prefsrc(pref)), Some(pref));
        // No route / no preferred source -> unresolved (tunnel stays pending).
        assert_eq!(choose_src(None, onlink_route()), None);
        assert_eq!(choose_src(None, None), None);
    }
}

//! Outer-endpoint resolution: source address selection and next-hop MAC.
//!
//! Resolves the route to the remote tunnel endpoint and, from the same lookup,
//! derives both the outer source address and the next-hop MAC:
//!
//! - **Source address.** When a tunnel configures an explicit `src`, it is used
//!   verbatim (and passed as the route lookup's source hint so policy routing and
//!   source-address selection behave as if the packet originated there). When
//!   `src` is omitted, the kernel's preferred source for the route (`RTA_PREFSRC`,
//!   i.e. its RFC 6724 selection) is adopted instead. If neither is available the
//!   source is left unresolved and the tunnel stays pending.
//! - **Next-hop MAC.** The next hop's link-layer address is looked up in the
//!   neighbour table. If the entry is missing or unusable, an active UDP probe is
//!   sent out the external interface to trigger kernel neighbour discovery — so no
//!   manual "ping the peer first" is required.

const PROBE_ATTEMPTS: usize = 10;
const PROBE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Policy for treating the remote endpoint as its own next hop ("on-link") when
/// the route lookup returns no gateway. The on-link assumption is dangerous when
/// the peer is actually reached via a router, so it must be chosen explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
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
    info: Option<crate::netlink::RouteInfo>,
    dst: std::net::Ipv6Addr,
) -> Option<std::net::Ipv6Addr> {
    if let Some(crate::netlink::RouteInfo {
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
}

/// Pick the effective outer source address. An explicit configuration always
/// wins; otherwise the route's preferred source (`RTA_PREFSRC`) is adopted, if
/// the kernel returned one for an IPv6 route. Pure so it can be unit-tested.
pub fn choose_src(
    configured: Option<std::net::Ipv6Addr>,
    info: Option<crate::netlink::RouteInfo>,
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

/// Resolve a tunnel's outer endpoint: the effective source address and the
/// next-hop MAC. Failure to resolve either is reported as `None` in the
/// respective field (not an error), since resolution is retried on netlink
/// changes and periodically. `probe` controls how hard neighbour discovery is
/// driven (see [`Probe`]).
pub async fn resolve_endpoint(
    nl: &crate::netlink::Netlink,
    external_ifindex: u32,
    external_name: &str,
    configured_src: Option<std::net::Ipv6Addr>,
    dst: std::net::Ipv6Addr,
    on_link: NextHopOnLink,
    probe: Probe,
) -> anyhow::Result<Resolved> {
    // A failed route lookup (e.g. no route / unreachable) is treated as "no
    // route info" so the on-link policy decides; resolution is retried later on
    // netlink changes, so a transient error is not fatal. An explicit source is
    // passed as a hint so policy routing / source selection behave as if the
    // packet originated there; auto source omits the hint so the kernel reports
    // its own preferred source.
    let info = match nl.route_get(dst, configured_src).await {
        Ok(info) => info,
        Err(e) => {
            log::debug!("route lookup for {dst} failed: {e}");
            None
        }
    };
    let src = choose_src(configured_src, info);
    if let Some(oif) = info.and_then(|i| i.oif)
        && oif != external_ifindex
    {
        log::warn!(
            "route to {dst} resolves via ifindex {oif}, not external interface \
             (ifindex {external_ifindex}); encap still egresses the external interface"
        );
    }
    let Some(next_hop) = choose_next_hop(on_link, info, dst) else {
        log::debug!(
            "no next hop for {dst} (no gateway and on-link policy is {on_link:?}); \
             leaving unresolved until a route appears"
        );
        return Ok(Resolved { src, dst_mac: None });
    };

    // Current usable MAC from the neighbour table, if any.
    let current = nl
        .neighbour_mac(external_ifindex, next_hop)
        .await?
        .filter(crate::netlink::NeighEntry::is_usable)
        .map(|e| e.mac);

    match probe {
        // Read only; the caller keeps its last-known MAC on `None`.
        Probe::Passive => Ok(Resolved {
            src,
            dst_mac: current,
        }),
        // One probe to keep a usable entry fresh (or nudge a missing one); the
        // periodic cadence retries and the neighbour monitor picks up the result.
        Probe::Refresh => {
            probe_once(external_ifindex, external_name, next_hop).await;
            Ok(Resolved {
                src,
                dst_mac: current,
            })
        }
        // Synchronous bring-up: probe and re-check up to PROBE_ATTEMPTS.
        Probe::Bringup => {
            if current.is_some() {
                return Ok(Resolved {
                    src,
                    dst_mac: current,
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
                    });
                }
            }
            Ok(Resolved { src, dst_mac: None })
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

    fn gw_route(gw: std::net::Ipv6Addr) -> Option<crate::netlink::RouteInfo> {
        Some(crate::netlink::RouteInfo {
            gateway: Some(std::net::IpAddr::V6(gw)),
            oif: Some(3),
            prefsrc: None,
        })
    }

    fn onlink_route() -> Option<crate::netlink::RouteInfo> {
        Some(crate::netlink::RouteInfo {
            gateway: None,
            oif: Some(3),
            prefsrc: None,
        })
    }

    fn route_with_prefsrc(prefsrc: std::net::Ipv6Addr) -> Option<crate::netlink::RouteInfo> {
        Some(crate::netlink::RouteInfo {
            gateway: None,
            oif: Some(3),
            prefsrc: Some(std::net::IpAddr::V6(prefsrc)),
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

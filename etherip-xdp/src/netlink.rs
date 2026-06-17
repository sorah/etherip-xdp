//! Async netlink (rtnetlink) helpers: link/veth management, MAC/MTU lookup,
//! source-aware route resolution, neighbour lookup, and a change monitor.

use futures_util::stream::TryStreamExt as _;

/// Link identity used when building tunnel config.
#[derive(Debug, Clone, Copy)]
pub struct LinkInfo {
    pub index: u32,
    pub mac: [u8; 6],
    pub mtu: u32,
}

/// Result of a route lookup.
#[derive(Debug, Clone, Copy)]
pub struct RouteInfo {
    /// Gateway (next hop), or `None` when the destination is on-link.
    pub gateway: Option<std::net::IpAddr>,
    /// Preferred source address the kernel would use for this route
    /// (`RTA_PREFSRC`), i.e. the result of its RFC 6724 source selection. Used to
    /// auto-pick the outer source when a tunnel does not configure one.
    pub prefsrc: Option<std::net::IpAddr>,
}

/// A resolved neighbour entry.
#[derive(Debug, Clone, Copy)]
pub struct NeighEntry {
    pub mac: [u8; 6],
    pub state: rtnetlink::packet_route::neighbour::NeighbourState,
}

impl NeighEntry {
    /// Whether the entry's link-layer address is currently usable.
    pub fn is_usable(&self) -> bool {
        matches!(
            self.state,
            rtnetlink::packet_route::neighbour::NeighbourState::Reachable
                | rtnetlink::packet_route::neighbour::NeighbourState::Stale
                | rtnetlink::packet_route::neighbour::NeighbourState::Delay
                | rtnetlink::packet_route::neighbour::NeighbourState::Probe
                | rtnetlink::packet_route::neighbour::NeighbourState::Permanent
        )
    }
}

/// A thin wrapper around an rtnetlink `Handle` whose connection task is driven
/// on the tokio runtime.
pub struct Netlink {
    handle: rtnetlink::Handle,
}

fn mac6(bytes: &[u8]) -> Option<[u8; 6]> {
    if bytes.len() >= 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&bytes[..6]);
        Some(m)
    } else {
        None
    }
}

impl Netlink {
    /// Open a netlink connection and spawn its driver task.
    pub fn connect() -> anyhow::Result<Self> {
        let (connection, handle, _rx) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Netlink { handle })
    }

    /// Look up a link's index, MAC, and MTU by name.
    pub async fn link_info(&self, name: &str) -> anyhow::Result<Option<LinkInfo>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        let Some(msg) = links.try_next().await? else {
            return Ok(None);
        };
        let index = msg.header.index;
        let mut mac = [0u8; 6];
        let mut mtu = 0u32;
        for attr in msg.attributes {
            match attr {
                rtnetlink::packet_route::link::LinkAttribute::Address(bytes) => {
                    if let Some(m) = mac6(&bytes) {
                        mac = m;
                    }
                }
                rtnetlink::packet_route::link::LinkAttribute::Mtu(m) => mtu = m,
                _ => {}
            }
        }
        Ok(Some(LinkInfo { index, mac, mtu }))
    }

    /// Return a link's index by name, or `None` if it doesn't exist.
    pub async fn index_of(&self, name: &str) -> anyhow::Result<Option<u32>> {
        Ok(self.link_info(name).await?.map(|i| i.index))
    }

    /// Create a veth pair (`name` <-> `peer`).
    pub async fn create_veth(&self, name: &str, peer: &str) -> anyhow::Result<()> {
        self.handle
            .link()
            .add(rtnetlink::LinkVeth::new(name, peer).build())
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("create veth {name}/{peer}: {e}"))
    }

    /// Delete a link by name; a no-op if it doesn't exist.
    pub async fn delete_link(&self, name: &str) -> anyhow::Result<()> {
        let Some(index) = self.index_of(name).await? else {
            return Ok(());
        };
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("delete link {name}: {e}"))
    }

    /// Set a link's MTU and bring it up.
    pub async fn set_mtu_up(&self, index: u32, mtu: u32) -> anyhow::Result<()> {
        self.handle
            .link()
            .set(
                rtnetlink::LinkUnspec::new_with_index(index)
                    .mtu(mtu)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("set mtu/up on ifindex {index}: {e}"))
    }

    /// Resolve the route to `dst`. Passing `src` makes the kernel apply policy
    /// routing rules and source-address selection as if the packet originated
    /// from that address (the "ip rule ... from <src>" case). Passing `oif`
    /// constrains the lookup to that output interface, matching the fact that
    /// encap always egresses the external interface; the request carries no
    /// `iif`, so the kernel routes it as the locally-originated (`iif lo`) packet
    /// it is.
    pub async fn route_get(
        &self,
        dst: std::net::Ipv6Addr,
        src: Option<std::net::Ipv6Addr>,
        oif: Option<u32>,
    ) -> anyhow::Result<Option<RouteInfo>> {
        let mut builder = rtnetlink::RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix(dst, 128);
        if let Some(src) = src {
            builder = builder.source_prefix(src, 128);
        }
        if let Some(oif) = oif {
            builder = builder.output_interface(oif);
        }
        let mut routes = self.handle.route().get(builder.build()).execute();
        let Some(route) = routes.try_next().await? else {
            return Ok(None);
        };
        let mut gateway = None;
        let mut prefsrc = None;
        for attr in route.attributes {
            match attr {
                rtnetlink::packet_route::route::RouteAttribute::Gateway(addr) => {
                    gateway = route_addr_to_ip(&addr);
                }
                rtnetlink::packet_route::route::RouteAttribute::PrefSource(addr) => {
                    prefsrc = route_addr_to_ip(&addr);
                }
                _ => {}
            }
        }
        Ok(Some(RouteInfo { gateway, prefsrc }))
    }

    /// Whether `addr` is currently assigned to any interface on the host. Used to
    /// warn when an explicitly-configured outer source is not (or no longer) a
    /// local address; the source is still used regardless (operator intent).
    pub async fn is_local_address(&self, addr: std::net::Ipv6Addr) -> anyhow::Result<bool> {
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_address_filter(std::net::IpAddr::V6(addr))
            .execute();
        Ok(addrs.try_next().await?.is_some())
    }

    /// List the global-scope ("universe") IPv6 addresses assigned to `ifindex`.
    /// Used to seed the outer source for an auto-`src` tunnel when the kernel
    /// cannot select one itself — on a host whose policy routing is source-keyed,
    /// a route lookup with no source matches no usable table, so the source must
    /// be supplied up front. Link-local and host-scoped addresses are excluded by
    /// the scope filter, leaving only addresses usable as an outer source.
    pub async fn interface_global_addrs(
        &self,
        ifindex: u32,
    ) -> anyhow::Result<Vec<std::net::Ipv6Addr>> {
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(ifindex)
            .execute();
        let mut out = Vec::new();
        while let Some(msg) = addrs.try_next().await? {
            if msg.header.scope != rtnetlink::packet_route::address::AddressScope::Universe {
                continue;
            }
            for attr in &msg.attributes {
                if let rtnetlink::packet_route::address::AddressAttribute::Address(
                    std::net::IpAddr::V6(v6),
                ) = attr
                {
                    out.push(*v6);
                }
            }
        }
        Ok(out)
    }

    /// Find the neighbour (link-layer) entry for `target` on interface
    /// `ifindex`. There is no kernel-side ifindex filter, so we dump and match.
    pub async fn neighbour_mac(
        &self,
        ifindex: u32,
        target: std::net::Ipv6Addr,
    ) -> anyhow::Result<Option<NeighEntry>> {
        let mut neighbours = self
            .handle
            .neighbours()
            .get()
            .set_family(rtnetlink::IpVersion::V6)
            .execute();
        while let Some(msg) = neighbours.try_next().await? {
            if msg.header.ifindex != ifindex {
                continue;
            }
            let mut dst = None;
            let mut mac = None;
            for attr in &msg.attributes {
                match attr {
                    rtnetlink::packet_route::neighbour::NeighbourAttribute::Destination(
                        rtnetlink::packet_route::neighbour::NeighbourAddress::Inet6(ip),
                    ) => dst = Some(*ip),
                    rtnetlink::packet_route::neighbour::NeighbourAttribute::LinkLayerAddress(
                        ll,
                    ) => {
                        mac = mac6(ll);
                    }
                    _ => {}
                }
            }
            if dst == Some(target)
                && let Some(mac) = mac
            {
                return Ok(Some(NeighEntry {
                    mac,
                    state: msg.header.state,
                }));
            }
        }
        Ok(None)
    }
}

fn route_addr_to_ip(
    addr: &rtnetlink::packet_route::route::RouteAddress,
) -> Option<std::net::IpAddr> {
    match addr {
        rtnetlink::packet_route::route::RouteAddress::Inet(v4) => Some(std::net::IpAddr::V4(*v4)),
        rtnetlink::packet_route::route::RouteAddress::Inet6(v6) => Some(std::net::IpAddr::V6(*v6)),
        _ => None,
    }
}

/// Spawn a netlink monitor for neighbour, route, and link changes. Returns a
/// receiver that gets a `()` (coalesced) whenever something relevant changes,
/// so the caller can re-resolve next hops.
pub fn spawn_change_monitor() -> anyhow::Result<tokio::sync::mpsc::Receiver<()>> {
    let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(&[
        rtnetlink::MulticastGroup::Neigh,
        rtnetlink::MulticastGroup::Ipv4Route,
        rtnetlink::MulticastGroup::Ipv6Route,
        rtnetlink::MulticastGroup::Link,
        // Local address add/remove: re-resolution re-derives the auto-selected
        // outer source, so it must wake when an underlay address changes.
        rtnetlink::MulticastGroup::Ipv4Ifaddr,
        rtnetlink::MulticastGroup::Ipv6Ifaddr,
    ])
    .map_err(|e| anyhow::anyhow!("open netlink monitor: {e}"))?;
    tokio::spawn(connection);

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        use futures_util::stream::StreamExt as _;
        while let Some((message, _addr)) = messages.next().await {
            if is_relevant(&message.payload) {
                // try_send coalesces bursts: a full single-slot channel already
                // signals "re-resolve pending".
                let _ = tx.try_send(());
            }
        }
    });
    Ok(rx)
}

fn is_relevant(
    payload: &rtnetlink::packet_core::NetlinkPayload<rtnetlink::packet_route::RouteNetlinkMessage>,
) -> bool {
    let rtnetlink::packet_core::NetlinkPayload::InnerMessage(inner) = payload else {
        return false;
    };
    matches!(
        inner,
        rtnetlink::packet_route::RouteNetlinkMessage::NewNeighbour(_)
            | rtnetlink::packet_route::RouteNetlinkMessage::DelNeighbour(_)
            | rtnetlink::packet_route::RouteNetlinkMessage::NewRoute(_)
            | rtnetlink::packet_route::RouteNetlinkMessage::DelRoute(_)
            | rtnetlink::packet_route::RouteNetlinkMessage::NewLink(_)
            | rtnetlink::packet_route::RouteNetlinkMessage::DelLink(_)
            | rtnetlink::packet_route::RouteNetlinkMessage::NewAddress(_)
            | rtnetlink::packet_route::RouteNetlinkMessage::DelAddress(_)
    )
}

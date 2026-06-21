//! Bridge types between the daemon's tokio loop (which owns the tunnel manager
//! and the aya `Bpf` handle) and the embedded varlink server task.
//!
//! These are plain owned snapshots — no aya/borrowed handles, no varlink wire
//! types — so they cross the actor channel freely and keep the daemon's
//! `Manager` confined to the main loop.

/// A request from the varlink server task to the main loop. The loop services
/// it synchronously (it owns `&mut Manager`) and replies over the oneshot.
pub enum ControlRequest {
    /// Build and return a full status snapshot of this daemon.
    Snapshot(tokio::sync::oneshot::Sender<StatusSnapshot>),
}

/// A full status snapshot of one daemon: its external interface, the
/// daemon-global counters, and every tunnel.
pub struct StatusSnapshot {
    pub external: ExternalSnapshot,
    /// `(name, value)` pairs from `COUNTER_NAMES` zipped with the summed
    /// per-CPU debug counters.
    pub counters: Vec<(&'static str, u64)>,
    pub tunnels: Vec<TunnelSnapshot>,
}

/// The shared external (uplink) interface this daemon drives.
pub struct ExternalSnapshot {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub mtu: u32,
}

/// Lifecycle state of a tunnel's data path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Outer source not yet resolved; data path inert.
    Pending,
    /// Source resolved and installed, but next-hop MAC unresolved; frames drop.
    NoNextHop,
    /// Fully resolved and forwarding.
    Up,
}

/// One tunnel's configuration and live runtime state.
pub struct TunnelSnapshot {
    pub name: String,
    pub config_path: Option<std::path::PathBuf>,
    pub configured_local: Option<std::net::Ipv6Addr>,
    pub remote: std::net::Ipv6Addr,
    pub effective_src: Option<std::net::Ipv6Addr>,
    pub state: TunnelState,
    pub tunnel_mtu: i32,
    pub mtu_override: Option<u32>,
    pub mac_policy: &'static str,
    pub tunnel_mac: [u8; 6],
    pub next_hop_on_link_policy: &'static str,
    pub mss_clamp_ipv4: u16,
    pub mss_clamp_ipv6: u16,
    pub peer_ifindex: u32,
    /// The resolved next hop (gateway, or the remote itself when on-link);
    /// `None` while no next hop has resolved.
    pub next_hop: Option<std::net::Ipv6Addr>,
    /// Whether the next hop is the remote endpoint itself (on-link).
    pub next_hop_on_link: bool,
    /// Resolved next-hop link-layer address; `None` when unresolved.
    pub next_hop_mac: Option<[u8; 6]>,
    /// Observed kernel neighbour state for the next hop.
    pub neigh_state: Option<&'static str>,
}

/// Derive the data-path state from the resolved source and the next-hop MAC.
/// A zero `dst_mac` after a source has resolved means the next hop is still
/// unresolved (the data path drops frames addressed to the null MAC).
pub fn derive_state(effective_src: Option<std::net::Ipv6Addr>, dst_mac: [u8; 6]) -> TunnelState {
    match effective_src {
        None => TunnelState::Pending,
        Some(_) if dst_mac == [0u8; 6] => TunnelState::NoNextHop,
        Some(_) => TunnelState::Up,
    }
}

#[cfg(test)]
mod tests {
    fn ip() -> std::net::Ipv6Addr {
        "2001:db8::1".parse().unwrap()
    }

    #[test]
    fn pending_without_source() {
        assert_eq!(
            super::derive_state(None, [0; 6]),
            super::TunnelState::Pending
        );
        assert_eq!(
            super::derive_state(None, [1, 2, 3, 4, 5, 6]),
            super::TunnelState::Pending
        );
    }

    #[test]
    fn no_next_hop_when_source_but_zero_mac() {
        assert_eq!(
            super::derive_state(Some(ip()), [0; 6]),
            super::TunnelState::NoNextHop
        );
    }

    #[test]
    fn up_when_source_and_mac() {
        assert_eq!(
            super::derive_state(Some(ip()), [0xde, 0xad, 0xbe, 0xef, 0, 1]),
            super::TunnelState::Up
        );
    }
}

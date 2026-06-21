//! Human-readable rendering of the management reply for `etheripctl`. Pure
//! functions over the generated wire types so they are unit-testable without a
//! live daemon.

// `generated` is referenced throughout; a module alias keeps the wire-type
// paths readable.
use std::fmt::Write as _;

use crate::manage::generated;

/// Render the `list` view: every interface with its tunnel table and non-zero
/// counters.
pub fn render_interfaces(interfaces: &[generated::InterfaceStatus]) -> String {
    if interfaces.is_empty() {
        return "no etherip-xdp interfaces found\n".to_string();
    }
    let mut out = String::new();
    for (i, iface) in interfaces.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = writeln!(
            out,
            "interface {} (ifindex {}, mac {}, mtu {})",
            iface.external.name, iface.external.ifindex, iface.external.mac, iface.external.mtu
        );
        if iface.tunnels.is_empty() {
            let _ = writeln!(out, "  (no tunnels)");
        } else {
            let _ = writeln!(
                out,
                "  {:<14} {:<12} {:<26} {:<26} NEXT-HOP",
                "TUNNEL", "STATE", "REMOTE", "SOURCE"
            );
            for t in &iface.tunnels {
                let _ = writeln!(
                    out,
                    "  {:<14} {:<12} {:<26} {:<26} {}",
                    t.name,
                    state_str(&t.state),
                    t.remote,
                    t.effectiveSource.as_deref().unwrap_or("-"),
                    next_hop_summary(&t.nextHop),
                );
            }
        }
        let counters = render_counters(&iface.counters);
        if !counters.is_empty() {
            let _ = writeln!(out, "  counters: {counters}");
        }
    }
    out
}

/// Render the `show`/`status` view: full detail for one tunnel plus the owning
/// interface's (interface-wide) counters.
pub fn render_detail(iface: &generated::InterfaceStatus, t: &generated::Tunnel) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "tunnel {}", t.name);
    let _ = writeln!(
        out,
        "  interface:        {} (ifindex {}, mac {}, mtu {})",
        iface.external.name, iface.external.ifindex, iface.external.mac, iface.external.mtu
    );
    let _ = writeln!(out, "  state:            {}", state_str(&t.state));
    let _ = writeln!(
        out,
        "  config file:      {}",
        t.configPath.as_deref().unwrap_or("(none)")
    );
    let _ = writeln!(out, "  remote:           {}", t.remote);
    let _ = writeln!(
        out,
        "  configured local: {}",
        t.configuredLocal.as_deref().unwrap_or("auto")
    );
    let _ = writeln!(
        out,
        "  effective source: {}",
        t.effectiveSource.as_deref().unwrap_or("(pending)")
    );
    let mtu_override = match t.mtuOverride {
        Some(m) => format!(" (override {m})"),
        None => String::new(),
    };
    let _ = writeln!(out, "  mtu:              {}{}", t.mtu, mtu_override);
    let _ = writeln!(
        out,
        "  mac:              {} (policy {})",
        t.mac,
        mac_policy_str(&t.macPolicy)
    );
    let _ = writeln!(
        out,
        "  mss clamp:        ipv4 {} ipv6 {}",
        mss_str(t.mssClampIpv4),
        mss_str(t.mssClampIpv6)
    );
    let _ = writeln!(out, "  next hop:         {}", next_hop_detail(t));
    let _ = writeln!(out, "  peer ifindex:     {}", t.peerIfindex);
    let counters = render_counters(&iface.counters);
    if !counters.is_empty() {
        let _ = writeln!(
            out,
            "  interface counters ({}): {counters}",
            iface.external.name
        );
    }
    out
}

fn state_str(s: &generated::TunnelState) -> &'static str {
    match s {
        generated::TunnelState::up => "up",
        generated::TunnelState::pending => "pending",
        generated::TunnelState::noNextHop => "no-next-hop",
    }
}

fn mac_policy_str(p: &generated::MacPolicy) -> &'static str {
    match p {
        generated::MacPolicy::auto => "auto",
        generated::MacPolicy::inherit => "inherit",
        generated::MacPolicy::explicit => "explicit",
    }
}

fn next_hop_on_link_policy_str(p: &generated::NextHopOnLinkPolicy) -> &'static str {
    match p {
        generated::NextHopOnLinkPolicy::maybe => "maybe",
        generated::NextHopOnLinkPolicy::always => "always",
        generated::NextHopOnLinkPolicy::never => "never",
    }
}

/// `0` means clamping disabled (matches the eBPF convention).
fn mss_str(v: i64) -> String {
    if v == 0 {
        "disabled".to_string()
    } else {
        v.to_string()
    }
}

/// Compact next-hop column for the list view.
fn next_hop_summary(nh: &generated::NextHop) -> String {
    let Some(addr) = &nh.address else {
        return "-".to_string();
    };
    let mut s = addr.clone();
    if nh.onLink {
        s.push_str(" (on-link)");
    }
    match (&nh.mac, &nh.neighbourState) {
        (Some(mac), Some(state)) => {
            let _ = write!(s, " mac {mac} [{state}]");
        }
        (Some(mac), None) => {
            let _ = write!(s, " mac {mac}");
        }
        _ => s.push_str(" (mac unresolved)"),
    }
    s
}

/// Verbose next-hop line for the detail view, including the configured policy.
fn next_hop_detail(t: &generated::Tunnel) -> String {
    let policy = next_hop_on_link_policy_str(&t.nextHopOnLinkPolicy);
    match &t.nextHop.address {
        None => format!("unresolved (on-link policy {policy})"),
        Some(addr) => {
            let kind = if t.nextHop.onLink {
                "on-link"
            } else {
                "gateway"
            };
            let mac = t.nextHop.mac.as_deref().unwrap_or("unresolved");
            let nstate = t.nextHop.neighbourState.as_deref().unwrap_or("-");
            format!("{addr} ({kind}, on-link policy {policy}) mac {mac} [{nstate}]")
        }
    }
}

/// Non-zero counters as `name=value` joined by spaces.
fn render_counters(counters: &[generated::Counter]) -> String {
    counters
        .iter()
        .filter(|c| c.value != 0)
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use crate::manage::generated;

    fn next_hop(
        addr: Option<&str>,
        on_link: bool,
        mac: Option<&str>,
        st: Option<&str>,
    ) -> generated::NextHop {
        generated::NextHop {
            address: addr.map(str::to_string),
            onLink: on_link,
            mac: mac.map(str::to_string),
            neighbourState: st.map(str::to_string),
        }
    }

    fn tunnel(name: &str, state: generated::TunnelState) -> generated::Tunnel {
        generated::Tunnel {
            name: name.to_string(),
            configPath: Some(format!("/etc/etherip-xdp/interfaces.d/eth1/{name}.json")),
            configuredLocal: None,
            remote: "2001:db8::2".to_string(),
            effectiveSource: Some("2001:db8::1".to_string()),
            state,
            mtu: 1444,
            mtuOverride: None,
            macPolicy: generated::MacPolicy::auto,
            mac: "02:00:00:00:00:09".to_string(),
            nextHopOnLinkPolicy: generated::NextHopOnLinkPolicy::maybe,
            nextHop: next_hop(
                Some("fe80::1"),
                false,
                Some("aa:bb:cc:dd:ee:ff"),
                Some("reachable"),
            ),
            mssClampIpv4: 1404,
            mssClampIpv6: 0,
            peerIfindex: 7,
        }
    }

    fn iface() -> generated::InterfaceStatus {
        generated::InterfaceStatus {
            external: generated::ExternalInterface {
                name: "eth1".to_string(),
                ifindex: 3,
                mac: "02:00:00:00:00:01".to_string(),
                mtu: 1500,
            },
            counters: vec![
                generated::Counter {
                    name: "encap_redirect".to_string(),
                    value: 9,
                },
                generated::Counter {
                    name: "encap_adjust_fail".to_string(),
                    value: 0,
                },
            ],
            tunnels: vec![tunnel("office", generated::TunnelState::up)],
        }
    }

    #[test]
    fn list_shows_interface_tunnels_and_nonzero_counters() {
        let out = super::render_interfaces(&[iface()]);
        assert!(out.contains("interface eth1 (ifindex 3, mac 02:00:00:00:00:01, mtu 1500)"));
        assert!(out.contains("office"));
        assert!(out.contains("up"));
        assert!(out.contains("fe80::1"));
        assert!(out.contains("[reachable]"));
        // Non-zero counter shown, zero one hidden.
        assert!(out.contains("encap_redirect=9"));
        assert!(!out.contains("encap_adjust_fail"));
    }

    #[test]
    fn list_empty_is_friendly() {
        assert_eq!(
            super::render_interfaces(&[]),
            "no etherip-xdp interfaces found\n"
        );
    }

    #[test]
    fn detail_shows_config_path_and_next_hop() {
        let iface = iface();
        let out = super::render_detail(&iface, &iface.tunnels[0]);
        assert!(out.contains("tunnel office"));
        assert!(out.contains("config file:      /etc/etherip-xdp/interfaces.d/eth1/office.json"));
        assert!(out.contains("gateway"));
        assert!(out.contains("mac aa:bb:cc:dd:ee:ff [reachable]"));
        assert!(out.contains("ipv6 disabled")); // 0 -> disabled
        assert!(out.contains("interface counters (eth1)"));
    }

    #[test]
    fn detail_pending_next_hop_is_unresolved() {
        let mut iface = iface();
        iface.tunnels[0].nextHop = next_hop(None, false, None, None);
        iface.tunnels[0].state = generated::TunnelState::pending;
        let out = super::render_detail(&iface, &iface.tunnels[0]);
        assert!(out.contains("next hop:         unresolved (on-link policy maybe)"));
    }
}

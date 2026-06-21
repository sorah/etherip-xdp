//! The per-daemon embedded varlink server. It implements the management
//! interface by asking the main loop (which owns the tunnel manager) for a
//! status snapshot over the actor channel, then maps that snapshot onto the
//! generated wire types.

/// Implements `co.0w0.etheripxdp.Management` for one daemon. Holds only the
/// channel sender to the main loop, so it stays `Send + Sync` and never touches
/// the (non-`Send`-shared) aya handles directly.
pub struct EtheripImpl {
    tx: tokio::sync::mpsc::Sender<crate::control::types::ControlRequest>,
}

impl EtheripImpl {
    pub fn new(tx: tokio::sync::mpsc::Sender<crate::control::types::ControlRequest>) -> Self {
        EtheripImpl { tx }
    }
}

#[async_trait::async_trait]
impl crate::manage::generated::VarlinkInterface for EtheripImpl {
    async fn list(
        &self,
        call: &mut dyn crate::manage::generated::Call_List,
    ) -> varlink::Result<()> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .tx
            .send(crate::control::types::ControlRequest::Snapshot(reply_tx))
            .await
            .is_err()
        {
            // Only happens while the daemon is shutting down (loop gone).
            log::warn!("control: main loop unavailable; replying empty status");
            return call.reply(Vec::new());
        }
        match reply_rx.await {
            Ok(snapshot) => call.reply(vec![interface_status(&snapshot)]),
            Err(_) => {
                log::warn!("control: status snapshot dropped; replying empty status");
                call.reply(Vec::new())
            }
        }
    }
}

/// Run the embedded varlink server for `device` until `stop` is set. Adopts a
/// systemd-passed socket (the `varlink`-named fd) when socket-activated;
/// otherwise self-binds the per-device socket under the runtime directory.
pub async fn serve(
    device: String,
    tx: tokio::sync::mpsc::Sender<crate::control::types::ControlRequest>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let address = crate::manage::discovery::socket_address(&device);

    // Self-bind fallback only: under socket activation systemd owns the socket
    // file and passes its fd, so the path must not be pre-created or removed.
    if std::env::var_os("LISTEN_FDS").is_none() {
        let path = crate::manage::discovery::socket_path(&device);
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            log::error!("control: create {}: {e}", parent.display());
        }
        let _ = std::fs::remove_file(&path);
    }

    let handler = std::sync::Arc::new(crate::manage::generated::new(std::sync::Arc::new(
        EtheripImpl::new(tx),
    )));
    let service = std::sync::Arc::new(varlink::AsyncVarlinkService::new(
        "co.0w0",
        "etherip-xdp",
        env!("CARGO_PKG_VERSION"),
        "https://github.com/sorah/etherip-xdp",
        vec![handler],
    ));
    let config = varlink::ListenAsyncConfig {
        idle_timeout: std::time::Duration::from_secs(1),
        stop_listening: Some(stop),
    };
    if let Err(e) = varlink::listen_async(service, address.clone(), &config).await {
        log::error!("control: varlink listener on {address} exited: {e:#}");
    }
}

/// Map an owned status snapshot onto the generated wire type.
fn interface_status(
    snapshot: &crate::control::types::StatusSnapshot,
) -> crate::manage::generated::InterfaceStatus {
    crate::manage::generated::InterfaceStatus {
        external: crate::manage::generated::ExternalInterface {
            name: snapshot.external.name.clone(),
            ifindex: snapshot.external.index.into(),
            mac: fmt_mac(&snapshot.external.mac),
            mtu: snapshot.external.mtu.into(),
        },
        counters: snapshot
            .counters
            .iter()
            .map(|(name, value)| crate::manage::generated::Counter {
                name: (*name).to_string(),
                value: *value as i64,
            })
            .collect(),
        tunnels: snapshot.tunnels.iter().map(tunnel).collect(),
    }
}

fn tunnel(t: &crate::control::types::TunnelSnapshot) -> crate::manage::generated::Tunnel {
    crate::manage::generated::Tunnel {
        name: t.name.clone(),
        configPath: t.config_path.as_ref().map(|p| p.display().to_string()),
        configuredLocal: t.configured_local.map(|a| a.to_string()),
        remote: t.remote.to_string(),
        effectiveSource: t.effective_src.map(|a| a.to_string()),
        state: tunnel_state(t.state),
        mtu: t.tunnel_mtu.into(),
        mtuOverride: t.mtu_override.map(i64::from),
        macPolicy: mac_policy(t.mac_policy),
        mac: fmt_mac(&t.tunnel_mac),
        nextHopOnLinkPolicy: next_hop_on_link_policy(t.next_hop_on_link_policy),
        nextHop: crate::manage::generated::NextHop {
            address: t.next_hop.map(|a| a.to_string()),
            onLink: t.next_hop_on_link,
            mac: t.next_hop_mac.as_ref().map(fmt_mac),
            neighbourState: t.neigh_state.map(str::to_string),
        },
        mssClampIpv4: t.mss_clamp_ipv4.into(),
        mssClampIpv6: t.mss_clamp_ipv6.into(),
        peerIfindex: t.peer_ifindex.into(),
    }
}

fn tunnel_state(s: crate::control::types::TunnelState) -> crate::manage::generated::TunnelState {
    match s {
        crate::control::types::TunnelState::Pending => {
            crate::manage::generated::TunnelState::pending
        }
        crate::control::types::TunnelState::NoNextHop => {
            crate::manage::generated::TunnelState::noNextHop
        }
        crate::control::types::TunnelState::Up => crate::manage::generated::TunnelState::up,
    }
}

fn mac_policy(s: &str) -> crate::manage::generated::MacPolicy {
    match s {
        "inherit" => crate::manage::generated::MacPolicy::inherit,
        "explicit" => crate::manage::generated::MacPolicy::explicit,
        _ => crate::manage::generated::MacPolicy::auto,
    }
}

fn next_hop_on_link_policy(s: &str) -> crate::manage::generated::NextHopOnLinkPolicy {
    match s {
        "always" => crate::manage::generated::NextHopOnLinkPolicy::always,
        "never" => crate::manage::generated::NextHopOnLinkPolicy::never,
        _ => crate::manage::generated::NextHopOnLinkPolicy::maybe,
    }
}

/// Format a MAC as lowercase colon-separated octets.
fn fmt_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

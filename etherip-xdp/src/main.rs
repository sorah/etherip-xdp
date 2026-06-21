//! XDP EtherIP (RFC 3378) tunnel daemon.
//!
//! One process owns one external (uplink) network device and every tunnel
//! configured on it (`/etc/etherip-xdp/interfaces.d/<device>/*.json`), so it maps
//! cleanly onto a templated `etherip-xdp@<device>.service`. SIGHUP reloads the
//! config gracefully; SIGINT/SIGTERM tear everything down.
//!
//! This binary is a thin entry point; the control plane lives in
//! [`etherip_xdp::control`].

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    etherip_xdp::control::daemon::run().await
}

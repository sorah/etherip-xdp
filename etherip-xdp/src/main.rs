//! XDP EtherIP (RFC 3378) tunnel daemon.
//!
//! One process owns one external (uplink) network device and every tunnel
//! configured on it (`/etc/etherip-xdp/interfaces.d/<device>/*.json`), so it maps
//! cleanly onto a templated `etherip-xdp@<device>.service`. SIGHUP reloads the
//! config gracefully; SIGINT/SIGTERM tear everything down.
//!
//! This binary is a thin entry point; the control plane lives in
//! [`etherip_xdp::control`].

fn main() -> anyhow::Result<()> {
    // SAFETY: no threads exist yet; must run before the runtime so nothing (the
    // varlink activation listener in particular) sees fd-store entries in
    // LISTEN_FDS.
    let inherited = unsafe { etherip_xdp::control::systemd::take_inherited_fds()? };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(etherip_xdp::control::daemon::run(inherited))
}

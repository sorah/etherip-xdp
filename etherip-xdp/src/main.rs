//! XDP EtherIP (RFC 3378) tunnel daemon.
//!
//! One process owns one external (uplink) network device and every tunnel
//! configured on it (`/etc/etherip-xdp/<device>.d/*.json`), so it maps cleanly
//! onto a templated `etherip-xdp@<device>.service`. SIGHUP reloads the config dir
//! gracefully; SIGINT/SIGTERM tear everything down.
#![deny(clippy::undocumented_unsafe_blocks)]

mod bpf;
mod config;
mod netlink;
mod offload;
mod resolver;
mod tunnel;

const RERESOLVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const MONITOR_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(200);

#[derive(clap::Parser)]
#[command(version, about = "XDP-based EtherIP tunnel (RFC 3378)")]
struct Opt {
    /// External (uplink) network device facing the tunnel peers.
    device: String,

    /// Directory of per-tunnel JSON configs (default /etc/etherip-xdp/<device>.d).
    #[arg(long)]
    config_dir: Option<std::path::PathBuf>,

    /// When to treat the remote endpoint as its own next hop ("on-link") if the
    /// route lookup returns no gateway: `maybe` (only when a connected route
    /// exists), `always`, or `never` (require a gateway).
    #[arg(long, value_enum, default_value = "maybe")]
    next_hop_on_link: resolver::NextHopOnLink,
}

fn bump_memlock_rlimit() {
    // No-op on kernels >= 5.11 (memcg accounting), but required on older kernels
    // or aya's BPF load fails with EPERM/ENOMEM.
    if let Err(e) = nix::sys::resource::setrlimit(
        nix::sys::resource::Resource::RLIMIT_MEMLOCK,
        nix::libc::RLIM_INFINITY,
        nix::libc::RLIM_INFINITY,
    ) {
        log::debug!("could not raise RLIMIT_MEMLOCK: {e}");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let opt = <Opt as clap::Parser>::parse();
    let config_dir = opt
        .config_dir
        .unwrap_or_else(|| std::path::PathBuf::from(format!("/etc/etherip-xdp/{}.d", opt.device)));

    bump_memlock_rlimit();

    let mut manager = tunnel::Manager::start(opt.device, config_dir, opt.next_hop_on_link).await?;
    log::info!("etherip-xdp ready; SIGHUP to reload, SIGINT/SIGTERM to stop");

    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut monitor = netlink::spawn_change_monitor()?;
    let mut ticker = tokio::time::interval(RERESOLVE_INTERVAL);
    ticker.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            _ = sighup.recv() => {
                log::info!("SIGHUP: reloading config");
                if let Err(e) = manager.reload().await {
                    log::error!("reload failed: {e:#}");
                }
            }
            _ = sigterm.recv() => { log::info!("SIGTERM: shutting down"); break; }
            _ = sigint.recv() => { log::info!("SIGINT: shutting down"); break; }
            Some(_) = monitor.recv() => {
                // Coalesce a burst of neighbour/route changes before re-resolving.
                tokio::time::sleep(MONITOR_DEBOUNCE).await;
                while monitor.try_recv().is_ok() {}
                // Reactive: react to the observed change; don't probe (a probe
                // would just generate more neighbour events).
                manager.reresolve_all(false).await;
            }
            _ = ticker.tick() => {
                // Periodic: send a keep-fresh probe so usable neighbour entries
                // don't decay (XDP egress never marks them used).
                manager.reresolve_all(true).await;
            }
        }
    }

    manager.dump_counters();
    manager.cleanup().await;
    Ok(())
}

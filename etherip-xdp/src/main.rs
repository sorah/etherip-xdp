//! XDP EtherIP (RFC 3378) tunnel daemon.
//!
//! One process owns one external (uplink) network device and every tunnel
//! configured on it (`/etc/etherip-xdp/interfaces.d/<device>/*.json`), so it maps
//! cleanly onto a templated `etherip-xdp@<device>.service`. SIGHUP reloads the
//! config gracefully; SIGINT/SIGTERM tear everything down.
#![deny(clippy::undocumented_unsafe_blocks)]

mod bpf;
mod config;
mod netlink;
mod netns;
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

    /// Directory of per-tunnel JSON configs, used verbatim (the
    /// `interfaces.d/<device>` layout is not applied). Repeatable: earlier
    /// directories take precedence, and a file name found in one shadows the
    /// same name in later directories (systemd drop-in semantics). Mutually
    /// exclusive with --config-root.
    #[arg(long, conflicts_with = "config_root")]
    config_dir: Vec<std::path::PathBuf>,

    /// Config root replacing the default search roots; the effective directory
    /// is `<root>/interfaces.d/<device>`. Repeatable with the same precedence
    /// and shadowing rules as --config-dir. Defaults to the systemd
    /// `$RUNTIME_DIRECTORY` directories (when set) then `/etc/etherip-xdp`.
    #[arg(long)]
    config_root: Vec<std::path::PathBuf>,

    /// Keep each tunnel's internal `<name>-xdp` veth peer in the host namespace
    /// instead of hiding it in a daemon-private anonymous network namespace. By
    /// default the peer is hidden so it does not appear in `ip link`; pass this to
    /// expose it (e.g. for debugging or on kernels without cross-namespace XDP
    /// redirect).
    #[arg(long)]
    disable_veth_peer_netns: bool,
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

/// Resolve the ordered list of directories to search for tunnel configs.
///
/// `--config-dir` values are used verbatim. Otherwise each root (the
/// `--config-root` values, or the defaults when none are given) is expanded to
/// `<root>/interfaces.d/<device>`. Precedence follows list order: earlier
/// directories win on a file-name collision (see [`config::load_dirs`]).
fn resolve_config_dirs(
    device: &str,
    config_dir: Vec<std::path::PathBuf>,
    config_root: Vec<std::path::PathBuf>,
    runtime_directory: Option<&std::ffi::OsStr>,
) -> Vec<std::path::PathBuf> {
    if !config_dir.is_empty() {
        return config_dir;
    }
    let roots = if config_root.is_empty() {
        default_config_roots(runtime_directory)
    } else {
        config_root
    };
    roots
        .into_iter()
        .map(|root| root.join("interfaces.d").join(device))
        .collect()
}

/// Default config roots, in precedence order: the systemd runtime directories
/// ahead of the system-wide `/etc/etherip-xdp`, mirroring systemd's `/run` >
/// `/etc` drop-in precedence. `RuntimeDirectory=` exports `RUNTIME_DIRECTORY` as
/// a colon-separated list of the granted `/run/<name>` directories; each is a
/// root verbatim (it is already the service's own directory, so no extra suffix
/// is appended).
fn default_config_roots(runtime_directory: Option<&std::ffi::OsStr>) -> Vec<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut roots = Vec::new();
    if let Some(dirs) = runtime_directory {
        for dir in dirs
            .as_bytes()
            .split(|&b| b == b':')
            .filter(|s| !s.is_empty())
        {
            roots.push(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(dir)));
        }
    }
    roots.push(std::path::PathBuf::from("/etc/etherip-xdp"));
    roots
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let opt = <Opt as clap::Parser>::parse();
    let config_dirs = resolve_config_dirs(
        &opt.device,
        opt.config_dir,
        opt.config_root,
        std::env::var_os("RUNTIME_DIRECTORY").as_deref(),
    );

    bump_memlock_rlimit();

    let mut manager =
        tunnel::Manager::start(opt.device, config_dirs, !opt.disable_veth_peer_netns).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pb(s: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(s)
    }

    #[test]
    fn default_roots_prepend_runtime_directory_when_set() {
        // RUNTIME_DIRECTORY is the service's own /run dir, used verbatim as a root.
        assert_eq!(
            resolve_config_dirs(
                "eth1",
                vec![],
                vec![],
                Some(std::ffi::OsStr::new("/run/etherip-xdp"))
            ),
            vec![
                pb("/run/etherip-xdp/interfaces.d/eth1"),
                pb("/etc/etherip-xdp/interfaces.d/eth1"),
            ]
        );
    }

    #[test]
    fn default_roots_split_runtime_directory_colon_list() {
        // systemd exports multiple RuntimeDirectory= entries colon-separated.
        assert_eq!(
            resolve_config_dirs(
                "eth1",
                vec![],
                vec![],
                Some(std::ffi::OsStr::new(
                    "/run/etherip-xdp:/run/host/etherip-xdp"
                )),
            ),
            vec![
                pb("/run/etherip-xdp/interfaces.d/eth1"),
                pb("/run/host/etherip-xdp/interfaces.d/eth1"),
                pb("/etc/etherip-xdp/interfaces.d/eth1"),
            ]
        );
    }

    #[test]
    fn default_roots_without_runtime_directory_are_etc_only() {
        // Unset and empty both fall back to the system root alone.
        assert_eq!(
            resolve_config_dirs("eth1", vec![], vec![], None),
            vec![pb("/etc/etherip-xdp/interfaces.d/eth1")]
        );
        assert_eq!(
            resolve_config_dirs("eth1", vec![], vec![], Some(std::ffi::OsStr::new(""))),
            vec![pb("/etc/etherip-xdp/interfaces.d/eth1")]
        );
    }

    #[test]
    fn config_root_replaces_defaults_and_expands_per_device() {
        assert_eq!(
            resolve_config_dirs(
                "wan0",
                vec![],
                vec![pb("/srv/a"), pb("/srv/b")],
                Some(std::ffi::OsStr::new("/run/etherip-xdp")),
            ),
            vec![
                pb("/srv/a/interfaces.d/wan0"),
                pb("/srv/b/interfaces.d/wan0"),
            ]
        );
    }

    #[test]
    fn config_dir_is_used_verbatim_and_wins_over_root() {
        // --config-dir bypasses the interfaces.d/<device> layout entirely.
        assert_eq!(
            resolve_config_dirs(
                "eth1",
                vec![pb("/tmp/x"), pb("/tmp/y")],
                vec![pb("/ignored")],
                Some(std::ffi::OsStr::new("/run/etherip-xdp")),
            ),
            vec![pb("/tmp/x"), pb("/tmp/y")]
        );
    }
}

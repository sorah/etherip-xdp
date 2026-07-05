//! etherip-xdp end-to-end integration scenario.
//!
//! Run on each of the two peers (VMs in `vm` mode, network namespaces in
//! `local` mode) with `--role server|client`. Both roles do the same thing:
//!
//! 1. (VM only) `modprobe veth` so the daemon can create veth pairs.
//! 2. Bring the uplink up with its outer IPv6 address.
//! 3. Write a one-tunnel config and launch the real `etherip-xdp` daemon on the
//!    uplink, pointing at the peer's outer address.
//! 4. Wait for the daemon's user-facing tunnel interface, give it an inner IPv4
//!    address.
//! 5. Drive traffic through the tunnel: ICMP echo (both directions) and a TCP
//!    echo exchange (server accepts, client connects), asserting it round-trips.
//!
//! Exit status 0 means the tunnel works; `init` translates that to
//! `init: success` for the host orchestrator. A global timeout guards against a
//! broken tunnel hanging the VM forever.
#![deny(clippy::undocumented_unsafe_blocks)]

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Role {
    Server,
    Client,
}

/// What to do for the TCP phase of the test.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum TcpMode {
    /// Full echo exchange (server echoes, client sends + verifies). Used for the
    /// symmetric Linux↔Linux test.
    Echo,
    /// Connect-only (client connects then closes; server accepts then closes).
    /// Used for interop against a peer that only `listen`s (e.g. FreeBSD `nc`).
    Connect,
    /// Skip the TCP phase entirely (ICMP only).
    Skip,
}

#[derive(clap::Parser)]
#[command(about = "etherip-xdp end-to-end integration scenario")]
struct Opt {
    /// Which side of the tunnel this instance plays.
    #[arg(long, value_enum)]
    role: Role,

    /// Uplink (outer) interface carrying encapsulated traffic.
    #[arg(long, default_value = "eth0")]
    uplink: String,

    /// Outer IPv6 address to assign to the uplink, with prefix (e.g. fd00::1/64).
    /// Defaults by role: server fd00::1/64, client fd00::2/64.
    #[arg(long)]
    uplink_cidr: Option<String>,

    /// Peer's outer IPv6 address (the tunnel remote). Defaults to the other role.
    #[arg(long)]
    peer_uplink: Option<std::net::Ipv6Addr>,

    /// Tunnel / user-facing interface name the daemon will create.
    #[arg(long, default_value = "etx0")]
    tunnel_name: String,

    /// Inner IPv4 address for the tunnel interface, with prefix (e.g. 10.0.0.1/24).
    /// Defaults by role: server 10.0.0.1/24, client 10.0.0.2/24.
    #[arg(long)]
    inner_cidr: Option<String>,

    /// Peer's inner IPv4 address (the ping / TCP target). Defaults to the other role.
    #[arg(long)]
    inner_peer: Option<std::net::Ipv4Addr>,

    /// Path to the `etherip-xdp` daemon binary.
    #[arg(long, default_value = "/sbin/etherip-xdp")]
    daemon_path: std::path::PathBuf,

    /// Directory to write the tunnel config into.
    #[arg(long, default_value = "/tmp/etherip-xdp-it")]
    config_dir: std::path::PathBuf,

    /// Load the `veth` module before starting (needed in the VM; the host
    /// already has it in `local` mode).
    #[arg(long, default_value_t = false)]
    load_veth: bool,

    /// Overall deadline for the whole scenario.
    #[arg(long, default_value_t = 90)]
    timeout_secs: u64,

    /// TCP port for the echo exchange.
    #[arg(long, default_value_t = 7878)]
    port: u16,

    /// TCP phase behaviour (echo for Linux↔Linux, connect for interop peers).
    #[arg(long, value_enum, default_value = "echo")]
    tcp: TcpMode,

    /// Run the daemon under the in-process sandbox (non-root uid + ambient caps +
    /// no-new-privs) mirroring packaging/etherip-xdp@.service.
    #[arg(long, default_value_t = false)]
    sandbox: bool,

    /// Exercise graceful-restart: SIGUSR2 handoff, crash + respawn, the
    /// skip-identical and atomic-swap paths, and a config edit applied across
    /// a restart — all under a continuity pinger asserting the data plane
    /// never stops.
    #[arg(long, default_value_t = false)]
    restart_scenarios: bool,

    /// Configure the tunnel endpoints as routed /112 prefixes instead of the
    /// uplink addresses: per-flow outer addresses (ECMP entropy) on encap,
    /// prefix-masked demux on decap. Adds a route to the peer's tunnel prefix
    /// via its uplink address, mirroring a real routed-prefix deployment.
    #[arg(long, default_value_t = false)]
    outer_prefix: bool,

    /// Run the underlay over an 802.1Q VLAN: create a `<uplink>.<vlan>`
    /// subinterface, put the outer address there, and set `"vlan": N` in the
    /// tunnel config, so XDP tags/strips on the physical uplink and the daemon
    /// resolves the next hop on the subinterface.
    #[arg(long)]
    vlan: Option<u16>,
}

mod minisystemd;
mod sandbox;

const PAYLOAD: &[u8] = b"etherip-xdp integration payload; the quick brown fox jumps; 0123456789";

/// Tunnel endpoint prefixes for `--outer-prefix` mode. Routed (via the peer's
/// uplink address), never assigned to an interface.
const TUNNEL_PREFIX_SERVER: &str = "fd00:a::/112";
const TUNNEL_PREFIX_CLIENT: &str = "fd00:b::/112";

/// (own, peer's) tunnel prefix by role.
fn tunnel_prefixes(role: Role) -> (&'static str, &'static str) {
    match role {
        Role::Server => (TUNNEL_PREFIX_SERVER, TUNNEL_PREFIX_CLIENT),
        Role::Client => (TUNNEL_PREFIX_CLIENT, TUNNEL_PREFIX_SERVER),
    }
}

fn main() {
    // Wrapper subcommands, intercepted before clap and before any threads
    // start: `__sandbox <daemon> [args...]` drops privileges and execs the
    // daemon (see sandbox.rs); `__listenfds [--fd N:NAME]... [--sandbox]
    // <daemon> [args...]` first rebuilds a systemd-style activation block from
    // inherited fds (see minisystemd.rs).
    let mut raw = std::env::args();
    let _ = raw.next();
    match raw.next().as_deref() {
        Some("__sandbox") => {
            if let Err(e) = sandbox::exec(&raw.collect::<Vec<_>>()) {
                eprintln!("sandbox: {e:#}");
                std::process::exit(127);
            }
            unreachable!();
        }
        Some("__listenfds") => {
            if let Err(e) = minisystemd::exec_with_listen_fds(&raw.collect::<Vec<_>>()) {
                eprintln!("listenfds: {e:#}");
                std::process::exit(127);
            }
            unreachable!();
        }
        _ => {}
    }

    let opt = <Opt as clap::Parser>::parse();
    let role = match opt.role {
        Role::Server => "server",
        Role::Client => "client",
    };

    // Hard watchdog: if anything blocks uninterruptibly past the deadline, kill
    // the process so `init` reports failure rather than hanging the VM.
    let watchdog = std::time::Duration::from_secs(opt.timeout_secs + 20);
    std::thread::spawn(move || {
        std::thread::sleep(watchdog);
        eprintln!("scenario watchdog fired after {watchdog:?}; aborting");
        std::process::exit(1);
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let deadline = std::time::Duration::from_secs(opt.timeout_secs);
    match rt.block_on(async { tokio::time::timeout(deadline, run(&opt)).await }) {
        Ok(Ok(())) => {
            println!("etherip-xdp e2e OK (role={role})");
            std::process::exit(0);
        }
        Ok(Err(e)) => {
            eprintln!("etherip-xdp e2e FAILED (role={role}): {e:#}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("etherip-xdp e2e TIMEOUT (role={role}) after {deadline:?}");
            std::process::exit(1);
        }
    }
}

async fn run(opt: &Opt) -> anyhow::Result<()> {
    // Per-role defaults so the common case needs only `--role` on the cmdline.
    // server is .1, client is .2 on both the outer (fd00::/64) and inner
    // (10.0.0.0/24) subnets.
    let (uplink_cidr, peer_uplink, inner_cidr, inner_peer) = match opt.role {
        Role::Server => ("fd00::1/64", "fd00::2", "10.0.0.1/24", "10.0.0.2"),
        Role::Client => ("fd00::2/64", "fd00::1", "10.0.0.2/24", "10.0.0.1"),
    };
    let uplink_cidr = opt.uplink_cidr.as_deref().unwrap_or(uplink_cidr);
    let peer_uplink = match opt.peer_uplink {
        Some(a) => a,
        None => peer_uplink.parse().expect("valid default peer_uplink"),
    };
    let inner_peer = match opt.inner_peer {
        Some(a) => a,
        None => inner_peer.parse().expect("valid default inner_peer"),
    };
    let inner_cidr = opt.inner_cidr.as_deref().unwrap_or(inner_cidr);

    let (uplink_ip, uplink_prefix) = parse_cidr_v6(uplink_cidr)?;
    let (inner_ip, inner_prefix) = parse_cidr_v4(inner_cidr)?;

    if opt.load_veth {
        // The uplink driver (virtio_net) is built-in on some kernels (e.g. 6.8)
        // but a module on others (e.g. 6.5); modprobe is a no-op when built-in,
        // and dependency-aware (pulls net_failover/failover) when modular. veth
        // is always a module and is needed for the daemon's veth pairs.
        modprobe("virtio_net")?;
        modprobe("veth")?;
    }
    if opt.vlan.is_some() {
        // The 802.1Q subinterface needs the `8021q` module (built-in on the
        // host in `local` mode, a no-op then; shipped in the VM initramfs).
        modprobe("8021q")?;
    }

    let (connection, handle, _rx) =
        rtnetlink::new_connection().map_err(|e| anyhow::anyhow!("netlink: {e}"))?;
    tokio::spawn(connection);

    log("bringing up uplink");
    let uplink_idx =
        wait_for_link(&handle, &opt.uplink, std::time::Duration::from_secs(20)).await?;
    set_up(&handle, uplink_idx).await?;

    // The outer address lives on the physical uplink normally, but on the VLAN
    // subinterface when the underlay is tagged — that is where the daemon
    // resolves the next hop (XDP still attaches to, and redirects out of, the
    // physical uplink).
    match opt.vlan {
        None => {
            add_address(
                &handle,
                uplink_idx,
                std::net::IpAddr::V6(uplink_ip),
                uplink_prefix,
            )
            .await?;
        }
        Some(vid) => {
            // Decap is VLAN-agnostic by default, so no RX-VLAN-offload change is
            // needed; the veth/virtio transports don't strip in-band tags anyway.
            let vlan_name = format!("{}.{vid}", opt.uplink);
            log(&format!(
                "creating VLAN subinterface {vlan_name} (id {vid}) on {}",
                opt.uplink
            ));
            add_vlan(&handle, &vlan_name, uplink_idx, vid).await?;
            let vlan_idx =
                wait_for_link(&handle, &vlan_name, std::time::Duration::from_secs(20)).await?;
            add_address(
                &handle,
                vlan_idx,
                std::net::IpAddr::V6(uplink_ip),
                uplink_prefix,
            )
            .await?;
            set_up(&handle, vlan_idx).await?;
        }
    }

    if opt.outer_prefix {
        // The peer's tunnel prefix is routed via its uplink address, as a real
        // routed-prefix deployment would; the per-flow addresses inside it are
        // never assigned or ND-resolved.
        let (_, peer_prefix) = tunnel_prefixes(opt.role);
        let (dst, plen) = parse_cidr_v6(peer_prefix)?;
        log("routing the peer's tunnel prefix via its uplink address");
        add_route_v6(&handle, dst, plen, peer_uplink).await?;
    }

    log("writing tunnel config and launching etherip-xdp");
    write_config(opt, uplink_ip, peer_uplink, None)?;
    prepare_bpffs_root(opt)?;
    let notify = minisystemd::NotifyServer::spawn(&opt.config_dir.join("notify.sock"))?;
    // Seed a bogus "netns" fd-store entry: the daemon must consume it out of
    // the activation block (so varlink fd routing stays intact) and release
    // the store slot, whatever it makes of the descriptor itself.
    let bogus_netns = nix::unistd::pipe().map_err(|e| anyhow::anyhow!("pipe: {e}"))?;
    let mut daemon = spawn_daemon(
        opt,
        notify.path(),
        &[(std::os::fd::AsRawFd::as_raw_fd(&bogus_netns.0), "netns")],
        0,
    )?;
    drop(bogus_netns);

    // The daemon creates the user-facing tunnel interface during start-up.
    log("waiting for tunnel interface");
    let tunnel_idx = wait_for_link(
        &handle,
        &opt.tunnel_name,
        std::time::Duration::from_secs(30),
    )
    .await?;

    log("waiting for the daemon to release the bogus stored netns fd");
    let released = notify
        .wait_removed("netns", std::time::Duration::from_secs(10))
        .await;
    anyhow::ensure!(released, "daemon did not FDSTOREREMOVE the bogus netns fd");

    // The data-plane maps and links must be pinned while the daemon runs (the
    // bpffs root above stands in for the packaged tmpfiles.d entry). The pass
    // link is attached only after endpoint resolution, which may probe for a
    // while — wait rather than sample.
    let pin_dir = bpffs_instance_dir(opt);
    let mut pins: Vec<std::path::PathBuf> = ["ENCAP_CONFIG", "DECAP_CONFIG", "ETHERIP_STATE"]
        .iter()
        .map(|m| pin_dir.join("maps").join(m))
        .collect();
    pins.push(pin_dir.join("links/decap"));
    pins.push(pin_dir.join(format!("links/tunnels/{}/encap", opt.tunnel_name)));
    pins.push(pin_dir.join(format!("links/tunnels/{}/pass", opt.tunnel_name)));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    for pin in &pins {
        while !pin.exists() {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "pin {} did not appear",
                pin.display()
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    log("map and link pins present");
    add_address(
        &handle,
        tunnel_idx,
        std::net::IpAddr::V4(inner_ip),
        inner_prefix,
    )
    .await?;
    set_up(&handle, tunnel_idx).await?;

    let result = async {
        // ICMP first: proves the tunnel end to end and seeds ARP for the
        // restart phases' continuity pinger.
        log("pinging peer inner address through the tunnel");
        tokio::task::spawn_blocking(move || ping(inner_peer, std::time::Duration::from_secs(45)))
            .await
            .map_err(|e| anyhow::anyhow!("ping task join: {e}"))??;
        log("ping OK");

        if opt.restart_scenarios {
            restart_phases(
                opt,
                &notify,
                &mut daemon,
                &handle,
                uplink_ip,
                peer_uplink,
                inner_peer,
            )
            .await?;
        }

        drive_tcp(opt, inner_ip, inner_peer).await
    }
    .await;
    if result.is_err() {
        dump_daemon_logs(opt);
    }

    // Stop the daemon (graceful: it tears down veths and dumps counters).
    terminate(&mut daemon).await;

    // A SIGTERM stop is a full teardown: the pins must be gone, and the netns
    // fd released from the store, with it. Skipped when the scenario already
    // failed — a failure can legitimately leave the daemon stopped mid-phase
    // with the pins deliberately in place, and this check must not shadow the
    // real error.
    let teardown = async {
        let pin_dir = bpffs_instance_dir(opt);
        anyhow::ensure!(
            !pin_dir.exists(),
            "pin dir {} survived SIGTERM teardown",
            pin_dir.display()
        );
        if opt.restart_scenarios {
            anyhow::ensure!(
                notify
                    .wait_unstored("netns", std::time::Duration::from_secs(5))
                    .await,
                "netns fd still in the store after SIGTERM teardown"
            );
        }
        log("pins removed on teardown");
        Ok(())
    };
    match result {
        Ok(()) => teardown.await,
        Err(e) => Err(e),
    }
}

/// The daemon's per-uplink pin directory (`control/bpf.rs::PinPaths`).
fn bpffs_instance_dir(opt: &Opt) -> std::path::PathBuf {
    std::path::PathBuf::from("/sys/fs/bpf/etherip-xdp").join(&opt.uplink)
}

/// Stand-in for the packaged tmpfiles.d entry: the pin root, group-writable
/// for the sandboxed daemon (setgid so its subdirectories inherit the group).
fn prepare_bpffs_root(opt: &Opt) -> anyhow::Result<()> {
    // `ip netns exec` (local mode) runs the scenario in a fresh mount
    // namespace with /sys re-mounted, losing the host's bpffs sub-mount —
    // mount one. It is private to the scenario and the daemons it spawns,
    // which is exactly the lifetime pin persistence needs here. The VM init
    // already mounts bpffs; leave a mounted one alone.
    let is_bpffs = nix::sys::statfs::statfs("/sys/fs/bpf")
        .map(|s| s.filesystem_type() == nix::sys::statfs::BPF_FS_MAGIC)
        .unwrap_or(false);
    if !is_bpffs {
        nix::mount::mount(
            Some("bpf"),
            "/sys/fs/bpf",
            Some("bpf"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| anyhow::anyhow!("mount bpffs at /sys/fs/bpf: {e}"))?;
    }
    let root = std::path::Path::new("/sys/fs/bpf/etherip-xdp");
    std::fs::create_dir_all(root).map_err(|e| anyhow::anyhow!("create {}: {e}", root.display()))?;
    if opt.sandbox {
        nix::unistd::chown(
            root,
            None,
            Some(nix::unistd::Gid::from_raw(sandbox::DAEMON_GID)),
        )
        .map_err(|e| anyhow::anyhow!("chown {}: {e}", root.display()))?;
        std::fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o2770))
            .map_err(|e| anyhow::anyhow!("chmod {}: {e}", root.display()))?;
    }
    Ok(())
}

/// TCP through the tunnel. Echo mode (Linux↔Linux) verifies a full
/// round-trip; connect mode (interop) only proves the handshake traverses the
/// tunnel — enough to exercise the inner-TCP path against a plain listener.
async fn drive_tcp(
    opt: &Opt,
    inner_ip: std::net::Ipv4Addr,
    inner_peer: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    let addr = std::net::SocketAddrV4::new(inner_ip, opt.port);
    let peer_addr = std::net::SocketAddrV4::new(inner_peer, opt.port);
    match (opt.tcp, opt.role) {
        (TcpMode::Skip, _) => Ok(()),
        (TcpMode::Echo, Role::Server) => tcp_echo_server(addr).await,
        (TcpMode::Echo, Role::Client) => tcp_echo_client(peer_addr).await,
        (TcpMode::Connect, Role::Server) => tcp_accept_once(addr).await,
        (TcpMode::Connect, Role::Client) => tcp_connect_once(peer_addr).await,
    }
}

// ---- graceful-restart phases ----

/// Drive the daemon through every restart flavor while a continuity pinger
/// asserts the data plane never pauses: SIGUSR2 handoff with the identical
/// object (skip-swap), a tampered object digest (atomic BPF_LINK_UPDATE swap),
/// a SIGKILL crash, and a config edit applied across a restart.
#[allow(clippy::too_many_arguments)]
async fn restart_phases(
    opt: &Opt,
    notify: &minisystemd::NotifyServer,
    daemon: &mut tokio::process::Child,
    handle: &rtnetlink::Handle,
    uplink_ip: std::net::Ipv6Addr,
    peer_uplink: std::net::Ipv6Addr,
    inner_peer: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        notify
            .wait_stored("netns", std::time::Duration::from_secs(10))
            .await,
        "daemon did not park its netns fd in the store"
    );

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pinger = {
        let stop = stop.clone();
        tokio::task::spawn_blocking(move || {
            ping_continuity(inner_peer, &stop, std::time::Duration::from_millis(1500))
        })
    };

    let phases = async {
        let adopted = format!("tunnel {}: adopted running data plane", opt.tunnel_name);
        // Signal only after the daemon's signal loop is up (deterministic exit codes).
        const READY: &str = "etherip-xdp ready";
        wait_daemon_log(opt, 0, READY, 20).await?;

        log("restart phase 1: SIGUSR2 handoff, identical object (skip swap)");
        stop_daemon(daemon, nix::sys::signal::Signal::SIGUSR2).await?;
        *daemon = respawn_daemon(opt, notify, 1)?;
        wait_daemon_log(opt, 1, "eBPF object unchanged", 20).await?;
        wait_daemon_log(opt, 1, "adopted the uplink decap link", 20).await?;
        wait_daemon_log(opt, 1, &adopted, 20).await?;
        wait_daemon_log(opt, 1, READY, 20).await?;

        log("restart phase 2: SIGUSR2 handoff, changed object digest (atomic swap)");
        stop_daemon(daemon, nix::sys::signal::Signal::SIGUSR2).await?;
        tamper_pinned_digest(opt)?;
        *daemon = respawn_daemon(opt, notify, 2)?;
        wait_daemon_log(opt, 2, "updating attached programs atomically", 20).await?;
        wait_daemon_log(opt, 2, &adopted, 20).await?;
        wait_daemon_log(opt, 2, READY, 20).await?;

        log("restart phase 3: crash (SIGKILL) and respawn");
        stop_daemon(daemon, nix::sys::signal::Signal::SIGKILL).await?;
        *daemon = respawn_daemon(opt, notify, 3)?;
        wait_daemon_log(opt, 3, &adopted, 20).await?;
        wait_daemon_log(opt, 3, READY, 20).await?;

        log("restart phase 4: config edited while down (mtu applied on adopt)");
        stop_daemon(daemon, nix::sys::signal::Signal::SIGUSR2).await?;
        write_config(opt, uplink_ip, peer_uplink, Some(RESTART_MTU))?;
        *daemon = respawn_daemon(opt, notify, 4)?;
        wait_daemon_log(opt, 4, &adopted, 20).await?;
        wait_daemon_log(opt, 4, READY, 20).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if link_mtu(handle, &opt.tunnel_name).await? == Some(RESTART_MTU) {
                break;
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "tunnel MTU was not updated to {RESTART_MTU} after the restart"
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        anyhow::Ok(())
    }
    .await;

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let continuity = pinger
        .await
        .map_err(|e| anyhow::anyhow!("pinger task join: {e}"))?;
    phases?;
    continuity?;
    log("restart phases OK (no data-plane gap observed)");
    Ok(())
}

/// Inner MTU applied through a config edit in restart phase 4.
const RESTART_MTU: u32 = 1300;

async fn stop_daemon(
    daemon: &mut tokio::process::Child,
    signal: nix::sys::signal::Signal,
) -> anyhow::Result<()> {
    let pid = daemon
        .id()
        .ok_or_else(|| anyhow::anyhow!("daemon already exited"))?;
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), signal)
        .map_err(|e| anyhow::anyhow!("kill({signal}): {e}"))?;
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), daemon.wait())
        .await
        .map_err(|_| anyhow::anyhow!("daemon did not exit on {signal}"))?
        .map_err(|e| anyhow::anyhow!("wait: {e}"))?;
    if signal != nix::sys::signal::Signal::SIGKILL {
        anyhow::ensure!(status.success(), "daemon exited with {status} on {signal}");
    }
    Ok(())
}

/// Respawn the daemon with the fd-store contents passed back, as systemd
/// would on `Restart=`.
fn respawn_daemon(
    opt: &Opt,
    notify: &minisystemd::NotifyServer,
    generation: usize,
) -> anyhow::Result<tokio::process::Child> {
    let mut fds: Vec<(std::os::fd::RawFd, &str)> = Vec::new();
    if let Some(fd) = notify.stored_fd("netns") {
        fds.push((fd, "netns"));
    }
    spawn_daemon(opt, notify.path(), &fds, generation)
}

fn daemon_log_path(opt: &Opt, generation: usize) -> std::path::PathBuf {
    opt.config_dir.join(format!("daemon-{generation}.log"))
}

/// Wait until the daemon's (stderr) log contains `needle`.
async fn wait_daemon_log(
    opt: &Opt,
    generation: usize,
    needle: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let path = daemon_log_path(opt, generation);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if std::fs::read_to_string(&path)
            .unwrap_or_default()
            .contains(needle)
        {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "daemon log {} did not contain {needle:?}",
            path.display()
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Print every captured daemon log (called on scenario failure).
fn dump_daemon_logs(opt: &Opt) {
    for generation in 0..=8 {
        let path = daemon_log_path(opt, generation);
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            println!("[daemon-{generation}] {line}");
        }
    }
}

/// Flip one byte of the pinned state record's object digest so the next
/// daemon start takes the changed-object path (atomic program swap) even
/// though the binary is identical.
fn tamper_pinned_digest(opt: &Opt) -> anyhow::Result<()> {
    let path = bpffs_instance_dir(opt).join("maps/ETHERIP_STATE");
    let data = aya::maps::MapData::from_pin(&path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
    // The record is opaque bytes here; the digest lives past the two header
    // words and the 32-byte version field (see etherip-xdp-common PinnedState).
    let mut array: aya::maps::Array<_, [u8; 72]> =
        aya::maps::Array::try_from(aya::maps::Map::Array(data))
            .map_err(|e| anyhow::anyhow!("state map shape: {e}"))?;
    let mut record = array.get(&0, 0).map_err(|e| anyhow::anyhow!("read: {e}"))?;
    record[40] ^= 0xff;
    array
        .set(0, record, 0)
        .map_err(|e| anyhow::anyhow!("write: {e}"))?;
    Ok(())
}

async fn link_mtu(handle: &rtnetlink::Handle, name: &str) -> anyhow::Result<Option<u32>> {
    use futures_util::stream::TryStreamExt as _;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await {
        Ok(Some(msg)) => Ok(msg.attributes.iter().find_map(|attr| match attr {
            rtnetlink::packet_route::link::LinkAttribute::Mtu(m) => Some(*m),
            _ => None,
        })),
        _ => Ok(None),
    }
}

/// Blocking continuity pinger: one echo every ~100 ms; errors if replies stop
/// for longer than `max_gap` (the data plane must keep flowing through every
/// restart flavor).
fn ping_continuity(
    target: std::net::Ipv4Addr,
    stop: &std::sync::atomic::AtomicBool,
    max_gap: std::time::Duration,
) -> anyhow::Result<()> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .map_err(|e| anyhow::anyhow!("open ICMP socket: {e}"))?;
    sock.set_read_timeout(Some(std::time::Duration::from_millis(100)))
        .map_err(|e| anyhow::anyhow!("set timeout: {e}"))?;
    let dest = socket2::SockAddr::from(std::net::SocketAddrV4::new(target, 0));
    // Distinct id so replies can't be confused with the setup ping's.
    let id: u16 = ((std::process::id() & 0xffff) as u16) ^ 0x5aa5;
    let mut last_reply = std::time::Instant::now();
    let mut seq: u16 = 0;
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let packet = icmp_echo_request(id, seq);
        sock.send_to(&packet, &dest)
            .map_err(|e| anyhow::anyhow!("send ICMP: {e}"))?;
        if recv_echo_reply(&sock, id) {
            last_reply = std::time::Instant::now();
        }
        let gap = last_reply.elapsed();
        if gap > max_gap {
            anyhow::bail!("data-plane gap: no echo reply for {gap:?} (seq {seq})");
        }
        seq = seq.wrapping_add(1);
    }
    Ok(())
}

/// Connect to the peer and immediately close — success proves the TCP handshake
/// (SYN/SYN-ACK) traversed the tunnel in both directions.
async fn tcp_connect_once(peer: std::net::SocketAddrV4) -> anyhow::Result<()> {
    log(&format!("TCP client: connecting to {peer}"));
    let _sock = connect_retry(peer, std::time::Duration::from_secs(30)).await?;
    log("TCP client: connected");
    Ok(())
}

/// Accept one connection then close (peer for connect mode).
async fn tcp_accept_once(addr: std::net::SocketAddrV4) -> anyhow::Result<()> {
    log("TCP server: listening (accept-only)");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    let (_sock, peer) = listener
        .accept()
        .await
        .map_err(|e| anyhow::anyhow!("accept: {e}"))?;
    log(&format!("TCP server: accepted {peer}"));
    Ok(())
}

async fn tcp_echo_server(addr: std::net::SocketAddrV4) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    log("TCP server: listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    let (mut sock, peer) = listener
        .accept()
        .await
        .map_err(|e| anyhow::anyhow!("accept: {e}"))?;
    log(&format!("TCP server: accepted {peer}"));
    // The client half-closes after sending, so reading to EOF yields the payload.
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf)
        .await
        .map_err(|e| anyhow::anyhow!("read: {e}"))?;
    sock.write_all(&buf)
        .await
        .map_err(|e| anyhow::anyhow!("echo write: {e}"))?;
    sock.shutdown()
        .await
        .map_err(|e| anyhow::anyhow!("shutdown: {e}"))?;
    // Wait for the client to close after it has verified the echo, so neither
    // side powers off mid-exchange.
    let _ = sock.read(&mut [0u8; 1]).await;
    log("TCP server: echoed payload");
    Ok(())
}

async fn tcp_echo_client(peer: std::net::SocketAddrV4) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    log(&format!("TCP client: connecting to {peer}"));
    let mut sock = connect_retry(peer, std::time::Duration::from_secs(30)).await?;
    sock.write_all(PAYLOAD)
        .await
        .map_err(|e| anyhow::anyhow!("write: {e}"))?;
    sock.shutdown()
        .await
        .map_err(|e| anyhow::anyhow!("shutdown: {e}"))?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf)
        .await
        .map_err(|e| anyhow::anyhow!("read echo: {e}"))?;
    if buf != PAYLOAD {
        anyhow::bail!(
            "TCP echo mismatch: sent {} bytes, received {} bytes",
            PAYLOAD.len(),
            buf.len()
        );
    }
    log("TCP client: echo verified");
    Ok(())
}

async fn connect_retry(
    peer: std::net::SocketAddrV4,
    timeout: std::time::Duration,
) -> anyhow::Result<tokio::net::TcpStream> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::net::TcpStream::connect(peer).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
    }
    Err(anyhow::anyhow!(
        "connect to {peer} timed out: {}",
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

// ---- networking helpers (rtnetlink) ----

async fn wait_for_link(
    handle: &rtnetlink::Handle,
    name: &str,
    timeout: std::time::Duration,
) -> anyhow::Result<u32> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(idx) = link_index(handle, name).await? {
            return Ok(idx);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("interface {name} did not appear within {timeout:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

async fn link_index(handle: &rtnetlink::Handle, name: &str) -> anyhow::Result<Option<u32>> {
    use futures_util::stream::TryStreamExt as _;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await {
        Ok(Some(msg)) => Ok(Some(msg.header.index)),
        Ok(None) => Ok(None),
        // "not found" surfaces as an error from the kernel; treat it as absent.
        Err(_) => Ok(None),
    }
}

async fn add_address(
    handle: &rtnetlink::Handle,
    index: u32,
    addr: std::net::IpAddr,
    prefix: u8,
) -> anyhow::Result<()> {
    handle
        .address()
        .add(index, addr, prefix)
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("add address {addr}/{prefix} to ifindex {index}: {e}"))
}

/// Add a static IPv6 route, retrying while the gateway is still unreachable
/// (the freshly-added uplink address may sit in DAD for a moment).
async fn add_route_v6(
    handle: &rtnetlink::Handle,
    dst: std::net::Ipv6Addr,
    prefix: u8,
    gateway: std::net::Ipv6Addr,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let route = rtnetlink::RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix(dst, prefix)
            .gateway(gateway)
            .build();
        match handle.route().add(route).execute().await {
            Ok(()) => return Ok(()),
            Err(e) if tokio::time::Instant::now() < deadline => {
                log(&format!(
                    "route {dst}/{prefix} via {gateway} not yet addable ({e}); retrying"
                ));
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "add route {dst}/{prefix} via {gateway}: {e}"
                ));
            }
        }
    }
}

/// Create an 802.1Q VLAN subinterface `name` with id `vid` on top of the link
/// at `base_index` (equivalent to `ip link add link <uplink> name <uplink>.<N>
/// type vlan id <N>`).
async fn add_vlan(
    handle: &rtnetlink::Handle,
    name: &str,
    base_index: u32,
    vid: u16,
) -> anyhow::Result<()> {
    handle
        .link()
        .add(rtnetlink::LinkVlan::new(name, base_index, vid).build())
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("create vlan {name} (id {vid}) on ifindex {base_index}: {e}"))
}

async fn set_up(handle: &rtnetlink::Handle, index: u32) -> anyhow::Result<()> {
    handle
        .link()
        .set(rtnetlink::LinkUnspec::new_with_index(index).up().build())
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("set ifindex {index} up: {e}"))
}

// ---- daemon process management ----

fn write_config(
    opt: &Opt,
    uplink_ip: std::net::Ipv6Addr,
    peer_uplink: std::net::Ipv6Addr,
    mtu: Option<u32>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&opt.config_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", opt.config_dir.display()))?;
    let path = opt.config_dir.join(format!("{}.json", opt.tunnel_name));
    let mtu_field = mtu.map(|m| format!(",\"mtu\":{m}")).unwrap_or_default();
    let vlan_field = opt
        .vlan
        .map(|v| format!(",\"vlan\":{v}"))
        .unwrap_or_default();
    // The prefixed pass also sets next_hop_src to the assigned uplink address,
    // exercising the explicit route-lookup hint end to end.
    let (local, remote, hint_field) = if opt.outer_prefix {
        let (mine, theirs) = tunnel_prefixes(opt.role);
        (
            mine.to_string(),
            theirs.to_string(),
            format!(",\"next_hop_src\":\"{uplink_ip}\""),
        )
    } else {
        (
            uplink_ip.to_string(),
            peer_uplink.to_string(),
            String::new(),
        )
    };
    let json = format!(
        "{{\"name\":\"{}\",\"local\":\"{local}\",\"remote\":\"{remote}\",\"mss\":\"auto\"{hint_field}{mtu_field}{vlan_field}}}\n",
        opt.tunnel_name
    );
    std::fs::write(&path, json).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    if opt.sandbox {
        let uid = Some(nix::unistd::Uid::from_raw(sandbox::DAEMON_UID));
        let gid = Some(nix::unistd::Gid::from_raw(sandbox::DAEMON_GID));
        nix::unistd::chown(&opt.config_dir, uid, gid)
            .and_then(|()| nix::unistd::chown(&path, uid, gid))
            .map_err(|e| anyhow::anyhow!("chown config to sandbox uid: {e}"))?;
    }
    Ok(())
}

/// Spawn the daemon through the `__listenfds` wrapper, which rebuilds a
/// systemd-style activation block from `stored_fds` (fd-store entries handed
/// back) and then execs — via the sandbox wrapper when requested. The
/// daemon's stderr (its log) is captured per `generation` so the restart
/// phases can assert on adoption markers.
fn spawn_daemon(
    opt: &Opt,
    notify_socket: &std::path::Path,
    stored_fds: &[(std::os::fd::RawFd, &str)],
    generation: usize,
) -> anyhow::Result<tokio::process::Child> {
    let me = std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe: {e}"))?;
    let log_path = daemon_log_path(opt, generation);
    let log = std::fs::File::create(&log_path)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", log_path.display()))?;
    let mut cmd = tokio::process::Command::new(me);
    cmd.arg("__listenfds");
    cmd.args(minisystemd::listenfds_args(stored_fds)?);
    if opt.sandbox {
        cmd.arg("--sandbox");
    }
    cmd.arg(&opt.daemon_path)
        .arg(&opt.uplink)
        .arg("--config-dir")
        .arg(&opt.config_dir)
        // bpf=debug so pin-classification decisions are visible in the
        // captured log when a phase assertion fails.
        .env("RUST_LOG", "info,etherip_xdp::control::bpf=debug")
        .env("NOTIFY_SOCKET", notify_socket)
        .stderr(std::process::Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn {}: {e}", opt.daemon_path.display()))
}

async fn terminate(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        // SAFETY: sending SIGTERM to a child PID is always memory-safe; the worst
        // case is ESRCH if it already exited, which we ignore.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
}

fn modprobe(module: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("/sbin/modprobe")
        .arg(module)
        .status()
        .map_err(|e| anyhow::anyhow!("run modprobe {module}: {e}"))?;
    if !status.success() {
        anyhow::bail!("modprobe {module} failed: {status:?}");
    }
    Ok(())
}

// ---- ICMP echo (raw socket; the VM/netns runs as root) ----

/// Send ICMP echo requests to `target`, retrying until a reply arrives or
/// `timeout` elapses. Blocking; call from `spawn_blocking`.
fn ping(target: std::net::Ipv4Addr, timeout: std::time::Duration) -> anyhow::Result<()> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .map_err(|e| anyhow::anyhow!("open ICMP socket: {e}"))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .map_err(|e| anyhow::anyhow!("set timeout: {e}"))?;
    let dest = socket2::SockAddr::from(std::net::SocketAddrV4::new(target, 0));
    let id: u16 = (std::process::id() & 0xffff) as u16;
    let start = std::time::Instant::now();
    let mut seq: u16 = 0;
    while start.elapsed() < timeout {
        let packet = icmp_echo_request(id, seq);
        sock.send_to(&packet, &dest)
            .map_err(|e| anyhow::anyhow!("send ICMP: {e}"))?;
        if recv_echo_reply(&sock, id) {
            return Ok(());
        }
        seq = seq.wrapping_add(1);
    }
    anyhow::bail!("no ICMP echo reply from {target} within {timeout:?}")
}

fn recv_echo_reply(sock: &socket2::Socket, id: u16) -> bool {
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    let Ok(n) = sock.recv(&mut buf) else {
        return false;
    };
    // SAFETY: `recv` reports `n` bytes initialized at the front of `buf`.
    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
    // Raw IPv4 sockets prepend the IP header; skip it (IHL is in 32-bit words).
    let ihl = ((data.first().copied().unwrap_or(0) & 0x0f) as usize) * 4;
    let Some(icmp) = data.get(ihl..) else {
        return false;
    };
    // Echo reply (type 0) carrying our identifier.
    icmp.len() >= 8 && icmp[0] == 0 && icmp[4..6] == id.to_be_bytes()
}

fn icmp_echo_request(id: u16, seq: u16) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[0] = 8; // echo request
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in p[8..].iter_mut().enumerate() {
        *b = i as u8;
    }
    let ck = icmp_checksum(&p);
    p[2..4].copy_from_slice(&ck.to_be_bytes());
    p
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ---- misc ----

fn parse_cidr_v6(s: &str) -> anyhow::Result<(std::net::Ipv6Addr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("expected ipv6/prefix, got {s:?}"))?;
    Ok((
        ip.parse()
            .map_err(|e| anyhow::anyhow!("bad ipv6 {ip:?}: {e}"))?,
        prefix
            .parse()
            .map_err(|e| anyhow::anyhow!("bad prefix {prefix:?}: {e}"))?,
    ))
}

fn parse_cidr_v4(s: &str) -> anyhow::Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("expected ipv4/prefix, got {s:?}"))?;
    Ok((
        ip.parse()
            .map_err(|e| anyhow::anyhow!("bad ipv4 {ip:?}: {e}"))?,
        prefix
            .parse()
            .map_err(|e| anyhow::anyhow!("bad prefix {prefix:?}: {e}"))?,
    ))
}

fn log(msg: &str) {
    println!("[e2e] {msg}");
}

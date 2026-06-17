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
}

const PAYLOAD: &[u8] = b"etherip-xdp integration payload; the quick brown fox jumps; 0123456789";

fn main() {
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

    let (connection, handle, _rx) =
        rtnetlink::new_connection().map_err(|e| anyhow::anyhow!("netlink: {e}"))?;
    tokio::spawn(connection);

    log("bringing up uplink");
    let uplink_idx =
        wait_for_link(&handle, &opt.uplink, std::time::Duration::from_secs(20)).await?;
    add_address(
        &handle,
        uplink_idx,
        std::net::IpAddr::V6(uplink_ip),
        uplink_prefix,
    )
    .await?;
    set_up(&handle, uplink_idx).await?;

    log("writing tunnel config and launching etherip-xdp");
    write_config(opt, uplink_ip, peer_uplink)?;
    let mut daemon = spawn_daemon(opt)?;

    // The daemon creates the user-facing tunnel interface during start-up.
    log("waiting for tunnel interface");
    let tunnel_idx = wait_for_link(
        &handle,
        &opt.tunnel_name,
        std::time::Duration::from_secs(30),
    )
    .await?;
    add_address(
        &handle,
        tunnel_idx,
        std::net::IpAddr::V4(inner_ip),
        inner_prefix,
    )
    .await?;
    set_up(&handle, tunnel_idx).await?;

    let result = drive_traffic(opt, inner_ip, inner_peer).await;

    // Stop the daemon (graceful: it tears down veths and dumps counters).
    terminate(&mut daemon).await;
    result
}

/// ICMP reachability plus a TCP echo exchange through the tunnel.
async fn drive_traffic(
    opt: &Opt,
    inner_ip: std::net::Ipv4Addr,
    inner_peer: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    // ICMP echo to the peer's inner address. The first packet triggers ARP over
    // the tunnel, so retry generously while both ends finish coming up.
    log("pinging peer inner address through the tunnel");
    tokio::task::spawn_blocking(move || ping(inner_peer, std::time::Duration::from_secs(45)))
        .await
        .map_err(|e| anyhow::anyhow!("ping task join: {e}"))??;
    log("ping OK");

    // TCP through the tunnel. Echo mode (Linux↔Linux) verifies a full
    // round-trip; connect mode (interop) only proves the handshake traverses the
    // tunnel — enough to exercise the inner-TCP path against a plain listener.
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
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&opt.config_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", opt.config_dir.display()))?;
    let path = opt.config_dir.join(format!("{}.json", opt.tunnel_name));
    let json = format!(
        "{{\"name\":\"{}\",\"local\":\"{}\",\"remote\":\"{}\",\"mss\":\"auto\"}}\n",
        opt.tunnel_name, uplink_ip, peer_uplink
    );
    std::fs::write(&path, json).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))
}

fn spawn_daemon(opt: &Opt) -> anyhow::Result<tokio::process::Child> {
    tokio::process::Command::new(&opt.daemon_path)
        .arg(&opt.uplink)
        .arg("--config-dir")
        .arg(&opt.config_dir)
        .env("RUST_LOG", "info")
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

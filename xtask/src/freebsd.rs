//! `freebsd-interop` runner: prove RFC 3378 EtherIP interop against FreeBSD's
//! native `if_gif` implementation.
//!
//! Topology mirrors the `vm` runner's `-netdev stream` L2 link, but the two
//! peers are asymmetric:
//!
//! * a **FreeBSD** guest (cross-platform-actions builder image) is the L2
//!   listener; over its user-net SSH port we configure a `gif` EtherIP tunnel
//!   (fd00::2 → fd00::1) bridged to an inner 10.0.0.2/24 responder;
//! * the **Linux** etherip-xdp guest (the existing initramfs) is the L2
//!   connector, run as a `--tcp connect` client (fd00::1, inner 10.0.0.1) that
//!   pings and TCP-connects to the FreeBSD inner address.
//!
//! The Linux guest is the verdict source (`init: success`), exactly as in the
//! `vm` runner — so success means etherip-xdp's version-3 / proto-97 frames are
//! accepted by FreeBSD and vice versa.

const FREEBSD_IMAGE_URL: &str = "https://github.com/cross-platform-actions/freebsd-builder/\
releases/download/v0.14.0/freebsd-15.0-x86-64.qcow2";

#[derive(clap::Parser)]
pub(crate) struct Options {
    /// Working directory for extracted kernels, images, overlays, and sockets.
    #[clap(long, default_value = "tmp/integration")]
    cache_dir: std::path::PathBuf,

    /// FreeBSD qcow2 image (cross-platform-actions builder); downloaded if absent.
    #[clap(long)]
    freebsd_image: Option<std::path::PathBuf>,

    /// Overall deadline in seconds (covers FreeBSD boot + the Linux scenario).
    #[clap(long, default_value_t = 300)]
    timeout_secs: u64,

    /// Linux kernel `.deb` archives (one `linux-image-*` + one `linux-modules-*`).
    #[clap(required = true)]
    kernel_archives: Vec<std::path::PathBuf>,
}

pub(crate) fn run(opts: Options, _workspace_root: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(&opts.cache_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", opts.cache_dir.display()))?;

    // --- Linux side: build binaries + initramfs (reuse the vm runner) ---
    println!("building harness binaries for x86_64-unknown-linux-musl…");
    let binaries = crate::build::build(
        Some("x86_64-unknown-linux-musl"),
        &["etherip-xdp", "test-distro", "integration-test"],
    )?;
    let init = crate::build::require(&binaries, "init")?;
    let modprobe = crate::build::require(&binaries, "modprobe")?;
    let daemon = crate::build::require(&binaries, "etherip-xdp")?;
    let scenario = crate::build::require(&binaries, "etherip-xdp-e2e")?;

    let groups = crate::vm::group_kernels(&opts.kernel_archives)?;
    let (version, image, modules) = groups
        .first()
        .ok_or_else(|| anyhow::anyhow!("need one Linux kernel (image + modules debs)"))?;
    println!("Linux kernel: {version}");

    let work = opts.cache_dir.join("extract").join(version);
    let img_dir = work.join("image");
    let mod_dir = work.join("modules");
    let _ = std::fs::remove_dir_all(&work);
    crate::deb::extract(image, &img_dir)?;
    crate::deb::extract(modules, &mod_dir)?;
    let vmlinuz = crate::deb::find_prefixed(&img_dir.join("boot"), "vmlinuz-")?;
    let initramfs = opts.cache_dir.join(format!("initramfs-{version}.img"));
    crate::vm::build_initramfs(
        init, modprobe, daemon, scenario, &mod_dir, version, &initramfs,
    )?;

    // --- FreeBSD side: ensure image, make a throwaway overlay ---
    let image_path = opts.freebsd_image.clone().unwrap_or_else(|| {
        opts.cache_dir
            .join("freebsd")
            .join("freebsd-15.0-x86-64.qcow2")
    });
    ensure_freebsd_image(&image_path)?;
    let overlay = opts.cache_dir.join("freebsd-overlay.qcow2");
    make_overlay(&image_path, &overlay)?;

    let sock = opts.cache_dir.join("fbsd.sock");
    let _ = std::fs::remove_file(&sock);
    let ssh_port = alloc_free_port()?;
    let askpass = write_askpass(&opts.cache_dir)?;

    run_interop(
        &vmlinuz,
        &initramfs,
        &overlay,
        &sock,
        ssh_port,
        &askpass,
        opts.timeout_secs,
    )
}

fn run_interop(
    vmlinuz: &std::path::Path,
    initramfs: &std::path::Path,
    overlay: &std::path::Path,
    sock: &std::path::Path,
    ssh_port: u16,
    askpass: &std::path::Path,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let sock_str = sock
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 socket path"))?;

    // FreeBSD is the L2 listener: its socket exists as soon as qemu starts, so
    // the Linux connector (booted later) can attach immediately.
    let mut fbsd = spawn_freebsd(overlay, sock_str, ssh_port)?;
    crate::vm::drain_stderr(&mut fbsd, "FBSD!".to_string());
    let fbsd_log = crate::vm::watch(
        fbsd.stdout.take().expect("piped stdout"),
        "FBSD".to_string(),
        std::sync::mpsc::channel().0, // serial echo only; verdict comes from Linux
    );

    let result = (|| -> anyhow::Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

        println!("waiting for FreeBSD SSH on 127.0.0.1:{ssh_port}…");
        wait_for_ssh(ssh_port, askpass, deadline)?;
        println!("configuring FreeBSD gif/bridge EtherIP tunnel…");
        ssh_exec(ssh_port, askpass, Some(FREEBSD_SETUP), "configure tunnel")?;

        // Boot the Linux etherip-xdp connector as a --tcp connect client.
        let reconnect = crate::vm::reconnect_option()?;
        let netdev =
            format!("stream,id=net0,server=off,addr.type=unix,addr.path={sock_str},{reconnect}");
        let mut linux = crate::vm::spawn_vm(
            vmlinuz,
            initramfs,
            &netdev,
            "52:54:00:00:00:01",
            &linux_client_args(),
        )?;
        crate::vm::drain_stderr(&mut linux, "LINUX!".to_string());
        let (tx, rx) = std::sync::mpsc::channel();
        let linux_log = crate::vm::watch(
            linux.stdout.take().expect("piped stdout"),
            "LINUX".to_string(),
            tx,
        );

        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let outcome = rx
            .recv_timeout(remaining)
            .map(|(_, o)| o)
            .unwrap_or(crate::vm::Outcome::Crashed);

        let _ = linux.kill();
        let _ = linux.wait();
        let _ = linux_log.join();

        if outcome == crate::vm::Outcome::Success {
            Ok(())
        } else {
            // On failure, dump what FreeBSD saw on the wire to aid diagnosis.
            println!("collecting FreeBSD diagnostics…");
            let _ = ssh_exec(ssh_port, askpass, Some(FREEBSD_DIAGNOSE), "diagnose");
            anyhow::bail!("Linux peer outcome: {outcome:?}")
        }
    })();

    let _ = fbsd.kill();
    let _ = fbsd.wait();
    let _ = fbsd_log.join();
    let _ = std::fs::remove_file(sock);

    match &result {
        Ok(()) => println!("=== FreeBSD interop: PASS ==="),
        Err(e) => eprintln!("=== FreeBSD interop: FAIL: {e:#} ==="),
    }
    result
}

/// `init.arg=` tokens for the Linux peer: client at fd00::1 / 10.0.0.1, driving
/// ping + a connect-only TCP check against the FreeBSD peer (fd00::2 / 10.0.0.2).
fn linux_client_args() -> Vec<String> {
    [
        "--role",
        "client",
        "--load-veth",
        "--uplink-cidr",
        "fd00::1/64",
        "--peer-uplink",
        "fd00::2",
        "--inner-cidr",
        "10.0.0.1/24",
        "--inner-peer",
        "10.0.0.2",
        "--tcp",
        "connect",
        "--timeout-secs",
        "150",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// FreeBSD setup pushed over SSH to `sudo sh -s`. Stands up a gif EtherIP-over-
/// IPv6 tunnel bridged to an inner responder. Adding gif to a bridge selects L2
/// EtherIP (proto 97, version 3) — byte-compatible with etherip-xdp.
const FREEBSD_SETUP: &str = r#"set -e
kldload if_gif 2>/dev/null || true
kldload if_bridge 2>/dev/null || true
# vtnet1 is the -netdev stream L2 link (PCI addr 0x07); vtnet0 is user-net/SSH.
ifconfig vtnet1 -rxcsum -txcsum -tso -lro -rxcsum6 -txcsum6 2>/dev/null || true
ifconfig vtnet1 inet6 fd00::2/64 up
# Order matters: gif must already be a bridge member when its tunnel is set, so
# FreeBSD registers the EtherIP (proto 97) receive demux instead of IP-in-IP.
# Otherwise inbound proto-97 is rejected with "ICMP6 parameter problem".
ifconfig gif0 create
ifconfig bridge0 create
ifconfig bridge0 addm gif0
# `inet6` is required: a bare `tunnel` uses the IPv4 ioctl (SIOCSIFPHYADDR) and
# rejects IPv6 endpoints with "Invalid argument".
ifconfig gif0 inet6 tunnel fd00::2 fd00::1
ifconfig gif0 up
ifconfig bridge0 inet 10.0.0.2/24
ifconfig bridge0 up
sysctl net.inet6.ip6.gifhlim=64 2>/dev/null || true
# Capture the outer link for post-test diagnosis (-U flushes per packet).
daemon -f /usr/sbin/tcpdump -Uni vtnet1 -s 0 -w /tmp/l2.pcap
# Keep-listening responder so the Linux client's TCP connect succeeds.
daemon -f /bin/sh -c 'while :; do /usr/bin/nc -4 -l 7878 >/dev/null 2>&1; done'
ifconfig vtnet1
ifconfig gif0
ifconfig bridge0
echo FREEBSD_SETUP_OK
"#;

/// Pulled after the Linux test to show what FreeBSD saw on the wire.
const FREEBSD_DIAGNOSE: &str = r#"set +e
pkill -INT tcpdump; sleep 1
echo '--- vtnet1 ---'; ifconfig -v vtnet1
echo '--- ndp ---'; ndp -an
echo '--- arp ---'; arp -an
echo '--- etherip stats ---'; netstat -sp etherip 2>/dev/null
echo '--- ip6 stats (head) ---'; netstat -sp ip6 2>/dev/null | head -40
echo '--- sysctls ---'; sysctl net.link.gif net.link.bridge.ipfw net.inet6.ip6.forwarding 2>/dev/null
echo '--- pcap summary ---'; tcpdump -nr /tmp/l2.pcap -c 40 2>/dev/null
echo '--- pcap proto 97 hex ---'; tcpdump -nr /tmp/l2.pcap -c 4 -X 'ip6 proto 97' 2>/dev/null
echo FREEBSD_DIAGNOSE_OK
"#;

fn spawn_freebsd(
    overlay: &std::path::Path,
    sock_str: &str,
    ssh_port: u16,
) -> anyhow::Result<std::process::Child> {
    let drive = format!(
        "if=none,file={},id=drive0,format=qcow2,cache=unsafe,discard=ignore",
        overlay
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 overlay path"))?
    );
    let mgmt = format!("user,id=mgmt,hostfwd=tcp:127.0.0.1:{ssh_port}-:22");
    let l2 = format!("stream,id=l2,server=on,addr.type=unix,addr.path={sock_str}");

    let mut cmd = std::process::Command::new("qemu-system-x86_64");
    cmd.args([
        "-machine",
        "accel=kvm:tcg",
        "-cpu",
        "max",
        "-smp",
        "2",
        "-m",
        "2048",
    ])
    .args(["-no-reboot", "-nographic"])
    .args(["-drive", &drive])
    .args(["-device", "virtio-blk-pci,drive=drive0,bootindex=0"])
    // Pin NICs to high, conflict-free slots (the disk auto-takes a low slot).
    // Lower slot enumerates first: 0x06 = vtnet0 (mgmt/SSH), 0x07 = vtnet1 (L2).
    .args(["-netdev", &mgmt])
    .args(["-device", "virtio-net-pci,netdev=mgmt,addr=0x06"])
    .args(["-netdev", &l2])
    .args([
        "-device",
        "virtio-net-pci,netdev=l2,addr=0x07,mac=52:54:00:00:00:02",
    ])
    .args(["-boot", "strict=off"])
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("spawn FreeBSD qemu: {e}"))
}

// ---- FreeBSD image management ----

fn ensure_freebsd_image(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", parent.display()))?;
    }
    println!("downloading FreeBSD image to {}…", path.display());
    crate::exec(
        std::process::Command::new("curl")
            .args(["-fSL", "--output"])
            .arg(path)
            .arg(FREEBSD_IMAGE_URL),
    )
}

/// Create a throwaway qcow2 overlay so the cached base image stays clean.
fn make_overlay(base: &std::path::Path, overlay: &std::path::Path) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(overlay);
    let base = std::fs::canonicalize(base)
        .map_err(|e| anyhow::anyhow!("canonicalize {}: {e}", base.display()))?;
    let backing = format!(
        "backing_file={},backing_fmt=qcow2",
        base.to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 base path"))?
    );
    crate::exec(
        std::process::Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2", "-o", &backing])
            .arg(overlay),
    )
}

// ---- SSH (password auth via SSH_ASKPASS; no sshpass dependency) ----

/// Write an askpass helper that supplies the cpa image's empty password.
fn write_askpass(dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let path = dir.join("askpass.sh");
    std::fs::write(&path, "#!/bin/sh\necho \"\"\n")
        .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| anyhow::anyhow!("chmod {}: {e}", path.display()))?;
    Ok(path)
}

fn wait_for_ssh(
    port: u16,
    askpass: &std::path::Path,
    deadline: std::time::Instant,
) -> anyhow::Result<()> {
    while std::time::Instant::now() < deadline {
        if ssh_exec(port, askpass, None, "probe").is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    anyhow::bail!("FreeBSD SSH on port {port} not ready before deadline")
}

/// Run a command on the FreeBSD guest as root. With `stdin_script`, pipes it to
/// `sudo sh -s`; otherwise runs `true` as a readiness probe.
fn ssh_exec(
    port: u16,
    askpass: &std::path::Path,
    stdin_script: Option<&str>,
    what: &str,
) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("ssh");
    cmd.env("SSH_ASKPASS", askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "PreferredAuthentications=password"])
        .args(["-o", "PubkeyAuthentication=no"])
        .args(["-o", "NumberOfPasswordPrompts=1"])
        .args(["-o", "ConnectTimeout=8"])
        .args(["-o", "LogLevel=ERROR"])
        .args(["-p", &port.to_string()])
        .arg("runner@127.0.0.1");
    if stdin_script.is_some() {
        cmd.arg("sudo sh -s");
    } else {
        cmd.arg("true");
    }
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn ssh ({what}): {e}"))?;
    if let Some(script) = stdin_script {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(script.as_bytes())
            .map_err(|e| anyhow::anyhow!("write ssh stdin: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("wait ssh ({what}): {e}"))?;
    // Echo guest-side output for diagnostics (stderr carries `set -x` traces).
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        println!("FBSD-ssh| {line}");
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        eprintln!("FBSD-ssh!| {line}");
    }
    if !output.status.success() {
        anyhow::bail!("ssh {what} failed: {}", output.status);
    }
    Ok(())
}

/// Reserve an ephemeral localhost port for the SSH hostfwd.
fn alloc_free_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| anyhow::anyhow!("bind ephemeral port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("local_addr: {e}"))?
        .port();
    Ok(port)
}

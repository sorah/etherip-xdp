//! `vm` runner: boot two `qemu-system-x86_64` guests joined by a `-netdev
//! stream` UNIX socket and run the scenario in each, once per kernel.

#[derive(clap::Parser)]
pub(crate) struct Options {
    /// Working directory for extracted kernels, initramfs images, and sockets.
    #[clap(long, default_value = "tmp/integration")]
    cache_dir: std::path::PathBuf,

    /// Per-VM scenario deadline, in seconds (passed to the guest scenario).
    #[clap(long, default_value_t = 120)]
    timeout_secs: u64,

    /// Kernel `.deb` archives: an `linux-image-*` and a `linux-modules-*` per
    /// version (grouped automatically by ABI string).
    #[clap(required = true)]
    kernel_archives: Vec<std::path::PathBuf>,
}

/// The PCI slot we pin the NIC to (`enp0s3`); with `net.ifnames=0` it is `eth0`.
const DEVICE_PROPS: &str = "mq=off,guest_csum=off,csum=off,gso=off,\
guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,\
host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off,mrg_rxbuf=off";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Outcome {
    Success,
    Failure,
    /// The guest produced no verdict (panic, kill, or boot failure).
    Crashed,
}

pub(crate) fn run(opts: Options, _workspace_root: &std::path::Path) -> anyhow::Result<()> {
    let Options {
        cache_dir,
        timeout_secs,
        kernel_archives,
    } = opts;
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", cache_dir.display()))?;

    println!("building harness binaries for x86_64-unknown-linux-musl…");
    let binaries = crate::build::build(
        Some("x86_64-unknown-linux-musl"),
        &["etherip-xdp", "dut-distro", "integration-test"],
    )?;
    let init = crate::build::require(&binaries, "init")?;
    let modprobe = crate::build::require(&binaries, "modprobe")?;
    let daemon = crate::build::require(&binaries, "etherip-xdp")?;
    let scenario = crate::build::require(&binaries, "etherip-xdp-e2e")?;

    let reconnect = reconnect_option()?;
    println!("qemu connector reconnect option: {reconnect}");

    let groups = group_kernels(&kernel_archives)?;
    let mut failures = Vec::new();
    for (index, (version, image, modules)) in groups.iter().enumerate() {
        println!("\n=== kernel {version} ===");
        let work = cache_dir.join("extract").join(version);
        let img_dir = work.join("image");
        let mod_dir = work.join("modules");
        let _ = std::fs::remove_dir_all(&work);
        crate::deb::extract(image, &img_dir)?;
        crate::deb::extract(modules, &mod_dir)?;

        let vmlinuz = crate::deb::find_prefixed(&img_dir.join("boot"), "vmlinuz-")?;
        let initramfs = cache_dir.join(format!("initramfs-{version}.img"));
        build_initramfs(
            init, modprobe, daemon, scenario, &mod_dir, version, &initramfs,
        )?;

        let sock = cache_dir.join(format!("s{index}.sock"));
        match run_pair(
            &vmlinuz,
            &initramfs,
            &sock,
            &reconnect,
            timeout_secs,
            version,
        ) {
            Ok(()) => println!("=== kernel {version}: PASS ==="),
            Err(e) => {
                eprintln!("=== kernel {version}: FAIL: {e:#} ===");
                failures.push(format!("{version}: {e:#}"));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("integration tests failed:\n  {}", failures.join("\n  "))
    }
}

/// Group the supplied debs by ABI string into (version, image_deb, modules_deb).
pub(crate) fn group_kernels(
    archives: &[std::path::PathBuf],
) -> anyhow::Result<Vec<(String, std::path::PathBuf, std::path::PathBuf)>> {
    let mut images: std::collections::BTreeMap<String, std::path::PathBuf> =
        std::collections::BTreeMap::new();
    let mut modules: std::collections::BTreeMap<String, std::path::PathBuf> =
        std::collections::BTreeMap::new();
    for path in archives {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("bad archive name: {}", path.display()))?;
        if let Some(rest) = name
            .strip_prefix("linux-image-unsigned-")
            .or_else(|| name.strip_prefix("linux-image-"))
        {
            let version = rest.split('_').next().unwrap_or(rest).to_string();
            images.insert(version, path.clone());
        } else if let Some(rest) = name.strip_prefix("linux-modules-") {
            let version = rest.split('_').next().unwrap_or(rest).to_string();
            modules.insert(version, path.clone());
        } else {
            eprintln!("ignoring unrecognised archive {name}");
        }
    }

    let mut groups = Vec::new();
    for (version, image) in images {
        let Some(modules) = modules.get(&version) else {
            anyhow::bail!("no linux-modules deb for kernel {version}");
        };
        groups.push((version, image, modules.clone()));
    }
    if groups.is_empty() {
        anyhow::bail!("no linux-image debs supplied");
    }
    Ok(groups)
}

/// Modules shipped in the initramfs when they exist as loadable `.ko` for the
/// target kernel (built-in ones are simply absent and need no shipping). `veth`
/// is always a module; `virtio_net` and its failover deps are built-in on some
/// kernels (e.g. 6.8) but loadable on others (e.g. 6.5), so the NIC driver chain
/// must be carried for the latter or eth0 never appears.
const WANTED_MODULES: &[&str] = &[
    "veth",
    "virtio_net",
    "virtio_pci",
    "net_failover",
    "failover",
    "virtio",
    "virtio_ring",
    "virtio_pci_modern_dev",
    "virtio_pci_legacy_dev",
];

/// Pack the initramfs: init + scenario + daemon + modprobe + the kernel modules
/// needed to bring up the uplink (virtio-net chain) and veth.
pub(crate) fn build_initramfs(
    init: &std::path::Path,
    modprobe: &std::path::Path,
    daemon: &std::path::Path,
    scenario: &std::path::Path,
    mod_dir: &std::path::Path,
    version: &str,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let read = |p: &std::path::Path| -> anyhow::Result<Vec<u8>> {
        std::fs::read(p).map_err(|e| anyhow::anyhow!("read {}: {e}", p.display()))
    };

    let mut cpio = crate::cpio::Cpio::new();
    cpio.add_dir("dev");
    cpio.add_file("init", 0o755, read(init)?);
    cpio.add_file("sbin/modprobe", 0o755, read(modprobe)?);
    cpio.add_file("sbin/etherip-xdp", 0o755, read(daemon)?);
    cpio.add_file("bin/etherip-xdp-e2e", 0o755, read(scenario)?);

    // Ship the wanted modules under `lib/modules/<ver>/...` so the guest's
    // `resolve_modules_dir` + `modprobe` find them. The deb may store them under
    // `lib/modules` or (usr-merge, e.g. 7.0) `usr/lib/modules`; we normalise to
    // `lib/modules` in the initramfs regardless.
    let version_dir = modules_version_dir(mod_dir, version)?;
    let found = find_modules(&version_dir)?;
    if !found.contains_key("veth") {
        anyhow::bail!("veth module not found under {}", version_dir.display());
    }
    for path in found.values() {
        let rel = path
            .strip_prefix(&version_dir)
            .map_err(|e| anyhow::anyhow!("strip prefix: {e}"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 module path: {}", path.display()))?;
        cpio.add_file(&format!("lib/modules/{version}/{rel}"), 0o644, read(path)?);
    }

    std::fs::write(out, cpio.finish()).map_err(|e| anyhow::anyhow!("write {}: {e}", out.display()))
}

/// The `<ver>` modules directory inside an extracted modules deb, under either
/// `lib/modules` or (usr-merge) `usr/lib/modules`.
fn modules_version_dir(
    mod_dir: &std::path::Path,
    version: &str,
) -> anyhow::Result<std::path::PathBuf> {
    for base in ["lib/modules", "usr/lib/modules"] {
        let dir = mod_dir.join(base).join(version);
        if dir.is_dir() {
            return Ok(dir);
        }
    }
    anyhow::bail!(
        "no modules directory for {version} under {} (lib/modules or usr/lib/modules)",
        mod_dir.display()
    )
}

/// Locate each [`WANTED_MODULES`] entry that exists as a `.ko[.xz|.zst]` under
/// `version_dir`, keyed by base module name.
fn find_modules(
    version_dir: &std::path::Path,
) -> anyhow::Result<std::collections::HashMap<String, std::path::PathBuf>> {
    let mut found = std::collections::HashMap::new();
    for entry in walkdir::WalkDir::new(version_dir) {
        let entry = entry.map_err(|e| anyhow::anyhow!("walk {}: {e}", version_dir.display()))?;
        let Some(name) = entry.file_name().to_str() else {
            continue;
        };
        let stem = name
            .strip_suffix(".ko")
            .or_else(|| name.strip_suffix(".ko.xz"))
            .or_else(|| name.strip_suffix(".ko.zst"));
        if let Some(stem) = stem
            && WANTED_MODULES.contains(&stem)
        {
            found.insert(stem.to_string(), entry.path().to_path_buf());
        }
    }
    Ok(found)
}

/// Boot the listener, wait for its socket, boot the connector, and require both
/// guests to print `init: success`.
fn run_pair(
    vmlinuz: &std::path::Path,
    initramfs: &std::path::Path,
    sock: &std::path::Path,
    reconnect: &str,
    timeout_secs: u64,
    label: &str,
) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(sock);
    let sock_str = sock
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 socket path"))?;

    let server_netdev = format!("stream,id=net0,server=on,addr.type=unix,addr.path={sock_str}");
    let client_netdev =
        format!("stream,id=net0,server=off,addr.type=unix,addr.path={sock_str},{reconnect}");

    let (tx, rx) = std::sync::mpsc::channel();

    // Start the listener and immediately begin capturing its console/stderr, so
    // a startup failure surfaces instead of just "socket never appeared".
    let mut server = spawn_vm(
        vmlinuz,
        initramfs,
        &server_netdev,
        "52:54:00:00:00:01",
        &linux_scenario_args("server", timeout_secs),
    )?;
    drain_stderr(&mut server, format!("{label}/A!"));
    let ta = watch(
        server.stdout.take().expect("piped stdout"),
        format!("{label}/A"),
        tx.clone(),
    );
    if let Err(e) = wait_for_socket(sock, &mut server, std::time::Duration::from_secs(20)) {
        let _ = server.kill();
        let _ = server.wait();
        let _ = ta.join();
        return Err(e);
    }

    let mut client = spawn_vm(
        vmlinuz,
        initramfs,
        &client_netdev,
        "52:54:00:00:00:02",
        &linux_scenario_args("client", timeout_secs),
    )?;
    drain_stderr(&mut client, format!("{label}/B!"));
    let tb = watch(
        client.stdout.take().expect("piped stdout"),
        format!("{label}/B"),
        tx,
    );

    // Allow boot + the in-guest scenario deadline, plus slack for TCG.
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(timeout_secs)
        + std::time::Duration::from_secs(120);
    let mut outcomes: std::collections::HashMap<String, Outcome> = std::collections::HashMap::new();
    while outcomes.len() < 2 {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok((who, outcome)) => {
                outcomes.insert(who, outcome);
            }
            Err(_) => break,
        }
    }

    let _ = server.kill();
    let _ = client.kill();
    let _ = server.wait();
    let _ = client.wait();
    let _ = ta.join();
    let _ = tb.join();
    let _ = std::fs::remove_file(sock);

    let server_outcome = outcomes
        .get(&format!("{label}/A"))
        .copied()
        .unwrap_or(Outcome::Crashed);
    let client_outcome = outcomes
        .get(&format!("{label}/B"))
        .copied()
        .unwrap_or(Outcome::Crashed);
    if server_outcome == Outcome::Success && client_outcome == Outcome::Success {
        Ok(())
    } else {
        anyhow::bail!("server={server_outcome:?} client={client_outcome:?}")
    }
}

/// Scenario `init.arg=` tokens for a Linux peer in the symmetric vm test.
fn linux_scenario_args(role: &str, timeout_secs: u64) -> Vec<String> {
    vec![
        "--role".into(),
        role.into(),
        "--load-veth".into(),
        "--timeout-secs".into(),
        timeout_secs.to_string(),
    ]
}

/// Boot a Linux guest: `netdev`/`mac` wire it to the L2 link, `scenario_args` are
/// forwarded to the in-guest scenario as `init.arg=` tokens.
pub(crate) fn spawn_vm(
    vmlinuz: &std::path::Path,
    initramfs: &std::path::Path,
    netdev: &str,
    mac: &str,
    scenario_args: &[String],
) -> anyhow::Result<std::process::Child> {
    let mut append =
        String::from("console=ttyS0 noapic net.ifnames=0 biosdevname=0 panic=-1 init=/init");
    for arg in scenario_args {
        append.push_str(" init.arg=");
        append.push_str(arg);
    }
    let device = format!("virtio-net-pci,netdev=net0,addr=0x3,mac={mac},{DEVICE_PROPS}");

    let mut cmd = std::process::Command::new("qemu-system-x86_64");
    // `-machine accel=kvm:tcg` tries KVM then falls back to TCG (the colon-list
    // form is only valid on `-machine accel=`, not on bare `-accel`).
    cmd.args([
        "-machine",
        "accel=kvm:tcg",
        "-m",
        "1024",
        "-smp",
        "2",
        "-no-reboot",
        "-nographic",
    ])
    .arg("-kernel")
    .arg(vmlinuz)
    .arg("-initrd")
    .arg(initramfs)
    .args(["-append", &append])
    .args(["-netdev", netdev])
    .args(["-device", &device])
    // Keep an (unused) stdin pipe open for the child's lifetime: with
    // `-nographic` QEMU muxes the monitor onto stdio, and a closed stdin can
    // make it misbehave. The pipe stays open until the Child is dropped.
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("spawn qemu (mac {mac}): {e}"))
}

fn wait_for_socket(
    sock: &std::path::Path,
    server: &mut std::process::Child,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if sock.exists() {
            return Ok(());
        }
        if let Some(status) = server
            .try_wait()
            .map_err(|e| anyhow::anyhow!("try_wait listener qemu: {e}"))?
        {
            anyhow::bail!("listener qemu exited before creating the socket: {status}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!("listener socket {} never appeared", sock.display())
}

/// Read a guest's serial console to EOF, echoing each line with `prefix`, and
/// send the final [`Outcome`] derived from the `init:` verdict line.
pub(crate) fn watch(
    stdout: std::process::ChildStdout,
    prefix: String,
    tx: std::sync::mpsc::Sender<(String, Outcome)>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(stdout);
        let mut outcome = Outcome::Crashed;
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end();
            println!("{prefix}| {text}");
            if text.contains("init: success") {
                outcome = Outcome::Success;
            } else if text.contains("init: failure") {
                outcome = Outcome::Failure;
            }
        }
        let _ = tx.send((prefix, outcome));
    })
}

pub(crate) fn drain_stderr(child: &mut std::process::Child, prefix: String) {
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stderr).lines() {
                match line {
                    Ok(l) => eprintln!("{prefix}| {l}"),
                    Err(_) => break,
                }
            }
        });
    }
}

/// `reconnect-ms=1000` on QEMU ≥ 9.2 (where `reconnect` is deprecated/removed),
/// else `reconnect=5`.
pub(crate) fn reconnect_option() -> anyhow::Result<String> {
    let out = std::process::Command::new("qemu-system-x86_64")
        .arg("--version")
        .output()
        .map_err(|e| anyhow::anyhow!("run qemu-system-x86_64 --version: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    // e.g. "QEMU emulator version 11.0.1"
    let (major, minor) = text
        .split_whitespace()
        .find_map(|tok| {
            let mut parts = tok.split('.');
            let major: u32 = parts.next()?.parse().ok()?;
            let minor: u32 = parts.next()?.parse().ok()?;
            Some((major, minor))
        })
        .ok_or_else(|| anyhow::anyhow!("could not parse qemu version from {text:?}"))?;
    Ok(reconnect_for(major, minor).to_string())
}

/// `reconnect-ms` was added in QEMU 9.2 (which deprecated, then 10.2 removed,
/// the seconds-valued `reconnect`); older QEMU only understands `reconnect`.
fn reconnect_for(major: u32, minor: u32) -> &'static str {
    if (major, minor) >= (9, 2) {
        "reconnect-ms=1000"
    } else {
        "reconnect=5"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reconnect_option_is_version_gated() {
        assert_eq!(super::reconnect_for(8, 2), "reconnect=5");
        assert_eq!(super::reconnect_for(9, 1), "reconnect=5");
        assert_eq!(super::reconnect_for(9, 2), "reconnect-ms=1000");
        assert_eq!(super::reconnect_for(10, 2), "reconnect-ms=1000");
        assert_eq!(super::reconnect_for(11, 0), "reconnect-ms=1000");
    }

    #[test]
    fn groups_image_and_modules_by_version() {
        let archives = [
            std::path::PathBuf::from(
                "x/linux-image-unsigned-7.0.0-070000-generic_7.0.0-070000.202604122140_amd64.deb",
            ),
            std::path::PathBuf::from(
                "x/linux-modules-7.0.0-070000-generic_7.0.0-070000.202604122140_amd64.deb",
            ),
        ];
        let groups = super::group_kernels(&archives).unwrap();
        assert_eq!(groups.len(), 1);
        let (version, image, modules) = &groups[0];
        assert_eq!(version, "7.0.0-070000-generic");
        assert!(image.to_str().unwrap().contains("linux-image-unsigned"));
        assert!(modules.to_str().unwrap().contains("linux-modules"));
    }

    #[test]
    fn errors_when_modules_deb_is_missing() {
        let archives = [std::path::PathBuf::from(
            "x/linux-image-unsigned-6.8.0-060800-generic_6.8.0-060800.202502181545_amd64.deb",
        )];
        assert!(super::group_kernels(&archives).is_err());
    }
}

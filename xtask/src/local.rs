//! `local` runner: wire two network namespaces with a veth "uplink" on the host
//! and run the scenario in each. Requires root (CAP_NET_ADMIN) and uses the host
//! kernel — fast iteration without QEMU.

#[derive(clap::Parser)]
pub(crate) struct Options {
    /// Working directory for per-role config.
    #[clap(long, default_value = "tmp/integration/local")]
    work_dir: std::path::PathBuf,

    /// Per-role scenario deadline, in seconds.
    #[clap(long, default_value_t = 60)]
    timeout_secs: u64,

    /// Run the daemon unsandboxed; by default it runs under the hardened
    /// (non-root + ambient caps + no-new-privs) sandbox.
    #[clap(long)]
    no_sandbox: bool,
}

const NS_A: &str = "etxa";
const NS_B: &str = "etxb";
const UPLINK_A: &str = "etxu0";
const UPLINK_B: &str = "etxu1";

pub(crate) fn run(opts: Options, _workspace_root: &std::path::Path) -> anyhow::Result<()> {
    require_root()?;
    std::fs::create_dir_all(&opts.work_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", opts.work_dir.display()))?;

    println!("building harness binaries for the host…");
    let binaries = crate::build::build(None, &["etherip-xdp", "integration-test"])?;
    let daemon = crate::build::require(&binaries, "etherip-xdp")?.clone();
    let scenario = crate::build::require(&binaries, "etherip-xdp-e2e")?.clone();

    // Clean any leftovers from a previous aborted run, then set up fresh.
    teardown();
    setup()?;

    let result = run_scenarios(&opts, &daemon, &scenario);

    teardown();
    result
}

fn setup() -> anyhow::Result<()> {
    ip(&["netns", "add", NS_A])?;
    ip(&["netns", "add", NS_B])?;
    ip(&[
        "link", "add", UPLINK_A, "type", "veth", "peer", "name", UPLINK_B,
    ])?;
    ip(&["link", "set", UPLINK_A, "netns", NS_A])?;
    ip(&["link", "set", UPLINK_B, "netns", NS_B])?;
    ip(&["-n", NS_A, "link", "set", "lo", "up"])?;
    ip(&["-n", NS_B, "link", "set", "lo", "up"])?;
    Ok(())
}

fn teardown() {
    // Deleting the netns removes the veths it holds; ignore errors.
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", NS_A])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", NS_B])
        .status();
}

fn run_scenarios(
    opts: &Options,
    daemon: &std::path::Path,
    scenario: &std::path::Path,
) -> anyhow::Result<()> {
    let mut server = spawn_scenario(opts, daemon, scenario, NS_A, "server", UPLINK_A)?;
    let mut client = spawn_scenario(opts, daemon, scenario, NS_B, "client", UPLINK_B)?;

    let server_ok = server
        .wait()
        .map_err(|e| anyhow::anyhow!("wait server: {e}"))?
        .success();
    let client_ok = client
        .wait()
        .map_err(|e| anyhow::anyhow!("wait client: {e}"))?
        .success();
    if server_ok && client_ok {
        Ok(())
    } else {
        anyhow::bail!("scenario failed (server_ok={server_ok}, client_ok={client_ok})")
    }
}

fn spawn_scenario(
    opts: &Options,
    daemon: &std::path::Path,
    scenario: &std::path::Path,
    netns: &str,
    role: &str,
    uplink: &str,
) -> anyhow::Result<std::process::Child> {
    let config_dir = opts.work_dir.join(role);
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["netns", "exec", netns])
        .arg(scenario)
        .args(["--role", role, "--uplink", uplink])
        .arg("--daemon-path")
        .arg(daemon)
        .arg("--config-dir")
        .arg(&config_dir)
        .arg("--timeout-secs")
        .arg(opts.timeout_secs.to_string());
    if !opts.no_sandbox {
        cmd.arg("--sandbox");
    }
    cmd.env("RUST_LOG", "info")
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn scenario ({role}) in {netns}: {e}"))
}

fn ip(args: &[&str]) -> anyhow::Result<()> {
    crate::exec(std::process::Command::new("ip").args(args))
}

fn require_root() -> anyhow::Result<()> {
    let out = std::process::Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| anyhow::anyhow!("run id -u: {e}"))?;
    let uid = String::from_utf8_lossy(&out.stdout);
    if uid.trim() != "0" {
        anyhow::bail!(
            "local mode requires root (CAP_NET_ADMIN). Re-run with: \
             sudo -E cargo xtask integration-test local"
        );
    }
    Ok(())
}

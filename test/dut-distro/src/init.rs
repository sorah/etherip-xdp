//! `init` is the first process started by the kernel inside the test VM.
//!
//! It creates the minimal mounts required to load and run BPF programs, then
//! runs every binary in `/bin` (the integration-test scenario), forwarding any
//! `init.arg=` kernel-cmdline tokens as arguments. It prints a final
//! `init: success` / `init: failure` line — which the host-side orchestrator
//! greps for — and powers the machine off.
//!
//! Ported from aya's `test-distro` `init`.
#![deny(clippy::undocumented_unsafe_blocks)]

#[derive(Debug)]
struct Errors(Vec<anyhow::Error>);

impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(errors) = self;
        for (i, error) in errors.iter().enumerate() {
            if i != 0 {
                writeln!(f)?;
            }
            write!(f, "{error:?}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Errors {}

struct Mount {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    /// `Some` ⇒ create the mountpoint with this mode first; `None` ⇒ it must
    /// already exist (e.g. sysfs-provided directories, or `/dev`).
    target_mode: Option<nix::sys::stat::Mode>,
}

fn run() -> anyhow::Result<()> {
    const RXRXRX: nix::sys::stat::Mode = nix::sys::stat::Mode::empty()
        .union(nix::sys::stat::Mode::S_IRUSR)
        .union(nix::sys::stat::Mode::S_IXUSR)
        .union(nix::sys::stat::Mode::S_IRGRP)
        .union(nix::sys::stat::Mode::S_IXGRP)
        .union(nix::sys::stat::Mode::S_IROTH)
        .union(nix::sys::stat::Mode::S_IXOTH);

    for Mount {
        source,
        target,
        fstype,
        target_mode,
    } in [
        Mount {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            target_mode: Some(RXRXRX),
        },
        Mount {
            source: "dev",
            target: "/dev",
            fstype: "devtmpfs",
            target_mode: None,
        },
        Mount {
            source: "tmpfs",
            target: "/tmp",
            fstype: "tmpfs",
            target_mode: Some(nix::sys::stat::Mode::all()),
        },
        Mount {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            target_mode: Some(RXRXRX),
        },
        Mount {
            source: "debugfs",
            target: "/sys/kernel/debug",
            fstype: "debugfs",
            target_mode: None,
        },
        Mount {
            source: "bpffs",
            target: "/sys/fs/bpf",
            fstype: "bpf",
            target_mode: None,
        },
        Mount {
            source: "cgroup2",
            target: "/sys/fs/cgroup",
            fstype: "cgroup2",
            target_mode: None,
        },
    ] {
        match target_mode {
            None => {
                let st = nix::sys::stat::stat(target)
                    .map_err(|e| anyhow::anyhow!("stat({target}): {e}"))?;
                if !nix::sys::stat::SFlag::from_bits_truncate(st.st_mode)
                    .contains(nix::sys::stat::SFlag::S_IFDIR)
                {
                    anyhow::bail!("{target} is not a directory");
                }
            }
            Some(target_mode) => {
                nix::unistd::mkdir(target, target_mode)
                    .map_err(|e| anyhow::anyhow!("mkdir({target}): {e}"))?;
            }
        }
        nix::mount::mount(
            Some(source),
            target,
            Some(fstype),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| anyhow::anyhow!("mount({source}, {target}, {fstype}): {e}"))?;
    }

    // Kernel parameters are space-separated on a single line; the orchestrator
    // passes per-VM arguments (e.g. `--role server`) as `init.arg=` tokens.
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|e| anyhow::anyhow!("read(/proc/cmdline): {e}"))?;
    let args: Vec<std::ffi::OsString> = cmdline
        .split_whitespace()
        .filter_map(|p| p.strip_prefix("init.arg=").map(std::ffi::OsString::from))
        .collect();

    // By contract, every binary in /bin is run with the forwarded args.
    let mut errors = Vec::new();
    for entry in std::fs::read_dir("/bin").map_err(|e| anyhow::anyhow!("read_dir(/bin): {e}"))? {
        let path = entry
            .map_err(|e| anyhow::anyhow!("read_dir(/bin): {e}"))?
            .path();
        let mut cmd = std::process::Command::new(&path);
        cmd.args(&args)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LOG", "debug");
        println!("running {cmd:?}");
        match cmd.status() {
            Ok(status) if status.code() == Some(0) => {}
            Ok(status) => errors.push(anyhow::anyhow!("{cmd:?} failed: {status:?}")),
            Err(e) => errors.push(anyhow::anyhow!("failed to run {cmd:?}: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Errors(errors).into())
    }
}

fn main() {
    match run() {
        Ok(()) => println!("init: success"),
        Err(err) => {
            println!("{err:?}");
            println!("init: failure");
        }
    }
    let how = nix::sys::reboot::RebootMode::RB_POWER_OFF;
    match nix::sys::reboot::reboot(how) {
        Ok(infallible) => match infallible {},
        Err(err) => panic!("reboot({how:?}) failed: {err:?}"),
    }
}

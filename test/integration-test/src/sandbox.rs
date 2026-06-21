//! In-process stand-in for the systemd hardening, used by the integration test
//! because systemd-run is unavailable in the dut-distro VM / netns harness.
//!
//! Re-exec the daemon as a non-root uid/gid with exactly the ambient capability
//! set, NoNewPrivileges, and a tightened bounding set from
//! packaging/etherip-xdp@.service. Run as a wrapper subcommand (not pre_exec) so
//! it executes single-threaded, before the tokio runtime starts — fork-in-a-
//! multithreaded-process is not safe for the capability/uid juggling below.

use anyhow::Context as _;

const UID: u32 = 61729;
const GID: u32 = 61729;

/// Ambient capabilities, mirroring the unit's AmbientCapabilities.
const CAPS: &[caps::Capability] = &[
    caps::Capability::CAP_NET_ADMIN,
    caps::Capability::CAP_BPF,
    caps::Capability::CAP_PERFMON,
    caps::Capability::CAP_SYS_RESOURCE,
    caps::Capability::CAP_NET_RAW,
    caps::Capability::CAP_SYS_ADMIN,
];

/// uid/gid the daemon is dropped to; the harness chowns its config to this.
pub const DAEMON_UID: u32 = UID;
pub const DAEMON_GID: u32 = GID;

/// `argv` is the daemon command (`<path> [args...]`). Applies the sandbox and
/// execs it, so this returns only on error.
pub fn exec(argv: &[String]) -> anyhow::Result<()> {
    let first = argv.first().context("sandbox: missing daemon argv")?;
    // Open the binary while still privileged, then fexecve it after dropping to
    // the sandbox uid: a path component of the (root-built) binary may not be
    // traversable by that uid, but an already-open fd execs fine — the inode
    // itself is world-executable.
    let fd = nix::fcntl::open(
        first.as_str(),
        nix::fcntl::OFlag::O_RDONLY,
        nix::sys::stat::Mode::empty(),
    )
    .with_context(|| format!("sandbox: open {first}"))?;
    apply()?;
    let cargs: Vec<std::ffi::CString> = argv
        .iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()))
        .collect::<Result<_, _>>()
        .context("sandbox: argv has NUL")?;
    let env: Vec<std::ffi::CString> = std::env::vars_os()
        .map(|(k, v)| {
            let mut kv = k.into_encoded_bytes();
            kv.push(b'=');
            kv.extend_from_slice(v.into_encoded_bytes().as_slice());
            std::ffi::CString::new(kv)
        })
        .collect::<Result<_, _>>()
        .context("sandbox: env has NUL")?;
    nix::unistd::fexecve(fd, &cargs, &env).context("sandbox: fexecve")?;
    unreachable!()
}

fn apply() -> anyhow::Result<()> {
    let want: caps::CapsHashSet = CAPS.iter().copied().collect();

    // Done while still root (CAP_SETPCAP effective): shrink the bounding set and
    // seed the inheritable set so the ambient caps can be raised after setresuid.
    for c in caps::all() {
        if !want.contains(&c) {
            let _ = caps::drop(None, caps::CapSet::Bounding, c);
        }
    }
    caps::set(None, caps::CapSet::Inheritable, &want).context("set inheritable")?;
    caps::securebits::set_keepcaps(true).context("keepcaps")?;

    let uid = nix::unistd::Uid::from_raw(UID);
    let gid = nix::unistd::Gid::from_raw(GID);
    nix::unistd::setgroups(&[gid]).context("setgroups")?;
    nix::unistd::setresgid(gid, gid, gid).context("setresgid")?;
    nix::unistd::setresuid(uid, uid, uid).context("setresuid")?;

    // Ambient caps survive execve and become the new program's permitted+effective.
    for &c in CAPS {
        caps::raise(None, caps::CapSet::Ambient, c)
            .with_context(|| format!("raise ambient {c:?}"))?;
    }
    nix::sys::prctl::set_no_new_privs().context("no_new_privs")?;
    Ok(())
}

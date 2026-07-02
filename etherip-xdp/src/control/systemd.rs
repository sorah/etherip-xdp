//! Just enough systemd integration for graceful restart: `sd_notify(3)`
//! datagrams (including fd-store messages) and adoption of named descriptors
//! passed back via `$LISTEN_FDS`.
//!
//! The daemon parks its hidden-netns descriptor in the service manager's fd
//! store (`FDSTORE=1`) so the namespace survives a restart; on the next start
//! the store hands it back through the socket-activation protocol, mixed in
//! with any real socket fds. Everything here is hand-rolled on `nix` — the
//! protocol is a couple of env vars and unix datagrams, not worth a crate.
//!
//! # Why the env rewrite
//!
//! The varlink activation listener takes fd 3 unconditionally whenever
//! `LISTEN_FDS=1`, ignoring `LISTEN_FDNAMES`. Stored fds therefore must be
//! consumed and removed from the activation env *before* anything else looks at
//! it: [`take_inherited_fds`] takes the fds it recognises by name, compacts the
//! remaining ones back down to fd 3, and rewrites (or clears) the `LISTEN_*`
//! variables to describe only what is left.

/// `FDNAME=` under which the hidden-netns descriptor is stored.
pub const FDNAME_NETNS: &str = "netns";

/// First descriptor of the socket-activation block (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: std::os::fd::RawFd = 3;

/// Descriptors recovered from the fd store, already removed from the
/// activation env.
#[derive(Default)]
pub struct InheritedFds {
    pub netns: Option<std::os::fd::OwnedFd>,
}

/// Take the fd-store descriptors out of the `$LISTEN_FDS` block and rewrite the
/// activation env to describe only the remaining (socket-activation) fds.
///
/// Must run while the process is still single-threaded: it mutates environment
/// variables, and the whole point is to finish before the varlink server (or
/// anything else) inspects `LISTEN_FDS`.
///
/// # Safety
///
/// Calling this after other threads have started is undefined behaviour (env
/// mutation); the daemon calls it first thing in `main()`.
pub unsafe fn take_inherited_fds() -> anyhow::Result<InheritedFds> {
    let nfds: usize = match std::env::var("LISTEN_FDS") {
        Ok(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("bad LISTEN_FDS {v:?}: {e}"))?,
        Err(_) => return Ok(InheritedFds::default()),
    };
    // Addressed to a different process (stale env): not ours to consume.
    if std::env::var("LISTEN_PID").ok().as_deref()
        != Some(nix::unistd::getpid().to_string().as_str())
    {
        return Ok(InheritedFds::default());
    }
    let names = std::env::var("LISTEN_FDNAMES").ok();
    let assigned = assign_fd_names(nfds, names.as_deref());

    let mut inherited = InheritedFds::default();
    let mut keep: Vec<(std::os::fd::RawFd, String)> = Vec::new();
    for (fd, name) in assigned {
        if name == FDNAME_NETNS && inherited.netns.is_none() {
            inherited.netns = Some(relocate_above(fd, LISTEN_FDS_START + nfds as i32)?);
        } else {
            keep.push((fd, name));
        }
    }
    if inherited.netns.is_none() {
        // Nothing consumed; leave the env exactly as systemd set it.
        return Ok(inherited);
    }

    for (src, dst) in compaction_plan(&keep.iter().map(|(fd, _)| *fd).collect::<Vec<_>>()) {
        move_fd(src, dst)?;
    }
    // SAFETY: single-threaded per this function's contract.
    unsafe {
        if keep.is_empty() {
            std::env::remove_var("LISTEN_FDS");
            std::env::remove_var("LISTEN_PID");
            std::env::remove_var("LISTEN_FDNAMES");
        } else {
            std::env::set_var("LISTEN_FDS", keep.len().to_string());
            if names.is_some() {
                std::env::set_var(
                    "LISTEN_FDNAMES",
                    keep.iter()
                        .map(|(_, name)| name.as_str())
                        .collect::<Vec<_>>()
                        .join(":"),
                );
            }
        }
    }
    Ok(inherited)
}

/// Pair each fd of the activation block with its `LISTEN_FDNAMES` entry.
/// systemd names every fd, but tolerate a short or absent list (unnamed fds get
/// `""`, which never matches a store name).
fn assign_fd_names(nfds: usize, fdnames: Option<&str>) -> Vec<(std::os::fd::RawFd, String)> {
    let mut names = fdnames
        .unwrap_or("")
        .split(':')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.resize(nfds, String::new());
    names
        .into_iter()
        .take(nfds)
        .enumerate()
        .map(|(i, name)| (LISTEN_FDS_START + i as std::os::fd::RawFd, name))
        .collect()
}

/// dup2 moves `(src, dst)` compacting `keep` (ascending fd numbers out of the
/// activation block) down to a contiguous run from fd 3. In-order execution is
/// safe: every dst slot is either its own src or was vacated by an earlier move
/// or a consumed fd.
fn compaction_plan(keep: &[std::os::fd::RawFd]) -> Vec<(std::os::fd::RawFd, std::os::fd::RawFd)> {
    keep.iter()
        .enumerate()
        .map(|(i, &src)| (src, LISTEN_FDS_START + i as std::os::fd::RawFd))
        .filter(|(src, dst)| src != dst)
        .collect()
}

/// Move a consumed fd out of the activation block so the compaction moves can
/// never land on it. `F_DUPFD_CLOEXEC` also detaches it from the inheritable
/// block semantics (stored fds come back with CLOEXEC clear).
fn relocate_above(
    fd: std::os::fd::RawFd,
    min: std::os::fd::RawFd,
) -> anyhow::Result<std::os::fd::OwnedFd> {
    // SAFETY: fds in the activation block are inherited and owned by no other
    // wrapper in this process.
    let orig = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let dup = nix::fcntl::fcntl(&orig, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(min))
        .map_err(|e| anyhow::anyhow!("relocate inherited fd {fd}: {e}"))?;
    // `orig` drops here, freeing the original slot.
    // SAFETY: `dup` is a fresh descriptor we solely own.
    Ok(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(dup) })
}

/// `dup2(src, dst)` then close `src`. `dst` must be a vacated slot (see
/// [`compaction_plan`]); the dup2 result has CLOEXEC clear, as activation fds
/// must.
fn move_fd(src: std::os::fd::RawFd, dst: std::os::fd::RawFd) -> anyhow::Result<()> {
    // SAFETY: `src` is an inherited activation fd we own.
    let src = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(src) };
    // SAFETY: `dst` is a closed fd number; wrapping it only lends dup2 a target
    // slot, and the descriptor it opens is released via into_raw_fd below.
    let mut dst = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(dst) };
    nix::unistd::dup2(&src, &mut dst).map_err(|e| anyhow::anyhow!("compact inherited fd: {e}"))?;
    // The slot must stay open for whoever consumes the activation block later.
    let _ = <std::os::fd::OwnedFd as std::os::fd::IntoRawFd>::into_raw_fd(dst);
    Ok(())
}

/// Send an `sd_notify(3)` state datagram. A no-op without `$NOTIFY_SOCKET`
/// (running outside systemd).
pub fn notify(state: &str) -> anyhow::Result<()> {
    notify_impl(state, None)
}

/// [`notify`] with a descriptor attached via `SCM_RIGHTS` (fd-store messages).
pub fn notify_with_fd(state: &str, fd: std::os::fd::BorrowedFd<'_>) -> anyhow::Result<()> {
    notify_impl(state, Some(fd))
}

/// Park the hidden-netns descriptor in the service manager's fd store, where it
/// survives daemon restarts (and crashes).
pub fn store_netns_fd(fd: std::os::fd::BorrowedFd<'_>) -> anyhow::Result<()> {
    notify_with_fd(&format!("FDSTORE=1\nFDNAME={FDNAME_NETNS}"), fd)
}

/// Drop the stored netns descriptor (full teardown: the namespace should die
/// with this daemon, not be revived by the next start).
pub fn remove_stored_netns() -> anyhow::Result<()> {
    notify(&format!("FDSTOREREMOVE=1\nFDNAME={FDNAME_NETNS}"))
}

fn notify_impl(state: &str, fd: Option<std::os::fd::BorrowedFd<'_>>) -> anyhow::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        log::debug!("NOTIFY_SOCKET unset; dropping sd_notify {state:?}");
        return Ok(());
    };
    let addr = notify_addr(&path)?;
    let sock = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| anyhow::anyhow!("notify socket: {e}"))?;
    let iov = [std::io::IoSlice::new(state.as_bytes())];
    let fds = fd.map(|fd| [std::os::fd::AsRawFd::as_raw_fd(&fd)]);
    let cmsgs = match &fds {
        Some(fds) => vec![nix::sys::socket::ControlMessage::ScmRights(fds)],
        None => vec![],
    };
    nix::sys::socket::sendmsg(
        std::os::fd::AsRawFd::as_raw_fd(&sock),
        &iov,
        &cmsgs,
        nix::sys::socket::MsgFlags::empty(),
        Some(&addr),
    )
    .map_err(|e| anyhow::anyhow!("sd_notify {state:?}: {e}"))?;
    Ok(())
}

/// `NOTIFY_SOCKET` is a filesystem path, or abstract-namespace when prefixed
/// with `@`.
fn notify_addr(path: &std::ffi::OsStr) -> anyhow::Result<nix::sys::socket::UnixAddr> {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_bytes();
    match bytes.split_first() {
        Some((b'@', rest)) => nix::sys::socket::UnixAddr::new_abstract(rest),
        _ => nix::sys::socket::UnixAddr::new(bytes),
    }
    .map_err(|e| anyhow::anyhow!("bad NOTIFY_SOCKET {path:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(pairs: &[(i32, &str)]) -> Vec<(std::os::fd::RawFd, String)> {
        pairs.iter().map(|&(fd, n)| (fd, n.to_owned())).collect()
    }

    #[test]
    fn assign_pairs_fds_with_colon_separated_names() {
        assert_eq!(
            assign_fd_names(3, Some("varlink:netns:other")),
            named(&[(3, "varlink"), (4, "netns"), (5, "other")])
        );
    }

    #[test]
    fn assign_pads_missing_or_absent_names() {
        // A short list (or none at all) leaves the tail unnamed rather than
        // shifting names onto the wrong fd.
        assert_eq!(
            assign_fd_names(2, Some("varlink")),
            named(&[(3, "varlink"), (4, "")])
        );
        assert_eq!(assign_fd_names(2, None), named(&[(3, ""), (4, "")]));
        assert_eq!(assign_fd_names(0, Some("ghost")), named(&[]));
    }

    #[test]
    fn assign_ignores_surplus_names() {
        assert_eq!(
            assign_fd_names(1, Some("varlink:netns")),
            named(&[(3, "varlink")])
        );
    }

    #[test]
    fn compaction_is_noop_when_already_contiguous() {
        assert_eq!(compaction_plan(&[3, 4]), vec![]);
        assert_eq!(compaction_plan(&[]), vec![]);
    }

    #[test]
    fn compaction_closes_gaps_in_order() {
        // netns was fd 3: everything shifts down one.
        assert_eq!(compaction_plan(&[4, 5]), vec![(4, 3), (5, 4)]);
        // netns was fd 4: only the tail moves.
        assert_eq!(compaction_plan(&[3, 5]), vec![(5, 4)]);
    }
}

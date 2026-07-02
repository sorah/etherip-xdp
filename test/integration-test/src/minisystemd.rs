//! Just-enough systemd for the scenario: a `NOTIFY_SOCKET` datagram listener
//! implementing the fd store (`FDSTORE=1` / `FDSTOREREMOVE=1` with
//! `SCM_RIGHTS`), plus a wrapper that re-execs the daemon with stored fds
//! passed back through the socket-activation protocol (`LISTEN_FDS`,
//! `LISTEN_FDNAMES`, `LISTEN_PID`). Lets the test drive the daemon's graceful
//! restart exactly the way `etherip-xdp@.service` would, without systemd in
//! the VM/netns.

/// First descriptor of the socket-activation block (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: std::os::fd::RawFd = 3;

#[derive(Default)]
struct Store {
    fds: std::sync::Mutex<std::collections::HashMap<String, std::os::fd::OwnedFd>>,
    removed: std::sync::Mutex<std::collections::HashSet<String>>,
    stop: std::sync::atomic::AtomicBool,
}

/// A `NOTIFY_SOCKET` server holding an fd store, one listener thread behind it.
pub struct NotifyServer {
    store: std::sync::Arc<Store>,
    path: std::path::PathBuf,
}

impl NotifyServer {
    /// Bind `path` and start the listener thread. The socket is world-writable
    /// so the sandboxed (non-root) daemon can send to it.
    pub fn spawn(path: &std::path::Path) -> anyhow::Result<Self> {
        let _ = std::fs::remove_file(path);
        let sock = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Datagram,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|e| anyhow::anyhow!("notify socket: {e}"))?;
        let addr = nix::sys::socket::UnixAddr::new(path)
            .map_err(|e| anyhow::anyhow!("notify addr: {e}"))?;
        nix::sys::socket::bind(std::os::fd::AsRawFd::as_raw_fd(&sock), &addr)
            .map_err(|e| anyhow::anyhow!("bind {}: {e}", path.display()))?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o666))
            .map_err(|e| anyhow::anyhow!("chmod {}: {e}", path.display()))?;
        // Wake up periodically so `stop` is honoured.
        nix::sys::socket::setsockopt(
            &sock,
            nix::sys::socket::sockopt::ReceiveTimeout,
            &nix::sys::time::TimeVal::new(0, 200_000),
        )
        .map_err(|e| anyhow::anyhow!("notify SO_RCVTIMEO: {e}"))?;

        let store = std::sync::Arc::new(Store::default());
        let thread_store = store.clone();
        std::thread::spawn(move || listen_loop(sock, &thread_store));
        Ok(NotifyServer {
            store,
            path: path.to_path_buf(),
        })
    }

    /// The value to put in the daemon's `NOTIFY_SOCKET`.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Wait until the daemon sends `FDSTOREREMOVE=1` for `name`.
    pub async fn wait_removed(&self, name: &str, timeout: std::time::Duration) -> bool {
        self.wait(timeout, || {
            self.store.removed.lock().unwrap().contains(name)
        })
        .await
    }

    async fn wait(&self, timeout: std::time::Duration, check: impl Fn() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if check() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }
}

impl Drop for NotifyServer {
    fn drop(&mut self) {
        self.store
            .stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn listen_loop(sock: std::os::fd::OwnedFd, store: &Store) {
    let mut buf = [0u8; 4096];
    let mut cmsgspace = nix::cmsg_space!([std::os::fd::RawFd; 8]);
    while !store.stop.load(std::sync::atomic::Ordering::SeqCst) {
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let (len, fds) = {
            let msg = match nix::sys::socket::recvmsg::<nix::sys::socket::UnixAddr>(
                std::os::fd::AsRawFd::as_raw_fd(&sock),
                &mut iov,
                Some(&mut cmsgspace),
                nix::sys::socket::MsgFlags::empty(),
            ) {
                Ok(msg) => msg,
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    eprintln!("[e2e] notify recvmsg: {e}");
                    return;
                }
            };
            let mut fds = Vec::new();
            for cmsg in msg.cmsgs().into_iter().flatten() {
                if let nix::sys::socket::ControlMessageOwned::ScmRights(raw) = cmsg {
                    for fd in raw {
                        // SAFETY: SCM_RIGHTS descriptors are freshly installed
                        // into this process and owned by nobody else.
                        fds.push(unsafe {
                            <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd)
                        });
                    }
                }
            }
            (msg.bytes, fds)
        };
        handle_datagram(&buf[..len], fds, store);
    }
}

fn handle_datagram(payload: &[u8], mut fds: Vec<std::os::fd::OwnedFd>, store: &Store) {
    let text = String::from_utf8_lossy(payload);
    let mut fdstore = false;
    let mut fdremove = false;
    let mut name = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("FDSTORE", "1")) => fdstore = true,
            Some(("FDSTOREREMOVE", "1")) => fdremove = true,
            Some(("FDNAME", n)) => name = Some(n.to_owned()),
            _ => {}
        }
    }
    let Some(name) = name else { return };
    if fdremove {
        store.fds.lock().unwrap().remove(&name);
        store.removed.lock().unwrap().insert(name);
    } else if fdstore && !fds.is_empty() {
        // One fd per message in our protocol; surplus descriptors just close.
        store.fds.lock().unwrap().insert(name, fds.remove(0));
    }
}

// ---- respawn plumbing: pass stored fds back via LISTEN_FDS ----

/// Prepare `(fd, name)` pairs for inheritance: clear CLOEXEC so they survive
/// the spawn, and render the `__listenfds` wrapper arguments.
pub fn listenfds_args(fds: &[(std::os::fd::RawFd, &str)]) -> anyhow::Result<Vec<String>> {
    let mut args = Vec::new();
    for &(fd, name) in fds {
        // SAFETY: borrowing an fd we hold open for the duration of the call.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        nix::fcntl::fcntl(
            borrowed,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .map_err(|e| anyhow::anyhow!("clear CLOEXEC on fd {fd}: {e}"))?;
        args.push("--fd".to_owned());
        args.push(format!("{fd}:{name}"));
    }
    Ok(args)
}

/// `__listenfds` wrapper: runs in the child before the daemon. Moves the
/// inherited fds to the activation block (fd 3..), sets
/// `LISTEN_FDS`/`LISTEN_FDNAMES`/`LISTEN_PID` (exec keeps the pid, so getpid
/// here is correct), then execs the daemon — via the sandbox when requested.
///
/// Usage: `__listenfds [--fd N:NAME]... [--sandbox] <daemon> [args...]`
pub fn exec_with_listen_fds(argv: &[String]) -> anyhow::Result<()> {
    let mut fds: Vec<(std::os::fd::RawFd, String)> = Vec::new();
    let mut rest = argv;
    let mut sandbox = false;
    loop {
        match rest.split_first() {
            Some((flag, tail)) if flag == "--fd" => {
                let (spec, tail) = tail
                    .split_first()
                    .ok_or_else(|| anyhow::anyhow!("--fd needs N:NAME"))?;
                let (fd, name) = spec
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("bad --fd {spec:?}"))?;
                fds.push((fd.parse()?, name.to_owned()));
                rest = tail;
            }
            Some((flag, tail)) if flag == "--sandbox" => {
                sandbox = true;
                rest = tail;
            }
            _ => break,
        }
    }
    anyhow::ensure!(!rest.is_empty(), "__listenfds: missing daemon argv");

    // Two phases so a source fd can never collide with a target slot: park
    // everything above the block, then dup2 down to 3.. in order.
    let parked = fds
        .iter()
        .map(|&(fd, _)| {
            // SAFETY: inherited fds owned by no wrapper in this process.
            let orig = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
            nix::fcntl::fcntl(
                &orig,
                nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(
                    LISTEN_FDS_START + fds.len() as std::os::fd::RawFd,
                ),
            )
            .map_err(|e| anyhow::anyhow!("park fd {fd}: {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    for (i, &parked_fd) in parked.iter().enumerate() {
        let dst_raw = LISTEN_FDS_START + i as std::os::fd::RawFd;
        // SAFETY: parked_fd is the descriptor we just created above.
        let src =
            unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(parked_fd) };
        // SAFETY: dst_raw is 3..3+n, vacated by the parking pass (or stale junk
        // from the parent, which the activation block overrides anyway).
        let mut dst =
            unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(dst_raw) };
        nix::unistd::dup2(&src, &mut dst).map_err(|e| anyhow::anyhow!("dup2 to {dst_raw}: {e}"))?;
        // Stays open for the daemon's activation block.
        let _ = <std::os::fd::OwnedFd as std::os::fd::IntoRawFd>::into_raw_fd(dst);
    }

    // No fds → no activation block at all (systemd omits the env entirely).
    if !fds.is_empty() {
        let names = fds.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>();
        // SAFETY: single-threaded wrapper path (pre-clap, pre-runtime).
        unsafe {
            std::env::set_var("LISTEN_FDS", fds.len().to_string());
            std::env::set_var("LISTEN_FDNAMES", names.join(":"));
            std::env::set_var("LISTEN_PID", nix::unistd::getpid().to_string());
        }
    }

    if sandbox {
        return crate::sandbox::exec(rest);
    }
    let cargs = rest
        .iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("argv has NUL: {e}"))?;
    nix::unistd::execv(&cargs[0], &cargs).map_err(|e| anyhow::anyhow!("execv: {e}"))?;
    unreachable!()
}

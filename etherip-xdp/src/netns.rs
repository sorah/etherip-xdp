//! A daemon-private, anonymous network namespace that hides the `<name>-xdp`
//! veth peers from userland.
//!
//! The user-facing `<name>` end stays in the host namespace where operators
//! expect it; only its peer — an internal artefact of driving encap through XDP —
//! is moved out of view. The namespace is anonymous: it is pinned by an open file
//! descriptor rather than a bind-mount under `/run/netns`, so it never appears in
//! `ip netns list` and is destroyed automatically when the daemon exits and the
//! descriptor closes.
//!
//! # Why a dedicated thread
//!
//! `unshare`/`setns` change the *calling thread's* namespace membership. The
//! daemon runs a multi-threaded tokio runtime in the host namespace, so the
//! switch must never happen on a runtime worker. Both [`NetNs::create`] and
//! [`NetNs::run_in`] therefore perform the switch on a short-lived,
//! purpose-spawned OS thread: the namespace work is fully contained on a thread
//! the runtime never touches, and that thread exits as soon as the work is done.

/// An anonymous network namespace, kept alive by an open descriptor.
pub struct NetNs {
    fd: std::os::fd::OwnedFd,
}

impl NetNs {
    /// Create a fresh anonymous network namespace and return a handle that pins
    /// it alive. The `unshare` runs on a throwaway thread so the daemon's own
    /// threads stay in the host namespace; the descriptor captured from that
    /// thread keeps the new namespace alive after the thread exits (descriptors
    /// are process-wide, not per-thread).
    pub fn create() -> anyhow::Result<Self> {
        let fd = std::thread::spawn(|| -> anyhow::Result<std::os::fd::OwnedFd> {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
                .map_err(|e| anyhow::anyhow!("unshare(CLONE_NEWNET): {e}"))?;
            let f = std::fs::File::open("/proc/thread-self/ns/net")
                .map_err(|e| anyhow::anyhow!("open hidden netns descriptor: {e}"))?;
            Ok(std::os::fd::OwnedFd::from(f))
        })
        .join()
        .map_err(|_| anyhow::anyhow!("hidden-netns creation thread panicked"))??;
        Ok(NetNs { fd })
    }

    /// The raw descriptor of the namespace, for `setns_by_fd` when moving a link
    /// into it (see [`crate::netlink::Netlink::move_link_to_netns`]).
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.fd)
    }

    /// Run `f` with the calling code switched into this namespace.
    ///
    /// The work runs on a dedicated, short-lived thread that `setns`es into the
    /// namespace; the daemon's tokio worker threads are never moved and stay in
    /// the host namespace. The thread exits immediately after `f`, so its
    /// namespace membership is dropped without an explicit restore. The thread is
    /// scoped, so `f` may borrow caller state (e.g. the loaded eBPF object) for
    /// attaches and map updates that must resolve ifindexes against this
    /// namespace.
    pub fn run_in<R, F>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce() -> anyhow::Result<R> + Send,
        R: Send,
    {
        std::thread::scope(|s| {
            s.spawn(|| -> anyhow::Result<R> {
                nix::sched::setns(&self.fd, nix::sched::CloneFlags::CLONE_NEWNET)
                    .map_err(|e| anyhow::anyhow!("setns into hidden netns: {e}"))?;
                f()
            })
            .join()
            .map_err(|_| anyhow::anyhow!("hidden-netns worker thread panicked"))?
        })
    }
}

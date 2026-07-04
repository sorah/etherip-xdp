//! Tunnel lifecycle and the reload manager.
//!
//! The [`Manager`] owns the loaded eBPF object, a netlink handle, the external
//! interface identity, and the set of running tunnels. Each tunnel owns a veth
//! pair (`<name>` user end, `<name>-xdp` peer) with `xdp_encap` on the peer and
//! `xdp_pass` on the user end; the shared `xdp_decap` on the uplink handles decap
//! for all tunnels.

const IFNAMSIZ: usize = 15;
const PEER_SUFFIX: &str = "-xdp";

/// Identity of the shared external (uplink) interface.
#[derive(Debug, Clone)]
pub struct ExternalInterface {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub mtu: u32,
}

/// A tunnel that is currently set up in the data plane.
pub struct RunningTunnel {
    spec: crate::control::config::TunnelSpec,
    /// Absolute path of the drop-in config file this tunnel was loaded from, if
    /// known (reported over the management interface). `None` for tunnels added
    /// other than from a file.
    config_path: Option<std::path::PathBuf>,
    peer_index: u32,
    tunnel_mtu: i32,
    config: etherip_xdp_common::TunnelConfig,
    decap_key: etherip_xdp_common::DecapKey,
    /// Outer source address currently in use, or `None` while the tunnel is
    /// pending (auto-select has not resolved a source yet). When `None`, the
    /// encap/decap map entries are deliberately withheld so the data path never
    /// encapsulates with a bogus source.
    effective_src: Option<std::net::Ipv6Addr>,
    /// Resolved next hop (gateway, or the remote itself when on-link); `None`
    /// while unresolved. Diagnostic only — reported over the management
    /// interface; the data path uses `config.dst_mac`.
    next_hop: Option<std::net::Ipv6Addr>,
    /// Whether the resolved next hop is the remote endpoint itself (on-link).
    next_hop_on_link: bool,
    /// Observed kernel neighbour state for the next hop, if looked up.
    neigh_state: Option<crate::control::netlink::NeighState>,
    encap_link: crate::control::bpf::Attachment,
    pass_link: crate::control::bpf::Attachment,
}

fn peer_name(name: &str) -> String {
    format!("{name}{PEER_SUFFIX}")
}

fn validate_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("tunnel name must not be empty");
    }
    if name.len() + PEER_SUFFIX.len() > IFNAMSIZ {
        anyhow::bail!(
            "tunnel name {name:?} too long: the peer {:?} exceeds {IFNAMSIZ} chars",
            peer_name(name)
        );
    }
    Ok(())
}

/// The set of config changes between the running tunnels and a new config.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<crate::control::config::TunnelSpec>,
    pub removed: Vec<String>,
    pub updated: Vec<crate::control::config::TunnelSpec>,
}

/// Compute the diff between currently-running specs and the newly-loaded specs.
/// Pure, so it is unit-tested. Tunnels are keyed by name; a name present in both
/// with a changed spec is an in-place update (never needs veth recreation since
/// the veth name is the key).
pub fn diff_specs(
    old: &std::collections::HashMap<String, crate::control::config::TunnelSpec>,
    new: &[crate::control::config::TunnelSpec],
) -> Diff {
    let mut diff = Diff::default();
    let new_names: std::collections::HashSet<&str> = new.iter().map(|s| s.name.as_str()).collect();
    for spec in new {
        match old.get(&spec.name) {
            None => diff.added.push(spec.clone()),
            Some(existing) if existing != spec => diff.updated.push(spec.clone()),
            Some(_) => {}
        }
    }
    for name in old.keys() {
        if !new_names.contains(name.as_str()) {
            diff.removed.push(name.clone());
        }
    }
    diff.removed.sort();
    Diff {
        added: diff.added,
        removed: diff.removed,
        updated: diff.updated,
    }
}

/// Owns the data plane and drives tunnel lifecycle + reloads.
pub struct Manager {
    bpf: crate::control::bpf::Bpf,
    nl: crate::control::netlink::Netlink,
    external: ExternalInterface,
    external_decap_link: crate::control::bpf::Attachment,
    /// bpffs pin layout when pinning is active; `None` when the pin root is
    /// unavailable (no bpffs, no packaging dir) and the data plane is
    /// process-lifetime only.
    pins: Option<crate::control::bpf::PinPaths>,
    config_dirs: Vec<std::path::PathBuf>,
    /// When `Some`, each tunnel's `<name>-xdp` peer is moved into this private
    /// anonymous namespace to hide it from userland; when `None`, peers stay in
    /// the host namespace alongside the user-facing ends.
    netns: Option<crate::control::netns::NetNs>,
    /// Whether the hidden netns descriptor is parked in the systemd fd store,
    /// i.e. survives this process.
    netns_stored: bool,
    tunnels: std::collections::HashMap<String, RunningTunnel>,
}

/// Wait for the external (uplink) interface to appear, retrying with capped
/// backoff. The underlay may not exist yet at boot (slow driver probe, hotplug,
/// netns setup), so the daemon waits rather than crash-looping. No signal
/// handlers are installed during `start`, so SIGINT/SIGTERM (`systemctl stop`)
/// still terminate the process while it waits.
async fn wait_for_external(
    nl: &crate::control::netlink::Netlink,
    name: &str,
) -> anyhow::Result<crate::control::netlink::LinkInfo> {
    const MAX_BACKOFF_SECS: u64 = 5;
    let mut attempt: u64 = 0;
    loop {
        // A genuine netlink error still propagates; only "not found" (None) waits.
        if let Some(info) = nl.link_info(name).await? {
            if attempt > 0 {
                log::info!(
                    "external interface {name} appeared (ifindex {})",
                    info.index
                );
            }
            return Ok(info);
        }
        if attempt == 0 {
            log::warn!("external interface {name} not found; waiting for it to appear");
        }
        attempt += 1;
        tokio::time::sleep(std::time::Duration::from_secs(
            attempt.min(MAX_BACKOFF_SECS),
        ))
        .await;
    }
}

/// State recovered by `main()` for a possible graceful restart.
pub struct RestartContext {
    /// The hidden-netns descriptor handed back by the systemd fd store.
    pub netns_fd: Option<std::os::fd::OwnedFd>,
    /// `false` disables pinning and adoption entirely
    /// (`--disable-graceful-restart`): every start attaches fresh, every exit
    /// tears down.
    pub graceful: bool,
}

impl Manager {
    /// Load the eBPF object, attach the main program to the uplink, and create
    /// all tunnels from the config directory — adopting whatever a previous
    /// instance left pinned instead of recreating it, so a daemon restart
    /// does not interrupt the data plane.
    pub async fn start(
        external_name: String,
        config_dirs: Vec<std::path::PathBuf>,
        hide_peer: bool,
        ctx: RestartContext,
    ) -> anyhow::Result<Self> {
        let nl = crate::control::netlink::Netlink::connect()?;
        let RestartContext { netns_fd, graceful } = ctx;

        // Pin the data-plane maps when the packaged bpffs directory is
        // available; anything less (no bpffs, missing tmpfiles dir, no group
        // access) degrades to a process-lifetime data plane.
        let pins = if graceful {
            let pins = crate::control::bpf::PinPaths::new(&external_name);
            match pins.ensure_dirs() {
                Ok(()) => Some(pins),
                Err(e) => {
                    log::warn!("bpffs pinning unavailable: {e:#}");
                    None
                }
            }
        } else {
            // Pinning disabled: also drop whatever an earlier (graceful) run
            // left behind, so nothing keeps running unowned.
            let stale = crate::control::bpf::PinPaths::new(&external_name);
            if let Err(e) = stale.remove_all() {
                log::warn!("remove pins left by a previous run: {e:#}");
            }
            None
        };

        let mut adoptable = false;
        if let Some(pins) = &pins {
            match crate::control::bpf::classify_pins(pins) {
                crate::control::bpf::PinState::Absent => {}
                crate::control::bpf::PinState::Compatible => adoptable = true,
                crate::control::bpf::PinState::Mismatch => {
                    // Partial pins (mid-setup crash) or another build's layout:
                    // not reusable, so release the kernel objects, start clean.
                    log::warn!(
                        "discarding incomplete or incompatible pins under {}",
                        pins.base().display()
                    );
                    pins.remove_all()?;
                    pins.ensure_dirs()?;
                }
            }
        }
        let mut bpf = crate::control::bpf::Bpf::load(pins.as_ref())?;

        // With compatible pins in hand, decide what to do about the attached
        // programs: identical object -> leave them running, otherwise swap
        // each adopted link's program atomically (BPF_LINK_UPDATE).
        let adopt_mode = if adoptable {
            match bpf.read_state() {
                Some(prev) if prev.obj_digest == crate::control::bpf::object_digest() => {
                    log::info!("eBPF object unchanged; leaving attached programs in place");
                    Some(crate::control::bpf::AdoptMode::SkipIdentical)
                }
                Some(prev) => {
                    log::info!(
                        "eBPF object changed ({} -> {}); updating attached programs atomically",
                        prev.pkg_version_str(),
                        env!("CARGO_PKG_VERSION")
                    );
                    Some(crate::control::bpf::AdoptMode::UpdateLinks)
                }
                None => Some(crate::control::bpf::AdoptMode::UpdateLinks),
            }
        } else {
            None
        };

        // The hidden netns: prefer the descriptor preserved in the fd store
        // (its veth peers are what the adopted links are attached to); anything
        // else gets a fresh namespace, parked in the store for the next
        // instance when the rest of the data plane is also restart-safe.
        let mut netns_stored = false;
        let netns = if hide_peer {
            let adopted = match netns_fd {
                Some(fd) if adopt_mode.is_some() => {
                    match crate::control::netns::NetNs::from_fd(fd) {
                        Ok(ns) => Some(ns),
                        Err(e) => {
                            log::warn!("stored netns fd unusable: {e:#}");
                            None
                        }
                    }
                }
                Some(_) => None, // pins gone: the old namespace's peers are useless
                None => None,
            };
            match adopted {
                Some(ns) => {
                    log::info!("adopted the hidden netns from the fd store");
                    netns_stored = true;
                    Some(ns)
                }
                None => {
                    // Drop a discarded stored fd before storing a fresh one
                    // (FileDescriptorStoreMax=1).
                    if let Err(e) = crate::control::systemd::remove_stored_netns() {
                        log::debug!("remove stored netns fd: {e:#}");
                    }
                    let ns = crate::control::netns::NetNs::create()?;
                    log::info!("hiding veth peers in a private anonymous network namespace");
                    if pins.is_some() && crate::control::systemd::notify_socket_available() {
                        match crate::control::systemd::store_netns_fd(ns.borrow_fd()) {
                            Ok(()) => netns_stored = true,
                            Err(e) => log::warn!("store netns fd: {e:#}"),
                        }
                    }
                    Some(ns)
                }
            }
        } else {
            if netns_fd.is_some()
                && let Err(e) = crate::control::systemd::remove_stored_netns()
            {
                log::debug!("remove stored netns fd: {e:#}");
            }
            log::info!("keeping veth peers in the host namespace (--disable-veth-peer-netns)");
            None
        };

        // Tolerate starting before the underlay is ready: wait for the uplink to
        // appear instead of crash-looping.
        let info = wait_for_external(&nl, &external_name).await?;
        let external = ExternalInterface {
            name: external_name,
            index: info.index,
            mac: info.mac,
            mtu: info.mtu,
        };
        log::info!(
            "external interface {} (ifindex {}, mac {}, mtu {})",
            external.name,
            external.index,
            fmt_mac(&external.mac),
            external.mtu
        );

        // The shared decap program + redirect target for the uplink. The
        // devmap re-insert is idempotent; the kernel already dropped the entry
        // if the device bounced while we were down.
        bpf.add_uplink_redirect(external.index)?;
        let decap_pin = pins.as_ref().map(|p| p.decap_link());
        let external_decap_link = match (adopt_mode, &decap_pin) {
            (Some(mode), Some(pin)) if pin.exists() => {
                match bpf.adopt_decap(pin, info.xdp_prog_id, mode) {
                    Ok(att) => {
                        log::info!("adopted the uplink decap link");
                        att
                    }
                    Err(e) => {
                        // Defunct (uplink recreated while down) or update
                        // failure: destroy the old link so a fresh attach
                        // doesn't hit EBUSY. Decap was already dead here, so
                        // this adds no interruption.
                        log::warn!("adopt uplink decap link: {e:#}; reattaching");
                        let _ = std::fs::remove_file(pin);
                        bpf.attach_decap(&external.name, decap_pin.as_deref())?
                    }
                }
            }
            _ => bpf.attach_decap(&external.name, decap_pin.as_deref())?,
        };

        let mut manager = Manager {
            bpf,
            nl,
            external,
            external_decap_link,
            pins,
            config_dirs,
            netns,
            netns_stored,
            tunnels: std::collections::HashMap::new(),
        };

        let specs = crate::control::config::load_dirs(&manager.config_dirs).await?;
        if specs.is_empty() {
            log::warn!(
                "no tunnel configs found in {}",
                manager.config_dirs_display()
            );
        }
        if adopt_mode.is_some() {
            // Config may have changed while down: pinned tunnels no longer
            // configured are torn down before their names can collide.
            let configured: std::collections::HashSet<String> =
                specs.iter().map(|(_, s)| s.name.clone()).collect();
            manager.remove_orphan_tunnels(&configured).await;
        }
        for (path, spec) in specs {
            let adopted = match adopt_mode {
                Some(mode) => manager
                    .adopt_tunnel(mode, Some(path.clone()), &spec)
                    .await
                    .unwrap_or_else(|e| {
                        log::warn!("tunnel {}: adoption failed: {e:#}", spec.name);
                        false
                    }),
                None => false,
            };
            if !adopted && let Err(e) = manager.add_tunnel(Some(path), spec).await {
                log::error!("failed to create tunnel: {e:#}");
            }
        }
        if adopt_mode.is_some() {
            manager.sweep_stale_map_entries();
        }
        // Stamp the pins as belonging to this build only now, with the data
        // plane fully set up under it — a crash mid-adoption must re-run the
        // program swap, never masquerade as "identical".
        if let Err(e) = manager.bpf.write_state() {
            log::warn!("record pinned state: {e:#}");
        }
        Ok(manager)
    }

    /// Whether the data plane can outlive this process: pinned maps and
    /// bpf_link attachments, plus the hidden netns parked in the fd store
    /// (or no hidden netns at all).
    pub fn is_graceful(&self) -> bool {
        self.pins.is_some()
            && !self.bpf.is_degraded()
            && (self.netns.is_none() || self.netns_stored)
    }

    /// Exit without teardown (SIGUSR2, i.e. `systemctl restart`): drop every
    /// in-process handle while the pinned links and maps — and the netns fd
    /// parked in the service manager — keep packets flowing until the next
    /// instance adopts them. Callers gate on [`Self::is_graceful`].
    pub fn abandon(self) {
        log::info!("leaving the data plane attached for the next daemon instance");
    }

    /// Render the searched config directories for log messages.
    fn config_dirs_display(&self) -> String {
        self.config_dirs
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn tunnel_mtu(&self, spec: &crate::control::config::TunnelSpec) -> i32 {
        match spec.mtu {
            Some(m) => m as i32,
            None => self.external.mtu as i32 - etherip_xdp_common::OUTER_OVERHEAD as i32,
        }
    }

    fn build_config(
        &self,
        spec: &crate::control::config::TunnelSpec,
        peer_index: u32,
        src: std::net::Ipv6Addr,
        tunnel_mac: [u8; 6],
        dst_mac: [u8; 6],
        tunnel_mtu: i32,
    ) -> etherip_xdp_common::TunnelConfig {
        let (mss4, mss6) = spec.mss.resolve(tunnel_mtu);
        etherip_xdp_common::TunnelConfig {
            src_addr: src.octets(),
            dst_addr: spec.remote.octets(),
            internal_ifindex: peer_index,
            external_ifindex: self.external.index,
            tunnel_mac,
            external_mac: self.external.mac,
            dst_mac,
            src_plen: 128,
            dst_plen: 128,
            mss_clamp_ipv4: mss4,
            mss_clamp_ipv6: mss6,
        }
    }

    /// Resolve the local MAC the user-facing interface should present, given its
    /// current (kernel-assigned) address. `Auto` keeps the current address;
    /// `Inherit`/`Explicit` force the external device's or a configured address.
    fn resolve_tunnel_mac(
        &self,
        spec: &crate::control::config::TunnelSpec,
        current: [u8; 6],
    ) -> [u8; 6] {
        match spec.mac {
            crate::control::config::MacConfig::Auto => current,
            crate::control::config::MacConfig::Inherit => self.external.mac,
            crate::control::config::MacConfig::Explicit(mac) => mac,
        }
    }

    fn decap_key(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr) -> etherip_xdp_common::DecapKey {
        etherip_xdp_common::DecapKey {
            remote: dst.octets(),
            local: src.octets(),
        }
    }

    /// Warn when an explicitly-configured source address is not assigned to the
    /// host. The source is still used (operator intent), but an unassigned source
    /// usually means a typo or a since-removed address and tends to be dropped by
    /// reverse-path filtering. Auto-selected sources are always local, so skip.
    async fn warn_if_src_unassigned(&self, spec: &crate::control::config::TunnelSpec) {
        let Some(src) = spec.local else { return };
        match self.nl.is_local_address(src).await {
            Ok(true) => {}
            Ok(false) => log::warn!(
                "tunnel {}: configured source {src} is not assigned to any local \
                 interface; using it anyway (packets may be dropped by reverse-path filtering)",
                spec.name
            ),
            Err(e) => log::debug!(
                "tunnel {}: could not verify source {src} is local: {e}",
                spec.name
            ),
        }
    }

    /// Bring the freshly-created peer up at `mtu`, attach the encap program, and
    /// register its decap redirect target. Returns the peer's ifindex (in the
    /// namespace it ends up in) and the encap link. With hiding enabled the peer
    /// is first moved into the private namespace and all of this runs there, so
    /// the attach and the devmap insert — both of which resolve the ifindex
    /// against the calling namespace — see the peer; otherwise it stays in the
    /// host namespace.
    async fn setup_peer(
        &mut self,
        peer: &str,
        mtu: u32,
        encap_pin: Option<std::path::PathBuf>,
    ) -> anyhow::Result<(u32, crate::control::bpf::Attachment)> {
        let peer_host_index = self
            .nl
            .index_of(peer)
            .await?
            .ok_or_else(|| anyhow::anyhow!("veth peer {peer} missing after creation"))?;

        match &self.netns {
            None => {
                self.nl.set_mtu_up(peer_host_index, mtu).await?;
                let encap_link = self.bpf.attach_encap(peer, encap_pin.as_deref())?;
                self.bpf.add_peer_redirect(peer_host_index)?;
                Ok((peer_host_index, encap_link))
            }
            Some(ns) => {
                self.nl
                    .move_link_to_netns(peer_host_index, ns.as_raw_fd())
                    .await?;
                let bpf = &mut self.bpf;
                ns.run_in(|| {
                    // A current-thread runtime drives netlink inside the namespace;
                    // the daemon's main runtime stays in the host namespace. The
                    // peer was reassigned a fresh ifindex by the move, so re-resolve
                    // it here.
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| anyhow::anyhow!("build hidden-netns runtime: {e}"))?;
                    let peer_index = rt.block_on(async {
                        let nl = crate::control::netlink::Netlink::connect()?;
                        let idx = nl.index_of(peer).await?.ok_or_else(|| {
                            anyhow::anyhow!("veth peer {peer} missing in hidden netns")
                        })?;
                        nl.set_mtu_up(idx, mtu).await?;
                        anyhow::Ok(idx)
                    })?;
                    // The pin lands on the host-wide bpffs: mount namespaces are
                    // untouched by the netns switch.
                    let encap_link = bpf.attach_encap(peer, encap_pin.as_deref())?;
                    bpf.add_peer_redirect(peer_index)?;
                    anyhow::Ok((peer_index, encap_link))
                })
            }
        }
    }

    /// Set the peer's MTU and keep it up, in the private namespace when hiding is
    /// enabled (its ifindex is only resolvable there) or the host namespace
    /// otherwise.
    async fn set_peer_mtu_up(&self, peer_index: u32, mtu: u32) -> anyhow::Result<()> {
        match &self.netns {
            None => self.nl.set_mtu_up(peer_index, mtu).await,
            Some(ns) => ns.run_in(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| anyhow::anyhow!("build hidden-netns runtime: {e}"))?;
                rt.block_on(async {
                    let nl = crate::control::netlink::Netlink::connect()?;
                    nl.set_mtu_up(peer_index, mtu).await
                })
            }),
        }
    }

    /// Look up a veth peer where it lives: the hidden namespace when peers are
    /// hidden, the host namespace otherwise.
    async fn peer_link_info(
        &self,
        peer: &str,
    ) -> anyhow::Result<Option<crate::control::netlink::LinkInfo>> {
        match &self.netns {
            None => self.nl.link_info(peer).await,
            Some(ns) => ns.run_in(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| anyhow::anyhow!("build hidden-netns runtime: {e}"))?;
                rt.block_on(async {
                    crate::control::netlink::Netlink::connect()?
                        .link_info(peer)
                        .await
                })
            }),
        }
    }

    /// Adopt one tunnel left running by the previous instance: both veth ends
    /// alive, both link pins live on their devices. Returns `Ok(false)` when
    /// any precondition fails and the tunnel should be recreated instead
    /// (interrupting only that tunnel). On success the recorded `ENCAP_CONFIG`
    /// entry reconstructs the runtime state, and a normal in-place update then
    /// applies whatever changed in the config while the daemon was down.
    async fn adopt_tunnel(
        &mut self,
        mode: crate::control::bpf::AdoptMode,
        config_path: Option<std::path::PathBuf>,
        spec: &crate::control::config::TunnelSpec,
    ) -> anyhow::Result<bool> {
        validate_name(&spec.name)?;
        let name = spec.name.clone();
        let peer = peer_name(&name);
        let Some(pins) = self.pins.clone() else {
            return Ok(false);
        };
        let encap_pin = pins.tunnel_link(&name, crate::control::bpf::LinkKind::Encap);
        let pass_pin = pins.tunnel_link(&name, crate::control::bpf::LinkKind::Pass);
        if !encap_pin.exists() || !pass_pin.exists() {
            return Ok(false);
        }
        let Some(user) = self.nl.link_info(&name).await? else {
            return Ok(false);
        };
        let Some(peer_info) = self.peer_link_info(&peer).await? else {
            return Ok(false);
        };

        let encap_link = match self
            .bpf
            .adopt_encap(&encap_pin, peer_info.xdp_prog_id, mode)
        {
            Ok(l) => l,
            Err(e) => {
                log::warn!("tunnel {name}: adopt encap link: {e:#}; recreating");
                return Ok(false);
            }
        };
        let pass_link = match self.bpf.adopt_pass(&pass_pin, user.xdp_prog_id, mode) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("tunnel {name}: adopt pass link: {e:#}; recreating");
                self.bpf.detach(encap_link).ok();
                return Ok(false);
            }
        };
        // Re-register the peer redirect from inside its namespace (devmap
        // entries resolve the ifindex against the caller's netns); the kernel
        // kept the existing entry alive with the device, so this is a no-op
        // re-insert in the common case.
        match &self.netns {
            None => self.bpf.add_peer_redirect(peer_info.index)?,
            Some(ns) => {
                let bpf = &mut self.bpf;
                ns.run_in(|| bpf.add_peer_redirect(peer_info.index))?;
            }
        }

        // The persisted encap entry is the previous instance's record of the
        // tunnel; no entry means it was still pending (entries withheld).
        let (config, decap_key, effective_src) = match self.bpf.get_encap(peer_info.index)? {
            Some(mut cfg) => {
                // The veth's actual MAC is the ground truth the update below
                // diffs against.
                cfg.tunnel_mac = user.mac;
                let (decap_key, effective_src) = reconstruct_adopted_state(&cfg);
                (cfg, decap_key, effective_src)
            }
            None => {
                let unspecified = std::net::Ipv6Addr::UNSPECIFIED;
                let config = self.build_config(
                    spec,
                    peer_info.index,
                    unspecified,
                    user.mac,
                    [0u8; 6],
                    user.mtu as i32,
                );
                (config, Self::decap_key(unspecified, spec.remote), None)
            }
        };
        self.tunnels.insert(
            name.clone(),
            RunningTunnel {
                spec: spec.clone(),
                config_path: config_path.clone(),
                peer_index: peer_info.index,
                // The veth's live MTU, so an offline config change is seen as
                // a change by the update below.
                tunnel_mtu: user.mtu as i32,
                config,
                decap_key,
                effective_src,
                next_hop: None,
                next_hop_on_link: false,
                neigh_state: None,
                encap_link,
                pass_link,
            },
        );
        log::info!("tunnel {name}: adopted running data plane");
        self.update_tunnel(config_path, spec.clone()).await?;
        Ok(true)
    }

    /// Tear down pinned tunnels whose names vanished from the config while the
    /// daemon was down. Unlinking the pins drops the links' last references;
    /// deleting the user-facing end removes the veth pair.
    async fn remove_orphan_tunnels(&mut self, configured: &std::collections::HashSet<String>) {
        let Some(pins) = self.pins.clone() else {
            return;
        };
        for name in pins.list_pinned_tunnels() {
            if configured.contains(&name) {
                continue;
            }
            log::info!("tunnel {name}: removed from config while down; tearing down leftovers");
            if let Err(e) = pins.remove_tunnel_dir(&name) {
                log::warn!("tunnel {name}: remove link pins: {e:#}");
            }
            self.nl.delete_link(&name).await.ok();
        }
    }

    /// Drop `ENCAP_CONFIG`/`DECAP_CONFIG` entries owned by no running tunnel —
    /// leftovers of tunnels that changed or disappeared while the daemon was
    /// down. The devmaps need no sweep: the kernel clears their entries when a
    /// device goes away.
    fn sweep_stale_map_entries(&mut self) {
        let owned_peers: std::collections::HashSet<u32> =
            self.tunnels.values().map(|t| t.peer_index).collect();
        let owned_keys: std::collections::HashSet<etherip_xdp_common::DecapKey> = self
            .tunnels
            .values()
            .filter(|t| t.effective_src.is_some())
            .map(|t| t.decap_key)
            .collect();
        match self.bpf.encap_keys() {
            Ok(keys) => {
                for key in stale_entries(keys, &owned_peers) {
                    log::info!("sweeping stale encap entry for ifindex {key}");
                    self.bpf.remove_encap(key).ok();
                }
            }
            Err(e) => log::warn!("sweep encap entries: {e:#}"),
        }
        match self.bpf.decap_keys() {
            Ok(keys) => {
                for key in stale_entries(keys, &owned_keys) {
                    log::info!("sweeping a stale decap entry");
                    self.bpf.remove_decap(&key).ok();
                }
            }
            Err(e) => log::warn!("sweep decap entries: {e:#}"),
        }
    }

    /// Create a new tunnel: veth pair, MTU/offload, map population, attach.
    async fn add_tunnel(
        &mut self,
        config_path: Option<std::path::PathBuf>,
        spec: crate::control::config::TunnelSpec,
    ) -> anyhow::Result<()> {
        validate_name(&spec.name)?;
        let name = spec.name.clone();
        let peer = peer_name(&name);
        let tunnel_mtu = self.tunnel_mtu(&spec);
        if tunnel_mtu <= 0 {
            anyhow::bail!("computed tunnel MTU {tunnel_mtu} for {name} is not positive");
        }

        // Recover from a previous unclean exit (mirrors the Go behaviour).
        self.nl.delete_link(&name).await.ok();
        self.nl.create_veth(&name, &peer).await?;

        let (encap_pin, pass_pin) = match &self.pins {
            Some(pins) => {
                pins.ensure_tunnel_dir(&name)?;
                (
                    Some(pins.tunnel_link(&name, crate::control::bpf::LinkKind::Encap)),
                    Some(pins.tunnel_link(&name, crate::control::bpf::LinkKind::Pass)),
                )
            }
            None => (None, None),
        };

        let user = self
            .nl
            .link_info(&name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("veth {name} missing after creation"))?;
        // Set the user-facing MAC before bringing the link up so the address it
        // first advertises on the L2 domain is already the configured one. This
        // is also the inner dst MAC the decap path writes, so the two stay equal.
        let tunnel_mac = self.resolve_tunnel_mac(&spec, user.mac);
        if tunnel_mac != user.mac {
            self.nl.set_mac(user.index, tunnel_mac).await?;
            log::info!("tunnel {name}: local MAC set to {}", fmt_mac(&tunnel_mac));
        }
        let mtu = tunnel_mtu as u32;
        self.nl.set_mtu_up(user.index, mtu).await?;
        // disable_tx_offload does blocking socket/ioctl syscalls; offload it from
        // the async runtime. The user-facing end stays in the host namespace, so
        // this is unaffected by peer hiding.
        let offload_name = name.clone();
        tokio::task::spawn_blocking(move || {
            crate::control::offload::disable_tx_offload(&offload_name)
        })
        .await
        .map_err(|e| anyhow::anyhow!("tx-offload task failed to join: {e}"))??;

        // Bring the peer up, attach encap, and register its decap redirect target.
        // Attach/redirect are registered unconditionally; the encap/decap map
        // entries (below) are what gate the data path, so a pending tunnel is
        // attached but inert. When hiding the peer, all three run inside the
        // private namespace: moving the link reassigns its ifindex there and
        // resets it to down, and both the XDP attach and the devmap insert resolve
        // the ifindex against the calling namespace.
        let (peer_index, encap_link) = self.setup_peer(&peer, mtu, encap_pin).await?;

        self.warn_if_src_unassigned(&spec).await;
        let resolved = match crate::control::resolver::resolve_endpoint(
            &self.nl,
            self.external.index,
            &self.external.name,
            spec.local,
            spec.remote,
            spec.next_hop_on_link,
            crate::control::resolver::Probe::Bringup,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("tunnel {name}: endpoint resolution error: {e:#}");
                crate::control::resolver::Resolved::default()
            }
        };
        let dst_mac = resolved.dst_mac.unwrap_or([0u8; 6]);

        // The user-facing end stays in the host namespace; its pass-through attach
        // satisfies the kernel's `veth_xdp_xmit` peer check for redirected frames.
        let pass_link = self.bpf.attach_pass(&name, pass_pin.as_deref())?;

        // Without a source address (auto-select found no route yet) the tunnel is
        // pending: withhold the map entries so the data path never encapsulates
        // with a bogus source. `reresolve_all` installs them once a source
        // resolves. The placeholder config/key are never written to the maps.
        let (config, decap_key, effective_src) = match resolved.src {
            Some(src) => {
                let config =
                    self.build_config(&spec, peer_index, src, tunnel_mac, dst_mac, tunnel_mtu);
                let decap_key = Self::decap_key(src, spec.remote);
                self.bpf.set_encap(peer_index, &config)?;
                self.bpf.set_decap(&decap_key, &config)?;
                if dst_mac == [0u8; 6] {
                    warn_next_hop_unresolved(&name, src, spec.remote);
                } else {
                    log::info!(
                        "tunnel {name} up: {} -> {} via next-hop {}, mtu {}, mss ({},{})",
                        src,
                        spec.remote,
                        fmt_mac(&dst_mac),
                        tunnel_mtu,
                        config.mss_clamp_ipv4,
                        config.mss_clamp_ipv6
                    );
                }
                (config, decap_key, Some(src))
            }
            None => {
                let unspecified = std::net::Ipv6Addr::UNSPECIFIED;
                let config = self.build_config(
                    &spec,
                    peer_index,
                    unspecified,
                    tunnel_mac,
                    dst_mac,
                    tunnel_mtu,
                );
                let decap_key = Self::decap_key(unspecified, spec.remote);
                log::warn!(
                    "tunnel {name}: no source address resolved yet (src auto-select); \
                     pending until a route to {} appears",
                    spec.remote
                );
                (config, decap_key, None)
            }
        };

        self.tunnels.insert(
            name,
            RunningTunnel {
                spec,
                config_path,
                peer_index,
                tunnel_mtu,
                config,
                decap_key,
                effective_src,
                next_hop: resolved.next_hop,
                next_hop_on_link: resolved.on_link,
                neigh_state: resolved.neigh_state,
                encap_link,
                pass_link,
            },
        );
        Ok(())
    }

    /// Tear down a tunnel: detach, remove maps, delete veth.
    async fn remove_tunnel(&mut self, name: &str) -> anyhow::Result<()> {
        let Some(t) = self.tunnels.remove(name) else {
            return Ok(());
        };
        if let Err(e) = self.bpf.detach(t.encap_link) {
            log::warn!("tunnel {name}: detach encap: {e:#}");
        }
        if let Err(e) = self.bpf.detach(t.pass_link) {
            log::warn!("tunnel {name}: detach pass: {e:#}");
        }
        self.bpf.remove_encap(t.peer_index).ok();
        self.bpf.remove_decap(&t.decap_key).ok();
        self.bpf.remove_peer_redirect(t.peer_index).ok();
        if let Some(pins) = &self.pins
            && let Err(e) = pins.remove_tunnel_dir(name)
        {
            log::warn!("tunnel {name}: remove link pins: {e:#}");
        }
        // Deleting the user-facing end removes the whole veth pair, including the
        // peer in the private namespace; the namespace itself outlives it for the
        // next tunnel and is torn down only when the daemon exits.
        self.nl.delete_link(name).await?;
        log::info!("tunnel {name} removed");
        Ok(())
    }

    /// Update a tunnel in place (src/dst/mss/mtu) without veth churn.
    async fn update_tunnel(
        &mut self,
        config_path: Option<std::path::PathBuf>,
        spec: crate::control::config::TunnelSpec,
    ) -> anyhow::Result<()> {
        let name = spec.name.clone();
        let (peer_index, old_key, old_mtu, cur_tunnel_mac, old_dst_mac, old_src) = {
            let t = self
                .tunnels
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("update of unknown tunnel {name}"))?;
            (
                t.peer_index,
                t.decap_key,
                t.tunnel_mtu,
                t.config.tunnel_mac,
                t.config.dst_mac,
                t.effective_src,
            )
        };

        let tunnel_mtu = self.tunnel_mtu(&spec);
        if tunnel_mtu <= 0 {
            anyhow::bail!("computed tunnel MTU {tunnel_mtu} for {name} is not positive");
        }
        if tunnel_mtu != old_mtu {
            let user_index = self
                .nl
                .index_of(&name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("veth {name} vanished"))?;
            self.nl.set_mtu_up(user_index, tunnel_mtu as u32).await?;
            self.set_peer_mtu_up(peer_index, tunnel_mtu as u32).await?;
        }

        // Apply a changed local MAC in place. `Auto` keeps the current address, so
        // switching to auto after an explicit/inherit value does not restore the
        // original kernel MAC without recreating the veth.
        let tunnel_mac = self.resolve_tunnel_mac(&spec, cur_tunnel_mac);
        if tunnel_mac != cur_tunnel_mac {
            let user_index = self
                .nl
                .index_of(&name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("veth {name} vanished"))?;
            self.nl.set_mac(user_index, tunnel_mac).await?;
            log::info!("tunnel {name}: local MAC set to {}", fmt_mac(&tunnel_mac));
        }

        self.warn_if_src_unassigned(&spec).await;
        // Re-resolve the endpoint for the new spec. Keep the last-known source and
        // MAC on a transient resolution failure rather than tearing the tunnel
        // down; a ready tunnel never flaps back to pending.
        let resolved = match crate::control::resolver::resolve_endpoint(
            &self.nl,
            self.external.index,
            &self.external.name,
            spec.local,
            spec.remote,
            spec.next_hop_on_link,
            crate::control::resolver::Probe::Bringup,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("tunnel {name}: endpoint resolution error: {e:#}");
                crate::control::resolver::Resolved::default()
            }
        };
        let dst_mac = resolved.dst_mac.unwrap_or(old_dst_mac);
        let was_installed = old_src.is_some();

        let Some(src) = resolved.src.or(old_src) else {
            // Still pending (auto-select has no route yet): keep the data-path
            // entries withheld, but record the new spec/MTU so a later resolve
            // installs the updated definition.
            let unspecified = std::net::Ipv6Addr::UNSPECIFIED;
            let config = self.build_config(
                &spec,
                peer_index,
                unspecified,
                tunnel_mac,
                dst_mac,
                tunnel_mtu,
            );
            if let Some(t) = self.tunnels.get_mut(&name) {
                t.spec = spec;
                t.config_path = config_path;
                t.tunnel_mtu = tunnel_mtu;
                t.config = config;
                t.decap_key = Self::decap_key(unspecified, t.spec.remote);
                t.effective_src = None;
                t.next_hop = resolved.next_hop;
                t.next_hop_on_link = resolved.on_link;
                t.neigh_state = resolved.neigh_state;
            }
            log::info!("tunnel {name} updated (pending: no source address yet)");
            return Ok(());
        };

        let config = self.build_config(&spec, peer_index, src, tunnel_mac, dst_mac, tunnel_mtu);
        let new_key = Self::decap_key(src, spec.remote);

        self.bpf.set_encap(peer_index, &config)?;
        if was_installed && new_key != old_key {
            self.bpf.remove_decap(&old_key).ok();
        }
        self.bpf.set_decap(&new_key, &config)?;

        if dst_mac == [0u8; 6] {
            warn_next_hop_unresolved(&name, src, spec.remote);
        } else {
            log::info!(
                "tunnel {name} updated: {} -> {} via next-hop {}, mtu {}, mss ({},{})",
                src,
                spec.remote,
                fmt_mac(&dst_mac),
                tunnel_mtu,
                config.mss_clamp_ipv4,
                config.mss_clamp_ipv6
            );
        }

        if let Some(t) = self.tunnels.get_mut(&name) {
            t.spec = spec;
            t.config_path = config_path;
            t.tunnel_mtu = tunnel_mtu;
            t.config = config;
            t.decap_key = new_key;
            t.effective_src = Some(src);
            t.next_hop = resolved.next_hop;
            t.next_hop_on_link = resolved.on_link;
            t.neigh_state = resolved.neigh_state;
        }
        Ok(())
    }

    /// Reload the config directories and apply the diff gracefully.
    pub async fn reload(&mut self) -> anyhow::Result<()> {
        let new_specs = crate::control::config::load_dirs(&self.config_dirs).await?;
        // The winning config-file path per tunnel name, to pass through to
        // add/update so each running tunnel can report its source file.
        let paths: std::collections::HashMap<String, std::path::PathBuf> = new_specs
            .iter()
            .map(|(p, s)| (s.name.clone(), p.clone()))
            .collect();
        let bare: Vec<crate::control::config::TunnelSpec> =
            new_specs.into_iter().map(|(_, s)| s).collect();
        let old: std::collections::HashMap<String, crate::control::config::TunnelSpec> = self
            .tunnels
            .iter()
            .map(|(k, t)| (k.clone(), t.spec.clone()))
            .collect();
        let diff = diff_specs(&old, &bare);
        log::info!(
            "reload: {} added, {} removed, {} updated",
            diff.added.len(),
            diff.removed.len(),
            diff.updated.len()
        );
        for name in diff.removed {
            if let Err(e) = self.remove_tunnel(&name).await {
                log::error!("reload: remove {name}: {e:#}");
            }
        }
        for spec in diff.added {
            let n = spec.name.clone();
            let path = paths.get(&n).cloned();
            if let Err(e) = self.add_tunnel(path, spec).await {
                log::error!("reload: add {n}: {e:#}");
            }
        }
        for spec in diff.updated {
            let n = spec.name.clone();
            let path = paths.get(&n).cloned();
            if let Err(e) = self.update_tunnel(path, spec).await {
                log::error!("reload: update {n}: {e:#}");
            }
        }
        Ok(())
    }

    /// Re-resolve every tunnel's outer endpoint (source address + next-hop MAC),
    /// updating the encap/decap entries when anything changed. Called on netlink
    /// change events and periodically. This is what picks up underlay changes: a
    /// new preferred source (when `src` is auto) or a new next-hop MAC, and it
    /// promotes a pending tunnel to ready once a source first resolves.
    ///
    /// `refresh` distinguishes the periodic tick (`true`) from a reactive netlink
    /// event (`false`). The tick sends a single keep-fresh ND probe per tunnel so
    /// usable neighbour entries don't decay (XDP egress never marks them used).
    /// The reactive path only probes tunnels that still lack a next-hop MAC (to
    /// speed bring-up when a route/neighbour appears); tunnels that already have a
    /// MAC are read passively, since probing a usable entry would just feed back
    /// into more neighbour events.
    pub async fn reresolve_all(&mut self, refresh: bool) {
        let names: Vec<String> = self.tunnels.keys().cloned().collect();
        for name in names {
            let Some((spec, peer_index, tunnel_mtu, cur_config, cur_key, eff_src)) =
                self.tunnels.get(&name).map(|t| {
                    (
                        t.spec.clone(),
                        t.peer_index,
                        t.tunnel_mtu,
                        t.config,
                        t.decap_key,
                        t.effective_src,
                    )
                })
            else {
                continue;
            };
            let probe = if refresh {
                crate::control::resolver::Probe::Refresh
            } else if cur_config.dst_mac == [0u8; 6] {
                // Reactive, but still without a MAC: nudge bring-up on the event.
                crate::control::resolver::Probe::Refresh
            } else {
                // Reactive with a MAC in hand: read only, no probe feedback.
                crate::control::resolver::Probe::Passive
            };
            let resolved = match crate::control::resolver::resolve_endpoint(
                &self.nl,
                self.external.index,
                &self.external.name,
                spec.local,
                spec.remote,
                spec.next_hop_on_link,
                probe,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("tunnel {name}: re-resolve error: {e:#}");
                    continue;
                }
            };

            // Record the freshly-observed next-hop diagnostics (reported over the
            // management interface) regardless of whether the data-path entries
            // change below, so the reported state never lags behind reality.
            if let Some(t) = self.tunnels.get_mut(&name) {
                t.next_hop = resolved.next_hop;
                t.next_hop_on_link = resolved.on_link;
                t.neigh_state = resolved.neigh_state;
            }

            // Keep the last-known source on a transient unresolution so a ready
            // tunnel never flaps back to pending; likewise keep the last MAC.
            let Some(src) = resolved.src.or(eff_src) else {
                continue; // still pending: nothing to install yet
            };
            let dst_mac = resolved.dst_mac.unwrap_or(cur_config.dst_mac);

            let new_config = self.build_config(
                &spec,
                peer_index,
                src,
                cur_config.tunnel_mac,
                dst_mac,
                tunnel_mtu,
            );
            let new_key = Self::decap_key(src, spec.remote);
            let was_installed = eff_src.is_some();

            if was_installed && new_config == cur_config && new_key == cur_key {
                continue; // nothing changed
            }

            if let Err(e) = self.bpf.set_encap(peer_index, &new_config) {
                log::error!("tunnel {name}: update encap: {e:#}");
                continue;
            }
            if was_installed && new_key != cur_key {
                self.bpf.remove_decap(&cur_key).ok();
            }
            if let Err(e) = self.bpf.set_decap(&new_key, &new_config) {
                log::error!("tunnel {name}: update decap: {e:#}");
                continue;
            }
            if let Some(t) = self.tunnels.get_mut(&name) {
                t.config = new_config;
                t.decap_key = new_key;
                t.effective_src = Some(src);
            }
            if dst_mac == [0u8; 6] {
                warn_next_hop_unresolved(&name, src, spec.remote);
            } else if was_installed {
                log::info!(
                    "tunnel {name}: endpoint updated (src {src}, next-hop {})",
                    fmt_mac(&dst_mac)
                );
            } else {
                log::info!(
                    "tunnel {name} up: {src} -> {} via next-hop {} (source resolved)",
                    spec.remote,
                    fmt_mac(&dst_mac)
                );
            }
        }
    }

    /// Service a control-plane request from the embedded varlink server. Runs
    /// synchronously on the main loop, which owns `&mut self`, so the snapshot
    /// can read the live BPF counters; the reply is sent back over the oneshot.
    pub fn handle_control(&mut self, req: crate::control::types::ControlRequest) {
        match req {
            crate::control::types::ControlRequest::Snapshot(reply) => {
                // The receiver may have hung up (client gone); ignore the result.
                let _ = reply.send(self.build_snapshot());
            }
        }
    }

    /// Build an owned status snapshot of this daemon for the management
    /// interface. Tunnel/external data is collected first (immutable borrows),
    /// then the per-CPU debug counters are read (mutable borrow of the BPF maps).
    fn build_snapshot(&mut self) -> crate::control::types::StatusSnapshot {
        let external = crate::control::types::ExternalSnapshot {
            name: self.external.name.clone(),
            index: self.external.index,
            mac: self.external.mac,
            mtu: self.external.mtu,
        };
        let tunnels: Vec<_> = self.tunnels.values().map(snapshot_tunnel).collect();
        let raw = self
            .bpf
            .read_counters()
            .unwrap_or([0u64; etherip_xdp_common::DBG_MAX as usize]);
        let counters = etherip_xdp_common::COUNTER_NAMES
            .iter()
            .copied()
            .zip(raw)
            .collect();
        crate::control::types::StatusSnapshot {
            external,
            counters,
            tunnels,
        }
    }

    /// Log the per-CPU debug counters (non-zero only).
    pub fn dump_counters(&mut self) {
        match self.bpf.read_counters() {
            Ok(counters) => {
                log::info!("--- debug counters ---");
                for (i, &count) in counters.iter().enumerate() {
                    if count > 0 {
                        log::info!("  {}: {count}", etherip_xdp_common::COUNTER_NAMES[i]);
                    }
                }
                log::info!("--- end counters ---");
            }
            Err(e) => log::error!("read debug counters: {e:#}"),
        }
    }

    /// Detach the uplink program and tear down all tunnels.
    pub async fn cleanup(mut self) {
        let names: Vec<String> = self.tunnels.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.remove_tunnel(&name).await {
                log::error!("cleanup: remove {name}: {e:#}");
            }
        }
        let Manager {
            mut bpf,
            external,
            external_decap_link,
            pins,
            netns,
            ..
        } = self;
        if let Err(e) = bpf.detach(external_decap_link) {
            log::warn!("cleanup: detach uplink program: {e:#}");
        }
        bpf.remove_uplink_redirect(external.index).ok();
        // Unpin everything: with the daemon's own references dropping below,
        // this releases the kernel's last hold on the maps.
        if let Some(pins) = &pins
            && let Err(e) = pins.remove_all()
        {
            log::warn!("cleanup: remove pins: {e:#}");
        }
        // Dropping the namespace descriptor destroys the private namespace and
        // any peers that survived individual teardown.
        drop(netns);
    }
}

/// Rebuild a tunnel's runtime identity from the `ENCAP_CONFIG` entry the
/// previous instance persisted: the decap demux key and the effective outer
/// source. An unspecified source cannot occur in an installed entry (pending
/// tunnels withhold their entries), but map to "pending" anyway. Pure, so the
/// round trip against `build_config`/`decap_key` is unit-tested.
fn reconstruct_adopted_state(
    cfg: &etherip_xdp_common::TunnelConfig,
) -> (etherip_xdp_common::DecapKey, Option<std::net::Ipv6Addr>) {
    let src = std::net::Ipv6Addr::from(cfg.src_addr);
    let decap_key = etherip_xdp_common::DecapKey {
        remote: cfg.dst_addr,
        local: cfg.src_addr,
    };
    (decap_key, (!src.is_unspecified()).then_some(src))
}

/// Observed map keys not owned by any running tunnel. Pure sweep core.
fn stale_entries<K: Eq + std::hash::Hash>(
    observed: Vec<K>,
    owned: &std::collections::HashSet<K>,
) -> Vec<K> {
    observed
        .into_iter()
        .filter(|k| !owned.contains(k))
        .collect()
}

/// A real neighbour MAC is never all-zero, so a zero `dst_mac` after resolution
/// means the next hop has not resolved yet: the encap/decap entries are installed
/// but the data path drops every frame (addressed to the null MAC) until a
/// neighbour appears. That is a failure the operator must see, hence `warn`.
fn warn_next_hop_unresolved(name: &str, src: std::net::Ipv6Addr, remote: std::net::Ipv6Addr) {
    log::warn!(
        "tunnel {name}: {src} -> {remote} installed but next-hop MAC unresolved; \
         frames are dropped until a neighbour resolves"
    );
}

fn fmt_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Snapshot one running tunnel's config and live runtime state for the
/// management interface.
fn snapshot_tunnel(t: &RunningTunnel) -> crate::control::types::TunnelSnapshot {
    let mac_policy = match t.spec.mac {
        crate::control::config::MacConfig::Auto => "auto",
        crate::control::config::MacConfig::Inherit => "inherit",
        crate::control::config::MacConfig::Explicit(_) => "explicit",
    };
    let next_hop_on_link_policy = match t.spec.next_hop_on_link {
        crate::control::resolver::NextHopOnLink::Maybe => "maybe",
        crate::control::resolver::NextHopOnLink::Always => "always",
        crate::control::resolver::NextHopOnLink::Never => "never",
    };
    // A non-zero installed dst_mac means the next hop is resolved.
    let next_hop_mac = (t.config.dst_mac != [0u8; 6]).then_some(t.config.dst_mac);
    crate::control::types::TunnelSnapshot {
        name: t.spec.name.clone(),
        config_path: t.config_path.clone(),
        configured_local: t.spec.local,
        remote: t.spec.remote,
        effective_src: t.effective_src,
        state: crate::control::types::derive_state(t.effective_src, t.config.dst_mac),
        tunnel_mtu: t.tunnel_mtu,
        mtu_override: t.spec.mtu,
        mac_policy,
        tunnel_mac: t.config.tunnel_mac,
        next_hop_on_link_policy,
        mss_clamp_ipv4: t.config.mss_clamp_ipv4,
        mss_clamp_ipv6: t.config.mss_clamp_ipv6,
        peer_ifindex: t.peer_index,
        next_hop: t.next_hop,
        next_hop_on_link: t.next_hop_on_link,
        next_hop_mac,
        neigh_state: t.neigh_state.map(|s| s.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(
        name: &str,
        remote: &str,
        mss: crate::control::config::MssConfig,
    ) -> crate::control::config::TunnelSpec {
        crate::control::config::TunnelSpec {
            name: name.to_string(),
            local: Some("2001:db8::1".parse().unwrap()),
            remote: remote.parse().unwrap(),
            mss,
            mtu: None,
            mac: crate::control::config::MacConfig::Auto,
            next_hop_on_link: crate::control::resolver::NextHopOnLink::default(),
        }
    }

    fn running(
        specs: &[crate::control::config::TunnelSpec],
    ) -> std::collections::HashMap<String, crate::control::config::TunnelSpec> {
        specs.iter().map(|s| (s.name.clone(), s.clone())).collect()
    }

    #[test]
    fn diff_add_remove_update_noop() {
        let a = spec("a", "2001:db8::2", crate::control::config::MssConfig::Auto);
        let b = spec("b", "2001:db8::3", crate::control::config::MssConfig::Auto);
        let b_changed = spec("b", "2001:db8::9", crate::control::config::MssConfig::Auto);
        let c = spec("c", "2001:db8::4", crate::control::config::MssConfig::Auto);

        let old = running(&[a.clone(), b.clone()]);
        // new: a unchanged, b changed, c added, (b removed? no) -> a noop, b updated, c added
        let new = vec![a.clone(), b_changed.clone(), c.clone()];
        let diff = diff_specs(&old, &new);
        assert_eq!(diff.added, vec![c]);
        assert_eq!(diff.updated, vec![b_changed]);
        assert!(diff.removed.is_empty());

        // Removing a from config.
        let new2 = vec![b.clone()];
        let diff2 = diff_specs(&old, &new2);
        assert_eq!(diff2.removed, vec!["a".to_string()]);
        assert!(diff2.added.is_empty());
        assert!(diff2.updated.is_empty());
    }

    #[test]
    fn diff_mss_change_is_update() {
        let a1 = spec("a", "2001:db8::2", crate::control::config::MssConfig::Auto);
        let a2 = spec("a", "2001:db8::2", crate::control::config::MssConfig::Off);
        let old = running(&[a1]);
        let diff = diff_specs(&old, std::slice::from_ref(&a2));
        assert_eq!(diff.updated, vec![a2]);
    }

    #[test]
    fn reconstruct_round_trips_installed_state() {
        // An installed entry records src/dst as add_tunnel wrote them; the
        // reconstruction must yield the same decap key and source.
        let src: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let remote: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut cfg = etherip_xdp_common::TunnelConfig::zeroed();
        cfg.src_addr = src.octets();
        cfg.dst_addr = remote.octets();
        let (key, eff) = reconstruct_adopted_state(&cfg);
        assert_eq!(key, Manager::decap_key(src, remote));
        assert_eq!(eff, Some(src));
    }

    #[test]
    fn reconstruct_maps_unspecified_src_to_pending() {
        let cfg = etherip_xdp_common::TunnelConfig::zeroed();
        let (_, eff) = reconstruct_adopted_state(&cfg);
        assert_eq!(eff, None);
    }

    #[test]
    fn stale_entries_filter_owned() {
        let owned: std::collections::HashSet<u32> = [3u32, 7].into_iter().collect();
        assert_eq!(stale_entries(vec![1, 3, 5, 7], &owned), vec![1, 5]);
        assert_eq!(stale_entries(Vec::<u32>::new(), &owned), Vec::<u32>::new());
    }

    #[test]
    fn peer_name_and_validation() {
        assert_eq!(peer_name("tunnel0"), "tunnel0-xdp");
        assert!(validate_name("tunnel0").is_ok());
        assert!(validate_name("").is_err());
        // 12 chars + "-xdp" (4) = 16 > 15.
        assert!(validate_name("abcdefghijkl").is_err());
        // 11 chars + 4 = 15, OK.
        assert!(validate_name("abcdefghijk").is_ok());
    }
}

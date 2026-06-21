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
    spec: crate::config::TunnelSpec,
    peer_index: u32,
    tunnel_mtu: i32,
    config: etherip_xdp_common::TunnelConfig,
    decap_key: etherip_xdp_common::DecapKey,
    /// Outer source address currently in use, or `None` while the tunnel is
    /// pending (auto-select has not resolved a source yet). When `None`, the
    /// encap/decap map entries are deliberately withheld so the data path never
    /// encapsulates with a bogus source.
    effective_src: Option<std::net::Ipv6Addr>,
    encap_link: aya::programs::xdp::XdpLinkId,
    pass_link: aya::programs::xdp::XdpLinkId,
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
    pub added: Vec<crate::config::TunnelSpec>,
    pub removed: Vec<String>,
    pub updated: Vec<crate::config::TunnelSpec>,
}

/// Compute the diff between currently-running specs and the newly-loaded specs.
/// Pure, so it is unit-tested. Tunnels are keyed by name; a name present in both
/// with a changed spec is an in-place update (never needs veth recreation since
/// the veth name is the key).
pub fn diff_specs(
    old: &std::collections::HashMap<String, crate::config::TunnelSpec>,
    new: &[crate::config::TunnelSpec],
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
    bpf: crate::bpf::Bpf,
    nl: crate::netlink::Netlink,
    external: ExternalInterface,
    external_decap_link: aya::programs::xdp::XdpLinkId,
    config_dir: std::path::PathBuf,
    on_link: crate::resolver::NextHopOnLink,
    /// When `Some`, each tunnel's `<name>-xdp` peer is moved into this private
    /// anonymous namespace to hide it from userland; when `None`, peers stay in
    /// the host namespace alongside the user-facing ends.
    netns: Option<crate::netns::NetNs>,
    tunnels: std::collections::HashMap<String, RunningTunnel>,
}

/// Wait for the external (uplink) interface to appear, retrying with capped
/// backoff. The underlay may not exist yet at boot (slow driver probe, hotplug,
/// netns setup), so the daemon waits rather than crash-looping. No signal
/// handlers are installed during `start`, so SIGINT/SIGTERM (`systemctl stop`)
/// still terminate the process while it waits.
async fn wait_for_external(
    nl: &crate::netlink::Netlink,
    name: &str,
) -> anyhow::Result<crate::netlink::LinkInfo> {
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

impl Manager {
    /// Load the eBPF object, attach the main program to the uplink, and create
    /// all tunnels from the config directory.
    pub async fn start(
        external_name: String,
        config_dir: std::path::PathBuf,
        on_link: crate::resolver::NextHopOnLink,
        hide_peer: bool,
    ) -> anyhow::Result<Self> {
        let nl = crate::netlink::Netlink::connect()?;
        let mut bpf = crate::bpf::Bpf::load()?;

        let netns = if hide_peer {
            let ns = crate::netns::NetNs::create()?;
            log::info!("hiding veth peers in a private anonymous network namespace");
            Some(ns)
        } else {
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

        // The shared decap program + redirect target for the uplink.
        bpf.add_uplink_redirect(external.index)?;
        let external_decap_link = bpf.attach_decap(&external.name)?;

        let mut manager = Manager {
            bpf,
            nl,
            external,
            external_decap_link,
            config_dir,
            on_link,
            netns,
            tunnels: std::collections::HashMap::new(),
        };

        let specs = crate::config::load_dir(&manager.config_dir).await?;
        if specs.is_empty() {
            log::warn!(
                "no tunnel configs found in {}",
                manager.config_dir.display()
            );
        }
        for spec in specs {
            if let Err(e) = manager.add_tunnel(spec).await {
                log::error!("failed to create tunnel: {e:#}");
            }
        }
        Ok(manager)
    }

    fn tunnel_mtu(&self, spec: &crate::config::TunnelSpec) -> i32 {
        match spec.mtu {
            Some(m) => m as i32,
            None => self.external.mtu as i32 - etherip_xdp_common::OUTER_OVERHEAD as i32,
        }
    }

    fn build_config(
        &self,
        spec: &crate::config::TunnelSpec,
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
            _pad: [0; 2],
            mss_clamp_ipv4: mss4,
            mss_clamp_ipv6: mss6,
        }
    }

    /// Resolve the local MAC the user-facing interface should present, given its
    /// current (kernel-assigned) address. `Auto` keeps the current address;
    /// `Inherit`/`Explicit` force the external device's or a configured address.
    fn resolve_tunnel_mac(&self, spec: &crate::config::TunnelSpec, current: [u8; 6]) -> [u8; 6] {
        match spec.mac {
            crate::config::MacConfig::Auto => current,
            crate::config::MacConfig::Inherit => self.external.mac,
            crate::config::MacConfig::Explicit(mac) => mac,
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
    async fn warn_if_src_unassigned(&self, spec: &crate::config::TunnelSpec) {
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
    ) -> anyhow::Result<(u32, aya::programs::xdp::XdpLinkId)> {
        let peer_host_index = self
            .nl
            .index_of(peer)
            .await?
            .ok_or_else(|| anyhow::anyhow!("veth peer {peer} missing after creation"))?;

        match &self.netns {
            None => {
                self.nl.set_mtu_up(peer_host_index, mtu).await?;
                let encap_link = self.bpf.attach_encap(peer)?;
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
                        let nl = crate::netlink::Netlink::connect()?;
                        let idx = nl.index_of(peer).await?.ok_or_else(|| {
                            anyhow::anyhow!("veth peer {peer} missing in hidden netns")
                        })?;
                        nl.set_mtu_up(idx, mtu).await?;
                        anyhow::Ok(idx)
                    })?;
                    let encap_link = bpf.attach_encap(peer)?;
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
                    let nl = crate::netlink::Netlink::connect()?;
                    nl.set_mtu_up(peer_index, mtu).await
                })
            }),
        }
    }

    /// Create a new tunnel: veth pair, MTU/offload, map population, attach.
    async fn add_tunnel(&mut self, spec: crate::config::TunnelSpec) -> anyhow::Result<()> {
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
        tokio::task::spawn_blocking(move || crate::offload::disable_tx_offload(&offload_name))
            .await
            .map_err(|e| anyhow::anyhow!("tx-offload task failed to join: {e}"))??;

        // Bring the peer up, attach encap, and register its decap redirect target.
        // Attach/redirect are registered unconditionally; the encap/decap map
        // entries (below) are what gate the data path, so a pending tunnel is
        // attached but inert. When hiding the peer, all three run inside the
        // private namespace: moving the link reassigns its ifindex there and
        // resets it to down, and both the XDP attach and the devmap insert resolve
        // the ifindex against the calling namespace.
        let (peer_index, encap_link) = self.setup_peer(&peer, mtu).await?;

        self.warn_if_src_unassigned(&spec).await;
        let resolved = match crate::resolver::resolve_endpoint(
            &self.nl,
            self.external.index,
            &self.external.name,
            spec.local,
            spec.remote,
            self.on_link,
            crate::resolver::Probe::Bringup,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("tunnel {name}: endpoint resolution error: {e:#}");
                crate::resolver::Resolved::default()
            }
        };
        let dst_mac = resolved.dst_mac.unwrap_or([0u8; 6]);

        // The user-facing end stays in the host namespace; its pass-through attach
        // satisfies the kernel's `veth_xdp_xmit` peer check for redirected frames.
        let pass_link = self.bpf.attach_pass(&name)?;

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
                peer_index,
                tunnel_mtu,
                config,
                decap_key,
                effective_src,
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
        if let Err(e) = self.bpf.detach_encap(t.encap_link) {
            log::warn!("tunnel {name}: detach encap: {e:#}");
        }
        if let Err(e) = self.bpf.detach_pass(t.pass_link) {
            log::warn!("tunnel {name}: detach pass: {e:#}");
        }
        self.bpf.remove_encap(t.peer_index).ok();
        self.bpf.remove_decap(&t.decap_key).ok();
        self.bpf.remove_peer_redirect(t.peer_index).ok();
        // Deleting the user-facing end removes the whole veth pair, including the
        // peer in the private namespace; the namespace itself outlives it for the
        // next tunnel and is torn down only when the daemon exits.
        self.nl.delete_link(name).await?;
        log::info!("tunnel {name} removed");
        Ok(())
    }

    /// Update a tunnel in place (src/dst/mss/mtu) without veth churn.
    async fn update_tunnel(&mut self, spec: crate::config::TunnelSpec) -> anyhow::Result<()> {
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
        let resolved = match crate::resolver::resolve_endpoint(
            &self.nl,
            self.external.index,
            &self.external.name,
            spec.local,
            spec.remote,
            self.on_link,
            crate::resolver::Probe::Bringup,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("tunnel {name}: endpoint resolution error: {e:#}");
                crate::resolver::Resolved::default()
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
                t.tunnel_mtu = tunnel_mtu;
                t.config = config;
                t.decap_key = Self::decap_key(unspecified, t.spec.remote);
                t.effective_src = None;
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
            t.tunnel_mtu = tunnel_mtu;
            t.config = config;
            t.decap_key = new_key;
            t.effective_src = Some(src);
        }
        Ok(())
    }

    /// Reload the config directory and apply the diff gracefully.
    pub async fn reload(&mut self) -> anyhow::Result<()> {
        let new_specs = crate::config::load_dir(&self.config_dir).await?;
        let old: std::collections::HashMap<String, crate::config::TunnelSpec> = self
            .tunnels
            .iter()
            .map(|(k, t)| (k.clone(), t.spec.clone()))
            .collect();
        let diff = diff_specs(&old, &new_specs);
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
            if let Err(e) = self.add_tunnel(spec).await {
                log::error!("reload: add {n}: {e:#}");
            }
        }
        for spec in diff.updated {
            let n = spec.name.clone();
            if let Err(e) = self.update_tunnel(spec).await {
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
                crate::resolver::Probe::Refresh
            } else if cur_config.dst_mac == [0u8; 6] {
                // Reactive, but still without a MAC: nudge bring-up on the event.
                crate::resolver::Probe::Refresh
            } else {
                // Reactive with a MAC in hand: read only, no probe feedback.
                crate::resolver::Probe::Passive
            };
            let resolved = match crate::resolver::resolve_endpoint(
                &self.nl,
                self.external.index,
                &self.external.name,
                spec.local,
                spec.remote,
                self.on_link,
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
        if let Err(e) = self.bpf.detach_decap(self.external_decap_link) {
            log::warn!("cleanup: detach uplink program: {e:#}");
        }
        self.bpf.remove_uplink_redirect(self.external.index).ok();
        // Dropping `self` closes the namespace descriptor, destroying the private
        // namespace and any peers that survived individual teardown.
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, remote: &str, mss: crate::config::MssConfig) -> crate::config::TunnelSpec {
        crate::config::TunnelSpec {
            name: name.to_string(),
            local: Some("2001:db8::1".parse().unwrap()),
            remote: remote.parse().unwrap(),
            mss,
            mtu: None,
            mac: crate::config::MacConfig::Auto,
        }
    }

    fn running(
        specs: &[crate::config::TunnelSpec],
    ) -> std::collections::HashMap<String, crate::config::TunnelSpec> {
        specs.iter().map(|s| (s.name.clone(), s.clone())).collect()
    }

    #[test]
    fn diff_add_remove_update_noop() {
        let a = spec("a", "2001:db8::2", crate::config::MssConfig::Auto);
        let b = spec("b", "2001:db8::3", crate::config::MssConfig::Auto);
        let b_changed = spec("b", "2001:db8::9", crate::config::MssConfig::Auto);
        let c = spec("c", "2001:db8::4", crate::config::MssConfig::Auto);

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
        let a1 = spec("a", "2001:db8::2", crate::config::MssConfig::Auto);
        let a2 = spec("a", "2001:db8::2", crate::config::MssConfig::Off);
        let old = running(&[a1]);
        let diff = diff_specs(&old, std::slice::from_ref(&a2));
        assert_eq!(diff.updated, vec![a2]);
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

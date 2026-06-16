//! Loads the eBPF object and wraps program attach/detach and map updates.
//!
//! The same `xdp_etherip` program is attached to the uplink (decap) and to each
//! veth peer (encap); `xdp_pass` is attached to each user-facing veth end. Maps
//! are shared across all attaches of a loaded object, so config reload is just
//! `insert`/`remove` on the typed map handles.

const MAIN_PROG: &str = "xdp_etherip";
const PASS_PROG: &str = "xdp_pass";

const ENCAP_CONFIG: &str = "ENCAP_CONFIG";
const DECAP_CONFIG: &str = "DECAP_CONFIG";
const REDIRECT_DEV: &str = "REDIRECT_DEV";
const DEBUG_COUNTERS: &str = "DEBUG_COUNTERS";

pub struct Bpf {
    ebpf: aya::Ebpf,
}

impl Bpf {
    /// Load the embedded object and verifier-load both XDP programs.
    pub fn load() -> anyhow::Result<Self> {
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/etherip-xdp"
        )))?;
        for name in [MAIN_PROG, PASS_PROG] {
            let prog: &mut aya::programs::Xdp = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("program {name} not found in object"))?
                .try_into()?;
            prog.load()
                .map_err(|e| anyhow::anyhow!("load program {name}: {e}"))?;
        }
        Ok(Bpf { ebpf })
    }

    fn attach(
        &mut self,
        prog: &str,
        ifname: &str,
    ) -> anyhow::Result<aya::programs::xdp::XdpLinkId> {
        let xdp: &mut aya::programs::Xdp = self
            .ebpf
            .program_mut(prog)
            .ok_or_else(|| anyhow::anyhow!("program {prog} missing"))?
            .try_into()?;
        // Prefer native (driver) mode, fall back to generic/SKB.
        match xdp.attach(ifname, aya::programs::XdpMode::Driver) {
            Ok(id) => {
                log::info!("attached {prog} to {ifname} (native/driver mode)");
                Ok(id)
            }
            Err(native_err) => {
                let id = xdp
                    .attach(ifname, aya::programs::XdpMode::Skb)
                    .map_err(|skb_err| {
                        anyhow::anyhow!(
                            "attach {prog} to {ifname}: native failed ({native_err}); \
                         skb failed ({skb_err})"
                        )
                    })?;
                log::info!("attached {prog} to {ifname} (generic/skb mode)");
                Ok(id)
            }
        }
    }

    fn detach(&mut self, prog: &str, id: aya::programs::xdp::XdpLinkId) -> anyhow::Result<()> {
        let xdp: &mut aya::programs::Xdp = self
            .ebpf
            .program_mut(prog)
            .ok_or_else(|| anyhow::anyhow!("program {prog} missing"))?
            .try_into()?;
        xdp.detach(id)
            .map_err(|e| anyhow::anyhow!("detach {prog}: {e}"))
    }

    /// Attach the main program to an interface (uplink or veth peer).
    pub fn attach_main(&mut self, ifname: &str) -> anyhow::Result<aya::programs::xdp::XdpLinkId> {
        self.attach(MAIN_PROG, ifname)
    }

    /// Attach the pass-through program to a user-facing veth end.
    pub fn attach_pass(&mut self, ifname: &str) -> anyhow::Result<aya::programs::xdp::XdpLinkId> {
        self.attach(PASS_PROG, ifname)
    }

    pub fn detach_main(&mut self, id: aya::programs::xdp::XdpLinkId) -> anyhow::Result<()> {
        self.detach(MAIN_PROG, id)
    }

    pub fn detach_pass(&mut self, id: aya::programs::xdp::XdpLinkId) -> anyhow::Result<()> {
        self.detach(PASS_PROG, id)
    }

    fn hash_map(
        &mut self,
        name: &str,
    ) -> anyhow::Result<
        aya::maps::HashMap<
            &mut aya::maps::MapData,
            etherip_xdp_common::DecapKey,
            etherip_xdp_common::TunnelConfig,
        >,
    > {
        let map = self
            .ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("map {name} missing"))?;
        Ok(aya::maps::HashMap::try_from(map)?)
    }

    /// Insert/update the encap config for a veth-peer ifindex.
    pub fn set_encap(
        &mut self,
        ifindex: u32,
        cfg: &etherip_xdp_common::TunnelConfig,
    ) -> anyhow::Result<()> {
        let map = self
            .ebpf
            .map_mut(ENCAP_CONFIG)
            .ok_or_else(|| anyhow::anyhow!("map {ENCAP_CONFIG} missing"))?;
        let mut map: aya::maps::HashMap<_, u32, etherip_xdp_common::TunnelConfig> =
            aya::maps::HashMap::try_from(map)?;
        map.insert(ifindex, *cfg, 0)?;
        Ok(())
    }

    pub fn remove_encap(&mut self, ifindex: u32) -> anyhow::Result<()> {
        let map = self
            .ebpf
            .map_mut(ENCAP_CONFIG)
            .ok_or_else(|| anyhow::anyhow!("map {ENCAP_CONFIG} missing"))?;
        let mut map: aya::maps::HashMap<_, u32, etherip_xdp_common::TunnelConfig> =
            aya::maps::HashMap::try_from(map)?;
        map.remove(&ifindex)?;
        Ok(())
    }

    /// Insert/update the decap config for an outer (remote, local) address pair.
    pub fn set_decap(
        &mut self,
        key: &etherip_xdp_common::DecapKey,
        cfg: &etherip_xdp_common::TunnelConfig,
    ) -> anyhow::Result<()> {
        let mut map = self.hash_map(DECAP_CONFIG)?;
        map.insert(*key, *cfg, 0)?;
        Ok(())
    }

    pub fn remove_decap(&mut self, key: &etherip_xdp_common::DecapKey) -> anyhow::Result<()> {
        let mut map = self.hash_map(DECAP_CONFIG)?;
        map.remove(key)?;
        Ok(())
    }

    /// Add an ifindex to the redirect devmap (target == key).
    pub fn add_redirect(&mut self, ifindex: u32) -> anyhow::Result<()> {
        let map = self
            .ebpf
            .map_mut(REDIRECT_DEV)
            .ok_or_else(|| anyhow::anyhow!("map {REDIRECT_DEV} missing"))?;
        let mut map: aya::maps::xdp::DevMapHash<_> = aya::maps::xdp::DevMapHash::try_from(map)?;
        map.insert(ifindex, ifindex, None, 0)?;
        Ok(())
    }

    pub fn remove_redirect(&mut self, ifindex: u32) -> anyhow::Result<()> {
        let map = self
            .ebpf
            .map_mut(REDIRECT_DEV)
            .ok_or_else(|| anyhow::anyhow!("map {REDIRECT_DEV} missing"))?;
        let mut map: aya::maps::xdp::DevMapHash<_> = aya::maps::xdp::DevMapHash::try_from(map)?;
        map.remove(ifindex)?;
        Ok(())
    }

    /// Read and sum the per-CPU debug counters.
    pub fn read_counters(&mut self) -> anyhow::Result<[u64; etherip_xdp_common::DBG_MAX as usize]> {
        let map = self
            .ebpf
            .map_mut(DEBUG_COUNTERS)
            .ok_or_else(|| anyhow::anyhow!("map {DEBUG_COUNTERS} missing"))?;
        let counters: aya::maps::PerCpuArray<_, u64> = aya::maps::PerCpuArray::try_from(map)?;
        let mut out = [0u64; etherip_xdp_common::DBG_MAX as usize];
        for (i, slot) in out.iter_mut().enumerate() {
            let per_cpu = counters.get(&(i as u32), 0)?;
            *slot = per_cpu.iter().copied().sum();
        }
        Ok(out)
    }
}

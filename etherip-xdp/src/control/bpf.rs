//! Loads the eBPF object and wraps program attach/detach and map updates.
//!
//! `xdp_decap` is attached to the uplink, `xdp_encap` to each veth peer, and
//! `xdp_pass` to each user-facing veth end. Maps are shared across all attaches
//! of a loaded object, so config reload is just `insert`/`remove` on the typed
//! map handles.
//!
//! # bpffs pinning
//!
//! For graceful restart the maps are pinned under
//! `/sys/fs/bpf/etherip-xdp/<uplink>/` ([`PinPaths`]): a restarted daemon
//! reopens the pinned maps (preserving the live data-plane state) instead of
//! creating fresh ones. A userspace-created `ETHERIP_STATE` map records who
//! owns the pins and the digest of the object behind them
//! ([`etherip_xdp_common::PinnedState`]); [`classify_pins`] gates reuse on
//! that record plus each map's kernel-reported shape, since aya adopts a
//! pinned map without any compatibility check.

const ENCAP_PROG: &str = "xdp_encap";
const DECAP_PROG: &str = "xdp_decap";
const PASS_PROG: &str = "xdp_pass";

const ENCAP_CONFIG: &str = "ENCAP_CONFIG";
const DECAP_CONFIG: &str = "DECAP_CONFIG";
const REDIRECT_UPLINK: &str = "REDIRECT_UPLINK";
const REDIRECT_PEER: &str = "REDIRECT_PEER";
const DEBUG_COUNTERS: &str = "DEBUG_COUNTERS";
/// Kernel name of the userspace-created state map (not part of the object).
const STATE_MAP: &str = "ETHERIP_STATE";

/// Map names of the embedded object, i.e. what [`Bpf::load`] pins.
const OBJECT_MAPS: [&str; 5] = [
    ENCAP_CONFIG,
    DECAP_CONFIG,
    REDIRECT_UPLINK,
    REDIRECT_PEER,
    DEBUG_COUNTERS,
];

const EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/etherip-xdp"));

/// bpffs layout for one uplink's pinned objects. Pure path math, so the
/// naming scheme is unit-testable and documented in one place:
///
/// ```text
/// /sys/fs/bpf/etherip-xdp/<uplink>/maps/<MAP_NAME>
/// ```
#[derive(Debug, Clone)]
pub struct PinPaths {
    base: std::path::PathBuf,
}

impl PinPaths {
    /// Root for all instances; each uplink daemon owns one subdirectory.
    /// Packaging creates it setgid `etherip-xdp-sock` so pins made by one
    /// `DynamicUser` uid stay reachable by the next (see the tmpfiles.d entry).
    pub const ROOT: &str = "/sys/fs/bpf/etherip-xdp";

    pub fn new(uplink: &str) -> Self {
        PinPaths {
            base: std::path::Path::new(Self::ROOT).join(uplink),
        }
    }

    pub fn base(&self) -> &std::path::Path {
        &self.base
    }

    fn maps_dir(&self) -> std::path::PathBuf {
        self.base.join("maps")
    }

    pub fn map(&self, name: &str) -> std::path::PathBuf {
        self.maps_dir().join(name)
    }

    /// Create the pin directories, group-accessible for the next instance's
    /// (different) DynamicUser uid. chmod only sticks for directories we own —
    /// ones adopted from a previous instance already carry these modes.
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        for dir in [self.base.clone(), self.maps_dir()] {
            std::fs::create_dir_all(&dir)
                .map_err(|e| anyhow::anyhow!("create {}: {e}", dir.display()))?;
            let _ = std::fs::set_permissions(
                &dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o2770),
            );
        }
        Ok(())
    }

    /// Remove every pinned object and the instance directory (full teardown:
    /// unpinning releases the kernel's last reference to maps and links).
    pub fn remove_all(&self) -> anyhow::Result<()> {
        match std::fs::remove_dir_all(&self.base) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow::anyhow!("remove {}: {e}", self.base.display())),
        }
    }
}

/// The kernel-visible shape a pinned map must have to be reused.
#[derive(Debug, Clone, Copy)]
pub struct MapSpec {
    pub name: &'static str,
    pub map_type: aya::maps::MapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl MapSpec {
    fn matches(&self, map_type: aya::maps::MapType, key: u32, value: u32, max: u32) -> bool {
        self.map_type == map_type
            && self.key_size == key
            && self.value_size == value
            && self.max_entries == max
    }
}

/// The expected shape of every pinned map, mirroring the eBPF declarations
/// (via the shared `*_MAX_ENTRIES` constants) plus the userspace state map.
pub fn expected_map_specs() -> [MapSpec; 6] {
    [
        MapSpec {
            name: ENCAP_CONFIG,
            map_type: aya::maps::MapType::Hash,
            key_size: std::mem::size_of::<u32>() as u32,
            value_size: std::mem::size_of::<etherip_xdp_common::TunnelConfig>() as u32,
            max_entries: etherip_xdp_common::ENCAP_CONFIG_MAX_ENTRIES,
        },
        MapSpec {
            name: DECAP_CONFIG,
            map_type: aya::maps::MapType::Hash,
            key_size: std::mem::size_of::<etherip_xdp_common::DecapKey>() as u32,
            value_size: std::mem::size_of::<etherip_xdp_common::TunnelConfig>() as u32,
            max_entries: etherip_xdp_common::DECAP_CONFIG_MAX_ENTRIES,
        },
        MapSpec {
            name: REDIRECT_UPLINK,
            map_type: aya::maps::MapType::DevMapHash,
            key_size: 4,
            value_size: 4,
            max_entries: etherip_xdp_common::REDIRECT_UPLINK_MAX_ENTRIES,
        },
        MapSpec {
            name: REDIRECT_PEER,
            map_type: aya::maps::MapType::DevMapHash,
            key_size: 4,
            value_size: 4,
            max_entries: etherip_xdp_common::REDIRECT_PEER_MAX_ENTRIES,
        },
        MapSpec {
            name: DEBUG_COUNTERS,
            map_type: aya::maps::MapType::PerCpuArray,
            key_size: 4,
            value_size: std::mem::size_of::<u64>() as u32,
            max_entries: etherip_xdp_common::DBG_MAX,
        },
        MapSpec {
            name: STATE_MAP,
            map_type: aya::maps::MapType::Array,
            key_size: 4,
            value_size: std::mem::size_of::<etherip_xdp_common::PinnedState>() as u32,
            max_entries: 1,
        },
    ]
}

/// What [`classify_pins`] concluded about an instance's existing pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinState {
    /// No pins: first start (or after a clean stop).
    Absent,
    /// A complete, schema-compatible set from a previous instance.
    Compatible,
    /// Partial or incompatible pins (mid-setup crash, or another build's
    /// layout): tear down and start fresh.
    Mismatch,
}

/// Pure core of [`classify_pins`]: fold per-map observations (`None` = pin
/// absent/unreadable, `Some(false)` = present but wrong shape, `Some(true)` =
/// compatible) into a verdict. `state_ok` is the [`PinnedState`] record gate
/// (magic + layout revision).
///
/// [`PinnedState`]: etherip_xdp_common::PinnedState
fn classify(observations: &[Option<bool>], state_ok: bool) -> PinState {
    let present = observations.iter().flatten().count();
    if observations.iter().flatten().any(|ok| !ok) {
        return PinState::Mismatch;
    }
    match present {
        0 => PinState::Absent,
        n if n == observations.len() && state_ok => PinState::Compatible,
        _ => PinState::Mismatch,
    }
}

/// Inspect the pinned maps under `pins` and decide whether they can be reused.
pub fn classify_pins(pins: &PinPaths) -> PinState {
    let specs = expected_map_specs();
    let observations: Vec<Option<bool>> = specs
        .iter()
        .map(|spec| {
            let info = aya::maps::MapInfo::from_pin(pins.map(spec.name)).ok()?;
            let map_type = info.map_type().ok()?;
            Some(spec.matches(
                map_type,
                info.key_size(),
                info.value_size(),
                info.max_entries(),
            ))
        })
        .collect();
    // The state record itself gates compatibility: a record from a different
    // layout revision means the (shape-identical or not) maps follow rules we
    // no longer understand.
    let state_ok = read_pinned_state(pins).is_some_and(|s| s.is_compatible());
    classify(&observations, state_ok)
}

/// Read the `PinnedState` record from an existing pin, if any.
fn read_pinned_state(pins: &PinPaths) -> Option<etherip_xdp_common::PinnedState> {
    let data = aya::maps::MapData::from_pin(pins.map(STATE_MAP)).ok()?;
    let array: aya::maps::Array<_, etherip_xdp_common::PinnedState> =
        aya::maps::Array::try_from(aya::maps::Map::Array(data)).ok()?;
    array.get(&0, 0).ok()
}

/// SHA-256 of the embedded eBPF object, identifying the build for the
/// skip-identical-swap decision. Stable across runs of the same binary.
pub fn object_digest() -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(EBPF_OBJECT).into()
}

pub struct Bpf {
    ebpf: aya::Ebpf,
    /// Handle on the pinned state map; `None` when pinning is disabled.
    state: Option<aya::maps::Array<aya::maps::MapData, etherip_xdp_common::PinnedState>>,
}

impl Bpf {
    /// Load the embedded object and verifier-load the XDP programs. With
    /// `pins`, the data-plane maps are pinned (or, when compatible pins
    /// already exist, reused — the caller gates that via [`classify_pins`])
    /// and the state map is opened or created.
    pub fn load(pins: Option<&PinPaths>) -> anyhow::Result<Self> {
        let mut ebpf = match pins {
            None => aya::Ebpf::load(EBPF_OBJECT)?,
            Some(pins) => {
                let mut loader = aya::EbpfLoader::new();
                for name in OBJECT_MAPS {
                    loader.map_pin_path(name, pins.map(name));
                }
                loader.load(EBPF_OBJECT)?
            }
        };
        for name in [ENCAP_PROG, DECAP_PROG, PASS_PROG] {
            let prog: &mut aya::programs::Xdp = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("program {name} not found in object"))?
                .try_into()?;
            prog.load()
                .map_err(|e| anyhow::anyhow!("load program {name}: {e}"))?;
        }
        let state = pins.map(open_or_create_state_map).transpose()?;
        if let Some(pins) = pins {
            chmod_pins(pins);
        }
        Ok(Bpf { ebpf, state })
    }

    /// The `PinnedState` record currently pinned, if valid.
    pub fn read_state(&self) -> Option<etherip_xdp_common::PinnedState> {
        let state = self.state.as_ref()?;
        state.get(&0, 0).ok().filter(|s| s.is_compatible())
    }

    /// Record this build (layout revision, package version, object digest) in
    /// the pinned state map. Written only once the data plane fully reflects
    /// this build, so a crash mid-setup can never masquerade as "identical".
    pub fn write_state(&mut self) -> anyhow::Result<()> {
        if let Some(state) = self.state.as_mut() {
            let record =
                etherip_xdp_common::PinnedState::new(env!("CARGO_PKG_VERSION"), object_digest());
            state
                .set(0, record, 0)
                .map_err(|e| anyhow::anyhow!("write pinned state: {e}"))?;
        }
        Ok(())
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

    /// Attach the encap program to a veth peer.
    pub fn attach_encap(&mut self, ifname: &str) -> anyhow::Result<aya::programs::xdp::XdpLinkId> {
        self.attach(ENCAP_PROG, ifname)
    }

    /// Attach the decap program to the uplink.
    pub fn attach_decap(&mut self, ifname: &str) -> anyhow::Result<aya::programs::xdp::XdpLinkId> {
        self.attach(DECAP_PROG, ifname)
    }

    /// Attach the pass-through program to a user-facing veth end.
    pub fn attach_pass(&mut self, ifname: &str) -> anyhow::Result<aya::programs::xdp::XdpLinkId> {
        self.attach(PASS_PROG, ifname)
    }

    pub fn detach_encap(&mut self, id: aya::programs::xdp::XdpLinkId) -> anyhow::Result<()> {
        self.detach(ENCAP_PROG, id)
    }

    pub fn detach_decap(&mut self, id: aya::programs::xdp::XdpLinkId) -> anyhow::Result<()> {
        self.detach(DECAP_PROG, id)
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

    fn devmap_insert(&mut self, name: &str, ifindex: u32) -> anyhow::Result<()> {
        let map = self
            .ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("map {name} missing"))?;
        let mut map: aya::maps::xdp::DevMapHash<_> = aya::maps::xdp::DevMapHash::try_from(map)?;
        map.insert(ifindex, ifindex, None, 0)?;
        Ok(())
    }

    fn devmap_remove(&mut self, name: &str, ifindex: u32) -> anyhow::Result<()> {
        let map = self
            .ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("map {name} missing"))?;
        let mut map: aya::maps::xdp::DevMapHash<_> = aya::maps::xdp::DevMapHash::try_from(map)?;
        map.remove(ifindex)?;
        Ok(())
    }

    /// Register the uplink as the encap redirect target. The insert resolves the
    /// ifindex against the calling process's namespace, so it must run from the
    /// host namespace where the uplink lives.
    pub fn add_uplink_redirect(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.devmap_insert(REDIRECT_UPLINK, ifindex)
    }

    pub fn remove_uplink_redirect(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.devmap_remove(REDIRECT_UPLINK, ifindex)
    }

    /// Register a veth peer as a decap redirect target. The insert resolves the
    /// ifindex against the calling process's namespace, so when the peer lives in
    /// a hidden namespace this must run from inside it.
    pub fn add_peer_redirect(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.devmap_insert(REDIRECT_PEER, ifindex)
    }

    pub fn remove_peer_redirect(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.devmap_remove(REDIRECT_PEER, ifindex)
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

/// Open the pinned state map, or create-and-pin it. Created from userspace
/// (not the eBPF object) since no program reads it and bpf-linker may collect
/// unreferenced object maps.
fn open_or_create_state_map(
    pins: &PinPaths,
) -> anyhow::Result<aya::maps::Array<aya::maps::MapData, etherip_xdp_common::PinnedState>> {
    let path = pins.map(STATE_MAP);
    let data = match aya::maps::MapData::from_pin(&path) {
        Ok(data) => data,
        Err(_) => {
            let def = aya_obj::maps::bpf_map_def {
                map_type: aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                key_size: std::mem::size_of::<u32>() as u32,
                value_size: std::mem::size_of::<etherip_xdp_common::PinnedState>() as u32,
                max_entries: 1,
                ..Default::default()
            };
            let obj = aya_obj::Map::Legacy(aya_obj::maps::LegacyMap {
                def,
                inner_def: None,
                section_index: 0,
                section_kind: aya_obj::EbpfSectionKind::Maps,
                symbol_index: None,
                data: Vec::new(),
            });
            let data = aya::maps::MapData::create(obj, STATE_MAP, None)
                .map_err(|e| anyhow::anyhow!("create state map: {e}"))?;
            data.pin(&path)
                .map_err(|e| anyhow::anyhow!("pin state map at {}: {e}", path.display()))?;
            data
        }
    };
    aya::maps::Array::try_from(aya::maps::Map::Array(data))
        .map_err(|e| anyhow::anyhow!("state map has an unexpected shape: {e}"))
}

/// Group-open the pins so the next instance's (different) DynamicUser uid can
/// reopen them; `UMask=0077` makes fresh pins 0600. Only the owner may chmod,
/// so failures on pins adopted from a previous instance (already 0660) are
/// expected and ignored.
fn chmod_pins(pins: &PinPaths) {
    for name in OBJECT_MAPS.iter().chain(std::iter::once(&STATE_MAP)) {
        let _ = std::fs::set_permissions(
            pins.map(name),
            std::os::unix::fs::PermissionsExt::from_mode(0o660),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_paths_layout() {
        let pins = PinPaths::new("eth1");
        assert_eq!(
            pins.base(),
            std::path::Path::new("/sys/fs/bpf/etherip-xdp/eth1")
        );
        assert_eq!(
            pins.map("ENCAP_CONFIG"),
            std::path::PathBuf::from("/sys/fs/bpf/etherip-xdp/eth1/maps/ENCAP_CONFIG")
        );
    }

    #[test]
    fn specs_match_shared_struct_sizes() {
        // The specs must track the real map value/key layouts; a drifting
        // struct must show up here, not as a silent runtime mismatch.
        let specs = expected_map_specs();
        let encap = specs.iter().find(|s| s.name == "ENCAP_CONFIG").unwrap();
        assert_eq!(
            encap.value_size as usize,
            std::mem::size_of::<etherip_xdp_common::TunnelConfig>()
        );
        let decap = specs.iter().find(|s| s.name == "DECAP_CONFIG").unwrap();
        assert_eq!(
            decap.key_size as usize,
            std::mem::size_of::<etherip_xdp_common::DecapKey>()
        );
        let state = specs.iter().find(|s| s.name == "ETHERIP_STATE").unwrap();
        assert_eq!(
            state.value_size as usize,
            std::mem::size_of::<etherip_xdp_common::PinnedState>()
        );
    }

    #[test]
    fn classify_verdicts() {
        // All present + state ok -> compatible.
        assert_eq!(
            classify(&[Some(true), Some(true)], true),
            PinState::Compatible
        );
        // Nothing pinned -> fresh start, regardless of the state gate.
        assert_eq!(classify(&[None, None], false), PinState::Absent);
        // Any wrong shape -> mismatch, even alongside compatible maps.
        assert_eq!(
            classify(&[Some(true), Some(false)], true),
            PinState::Mismatch
        );
        // Partial set (mid-setup crash) -> mismatch.
        assert_eq!(classify(&[Some(true), None], true), PinState::Mismatch);
        // Complete set but a foreign/absent state record -> mismatch.
        assert_eq!(
            classify(&[Some(true), Some(true)], false),
            PinState::Mismatch
        );
    }

    #[test]
    fn object_digest_is_stable() {
        assert_eq!(object_digest(), object_digest());
        assert_ne!(object_digest(), [0u8; 32]);
    }
}

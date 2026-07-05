//! JSON tunnel configuration.
//!
//! Each tunnel is a drop-in file under the per-interface config directory
//! (default `/etc/etherip-xdp/interfaces.d/<device>/`), one tunnel per file:
//!
//! ```json
//! { "name": "peer", "local": "2001:db8::1", "remote": "2001:db8::2", "mss": "auto" }
//! ```
//!
//! Directories are searched with systemd drop-in precedence (the runtime root
//! from `$RUNTIME_DIRECTORY`, then `/etc/etherip-xdp`, overridable via
//! `--config-root`/`--config-dir`): a file name found in a higher-precedence
//! directory shadows the same name lower down.
//!
//! The external device is the process scope (CLI `device` argument / systemd
//! instance `%i`), so it is not repeated per file. `name` defaults to the file
//! stem. `local` may be omitted to auto-select the outer source address from the
//! route to `remote` (the kernel's preferred source), which then tracks underlay
//! address changes. Both endpoints accept an optional `/N` prefix length
//! (64..=128, e.g. `"local": "2001:db8:1::/64"`) when the underlay *routes*
//! that prefix to the node: the bits below `/N` then carry a per-flow hash of
//! the inner headers so transit ECMP/LAG sees flow entropy, and decap accepts
//! any host bits within the peer's prefix. A prefixed `local` must be explicit
//! (auto-select only ever yields a single address). `mss` is `"auto"` (default), `"off"`, an integer (both
//! families), or `{ "ipv4": N, "ipv6": N }` (a missing family falls back to auto).
//! `mac` sets the user-facing interface's MAC on the connected L2 domain: omit to
//! keep the kernel-assigned address (default), `"inherit"` to copy the external
//! device's MAC, or an explicit `"xx:xx:xx:xx:xx:xx"` address.
//! `next_hop_on_link` selects how the remote endpoint is treated when the route
//! lookup returns no gateway: `"maybe"` (default), `"always"`, or `"never"`.
//! `next_hop_src` overrides the source address hinting the route lookup that
//! resolves the next hop (default: `local`'s address or prefix base) — for
//! source-keyed policy routing, or when a routed prefix base selects no route.

/// How to clamp the inner TCP MSS for a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MssConfig {
    /// Derive both clamps from the tunnel MTU (default).
    #[default]
    Auto,
    /// Disable MSS clamping.
    Off,
    /// Use one explicit value for both IPv4 and IPv6.
    Both(u16),
    /// Explicit per-family clamps; a missing family falls back to auto.
    PerFamily {
        ipv4: Option<u16>,
        ipv6: Option<u16>,
    },
}

impl MssConfig {
    /// Resolve to concrete `(ipv4, ipv6)` clamp values for a tunnel MTU. A value
    /// of 0 means "no clamping" to the eBPF program.
    pub fn resolve(&self, tunnel_mtu: i32) -> (u16, u16) {
        let (auto4, auto6) = etherip_xdp_common::mss_clamp_from_mtu(tunnel_mtu);
        match *self {
            MssConfig::Auto => (auto4, auto6),
            MssConfig::Off => (0, 0),
            MssConfig::Both(v) => (v, v),
            MssConfig::PerFamily { ipv4, ipv6 } => (ipv4.unwrap_or(auto4), ipv6.unwrap_or(auto6)),
        }
    }
}

/// Local MAC address policy for the user-facing tunnel interface, i.e. the
/// address it presents on the connected L2 domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MacConfig {
    /// Keep the kernel-assigned veth MAC (default).
    #[default]
    Auto,
    /// Inherit the external (uplink) device's MAC.
    Inherit,
    /// Force an explicit MAC address.
    Explicit([u8; 6]),
}

/// A tunnel endpoint: base address plus prefix length. `plen == 128` is a
/// single fixed address; 64..=127 is a routed prefix whose host bits carry the
/// inner flow hash on encap and match any value on decap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointPrefix {
    /// Masked base address (bits below `plen` are zero, enforced at parse).
    pub addr: std::net::Ipv6Addr,
    /// Prefix length, 64..=128.
    pub plen: u8,
}

impl EndpointPrefix {
    /// A single fixed address (`/128`).
    pub fn host(addr: std::net::Ipv6Addr) -> Self {
        EndpointPrefix { addr, plen: 128 }
    }

    /// Whether the two prefixes share any address (the shorter one contains
    /// the other's base).
    pub fn overlaps(&self, other: &EndpointPrefix) -> bool {
        let p = self.plen.min(other.plen);
        etherip_xdp_common::mask_addr(self.addr.octets(), p)
            == etherip_xdp_common::mask_addr(other.addr.octets(), p)
    }
}

impl std::fmt::Display for EndpointPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.plen == 128 {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.plen)
        }
    }
}

impl std::str::FromStr for EndpointPrefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        parse_endpoint(s, "endpoint")
    }
}

/// A fully-validated tunnel definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSpec {
    /// Tunnel name (also the user-facing veth interface name).
    pub name: String,
    /// Local outer IPv6 endpoint. `None` means auto-select from the route to
    /// `remote` (the kernel's preferred source), tracking underlay changes;
    /// auto-selected sources are always single addresses (`/128`).
    pub local: Option<EndpointPrefix>,
    /// Remote outer IPv6 endpoint.
    pub remote: EndpointPrefix,
    /// MSS clamping policy.
    pub mss: MssConfig,
    /// Optional tunnel MTU override (default: external MTU minus overhead).
    pub mtu: Option<u32>,
    /// Local MAC address presented on the connected L2 domain.
    pub mac: MacConfig,
    /// On-link policy for the next hop when the route lookup returns no gateway.
    pub next_hop_on_link: crate::control::resolver::NextHopOnLink,
    /// Source address used as the `from` hint of the route lookup that
    /// resolves the next hop for `remote`. `None` hints with `local`'s
    /// address (or prefix base). Needed when that default selects no route —
    /// e.g. source-keyed policy routing, or a routed prefix base the FIB
    /// rules don't cover.
    pub next_hop_src: Option<std::net::Ipv6Addr>,
    /// Outer 802.1Q VLAN id (1..=4094) the underlay runs on; `None` means
    /// untagged. The data path tags encapsulated frames with it, and next-hop
    /// resolution runs on the matching VLAN subinterface of the uplink rather
    /// than the physical device.
    pub vlan: Option<u16>,
    /// Enforce on decap that a frame's outer VLAN matches [`Self::vlan`]
    /// (default `false`). Off, decap is VLAN-agnostic and works regardless of
    /// the uplink's RX VLAN offload; on, it drops wrong-VLAN frames but then
    /// requires the tag to be visible to XDP (RX VLAN offload disabled).
    pub check_vlan_tag_on_decap: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunnel {
    name: Option<String>,
    local: Option<String>,
    remote: String,
    mss: Option<RawMss>,
    mtu: Option<u32>,
    mac: Option<String>,
    next_hop_on_link: Option<String>,
    next_hop_src: Option<std::net::Ipv6Addr>,
    vlan: Option<u16>,
    check_vlan_tag_on_decap: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum RawMss {
    Keyword(String),
    Value(u16),
    PerFamily {
        ipv4: Option<u16>,
        ipv6: Option<u16>,
    },
}

fn convert_mss(raw: Option<RawMss>) -> anyhow::Result<MssConfig> {
    Ok(match raw {
        None => MssConfig::Auto,
        Some(RawMss::Keyword(k)) => match k.to_ascii_lowercase().as_str() {
            "auto" => MssConfig::Auto,
            "off" | "none" | "disabled" => MssConfig::Off,
            other => anyhow::bail!(
                "invalid mss value {other:?} (expected \"auto\", \"off\", an integer, or {{ipv4,ipv6}})"
            ),
        },
        Some(RawMss::Value(v)) => MssConfig::Both(v),
        Some(RawMss::PerFamily { ipv4, ipv6 }) => MssConfig::PerFamily { ipv4, ipv6 },
    })
}

fn convert_on_link(raw: Option<String>) -> anyhow::Result<crate::control::resolver::NextHopOnLink> {
    Ok(match raw {
        None => crate::control::resolver::NextHopOnLink::default(),
        Some(k) => match k.to_ascii_lowercase().as_str() {
            "maybe" => crate::control::resolver::NextHopOnLink::Maybe,
            "always" => crate::control::resolver::NextHopOnLink::Always,
            "never" => crate::control::resolver::NextHopOnLink::Never,
            other => anyhow::bail!(
                "invalid next_hop_on_link value {other:?} (expected \"maybe\", \"always\", or \"never\")"
            ),
        },
    })
}

/// Validate an optional VLAN id: 1..=4094 (0 and 4095 are reserved by 802.1Q).
fn convert_vlan(raw: Option<u16>) -> anyhow::Result<Option<u16>> {
    match raw {
        None => Ok(None),
        Some(v) if (1..=4094).contains(&v) => Ok(Some(v)),
        Some(v) => anyhow::bail!("invalid vlan {v}: id must be between 1 and 4094"),
    }
}

fn convert_mac(raw: Option<String>) -> anyhow::Result<MacConfig> {
    let Some(s) = raw else {
        return Ok(MacConfig::Auto);
    };
    if s.eq_ignore_ascii_case("inherit") {
        return Ok(MacConfig::Inherit);
    }
    Ok(MacConfig::Explicit(parse_mac(&s)?))
}

/// Parse a colon-separated `xx:xx:xx:xx:xx:xx` unicast MAC address.
fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut octets = [0u8; 6];
    let mut count = 0;
    for (i, part) in s.split(':').enumerate() {
        let octet = octets.get_mut(i).ok_or_else(|| {
            anyhow::anyhow!("invalid mac {s:?}: expected 6 colon-separated octets")
        })?;
        *octet = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow::anyhow!("invalid mac {s:?}: bad octet {part:?}"))?;
        count = i + 1;
    }
    if count != 6 {
        anyhow::bail!("invalid mac {s:?}: expected 6 colon-separated octets");
    }
    if octets[0] & 0x01 != 0 {
        anyhow::bail!(
            "invalid mac {s:?}: multicast/broadcast addresses cannot be an interface MAC"
        );
    }
    if octets == [0u8; 6] {
        anyhow::bail!("invalid mac {s:?}: the all-zero address cannot be an interface MAC");
    }
    Ok(octets)
}

fn validate_next_hop_src(addr: std::net::Ipv6Addr) -> anyhow::Result<std::net::Ipv6Addr> {
    if addr.to_ipv4_mapped().is_some() {
        anyhow::bail!(
            "next_hop_src address {addr} is an IPv4-mapped address, not a genuine IPv6 source"
        );
    }
    if addr.is_unspecified() {
        anyhow::bail!("next_hop_src must not be the unspecified address");
    }
    Ok(addr)
}

/// Parse an endpoint as `addr` or `addr/plen` (64..=128), rejecting non-zero
/// host bits so the stored base is always the masked prefix.
fn parse_endpoint(s: &str, role: &str) -> anyhow::Result<EndpointPrefix> {
    let (addr_str, plen) = match s.split_once('/') {
        None => (s, 128u8),
        Some((addr, plen)) => {
            let plen: u8 = plen
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid {role} {s:?}: bad prefix length"))?;
            if !(64..=128).contains(&plen) {
                anyhow::bail!(
                    "invalid {role} {s:?}: prefix length must be between 64 and 128 \
                     (the host bits carry a 64-bit flow hash)"
                );
            }
            (addr, plen)
        }
    };
    let addr: std::net::Ipv6Addr = addr_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid {role} {s:?}: not an IPv6 address"))?;
    if addr.to_ipv4_mapped().is_some() {
        anyhow::bail!(
            "{role} address {addr} is an IPv4-mapped address, not a genuine IPv6 endpoint"
        );
    }
    let masked = std::net::Ipv6Addr::from(etherip_xdp_common::mask_addr(addr.octets(), plen));
    if masked != addr {
        anyhow::bail!(
            "{role} {s} has non-zero bits below /{plen}; the host bits are filled \
             per flow — use {masked}/{plen}"
        );
    }
    if plen < 128 && addr.is_unspecified() {
        // The daemon uses an unspecified source as its "pending" sentinel, so a
        // legitimately-zero base must be impossible.
        anyhow::bail!("invalid {role} {s:?}: the all-zero prefix cannot be an endpoint");
    }
    Ok(EndpointPrefix { addr, plen })
}

/// Reject tunnel combinations the decap demux cannot disambiguate (or fit).
/// Auto-selected locals are unknown until runtime, so they conservatively
/// overlap any prefixed local and nothing else.
pub fn validate_tunnel_set(specs: &[TunnelSpec]) -> anyhow::Result<()> {
    let locals_overlap = |a: &TunnelSpec, b: &TunnelSpec| match (&a.local, &b.local) {
        (Some(a), Some(b)) => a.overlaps(b),
        (None, Some(one)) | (Some(one), None) => one.plen < 128,
        (None, None) => false,
    };
    for (i, a) in specs.iter().enumerate() {
        if let Some(local) = &a.local
            && local.overlaps(&a.remote)
            && (local.plen < 128 || a.remote.plen < 128)
        {
            anyhow::bail!(
                "tunnel {:?}: local {} overlaps remote {} — the node would decap \
                 its own encapsulated frames",
                a.name,
                local,
                a.remote
            );
        }
        for b in &specs[i + 1..] {
            if a.remote.overlaps(&b.remote) && locals_overlap(a, b) {
                anyhow::bail!(
                    "tunnels {:?} (remote {}) and {:?} (remote {}) are ambiguous: \
                     a packet could demux to either",
                    a.name,
                    a.remote,
                    b.name,
                    b.remote
                );
            }
        }
    }
    let mut pairs: Vec<(u8, u8)> = specs
        .iter()
        .map(|s| (s.remote.plen, s.local_plen()))
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    if pairs.len() > etherip_xdp_common::DECAP_PLEN_PAIRS_MAX {
        anyhow::bail!(
            "{} distinct (remote, local) prefix-length combinations exceed the \
             decap table capacity of {}",
            pairs.len(),
            etherip_xdp_common::DECAP_PLEN_PAIRS_MAX
        );
    }
    Ok(())
}

impl TunnelSpec {
    fn from_raw(raw: RawTunnel, default_name: &str) -> anyhow::Result<Self> {
        Ok(TunnelSpec {
            name: raw.name.unwrap_or_else(|| default_name.to_string()),
            local: raw.local.map(|s| parse_endpoint(&s, "local")).transpose()?,
            remote: parse_endpoint(&raw.remote, "remote")?,
            mss: convert_mss(raw.mss)?,
            mtu: raw.mtu,
            mac: convert_mac(raw.mac)?,
            next_hop_on_link: convert_on_link(raw.next_hop_on_link)?,
            next_hop_src: raw.next_hop_src.map(validate_next_hop_src).transpose()?,
            vlan: convert_vlan(raw.vlan)?,
            check_vlan_tag_on_decap: raw.check_vlan_tag_on_decap.unwrap_or(false),
        })
    }

    /// Prefix length of the local endpoint; an auto-selected source is always
    /// a single address.
    pub fn local_plen(&self) -> u8 {
        self.local.map_or(128, |e| e.plen)
    }

    /// Parse a single tunnel definition from JSON text, defaulting the name to
    /// `default_name` when the file omits it.
    pub fn from_json(text: &str, default_name: &str) -> anyhow::Result<Self> {
        let raw: RawTunnel = serde_json::from_str(text)?;
        TunnelSpec::from_raw(raw, default_name)
    }
}

/// Load and validate every `*.json` tunnel definition across `dirs`, applying
/// systemd-style drop-in precedence: when the same file name appears in more
/// than one directory, the copy in the earlier (higher-precedence) directory
/// wins and the rest are shadowed. Surviving files are processed in file-name
/// order for determinism. A missing directory is skipped (not every searched
/// root is present); duplicate tunnel names (after shadowing) are an error.
///
/// Each spec is returned paired with the absolute path of the winning file it
/// was loaded from, so the daemon can report it over the management interface.
pub async fn load_dirs(
    dirs: &[std::path::PathBuf],
) -> anyhow::Result<Vec<(std::path::PathBuf, TunnelSpec)>> {
    // File name -> winning path, kept ordered by file name for a deterministic
    // load order regardless of directory iteration order.
    let mut chosen: std::collections::BTreeMap<std::ffi::OsString, std::path::PathBuf> =
        std::collections::BTreeMap::new();
    for dir in dirs {
        let mut entries = match tokio::fs::read_dir(dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(anyhow::anyhow!("read config dir {}: {e}", dir.display())),
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| anyhow::anyhow!("read config dir {}: {e}", dir.display()))?
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                // The first directory to claim a file name wins; later (lower
                // precedence) directories with the same name are shadowed.
                chosen.entry(entry.file_name()).or_insert(path);
            }
        }
    }

    let mut specs: Vec<(std::path::PathBuf, TunnelSpec)> = Vec::with_capacity(chosen.len());
    let mut seen = std::collections::HashSet::new();
    for path in chosen.into_values() {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 config file name: {}", path.display()))?;
        let text = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        let spec = TunnelSpec::from_json(&text, stem)
            .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
        if !seen.insert(spec.name.clone()) {
            anyhow::bail!(
                "duplicate tunnel name {:?} (in {})",
                spec.name,
                path.display()
            );
        }
        specs.push((path, spec));
    }
    let bare: Vec<TunnelSpec> = specs.iter().map(|(_, s)| s.clone()).collect();
    validate_tunnel_set(&bare)?;
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(json: &str) -> TunnelSpec {
        TunnelSpec::from_json(json, "stemname").unwrap()
    }

    #[test]
    fn name_defaults_to_stem() {
        let s = spec(r#"{"local":"2001:db8::1","remote":"2001:db8::2"}"#);
        assert_eq!(s.name, "stemname");
        assert_eq!(s.mss, MssConfig::Auto); // omitted -> auto
    }

    #[test]
    fn explicit_name_wins() {
        let s = spec(r#"{"name":"peer","local":"2001:db8::1","remote":"2001:db8::2"}"#);
        assert_eq!(s.name, "peer");
    }

    #[test]
    fn local_is_optional() {
        // Omitted local -> auto-select.
        let s = spec(r#"{"remote":"2001:db8::2"}"#);
        assert_eq!(s.local, None);
        // Explicit local is parsed.
        let s = spec(r#"{"local":"2001:db8::1","remote":"2001:db8::2"}"#);
        assert_eq!(s.local, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn endpoint_prefix_parse_and_display() {
        let e: EndpointPrefix = "2001:db8::1".parse().unwrap();
        assert_eq!((e.addr.to_string().as_str(), e.plen), ("2001:db8::1", 128));
        assert_eq!(e.to_string(), "2001:db8::1");

        let e: EndpointPrefix = "2001:db8:1::/64".parse().unwrap();
        assert_eq!((e.addr.to_string().as_str(), e.plen), ("2001:db8:1::", 64));
        assert_eq!(e.to_string(), "2001:db8:1::/64");

        let s = spec(r#"{"local":"fd00:a::/112","remote":"fd00:b::/64"}"#);
        assert_eq!(s.local.unwrap().plen, 112);
        assert_eq!(s.remote.plen, 64);
        assert_eq!(s.local_plen(), 112);
    }

    #[test]
    fn endpoint_prefix_rejects_invalid() {
        let parse = |s: &str| TunnelSpec::from_json(&format!(r#"{{"remote":"{s}"}}"#), "t");
        for bad in [
            "2001:db8::/63",    // below the 64-bit hash width
            "2001:db8::/129",   // out of range
            "2001:db8::/x",     // not a number
            "2001:db8::/64/64", // double suffix
            "nonsense/64",      // not an address
            "::ffff:1.2.3.4",   // IPv4-mapped (pre-existing rule)
            "::/64",            // all-zero base is the pending sentinel
        ] {
            assert!(parse(bad).is_err(), "{bad} must be rejected");
        }
        // Non-zero host bits: the error suggests the masked base.
        let err = parse("2001:db8::1/64").unwrap_err().to_string();
        assert!(err.contains("2001:db8::/64"), "unhelpful error: {err}");
    }

    #[test]
    fn next_hop_src_variants() {
        // Omitted -> the local endpoint hints the lookup.
        assert_eq!(spec(r#"{"remote":"2001:db8::2"}"#).next_hop_src, None);
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","next_hop_src":"2001:db8::a"}"#).next_hop_src,
            Some("2001:db8::a".parse().unwrap())
        );
        // A plain address only: no prefix suffix, no IPv4-mapped, no ::.
        for bad in [
            r#"{"remote":"2001:db8::2","next_hop_src":"2001:db8::/64"}"#,
            r#"{"remote":"2001:db8::2","next_hop_src":"::ffff:1.2.3.4"}"#,
            r#"{"remote":"2001:db8::2","next_hop_src":"::"}"#,
        ] {
            assert!(
                TunnelSpec::from_json(bad, "t").is_err(),
                "{bad} must be rejected"
            );
        }
    }

    fn named(name: &str, local: Option<&str>, remote: &str) -> TunnelSpec {
        TunnelSpec {
            name: name.to_string(),
            local: local.map(|l| l.parse().unwrap()),
            remote: remote.parse().unwrap(),
            mss: MssConfig::Auto,
            mtu: None,
            mac: MacConfig::Auto,
            next_hop_on_link: crate::control::resolver::NextHopOnLink::default(),
            next_hop_src: None,
            vlan: None,
            check_vlan_tag_on_decap: false,
        }
    }

    #[test]
    fn validate_tunnel_set_overlap_matrix() {
        let ok = |specs: &[TunnelSpec]| validate_tunnel_set(specs).is_ok();

        // Today's shapes stay legal: distinct /128s, same remote with two
        // auto locals, same remote with an auto and an explicit /128 local.
        assert!(ok(&[
            named("a", Some("fd00::1"), "fd00::2"),
            named("b", Some("fd00::1"), "fd00::3"),
        ]));
        assert!(ok(&[
            named("a", None, "fd00::2"),
            named("b", None, "fd00::2"),
        ]));
        assert!(ok(&[
            named("a", None, "fd00::2"),
            named("b", Some("fd00::9"), "fd00::2"),
        ]));

        // Distinct prefixes demux fine.
        assert!(ok(&[
            named("a", Some("fd00:a::/112"), "fd00:b::/112"),
            named("b", Some("fd00:a::1:0/112"), "fd00:b::1:0/112"),
        ]));

        // Identical (remote, local) pair: one decap key, ambiguous.
        assert!(!ok(&[
            named("a", Some("fd00::1"), "fd00::2"),
            named("b", Some("fd00::1"), "fd00::2"),
        ]));
        // Overlapping remote prefixes with overlapping locals.
        assert!(!ok(&[
            named("a", Some("fd00:a::/64"), "fd00:b::/64"),
            named("b", Some("fd00:a::/64"), "fd00:b::beef:0:0:0/112"),
        ]));
        // An auto local cannot be proven outside a prefixed local.
        assert!(!ok(&[
            named("a", None, "fd00::2"),
            named("b", Some("fd00:a::/64"), "fd00::2"),
        ]));

        // Per-tunnel: local overlapping remote decapsulates our own frames.
        assert!(!ok(&[named("a", Some("fd00:a::/64"), "fd00:a::/112")]));
        // ... but two equal /128s (loopback-guard territory) stay accepted.
        assert!(ok(&[named("a", Some("fd00::1"), "fd00::1")]));
    }

    #[test]
    fn validate_tunnel_set_caps_plen_pairs() {
        // 9 distinct (remote, local) plen combinations exceed the table.
        let specs: Vec<TunnelSpec> = (0..9u32)
            .map(|i| {
                named(
                    &format!("t{i}"),
                    Some(&format!("fd00:a:{i}::/{}", 96 + i)),
                    &format!("fd00:b:{i}::/112"),
                )
            })
            .collect();
        let err = validate_tunnel_set(&specs).unwrap_err().to_string();
        assert!(err.contains("capacity"), "unexpected error: {err}");

        // The same combination repeated does not count against the cap.
        let specs: Vec<TunnelSpec> = (0..9u32)
            .map(|i| {
                named(
                    &format!("t{i}"),
                    Some(&format!("fd00:a:{i}::/112")),
                    &format!("fd00:b:{i}::/112"),
                )
            })
            .collect();
        assert!(validate_tunnel_set(&specs).is_ok());
    }

    #[test]
    fn mss_variants() {
        assert_eq!(
            spec(r#"{"local":"2001:db8::1","remote":"2001:db8::2","mss":"auto"}"#).mss,
            MssConfig::Auto
        );
        assert_eq!(
            spec(r#"{"local":"2001:db8::1","remote":"2001:db8::2","mss":"off"}"#).mss,
            MssConfig::Off
        );
        assert_eq!(
            spec(r#"{"local":"2001:db8::1","remote":"2001:db8::2","mss":1404}"#).mss,
            MssConfig::Both(1404)
        );
        assert_eq!(
            spec(
                r#"{"local":"2001:db8::1","remote":"2001:db8::2","mss":{"ipv4":1404,"ipv6":1384}}"#
            )
            .mss,
            MssConfig::PerFamily {
                ipv4: Some(1404),
                ipv6: Some(1384)
            }
        );
        assert_eq!(
            spec(r#"{"local":"2001:db8::1","remote":"2001:db8::2","mss":{"ipv4":1404}}"#).mss,
            MssConfig::PerFamily {
                ipv4: Some(1404),
                ipv6: None
            }
        );
    }

    #[test]
    fn mss_resolution() {
        // Auto derives from the MTU.
        assert_eq!(MssConfig::Auto.resolve(1444), (1404, 1384));
        assert_eq!(MssConfig::Off.resolve(1444), (0, 0));
        assert_eq!(MssConfig::Both(1300).resolve(1444), (1300, 1300));
        // PerFamily: missing family falls back to auto.
        assert_eq!(
            MssConfig::PerFamily {
                ipv4: Some(1300),
                ipv6: None
            }
            .resolve(1444),
            (1300, 1384)
        );
    }

    #[test]
    fn mac_variants() {
        // Omitted -> auto (keep kernel-assigned).
        assert_eq!(spec(r#"{"remote":"2001:db8::2"}"#).mac, MacConfig::Auto);
        // Keyword "inherit" is case-insensitive.
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","mac":"inherit"}"#).mac,
            MacConfig::Inherit
        );
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","mac":"INHERIT"}"#).mac,
            MacConfig::Inherit
        );
        // Explicit address.
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","mac":"02:00:5e:10:00:01"}"#).mac,
            MacConfig::Explicit([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01])
        );
    }

    #[test]
    fn vlan_variants() {
        // Omitted -> untagged.
        assert_eq!(spec(r#"{"remote":"2001:db8::2"}"#).vlan, None);
        // A valid id is carried through.
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","vlan":100}"#).vlan,
            Some(100)
        );
        // Boundary ids (1 and 4094) are accepted.
        assert_eq!(spec(r#"{"remote":"2001:db8::2","vlan":1}"#).vlan, Some(1));
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","vlan":4094}"#).vlan,
            Some(4094)
        );
        // Reserved/out-of-range ids are rejected (0, 4095, and above the u16 is
        // caught by serde before us).
        for bad in ["0", "4095", "5000"] {
            assert!(
                TunnelSpec::from_json(&format!(r#"{{"remote":"2001:db8::2","vlan":{bad}}}"#), "n")
                    .is_err(),
                "vlan {bad} must be rejected"
            );
        }
    }

    #[test]
    fn check_vlan_tag_on_decap_defaults_off() {
        // Omitted -> false (VLAN-agnostic decap).
        assert!(!spec(r#"{"remote":"2001:db8::2","vlan":100}"#).check_vlan_tag_on_decap);
        // Explicit true is carried through.
        assert!(
            spec(r#"{"remote":"2001:db8::2","vlan":100,"check_vlan_tag_on_decap":true}"#)
                .check_vlan_tag_on_decap
        );
        assert!(
            !spec(r#"{"remote":"2001:db8::2","check_vlan_tag_on_decap":false}"#)
                .check_vlan_tag_on_decap
        );
    }

    #[test]
    fn next_hop_on_link_variants() {
        // Omitted -> default (maybe).
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2"}"#).next_hop_on_link,
            crate::control::resolver::NextHopOnLink::Maybe
        );
        // Keywords are case-insensitive.
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","next_hop_on_link":"always"}"#).next_hop_on_link,
            crate::control::resolver::NextHopOnLink::Always
        );
        assert_eq!(
            spec(r#"{"remote":"2001:db8::2","next_hop_on_link":"NEVER"}"#).next_hop_on_link,
            crate::control::resolver::NextHopOnLink::Never
        );
        // Unknown keyword is rejected.
        assert!(
            TunnelSpec::from_json(
                r#"{"remote":"2001:db8::2","next_hop_on_link":"sometimes"}"#,
                "n"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_bad_mac() {
        // Too few octets.
        assert!(
            TunnelSpec::from_json(r#"{"remote":"2001:db8::2","mac":"02:00:5e"}"#, "n").is_err()
        );
        // Too many octets.
        assert!(
            TunnelSpec::from_json(
                r#"{"remote":"2001:db8::2","mac":"02:00:5e:10:00:01:02"}"#,
                "n"
            )
            .is_err()
        );
        // Non-hex octet.
        assert!(
            TunnelSpec::from_json(r#"{"remote":"2001:db8::2","mac":"02:00:5e:10:00:zz"}"#, "n")
                .is_err()
        );
        // Multicast (group bit set in the first octet).
        assert!(
            TunnelSpec::from_json(r#"{"remote":"2001:db8::2","mac":"01:00:5e:10:00:01"}"#, "n")
                .is_err()
        );
        // All-zero.
        assert!(
            TunnelSpec::from_json(r#"{"remote":"2001:db8::2","mac":"00:00:00:00:00:00"}"#, "n")
                .is_err()
        );
    }

    #[test]
    fn rejects_non_ipv6() {
        // IPv4 literal cannot deserialize as an Ipv6Addr.
        assert!(
            TunnelSpec::from_json(r#"{"local":"192.168.1.1","remote":"2001:db8::2"}"#, "n")
                .is_err()
        );
        // Not an address at all.
        assert!(
            TunnelSpec::from_json(r#"{"local":"not-an-ip","remote":"2001:db8::2"}"#, "n").is_err()
        );
        // IPv4-mapped is rejected as not a genuine IPv6 endpoint.
        assert!(
            TunnelSpec::from_json(
                r#"{"local":"::ffff:192.0.2.1","remote":"2001:db8::2"}"#,
                "n"
            )
            .is_err()
        );
    }

    fn write(dir: &std::path::Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    fn names(specs: &[(std::path::PathBuf, TunnelSpec)]) -> Vec<&str> {
        specs.iter().map(|(_, s)| s.name.as_str()).collect()
    }

    #[tokio::test]
    async fn load_dirs_skips_missing_and_non_json() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "peer.json", r#"{"remote":"2001:db8::2"}"#);
        write(dir.path(), "notes.txt", "ignored");
        let missing = dir.path().join("does-not-exist");
        let specs = load_dirs(&[missing, dir.path().to_path_buf()])
            .await
            .unwrap();
        assert_eq!(names(&specs), vec!["peer"]);
    }

    #[tokio::test]
    async fn load_dirs_sorts_surviving_files_by_name() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.json", r#"{"remote":"2001:db8::2"}"#);
        write(dir.path(), "a.json", r#"{"remote":"2001:db8::3"}"#);
        let specs = load_dirs(&[dir.path().to_path_buf()]).await.unwrap();
        assert_eq!(names(&specs), vec!["a", "b"]);
    }

    #[tokio::test]
    async fn load_dirs_shadows_by_file_name_with_first_dir_winning() {
        let high = tempfile::tempdir().unwrap();
        let low = tempfile::tempdir().unwrap();
        // Same file name in both dirs: the higher-precedence (first) one wins.
        write(high.path(), "peer.json", r#"{"remote":"2001:db8::1"}"#);
        write(low.path(), "peer.json", r#"{"remote":"2001:db8::2"}"#);
        // A name only present in the lower-precedence dir still loads.
        write(low.path(), "office.json", r#"{"remote":"2001:db8::3"}"#);
        let specs = load_dirs(&[high.path().to_path_buf(), low.path().to_path_buf()])
            .await
            .unwrap();
        assert_eq!(names(&specs), vec!["office", "peer"]);
        let peer = specs.iter().find(|(_, s)| s.name == "peer").unwrap();
        let expected: EndpointPrefix = "2001:db8::1".parse().unwrap();
        assert_eq!(peer.1.remote, expected);
    }

    #[tokio::test]
    async fn load_dirs_rejects_duplicate_tunnel_names_across_files() {
        let dir = tempfile::tempdir().unwrap();
        // Different file names, same explicit tunnel name.
        write(
            dir.path(),
            "a.json",
            r#"{"name":"dup","remote":"2001:db8::2"}"#,
        );
        write(
            dir.path(),
            "b.json",
            r#"{"name":"dup","remote":"2001:db8::3"}"#,
        );
        assert!(load_dirs(&[dir.path().to_path_buf()]).await.is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_mss() {
        assert!(
            TunnelSpec::from_json(
                r#"{"local":"2001:db8::1","remote":"2001:db8::2","bogus":1}"#,
                "n"
            )
            .is_err()
        );
        assert!(
            TunnelSpec::from_json(
                r#"{"local":"2001:db8::1","remote":"2001:db8::2","mss":"huge"}"#,
                "n"
            )
            .is_err()
        );
    }
}

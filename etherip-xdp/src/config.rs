//! JSON tunnel configuration.
//!
//! Each tunnel is a drop-in file under the config directory (default
//! `/etc/etherip-xdp/<device>.d/`), one tunnel per file:
//!
//! ```json
//! { "name": "peer", "local": "2001:db8::1", "remote": "2001:db8::2", "mss": "auto" }
//! ```
//!
//! The external device is the process scope (CLI `device` argument / systemd
//! instance `%i`), so it is not repeated per file. `name` defaults to the file
//! stem. `local` may be omitted to auto-select the outer source address from the
//! route to `remote` (the kernel's preferred source), which then tracks underlay
//! address changes. `mss` is `"auto"` (default), `"off"`, an integer (both
//! families), or `{ "ipv4": N, "ipv6": N }` (a missing family falls back to auto).
//! `mac` sets the user-facing interface's MAC on the connected L2 domain: omit to
//! keep the kernel-assigned address (default), `"inherit"` to copy the external
//! device's MAC, or an explicit `"xx:xx:xx:xx:xx:xx"` address.

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

/// A fully-validated tunnel definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSpec {
    /// Tunnel name (also the user-facing veth interface name).
    pub name: String,
    /// Local outer IPv6 endpoint. `None` means auto-select from the route to
    /// `remote` (the kernel's preferred source), tracking underlay changes.
    pub local: Option<std::net::Ipv6Addr>,
    /// Remote outer IPv6 endpoint.
    pub remote: std::net::Ipv6Addr,
    /// MSS clamping policy.
    pub mss: MssConfig,
    /// Optional tunnel MTU override (default: external MTU minus overhead).
    pub mtu: Option<u32>,
    /// Local MAC address presented on the connected L2 domain.
    pub mac: MacConfig,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunnel {
    name: Option<String>,
    local: Option<std::net::Ipv6Addr>,
    remote: std::net::Ipv6Addr,
    mss: Option<RawMss>,
    mtu: Option<u32>,
    mac: Option<String>,
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

fn validate_endpoint(addr: std::net::Ipv6Addr, role: &str) -> anyhow::Result<std::net::Ipv6Addr> {
    if addr.to_ipv4_mapped().is_some() {
        anyhow::bail!(
            "{role} address {addr} is an IPv4-mapped address, not a genuine IPv6 endpoint"
        );
    }
    Ok(addr)
}

impl TunnelSpec {
    fn from_raw(raw: RawTunnel, default_name: &str) -> anyhow::Result<Self> {
        Ok(TunnelSpec {
            name: raw.name.unwrap_or_else(|| default_name.to_string()),
            local: raw
                .local
                .map(|s| validate_endpoint(s, "local"))
                .transpose()?,
            remote: validate_endpoint(raw.remote, "remote")?,
            mss: convert_mss(raw.mss)?,
            mtu: raw.mtu,
            mac: convert_mac(raw.mac)?,
        })
    }

    /// Parse a single tunnel definition from JSON text, defaulting the name to
    /// `default_name` when the file omits it.
    pub fn from_json(text: &str, default_name: &str) -> anyhow::Result<Self> {
        let raw: RawTunnel = serde_json::from_str(text)?;
        TunnelSpec::from_raw(raw, default_name)
    }
}

/// Load and validate every `*.json` tunnel definition in `dir`, sorted by file
/// name for determinism. Duplicate tunnel names are an error.
pub async fn load_dir(dir: &std::path::Path) -> anyhow::Result<Vec<TunnelSpec>> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| anyhow::anyhow!("read config dir {}: {e}", dir.display()))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| anyhow::anyhow!("read config dir {}: {e}", dir.display()))?
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();

    let mut specs: Vec<TunnelSpec> = Vec::with_capacity(files.len());
    let mut seen = std::collections::HashSet::new();
    for path in files {
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
        specs.push(spec);
    }
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

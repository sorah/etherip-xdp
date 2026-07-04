//! Shared fixtures for the EtherIP data-path fuzz targets: the two ends of a
//! tunnel as [`TunnelConfig`](etherip_xdp_common::TunnelConfig)s, and an
//! `arbitrary`-driven inner-frame builder.
//!
//! The "A" end ([`encap_cfg`]) encapsulates toward the "B" end ([`decap_cfg`]);
//! their addresses are deliberately distinct so an A→B frame never trips B's
//! loopback guard, which lets [`roundtrip`](../roundtrip/index.html) assert that
//! `decap ∘ encap` reconstructs the inner frame.

/// Outer source address of the A end (and the remote, as seen from B).
pub const ADDR_A: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
/// Outer source address of the B end (and the remote, as seen from A).
pub const ADDR_B: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

const EXTERNAL_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
const DST_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02];
const TUNNEL_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03];

const EXTERNAL_IFINDEX: u32 = 2;
const PEER_IFINDEX: u32 = 3;

/// The A-end encap config: encapsulates toward B with active MSS clamps, so the
/// inner TCP-option parser is exercised.
pub fn encap_cfg() -> etherip_xdp_common::TunnelConfig {
    etherip_xdp_common::TunnelConfig {
        src_addr: ADDR_A,
        dst_addr: ADDR_B,
        internal_ifindex: PEER_IFINDEX,
        external_ifindex: EXTERNAL_IFINDEX,
        tunnel_mac: TUNNEL_MAC,
        external_mac: EXTERNAL_MAC,
        dst_mac: DST_MAC,
        src_plen: 128,
        dst_plen: 128,
        mss_clamp_ipv4: 1404,
        mss_clamp_ipv6: 1384,
    }
}

/// Prefixed A-end local base (`fd00:a::/112`).
pub const PREFIX_A: [u8; 16] = [0xfd, 0x00, 0, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Prefixed B-end local base (`fd00:b::/64`), the remote as seen from A.
pub const PREFIX_B: [u8; 16] = [0xfd, 0x00, 0, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Prefix length of [`PREFIX_A`].
pub const PLEN_A: u8 = 112;
/// Prefix length of [`PREFIX_B`].
pub const PLEN_B: u8 = 64;

/// As [`encap_cfg`] but with prefixed endpoints, so encap fills the host bits
/// of both outer addresses from the inner flow hash.
pub fn encap_cfg_prefixed() -> etherip_xdp_common::TunnelConfig {
    etherip_xdp_common::TunnelConfig {
        src_addr: PREFIX_A,
        dst_addr: PREFIX_B,
        src_plen: PLEN_A,
        dst_plen: PLEN_B,
        ..encap_cfg()
    }
}

/// As [`encap_cfg`] but with MSS clamping disabled, so the inner frame is
/// preserved byte for byte (used by the round-trip property).
pub fn encap_cfg_no_clamp() -> etherip_xdp_common::TunnelConfig {
    etherip_xdp_common::TunnelConfig {
        mss_clamp_ipv4: 0,
        mss_clamp_ipv6: 0,
        ..encap_cfg()
    }
}

/// The B-end decap config: its local address is `ADDR_B`, distinct from the
/// `ADDR_A` source of an encapsulated A→B frame, so the loopback guard passes.
pub fn decap_cfg() -> etherip_xdp_common::TunnelConfig {
    etherip_xdp_common::TunnelConfig {
        src_addr: ADDR_B,
        dst_addr: ADDR_A,
        internal_ifindex: PEER_IFINDEX,
        external_ifindex: EXTERNAL_IFINDEX,
        tunnel_mac: TUNNEL_MAC,
        external_mac: EXTERNAL_MAC,
        dst_mac: DST_MAC,
        src_plen: 128,
        dst_plen: 128,
        mss_clamp_ipv4: 0,
        mss_clamp_ipv6: 0,
    }
}

/// Layer-3 choice for a generated inner frame.
#[derive(arbitrary::Arbitrary, Debug)]
pub enum L3 {
    V4 { src: [u8; 4], dst: [u8; 4] },
    V6 { src: [u8; 16], dst: [u8; 16] },
}

/// A fuzzer-chosen inner Ethernet/IP/TCP frame description.
#[derive(arbitrary::Arbitrary, Debug)]
pub struct InnerSpec {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub l3: L3,
    pub sport: u16,
    pub dport: u16,
    pub syn: bool,
    pub mss: Option<u16>,
    pub payload_len: u8,
}

/// Build the inner Ethernet frame described by `spec`, or `None` if etherparse
/// rejects the combination (e.g. an over-long packet).
pub fn build_inner(spec: &InnerSpec) -> Option<Vec<u8>> {
    // Keep frames small so fuzzing stays fast; the parsers are length-driven, not
    // payload-content-driven.
    let payload = vec![0u8; (spec.payload_len as usize) % 64];

    let eth = etherparse::PacketBuilder::ethernet2(spec.src_mac, spec.dst_mac);
    let ip = match spec.l3 {
        L3::V4 { src, dst } => eth.ipv4(src, dst, 64),
        L3::V6 { src, dst } => eth.ipv6(src, dst, 64),
    };
    let mut tcp = ip.tcp(spec.sport, spec.dport, 0, 0);
    if spec.syn {
        tcp = tcp.syn();
    }
    let builder = match spec.mss {
        Some(mss) => tcp
            .options(&[etherparse::TcpOptionElement::MaximumSegmentSize(mss)])
            .ok()?,
        None => tcp,
    };

    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).ok()?;
    Some(buf)
}

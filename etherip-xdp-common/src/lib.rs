#![cfg_attr(not(test), no_std)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! Types and helpers shared between the userspace daemon and the eBPF program.
//!
//! The wire/config structs here are `#[repr(C)]` and used verbatim as BPF map
//! values, so both sides see an identical byte layout. Pure scalar helpers
//! ([`mss_clamp_from_mtu`], [`checksum_update`]) are unit-tested on the host and
//! reused by both the daemon and the kernel program.

/// IP protocol number for EtherIP (RFC 3378).
pub const ETHERIP_PROTO: u8 = 97;
/// Default outer IPv6 hop limit.
pub const HOP_LIMIT_DEFAULT: u8 = 64;
/// EtherIP version nibble in the high 4 bits of the first header byte (v3 << 4).
pub const ETHERIP_VERSION: u8 = 0x30;

/// Outer encapsulation overhead: Ethernet (14) + IPv6 (40) + EtherIP (2).
pub const OUTER_OVERHEAD: usize = 14 + 40 + 2;

/// Maximum IPv6 extension headers walked on the decap path.
pub const MAX_EXT_HEADERS: usize = 6;
/// Maximum TCP option entries scanned while MSS clamping.
pub const MAX_TCP_OPT_ITERATIONS: usize = 10;

// Header sizes for MSS clamp computation (see `mss_clamp_from_mtu`).
const IPV4_HEADER_LEN: i32 = 20;
const IPV6_HEADER_LEN: i32 = 40;
const TCP_HEADER_LEN: i32 = 20;

/// Per-tunnel parameters, keyed by veth-peer ifindex (encap) and by
/// [`DecapKey`] (decap). Layout is shared with the eBPF program.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelConfig {
    /// Local outer IPv6 source address.
    pub src_addr: [u8; 16],
    /// Remote outer IPv6 destination address.
    pub dst_addr: [u8; 16],
    /// veth-peer ifindex — decap redirect target.
    pub internal_ifindex: u32,
    /// External (uplink) ifindex — encap redirect target.
    pub external_ifindex: u32,
    /// User-facing tunnel interface MAC — written as inner dst MAC on decap.
    pub tunnel_mac: [u8; 6],
    /// Uplink MAC — written as outer src MAC on encap.
    pub external_mac: [u8; 6],
    /// Next-hop MAC — written as outer dst MAC on encap.
    pub dst_mac: [u8; 6],
    pub _pad: [u8; 2],
    /// IPv4 inner MSS clamp; 0 disables clamping.
    pub mss_clamp_ipv4: u16,
    /// IPv6 inner MSS clamp; 0 disables clamping.
    pub mss_clamp_ipv6: u16,
}

impl TunnelConfig {
    /// A zeroed config (all addresses/MACs unset, clamping off).
    pub const fn zeroed() -> Self {
        Self {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            internal_ifindex: 0,
            external_ifindex: 0,
            tunnel_mac: [0; 6],
            external_mac: [0; 6],
            dst_mac: [0; 6],
            _pad: [0; 2],
            mss_clamp_ipv4: 0,
            mss_clamp_ipv6: 0,
        }
    }
}

/// Decap demux key: the outer IPv6 (source, destination) pair, i.e. the
/// remote endpoint as `remote` and our local endpoint as `local`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecapKey {
    /// Expected outer IPv6 source (remote endpoint).
    pub remote: [u8; 16],
    /// Expected outer IPv6 destination (our local endpoint).
    pub local: [u8; 16],
}

// Per-path debug counters (indices into the PERCPU_ARRAY). Mirrors the Go
// program's counters, with DECAP_NO_TUNNEL replacing MAIN_NO_CFG for the
// multi-tunnel demux path.
pub const DBG_ENCAP_ENTER: u32 = 0;
pub const DBG_ENCAP_ADJUST_FAIL: u32 = 1;
pub const DBG_ENCAP_BUILD_FAIL: u32 = 2;
pub const DBG_ENCAP_MSS_FAIL: u32 = 3;
pub const DBG_ENCAP_BOUNDS_FAIL: u32 = 4;
pub const DBG_ENCAP_REDIRECT: u32 = 5;
pub const DBG_DECAP_ENTER: u32 = 6;
pub const DBG_DECAP_NOT_IPV6: u32 = 7;
pub const DBG_DECAP_NOT_ETHERIP: u32 = 8;
pub const DBG_DECAP_NO_TUNNEL: u32 = 9;
pub const DBG_DECAP_OWN_PKT: u32 = 10;
pub const DBG_DECAP_BAD_HEADER: u32 = 11;
pub const DBG_DECAP_REDIRECT: u32 = 12;
pub const DBG_MAIN_ENTER: u32 = 13;
/// Number of debug counters (PERCPU_ARRAY `max_entries`).
pub const DBG_MAX: u32 = 14;

/// Human-readable counter names, indexed by the `DBG_*` constants.
pub const COUNTER_NAMES: [&str; DBG_MAX as usize] = [
    "encap_enter",
    "encap_adjust_fail",
    "encap_build_fail",
    "encap_mss_fail",
    "encap_bounds_fail",
    "encap_redirect",
    "decap_enter",
    "decap_not_ipv6",
    "decap_not_etherip",
    "decap_no_tunnel",
    "decap_own_pkt",
    "decap_bad_header",
    "decap_redirect",
    "main_enter",
];

/// Compute the IPv4 and IPv6 inner-MSS clamp values for a given tunnel MTU.
///
/// Returns `(0, 0)` when the MTU is too small to fit the tunnel overhead.
/// Ports `pkg/tunnel/mss.go:ComputeMSSClamp`.
pub fn mss_clamp_from_mtu(tunnel_mtu: i32) -> (u16, u16) {
    const MIN_MTU: i32 = IPV6_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN; // 80
    if tunnel_mtu < MIN_MTU {
        return (0, 0);
    }
    (
        (tunnel_mtu - IPV4_HEADER_LEN - TCP_HEADER_LEN) as u16,
        (tunnel_mtu - IPV6_HEADER_LEN - TCP_HEADER_LEN) as u16,
    )
}

/// 20-bit ECMP flow hash of an inner Ethernet frame: a polynomial hash over
/// the destination MAC, source MAC, EtherType, and L3 addresses (IPv4 src/dst
/// or IPv6 src/dst). L4 ports are intentionally excluded.
///
/// Ports `src/xdp_prog.c:inner_flow_hash`. The eBPF program mirrors this byte
/// for byte; this slice version is the host-testable reference and is used by
/// the data-path tests to predict the outer IPv6 flow label. IPv4 addresses
/// are folded as native-endian `u32` to match the kernel reading `iphdr->saddr`
/// on a little-endian target.
pub fn inner_flow_hash(frame: &[u8]) -> u32 {
    if frame.len() < 14 {
        return 0;
    }
    let mut h: u32 = 0;
    for &b in &frame[0..6] {
        h = h.wrapping_mul(31).wrapping_add(b as u32); // h_dest
    }
    for &b in &frame[6..12] {
        h = h.wrapping_mul(31).wrapping_add(b as u32); // h_source
    }
    let proto = ((frame[12] as u32) << 8) | (frame[13] as u32); // ntohs(h_proto)
    h = h.wrapping_mul(31).wrapping_add(proto);

    match proto {
        0x0800 if frame.len() >= 14 + 20 => {
            let saddr = u32::from_le_bytes([frame[26], frame[27], frame[28], frame[29]]);
            let daddr = u32::from_le_bytes([frame[30], frame[31], frame[32], frame[33]]);
            h = h.wrapping_mul(31).wrapping_add(saddr);
            h = h.wrapping_mul(31).wrapping_add(daddr);
        }
        0x86DD if frame.len() >= 14 + 40 => {
            for &b in &frame[22..38] {
                h = h.wrapping_mul(31).wrapping_add(b as u32); // saddr
            }
            for &b in &frame[38..54] {
                h = h.wrapping_mul(31).wrapping_add(b as u32); // daddr
            }
        }
        _ => {}
    }

    h & 0xFFFFF
}

/// RFC 1624 incremental 16-bit one's-complement checksum update for a single
/// changed 16-bit word (`old` -> `new`). All inputs are host-order `u16`.
///
/// Ports `src/xdp_prog.c:update_checksum`. Returns the new checksum value.
#[inline]
pub fn checksum_update(csum: u16, old: u16, new: u16) -> u16 {
    let csum = csum as u32;
    let old = old as u32;
    let new = new as u32;

    let not_old = !old;
    let undo = (!csum).wrapping_add(not_old);
    let new_csum_value = undo.wrapping_add((undo < not_old) as u32).wrapping_add(new);
    let mut comp = new_csum_value.wrapping_add((new_csum_value < new) as u32);
    comp = (comp & 0xffff) + (comp >> 16);
    comp = (comp & 0xffff) + (comp >> 16);
    !(comp as u16)
}

// SAFETY: `TunnelConfig` is `#[repr(C)]`, `Copy`, and contains only `u8`/`u16`/
// `u32` and byte arrays with an explicit `_pad` field — no padding-dependent or
// otherwise-invalid bit patterns and no pointers. Every byte sequence of its
// size is therefore a valid value, satisfying aya's `Pod` contract.
#[cfg(feature = "user")]
unsafe impl aya::Pod for TunnelConfig {}
// SAFETY: `DecapKey` is `#[repr(C)]`, `Copy`, and is just two 16-byte arrays
// with no padding, so any byte pattern is a valid value (aya `Pod` contract).
#[cfg(feature = "user")]
unsafe impl aya::Pod for DecapKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_clamp_table() {
        // Mirrors pkg/tunnel/tunnel_test.go:TestComputeMSSClamp.
        assert_eq!(mss_clamp_from_mtu(1444), (1404, 1384));
        assert_eq!(mss_clamp_from_mtu(1280), (1240, 1220));
        assert_eq!(mss_clamp_from_mtu(70), (0, 0)); // too small
        assert_eq!(mss_clamp_from_mtu(80), (40, 20)); // exactly min
        assert_eq!(mss_clamp_from_mtu(0), (0, 0));
    }

    #[test]
    fn checksum_update_is_reversible() {
        // Applying old->new then new->old must restore the original checksum,
        // modulo one's-complement negative zero (0xffff and 0x0000 are equal).
        fn norm(c: u16) -> u16 {
            if c == 0xffff { 0 } else { c }
        }
        for &csum in &[0x0000u16, 0x1234, 0xabcd, 0xffff, 0x8000] {
            for &old in &[0x05b4u16, 0x0000, 0xffff, 0x1111] {
                for &new in &[0x057cu16, 0x0001, 0xfffe, 0x2222] {
                    let updated = checksum_update(csum, old, new);
                    assert_eq!(
                        norm(checksum_update(updated, new, old)),
                        norm(csum),
                        "csum={csum:#06x} old={old:#06x} new={new:#06x}"
                    );
                }
            }
        }
    }

    #[test]
    fn checksum_update_known_vector() {
        // A correct one's-complement checksum recomputed from scratch must
        // equal the incremental update. Build a tiny "header" of two 16-bit
        // words, checksum it, change one word, and compare.
        fn ones_complement(words: &[u16]) -> u16 {
            let mut sum: u32 = 0;
            for &w in words {
                sum += w as u32;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !(sum as u16)
        }
        let old_word = 0x05b4; // MSS 1460
        let new_word = 0x057c; // MSS 1404
        let other = 0x4000;
        let csum = ones_complement(&[old_word, other]);
        let recomputed = ones_complement(&[new_word, other]);
        assert_eq!(checksum_update(csum, old_word, new_word), recomputed);
    }

    #[test]
    fn counter_names_cover_all() {
        assert_eq!(COUNTER_NAMES.len(), DBG_MAX as usize);
    }

    #[test]
    fn flow_hash_properties() {
        // Too short -> 0.
        assert_eq!(inner_flow_hash(&[0u8; 13]), 0);

        // Minimal IPv4 frame (eth + 20-byte IPv4 header).
        let mut frame = [0u8; 14 + 20];
        frame[0..6].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x11, 0x01]); // dst
        frame[6..12].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x11, 0x02]); // src
        frame[12] = 0x08; // EtherType IPv4
        frame[13] = 0x00;
        frame[26..30].copy_from_slice(&[192, 168, 100, 200]); // saddr
        frame[30..34].copy_from_slice(&[192, 168, 30, 1]); // daddr

        let h = inner_flow_hash(&frame);
        assert!(h <= 0xFFFFF, "hash must be 20-bit, got {h:#x}");

        // Changing the source MAC changes the hash.
        let mut frame2 = frame;
        frame2[6] = 0xff;
        assert_ne!(inner_flow_hash(&frame2), h);

        // Deterministic.
        assert_eq!(inner_flow_hash(&frame), h);
    }
}

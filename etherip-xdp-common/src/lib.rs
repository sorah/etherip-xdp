#![cfg_attr(not(test), no_std)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! Types and helpers shared between the userspace daemon and the eBPF program.
//!
//! [`data_path`] holds the packet-processing core, generic over a packet-memory
//! abstraction so the same code runs in the kernel (XDP) and on the host (tests,
//! fuzzing).
//!
//! The wire/config structs here are `#[repr(C)]` and used verbatim as BPF map
//! values, so both sides see an identical byte layout. Pure scalar helpers
//! ([`mss_clamp_from_mtu`], [`checksum_update`]) are unit-tested on the host and
//! reused by both the daemon and the kernel program.

// The host `Packet` implementation in `data_path` needs an allocator while the
// crate stays `no_std` for the kernel build.
#[cfg(feature = "host")]
extern crate alloc;

pub mod data_path;

/// IP protocol number for EtherIP (RFC 3378).
pub const ETHERIP_PROTO: u8 = 97;
/// Default outer IPv6 hop limit.
pub const HOP_LIMIT_DEFAULT: u8 = 64;
/// EtherIP version nibble in the high 4 bits of the first header byte (v3 << 4).
pub const ETHERIP_VERSION: u8 = 0x30;

/// Outer encapsulation overhead: Ethernet (14) + IPv6 (40) + EtherIP (2).
pub const OUTER_OVERHEAD: usize = 14 + 40 + 2;

// Map capacities, shared by the eBPF map declarations and the userspace
// validator that decides whether an existing set of bpffs pins is still
// compatible with this build (see `control/bpf.rs` in the daemon).
/// `ENCAP_CONFIG` capacity (tunnels per uplink).
pub const ENCAP_CONFIG_MAX_ENTRIES: u32 = 256;
/// `DECAP_CONFIG` capacity (tunnels per uplink).
pub const DECAP_CONFIG_MAX_ENTRIES: u32 = 256;
/// `REDIRECT_UPLINK` capacity (single uplink per process).
pub const REDIRECT_UPLINK_MAX_ENTRIES: u32 = 1;
/// `REDIRECT_PEER` capacity (veth peers).
pub const REDIRECT_PEER_MAX_ENTRIES: u32 = 512;

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
    /// User-facing tunnel interface MAC (applied to the interface via netlink).
    /// The loader's record of the current address; not read by the data path.
    pub tunnel_mac: [u8; 6],
    /// Uplink MAC — written as outer src MAC on encap.
    pub external_mac: [u8; 6],
    /// Next-hop MAC — written as outer dst MAC on encap.
    pub dst_mac: [u8; 6],
    /// Prefix length of `src_addr` (64..=128). Encap fills the bits below it
    /// with the inner flow hash; 128 keeps the fixed-address behavior.
    pub src_plen: u8,
    /// Prefix length of `dst_addr` (64..=128), likewise (hash mixed via
    /// [`mix_entropy`]).
    pub dst_plen: u8,
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
            // 128 = no entropy fill: a zeroed config must never spray hash
            // bits over the whole address if it ever leaks into the maps.
            src_plen: 128,
            dst_plen: 128,
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

/// Expected [`PinnedState::magic`] value ("eXdP", little-endian).
pub const PINNED_STATE_MAGIC: u32 = u32::from_le_bytes(*b"eXdP");
/// Revision of the pinned-state layout: the map schemas ([`TunnelConfig`],
/// [`DecapKey`], capacities) and the bpffs pin paths, as one compatibility
/// number. Bump on any change to those; a daemon (or external tool) finding a
/// different revision must not touch the pinned objects beyond tearing them
/// down.
///
/// Revision 2: `TunnelConfig` gained `src_plen`/`dst_plen` (repurposing the
/// former `_pad` bytes, which a revision-1 daemon wrote as zero — an invalid
/// prefix length under the new semantics).
pub const PINNED_LAYOUT_REVISION: u32 = 2;

/// Identity record stored in the pinned `ETHERIP_STATE` map (a 1-entry array
/// on bpffs, next to the data-plane maps). This is the cross-process contract
/// for the pinned data plane: it names who created the pins
/// ([`Self::pkg_version`]), which schema they follow
/// ([`Self::layout_revision`]), and the exact eBPF object behind the attached
/// programs ([`Self::obj_digest`], used to skip the program swap when a
/// restarted daemon embeds the identical object).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedState {
    /// [`PINNED_STATE_MAGIC`].
    pub magic: u32,
    /// [`PINNED_LAYOUT_REVISION`] at the time the pins were created.
    pub layout_revision: u32,
    /// NUL-padded `CARGO_PKG_VERSION` of the daemon that wrote the record.
    /// Informational (logging, external tooling); compatibility is governed by
    /// `layout_revision` alone.
    pub pkg_version: [u8; 32],
    /// SHA-256 of the embedded eBPF object bytes.
    pub obj_digest: [u8; 32],
}

impl PinnedState {
    /// Build the record for the running daemon.
    pub fn new(pkg_version: &str, obj_digest: [u8; 32]) -> Self {
        let mut version = [0u8; 32];
        let src = pkg_version.as_bytes();
        let n = src.len().min(version.len());
        version[..n].copy_from_slice(&src[..n]);
        PinnedState {
            magic: PINNED_STATE_MAGIC,
            layout_revision: PINNED_LAYOUT_REVISION,
            pkg_version: version,
            obj_digest,
        }
    }

    /// Whether the record was written by a build speaking this layout.
    pub fn is_compatible(&self) -> bool {
        self.magic == PINNED_STATE_MAGIC && self.layout_revision == PINNED_LAYOUT_REVISION
    }

    /// The recorded package version, for logging.
    pub fn pkg_version_str(&self) -> &str {
        let end = self
            .pkg_version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.pkg_version.len());
        core::str::from_utf8(&self.pkg_version[..end]).unwrap_or("")
    }
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

const FNV64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64 over `bytes`, continuing from `h`.
const fn fnv64(mut h: u64, bytes: &[u8]) -> u64 {
    let mut i = 0;
    while i < bytes.len() {
        h = (h ^ bytes[i] as u64).wrapping_mul(FNV64_PRIME);
        i += 1;
    }
    h
}

/// 64-bit entropy hash of an inner Ethernet frame's L3/L4 flow identity, used
/// to fill the host bits of prefixed outer endpoints ([`fill_host_bits`]).
///
/// FNV-1a 64 over, per inner EtherType:
/// - IPv4: saddr, daddr, protocol; plus the 4 L4 port bytes when the protocol
///   is TCP/UDP and the packet is unfragmented (`frag_off & 0x3FFF == 0`, so
///   every fragment of a fragmented datagram hashes identically).
/// - IPv6: saddr, daddr, nexthdr; plus the port bytes when `nexthdr` is
///   directly TCP/UDP. Extension headers are not walked (keeps the eBPF twin
///   loop-free; a fragment header therefore also falls back to L3-only).
/// - Other (or truncated IP headers): dst MAC, src MAC, EtherType.
///
/// MACs are deliberately excluded for IP frames — unlike [`inner_flow_hash`]
/// (the flow-label hash, which stays as is) — so a neighbour MAC change does
/// not re-path in-flight flows. The eBPF program mirrors this byte for byte
/// via `data_path::inner_flow_hash64`; this slice version is the host-testable
/// reference.
pub fn inner_flow_hash64(frame: &[u8]) -> u64 {
    if frame.len() < 14 {
        return 0;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == 0x0800 && frame.len() >= 14 + 20 {
        let ip = &frame[14..34];
        let mut h = fnv64(FNV64_OFFSET, &ip[12..20]); // saddr + daddr
        let proto = ip[9];
        h = fnv64(h, &[proto]);
        let frag = u16::from_be_bytes([ip[6], ip[7]]) & 0x3FFF; // MF | offset
        let ihl = (ip[0] & 0x0F) as usize;
        let ports_off = 14 + ihl * 4;
        if (proto == 6 || proto == 17) && frag == 0 && ihl >= 5 && frame.len() >= ports_off + 4 {
            h = fnv64(h, &frame[ports_off..ports_off + 4]);
        }
        return h;
    }
    if ethertype == 0x86DD && frame.len() >= 14 + 40 {
        let ip6 = &frame[14..54];
        let mut h = fnv64(FNV64_OFFSET, &ip6[8..40]); // saddr + daddr
        let nexthdr = ip6[6];
        h = fnv64(h, &[nexthdr]);
        if (nexthdr == 6 || nexthdr == 17) && frame.len() >= 54 + 4 {
            h = fnv64(h, &frame[54..58]);
        }
        return h;
    }
    fnv64(FNV64_OFFSET, &frame[0..14])
}

/// Zero the host bits of `addr` below a `plen`-bit prefix (`plen >= 128` is a
/// no-op).
pub const fn mask_addr(addr: [u8; 16], plen: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        let bit = 8 * i as u32;
        let keep: u8 = if plen as u32 >= bit + 8 {
            0xFF
        } else if plen as u32 <= bit {
            0x00
        } else {
            0xFFu8 << (8 - (plen as u32 - bit))
        };
        out[i] = addr[i] & keep;
        i += 1;
    }
    out
}

/// OR the low `128 - plen` bits of `entropy` into `base` (whose host bits are
/// zero — enforced by config validation). `plen == 128` returns `base`
/// unchanged. Callers validate `plen >= 64`: the entropy is 64 bits, so bits
/// 64..plen of a shorter prefix would stay zero.
pub const fn fill_host_bits(base: [u8; 16], plen: u8, entropy: u64) -> [u8; 16] {
    let e = entropy.to_be_bytes();
    let mut out = base;
    let mut i = 8;
    while i < 16 {
        let bit = 8 * i as u32;
        let host: u8 = if plen as u32 <= bit {
            0xFF
        } else if plen as u32 >= bit + 8 {
            0x00
        } else {
            0xFFu8 >> (plen as u32 - bit)
        };
        out[i] |= e[i - 8] & host;
        i += 1;
    }
    out
}

/// splitmix64 finalizer. Encap fills the outer destination's host bits with
/// `mix_entropy(h)` while the source uses `h` directly, so ECMP hashes that
/// fold src ⊕ dst don't see the two suffixes cancel to a constant.
pub const fn mix_entropy(h: u64) -> u64 {
    let mut z = h.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
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
// `u32` and byte arrays laid out without implicit padding — no padding-dependent
// or otherwise-invalid bit patterns and no pointers. Every byte sequence of its
// size is therefore a valid value, satisfying aya's `Pod` contract.
#[cfg(feature = "user")]
unsafe impl aya::Pod for TunnelConfig {}
// SAFETY: `DecapKey` is `#[repr(C)]`, `Copy`, and is just two 16-byte arrays
// with no padding, so any byte pattern is a valid value (aya `Pod` contract).
#[cfg(feature = "user")]
unsafe impl aya::Pod for DecapKey {}
// SAFETY: `PinnedState` is `#[repr(C)]`, `Copy`, two naturally-aligned `u32`s
// followed by byte arrays — no padding, no invalid bit patterns (aya `Pod`
// contract).
#[cfg(feature = "user")]
unsafe impl aya::Pod for PinnedState {}

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
    fn pinned_state_round_trip() {
        let digest = [0xabu8; 32];
        let s = PinnedState::new("0.1.0", digest);
        assert!(s.is_compatible());
        assert_eq!(s.pkg_version_str(), "0.1.0");
        assert_eq!(s.obj_digest, digest);
    }

    #[test]
    fn pinned_state_truncates_long_version() {
        let long = "1.2.3-a-very-long-prerelease-identifier-string";
        let s = PinnedState::new(long, [0u8; 32]);
        assert_eq!(s.pkg_version_str().len(), 32);
        assert!(long.starts_with(s.pkg_version_str()));
    }

    #[test]
    fn pinned_state_incompatible_on_magic_or_revision() {
        let mut s = PinnedState::new("0.1.0", [0u8; 32]);
        s.magic ^= 1;
        assert!(!s.is_compatible());
        let mut s = PinnedState::new("0.1.0", [0u8; 32]);
        s.layout_revision += 1;
        assert!(!s.is_compatible());
    }

    #[test]
    fn pinned_state_has_no_padding() {
        // The struct is a bpffs map value read by external tooling; its size
        // must be exactly the sum of its fields on every target.
        assert_eq!(core::mem::size_of::<PinnedState>(), 4 + 4 + 32 + 32);
    }

    #[test]
    fn mask_addr_vectors() {
        let all = [0xFFu8; 16];
        assert_eq!(mask_addr(all, 128), all);
        assert_eq!(mask_addr(all, 0), [0u8; 16]);

        let mut expect = [0u8; 16];
        expect[..8].copy_from_slice(&[0xFF; 8]);
        assert_eq!(mask_addr(all, 64), expect);

        expect[8] = 0x80;
        assert_eq!(mask_addr(all, 65), expect);

        let mut expect = [0xFFu8; 16];
        expect[14] = 0;
        expect[15] = 0;
        assert_eq!(mask_addr(all, 112), expect);
        expect[14] = 0xFF;
        expect[15] = 0xFE;
        assert_eq!(mask_addr(all, 127), expect);

        // Idempotent.
        assert_eq!(mask_addr(mask_addr(all, 80), 80), mask_addr(all, 80));
    }

    #[test]
    fn fill_host_bits_vectors() {
        let mut base = [0u8; 16];
        base[0] = 0xfd;
        base[1] = 0x00;
        base[7] = 0x01;

        // /128 carries no entropy.
        assert_eq!(fill_host_bits(base, 128, u64::MAX), base);

        // /64 fills the whole low half.
        let e = 0x0123_4567_89AB_CDEFu64;
        let filled = fill_host_bits(base, 64, e);
        assert_eq!(filled[..8], base[..8]);
        assert_eq!(filled[8..], e.to_be_bytes());

        // /112 keeps only the low 16 bits of entropy.
        let filled = fill_host_bits(base, 112, u64::MAX);
        let mut expect = base;
        expect[14] = 0xFF;
        expect[15] = 0xFF;
        assert_eq!(filled, expect);

        // /65 masks the top host byte to 7 bits.
        let filled = fill_host_bits(base, 65, u64::MAX);
        assert_eq!(filled[8], 0x7F);
        assert_eq!(filled[9..], [0xFF; 7]);

        // The fill never leaks above the prefix.
        for plen in [64u8, 65, 80, 112, 127, 128] {
            assert_eq!(
                mask_addr(fill_host_bits(base, plen, u64::MAX), plen),
                mask_addr(base, plen),
                "plen {plen}"
            );
        }
    }

    #[test]
    fn mix_entropy_decorrelates() {
        for h in [0u64, 1, 0xdead_beef, u64::MAX] {
            assert_ne!(mix_entropy(h), h);
            assert_eq!(mix_entropy(h), mix_entropy(h));
        }
        assert_ne!(mix_entropy(0), mix_entropy(1));
    }

    fn ipv4_tcp_frame() -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20];
        f[0..6].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x11, 0x01]); // dst MAC
        f[6..12].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x11, 0x02]); // src MAC
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x45; // v4, ihl 5
        f[23] = 6; // TCP
        f[26..30].copy_from_slice(&[192, 168, 100, 200]);
        f[30..34].copy_from_slice(&[192, 168, 30, 1]);
        f[34..36].copy_from_slice(&1234u16.to_be_bytes()); // sport
        f[36..38].copy_from_slice(&80u16.to_be_bytes()); // dport
        f
    }

    fn ipv6_tcp_frame() -> Vec<u8> {
        let mut f = vec![0u8; 14 + 40 + 20];
        f[0..6].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x11, 0x01]);
        f[6..12].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x11, 0x02]);
        f[12..14].copy_from_slice(&[0x86, 0xDD]);
        f[14] = 0x60;
        f[20] = 6; // nexthdr TCP
        f[22] = 0xfd; // saddr fd00::…
        f[37] = 0x01;
        f[38] = 0xfd; // daddr
        f[53] = 0x02;
        f[54..56].copy_from_slice(&1234u16.to_be_bytes());
        f[56..58].copy_from_slice(&80u16.to_be_bytes());
        f
    }

    #[test]
    fn flow_hash64_ports_and_macs() {
        for frame in [ipv4_tcp_frame(), ipv6_tcp_frame()] {
            let h = inner_flow_hash64(&frame);
            assert_eq!(inner_flow_hash64(&frame), h, "deterministic");

            // L4 ports contribute for plain TCP.
            let mut other_port = frame.clone();
            let sport_off = if frame[12] == 0x08 { 34 } else { 54 };
            other_port[sport_off] ^= 0xFF;
            assert_ne!(inner_flow_hash64(&other_port), h, "port-sensitive");

            // MACs must not contribute for IP frames.
            let mut other_mac = frame.clone();
            other_mac[6] ^= 0xFF;
            assert_eq!(inner_flow_hash64(&other_mac), h, "MAC-insensitive");
        }
    }

    #[test]
    fn flow_hash64_skips_ports_when_unsafe() {
        // IPv4 fragments: offset != 0, and MF on a first fragment.
        for frag in [[0x00u8, 0x10], [0x20, 0x00]] {
            let mut a = ipv4_tcp_frame();
            a[20..22].copy_from_slice(&frag);
            let mut b = a.clone();
            b[34] ^= 0xFF;
            assert_eq!(
                inner_flow_hash64(&a),
                inner_flow_hash64(&b),
                "fragment must hash L3-only (frag {frag:02x?})"
            );
        }

        // Non-TCP/UDP protocol.
        let mut a = ipv4_tcp_frame();
        a[23] = 47; // GRE
        let mut b = a.clone();
        b[34] ^= 0xFF;
        assert_eq!(inner_flow_hash64(&a), inner_flow_hash64(&b));

        // IPv6 extension header: ports are not walked to.
        let mut a = ipv6_tcp_frame();
        a[20] = 44; // fragment header instead of TCP
        let mut b = a.clone();
        b[54] ^= 0xFF;
        assert_eq!(inner_flow_hash64(&a), inner_flow_hash64(&b));
    }

    #[test]
    fn flow_hash64_non_ip_and_short() {
        assert_eq!(inner_flow_hash64(&[0u8; 13]), 0);

        // Non-IP frames fall back to MAC + EtherType.
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        let h = inner_flow_hash64(&arp);
        let mut other = arp.clone();
        other[0] ^= 0xFF;
        assert_ne!(inner_flow_hash64(&other), h, "MAC-sensitive for non-IP");
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

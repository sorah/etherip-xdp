//! The EtherIP data path, factored out of the eBPF program so it can run both
//! in the kernel (over an [`aya_ebpf::programs::XdpContext`]) and on the host
//! (over a plain byte buffer) from one source of truth.
//!
//! All packet memory access is funnelled through the [`Packet`] trait, which the
//! eBPF program implements with the verifier-safe `load`/`store` primitives and
//! the host implements ([`HostPacket`], behind the `host` feature) with a
//! bounds-checked `Vec<u8>`. The parsing/transform logic ([`encap`], [`decap`]
//! and their helpers) is generic over `Packet` and contains no `unsafe`: every
//! interesting branch — IPv6 extension-header walking, TCP-option MSS clamping,
//! header rewriting — is exercised identically on both sides. The byte-exact
//! `BPF_PROG_TEST_RUN` tests assert the two implementations agree, so
//! coverage-guided fuzzing of the host core ([`encap`]/[`decap`]) is meaningful
//! for the kernel program too.
#![allow(clippy::result_unit_err)]

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;

const ETH_HDR_LEN: usize = 14;
const IPV6_HDR_LEN: usize = 40;
const ETHERIP_HDR_LEN: usize = 2;

/// Inner/outer Ethernet header.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: [u8; 2],
}

/// IPv6 header (outer encapsulation header, also the inner header when clamping).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Hdr {
    /// version (4) | traffic class (8) | flow label (20).
    pub vtf: [u8; 4],
    pub payload_len: [u8; 2],
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

/// EtherIP header (RFC 3378): a version nibble and a zero pad byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EtherIpHdr {
    pub ver: u8,
    pub pad: u8,
}

/// Generic IPv6 extension header (`nexthdr` + length in 8-octet units).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExtHdr {
    pub nexthdr: u8,
    pub hdrlen: u8,
}

/// Abstraction over the packet buffer, hiding the difference between an XDP
/// context (kernel) and a byte buffer (host). The contract mirrors the eBPF
/// primitives byte for byte.
///
/// `load`/`store` read/write a `Copy` `T` at a *constant* offset.
/// `load_var`/`store_var` are for *packet-derived* offsets: the eBPF
/// implementation hides the offset behind a `black_box` barrier so each access's
/// bounds check survives the verifier (see the eBPF `load_var` doc); the host
/// implementation is identical to `load`/`store`. `ensure` answers "do bytes
/// `[0, end)` exist?" without the packet-pointer subtraction newer kernels
/// reject; `buff_len` is the total length as a scalar; `adjust_head` grows
/// (`delta < 0`) or shrinks (`delta > 0`) the headroom.
pub trait Packet {
    fn load<T: Copy>(&self, offset: usize) -> Result<T, ()>;
    fn store<T: Copy>(&mut self, offset: usize, value: T) -> Result<(), ()>;
    fn load_var<T: Copy>(&self, offset: usize) -> Result<T, ()>;
    fn store_var<T: Copy>(&mut self, offset: usize, value: T) -> Result<(), ()>;
    /// True iff bytes `[0, end)` lie within the packet.
    fn ensure(&self, end: usize) -> bool;
    /// Total packet length (eBPF: `bpf_xdp_get_buff_len`).
    fn buff_len(&self) -> usize;
    /// Grow (`delta < 0`) or shrink (`delta > 0`) headroom; `Err(())` on failure.
    fn adjust_head(&mut self, delta: i32) -> Result<(), ()>;
}

/// Walk IPv6 extension headers (hop-by-hop, routing, fragment, dest-options),
/// returning the offset of and protocol after the last one. `Err(())` means a
/// malformed/truncated header.
#[inline(always)]
pub fn skip_ext_headers<P: Packet>(
    pkt: &P,
    mut pos: usize,
    mut nexthdr: u8,
) -> Result<(usize, u8), ()> {
    for _ in 0..crate::MAX_EXT_HEADERS {
        if nexthdr != 0 && nexthdr != 43 && nexthdr != 44 && nexthdr != 60 {
            return Ok((pos, nexthdr));
        }
        let ext: ExtHdr = pkt.load_var(pos)?;
        let cur = nexthdr;
        nexthdr = ext.nexthdr;
        let hdrlen = ext.hdrlen as usize;
        if cur == 44 {
            pos += 8; // fragment header is fixed 8 bytes
        } else {
            pos += (hdrlen + 1) * 8;
        }
        if !pkt.ensure(pos) {
            return Err(());
        }
    }
    Ok((pos, nexthdr))
}

/// Clamp the MSS option of an inner TCP SYN at `tcp_off`. `Err(())` signals a
/// truncated TCP header (caller aborts). `new_mss == 0` disables clamping.
#[inline(always)]
pub fn update_tcp_mss<P: Packet>(pkt: &mut P, tcp_off: usize, new_mss: u16) -> Result<(), ()> {
    if new_mss == 0 {
        return Ok(());
    }
    if !pkt.ensure(tcp_off + 20) {
        return Err(());
    }
    let data_offset = (pkt.load_var::<u8>(tcp_off + 12)? >> 4) as usize;
    let flags = pkt.load_var::<u8>(tcp_off + 13)?;
    if flags & 0x02 == 0 {
        return Ok(()); // not a SYN
    }
    if data_offset < 5 {
        return Ok(());
    }
    if !pkt.ensure(tcp_off + data_offset * 4) {
        return Err(());
    }

    let mut remaining: i32 = data_offset as i32 * 4 - 20;
    let mut opt_off = tcp_off + 20;
    for _ in 0..crate::MAX_TCP_OPT_ITERATIONS {
        if remaining < 1 {
            break;
        }
        let Ok(kind) = pkt.load_var::<u8>(opt_off) else {
            break;
        };
        if kind == 0 {
            break; // end of options
        }
        if kind == 1 {
            opt_off += 1; // NOP
            remaining -= 1;
            continue;
        }
        if remaining < 2 {
            break;
        }
        let Ok(len_byte) = pkt.load_var::<u8>(opt_off + 1) else {
            break;
        };
        let len = len_byte as i32;
        if len < 2 || len > remaining || !pkt.ensure(opt_off + len as usize) {
            break;
        }
        if kind == 2 && len == 4 {
            let old_mss = u16::from_be_bytes(pkt.load_var::<[u8; 2]>(opt_off + 2)?);
            if old_mss > new_mss {
                pkt.store_var(opt_off + 2, new_mss.to_be_bytes())?;
                let csum = u16::from_be_bytes(pkt.load_var::<[u8; 2]>(tcp_off + 16)?);
                let updated = crate::checksum_update(csum, old_mss, new_mss);
                pkt.store_var(tcp_off + 16, updated.to_be_bytes())?;
            }
            return Ok(());
        }
        opt_off += len as usize;
        remaining -= len;
    }
    Ok(())
}

/// 20-bit ECMP flow hash of the inner frame at offset 0. Mirrors
/// [`crate::inner_flow_hash`] (the slice-based host reference) byte for byte.
#[inline(always)]
pub fn inner_flow_hash<P: Packet>(pkt: &P) -> u32 {
    let Ok(eth) = pkt.load::<[u8; ETH_HDR_LEN]>(0) else {
        return 0;
    };
    let mut h: u32 = 0;
    for &b in &eth[0..12] {
        h = h.wrapping_mul(31).wrapping_add(b as u32); // h_dest + h_source
    }
    let proto = ((eth[12] as u32) << 8) | (eth[13] as u32); // ntohs(h_proto)
    h = h.wrapping_mul(31).wrapping_add(proto);

    if proto as u16 == ETH_P_IP {
        // IPv4 saddr (26..30) + daddr (30..34), folded as native-endian u32.
        if let Ok(addrs) = pkt.load::<[u8; 8]>(26) {
            let s = u32::from_le_bytes([addrs[0], addrs[1], addrs[2], addrs[3]]);
            let d = u32::from_le_bytes([addrs[4], addrs[5], addrs[6], addrs[7]]);
            h = h.wrapping_mul(31).wrapping_add(s);
            h = h.wrapping_mul(31).wrapping_add(d);
        }
    } else if proto as u16 == ETH_P_IPV6 {
        // IPv6 saddr (22..38) + daddr (38..54), folded byte by byte.
        if let Ok(addrs) = pkt.load::<[u8; 32]>(22) {
            for &b in &addrs {
                h = h.wrapping_mul(31).wrapping_add(b as u32);
            }
        }
    }

    h & 0xFFFFF
}

/// Write the outer IPv6 and EtherIP headers over the freshly grown headroom (the
/// outer Ethernet header is written by the caller).
#[inline(always)]
pub fn build_outer_headers<P: Packet>(
    pkt: &mut P,
    cfg: &crate::TunnelConfig,
    flow_hash: u32,
) -> Result<(), ()> {
    let eip_off = ETH_HDR_LEN + IPV6_HDR_LEN;
    // Outer IPv6 payload length = EtherIP + inner frame = total length minus the
    // outer Ethernet+IPv6 headers. Computed from the scalar buffer length to
    // avoid a packet-pointer subtraction the verifier rejects on newer kernels.
    let payload_len = pkt.buff_len().saturating_sub(eip_off) as u16; // EtherIP + inner
    let ip6 = Ipv6Hdr {
        vtf: [
            0x60, // version 6, traffic class 0
            ((flow_hash >> 16) & 0x0F) as u8,
            ((flow_hash >> 8) & 0xFF) as u8,
            (flow_hash & 0xFF) as u8,
        ],
        payload_len: payload_len.to_be_bytes(),
        nexthdr: crate::ETHERIP_PROTO,
        hop_limit: crate::HOP_LIMIT_DEFAULT,
        saddr: cfg.src_addr,
        daddr: cfg.dst_addr,
    };
    pkt.store(ETH_HDR_LEN, ip6)?;

    let eip = EtherIpHdr {
        ver: crate::ETHERIP_VERSION,
        pad: 0,
    };
    pkt.store(eip_off, eip)
}

/// Clamp the inner TCP MSS for the frame at `inner_off`. `Err(())` aborts
/// (truncated inner headers).
#[inline(always)]
pub fn clamp_inner_tcp_mss<P: Packet>(
    pkt: &mut P,
    inner_off: usize,
    cfg: &crate::TunnelConfig,
) -> Result<(), ()> {
    let eth: EthHdr = pkt.load(inner_off)?;
    let ethertype = u16::from_be_bytes(eth.ethertype);

    if ethertype == ETH_P_IP {
        let ip_off = inner_off + ETH_HDR_LEN;
        let ip: [u8; 20] = pkt.load(ip_off)?; // full minimum IPv4 header
        if ip[9] == IPPROTO_TCP {
            let ihl = (ip[0] & 0x0f) as usize;
            if ihl < 5 {
                return Err(());
            }
            return update_tcp_mss(pkt, ip_off + ihl * 4, cfg.mss_clamp_ipv4);
        }
    } else if ethertype == ETH_P_IPV6 {
        let ip6_off = inner_off + ETH_HDR_LEN;
        let ip6: Ipv6Hdr = pkt.load(ip6_off)?;
        let (pos, final_nexthdr) = skip_ext_headers(pkt, ip6_off + IPV6_HDR_LEN, ip6.nexthdr)?;
        if final_nexthdr == IPPROTO_TCP {
            return update_tcp_mss(pkt, pos, cfg.mss_clamp_ipv6);
        }
    }

    Ok(())
}

/// The outcome of [`encap`], in one-to-one correspondence with the eBPF program's
/// debug counters / actions. The caller (kernel wrapper) maps each variant to the
/// `DBG_ENCAP_*` counter and XDP action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncapOutcome {
    /// Inner Ethernet header absent (no counter; `XDP_ABORTED`).
    Abort,
    /// `bpf_xdp_adjust_head` failed.
    AdjustFail,
    /// Writing the outer headers failed (out of bounds).
    BuildFail,
    /// Inner TCP headers truncated while MSS clamping.
    MssFail,
    /// Writing the outer Ethernet header failed (out of bounds).
    BoundsFail,
    /// Encapsulated; redirect to the uplink (`cfg.external_ifindex`).
    Redirect,
}

/// Encapsulate the inner frame currently in `pkt`: grow headroom, write the outer
/// Ethernet/IPv6/EtherIP headers, and clamp the inner TCP MSS.
#[inline(always)]
pub fn encap<P: Packet>(pkt: &mut P, cfg: &crate::TunnelConfig) -> EncapOutcome {
    if pkt.load::<EthHdr>(0).is_err() {
        return EncapOutcome::Abort;
    }
    let flow_hash = inner_flow_hash(pkt);

    let outer_len = crate::OUTER_OVERHEAD;
    if pkt.adjust_head(-(outer_len as i32)).is_err() {
        return EncapOutcome::AdjustFail;
    }
    if build_outer_headers(pkt, cfg, flow_hash).is_err() {
        return EncapOutcome::BuildFail;
    }
    if clamp_inner_tcp_mss(pkt, outer_len, cfg).is_err() {
        return EncapOutcome::MssFail;
    }

    let eth = EthHdr {
        dst: cfg.dst_mac,
        src: cfg.external_mac,
        ethertype: ETH_P_IPV6.to_be_bytes(),
    };
    if pkt.store(0, eth).is_err() {
        return EncapOutcome::BoundsFail;
    }

    EncapOutcome::Redirect
}

/// The outcome of [`decap`], in one-to-one correspondence with the eBPF program's
/// debug counters / actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecapOutcome {
    /// Truncated outer headers (no counter; `XDP_ABORTED`).
    Abort,
    /// Outer EtherType is not IPv6 (`XDP_PASS`).
    NotIpv6,
    /// Final next-header is not EtherIP (`XDP_PASS`).
    NotEtherip,
    /// No tunnel matches the outer (remote, local) pair (`XDP_PASS`).
    NoTunnel,
    /// Frame is sourced from our own tunnel address — loopback guard (`XDP_PASS`).
    OwnPkt,
    /// EtherIP version/pad mismatch (`XDP_PASS`).
    BadHeader,
    /// Decapsulated; redirect to the veth peer (`internal_ifindex`).
    Redirect { internal_ifindex: u32 },
}

/// Decapsulate the outer frame in `pkt`: demux by the outer IPv6 (source,
/// destination) pair via `find`, strip the outer headers, and rewrite the inner
/// destination MAC. `find` returns the tunnel config for a [`DecapKey`] (the
/// eBPF program backs it with the `DECAP_CONFIG` map; the host backs it with a
/// fixed table).
#[inline(always)]
pub fn decap<P, F>(pkt: &mut P, find: F) -> DecapOutcome
where
    P: Packet,
    F: FnOnce(&crate::DecapKey) -> Option<crate::TunnelConfig>,
{
    let eth: EthHdr = match pkt.load(0) {
        Ok(e) => e,
        Err(()) => return DecapOutcome::Abort,
    };
    if u16::from_be_bytes(eth.ethertype) != ETH_P_IPV6 {
        return DecapOutcome::NotIpv6;
    }

    let ip6: Ipv6Hdr = match pkt.load(ETH_HDR_LEN) {
        Ok(h) => h,
        Err(()) => return DecapOutcome::Abort,
    };

    let (eip_off, final_nexthdr) =
        match skip_ext_headers(pkt, ETH_HDR_LEN + IPV6_HDR_LEN, ip6.nexthdr) {
            Ok(v) => v,
            Err(()) => return DecapOutcome::Abort,
        };
    if final_nexthdr != crate::ETHERIP_PROTO {
        return DecapOutcome::NotEtherip;
    }

    let key = crate::DecapKey {
        remote: ip6.saddr,
        local: ip6.daddr,
    };
    let cfg = match find(&key) {
        Some(c) => c,
        None => return DecapOutcome::NoTunnel,
    };

    // Loopback guard: drop frames sourced from our own tunnel address.
    if ip6.saddr == cfg.src_addr {
        return DecapOutcome::OwnPkt;
    }

    let eip: EtherIpHdr = match pkt.load_var(eip_off) {
        Ok(e) => e,
        Err(()) => return DecapOutcome::Abort,
    };
    if eip.ver != crate::ETHERIP_VERSION || eip.pad != 0 {
        return DecapOutcome::BadHeader;
    }

    // Inner Ethernet header must be present after the EtherIP header.
    let strip_len = eip_off + ETHERIP_HDR_LEN;
    if !pkt.ensure(strip_len + ETH_HDR_LEN) {
        return DecapOutcome::Abort;
    }

    if pkt.adjust_head(strip_len as i32).is_err() {
        return DecapOutcome::Abort;
    }

    if pkt.store(0, cfg.tunnel_mac).is_err() {
        return DecapOutcome::Abort;
    }

    DecapOutcome::Redirect {
        internal_ifindex: cfg.internal_ifindex,
    }
}

/// Host implementation of [`Packet`] over a growable byte buffer, used by the
/// data-path equivalence tests and the fuzz harness. Available behind the `host`
/// feature.
#[cfg(feature = "host")]
pub struct HostPacket {
    data: alloc::vec::Vec<u8>,
}

#[cfg(feature = "host")]
impl HostPacket {
    /// Wrap an owned byte buffer (the on-the-wire frame).
    pub fn new(data: alloc::vec::Vec<u8>) -> Self {
        Self { data }
    }

    /// Borrow the current packet bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Consume the packet, returning the buffer.
    pub fn into_inner(self) -> alloc::vec::Vec<u8> {
        self.data
    }
}

#[cfg(feature = "host")]
impl Packet for HostPacket {
    #[inline]
    fn load<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        let size = core::mem::size_of::<T>();
        let end = offset.checked_add(size).ok_or(())?;
        if end > self.data.len() {
            return Err(());
        }
        // SAFETY: `[offset, offset+size)` lies within `data` (checked above).
        // `read_unaligned` mirrors the eBPF primitive: it makes no alignment
        // assumption and every `T` used here is a `#[repr(C)]` header or integer
        // array for which all bit patterns are valid.
        Ok(unsafe { core::ptr::read_unaligned(self.data.as_ptr().add(offset).cast::<T>()) })
    }

    #[inline]
    fn store<T: Copy>(&mut self, offset: usize, value: T) -> Result<(), ()> {
        let size = core::mem::size_of::<T>();
        let end = offset.checked_add(size).ok_or(())?;
        if end > self.data.len() {
            return Err(());
        }
        // SAFETY: `[offset, offset+size)` lies within `data` (checked above);
        // `write_unaligned` mirrors the eBPF primitive (no alignment assumption).
        unsafe {
            core::ptr::write_unaligned(self.data.as_mut_ptr().add(offset).cast::<T>(), value)
        };
        Ok(())
    }

    #[inline]
    fn load_var<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        self.load(offset)
    }

    #[inline]
    fn store_var<T: Copy>(&mut self, offset: usize, value: T) -> Result<(), ()> {
        self.store(offset, value)
    }

    #[inline]
    fn ensure(&self, end: usize) -> bool {
        end <= self.data.len()
    }

    #[inline]
    fn buff_len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn adjust_head(&mut self, delta: i32) -> Result<(), ()> {
        if delta <= 0 {
            // Grow headroom: prepend `-delta` zero bytes, as the kernel exposes
            // fresh (here zeroed) headroom that the program then overwrites.
            let grow = (-(delta as i64)) as usize;
            let mut grown = alloc::vec::Vec::with_capacity(grow + self.data.len());
            grown.resize(grow, 0);
            grown.extend_from_slice(&self.data);
            self.data = grown;
            Ok(())
        } else {
            // Shrink headroom: drop `delta` leading bytes.
            let shrink = delta as usize;
            if shrink > self.data.len() {
                return Err(());
            }
            self.data.drain(0..shrink);
            Ok(())
        }
    }
}

#![no_std]
#![no_main]
#![deny(clippy::undocumented_unsafe_blocks)]

//! XDP EtherIP (RFC 3378) data plane — a Rust port of `src/xdp_prog.c`.
//!
//! Two entry points: [`xdp_encap`], attached to every veth peer (one per tunnel,
//! keyed by ingress ifindex), and [`xdp_decap`], attached to the uplink and
//! shared by all tunnels on that NIC (demuxed by the outer IPv6 (source,
//! destination) address pair). Keeping the roles in separate programs means the
//! encap config lookup is never reached on the uplink, so a veth-peer ifindex
//! (which, when the peer lives in a hidden network namespace, is allocated
//! independently of the uplink's) can never be mistaken for the uplink's and
//! misclassify decap traffic as encap.
//!
//! # Safety model
//!
//! Every access to packet memory goes through [`load`]/[`store`], which call
//! [`ptr_at`]/[`ptr_at_mut`] to prove the access lies within `[data, data_end)`
//! before dereferencing. After any `bpf_xdp_adjust_head` the old bounds are void,
//! so all subsequent accesses re-derive `data`/`data_end` (they go through
//! `load`/`store` again). This keeps the only `unsafe` to a handful of
//! well-documented primitives.

use aya_ebpf::bindings::xdp_action;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;

const ETH_HDR_LEN: usize = 14;
const IPV6_HDR_LEN: usize = 40;
const ETHERIP_HDR_LEN: usize = 2;

/// The config hash maps are declared `BPF_F_NO_PREALLOC` so the kernel frees a
/// replaced or removed element via `call_rcu` instead of immediately recycling
/// it onto a freelist. XDP runs inside an RCU read-side critical section, so a
/// value obtained from `get()` stays alive and consistent for the whole program
/// run even while userspace rewrites these maps during `systemctl reload`. With
/// a prealloc map the element could be recycled (and overwritten) concurrently,
/// producing torn/aliased reads — a mis-encapsulated or dropped packet.
const NO_PREALLOC: u32 = aya_ebpf::bindings::BPF_F_NO_PREALLOC as u32;

/// Per-tunnel encap parameters, keyed by the ingress (veth-peer) ifindex.
#[aya_ebpf::macros::map]
static ENCAP_CONFIG: aya_ebpf::maps::HashMap<u32, etherip_xdp_common::TunnelConfig> =
    aya_ebpf::maps::HashMap::with_max_entries(256, NO_PREALLOC);

/// Per-tunnel decap parameters, keyed by the outer IPv6 (remote, local) pair.
#[aya_ebpf::macros::map]
static DECAP_CONFIG: aya_ebpf::maps::HashMap<
    etherip_xdp_common::DecapKey,
    etherip_xdp_common::TunnelConfig,
> = aya_ebpf::maps::HashMap::with_max_entries(256, NO_PREALLOC);

/// Encap redirect target: the shared uplink, keyed by its ifindex. Held separate
/// from [`REDIRECT_PEER`] so a veth-peer ifindex — which, when the peer lives in a
/// hidden network namespace, is allocated independently of the uplink's and
/// routinely takes the same small value — can never collide with the uplink key
/// and steer encap and decap to the wrong device.
#[aya_ebpf::macros::map]
static REDIRECT_UPLINK: aya_ebpf::maps::DevMapHash =
    aya_ebpf::maps::DevMapHash::with_max_entries(1, 0);

/// Decap redirect targets: the veth peers, keyed by ifindex.
#[aya_ebpf::macros::map]
static REDIRECT_PEER: aya_ebpf::maps::DevMapHash =
    aya_ebpf::maps::DevMapHash::with_max_entries(512, 0);

/// Per-CPU per-path debug counters (see `etherip_xdp_common::DBG_*`).
#[aya_ebpf::macros::map]
static DEBUG_COUNTERS: aya_ebpf::maps::PerCpuArray<u64> =
    aya_ebpf::maps::PerCpuArray::with_max_entries(etherip_xdp_common::DBG_MAX, 0);

mod headers {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct EthHdr {
        pub dst: [u8; 6],
        pub src: [u8; 6],
        pub ethertype: [u8; 2],
    }

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

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct EtherIpHdr {
        pub ver: u8,
        pub pad: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ExtHdr {
        pub nexthdr: u8,
        pub hdrlen: u8,
    }
}

/// Return a pointer to `T` at `offset` only if `size_of::<T>()` bytes there lie
/// within the packet. Contains no `unsafe`: it just bounds-checks and casts; the
/// caller (always `load`/`store`) is responsible for the dereference.
#[inline(always)]
fn ptr_at<T>(ctx: &aya_ebpf::programs::XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &aya_ebpf::programs::XdpContext, offset: usize) -> Result<*mut T, ()> {
    Ok(ptr_at::<T>(ctx, offset)? as *mut T)
}

/// Read a `T` from the packet at `offset`. `Err(())` if out of bounds.
#[inline(always)]
fn load<T: Copy>(ctx: &aya_ebpf::programs::XdpContext, offset: usize) -> Result<T, ()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    // SAFETY: `ptr_at` verified that `size_of::<T>()` bytes starting at `offset`
    // lie within `[data(), data_end())`, so the read is in-bounds. `T` is `Copy`
    // and only ever a plain integer or byte-array header, for which every bit
    // pattern is valid; `read_unaligned` makes no alignment assumption about the
    // packet buffer.
    Ok(unsafe { core::ptr::read_unaligned(ptr) })
}

/// Write `value` into the packet at `offset`. `Err(())` if out of bounds.
#[inline(always)]
fn store<T: Copy>(ctx: &aya_ebpf::programs::XdpContext, offset: usize, value: T) -> Result<(), ()> {
    let ptr = ptr_at_mut::<T>(ctx, offset)?;
    // SAFETY: `ptr_at_mut` verified that `size_of::<T>()` bytes starting at
    // `offset` lie within the (writable) XDP packet; `write_unaligned` stores
    // `value` there without any alignment assumption.
    unsafe { core::ptr::write_unaligned(ptr, value) };
    Ok(())
}

/// `load`, but for a *packet-derived* (variable) offset. The barrier is what
/// makes variable-offset access pass the verifier: without it, when an earlier
/// bounds check covers a wider span (e.g. `data + tcp_off + 20 > data_end`),
/// LLVM proves this access's own `ptr_at` check redundant and elides it. The
/// pointer is then recomputed as a fresh register that reaches the verifier
/// with no bounds it can see ("R0 offset is outside of the packet"). Hiding the
/// offset behind `black_box` keeps every access's check independent and tied to
/// its own dereference. This is the safe equivalent of the `asm volatile` hint
/// in the original C/Go implementation.
#[inline(always)]
fn load_var<T: Copy>(ctx: &aya_ebpf::programs::XdpContext, offset: usize) -> Result<T, ()> {
    load(ctx, core::hint::black_box(offset))
}

/// `store`, for a packet-derived (variable) offset. See `load_var`.
#[inline(always)]
fn store_var<T: Copy>(
    ctx: &aya_ebpf::programs::XdpContext,
    offset: usize,
    value: T,
) -> Result<(), ()> {
    store(ctx, core::hint::black_box(offset), value)
}

#[inline(always)]
fn dbg_inc(idx: u32) {
    if let Some(ptr) = DEBUG_COUNTERS.get_ptr_mut(idx) {
        // SAFETY: `get_ptr_mut` returned a valid pointer to this CPU's `u64` slot
        // in the per-CPU array. Per-CPU storage has no cross-CPU aliasing, so the
        // unsynchronized increment is sound.
        unsafe { *ptr += 1 };
    }
}

/// Walk IPv6 extension headers (hop-by-hop, routing, fragment, dest-options),
/// returning the offset of and protocol after the last one. Ports
/// `skip_ext_headers`. `Err(())` means a malformed/truncated header.
#[inline(always)]
fn skip_ext_headers(
    ctx: &aya_ebpf::programs::XdpContext,
    mut pos: usize,
    mut nexthdr: u8,
) -> Result<(usize, u8), ()> {
    for _ in 0..etherip_xdp_common::MAX_EXT_HEADERS {
        if nexthdr != 0 && nexthdr != 43 && nexthdr != 44 && nexthdr != 60 {
            return Ok((pos, nexthdr));
        }
        let ext: headers::ExtHdr = load_var(ctx, pos)?;
        let cur = nexthdr;
        nexthdr = ext.nexthdr;
        let hdrlen = ext.hdrlen as usize;
        if cur == 44 {
            pos += 8; // fragment header is fixed 8 bytes
        } else {
            pos += (hdrlen + 1) * 8;
        }
        if ctx.data() + pos > ctx.data_end() {
            return Err(());
        }
    }
    Ok((pos, nexthdr))
}

/// Clamp the MSS option of an inner TCP SYN at `tcp_off`. `Err(())` signals a
/// truncated TCP header (caller aborts). `new_mss == 0` disables clamping.
/// Ports `update_tcp_mss`.
#[inline(always)]
fn update_tcp_mss(
    ctx: &aya_ebpf::programs::XdpContext,
    tcp_off: usize,
    new_mss: u16,
) -> Result<(), ()> {
    if new_mss == 0 {
        return Ok(());
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + tcp_off + 20 > data_end {
        return Err(());
    }
    let data_offset = (load_var::<u8>(ctx, tcp_off + 12)? >> 4) as usize;
    let flags = load_var::<u8>(ctx, tcp_off + 13)?;
    if flags & 0x02 == 0 {
        return Ok(()); // not a SYN
    }
    if data_offset < 5 {
        return Ok(());
    }
    if data + tcp_off + data_offset * 4 > data_end {
        return Err(());
    }

    let mut remaining: i32 = data_offset as i32 * 4 - 20;
    let mut opt_off = tcp_off + 20;
    for _ in 0..etherip_xdp_common::MAX_TCP_OPT_ITERATIONS {
        if remaining < 1 {
            break;
        }
        let Ok(kind) = load_var::<u8>(ctx, opt_off) else {
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
        let Ok(len_byte) = load_var::<u8>(ctx, opt_off + 1) else {
            break;
        };
        let len = len_byte as i32;
        if len < 2 || len > remaining || data + opt_off + len as usize > data_end {
            break;
        }
        if kind == 2 && len == 4 {
            let old_mss = u16::from_be_bytes(load_var::<[u8; 2]>(ctx, opt_off + 2)?);
            if old_mss > new_mss {
                store_var(ctx, opt_off + 2, new_mss.to_be_bytes())?;
                let csum = u16::from_be_bytes(load_var::<[u8; 2]>(ctx, tcp_off + 16)?);
                let updated = etherip_xdp_common::checksum_update(csum, old_mss, new_mss);
                store_var(ctx, tcp_off + 16, updated.to_be_bytes())?;
            }
            return Ok(());
        }
        opt_off += len as usize;
        remaining -= len;
    }
    Ok(())
}

/// 20-bit ECMP flow hash of the inner frame at offset 0. Mirrors
/// `etherip_xdp_common::inner_flow_hash` (which is the host-tested reference).
#[inline(always)]
fn inner_flow_hash(ctx: &aya_ebpf::programs::XdpContext) -> u32 {
    let Ok(eth) = load::<[u8; ETH_HDR_LEN]>(ctx, 0) else {
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
        if let Ok(addrs) = load::<[u8; 8]>(ctx, 26) {
            let s = u32::from_le_bytes([addrs[0], addrs[1], addrs[2], addrs[3]]);
            let d = u32::from_le_bytes([addrs[4], addrs[5], addrs[6], addrs[7]]);
            h = h.wrapping_mul(31).wrapping_add(s);
            h = h.wrapping_mul(31).wrapping_add(d);
        }
    } else if proto as u16 == ETH_P_IPV6 {
        // IPv6 saddr (22..38) + daddr (38..54), folded byte by byte.
        if let Ok(addrs) = load::<[u8; 32]>(ctx, 22) {
            for &b in &addrs {
                h = h.wrapping_mul(31).wrapping_add(b as u32);
            }
        }
    }

    h & 0xFFFFF
}

/// Write the outer IPv6 and EtherIP headers over the freshly grown headroom (the
/// outer Ethernet header is written by the caller). Ports `build_outer_headers`.
#[inline(always)]
fn build_outer_headers(
    ctx: &aya_ebpf::programs::XdpContext,
    cfg: &etherip_xdp_common::TunnelConfig,
    flow_hash: u32,
) -> Result<(), ()> {
    let eip_off = ETH_HDR_LEN + IPV6_HDR_LEN;
    // Outer IPv6 payload length = EtherIP + inner frame = total length minus the
    // outer Ethernet+IPv6 headers. Computing this as `data_end - (data + eip_off)`
    // is a packet-pointer subtraction the verifier rejects on newer kernels
    // ("R2 pointer -= pointer prohibited", seen on 6.x/7.0); the buff-len helper
    // returns the total length as a scalar instead.
    // SAFETY: eBPF helper; `ctx.ctx` is the valid `xdp_md` pointer aya provides.
    let total_len = unsafe { aya_ebpf::helpers::bpf_xdp_get_buff_len(ctx.ctx) } as usize;
    let payload_len = total_len.saturating_sub(eip_off) as u16; // EtherIP + inner
    let ip6 = headers::Ipv6Hdr {
        vtf: [
            0x60, // version 6, traffic class 0
            ((flow_hash >> 16) & 0x0F) as u8,
            ((flow_hash >> 8) & 0xFF) as u8,
            (flow_hash & 0xFF) as u8,
        ],
        payload_len: payload_len.to_be_bytes(),
        nexthdr: etherip_xdp_common::ETHERIP_PROTO,
        hop_limit: etherip_xdp_common::HOP_LIMIT_DEFAULT,
        saddr: cfg.src_addr,
        daddr: cfg.dst_addr,
    };
    store(ctx, ETH_HDR_LEN, ip6)?;

    let eip = headers::EtherIpHdr {
        ver: etherip_xdp_common::ETHERIP_VERSION,
        pad: 0,
    };
    store(ctx, eip_off, eip)
}

/// Clamp the inner TCP MSS for the frame at `inner_off`. Ports
/// `clamp_inner_tcp_mss`; `Err(())` aborts (truncated inner headers).
#[inline(always)]
fn clamp_inner_tcp_mss(
    ctx: &aya_ebpf::programs::XdpContext,
    inner_off: usize,
    cfg: &etherip_xdp_common::TunnelConfig,
) -> Result<(), ()> {
    let eth: headers::EthHdr = load(ctx, inner_off)?;
    let ethertype = u16::from_be_bytes(eth.ethertype);

    if ethertype == ETH_P_IP {
        let ip_off = inner_off + ETH_HDR_LEN;
        let ip: [u8; 20] = load(ctx, ip_off)?; // full minimum IPv4 header
        if ip[9] == IPPROTO_TCP {
            let ihl = (ip[0] & 0x0f) as usize;
            if ihl < 5 {
                return Err(());
            }
            return update_tcp_mss(ctx, ip_off + ihl * 4, cfg.mss_clamp_ipv4);
        }
    } else if ethertype == ETH_P_IPV6 {
        let ip6_off = inner_off + ETH_HDR_LEN;
        let ip6: headers::Ipv6Hdr = load(ctx, ip6_off)?;
        let (pos, final_nexthdr) = skip_ext_headers(ctx, ip6_off + IPV6_HDR_LEN, ip6.nexthdr)?;
        if final_nexthdr == IPPROTO_TCP {
            return update_tcp_mss(ctx, pos, cfg.mss_clamp_ipv6);
        }
    }

    Ok(())
}

#[inline(always)]
fn handle_encap(
    ctx: &aya_ebpf::programs::XdpContext,
    cfg: &etherip_xdp_common::TunnelConfig,
) -> u32 {
    dbg_inc(etherip_xdp_common::DBG_ENCAP_ENTER);

    if ptr_at::<headers::EthHdr>(ctx, 0).is_err() {
        return xdp_action::XDP_ABORTED;
    }
    let flow_hash = inner_flow_hash(ctx);

    let outer_len = etherip_xdp_common::OUTER_OVERHEAD;
    // SAFETY: `bpf_xdp_adjust_head` is an eBPF helper; `ctx.ctx` is the valid
    // `xdp_md` pointer aya provides. A negative delta grows headroom for the
    // outer headers. All packet pointers are re-derived (via `load`/`store`)
    // afterwards, so no stale pointer is used.
    let ret = unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx, -(outer_len as i32)) };
    if ret != 0 {
        dbg_inc(etherip_xdp_common::DBG_ENCAP_ADJUST_FAIL);
        return xdp_action::XDP_ABORTED;
    }

    if build_outer_headers(ctx, cfg, flow_hash).is_err() {
        dbg_inc(etherip_xdp_common::DBG_ENCAP_BUILD_FAIL);
        return xdp_action::XDP_ABORTED;
    }

    if clamp_inner_tcp_mss(ctx, outer_len, cfg).is_err() {
        dbg_inc(etherip_xdp_common::DBG_ENCAP_MSS_FAIL);
        return xdp_action::XDP_ABORTED;
    }

    let eth = headers::EthHdr {
        dst: cfg.dst_mac,
        src: cfg.external_mac,
        ethertype: ETH_P_IPV6.to_be_bytes(),
    };
    if store(ctx, 0, eth).is_err() {
        dbg_inc(etherip_xdp_common::DBG_ENCAP_BOUNDS_FAIL);
        return xdp_action::XDP_ABORTED;
    }

    dbg_inc(etherip_xdp_common::DBG_ENCAP_REDIRECT);
    REDIRECT_UPLINK
        .redirect(cfg.external_ifindex, 0)
        .unwrap_or(xdp_action::XDP_ABORTED)
}

#[inline(always)]
fn handle_decap(ctx: &aya_ebpf::programs::XdpContext) -> u32 {
    dbg_inc(etherip_xdp_common::DBG_DECAP_ENTER);

    let eth: headers::EthHdr = match load(ctx, 0) {
        Ok(e) => e,
        Err(()) => return xdp_action::XDP_ABORTED,
    };
    if u16::from_be_bytes(eth.ethertype) != ETH_P_IPV6 {
        dbg_inc(etherip_xdp_common::DBG_DECAP_NOT_IPV6);
        return xdp_action::XDP_PASS;
    }

    let ip6: headers::Ipv6Hdr = match load(ctx, ETH_HDR_LEN) {
        Ok(h) => h,
        Err(()) => return xdp_action::XDP_ABORTED,
    };

    let (eip_off, final_nexthdr) =
        match skip_ext_headers(ctx, ETH_HDR_LEN + IPV6_HDR_LEN, ip6.nexthdr) {
            Ok(v) => v,
            Err(()) => return xdp_action::XDP_ABORTED,
        };
    if final_nexthdr != etherip_xdp_common::ETHERIP_PROTO {
        dbg_inc(etherip_xdp_common::DBG_DECAP_NOT_ETHERIP);
        return xdp_action::XDP_PASS;
    }

    let key = etherip_xdp_common::DecapKey {
        remote: ip6.saddr,
        local: ip6.daddr,
    };
    // SAFETY: aya's `HashMap::get` is unsafe because it returns a reference into
    // map memory. DECAP_CONFIG is BPF_F_NO_PREALLOC and XDP runs under RCU, so
    // the element cannot be freed/recycled mid-run even if userspace updates the
    // map during reload; we also copy the value out immediately.
    let cfg = match unsafe { DECAP_CONFIG.get(&key) } {
        Some(c) => *c,
        None => {
            dbg_inc(etherip_xdp_common::DBG_DECAP_NO_TUNNEL);
            return xdp_action::XDP_PASS;
        }
    };

    // Loopback guard: drop frames sourced from our own tunnel address.
    if ip6.saddr == cfg.src_addr {
        dbg_inc(etherip_xdp_common::DBG_DECAP_OWN_PKT);
        return xdp_action::XDP_PASS;
    }

    let eip: headers::EtherIpHdr = match load_var(ctx, eip_off) {
        Ok(e) => e,
        Err(()) => return xdp_action::XDP_ABORTED,
    };
    if eip.ver != etherip_xdp_common::ETHERIP_VERSION || eip.pad != 0 {
        dbg_inc(etherip_xdp_common::DBG_DECAP_BAD_HEADER);
        return xdp_action::XDP_PASS;
    }

    // Inner Ethernet header must be present after the EtherIP header.
    let strip_len = eip_off + ETHERIP_HDR_LEN;
    if ctx.data() + strip_len + ETH_HDR_LEN > ctx.data_end() {
        return xdp_action::XDP_ABORTED;
    }

    // SAFETY: `bpf_xdp_adjust_head` with a positive delta strips the outer
    // headers; `ctx.ctx` is the valid `xdp_md` pointer. Packet pointers are
    // re-derived via `store` below, so no stale pointer is used.
    let ret = unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx, strip_len as i32) };
    if ret != 0 {
        return xdp_action::XDP_ABORTED;
    }

    if store(ctx, 0, cfg.tunnel_mac).is_err() {
        return xdp_action::XDP_ABORTED;
    }

    dbg_inc(etherip_xdp_common::DBG_DECAP_REDIRECT);
    REDIRECT_PEER
        .redirect(cfg.internal_ifindex, 0)
        .unwrap_or(xdp_action::XDP_ABORTED)
}

/// Encap entry, attached to each veth peer. The per-tunnel config is keyed by the
/// ingress (veth-peer) ifindex; a peer whose tunnel is still pending has no entry
/// yet, so its frames pass through untouched until a source resolves.
#[aya_ebpf::macros::xdp]
pub fn xdp_encap(ctx: aya_ebpf::programs::XdpContext) -> u32 {
    dbg_inc(etherip_xdp_common::DBG_MAIN_ENTER);
    let in_if = ctx.ingress_ifindex() as u32;
    // SAFETY: aya's `HashMap::get` is unsafe because it returns a reference into
    // map memory. ENCAP_CONFIG is BPF_F_NO_PREALLOC and XDP runs under RCU, so a
    // concurrent reload cannot free/recycle the element mid-run. We copy the
    // config onto the stack here so the rest of encap never touches map memory.
    match unsafe { ENCAP_CONFIG.get(&in_if) } {
        Some(cfg) => {
            let cfg = *cfg;
            handle_encap(&ctx, &cfg)
        }
        None => xdp_action::XDP_PASS,
    }
}

/// Decap entry, attached to the shared uplink. Frames are demuxed by the outer
/// IPv6 (remote, local) address pair inside [`handle_decap`]; the encap config is
/// never consulted here, so a veth-peer ifindex can never be misread as decap.
#[aya_ebpf::macros::xdp]
pub fn xdp_decap(ctx: aya_ebpf::programs::XdpContext) -> u32 {
    dbg_inc(etherip_xdp_common::DBG_MAIN_ENTER);
    handle_decap(&ctx)
}

/// Minimal pass-through attached to the user-facing veth end so the kernel's
/// `veth_xdp_xmit` peer check succeeds for redirected frames.
#[aya_ebpf::macros::xdp]
pub fn xdp_pass(_ctx: aya_ebpf::programs::XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

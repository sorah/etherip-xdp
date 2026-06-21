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
//! The actual packet parsing/transform lives in
//! [`etherip_xdp_common::data_path`], generic over a packet-memory abstraction so
//! it is shared verbatim with the host tests and fuzzers. This file supplies the
//! kernel half: the verifier-safe [`Packet`](etherip_xdp_common::data_path::Packet)
//! implementation over an [`aya_ebpf::programs::XdpContext`], the BPF maps, and
//! the per-path counters and redirects.
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

/// Kernel [`Packet`](etherip_xdp_common::data_path::Packet) implementation: the
/// verifier-safe primitives above, wrapped around an XDP context. The
/// `black_box` barrier for packet-derived offsets and the only `unsafe` in the
/// data path live here, so the shared core in `etherip_xdp_common::data_path`
/// stays free of both.
struct XdpPacket<'a> {
    ctx: &'a aya_ebpf::programs::XdpContext,
}

impl etherip_xdp_common::data_path::Packet for XdpPacket<'_> {
    #[inline(always)]
    fn load<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        load(self.ctx, offset)
    }

    #[inline(always)]
    fn store<T: Copy>(&mut self, offset: usize, value: T) -> Result<(), ()> {
        store(self.ctx, offset, value)
    }

    #[inline(always)]
    fn load_var<T: Copy>(&self, offset: usize) -> Result<T, ()> {
        load_var(self.ctx, offset)
    }

    #[inline(always)]
    fn store_var<T: Copy>(&mut self, offset: usize, value: T) -> Result<(), ()> {
        store_var(self.ctx, offset, value)
    }

    #[inline(always)]
    fn ensure(&self, end: usize) -> bool {
        // `data() + end <= data_end()` is a packet-pointer + scalar comparison the
        // verifier accepts, unlike the `data_end - data` subtraction it rejects on
        // newer kernels.
        self.ctx.data() + end <= self.ctx.data_end()
    }

    #[inline(always)]
    fn buff_len(&self) -> usize {
        // SAFETY: eBPF helper; `ctx.ctx` is the valid `xdp_md` pointer aya provides.
        unsafe { aya_ebpf::helpers::bpf_xdp_get_buff_len(self.ctx.ctx) as usize }
    }

    #[inline(always)]
    fn adjust_head(&mut self, delta: i32) -> Result<(), ()> {
        // SAFETY: `bpf_xdp_adjust_head` is an eBPF helper; `ctx.ctx` is the valid
        // `xdp_md` pointer. A negative delta grows headroom for the outer headers,
        // a positive delta strips them. All packet pointers are re-derived (via
        // `load`/`store`) afterwards, so no stale pointer is used.
        let ret = unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(self.ctx.ctx, delta) };
        if ret == 0 { Ok(()) } else { Err(()) }
    }
}

#[inline(always)]
fn handle_encap(
    ctx: &aya_ebpf::programs::XdpContext,
    cfg: &etherip_xdp_common::TunnelConfig,
) -> u32 {
    dbg_inc(etherip_xdp_common::DBG_ENCAP_ENTER);
    let mut pkt = XdpPacket { ctx };
    match etherip_xdp_common::data_path::encap(&mut pkt, cfg) {
        etherip_xdp_common::data_path::EncapOutcome::Abort => xdp_action::XDP_ABORTED,
        etherip_xdp_common::data_path::EncapOutcome::AdjustFail => {
            dbg_inc(etherip_xdp_common::DBG_ENCAP_ADJUST_FAIL);
            xdp_action::XDP_ABORTED
        }
        etherip_xdp_common::data_path::EncapOutcome::BuildFail => {
            dbg_inc(etherip_xdp_common::DBG_ENCAP_BUILD_FAIL);
            xdp_action::XDP_ABORTED
        }
        etherip_xdp_common::data_path::EncapOutcome::MssFail => {
            dbg_inc(etherip_xdp_common::DBG_ENCAP_MSS_FAIL);
            xdp_action::XDP_ABORTED
        }
        etherip_xdp_common::data_path::EncapOutcome::BoundsFail => {
            dbg_inc(etherip_xdp_common::DBG_ENCAP_BOUNDS_FAIL);
            xdp_action::XDP_ABORTED
        }
        etherip_xdp_common::data_path::EncapOutcome::Redirect => {
            dbg_inc(etherip_xdp_common::DBG_ENCAP_REDIRECT);
            REDIRECT_UPLINK
                .redirect(cfg.external_ifindex, 0)
                .unwrap_or(xdp_action::XDP_ABORTED)
        }
    }
}

#[inline(always)]
fn handle_decap(ctx: &aya_ebpf::programs::XdpContext) -> u32 {
    dbg_inc(etherip_xdp_common::DBG_DECAP_ENTER);
    let mut pkt = XdpPacket { ctx };
    let outcome = etherip_xdp_common::data_path::decap(&mut pkt, |key| {
        // SAFETY: aya's `HashMap::get` is unsafe because it returns a reference
        // into map memory. DECAP_CONFIG is BPF_F_NO_PREALLOC and XDP runs under
        // RCU, so the element cannot be freed/recycled mid-run even if userspace
        // updates the map during reload; `.copied()` copies the value out
        // immediately so the rest of decap never touches map memory.
        unsafe { DECAP_CONFIG.get(key).copied() }
    });
    match outcome {
        etherip_xdp_common::data_path::DecapOutcome::Abort => xdp_action::XDP_ABORTED,
        etherip_xdp_common::data_path::DecapOutcome::NotIpv6 => {
            dbg_inc(etherip_xdp_common::DBG_DECAP_NOT_IPV6);
            xdp_action::XDP_PASS
        }
        etherip_xdp_common::data_path::DecapOutcome::NotEtherip => {
            dbg_inc(etherip_xdp_common::DBG_DECAP_NOT_ETHERIP);
            xdp_action::XDP_PASS
        }
        etherip_xdp_common::data_path::DecapOutcome::NoTunnel => {
            dbg_inc(etherip_xdp_common::DBG_DECAP_NO_TUNNEL);
            xdp_action::XDP_PASS
        }
        etherip_xdp_common::data_path::DecapOutcome::OwnPkt => {
            dbg_inc(etherip_xdp_common::DBG_DECAP_OWN_PKT);
            xdp_action::XDP_PASS
        }
        etherip_xdp_common::data_path::DecapOutcome::BadHeader => {
            dbg_inc(etherip_xdp_common::DBG_DECAP_BAD_HEADER);
            xdp_action::XDP_PASS
        }
        etherip_xdp_common::data_path::DecapOutcome::Redirect { internal_ifindex } => {
            dbg_inc(etherip_xdp_common::DBG_DECAP_REDIRECT);
            REDIRECT_PEER
                .redirect(internal_ifindex, 0)
                .unwrap_or(xdp_action::XDP_ABORTED)
        }
    }
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

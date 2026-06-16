# etherip-xdp — handover sitrep

Port of **amaumene/xdp-etherip** (Go) → **Rust + aya**, with enhancements. Fresh
repo generated from `aya-template`; everything below was written this session.

> Source of truth for intent: `/home/sorah/.claude/plans/polished-leaping-garden.md`
> (the approved plan). This file is the *current* state + caveats.

## TL;DR status

- ✅ Builds (debug + release), **including the eBPF compiled for the BPF target** via `aya-build`.
- ✅ Host tests pass: **17** in `etherip-xdp` + **5** in `etherip-xdp-common`.
- ✅ `clippy --all-targets … -D warnings` clean, with `clippy::undocumented_unsafe_blocks` **enforced**.
- ✅ `cargo +nightly fmt --all -- --check` clean. `actionlint` clean on CI workflows.
- ❗ **NOT verified locally:** the eBPF *verifier* acceptance, the byte-exact
  `BPF_PROG_TEST_RUN` data-path tests, and live runtime. The sandbox is
  unprivileged (uid != 0, no CAP_BPF, no passwordless sudo). These need **root +
  kernel ≥ 5.15** — run `mise run test-bpf` (or rely on CI). This is the single
  biggest open risk; see "Open risks" below.
- 🚫 **Nothing is committed.** Fresh repo, all files untracked (per user pref:
  commit/branch/push only when explicitly asked). `Cargo.lock` is present & should be committed.

## What it does

XDP EtherIP (RFC 3378) tunnels: Ethernet-in-IPv6/EtherIP, encap on a veth peer,
decap on the shared uplink, DEVMAP_HASH redirect. Enhancements over the Go original:

1. **Multiple tunnels per uplink** — eBPF demuxes by ingress ifindex (encap) and
   outer IPv6 (remote,local) pair (decap).
2. **Continuous next-hop tracking** — netlink neigh/route/link/**addr** monitor +
   30s periodic re-resolve + ND probe; source-address-aware route lookup. The
   periodic tick sends a **keep-fresh probe** (XDP egress bypasses the kernel
   neighbour table, so entries would otherwise decay); the reactive (event) path
   only probes tunnels still lacking a MAC, else reads passively (no probe
   feedback loop). Probe policy is `resolver::Probe::{Bringup,Refresh,Passive}`.
3. **Auto / runtime-tracked local source** — `src` is now **optional**; when
   omitted, the outer source is the kernel's preferred source (`RTA_PREFSRC`) for
   the route to `dst`, re-derived on every re-resolution so it tracks underlay
   address changes. No source yet ⇒ tunnel is **pending** (veth + programs exist,
   encap/decap map entries withheld so nothing encaps with a bogus source). An
   explicit `src` not assigned locally is used anyway but warned.
4. **Customisable MSS clamp** — per tunnel: `auto`/`off`/int/`{ipv4,ipv6}`.
5. **JSON config + graceful `systemctl reload`** (SIGHUP diff: add/remove/update in place).

**Process model (decided w/ user):** one process per **external interface** →
templated `etherip-xdp@<iface>.service`. Forced by "one XDP program per
interface": tunnels sharing an uplink share one program + maps.

## Architecture / data plane

- One eBPF program `xdp_etherip` attached to the uplink (decap, shared) and to
  every `<name>-xdp` veth peer (encap). Branches on `ctx.ingress_ifindex()`.
- `xdp_pass` (second program in the same object) on each user-facing veth end
  `<name>` to satisfy the kernel's veth-redirect peer check.
- eBPF maps:
  - `ENCAP_CONFIG`: `HashMap<u32 veth_peer_ifindex, TunnelConfig>` — **BPF_F_NO_PREALLOC**.
  - `DECAP_CONFIG`: `HashMap<DecapKey{remote[16],local[16]}, TunnelConfig>` — **BPF_F_NO_PREALLOC**.
  - `REDIRECT_DEV`: `DevMapHash` (uplink + each veth-peer ifindex).
  - `DEBUG_COUNTERS`: `PerCpuArray<u64>` (DBG_* indices, dumped on exit).
- `TunnelConfig`/`DecapKey` are `#[repr(C)]` and shared via `etherip-xdp-common`
  (Pod impls behind the `user` feature).

## File map

- `etherip-xdp-common/src/lib.rs` — `TunnelConfig`, `DecapKey`, constants, DBG_* +
  `COUNTER_NAMES`, pure helpers `mss_clamp_from_mtu` / `checksum_update` /
  `inner_flow_hash` (+ unit tests). `#![cfg_attr(not(test), no_std)]`.
- `etherip-xdp-ebpf/src/main.rs` — the XDP programs. All packet access goes
  through documented `load`/`store` (`read_unaligned`/`write_unaligned` after a
  `ptr_at` bounds check). Ports: encap/decap/skip_ext_headers/update_tcp_mss/
  inner_flow_hash/build_outer_headers/clamp_inner_tcp_mss. `src/lib.rs` is the
  template's stub to enable the lib target (do not delete).
- `etherip-xdp/src/`:
  - `main.rs` — clap CLI, memlock bump (nix), signal+monitor+periodic select loop.
  - `config.rs` — JSON per-tunnel parsing (`TunnelSpec`, `MssConfig`), `load_dir`
    (async, `tokio::fs`) + tests. JSON fields are `local`/`remote`; **`local` is
    `Option<Ipv6Addr>`** (None = auto).
  - `netlink.rs` — rtnetlink 0.21 wrappers (link/veth/mtu, source-aware route_get
    incl. **`prefsrc`/RTA_PREFSRC**, neighbour, **`is_local_address`**, change
    monitor incl. **Ipv4/Ipv6 Ifaddr** groups + NewAddress/DelAddress). **Uses
    `rtnetlink::packet_route` / `::packet_core` re-exports**, NOT direct
    netlink-packet-* deps (version-match reasons).
  - `offload.rs` — ethtool TX-csum-disable via `nix` ioctl (SIOCETHTOOL).
  - `resolver.rs` — `resolve_endpoint` → `Resolved {src, dst_mac}` (combined
    source + next-hop resolution); pure `choose_src` (explicit wins, else prefsrc)
    + `choose_next_hop`; `NextHopOnLink` policy; `Probe` enum + `probe_once`.
  - `bpf.rs` — `aya::Ebpf` wrapper: load/attach(native→skb)/detach, typed map ops.
  - `tunnel.rs` — `Manager` (owns everything), per-tunnel lifecycle w/
    `effective_src` (pending vs ready), reload diff (`diff_specs`, pure + tests),
    `wait_for_external`, `reresolve_all(refresh: bool)`, `warn_if_src_unassigned`.
  - `tests/data_path.rs` — byte-exact `BPF_PROG_TEST_RUN` tests (`#[ignore]`, root).
- `packaging/etherip-xdp@.service`, `packaging/etc/etherip-xdp/eth1.d/*.json` (examples).
- `mise.toml` — task runner (migrated from justfile, which was deleted) + pins
  `cargo:bpf-linker`. Tasks: build/test/test-bpf/lint/fmt/run/install.
- `.github/workflows/ci.yml` (entry) → `_test.yml` (reusable; matrix
  `ubuntu-latest` + `ubuntu-24.04-arm`; build/clippy/fmt/host-tests/bpf-data-path).
- `README.md`, `Cargo.toml` (workspace; aya pinned rev), `.cargo/config.toml`.

## Key decisions / conventions (don't regress these)

- **aya pinned** to rev `b277f74443d4befdeb088879d0c358d726f9aa8e` in workspace
  `Cargo.toml` (needs the `TestRun`/`BPF_PROG_TEST_RUN` API). All aya crates same rev.
- **nix, not raw libc** for syscalls (ioctl/setrlimit/socket). User preference
  (saved to memory). Using libc *type defs* via `nix::libc`/`std::ffi` is fine.
- **`clippy::undocumented_unsafe_blocks` is `#![deny]`d** in all crate roots
  (common, ebpf, bin, the test). Every `unsafe` has a `// SAFETY:` comment. Keep it so.
- **eBPF unaligned access:** never `(*ptr).field` on packet memory — use `load`/
  `store` (read_unaligned/write_unaligned). Centralized + documented.
- **NO_PREALLOC on config maps:** required for reload-safety (RCU keeps a `get()`
  value valid for the whole XDP run; prealloc would recycle/tear it). See the
  long comment at the `NO_PREALLOC` const in the ebpf.
- **async-safety:** blocking syscalls (`probe_next_hop`, `offload::disable_tx_offload`)
  run via `tokio::task::spawn_blocking`; config I/O via `tokio::fs`. netlink is async.
- **`--next-hop-on-link={maybe,always,never}`** (default `maybe`): on-link
  assumption only with explicit intent. `maybe` = on-link only if the route table
  returns a gatewayless route; no route → unresolved (self-heals). Logic is in
  `resolver::choose_next_hop` (pure, tested).
- **Probe policy (`resolver::Probe`)** — don't collapse back into one mode:
  `Bringup` (add/update only) = the ≤5s retry loop; `Refresh` (periodic tick) =
  one keep-fresh probe so XDP-bypassed neighbour entries don't decay; `Passive`
  (reactive event w/ a MAC already) = read only, to avoid probe→event feedback.
  The reactive path uses `Refresh` only while a tunnel still lacks a MAC.
- **Pending vs ready (`RunningTunnel.effective_src`)** — a tunnel with no resolved
  source withholds its encap+decap map entries (never encap with `::`); programs
  are still attached. `reresolve_all` promotes pending→ready and **keeps the
  last-known src/MAC on transient failure** (never flaps ready→pending). eBPF maps
  are only rewritten when the built `TunnelConfig`/`DecapKey` actually changed.
- **Rust style** (sorah-guides): avoid `use` for types (full paths); `crate::` for
  intra-crate; trait `use` in narrowest scope. clippy must pass before commit.
- **clippy excludes the ebpf crate** (it's `no_std`/`no_main` for the bpf target):
  `cargo clippy --all-targets --workspace --exclude etherip-xdp-ebpf -- -D warnings`.
- **fmt needs nightly** (rustfmt.toml has unstable options): `cargo +nightly fmt`.
- `.cargo/config.toml` has **no `runner = sudo`** (removed; it broke host tests) —
  run the daemon/root tests with explicit sudo.

## Cold-start / robustness behaviour (recently added)

- **Missing uplink:** `wait_for_external` retries with capped backoff (1→5s)
  indefinitely; `systemctl stop`/Ctrl-C still terminate during the wait (no signal
  handlers installed yet). No more crash-loop.
- **Missing route / next-hop:** tunnel is still created (veth/attach/maps with
  `dst_mac=0`); the netlink monitor + periodic re-resolve fill it in when the
  underlay appears. `add_tunnel` never fails on resolution.

## Build / test / run

```sh
mise install                 # bpf-linker (also: rustup nightly + rust-src, stable)
mise run build               # cargo build --release (builds eBPF via build.rs)
mise run test                # host unit tests (no root)
mise run lint                # clippy -D warnings
mise run test-bpf            # ROOT + kernel>=5.15: byte-exact data-path tests
sudo ./target/release/etherip-xdp eth1   # or: mise run run eth1
```
Config: `/etc/etherip-xdp/<device>.d/*.json` (one tunnel per file; `name` defaults
to file stem; `local`/`remote` IPv6; `mss` auto/off/int/{ipv4,ipv6}; optional `mtu`).

## Open risks / TODO for next agent

1. **eBPF verifier UNVALIDATED locally.** Highest priority: run `mise run test-bpf`
   on a privileged host (or push to CI). Riskiest constructs if it's rejected:
   `load`/`store` `read_unaligned` of large types (`Ipv6Hdr` 40B, `[u8;32]`,
   `[u8;20]`) and the bounded variable-offset loops (`skip_ext_headers`,
   TCP-option scan). The Go original used an `asm volatile` verifier hint in the
   MSS loop that we don't replicate — watch that path. Fixes would be localized.
2. **Multi-program-in-one-section** (`xdp_etherip` + `xdp_pass` share SEC `xdp`):
   aya-obj extracts per function symbol (confirmed from source), but runtime load
   of both is unconfirmed without root. `bpf.rs::Bpf::load` loads both by name.
3. **GitHub runners + BPF_PROG_TEST_RUN:** CI runs the data-path tests under sudo
   on `ubuntu-latest`/`ubuntu-24.04-arm`. Should work (root, recent kernel) but
   unconfirmed; if the runner blocks BPF, gate/remove that CI step. `ubuntu-24.04-arm`
   is free only for public repos.
4. **External MAC/MTU captured once** at first appearance, not refreshed on link
   change. If the uplink MAC/MTU changes at runtime, running tunnels keep stale
   values until restart. (Offered to fix via the link-change monitor path; not done.)
   NOTE: the analogous gap for the *outer source address* is now **fixed** — auto
   `src` re-derives on every re-resolve and the addr monitor wakes it; only the
   uplink MAC/MTU remain captured-once.
5. **`add_tunnel`/`update_tunnel` next-hop bring-up is sequential** per tunnel
   (`Probe::Bringup` = ≤10×500ms = 5s each worst case). The *periodic/reactive*
   re-resolve no longer does the 5s loop (single `Refresh` probe / `Passive`
   read), so a dead peer no longer stalls the others there; only the explicit
   add/update path is still serial. Could decouple if many tunnels.
   **Pending-state map-withholding is only exercised live (root)** — verify on a
   privileged host that a pending tunnel installs its encap/decap entries once a
   route/source appears.
6. **README/plan** describe the design; keep README's `--next-hop-on-link` table
   and config schema in sync if you change them.

## Environment (this machine)

kernel 6.19, rustup nightly + rust-src, stable rustc 1.96, bpf-linker 0.10.3 (mise:
`cargo:bpf-linker`), clang present, `actionlint` present (mise). uid is unprivileged.

## Memory (already saved for future sessions)

- `prefer-nix-rustix-over-libc` (feedback)
- `wants-adequate-unit-tests` (feedback)
(see the project memory dir `MEMORY.md`).

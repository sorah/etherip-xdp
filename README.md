# etherip-xdp

XDP-accelerated **EtherIP (RFC 3378) over IPv6** tunnels, written in Rust with
[aya](https://aya-rs.dev/). Ethernet frames are encapsulated in
`outer-Ethernet + IPv6 + EtherIP` and moved between a physical uplink and a veth
pair entirely in XDP, with DEVMAP redirect on both directions.

This is a Rust port of [amaumene/xdp-etherip](https://github.com/amaumene/xdp-etherip)
(itself a fork of [x86taka/xdp-etherip](https://github.com/x86taka/xdp-etherip)),
with several enhancements:

- **Multiple tunnels per uplink** — many EtherIP tunnels share one physical
  interface, demultiplexed in eBPF by ingress ifindex (encap) and outer IPv6
  address pair (decap).
- **Continuous next-hop tracking** — the next-hop MAC is re-resolved on netlink
  neighbour/route changes (plus a periodic safety sweep), honouring policy
  routing and source-address selection. An active ND probe is sent if the
  neighbour entry is missing, so no manual "ping the peer first" is needed; the
  periodic sweep also re-probes to keep entries fresh, since XDP egress bypasses
  the kernel neighbour table and never refreshes them itself.
- **Customisable TCP MSS clamping** — per tunnel: `auto` (from MTU), explicit, or off.
- **JSON config with graceful reload** — `systemctl reload` (SIGHUP) applies
  config changes in place; unaffected tunnels keep forwarding.

## How it works

```
        /etc/etherip-xdp/eth1.d/{peer,office}.json   (one file per tunnel)
                         │  one process per uplink: etherip-xdp@eth1
   user iface peer  ◄─XDP_PASS             user iface office  ◄─XDP_PASS   (host netns)
        │ veth                                  │ veth
··· hidden netns ·······························│··································
   peer-xdp  ◄─ xdp_encap                  office-xdp  ◄─ xdp_encap
        │                                       │
        └──────────── DEVMAP_HASH redirect ─────┴──────────►  eth1 ◄─ xdp_decap (shared)
```

A veth pair is created per tunnel; the user-facing end (`<name>`) carries your L2
traffic, the peer (`<name>-xdp`) runs `xdp_encap`. The shared `xdp_decap` program
on the uplink handles decap for every tunnel. A minimal `XDP_PASS` program on each
user-facing end satisfies the kernel's veth redirect peer check.

**Hidden peer namespace:** the `<name>-xdp` peer is purely an internal artefact of
driving encap through XDP, so by default it is moved into a daemon-private,
anonymous network namespace — it never shows up in `ip link` (or `ip netns list`)
and is destroyed when the daemon exits. Only the user-facing `<name>` end stays in
the host namespace. Decap and encap therefore redirect across the namespace
boundary, which native-mode XDP supports (the same path container networking uses);
encap and decap use separate devmaps so the peer's namespace-local ifindex can
never collide with the uplink's. Pass `--disable-veth-peer-netns` to keep the peer
in the host namespace instead (for debugging, or on kernels without working
cross-namespace XDP redirect, where it would otherwise fall back to slower SKB
mode or fail).

**Why one process per uplink:** only one XDP program may be attached to a given
interface, so tunnels sharing an uplink must share one program. The process /
systemd-instance boundary is therefore the uplink (`etherip-xdp@eth1`,
`etherip-xdp@eth2`, …), not the individual tunnel.

The tunnel MTU defaults to `external_mtu - 56` (outer IPv6 40 + EtherIP 2 + inner
Ethernet 14) and can be overridden per tunnel.

## Build

Prerequisites:

```shell
rustup toolchain install stable
rustup toolchain install nightly --component rust-src   # builds the eBPF
# bpf-linker is pinned in mise.toml; `mise install` provides it (or: cargo install bpf-linker)
```

Then:

```shell
mise run build       # or: cargo build --release
```

Tasks are defined in `mise.toml`; list them with `mise tasks`.

The eBPF object is compiled and embedded automatically by `etherip-xdp/build.rs`
(via `aya-build`); no separate clang/libbpf step is required.

## Configure

One JSON file per tunnel under `/etc/etherip-xdp/<device>.d/`:

```json
{
  "local": "2001:db8::1",
  "remote": "2001:db8::2",
  "mss": "auto"
}
```

| Field    | Required | Description |
|----------|----------|-------------|
| `name`   | no       | Tunnel / user-facing interface name (default: file stem). Max 11 chars. |
| `local`  | no       | Local outer IPv6 endpoint. Omit to auto-select the kernel's preferred source for the route to `remote`; the choice is re-evaluated on underlay changes. |
| `remote` | yes      | Remote outer IPv6 endpoint. |
| `mss`    | no       | `"auto"` (default), `"off"`, an integer (both families), or `{ "ipv4": N, "ipv6": N }`. |
| `mtu`    | no       | Tunnel MTU override (default: uplink MTU − 56). |
| `mac`    | no       | Local MAC the user-facing interface presents on the connected L2 domain. Omit to keep the kernel-assigned address, `"inherit"` to copy the external device's MAC, or an explicit `"xx:xx:xx:xx:xx:xx"`. |

The external device is the process scope, so it is **not** repeated in the
file (see `packaging/etc/etherip-xdp/eth1.d/` for examples).

## Reload

The daemon re-reads the config directory only on **SIGHUP** (`systemctl reload
etherip-xdp@<device>`); editing files has no effect until then. A reload is
graceful: the new set of configs is diffed against the running tunnels **by
tunnel name**, and only the difference is applied — unchanged tunnels are left
running and never flap.

Each loaded config falls into one of three cases:

| Case | Trigger | Action |
|------|---------|--------|
| Added   | A tunnel name not currently running | Created fresh: veth pair, XDP attach, map entries. |
| Removed | A running tunnel whose name is gone from the configs | Torn down: programs detached, map entries removed, veth deleted. |
| Updated | Same name, any field changed | Reconfigured **in place** — the veth is never recreated, because its name is the tunnel's identity. |

Because the tunnel name is the identity, an in-place update covers every other
attribute without dropping the interface. How each behaves on update:

| Attribute | Behavior on reload |
|-----------|--------------------|
| `name`   | This *is* the identity, so it is not an in-place update: the old name is treated as removed and the new one as added (the veth is recreated under the new name, with a brief data interruption). Renaming the file behaves the same, since the name defaults to the file stem. |
| `local`  | Outer source re-resolved; the decap key and encap/decap map entries are updated. The last-known source is kept if a new one cannot be resolved, so a ready tunnel never flaps back to pending. |
| `remote` | Outer destination and decap key updated; the next-hop MAC is re-resolved (with an ND probe) for the new endpoint. |
| `mss`    | Recomputed and rewritten into the map. No veth or attach churn. |
| `mtu`    | The user-facing veth and its peer are set to the new MTU in place. No recreation. |
| `mac`    | Applied to the existing veth via netlink. Switching back to the omitted/default keeps the current address — the original kernel-assigned MAC is **not** restored without recreating the veth (rename or remove+add it to do so). |

If applying one tunnel fails during a reload, the error is logged and the
remaining tunnels are still processed. A tunnel that is still pending (an
auto-selected `local` with no route yet) records the new spec on reload and is
installed once a source resolves.

Underlay tracking — re-selecting an auto `local` source and refreshing the
next-hop MAC — happens continuously on netlink change events and a periodic
tick, independent of SIGHUP. SIGHUP is only for applying config-file edits.

## Run

```shell
# Manually (root):
sudo ./target/release/etherip-xdp eth1
# or `mise run run eth1`

# Via systemd (templated by uplink):
sudo install -Dm0755 target/release/etherip-xdp /usr/bin/etherip-xdp
sudo install -Dm0644 packaging/etherip-xdp@.service /etc/systemd/system/etherip-xdp@.service
sudo systemctl enable --now etherip-xdp@eth1
sudo systemctl reload etherip-xdp@eth1   # graceful reload after editing configs
```

### Debian package

A `.deb` (binary at `/usr/bin/etherip-xdp`, the templated unit at
`/lib/systemd/system/etherip-xdp@.service`, example configs under
`/usr/share/doc/etherip-xdp/examples/`) can be built with
[`cargo-deb`](https://github.com/kornelski/cargo-deb):

```shell
cargo install cargo-deb
cargo deb -p etherip-xdp        # release build, then ./target/debian/*.deb
```

The package only runs `systemctl daemon-reload`; enable it per uplink yourself:

```shell
sudo systemctl enable --now etherip-xdp@eth1
```

On SIGINT/SIGTERM the program prints its debug counters and tears down all veths
and XDP attachments.

### Next-hop resolution & the on-link policy

The next-hop MAC is resolved from the kernel routing/neighbour tables (honouring
policy routing and source-address selection) and re-resolved on netlink changes.
If a tunnel can't be resolved at startup (no route, no neighbour, uplink not up
yet) the tunnel is still created and self-heals once the underlay is ready — the
daemon also waits for the uplink interface to appear instead of crash-looping.

When the route lookup returns **no gateway**, whether the remote endpoint is
treated as its own next hop ("on-link") is controlled by `--next-hop-on-link`:

| Value | Behaviour |
|-------|-----------|
| `maybe` (default) | On-link only when the routing table returns a gatewayless (connected) route for the destination. No route → left unresolved (retried on netlink changes). |
| `always` | Always treat the destination as on-link when no gateway is found, even without a matching route. |
| `never` | Never assume on-link; a gateway is required. |

An explicit gateway from the route lookup always takes precedence regardless of
this setting.

### Outer source address

If `local` is set, it is used verbatim (and passed to the route lookup so policy
routing and source-address selection behave as if the packet originated there).
If `local` is **omitted**, the kernel's preferred source for the route to
`remote` (its RFC 6724 selection) is adopted, and is re-evaluated on every
re-resolution — so a change to the underlay address (e.g. a renumber, or the
address appearing after boot) is picked up automatically. Until a source
resolves, the tunnel is **pending**: the veth and programs exist but the
data-path map entries are withheld, so nothing is encapsulated with a bogus
source. A configured `local` that is not assigned to any local interface is
used anyway but logged as a
warning (it is usually a typo or a removed address, and tends to be dropped by
reverse-path filtering).

## Debug counters

Per-CPU counters are maintained across the encap/decap paths and dumped on exit
(`encap_enter`, `encap_redirect`, `encap_mss_fail`, `decap_enter`,
`decap_redirect`, `decap_not_ipv6`, `decap_not_etherip`, `decap_no_tunnel`,
`decap_own_pkt`, `decap_bad_header`, `main_enter`, …). Set `RUST_LOG=debug` for
verbose logging.

## Test

```shell
mise run test       # host unit tests (config, MSS, checksum, flow hash, reload diff)
mise run lint       # clippy (must pass before commit)
mise run test-bpf   # byte-exact data-path tests via BPF_PROG_TEST_RUN (root, kernel >= 5.15)
```

The data-path tests drive the XDP program with `BPF_PROG_TEST_RUN` and assert the
exact encap/decap output and action, mirroring the upstream Go test suite.

### Fuzzing

The packet parsing/transform logic lives in `etherip_xdp_common::data_path`,
generic over a packet-memory abstraction so it compiles both as the kernel XDP
program and against a plain byte buffer on the host. The `BPF_PROG_TEST_RUN` tests
above assert the two agree byte for byte, so coverage-guided fuzzing of the host
core carries over to the kernel program — without needing root or a BPF-capable
kernel:

```shell
mise run fuzz roundtrip   # encap∘decap round-trip property (default target)
mise run fuzz encap       # outer header/flow-label invariants on arbitrary inner frames
mise run fuzz decap       # IPv6 ext-header walking + EtherIP strip on arbitrary frames
```

Targets live under [`test/fuzzing/`](test/fuzzing/) (its own [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
workspace; needs nightly). CI runs a short bounded pass of each on every change.

### Integration tests

End-to-end tests run the **real** daemon on two peers and tunnel between them,
covering the live attach/redirect path that `BPF_PROG_TEST_RUN` cannot:

```shell
mise run integration-local   # two network namespaces on the host (root)
mise run integration-vm      # two qemu-system-x86_64 VMs (kernels 6.5/6.8/7.0)
```

The VM runner joins the two guests with a QEMU `-netdev stream` socket, so no
privileged host networking is required. See [`test/README.md`](test/README.md).

## License

With the exception of eBPF code, etherip-xdp is distributed under the terms of
the [MIT license].

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

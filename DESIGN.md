# etherip-xdp design

Technical design notes for etherip-xdp. For installation and day-to-day use, see
[README.md](README.md); this document covers the mechanisms behind it.

## Data path

```
  /etc/etherip-xdp/interfaces.d/eth1/{peer,office}.json   (one file per tunnel)
                         │  one process per uplink: etherip-xdp@eth1
   tunnel iface peer ◄─XDP_PASS              tunnel iface office ◄─XDP_PASS  (host netns)
        │ veth                                   │ veth
··· hidden netns ········································································
   peer-xdp  ◄─ xdp_encap                   office-xdp  ◄─ xdp_encap
        │                                        │
        └──────────── DEVMAP_HASH redirect ──────┴──────────►  eth1 ◄─ xdp_decap (shared)
```

A veth pair is created per tunnel. The user-facing end (`<name>`) carries your L2
traffic; the peer (`<name>-xdp`) runs `xdp_encap`. The shared `xdp_decap` program
on the uplink handles decap for every tunnel. A minimal `XDP_PASS` program on each
user-facing end satisfies the kernel's veth redirect peer check.

Encap demultiplexes by ingress ifindex (each tunnel's peer veth is distinct);
decap demultiplexes by the outer IPv6 source/destination address pair, so many
tunnels share the one uplink program. Redirect uses `DEVMAP_HASH` in both
directions; encap and decap use separate devmaps so the peer's namespace-local
ifindex can never collide with the uplink's.

### Transparent L2

Both directions preserve the inner Ethernet frame byte for byte: encap only
prepends the outer headers (and optionally clamps the inner TCP MSS), decap only
strips them; neither rewrites the inner MACs. So `<name>` is a plain L2
interface: give it an IP to use as a host endpoint (the far side reaches its MAC
via ordinary ARP/ND), or enslave it to a Linux bridge to extend an L2 segment.
The `mac` config option only sets `<name>`'s own address.

The tunnel MTU defaults to `external_mtu - 56` (outer IPv6 40 + EtherIP 2 + inner
Ethernet 14) and can be overridden per tunnel.

### Hidden peer namespace

The `<name>-xdp` peer is purely an internal artefact of driving encap through
XDP, so by default it is moved into a daemon-private, anonymous network
namespace; it never shows up in `ip link` (or `ip netns list`) and is destroyed
when the daemon exits. Only the user-facing `<name>` end stays in the host
namespace.

Decap and encap therefore redirect across the namespace boundary, which
native-mode XDP supports (the same path container networking uses). Pass
`--disable-veth-peer-netns` to keep the peer in the host namespace instead (for
debugging, or on kernels without working cross-namespace XDP redirect, where it
would otherwise fall back to slower SKB mode or fail).

### One process per uplink

Only one XDP program may be attached to a given interface, so tunnels sharing an
uplink must share one program. The process / systemd-instance boundary is
therefore the uplink (`etherip-xdp@eth1`, `etherip-xdp@eth2`, …), not the
individual tunnel. The daemon owns its uplink's device, every tunnel's veth pair,
the shared maps, and the management socket.

## Next-hop resolution

XDP egress bypasses the kernel neighbour table and never refreshes it, so the
daemon resolves and maintains the next-hop MAC itself. It looks up the route to
`remote` (honouring policy routing and source-address selection), finds the
next-hop neighbour, and writes its MAC into the encap map. If the neighbour entry
is missing, an active ND probe is sent, so there is no manual "ping the peer
first" step.

Resolution is continuous: it re-runs on netlink neighbour/route change events
(debounced) and on a periodic safety sweep (every 30 s). The sweep also re-probes
to keep entries fresh, since the kernel won't. A tunnel that can't resolve at
startup (no route, no neighbour, uplink not up yet) is still created and
self-heals once the underlay is ready; the daemon waits for the uplink interface
to appear rather than crash-looping.

### The on-link policy

When the route lookup returns **no gateway**, whether the remote endpoint is
treated as its own next hop ("on-link") is controlled per tunnel by
`next_hop_on_link`:

| Value | Behaviour |
|-------|-----------|
| `maybe` (default) | On-link only when the routing table returns a gatewayless (connected) route for the destination. No route → left unresolved (retried on netlink changes). |
| `always` | Always treat the destination as on-link when no gateway is found, even without a matching route. |
| `never` | Never assume on-link; a gateway is required. |

An explicit gateway from the route lookup always takes precedence regardless of
this setting.

## Outer source address

If `local` is set, it is used verbatim (and passed to the route lookup so policy
routing and source-address selection behave as if the packet originated there).
If `local` is **omitted**, the kernel's preferred source for the route to
`remote` (its RFC 6724 selection) is adopted, and is re-evaluated on every
re-resolution, so a change to the underlay address (a renumber, or the address
appearing after boot) is picked up automatically.

Until a source resolves, the tunnel is **pending**: the veth and programs exist
but the data-path map entries are withheld, so nothing is encapsulated with a
bogus source. A configured `local` that is not assigned to any local interface is
used anyway but logged as a warning (usually a typo or a removed address, and
tends to be dropped by reverse-path filtering).

## Reload

The daemon re-reads the config directories only on **SIGHUP** (`systemctl reload
etherip-xdp@<uplink>`); editing files has no effect until then. The reload is
graceful: the new set of configs is diffed against the running tunnels **by
tunnel name**, and only the difference is applied; unchanged tunnels are left
running and never flap.

Each loaded config falls into one of three cases:

| Case | Trigger | Action |
|------|---------|--------|
| Added   | A tunnel name not currently running | Created fresh: veth pair, XDP attach, map entries. |
| Removed | A running tunnel whose name is gone from the configs | Torn down: programs detached, map entries removed, veth deleted. |
| Updated | Same name, any field changed | Reconfigured **in place**; the veth is never recreated, because its name is the tunnel's identity. |

Because the tunnel name is the identity, an in-place update covers every other
attribute without dropping the interface:

| Attribute | Behavior on reload |
|-----------|--------------------|
| `name`   | This *is* the identity, so it is not an in-place update: the old name is treated as removed and the new one as added (the veth is recreated under the new name, with a brief data interruption). Renaming the file behaves the same, since the name defaults to the file stem. |
| `local`  | Outer source re-resolved; the decap key and encap/decap map entries are updated. The last-known source is kept if a new one cannot be resolved, so a ready tunnel never flaps back to pending. |
| `remote` | Outer destination and decap key updated; the next-hop MAC is re-resolved (with an ND probe) for the new endpoint. |
| `mss`    | Recomputed and rewritten into the map. No veth or attach churn. |
| `mtu`    | The user-facing veth and its peer are set to the new MTU in place. No recreation. |
| `mac`    | Applied to the existing veth via netlink. Switching back to the omitted/default keeps the current address; the original kernel-assigned MAC is **not** restored without recreating the veth (rename or remove+add it to do so). |
| `next_hop_on_link` | Next-hop MAC re-resolved under the new policy; the encap/decap map entries are updated. No veth or attach churn. |

If applying one tunnel fails during a reload, the error is logged and the
remaining tunnels are still processed. A tunnel that is still pending (an
auto-selected `local` with no route yet) records the new spec on reload and is
installed once a source resolves.

Underlay tracking (re-selecting an auto `local` source and refreshing the
next-hop MAC) happens continuously on netlink change events and a periodic
tick, independent of SIGHUP. SIGHUP is only for applying config-file edits.

### Config directory resolution

The daemon reads tunnels from `/etc/etherip-xdp/interfaces.d/<uplink>/` by
default. Two mutually-exclusive flags (both repeatable) point elsewhere:

- `--config-root <dir>` replaces the config root; the `interfaces.d/<uplink>`
  layout is still appended (so the directory becomes
  `<dir>/interfaces.d/<uplink>/`).
- `--config-dir <dir>` names a directory to read verbatim, without the
  `interfaces.d/<uplink>` layout.

When several directories are given (or searched by default), they follow systemd
drop-in precedence: a file name found in an earlier (higher-precedence) directory
shadows the same name in later ones.

The bundled `etherip-xdp@.service` sets `RuntimeDirectory=etherip-xdp`, so a
systemd-managed daemon also searches `/run/etherip-xdp/interfaces.d/<uplink>/`
*ahead* of `/etc` (via the exported `$RUNTIME_DIRECTORY`). This lets a generator
or orchestration layer write volatile tunnel drop-ins under `/run` that override
or extend the on-disk `/etc` config without touching it; the directory is kept
across daemon restarts (`RuntimeDirectoryPreserve=yes`) and cleared only at
reboot.

## Management plane

Status is exposed over a [varlink](https://varlink.org/) interface,
`co.0w0.etheripxdp.Management`, with a single read-only `List` method returning
each uplink's `InterfaceStatus` (external device, per-CPU debug counters summed,
and the tunnel list with state, configured/effective source, next hop, MSS, MTU,
MAC, and policies). The IDL lives at
`etherip-xdp/src/manage/co.0w0.etheripxdp.Management.varlink` and the Rust
bindings are generated from it at build time.

There are three pieces:

- **Per-uplink daemon socket.** Each `etherip-xdp@<uplink>` daemon serves the
  interface on a socket-activated control socket at
  `/run/etherip-xdp/<uplink>/co.0w0.etheripxdp.Management`
  (`etherip-xdp-varlink@<uplink>.socket`). Its `List` returns that one daemon's
  status.
- **Host-wide manager.** `etherip-xdp-manager` is a small proxy that discovers
  every per-uplink socket under `/run/etherip-xdp/` and aggregates their `List`
  replies into one. It listens at the top-level
  `/run/etherip-xdp/co.0w0.etheripxdp.Management`
  (`etherip-xdp-manager.socket`), which is the well-known endpoint and the only
  one registered under `/run/varlink/registry` so `varlinkctl` can address it by
  interface name.
- **`etheripctl`.** The CLI connects to the manager (or, with `--socket`, a
  single daemon for debugging), calls `List`, and renders the result. It is
  read-only.

### Privilege separation

The daemons and the manager run as separate `DynamicUser`s, so neither runs as
root or shares the other's private runtime directory. They coordinate through a
static `etherip-xdp-sock` group: `/run/etherip-xdp` and the `0660` control
sockets are group-owned, the directory is `2750` setgid so socket-activated
per-uplink subdirectories inherit the group, and both the daemons and the manager
join the group as a supplementary group. That lets the manager read the daemons'
sockets, and lets a human in the group run `etheripctl`, without anyone holding
root. (A shared `DynamicUser` could not do this: systemd parks a shared
`RuntimeDirectory` under `/run/private` at `0700`.)

The daemon itself needs a focused capability set,
`CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_NET_RAW CAP_SYS_ADMIN`
(the last for `unshare(CLONE_NEWNET)`, dropped by `--disable-veth-peer-netns`),
under full `systemd-analyze security` sandboxing. The manager needs no
capabilities at all.

## Debug counters

Per-CPU counters are maintained across the encap/decap paths, summed across CPUs,
surfaced in `etheripctl` (non-zero only) and dumped on exit: `encap_enter`,
`encap_redirect`, `encap_mss_fail`, `decap_enter`, `decap_redirect`,
`decap_not_ipv6`, `decap_not_etherip`, `decap_no_tunnel`, `decap_own_pkt`,
`decap_bad_header`, `main_enter`, … Set `RUST_LOG=debug` for verbose logging.

## Testing

The packet parsing/transform logic lives in `etherip_xdp_common::data_path`,
generic over a packet-memory abstraction so it compiles both as the kernel XDP
program and against a plain byte buffer on the host.

- **Host unit tests** (`mise run test`) cover config parsing, MSS computation,
  checksum, flow hashing, and the reload diff.
- **Byte-exact data-path tests** (`mise run test-bpf`) drive the real XDP program
  with `BPF_PROG_TEST_RUN` and assert the exact encap/decap output and action,
  mirroring the upstream Go test suite (root, kernel ≥ 5.15).
- **Fuzzing.** Because the `BPF_PROG_TEST_RUN` tests assert the host core and the
  kernel program agree byte for byte, coverage-guided fuzzing of the host core
  carries over to the kernel program without root or a BPF-capable kernel.
  Targets live under [`test/fuzzing/`](test/fuzzing/) (its own
  [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) workspace; nightly):

  ```shell
  mise run fuzz roundtrip   # encap∘decap round-trip property (default target)
  mise run fuzz encap       # outer header/flow-label invariants on arbitrary inner frames
  mise run fuzz decap       # IPv6 ext-header walking + EtherIP strip on arbitrary frames
  ```

- **Integration tests** run the real daemon on two peers and tunnel between them,
  covering the live attach/redirect path that `BPF_PROG_TEST_RUN` cannot:

  ```shell
  mise run integration-local   # two network namespaces on the host (root)
  mise run integration-vm      # two qemu-system-x86_64 VMs (kernels 6.5/6.8/7.0)
  ```

  The VM runner joins the two guests with a QEMU `-netdev stream` socket, so no
  privileged host networking is required. See [`test/README.md`](test/README.md).

CI runs the unit tests, clippy, and a short bounded pass of each fuzz target on
every change.

# etherip-xdp

XDP-accelerated **EtherIP (RFC 3378) over IPv6** tunnels. A transparent
Layer-2 tunnel that forwards entirely in the kernel fast path, **designed for
production: built to be configured, observed, and changed by an operator on a
live host without dropping traffic.**

Each tunnel appears on the host as a plain Ethernet interface: give it an IP to
use as an endpoint, or enslave it to a bridge to stretch an L2 segment across
the network. Frames are encapsulated in `IPv6 + EtherIP` and moved between your
physical uplink and the tunnel interface by an XDP program, never touching the
normal network stack on the way through, so it stays fast even at high packet
rates.

The XDP fast path is the easy part; running it in production is the hard part,
and that is what this project is about. Tunnels are described by plain JSON files
and reloaded gracefully, the next hop is resolved and kept fresh automatically,
live state is one `etheripctl` command away, and the shipped systemd units are
sandboxed and run unprivileged. An operator can stand a tunnel up, see what
it is doing, and reconfigure it safely while the rest keep forwarding.

## Why etherip-xdp

This is a Rust rewrite of [amaumene/xdp-etherip](https://github.com/amaumene/xdp-etherip)
(itself a fork of [x86taka/xdp-etherip](https://github.com/x86taka/xdp-etherip)).
The originals prove out the XDP data path; this rewrite is built for the operator
who has to run it. Everything below exists to make day-2 operations
(deploy, observe, reconfigure, troubleshoot) safe and routine:

- **Many tunnels per uplink.** One physical interface carries as many EtherIP
  tunnels as you configure, not one tunnel per program.
- **JSON configuration, one file per tunnel.** Drop a small `*.json` file in a
  directory; no recompiling, no hand-edited program constants. systemd drop-in
  precedence is supported for layering volatile config over on-disk config.
- **Graceful, safe reload.** `systemctl reload` applies config changes in place.
  Unchanged tunnels keep forwarding and never flap; only the tunnels that
  actually changed are touched.
- **Automatic next-hop resolution.** The daemon resolves the peer's next-hop MAC
  from the kernel routing/neighbour tables, honouring policy routing and source
  selection, and keeps it fresh as the network changes. No "ping the peer
  first" ritual; tunnels self-heal once the underlay is ready.
- **A live status CLI.** `etheripctl` shows every interface, every tunnel, its
  state, resolved source/next-hop, and counters across all uplinks on the host.
- **Per-tunnel TCP MSS clamping.** `auto` (derived from MTU), an explicit value,
  or off.
- **Hardened by default.** The shipped systemd units run as a `DynamicUser` with
  a tight capability set and `systemd-analyze security` sandboxing.

## Quick start

### 1. Install

Build a Debian package with [`cargo-deb`](https://github.com/kornelski/cargo-deb)
and install it (this places the binaries, systemd units, and example configs):

```shell
cargo install cargo-deb
cargo deb -p etherip-xdp
sudo dpkg -i target/debian/etherip-xdp_*.deb
```

Or build and install the binaries directly; see [Build](#build) below.

### 2. Configure a tunnel

Configuration is one JSON file per tunnel, under a directory named for the
uplink it rides on. To run two tunnels over `eth1`:

```shell
sudo mkdir -p /etc/etherip-xdp/interfaces.d/eth1
```

`/etc/etherip-xdp/interfaces.d/eth1/peer.json`:

```json
{
  "remote": "2001:db8::2",
  "mss": "auto"
}
```

That is the minimum: just the remote IPv6 endpoint. The tunnel interface is
named after the file (`peer` here), and the local outer source is auto-selected
from the routing table. See the [configuration reference](#configuration-reference)
for every field.

### 3. Start it

One systemd instance owns one uplink and all of its tunnels:

```shell
sudo systemctl enable --now etherip-xdp@eth1
```

The tunnel interface `peer` now exists on the host. Address it like any L2
interface:

```shell
sudo ip addr add 192.0.2.1/24 dev peer
sudo ip link set peer up
```

To inspect tunnels with `etheripctl` (next step), also enable the management
socket and the host-wide manager once:

```shell
sudo systemctl enable --now etherip-xdp-varlink@eth1.socket
sudo systemctl enable --now etherip-xdp-manager.socket
```

### 4. Check it

```shell
sudo etheripctl                  # every interface and its tunnels
sudo etheripctl show peer        # full detail for one tunnel
```

```
interface eth1 (ifindex 3, mac 02:00:00:00:00:01, mtu 1500)
  TUNNEL         STATE        REMOTE                     SOURCE                     NEXT-HOP
  peer           up           2001:db8::2                2001:db8::1                fe80::1 mac aa:bb:cc:dd:ee:ff [reachable]
  counters: encap_redirect=9 decap_redirect=7
```

A tunnel reports `up` once both its outer source and the peer's next-hop MAC are
resolved; `pending` (no source yet) and `no-next-hop` (source but no neighbour)
tell you exactly what is missing while it self-heals.

### 5. Change config and reload

Edit, add, or remove files under `interfaces.d/eth1/`, then:

```shell
sudo systemctl reload etherip-xdp@eth1
```

The reload is graceful: the new config set is diffed against what is running and
only the difference is applied. Tunnels you did not touch keep forwarding without
interruption. (Editing files alone does nothing until you reload.)

## Configuration reference

One JSON file per tunnel under `/etc/etherip-xdp/interfaces.d/<uplink>/`:

| Field    | Required | Description |
|----------|----------|-------------|
| `remote` | yes      | Remote outer IPv6 endpoint. |
| `name`   | no       | Tunnel / interface name (default: file stem). Max 11 chars. |
| `local`  | no       | Local outer IPv6 source. Omit to auto-select the kernel's preferred source for the route to `remote` (re-evaluated as the underlay changes). |
| `mss`    | no       | `"auto"` (default), `"off"`, an integer (both families), or `{ "ipv4": N, "ipv6": N }`. |
| `mtu`    | no       | Tunnel MTU override (default: uplink MTU − 56). |
| `mac`    | no       | MAC the interface presents: omit to keep the kernel default, `"inherit"` to copy the uplink's MAC, or an explicit `"xx:xx:xx:xx:xx:xx"`. |
| `next_hop_on_link` | no | On-link policy when the route returns no gateway: `"maybe"` (default), `"always"`, or `"never"`. |

The uplink is the directory name, so it is **not** repeated inside the file. See
`packaging/etc/etherip-xdp/interfaces.d/eth1/` for examples.

**Config directories.** The default is `/etc/etherip-xdp/interfaces.d/<uplink>/`.
The systemd unit also searches `/run/etherip-xdp/interfaces.d/<uplink>/` *ahead*
of `/etc`, so a generator or orchestration layer can drop volatile tunnels under
`/run` that override or extend the on-disk config without editing it. When a file
name appears in more than one directory, the higher-precedence one wins (systemd
drop-in semantics). The `--config-root` and `--config-dir` flags point the daemon
elsewhere; run `etherip-xdp --help` for details.

## etheripctl

`etheripctl` queries the running daemons through the host-wide manager and prints
live status; it changes nothing.

```shell
etheripctl                  # list every uplink and its tunnels (default)
etheripctl -i eth1          # limit to one uplink
etheripctl show <tunnel>    # full detail for one tunnel (alias: status)
```

It needs the `etherip-xdp-manager.socket` (and each uplink's
`etherip-xdp-varlink@<uplink>.socket`) enabled. Run it as root or as a member of
the `etherip-xdp-sock` group; it tells you precisely which is missing if a
connection fails. The interface is [varlink](https://varlink.org/), so
`varlinkctl call /run/etherip-xdp/co.0w0.etheripxdp.Management.List` works too.

## Reload behaviour

A reload diffs the configs against the running tunnels **by name**:

| Case | Trigger | Action |
|------|---------|--------|
| Added   | A name not currently running | Created fresh. |
| Removed | A running name no longer in the configs | Torn down. |
| Updated | Same name, any field changed | Reconfigured **in place**; the interface is never recreated. |

Because the name is the tunnel's identity, every other field (`local`, `remote`,
`mss`, `mtu`, `mac`, `next_hop_on_link`) updates in place without dropping the
interface. Renaming a tunnel (or its file) is the one exception: it is a remove
plus an add, with a brief interruption. If one tunnel fails to apply, the error
is logged and the rest still proceed.

Reload is only for config-file edits. Tracking the underlay (re-selecting an
auto `local` source and refreshing the next-hop MAC) happens continuously on
its own, independent of reload.

## Run without systemd

```shell
sudo etherip-xdp eth1          # foreground, owns eth1 and its tunnels
```

On SIGHUP it reloads config; on SIGINT/SIGTERM it prints debug counters and
tears down all interfaces and XDP attachments.

## How it works

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

Each tunnel is a veth pair. The user-facing end (`<name>`) carries your L2
traffic; its hidden peer runs the `xdp_encap` program that adds the outer
`IPv6 + EtherIP` headers and redirects the frame to the uplink. A single shared
`xdp_decap` program on the uplink strips the headers off inbound frames and
redirects each to the right tunnel, demultiplexing by the outer IPv6 address
pair. Both directions preserve the inner Ethernet frame byte for byte, which is
what makes `<name>` behave as an ordinary L2 interface.

One process owns one uplink because only one XDP program can attach to an
interface, so tunnels sharing an uplink must share its program; hence the
`etherip-xdp@<uplink>` systemd instance boundary.

See [DESIGN.md](DESIGN.md) for the full design: the hidden namespace,
cross-namespace redirect, next-hop resolution and the on-link policy,
outer-source selection, the reload diff, and the varlink management plane.

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

The eBPF object is compiled and embedded automatically by the build script (via
`aya-build`); no separate clang/libbpf step is required. Tasks are defined in
`mise.toml`; list them with `mise tasks`.

To install the binaries manually instead of via the `.deb`:

```shell
sudo install -Dm0755 target/release/etherip-xdp        /usr/bin/etherip-xdp
sudo install -Dm0755 target/release/etherip-xdp-manager /usr/bin/etherip-xdp-manager
sudo install -Dm0755 target/release/etheripctl         /usr/bin/etheripctl
sudo install -Dm0644 packaging/etherip-xdp@.service    /etc/systemd/system/etherip-xdp@.service
# plus the manager/varlink units under packaging/ for etheripctl; see DESIGN.md
```

## Test

```shell
mise run test       # host unit tests (config, MSS, checksum, flow hash, reload diff)
mise run lint       # clippy (must pass before commit)
mise run test-bpf   # byte-exact data-path tests via BPF_PROG_TEST_RUN (root, kernel >= 5.15)
```

The data path is a shared core, fuzzed on the host and asserted byte-for-byte
equal to the kernel program via `BPF_PROG_TEST_RUN`; end-to-end integration
tests run the real daemon between two peers. See [DESIGN.md](DESIGN.md#testing)
and [`test/README.md`](test/README.md).

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

# etherip-xdp integration tests

End-to-end tests that run the **real** `etherip-xdp` daemon (XDP programs and
all) on two peers, build a tunnel between them, and assert that ICMP and TCP
traffic round-trips through it. Modelled on
[aya](https://github.com/aya-rs/aya)'s `cargo xtask integration-test`, but the
two peers are wired together so no privileged host networking is needed.

There are two runners, both driven by `cargo xtask integration-test`:

| Runner  | Peers                         | Needs            | Use |
|---------|-------------------------------|------------------|-----|
| `local` | two network namespaces        | root (host)      | fast iteration on the host kernel |
| `vm`    | two `qemu-system-x86_64` VMs  | qemu (unprivileged) | matrix over kernels 6.5 / 6.8 / 7.0 |
| `freebsd-interop` | Linux etherip-xdp VM + FreeBSD VM | qemu, ssh (unprivileged) | RFC 3378 interop vs FreeBSD's native `gif` EtherIP |

## What the test does

The scenario binary (`test/integration-test`, `--role server|client`) runs on
each peer and:

1. (VM only) `modprobe veth` — `virtio_net` is built into the generic kernel, so
   only `veth` needs loading for the daemon's veth pairs.
2. brings the uplink up with an outer IPv6 address (`fd00::1` / `fd00::2`);
3. writes a one-tunnel config and launches the real `etherip-xdp` daemon on the
   uplink, pointing at the peer;
4. waits for the daemon's user-facing tunnel interface and gives it an inner
   IPv4 address (`10.0.0.1` / `10.0.0.2`);
5. drives traffic through the tunnel — ICMP echo plus a TCP echo exchange — and
   asserts it round-trips.

A successful run exercises the whole live data path (multi-program load, native
→ SKB XDP attach, DEVMAP redirect, encap/decap over a real wire) that the
`BPF_PROG_TEST_RUN` data-path tests in `etherip-xdp/tests/data_path.rs` cannot.

## Running

```sh
# Host, two netns (root):
mise run integration-local
# or: sudo -E env "PATH=$PATH" "$(command -v cargo)" xtask integration-test local

# VMs (downloads kernels into tmp/integration/kernels first):
mise run integration-vm
# or, against your own debs:
cargo xtask integration-test vm path/to/linux-image-*.deb path/to/linux-modules-*.deb
```

Prerequisites for `vm`: `qemu-system-x86_64` (≥ 7.2, for `-netdev stream`),
`bpf-linker`, a nightly toolchain with `rust-src`, and the
`x86_64-unknown-linux-musl` target. Kernels come from the
[Ubuntu mainline PPA](https://kernel.ubuntu.com/~kernel-ppa/mainline/) via
`.github/scripts/download_kernel_images.sh`.

## How `vm` is wired

The two guests are joined by a QEMU `-netdev stream` UNIX socket — a
point-to-point L2 link that needs no tap/bridge/root on the host. `xtask` starts
the listener first, waits for its socket, then starts the connector (with a
version-gated `reconnect`/`reconnect-ms` as a backstop). Each guest's
`virtio-net` NIC is configured with guest offloads off (`guest_csum=off`, …) —
mandatory, or XDP_REDIRECT corrupts frames. Each guest boots a tiny initramfs
(`test-distro` `init` as PID 1) that runs the scenario and prints
`init: success` / `init: failure`, which `xtask` reads from the serial console.

## FreeBSD interop (`freebsd-interop`)

Proves etherip-xdp speaks RFC 3378 EtherIP on the wire by interoperating with an
**independent** implementation: FreeBSD's native `if_gif`. One peer is the Linux
etherip-xdp VM (the existing initramfs, run as a `--tcp connect` client at
`fd00::1` / inner `10.0.0.1`); the other is a FreeBSD VM whose `gif` EtherIP
tunnel is bridged to an inner responder at `fd00::2` / `10.0.0.2`. They share the
same `-netdev stream` L2 link. The Linux side pings and TCP-connects across the
tunnel and is the verdict source (`init: success`).

The FreeBSD VM is the [cross-platform-actions](https://github.com/cross-platform-actions/action)
builder image (`freebsd-15.0-x86-64.qcow2`), booted by our own xtask (not the
GitHub Action), so it runs locally and in CI alike. xtask drives it over SSH on a
user-net hostfwd port — password auth with the image's empty `runner` password,
supplied via `SSH_ASKPASS` (no `sshpass` dependency). The gif setup, pushed over
SSH, has two non-obvious requirements (both learned the hard way and commented in
`xtask/src/freebsd.rs`):

- `ifconfig gif0 **inet6** tunnel fd00::2 fd00::1` — a bare `tunnel` uses the IPv4
  ioctl and rejects IPv6 endpoints with "Invalid argument".
- `gif0` must be a **bridge member before** its tunnel is set, so FreeBSD
  registers the EtherIP (proto 97) receive demux rather than IP-in-IP (otherwise
  inbound proto-97 is answered with "ICMP6 parameter problem, unrecognized next
  header").

## Crates

- `test-distro/` — `init` (PID 1), plus minimal `modprobe` (dependency-aware,
  zstd-capable) and `depmod`. Ported from aya.
- `test/integration-test/` — the `--role`-based scenario binary (`etherip-xdp-e2e`).
- `xtask/` — the orchestrator: builds the binaries, extracts kernels, packs the
  initramfs, and runs the two peers.

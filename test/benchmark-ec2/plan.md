# benchmark-ec2 — etherip-xdp benchmark & test environment

A jsonnet-composed CloudFormation template that stands up a 3-instance AWS
environment to benchmark and functionally test etherip-xdp end-to-end: a traffic
**generator** drives packets through two **DUT** instances joined by an
etherip-xdp tunnel and back to itself, so the only variable on the hot path is
the DUT encap/decap.

```
generator ──[a]──► dut-1 ══encap══► [b] ──► VPC router ──► [c] ══decap══► dut-2 ──[d]──► generator
          on-link          (und-b GUA)                  (und-c GUA)              on-link
```

The etherip **underlay endpoints sit on different subnets** (dut-1 on subnet b,
dut-2 on subnet c), so the outer tunnel packets are routed by the VPC router
rather than delivered on-link. This deliberately exercises etherip-xdp's L3
next-hop (gateway) resolution — the majority use case — instead of a trivial
same-subnet path.

All overlay/management addressing is IPv6-first; full IPv4 parity is built
alongside it. The underlay (VPC) has **no public IPv4** — instances get public
IPv6 (via the internet gateway) plus private IPv4. apt and the etherip-xdp `.deb`
are fetched over IPv6 (`ap-northeast-1.ec2.archive.ubuntu.com` publishes AAAA;
the deb URL must be IPv6-reachable).

---

## 1. Conventions & addressing

### Instance / subnet numbering

- **Instances**: generator = 0, dut-1 = 1, dut-2 = 2.
- **Subnets**: a = 0, b = 1, c = 2, d = 3 (four subnets, **all in one AZ** — one
  `availability_zone` constant — so cross-AZ latency/cost stays out of the
  measurement).

| instance    | ENIs (subnet @ device-index)  | role                          |
|-------------|-------------------------------|-------------------------------|
| `generator` | a@0, d@1                      | trafgen source + sink         |
| `dut-1`     | a@0, b@1 *(uplink)*           | etherip-xdp, `@und-b`         |
| `dut-2`     | d@0, c@1 *(uplink)*           | etherip-xdp, `@und-c`         |

Subnet membership: **a** = {generator, dut-1}, **b** = {dut-1}, **c** = {dut-2},
**d** = {dut-2, generator}. Subnets b and c each hold a single DUT uplink; the
tunnel underlay crosses the VPC router between them.

### Overlay loopback addresses (on `lo`)

Keyed by instance × subnet number:
- IPv6: `fd00:ffff::<instance>:<subnet>` (both nibbles; all inside `fd00:ffff::/64`)
- IPv4: `10.<instance>.<subnet>.1/32`

| host       | subnet | IPv6 (/128)        | IPv4 (/32)  |
|------------|--------|--------------------|-------------|
| generator  | a (0)  | `fd00:ffff::0:0`   | `10.0.0.1`  |
| generator  | d (3)  | `fd00:ffff::0:3`   | `10.0.3.1`  |
| dut-1      | a (0)  | `fd00:ffff::1:0`   | `10.1.0.1`  |
| dut-1      | b (1)  | `fd00:ffff::1:1`   | `10.1.1.1`  |
| dut-2      | c (2)  | `fd00:ffff::2:2`   | `10.2.2.1`  |
| dut-2      | d (3)  | `fd00:ffff::2:3`   | `10.2.3.1`  |

The **benchmark flow** is generator@a (`fd00:ffff::0:0`) → generator@d
(`fd00:ffff::0:3`); the remaining loopbacks give every node a reachable address
on each of its subnets for connectivity verification across both the VPC fabric
and the tunnel.

### Underlay (ENI) addresses

Each ENI is an explicit `AWS::EC2::NetworkInterface` with `Ipv6AddressCount: 1`
(AWS-assigned GUA from the subnet's Amazon-provided `/64`) and a DHCP private
IPv4. `SourceDestCheck: false` on every ENI (see §5).

The **etherip tunnel underlay endpoints are the uplink ENI GUAs** — dut-1's
subnet-b ENI and dut-2's subnet-c ENI — *not* any `fd00:ffff::` loopback. Because
the two live on different subnets, the route between them resolves to the VPC
router as gateway (the L3 next-hop case). The peer's uplink GUA is injected into
each DUT's user-data via `Fn::Sub` + `Fn::GetAtt <Eni>.PrimaryIpv6Address`
(verified attribute), so no runtime EC2 API / IAM is required.

### etherip tunnel (inner link)

The user-facing veth created by etherip-xdp is named `etherip` on both DUTs and
forms one L2 segment across the tunnel. Static link-local next-hops:

| host  | etherip IPv6   | etherip IPv4 (link)   |
|-------|----------------|-----------------------|
| dut-1 | `fe80::1/64`   | `169.254.0.1/30`      |
| dut-2 | `fe80::2/64`   | `169.254.0.2/30`      |

Tunnel MTU = uplink 1500 − 56 = **1444** (auto). Inner benchmark frames must be
≤ 1444 bytes or they won't fit post-encap on the 1500-byte underlay.

---

## 2. Constants & inputs

`constants.libsonnet` holds defaults and merges a git-ignored
`inputs.libsonnet` over them (`constants + inputs`). Ship an
`inputs.example.libsonnet` documenting the required keys.

| key                 | default                  | notes                                            |
|---------------------|--------------------------|--------------------------------------------------|
| `availability_zone` | `ap-northeast-1a`        | single AZ for all subnets; region derived from it |
| `key_name`          | *(required input)*       | existing EC2 keypair name for SSH                 |
| `ami`               | `ami-0126975fb247bf2e7`  | Ubuntu 26.04, x86_64, hvm:ebs-ssd-gp3            |
| `deb_url`           | *(required input)*       | IPv6-reachable URL to the etherip-xdp `.deb`     |
| `instance_type`     | `c8i.xlarge`             | applies to all three instances                   |
| `vpc_cidr`          | `192.168.36.0/22`        | aligned /22 covering the four /24s below          |
| `subnet_cidr_a`     | `192.168.36.0/24`        | subnet 0                                          |
| `subnet_cidr_b`     | `192.168.37.0/24`        | subnet 1                                          |
| `subnet_cidr_c`     | `192.168.38.0/24`        | subnet 2                                          |
| `subnet_cidr_d`     | `192.168.39.0/24`        | subnet 3                                          |
| `ssh_ingress_v6`    | `::/0`                   | management ingress is IPv6-only                  |
| `trafgen_package`   | `netsniff-ng`            | provides `trafgen`                               |

Region = `std.substr(az, 0, std.length(az) - 1)`.

---

## 3. File layout (`test/benchmark-ec2/`)

```
plan.md                    # this document
constants.libsonnet        # defaults + merge of inputs.libsonnet
inputs.example.libsonnet   # documented template for the git-ignored inputs
inputs.libsonnet           # (git-ignored) real values: key_name, deb_url, ...
template.jsonnet           # entrypoint; emits the CloudFormation JSON
lib/
  network.libsonnet        # VPC/subnet/route/ENI/SG resource builders + addr tables
  userdata.libsonnet       # per-role cloud-config builder (networkd, sysctl, etherip)
.gitignore                 # inputs.libsonnet, template.json
README.md                  # build + deploy + run-benchmark commands
```

Build/deploy:

```sh
jsonnet template.jsonnet > template.json
aws cloudformation deploy --template-file template.json \
  --stack-name etherip-xdp-bench --region ap-northeast-1
```

User-data is composed as a jsonnet object and rendered with
`std.manifestJsonEx` (JSON is valid cloud-config YAML), prefixed with
`#cloud-config\n`, then wrapped as `{ "Fn::Base64": { "Fn::Sub": <text> } }` so
`${<Eni>.PrimaryIpv6Address}` GetAtt placeholders resolve at deploy time. All
bash in the scripts is written brace-free (`$VAR`, `$(...)`, `$((...))`), so the
**only** `${...}` tokens are those intended GetAtt refs — nothing needs `${!...}`
escaping.

---

## 4. CloudFormation resources

- **VPC** `192.168.36.0/22`, plus `AWS::EC2::VPCCidrBlock` with
  `AmazonProvidedIpv6CidrBlock: true`.
- **4 subnets** a/b/c/d in the one AZ. Each: an IPv4 `/24` and an IPv6 `/64`
  carved from the VPC's Amazon `/56` (`Fn::Select` + `Fn::Cidr`).
  `AssignIpv6AddressOnCreation: true`, `MapPublicIpOnLaunch: false`.
- **Internet gateway** + attachment. (IGW, not egress-only: inbound IPv6 SSH
  needs it.)
- **One route table**, associated to all four subnets:
  - `::/0` → IGW (public IPv6 in/out)
  - overlay `/128` + `/32` host routes → owning ENI (table in §6a)
  - *no* `0.0.0.0/0` — private IPv4 is intra-VPC only (implicit local route).
  - *No special route for the tunnel underlay* — dut-1@b ↔ dut-2@c is native
    inter-subnet VPC routing; that's the point.
- **Security group**: ingress ICMPv6 (all) + TCP/22 from `ssh_ingress_v6`
  (`::/0`); ingress all-from-self; egress allow-all. On all six ENIs.
- **6 × `AWS::EC2::NetworkInterface`** — `GenEniA`, `GenEniD`, `Dut1EniA`,
  `Dut1EniB`, `Dut2EniC`, `Dut2EniD`: `Ipv6AddressCount: 1`,
  `SourceDestCheck: false`, matching subnet + SG, tagged `role`/`subnet`.
- **3 × `AWS::EC2::Instance`** — `instance_type`, `ami`, `key_name`, ENIs
  attached at the fixed `DeviceIndex` from §1, role-specific user-data.

No IAM role/instance profile (underlay discovery is via `GetAtt`).

---

## 5. Why source/dest check is off

- The DUTs **forward** packets whose dst is another node's loopback (not the
  DUT ENI's own address); VPC drops these unless `SourceDestCheck=false`.
- A VPC `/128` route pointing e.g. `fd00:ffff::0:3/128` at `GenEniD` **delivers
  to an ENI an address it doesn't own** — only works with the check disabled.
  The generator also emits frames sourced from a loopback (`fd00:ffff::0:0`),
  not its ENI address.

(The *outer* tunnel packets use the uplink ENIs' own GUAs as src/dst, so they
would pass the check on their own; it's the overlay forwarding/delivery that
requires it. Disable it on all ENIs for simplicity.)

Host sysctls (via `sysctl.d`): `net.ipv6.conf.all.forwarding=1`,
`net.ipv4.ip_forward=1` (DUTs); `net.ipv4.conf.all.rp_filter=0` (asymmetric
paths); `accept_ra=2` on underlay ifaces (forwarding hosts still need the
RA-learned VPC-router default route — see §7).

---

## 6. Routing tables

### 6a. VPC route table (host routes → ENI)

| destination (v6 / v4)                  | target ENI |
|----------------------------------------|------------|
| `fd00:ffff::0:0/128` / `10.0.0.1/32`   | `GenEniA`  |
| `fd00:ffff::0:3/128` / `10.0.3.1/32`   | `GenEniD`  |
| `fd00:ffff::1:0/128` / `10.1.0.1/32`   | `Dut1EniA` |
| `fd00:ffff::1:1/128` / `10.1.1.1/32`   | `Dut1EniB` |
| `fd00:ffff::2:2/128` / `10.2.2.1/32`   | `Dut2EniC` |
| `fd00:ffff::2:3/128` / `10.2.3.1/32`   | `Dut2EniD` |

### 6b. Per-instance kernel routes

Only the **`via etherip`** routes are materialized host-side — they must override
the default route to force tunnel traversal, and they are static (known at
template time), so they live in `20-etherip.network` (DUTs only).

The **`via VPC@x`** rows are *not* configured as explicit host routes: such a
destination is reached via the node's default route → the VPC router → the VPC
route table's `/128`·`/32` entry → the owning ENI (source/dest check is off).
So the rows below marked "via VPC@x" are descriptive of the resulting path, not
routes we install.

**generator** (own loopbacks `::0:0`,`::0:3`,`10.0.0.1`,`10.0.3.1` on `lo`):

| dest                              | next hop  |
|-----------------------------------|-----------|
| `fd00:ffff::1:0` / `10.1.0.1`     | via VPC@a |
| `fd00:ffff::1:1` / `10.1.1.1`     | via VPC@a |
| `fd00:ffff::2:2` / `10.2.2.1`     | via VPC@d |
| `fd00:ffff::2:3` / `10.2.3.1`     | via VPC@d |

**dut-1** (own loopbacks `::1:0`,`::1:1`,`10.1.0.1`,`10.1.1.1`; uplink b):

| dest                              | next hop                                  |
|-----------------------------------|-------------------------------------------|
| `fd00:ffff::0:0` / `10.0.0.1`     | via VPC@a                                  |
| `fd00:ffff::0:3` / `10.0.3.1`     | via `fe80::2` / `169.254.0.2` dev etherip |
| `fd00:ffff::2:2` / `10.2.2.1`     | via etherip                               |
| `fd00:ffff::2:3` / `10.2.3.1`     | via etherip                               |

**dut-2** (own loopbacks `::2:2`,`::2:3`,`10.2.2.1`,`10.2.3.1`; uplink c):

| dest                              | next hop                                  |
|-----------------------------------|-------------------------------------------|
| `fd00:ffff::0:0` / `10.0.0.1`     | via `fe80::1` / `169.254.0.1` dev etherip |
| `fd00:ffff::0:3` / `10.0.3.1`     | via VPC@d                                  |
| `fd00:ffff::1:0` / `10.1.0.1`     | via etherip                               |
| `fd00:ffff::1:1` / `10.1.1.1`     | via etherip                               |

### 6c. Tunnel underlay (the L3 next-hop case)

dut-1 etherip: `local = Dut1BEni GUA` (subnet b), `remote = Dut2CEni GUA`
(subnet c). dut-2 is the mirror. The route from dut-1 to dut-2's subnet-c GUA is
**not on-link** (different subnet), so it resolves to the VPC-router gateway on
subnet b — exactly the next-hop MAC resolution etherip-xdp re-tracks on netlink
changes. `--next-hop-on-link` stays default `maybe` (the route lookup returns a
gateway, which always wins).

Both ENIs carry an RA default route, so a plain route lookup to the peer could
egress the wrong subnet. No host route is pinned to compensate: etherip-xdp's
resolver constrains its lookup to the uplink (`oif`), since encap always egresses
there, so it always selects the uplink's gateway regardless of default-route
metrics.

### Path validation (benchmark flow)

src `fd00:ffff::0:0`, dst `fd00:ffff::0:3`: generator emits on und-a (L2 → dut-1
und-a MAC) → dut-1 routes dst `::0:3` **via etherip** → encap, outer dst =
Dut2CEni GUA → **VPC router (subnet b → c)** → dut-2 ENI-c → decap → dut-2 routes
`::0:3` **via VPC@d** → `/128` route → `GenEniD` → generator sink. ✓

---

## 7. Per-instance setup (cloud-init user-data)

`network: {config: disabled}` hands networking to systemd-networkd. Nearly
everything is **precomputed and shipped via `write_files`** (no runtime
generation); a slim `runcmd` script handles only the genuinely runtime bits.

**Static `write_files`:**

- `10-underlay.network` — one file, `[Match] Driver=ena`: `MTUBytes=1500`,
  `DHCP=yes` (DHCPv4 lease + DHCPv6 for the ENI's assigned GUA), `IPv6AcceptRA=yes`
  (RA supplies the VPC-router default route), `IPv4Forwarding=yes`,
  `IPv6Forwarding=yes`.
- `15-loopback.network` — `[Match] Name=lo`: `127.0.0.1/8`, `::1/128`, plus this
  role's overlay loopbacks (§1).
- `20-etherip.network` (DUTs) — `[Match] Name=etherip`: `fe80::{1,2}/64` +
  `169.254.0.{1,2}/30`, forwarding on, and the `via etherip` routes from §6b.
  networkd applies it whenever the daemon creates the veth.
- `etherip-xdp@.service.d/10-config-dir.conf` (DUTs) — drop-in pinning
  `--config-dir /etc/etherip-xdp/tunnel.d`, so the config path doesn't depend on
  the (AWS-assigned) interface name.
- `/etc/etherip-xdp/tunnel.d/etherip.json` (DUTs) — **pre-created**; both endpoint
  GUAs are known at deploy time, injected by `Fn::Sub`:
  ```json
  { "name": "etherip", "local": "${<own uplink Eni>.PrimaryIpv6Address}", "remote": "${<peer uplink Eni>.PrimaryIpv6Address}", "mss": "auto" }
  ```
  `local` is set explicitly to the uplink GUA for a deterministic outer source
  (egress is already pinned by the resolver's `oif`, see §6c; `local` could also
  be omitted to auto-select).
- `99-etherip-bench.conf` (sysctl, §5): **`net.ipv6.conf.all.forwarding=1`** and
  `net.ipv4.ip_forward=1` are required even with the per-interface
  `IPv6Forwarding=`/`IPv4Forwarding=` above; plus `rp_filter=0` (the generator
  receives return packets sourced from its own `und-a` loopback on `und-d`, which
  strict RPF would drop).

**Provisioning runs as a systemd oneshot unit** (`etherip-bench-setup.service`,
also a `write_files`), not a cloud-init `runcmd` — so it is ordered
`After=systemd-networkd.service ... cloud-init.target` (waits for cloud-init to
finish writing files and to settle its per-boot run), `Restart=on-failure`
(retries transient apt / not-yet-assigned GUA), logs to the journal, and is
idempotent across reboots. cloud-init's only `runcmd` is `daemon-reload`,
`enable`, then `start --no-block` of it — `--no-block` because a blocking start
from cloud-final would deadlock against `After=cloud-init.target`.

The unit's script handles the one non-precomputable bit — which kernel interface
carries the uplink ENI (AWS assigns the `enX`/`ens` names). No IMDS: the GUA is
known, so the interface is found by it.

1. ensure `systemd-networkd`/`systemd-resolved` up, `networkctl reload`, sysctls.
2. (DUTs) find the uplink iface by its known GUA
   (`ip -6 addr show to <gua>/128`; non-zero exit → unit retries until DHCPv6
   assigns it), install the `.deb` if absent, then
   `systemctl enable --now etherip-xdp@<uplink-if>`. The generator just installs
   `trafgen_package`.

> Note on "static routes": AWS provides the IPv6 default gateway only via RA, so
> underlay ifaces keep `IPv6AcceptRA` on to learn the VPC-router link-local;
> addresses and tunnel routes are static. This is the one deviation from "fully
> static".

---

## 8. Benchmark tooling

`trafgen` (from `netsniff-ng`) on the generator blasts crafted frames out its
subnet-a interface. The frame is delivered on-link to dut-1 (same subnet a), so
it carries dut-1's subnet-a ENI MAC at L2; that MAC isn't known at template time,
so `etherip-bench` resolves it at run time.

`etherip-bench` (installed on the generator) — all GUAs baked in via `Fn::Sub`,
no IMDS:
1. find the und-a / und-d interfaces by their known GUAs
   (`ip -6 addr show to <gua>/128`).
2. `ping6 <dut-1 und-a GUA>` then `ip -6 neigh get` → dut-1's MAC.
3. Render a trafgen config: L2 src = generator und-a MAC, dst = resolved dut-1
   MAC; L3 src `fd00:ffff::0:0`, dst `fd00:ffff::0:3`; UDP; payload sized ≤ 1444
   (configurable for a pps vs. throughput sweep), and run it for a fixed duration.

Measurement: RX on the generator's und-d sink (`/sys/class/net/<if>/statistics`)
and the DUT etherip-xdp debug counters (`encap_*` / `decap_*`, dumped on SIGTERM,
or `RUST_LOG=debug`). The reverse direction (generator@d → dut-2 → tunnel → dut-1
→ generator@a) is symmetric for bidirectional load.

---

## 9. Open items / assumptions

- **AMI** `ami-0126975fb247bf2e7` assumed Ubuntu 26.04 x86_64 in
  `ap-northeast-1`; verify before deploy.
- **`deb_url`** to be provided (IPv6-reachable); DUTs need the deb,
  generator needs only `netsniff-ng`.
- etherip-xdp outer endpoints are **IPv6-only** (config rejects v4), so IPv4
  parity is inner/overlay only — the tunnel transport stays IPv6.
- trafgen exact packet templates (header layout, ports, size sweep) finalized
  during implementation.

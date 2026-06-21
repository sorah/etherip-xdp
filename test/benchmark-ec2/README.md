# benchmark-ec2

A jsonnet-composed CloudFormation template that stands up an AWS environment to
benchmark and functionally test etherip-xdp end-to-end. See [`plan.md`](plan.md)
for the full topology, addressing and rationale.

```
generator ─[a]─► dut-1 ══encap══► [b] ─► VPC router ─► [c] ══decap══► dut-2 ─[d]─► generator
```

The two DUT uplinks sit on **different subnets** (b and c), so the etherip outer
packets are routed by the VPC router — exercising etherip-xdp's L3 next-hop
resolution rather than a trivial on-link path.

## Prerequisites

- `jsonnet`, `aws` CLI.
- An existing EC2 key pair, and an **IPv6-reachable** URL to the etherip-xdp
  `.deb` (the underlay has no public IPv4).

## Configure

Copy the inputs template and fill in real values (git-ignored):

```sh
cp inputs.example.libsonnet inputs.libsonnet
$EDITOR inputs.libsonnet   # set key_name and deb_url (others default)
```

## Build & deploy

Build the template (jsonnet → CloudFormation JSON), then create/update the stack:

```sh
jsonnet template.jsonnet > template.json
aws cloudformation deploy \
  --template-file template.json \
  --stack-name etherip-xdp-bench \
  --region ap-northeast-1 \
  --tags Owner=sorah Project=etherip-bench   # stack tags
```

Stack-level `--tags` are **propagated automatically by CloudFormation** to every
resource that supports tagging (instances, ENIs, volumes, VPC, subnets, …) — no
need to add them in the template. `deploy` does create-or-update; for an explicit
first creation you can use `aws cloudformation create-stack --template-body
file://template.json --tags Key=Owner,Value=sorah ...` instead.

Each instance configures itself from user-data (cloud-init): systemd-networkd
takes over from netplan using static config files (addresses, loopbacks, tunnel
routes, and the pre-created `etherip.json` are all baked in at deploy time via
`Fn::Sub`). A oneshot unit `etherip-bench-setup.service` then finds the uplink
interface by its known GUA, installs the `.deb`, and starts `etherip-xdp@<uplink>`
(it retries on failure and re-runs idempotently on reboot). Inspect progress with
`journalctl -u etherip-bench-setup`.

## Run the benchmark

The stack outputs each instance's SSH IPv6 address (`GeneratorIpv6`, `Dut1Ipv6`,
`Dut2Ipv6`):

```sh
aws cloudformation describe-stacks --stack-name etherip-xdp-bench \
  --region ap-northeast-1 --query 'Stacks[0].Outputs' --output table
ssh ubuntu@<GeneratorIpv6>
```

SSH (over IPv6) to the generator and run:

```sh
sudo etherip-bench [payload_bytes=1000] [duration_s=20]
```

`payload_bytes` is the UDP payload (default 1000); the inner IPv6+UDP packet is
`payload + 48`, which must stay within the **1444** tunnel MTU, so the **max is
1396**. Larger values are rejected (they would be dropped as ICMPv6 Packet Too
Big before encap, looping back ~nothing).

It resolves dut-1's on-link MAC, blasts trafgen from `fd00:ffff::0:0` →
`fd00:ffff::0:3` (which loops through both DUTs and the tunnel), and reports the
RX delta on the `und-d` sink. Inspect the DUT counters with
`journalctl -u etherip-xdp@<uplink>` (dumped on stop) or `RUST_LOG=debug`.

## Layout

| file | purpose |
|------|---------|
| `constants.libsonnet` | defaults, merged with git-ignored `inputs.libsonnet` |
| `inputs.example.libsonnet` | template for `inputs.libsonnet` |
| `template.jsonnet` | entrypoint; emits the CloudFormation JSON |
| `lib/network.libsonnet` | topology + VPC/subnet/route/ENI/SG resources |
| `lib/userdata.libsonnet` | per-node cloud-config (networkd, routes, tunnel) |

## Recovering a box (lost SSH)

Ingress is IPv6-only, so if you break networking you can't SSH in. Set
`root_password` in `inputs.libsonnet` (re-deploy) and use the **EC2 Serial
Console** (Nitro): enable it once per account/region
(`aws ec2 enable-serial-console-access`), then connect from the console or
`aws ec2-instance-connect send-serial-console-ssh-public-key` / the web console
and log in as `root`. The password is plaintext in user-data — use a throwaway.

## Teardown

```sh
aws cloudformation delete-stack --stack-name etherip-xdp-bench --region ap-northeast-1
```

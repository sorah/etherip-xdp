// Per-node cloud-config (user-data) builder.
//
// Everything that can be precomputed is shipped via write_files, including the
// etherip-xdp tunnel config itself: both endpoint GUAs are known at deploy time
// (Fn::GetAtt <eni>.PrimaryIpv6Address), so etherip.json is a static file with
// the GUAs injected by Fn::Sub. The unit's config dir is fixed via a drop-in, so
// neither the file path nor its content depends on the (AWS-assigned) interface
// name.
//
// No IMDS: the only runtime unknown is which kernel interface carries a given
// ENI. We find it by its *known* GUA (`ip -6 addr show to <gua>/128`) — so there
// is no token dance, no link-local bootstrap, no subnet→interface mapping.
//
// The whole user-data is wrapped in Fn::Sub (see template.jsonnet). To keep that
// safe, every bash variable is written WITHOUT braces ($VAR, $(...), $((...))),
// so the only `${...}` tokens are the intended GetAtt placeholders — nothing to
// escape.
local c = import '../constants.libsonnet';
local net = import 'network.libsonnet';

local guaRef(eni) = '${' + eni + '.PrimaryIpv6Address}';

// MTU 1500 is mandatory on the DUT uplink: the ENA driver refuses native XDP
// when MTU > 3498, and without native XDP the encap REDIRECT cannot xdp_xmit.
// AWS DHCP/RA advertise MTU 9001, so UseMTU=no is required for MTUBytes to stick.
// This file must sort before netplan's /run/systemd/network/10-netplan-*.network
// (cloud-init's `network: {config: disabled}` can't prevent the first-boot
// render), since networkd applies the first matching .network per link — hence
// the `05-` prefix so this `Driver=ena` match wins over netplan's per-NIC files.
local underlayBody = |||
  [Link]
  MTUBytes=1500

  [Network]
  DHCP=yes
  IPv6AcceptRA=yes
  IPv4Forwarding=yes
  IPv6Forwarding=yes

  [DHCPv4]
  UseMTU=no

  [IPv6AcceptRA]
  UseMTU=no
|||;
// Shared base for all ENAs. Per-link files (eniNetworks) reuse the
// same body in a Name-matched, earlier-sorting file so they win for that link.
local underlayNetwork = '[Match]\nDriver=ena\n\n' + underlayBody;

local loopbackHeader = |||
  [Match]
  Name=lo

  [Network]
  Address=127.0.0.1/8
  Address=::1/128
|||;
local loopbackAddr = |||
  Address=%s/128
  Address=%s/32
|||;
local loopbackNetwork(key) =
  loopbackHeader + std.join('', [loopbackAddr % [lb.v6, lb.v4] for lb in net.loopbacksOf(key)]);

local etheripHeader = |||
  [Match]
  Name=etherip

  [Network]
  LinkLocalAddressing=no
  IPv6AcceptRA=no
  IPv4Forwarding=yes
  IPv6Forwarding=yes
  Address=%s
  Address=%s
|||;
local etheripRoute = |||
  [Route]
  Destination=%s/128
  Gateway=%s

  [Route]
  Destination=%s/32
  Gateway=%s
|||;
local etheripNetwork(inst) =
  etheripHeader % [inst.etherip.selfV6, inst.etherip.selfV4]
  + std.join('', [
    '\n' + etheripRoute % [net.v6(r.di, r.ds), inst.etherip.peerV6, net.v4(r.di, r.ds), inst.etherip.peerV4]
    for r in inst.routes
    if r.via == 'etherip'
  ]);

local sysctlConf = |||
  net.ipv6.conf.all.forwarding=1
  net.ipv4.ip_forward=1
  net.ipv4.conf.all.rp_filter=0
  net.ipv4.conf.default.rp_filter=0
|||;

// Read tunnels from a fixed, verbatim --config-dir instead of the default
// /etc/etherip-xdp/interfaces.d/<device>/ layout, so etherip.json can be a
// static, pre-created file regardless of the uplink interface name (which
// becomes the `%i` device arg, only known at boot).
// CAP_PERFMON is required for the data-path verifier on newer kernels (also set
// in the packaging unit; harmless if the installed deb already has it).
local etheripDropin = |||
  [Service]
  ExecStart=
  ExecStart=/usr/bin/etherip-xdp --config-dir /etc/etherip-xdp/tunnels %i
  AmbientCapabilities=CAP_PERFMON
  CapabilityBoundingSet=CAP_PERFMON
|||;

// systemd-networkd's default MACAddressPolicy=persistent rewrites the etherip
// veth's MAC *after* etherip-xdp captures it for the decap dst-MAC rewrite, so
// decapped frames get an address the veth no longer owns and the kernel drops
// them. Keep the kernel-assigned MAC so the daemon's captured value stays valid.
local etheripLink = |||
  [Match]
  OriginalName=etherip

  [Link]
  MACAddressPolicy=none
|||;

// `local` is omitted (auto-source): the daemon's resolver passes a configured
// `local` as the route lookup's `from`, and `ip route get <peer> from <local> oif
// <uplink>` ignores `oif` when another ENI's default outranks the uplink's (it now
// does — the uplink's RA default is deprioritised for SSH symmetry above), picking
// that ENI's gateway and leaving the tunnel with no usable next hop. The sourceless
// `oif` lookup honours the uplink and prefsrc yields the same outer source (the
// uplink GUA).
local etheripJson(inst) =
  '{ "name": "etherip", "remote": "%s", "mss": "auto" }\n'
  % [guaRef(inst.peerUplinkEni)];

// Provisioning runs as a oneshot unit (not cloud-init runcmd) so it is ordered
// after networkd, retried on transient failure, logged to the journal, and
// idempotent across reboots.
local setupUnit = |||
  [Unit]
  Description=etherip-xdp benchmark node provisioning
  Wants=systemd-networkd.service systemd-resolved.service
  # Wait for cloud-init to finish (write_files in place; no per-boot races).
  After=systemd-networkd.service systemd-resolved.service cloud-init.target

  [Service]
  Type=oneshot
  RemainAfterExit=yes
  ExecStart=/usr/local/sbin/etherip-bench-setup
  Restart=on-failure
  RestartSec=10

  [Install]
  WantedBy=multi-user.target
|||;

// DUT setup: bring networkd up, find the uplink interface by its known GUA, then
// install the deb and start the tunnel. @@OWN_GUA@@ is an Fn::Sub GetAtt ref.
local dutSetupTmpl = |||
  #!/bin/bash
  set -euo pipefail
  echo "=== etherip-bench-setup $(date -u) ==="
  udevadm control --reload 2>/dev/null || true   # pick up 19-etherip.link
  systemctl enable --now systemd-networkd systemd-resolved
  networkctl reload 2>/dev/null || systemctl restart systemd-networkd
  sysctl --system >/dev/null

  # Locate the uplink interface by its known GUA (DHCPv6-assigned). Doubles as a
  # wait-for-network: exit non-zero so the unit retries until it appears.
  UPLINK_IF=""
  for _ in $(seq 1 60); do
    UPLINK_IF=$(ip -o -6 addr show to @@OWN_GUA@@/128 scope global | awk '{print $2; exit}')
    [ -n "$UPLINK_IF" ] && break
    sleep 2
  done
  [ -n "$UPLINK_IF" ] || { echo "uplink GUA not found yet"; exit 1; }
  echo "uplink interface: $UPLINK_IF"

  # ENA native XDP needs the combined channel count <= half the maximum (it
  # reserves queues for XDP TX). Without native XDP the encap REDIRECT is dropped.
  # Set combined to floor(max/2) regardless of size (e.g. 4->2, 2->1).
  MAXQ=$(ethtool -l "$UPLINK_IF" 2>/dev/null | awk '/^Combined:/{print $2; exit}')
  [ -n "$MAXQ" ] || MAXQ=0
  HALF=$((MAXQ / 2))
  [ "$HALF" -ge 1 ] && ethtool -L "$UPLINK_IF" combined "$HALF" || true

  @@PINS@@
  export DEBIAN_FRONTEND=noninteractive
  if ! dpkg -s etherip-xdp >/dev/null 2>&1; then
    apt-get update
    curl -fsSL -o /tmp/etherip-xdp.deb '@@DEB_URL@@'
    apt-get install -y /tmp/etherip-xdp.deb
  fi
  # postinst seeds the group/dir; the daemon Wants= its control socket.
  systemctl enable --now etherip-xdp@"$UPLINK_IF"
  systemctl enable --now etherip-xdp-manager.socket
  echo "=== etherip-bench-setup done ==="
|||;

local generatorSetupTmpl = |||
  #!/bin/bash
  set -euo pipefail
  echo "=== etherip-bench-setup $(date -u) ==="
  systemctl enable --now systemd-networkd systemd-resolved
  networkctl reload 2>/dev/null || systemctl restart systemd-networkd
  sysctl --system >/dev/null
  for _ in $(seq 1 60); do ip -6 route show default | grep -q . && break; sleep 2; done
  @@PINS@@
  export DEBIAN_FRONTEND=noninteractive
  if ! dpkg -s @@TRAFGEN@@ >/dev/null 2>&1; then
    apt-get update
    apt-get install -y @@TRAFGEN@@
  fi
  echo "=== etherip-bench-setup done ==="
|||;

// Generator bench tool. @@*@@ are Fn::Sub GetAtt refs (interface GUAs).
// Source/dest overlay = fd00:ffff::0:0 -> fd00:ffff::0:3 (generator @a -> @d),
// which dut-1 routes into the tunnel; the loop returns on und-d. The frame is
// emitted as raw bytes because trafgen 0.6.9's high-level ipv6() produces no
// packet. payload defaults to 1000 (inner IP 1048 <= tunnel MTU 1444).
local benchTmpl = |||
  #!/bin/bash
  # Usage: etherip-bench [payload_bytes] [duration_s]
  set -euo pipefail
  SIZE=$1; [ -n "$SIZE" ] || SIZE=1000
  DUR=$2; [ -n "$DUR" ] || DUR=20

  # Inner IPv6+UDP packet is SIZE + 48 (IPv6 40 + UDP 8). The tunnel MTU is
  # 1444 (uplink 1500 - 56 EtherIP overhead), so anything larger is dropped by
  # dut-1 with ICMPv6 Packet Too Big before it ever reaches encap (the run would
  # report ~0 looped back). Fail loudly instead of silently measuring nothing.
  MAXSIZE=1396
  if [ "$SIZE" -gt "$MAXSIZE" ]; then
    echo "payload $SIZE too large: inner packet $((SIZE + 48)) > tunnel MTU 1444; max payload is $MAXSIZE" >&2
    exit 1
  fi

  DEV=$(ip -o -6 addr show to @@GEN_A@@/128 scope global | awk '{print $2; exit}')
  SINK=$(ip -o -6 addr show to @@GEN_D@@/128 scope global | awk '{print $2; exit}')
  DUT1_A=@@DUT1_A@@
  [ -n "$DEV" ] || { echo "und-a interface not found"; exit 1; }
  [ -n "$SINK" ] || { echo "und-d interface not found"; exit 1; }

  SRC_MAC=$(cat /sys/class/net/"$DEV"/address)
  ping6 -c2 -I "$DEV" "$DUT1_A" >/dev/null 2>&1 || true
  DST_MAC=$(ip -6 neigh get "$DUT1_A" dev "$DEV" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}')
  [ -n "$DST_MAC" ] || { echo "could not resolve dut-1 MAC for $DUT1_A on $DEV"; exit 1; }

  macb() { echo "$1" | sed 's/[0-9a-f][0-9a-f]/0x&/g; s/:/, /g'; }
  UDPLEN=$((SIZE + 8))
  CFG=$(mktemp)
  # eth | IPv6 (src fd00:ffff::0:0, dst fd00:ffff::0:3, nexthdr=UDP) | UDP | payload
  cat > "$CFG" <<EOF
  {
    $(macb "$DST_MAC"),
    $(macb "$SRC_MAC"),
    0x86, 0xdd,
    0x60, 0x00, 0x00, 0x00,
    const16($UDPLEN), 17, 64,
    0xfd,0x00,0xff,0xff,0,0,0,0,0,0,0,0,0,0,0,0,
    0xfd,0x00,0xff,0xff,0,0,0,0,0,0,0,0,0,0,0,0x03,
    const16(12345), const16(12345), const16($UDPLEN), const16(0),
    fill(0x42, $SIZE),
  }
  EOF

  echo "trafgen: $DEV -> dut-1($DST_MAC), fd00:ffff::0:0 -> fd00:ffff::0:3, payload $SIZE bytes, $DUR seconds"
  TX0=$(cat /sys/class/net/"$DEV"/statistics/tx_packets)
  RX0=$(cat /sys/class/net/"$SINK"/statistics/rx_packets)
  # Bound the run with timeout and reap stragglers: trafgen forks a worker per CPU
  # and killing the parent does not reliably stop the children.
  timeout "$DUR" trafgen --in "$CFG" --out "$DEV" -t0 >/dev/null 2>&1 || true
  pkill -9 -x trafgen 2>/dev/null || true
  TX1=$(cat /sys/class/net/"$DEV"/statistics/tx_packets)
  RX1=$(cat /sys/class/net/"$SINK"/statistics/rx_packets)
  sent=$((TX1 - TX0)); rx=$((RX1 - RX0))
  echo "sent (und-a tx): $sent; looped back (und-d rx): $rx over $DUR seconds (~$((sent / DUR)) pps tx, ~$((rx / DUR)) pps rx)"
  rm -f "$CFG"
|||;

local raRoutes(dests) = std.join('', [
  '\n[Route]\nDestination=%s/128\nGateway=_ipv6ra\n\n[Route]\nDestination=%s/32\nGateway=_dhcp4\n' % [d.v6, d.v4]
  for d in dests
]);

// Per-ENI networkd config, written at runtime because the interface NAME is
// AWS-assigned (found by the ENI's known GUA). One file per ENI, sorting before
// 05-underlay so it wins. Two jobs:
//
//   1. RA priority: the device-index-1 (secondary/uplink) ENI gets a higher
//      RA/DHCP RouteMetric so the device-0 ENI — the one the SSH GUA and stack
//      outputs use — wins the default route. Otherwise both ENIs install an
//      equal-metric RA default and the kernel's ECMP can egress replies on the
//      wrong ENI, which AWS drops as asymmetric (instance unreachable over SSH).
//      encap is unaffected: the daemon's resolver pins it to the uplink via oif.
//
//   2. Overlay routes: pin each `via: 'subnet:X'` /128 (+/32) to its subnet's ENI
//      via Gateway=_ipv6ra/_dhcp4, so the decapped inner packet's exit rides the
//      right ENI rather than the ECMP default.
local eniNetworks(key) =
  local routes = net.instances[key].routes;
  std.join('', [
    local metric = if e.deviceIndex == 0 then '' else 'RouteMetric=2048\n';
    local dests = [{ v6: net.v6(r.di, r.ds), v4: net.v4(r.di, r.ds) } for r in routes if r.via == 'subnet:' + e.subnet];
    'UND_IF=$(ip -o -6 addr show to %s/128 scope global | awk \'{print $2; exit}\')\n' % guaRef(e.logical)
    + '[ -n "$UND_IF" ] || { echo "subnet-%s ENI not up yet"; exit 1; }\n' % e.subnet
    + 'cat > /etc/systemd/network/04-und-%s.network <<EOFNET\n' % e.subnet
    + '[Match]\nName=$UND_IF\n\n[Link]\nMTUBytes=1500\n\n[Network]\nDHCP=yes\nIPv6AcceptRA=yes\nIPv4Forwarding=yes\nIPv6Forwarding=yes\n\n[DHCPv4]\nUseMTU=no\n'
    + metric
    + '\n[IPv6AcceptRA]\nUseMTU=no\n'
    + metric
    + raRoutes(dests)
    + 'EOFNET\n'
    for e in net.enisOf(key)
  ]) + 'networkctl reload\n';

local dutSetup(key) =
  local inst = net.instances[key];
  std.strReplace(
    std.strReplace(
      std.strReplace(dutSetupTmpl, '@@OWN_GUA@@', guaRef(inst.uplinkEni)),
      '@@DEB_URL@@', c.deb_url
    ),
    '@@PINS@@', eniNetworks(key)
  );

local generatorSetup(key) =
  std.strReplace(
    std.strReplace(generatorSetupTmpl, '@@TRAFGEN@@', c.trafgen_package),
    '@@PINS@@', eniNetworks(key)
  );

local benchScript(inst) =
  std.strReplace(
    std.strReplace(
      std.strReplace(benchTmpl, '@@GEN_A@@', guaRef(inst.benchSrcEni)),
      '@@GEN_D@@', guaRef(inst.benchSinkEni)
    ),
    '@@DUT1_A@@', guaRef(inst.benchTargetEni)
  );

local file(path, content, perm='0644') = { path: path, permissions: perm, content: content };

{
  build(key)::
    local inst = net.instances[key];
    local isDut = inst.uplink != null;
    local common = [
      file('/etc/systemd/network/05-underlay.network', underlayNetwork),
      file('/etc/systemd/network/15-loopback.network', loopbackNetwork(key)),
      file('/etc/sysctl.d/99-etherip-bench.conf', sysctlConf),
      file('/etc/systemd/system/etherip-bench-setup.service', setupUnit),
    ];
    local dutFiles = [
      file('/etc/systemd/network/19-etherip.link', etheripLink),
      file('/etc/systemd/network/20-etherip.network', etheripNetwork(inst)),
      file('/etc/etherip-xdp/tunnels/etherip.json', etheripJson(inst)),
      file('/etc/systemd/system/etherip-xdp@.service.d/10-config-dir.conf', etheripDropin),
      file('/usr/local/sbin/etherip-bench-setup', dutSetup(key), '0755'),
    ];
    local generatorFiles = [
      file('/usr/local/sbin/etherip-bench-setup', generatorSetup(key), '0755'),
      file('/usr/local/bin/etherip-bench', benchScript(inst), '0755'),
    ];
    // Optional root password for EC2 Serial Console recovery if SSH is lost.
    local pwCfg = if c.root_password != null then {
      chpasswd: { expire: false, users: [{ name: 'root', password: c.root_password, type: 'text' }] },
    } else {};
    pwCfg {
      network: { config: 'disabled' },
      write_files: common + (if isDut then dutFiles else generatorFiles),
      // cloud-init only enables the unit; all provisioning logic lives in it.
      // Start with --no-block: the unit is ordered After=cloud-init.target, so a
      // blocking start from cloud-final's runcmd would deadlock (cloud-final waits
      // on the start job, which waits on cloud-init.target, which waits on
      // cloud-final). --no-block enqueues it to run once cloud-init.target is up.
      runcmd: [
        ['systemctl', 'daemon-reload'],
        ['systemctl', 'enable', 'etherip-bench-setup.service'],
        ['systemctl', 'start', '--no-block', 'etherip-bench-setup.service'],
      ],
    },
}

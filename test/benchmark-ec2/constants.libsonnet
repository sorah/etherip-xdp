// Default constants for the etherip-xdp benchmark environment.
//
// Real per-deployment values (at minimum `key_name` and `deb_url`) live in the
// git-ignored `inputs.libsonnet`, which is merged on top of these defaults. See
// `inputs.example.libsonnet`.

// jsonnet has no "optional import", so inputs.libsonnet must exist — copy it
// from inputs.example.libsonnet. It may be `{}` to accept every default that
// has one, but key_name/deb_url have no default.
local overrides = import 'inputs.libsonnet';

local defaults = {
  // Single AZ for every subnet (region is derived from this).
  availability_zone: 'ap-northeast-1a',

  // Existing EC2 key pair name for SSH (no default — set in inputs.libsonnet).
  key_name: error 'set key_name in inputs.libsonnet',

  // Ubuntu 26.04 x86_64 hvm:ebs-ssd-gp3 in ap-northeast-1.
  ami: 'ami-0126975fb247bf2e7',

  // IPv6-reachable URL to the etherip-xdp .deb (no default).
  deb_url: error 'set deb_url in inputs.libsonnet',

  instance_type: 'c8i.xlarge',

  // Aligned /22 covering the four /24s below.
  vpc_cidr: '192.168.36.0/22',
  subnet_cidr_a: '192.168.36.0/24',  // subnet 0
  subnet_cidr_b: '192.168.37.0/24',  // subnet 1
  subnet_cidr_c: '192.168.38.0/24',  // subnet 2
  subnet_cidr_d: '192.168.39.0/24',  // subnet 3

  // Management ingress (SSH/ICMPv6) is IPv6-only.
  ssh_ingress_v6: '::/0',

  // apt package providing trafgen.
  trafgen_package: 'netsniff-ng',

  // Optional: set a root password so you can log in via the EC2 Serial Console
  // (Nitro) to troubleshoot if IPv6 SSH is lost. null = leave root locked
  // (default). Note: stored in plaintext in the template/user-data — use a
  // throwaway value, and avoid the literal sequence `${` (it would trip Fn::Sub).
  root_password: null,
};

defaults + overrides

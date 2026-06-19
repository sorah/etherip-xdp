// Copy this file to `inputs.libsonnet` (git-ignored) and fill in real values.
// Anything omitted falls back to the default in `constants.libsonnet`; only
// `key_name` and `deb_url` have no default.
{
  key_name: 'my-ec2-keypair',
  deb_url: 'https://example.invalid/etherip-xdp_0.1.0_amd64.deb',  // must be IPv6-reachable

  // Optional overrides:
  // availability_zone: 'ap-northeast-1a',
  // ami: 'ami-0126975fb247bf2e7',
  // instance_type: 'c8i.xlarge',
}

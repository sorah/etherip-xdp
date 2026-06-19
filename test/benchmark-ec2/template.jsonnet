// etherip-xdp benchmark environment — CloudFormation template (jsonnet).
//
//   jsonnet template.jsonnet > template.json
//   aws cloudformation deploy --template-file template.json \
//     --stack-name etherip-xdp-bench --region <region>
//
// See plan.md for the topology. Per-deployment values go in inputs.libsonnet.
local c = import 'constants.libsonnet';
local net = import 'lib/network.libsonnet';
local userdata = import 'lib/userdata.libsonnet';

local instanceResources = {
  [net.instances[key].logical]: {
    Type: 'AWS::EC2::Instance',
    Properties: {
      ImageId: c.ami,
      InstanceType: c.instance_type,
      KeyName: c.key_name,
      AvailabilityZone: net.az,
      NetworkInterfaces: [
        { NetworkInterfaceId: { Ref: e.logical }, DeviceIndex: e.deviceIndex }
        for e in net.enisOf(key)
      ],
      MetadataOptions: { HttpEndpoint: 'enabled', HttpTokens: 'required' },
      // Fn::Sub resolves the ${<Eni>.PrimaryIpv6Address} GetAtt refs the scripts
      // and etherip.json embed; all bash vars are brace-free so nothing else is
      // treated as a substitution.
      UserData: { 'Fn::Base64': { 'Fn::Sub': '#cloud-config\n' + std.manifestJsonEx(userdata.build(key), '  ') } },
      Tags: net.tags([
        { Key: 'Name', Value: 'etherip-bench-' + net.instances[key].name },
        { Key: 'role', Value: net.instances[key].name },
      ]),
    },
  }
  for key in net.instanceKeys
};

{
  AWSTemplateFormatVersion: '2010-09-09',
  Description: 'etherip-xdp benchmark environment (generator + 2 DUTs, IPv6 overlay)',
  Resources: net.baseResources + instanceResources,
  Outputs: {
    [net.instances[key].logical + 'Id']: {
      Description: net.instances[key].name + ' instance id',
      Value: { Ref: net.instances[key].logical },
    }
    for key in net.instanceKeys
  } + {
    // Public IPv6 of each instance's device-0 ENI: `ssh ubuntu@<addr>`
    // (SG allows TCP/22 from ::/0, ::/0 routes to the internet gateway).
    [net.instances[key].logical + 'Ipv6']: {
      Description: net.instances[key].name + ' SSH IPv6 address',
      Value: { 'Fn::GetAtt': [net.enisOf(key)[0].logical, 'PrimaryIpv6Address'] },
    }
    for key in net.instanceKeys
  },
}

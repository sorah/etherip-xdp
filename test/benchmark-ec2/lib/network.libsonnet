// Topology data + CloudFormation resource builders for the benchmark VPC.
//
// Single source of truth for instances, ENIs, overlay loopbacks and routes;
// consumed both here (to emit VPC/subnet/route/ENI resources) and by
// userdata.libsonnet (to emit per-node cloud-config).
local c = import '../constants.libsonnet';

local az = c.availability_zone;
local up(letter) = std.asciiUpper(letter);
local subnetRes(letter) = 'Subnet' + up(letter);

// Overlay loopback addresses, keyed by instance number x subnet number.
local v6(instNum, subnetNum) = 'fd00:ffff::%d:%d' % [instNum, subnetNum];
local v4(instNum, subnetNum) = '10.%d.%d.1' % [instNum, subnetNum];

local subnets = {
  a: { num: 0, cidr: c.subnet_cidr_a },
  b: { num: 1, cidr: c.subnet_cidr_b },
  c: { num: 2, cidr: c.subnet_cidr_c },
  d: { num: 3, cidr: c.subnet_cidr_d },
};

// Every ENI in the environment (one resource each, attached at deviceIndex).
local allEnis = [
  { logical: 'GenEniA', instanceKey: 'generator', subnet: 'a', deviceIndex: 0 },
  { logical: 'GenEniD', instanceKey: 'generator', subnet: 'd', deviceIndex: 1 },
  { logical: 'Dut1EniA', instanceKey: 'dut1', subnet: 'a', deviceIndex: 0 },
  { logical: 'Dut1EniB', instanceKey: 'dut1', subnet: 'b', deviceIndex: 1 },  // uplink
  { logical: 'Dut2EniD', instanceKey: 'dut2', subnet: 'd', deviceIndex: 0 },
  { logical: 'Dut2EniC', instanceKey: 'dut2', subnet: 'c', deviceIndex: 1 },  // uplink
];

local instances = {
  generator: {
    num: 0,
    name: 'generator',
    logical: 'Generator',
    uplink: null,
    // ENIs the bench script locates (by GUA via GetAtt/Fn::Sub): trafgen source,
    // sink, and dut-1's subnet-a ENI (whose MAC the generator resolves on-link).
    benchSrcEni: 'GenEniA',
    benchSinkEni: 'GenEniD',
    benchTargetEni: 'Dut1EniA',
    // overlay routes: { destInst, destSubnetNum, via }
    routes: [
      { di: 1, ds: 0, via: 'subnet:a' },  // dut-1 @a
      { di: 1, ds: 1, via: 'subnet:a' },  // dut-1 @b
      { di: 2, ds: 2, via: 'subnet:d' },  // dut-2 @c
      { di: 2, ds: 3, via: 'subnet:d' },  // dut-2 @d
    ],
  },
  dut1: {
    num: 1,
    name: 'dut-1',
    logical: 'Dut1',
    uplink: 'b',
    uplinkEni: 'Dut1EniB',
    peerUplinkEni: 'Dut2EniC',
    etherip: { selfV6: 'fe80::1/64', selfV4: '169.254.0.1/30', peerV6: 'fe80::2', peerV4: '169.254.0.2' },
    routes: [
      { di: 0, ds: 0, via: 'subnet:a' },  // generator @a
      { di: 0, ds: 3, via: 'etherip' },   // generator @d
      { di: 2, ds: 2, via: 'etherip' },   // dut-2 @c
      { di: 2, ds: 3, via: 'etherip' },   // dut-2 @d
    ],
  },
  dut2: {
    num: 2,
    name: 'dut-2',
    logical: 'Dut2',
    uplink: 'c',
    uplinkEni: 'Dut2EniC',
    peerUplinkEni: 'Dut1EniB',
    etherip: { selfV6: 'fe80::2/64', selfV4: '169.254.0.2/30', peerV6: 'fe80::1', peerV4: '169.254.0.1' },
    routes: [
      { di: 0, ds: 0, via: 'etherip' },   // generator @a
      { di: 0, ds: 3, via: 'subnet:d' },  // generator @d
      { di: 1, ds: 0, via: 'etherip' },   // dut-1 @a
      { di: 1, ds: 1, via: 'etherip' },   // dut-1 @b
    ],
  },
};

local instanceKeys = ['generator', 'dut1', 'dut2'];
local enisOf(key) = std.sort([e for e in allEnis if e.instanceKey == key], function(e) e.deviceIndex);

// Loopbacks owned by an instance = one per subnet it has an ENI on.
local loopbacksOf(key) = [
  { subnet: e.subnet, v6: v6(instances[key].num, subnets[e.subnet].num), v4: v4(instances[key].num, subnets[e.subnet].num) }
  for e in enisOf(key)
];

local tags(extra) = [{ Key: 'Project', Value: 'etherip-bench' }] + extra;

// ---- CloudFormation resources (everything except the instances) ----------

local vpcResources = {
  Vpc: {
    Type: 'AWS::EC2::VPC',
    Properties: {
      CidrBlock: c.vpc_cidr,
      EnableDnsSupport: true,
      EnableDnsHostnames: true,
      Tags: tags([{ Key: 'Name', Value: 'etherip-bench' }]),
    },
  },
  Ipv6Cidr: {
    Type: 'AWS::EC2::VPCCidrBlock',
    Properties: { VpcId: { Ref: 'Vpc' }, AmazonProvidedIpv6CidrBlock: true },
  },
  Igw: { Type: 'AWS::EC2::InternetGateway', Properties: { Tags: tags([{ Key: 'Name', Value: 'etherip-bench' }]) } },
  IgwAttach: {
    Type: 'AWS::EC2::VPCGatewayAttachment',
    Properties: { VpcId: { Ref: 'Vpc' }, InternetGatewayId: { Ref: 'Igw' } },
  },
  Rt: { Type: 'AWS::EC2::RouteTable', Properties: { VpcId: { Ref: 'Vpc' }, Tags: tags([{ Key: 'Name', Value: 'etherip-bench' }]) } },
  DefaultV6Route: {
    Type: 'AWS::EC2::Route',
    DependsOn: 'IgwAttach',
    Properties: { RouteTableId: { Ref: 'Rt' }, DestinationIpv6CidrBlock: '::/0', GatewayId: { Ref: 'Igw' } },
  },
};

local subnetResources = {
  [subnetRes(letter)]: {
    Type: 'AWS::EC2::Subnet',
    DependsOn: 'Ipv6Cidr',
    Properties: {
      VpcId: { Ref: 'Vpc' },
      AvailabilityZone: az,
      CidrBlock: subnets[letter].cidr,
      Ipv6CidrBlock: {
        'Fn::Select': [
          subnets[letter].num,
          { 'Fn::Cidr': [{ 'Fn::Select': [0, { 'Fn::GetAtt': ['Vpc', 'Ipv6CidrBlocks'] }] }, 4, 64] },
        ],
      },
      AssignIpv6AddressOnCreation: true,
      MapPublicIpOnLaunch: false,
      Tags: tags([{ Key: 'Name', Value: 'etherip-bench-' + letter }, { Key: 'subnet', Value: letter }]),
    },
  }
  for letter in std.objectFields(subnets)
} + {
  ['SubnetAssoc' + up(letter)]: {
    Type: 'AWS::EC2::SubnetRouteTableAssociation',
    Properties: { SubnetId: { Ref: subnetRes(letter) }, RouteTableId: { Ref: 'Rt' } },
  }
  for letter in std.objectFields(subnets)
};

local sgResources = {
  Sg: {
    Type: 'AWS::EC2::SecurityGroup',
    Properties: {
      GroupDescription: 'etherip-bench: IPv6 SSH/ICMP from anywhere, all intra-group',
      VpcId: { Ref: 'Vpc' },
      SecurityGroupIngress: [
        { IpProtocol: 'icmpv6', FromPort: -1, ToPort: -1, CidrIpv6: c.ssh_ingress_v6 },
        { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, CidrIpv6: c.ssh_ingress_v6 },
      ],
      SecurityGroupEgress: [
        { IpProtocol: '-1', CidrIp: '0.0.0.0/0' },
        { IpProtocol: '-1', CidrIpv6: '::/0' },
      ],
      Tags: tags([{ Key: 'Name', Value: 'etherip-bench' }]),
    },
  },
  // "everything from the same security group" (both families) — self-referencing.
  SgSelf: {
    Type: 'AWS::EC2::SecurityGroupIngress',
    Properties: { GroupId: { Ref: 'Sg' }, IpProtocol: '-1', SourceSecurityGroupId: { Ref: 'Sg' } },
  },
};

local eniResources = {
  [e.logical]: {
    Type: 'AWS::EC2::NetworkInterface',
    Properties: {
      SubnetId: { Ref: subnetRes(e.subnet) },
      GroupSet: [{ Ref: 'Sg' }],
      Ipv6AddressCount: 1,
      // Designate the GUA as the ENI's primary IPv6 so GetAtt PrimaryIpv6Address
      // is populated (required for the tunnel config, find-by-GUA and SSH outputs).
      EnablePrimaryIpv6: true,
      SourceDestCheck: false,
      Description: e.logical,
      Tags: tags([
        { Key: 'Name', Value: 'etherip-bench-' + instances[e.instanceKey].name + '-' + e.subnet },
        { Key: 'role', Value: instances[e.instanceKey].name },
        { Key: 'subnet', Value: e.subnet },
      ]),
    },
  }
  for e in allEnis
};

// VPC host routes: each overlay loopback /128 (and /32) -> its owning ENI.
local hostRouteResources = std.foldl(function(acc, e) acc {
  ['Route' + e.logical + 'V6']: {
    Type: 'AWS::EC2::Route',
    DependsOn: instances[e.instanceKey].logical,
    Properties: {
      RouteTableId: { Ref: 'Rt' },
      DestinationIpv6CidrBlock: v6(instances[e.instanceKey].num, subnets[e.subnet].num) + '/128',
      NetworkInterfaceId: { Ref: e.logical },
    },
  },
  ['Route' + e.logical + 'V4']: {
    Type: 'AWS::EC2::Route',
    DependsOn: instances[e.instanceKey].logical,
    Properties: {
      RouteTableId: { Ref: 'Rt' },
      DestinationCidrBlock: v4(instances[e.instanceKey].num, subnets[e.subnet].num) + '/32',
      NetworkInterfaceId: { Ref: e.logical },
    },
  },
}, allEnis, {});

{
  az: az,
  region: std.substr(az, 0, std.length(az) - 1),
  subnets: subnets,
  instances: instances,
  instanceKeys: instanceKeys,
  enisOf:: enisOf,
  loopbacksOf:: loopbacksOf,
  v6:: v6,
  v4:: v4,
  subnetRes:: subnetRes,
  tags:: tags,

  baseResources: vpcResources + subnetResources + sgResources + eniResources + hostRouteResources,
}

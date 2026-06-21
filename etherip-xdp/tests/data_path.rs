//! Byte-exact data-path tests for the XDP program, ported from the Go suite
//! (`pkg/coreelf/xdp_test.go`). They drive the program with `BPF_PROG_TEST_RUN`
//! via aya's `TestRun` and assert the exact output and action.
//!
//! These require root (CAP_BPF/CAP_NET_ADMIN) and kernel >= 5.15 (for passing
//! `ctx_in`/`ingress_ifindex`), so they are `#[ignore]`d by default. Run with:
//!
//! ```text
//! cargo test -p etherip-xdp --test data_path --no-run
//! sudo -E <built test binary> --ignored --test-threads=1
//! ```
//! (or `mise run test-bpf`).
#![deny(clippy::undocumented_unsafe_blocks)]

const EXTERNAL_IFINDEX: u32 = 2;
const PEER_IFINDEX: u32 = 3;

const EXTERNAL_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
const DST_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02];
const TUNNEL_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03];

const MSS_V4: u16 = 1404;
const MSS_V6: u16 = 1384;

fn local() -> std::net::Ipv6Addr {
    "fe80::1".parse().unwrap()
}
fn remote() -> std::net::Ipv6Addr {
    "fe80::2".parse().unwrap()
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

fn ctx_bytes(md: &XdpMd) -> &[u8] {
    // SAFETY: `XdpMd` is `#[repr(C)]` plain old data; we expose exactly
    // `size_of::<XdpMd>()` bytes of it as an immutable view, with the same
    // lifetime as the `&md` borrow, so the slice never outlives the value.
    unsafe {
        std::slice::from_raw_parts(
            (md as *const XdpMd).cast::<u8>(),
            std::mem::size_of::<XdpMd>(),
        )
    }
}

fn test_config() -> etherip_xdp_common::TunnelConfig {
    etherip_xdp_common::TunnelConfig {
        src_addr: local().octets(),
        dst_addr: remote().octets(),
        internal_ifindex: PEER_IFINDEX,
        external_ifindex: EXTERNAL_IFINDEX,
        tunnel_mac: TUNNEL_MAC,
        external_mac: EXTERNAL_MAC,
        dst_mac: DST_MAC,
        _pad: [0; 2],
        mss_clamp_ipv4: MSS_V4,
        mss_clamp_ipv6: MSS_V6,
    }
}

fn load_and_setup() -> aya::Ebpf {
    // Required on kernels < 5.11; a no-op otherwise.
    let _ = nix::sys::resource::setrlimit(
        nix::sys::resource::Resource::RLIMIT_MEMLOCK,
        nix::libc::RLIM_INFINITY,
        nix::libc::RLIM_INFINITY,
    );

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/etherip-xdp"
    )))
    .expect("load ebpf object");

    for name in ["xdp_encap", "xdp_decap"] {
        let prog: &mut aya::programs::Xdp = ebpf.program_mut(name).unwrap().try_into().unwrap();
        prog.load()
            .unwrap_or_else(|e| panic!("verifier-load {name}: {e}"));
    }

    let cfg = test_config();
    let key = etherip_xdp_common::DecapKey {
        remote: remote().octets(),
        local: local().octets(),
    };
    {
        let mut m: aya::maps::HashMap<_, u32, etherip_xdp_common::TunnelConfig> =
            aya::maps::HashMap::try_from(ebpf.map_mut("ENCAP_CONFIG").unwrap()).unwrap();
        m.insert(PEER_IFINDEX, cfg, 0).unwrap();
    }
    {
        let mut m: aya::maps::HashMap<
            _,
            etherip_xdp_common::DecapKey,
            etherip_xdp_common::TunnelConfig,
        > = aya::maps::HashMap::try_from(ebpf.map_mut("DECAP_CONFIG").unwrap()).unwrap();
        m.insert(key, cfg, 0).unwrap();
    }
    {
        let mut d: aya::maps::xdp::DevMapHash<_> =
            aya::maps::xdp::DevMapHash::try_from(ebpf.map_mut("REDIRECT_UPLINK").unwrap()).unwrap();
        d.insert(EXTERNAL_IFINDEX, EXTERNAL_IFINDEX, None, 0)
            .unwrap();
    }
    {
        let mut d: aya::maps::xdp::DevMapHash<_> =
            aya::maps::xdp::DevMapHash::try_from(ebpf.map_mut("REDIRECT_PEER").unwrap()).unwrap();
        d.insert(PEER_IFINDEX, PEER_IFINDEX, None, 0).unwrap();
    }
    ebpf
}

fn run(
    ebpf: &mut aya::Ebpf,
    prog_name: &str,
    input: &[u8],
    ingress_ifindex: u32,
) -> (u32, Vec<u8>) {
    use aya::programs::TestRun as _;
    let md = XdpMd {
        data: 0,
        data_end: input.len() as u32,
        data_meta: 0,
        ingress_ifindex,
        rx_queue_index: 0,
        egress_ifindex: 0,
    };
    let mut data_out = vec![0u8; input.len() + 256];
    let mut ctx_out = vec![0u8; std::mem::size_of::<XdpMd>()];
    let prog: &mut aya::programs::Xdp = ebpf.program_mut(prog_name).unwrap().try_into().unwrap();
    let result = prog
        .test_run(aya::programs::TestRunOptions {
            data_in: Some(input),
            data_out: Some(&mut data_out),
            ctx_in: Some(ctx_bytes(&md)),
            ctx_out: Some(&mut ctx_out),
            ..Default::default()
        })
        .expect("test_run");
    data_out.truncate(result.data_size_out as usize);
    (result.return_value, data_out)
}

/// Run the shared host data-path core (`data_path::encap`) over `input`,
/// returning the outcome and the transformed buffer. Each test asserts this
/// matches the eBPF program's `BPF_PROG_TEST_RUN` output byte for byte, so the
/// coverage-guided fuzzing of this same core (see `test/fuzzing/`) carries over to the
/// kernel program.
fn host_encap(input: &[u8]) -> (etherip_xdp_common::data_path::EncapOutcome, Vec<u8>) {
    let mut pkt = etherip_xdp_common::data_path::HostPacket::new(input.to_vec());
    let outcome = etherip_xdp_common::data_path::encap(&mut pkt, &test_config());
    (outcome, pkt.into_inner())
}

/// Run the shared host data-path core (`data_path::decap`) over `input`, backing
/// the tunnel demux with the single test tunnel (so the lookup matches the same
/// (remote, local) pair the eBPF `DECAP_CONFIG` map holds).
fn host_decap(input: &[u8]) -> (etherip_xdp_common::data_path::DecapOutcome, Vec<u8>) {
    let cfg = test_config();
    let key = etherip_xdp_common::DecapKey {
        remote: remote().octets(),
        local: local().octets(),
    };
    let mut pkt = etherip_xdp_common::data_path::HostPacket::new(input.to_vec());
    let outcome = etherip_xdp_common::data_path::decap(&mut pkt, |k| (*k == key).then_some(cfg));
    (outcome, pkt.into_inner())
}

/// An inner Ethernet frame: IPv4 TCP SYN with a single MSS option.
fn ipv4_tcp_syn(mss: u16) -> Vec<u8> {
    let payload = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let builder = etherparse::PacketBuilder::ethernet2(
        [0x00, 0x00, 0x5e, 0x00, 0x11, 0x02], // inner src
        [0x00, 0x00, 0x5e, 0x00, 0x11, 0x01], // inner dst
    )
    .ipv4([192, 168, 100, 200], [192, 168, 30, 1], 64)
    .tcp(1234, 80, 0, 0)
    .syn()
    .options(&[etherparse::TcpOptionElement::MaximumSegmentSize(mss)])
    .unwrap();
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

fn expected_outer_headers(inner_len: usize, flow_hash: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(etherip_xdp_common::OUTER_OVERHEAD);
    h.extend_from_slice(&DST_MAC); // outer eth dst = next hop
    h.extend_from_slice(&EXTERNAL_MAC); // outer eth src = uplink
    h.extend_from_slice(&[0x86, 0xDD]); // IPv6
    h.extend_from_slice(&[
        0x60,
        ((flow_hash >> 16) & 0x0F) as u8,
        ((flow_hash >> 8) & 0xFF) as u8,
        (flow_hash & 0xFF) as u8,
    ]);
    let payload_len = (etherip_xdp_common::OUTER_OVERHEAD - 14 - 40 + inner_len) as u16; // etherip(2) + inner
    h.extend_from_slice(&payload_len.to_be_bytes());
    h.push(etherip_xdp_common::ETHERIP_PROTO);
    h.push(etherip_xdp_common::HOP_LIMIT_DEFAULT);
    h.extend_from_slice(&local().octets()); // src
    h.extend_from_slice(&remote().octets()); // dst
    h.push(etherip_xdp_common::ETHERIP_VERSION);
    h.push(0x00);
    h
}

#[test]
#[ignore = "requires root and kernel >= 5.15"]
fn encap_ipv4_tcp_syn_is_clamped_and_redirected() {
    let mut ebpf = load_and_setup();
    let input = ipv4_tcp_syn(1460);
    let expected_inner = ipv4_tcp_syn(MSS_V4); // 1460 clamped to 1404

    let (action, out) = run(&mut ebpf, "xdp_encap", &input, PEER_IFINDEX);
    assert_eq!(action, 4, "expected XDP_REDIRECT");

    let mut expected =
        expected_outer_headers(input.len(), etherip_xdp_common::inner_flow_hash(&input));
    expected.extend_from_slice(&expected_inner);
    assert_eq!(out.len(), expected.len(), "output length");
    assert_eq!(out, expected, "byte-exact encap output");

    let (outcome, host_out) = host_encap(&input);
    assert_eq!(
        outcome,
        etherip_xdp_common::data_path::EncapOutcome::Redirect
    );
    assert_eq!(host_out, out, "host core matches eBPF byte-exact (encap)");
}

#[test]
#[ignore = "requires root and kernel >= 5.15"]
fn encap_mss_not_raised_when_below_clamp() {
    // An inner MSS already below the clamp must be left untouched.
    let mut ebpf = load_and_setup();
    let input = ipv4_tcp_syn(1000);
    let (action, out) = run(&mut ebpf, "xdp_encap", &input, PEER_IFINDEX);
    assert_eq!(action, 4);
    // Inner (offset 56..) is byte-identical to the input.
    assert_eq!(&out[etherip_xdp_common::OUTER_OVERHEAD..], &input[..]);

    let (outcome, host_out) = host_encap(&input);
    assert_eq!(
        outcome,
        etherip_xdp_common::data_path::EncapOutcome::Redirect
    );
    assert_eq!(host_out, out, "host core matches eBPF byte-exact (encap)");
}

fn etherip_wrap(inner: &[u8], src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x02, 0x02, 0x02, 0x02, 0x02, 0x02]); // outer dst (us) — unused by decap
    buf.extend_from_slice(&[0x03, 0x03, 0x03, 0x03, 0x03, 0x03]); // outer src (remote) — unused
    buf.extend_from_slice(&[0x86, 0xDD]);
    buf.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&((2 + inner.len()) as u16).to_be_bytes());
    buf.push(etherip_xdp_common::ETHERIP_PROTO);
    buf.push(etherip_xdp_common::HOP_LIMIT_DEFAULT);
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(etherip_xdp_common::ETHERIP_VERSION);
    buf.push(0x00);
    buf.extend_from_slice(inner);
    buf
}

#[test]
#[ignore = "requires root and kernel >= 5.15"]
fn decap_strips_outer_and_rewrites_inner_dst_mac() {
    let mut ebpf = load_and_setup();
    let inner = ipv4_tcp_syn(1460); // any inner frame; decap doesn't clamp
    // Packet arrives from remote (src) to us (dst=local).
    let input = etherip_wrap(&inner, remote(), local());

    let (action, out) = run(&mut ebpf, "xdp_decap", &input, EXTERNAL_IFINDEX);
    assert_eq!(action, 4, "expected XDP_REDIRECT");

    let mut expected = inner.clone();
    expected[0..6].copy_from_slice(&TUNNEL_MAC); // inner dst MAC rewritten
    assert_eq!(out, expected, "byte-exact decap output");

    let (outcome, host_out) = host_decap(&input);
    assert_eq!(
        outcome,
        etherip_xdp_common::data_path::DecapOutcome::Redirect {
            internal_ifindex: PEER_IFINDEX
        }
    );
    assert_eq!(host_out, out, "host core matches eBPF byte-exact (decap)");
}

#[test]
#[ignore = "requires root and kernel >= 5.15"]
fn decap_passes_non_etherip() {
    let mut ebpf = load_and_setup();
    // A plain IPv4 frame on the uplink is not EtherIP -> XDP_PASS.
    let input = ipv4_tcp_syn(1460);
    let (action, _out) = run(&mut ebpf, "xdp_decap", &input, EXTERNAL_IFINDEX);
    assert_eq!(action, 2, "expected XDP_PASS");

    // Outer EtherType is IPv4, not IPv6, so the core bails at the first check and
    // leaves the buffer untouched.
    let (outcome, host_out) = host_decap(&input);
    assert_eq!(
        outcome,
        etherip_xdp_common::data_path::DecapOutcome::NotIpv6
    );
    assert_eq!(
        host_out, input,
        "decap must not mutate a passed-through frame"
    );
}

#[test]
#[ignore = "requires root and kernel >= 5.15"]
fn decap_passes_unknown_tunnel_pair() {
    let mut ebpf = load_and_setup();
    let inner = ipv4_tcp_syn(1460);
    // Outer source is our own local address, so the (remote, local) pair matches
    // no tunnel (and would also trip the loopback guard): must not be decapsulated.
    let input = etherip_wrap(&inner, local(), local());
    let (action, _out) = run(&mut ebpf, "xdp_decap", &input, EXTERNAL_IFINDEX);
    assert_eq!(action, 2, "expected XDP_PASS for an unknown tunnel pair");

    // (remote=local, local=local) matches no tunnel, so the core passes it
    // through unchanged before the loopback guard is even reached.
    let (outcome, host_out) = host_decap(&input);
    assert_eq!(
        outcome,
        etherip_xdp_common::data_path::DecapOutcome::NoTunnel
    );
    assert_eq!(
        host_out, input,
        "decap must not mutate a passed-through frame"
    );
}

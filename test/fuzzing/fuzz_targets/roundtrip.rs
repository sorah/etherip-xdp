//! Round-trip property: encapsulating a well-formed inner frame at the A end and
//! decapsulating it at the B end must reconstruct the original frame exactly —
//! neither side touches the inner MACs. MSS clamping is disabled on the encap side
//! so the inner bytes are preserved exactly. Runs over both the /128 tunnel and
//! the prefixed one; the latter asserts end-to-end that B's masked lookup accepts
//! whatever entropy-filled outer addresses A's encap produced.
//!
//! The inner frame is built from fuzzer-chosen fields (`InnerSpec`) via
//! etherparse, so this also drives the inner IPv4/IPv6 + TCP-option parsing with
//! structurally valid input.
#![no_main]

fn roundtrip(
    inner: &[u8],
    enc_cfg: &etherip_xdp_common::TunnelConfig,
    dec_cfg: &etherip_xdp_common::TunnelConfig,
    table: &etherip_xdp_common::DecapPlens,
    key: &etherip_xdp_common::DecapKey,
) {
    let mut pkt = etherip_xdp_common::data_path::HostPacket::new(inner.to_vec());
    if etherip_xdp_common::data_path::encap(&mut pkt, enc_cfg)
        != etherip_xdp_common::data_path::EncapOutcome::Redirect
    {
        // A well-formed etherparse frame always encapsulates; bail defensively
        // rather than asserting, so a future builder change can't wedge the fuzzer.
        return;
    }

    // The lookup is keyed: B only resolves the tunnel when masking A's output
    // down to the configured prefixes yields the expected bases.
    let outcome =
        etherip_xdp_common::data_path::decap(&mut pkt, table, |k| (k == key).then_some(*dec_cfg));

    match outcome {
        etherip_xdp_common::data_path::DecapOutcome::Redirect { internal_ifindex } => {
            assert_eq!(internal_ifindex, dec_cfg.internal_ifindex);
            assert_eq!(
                pkt.as_slice(),
                inner,
                "encap+decap must round-trip the inner frame exactly"
            );
        }
        other => panic!("expected a round-trip redirect, got {other:?}"),
    }
}

libfuzzer_sys::fuzz_target!(|spec: etherip_xdp_fuzz::InnerSpec| {
    let Some(inner) = etherip_xdp_fuzz::build_inner(&spec) else {
        return;
    };
    if inner.len() < 14 {
        return;
    }

    roundtrip(
        &inner,
        &etherip_xdp_fuzz::encap_cfg_no_clamp(),
        &etherip_xdp_fuzz::decap_cfg(),
        &etherip_xdp_fuzz::plens(&[(128, 128)]),
        &etherip_xdp_common::DecapKey {
            remote: etherip_xdp_fuzz::ADDR_A,
            local: etherip_xdp_fuzz::ADDR_B,
        },
    );
    roundtrip(
        &inner,
        &etherip_xdp_fuzz::encap_cfg_prefixed_no_clamp(),
        &etherip_xdp_fuzz::decap_cfg_prefixed(),
        &etherip_xdp_fuzz::plens(&[(etherip_xdp_fuzz::PLEN_A, etherip_xdp_fuzz::PLEN_B)]),
        &etherip_xdp_common::DecapKey {
            remote: etherip_xdp_fuzz::PREFIX_A,
            local: etherip_xdp_fuzz::PREFIX_B,
        },
    );
    // Tagged tunnel: encap adds an 802.1Q tag that decap must strip to recover
    // the inner frame, over the same arbitrary inner frames.
    roundtrip(
        &inner,
        &etherip_xdp_fuzz::encap_cfg_vlan_no_clamp(),
        &etherip_xdp_fuzz::decap_cfg_vlan(),
        &etherip_xdp_fuzz::plens(&[(128, 128)]),
        &etherip_xdp_common::DecapKey {
            remote: etherip_xdp_fuzz::ADDR_A,
            local: etherip_xdp_fuzz::ADDR_B,
        },
    );
});

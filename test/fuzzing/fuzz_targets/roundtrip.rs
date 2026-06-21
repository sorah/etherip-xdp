//! Round-trip property: encapsulating a well-formed inner frame at the A end and
//! decapsulating it at the B end must reconstruct the original frame, save for
//! the inner destination MAC that decap rewrites to the tunnel MAC. MSS clamping
//! is disabled on the encap side so the inner bytes are preserved exactly.
//!
//! The inner frame is built from fuzzer-chosen fields (`InnerSpec`) via
//! etherparse, so this also drives the inner IPv4/IPv6 + TCP-option parsing with
//! structurally valid input.
#![no_main]

libfuzzer_sys::fuzz_target!(|spec: etherip_xdp_fuzz::InnerSpec| {
    let Some(inner) = etherip_xdp_fuzz::build_inner(&spec) else {
        return;
    };
    if inner.len() < 14 {
        return;
    }

    let mut pkt = etherip_xdp_common::data_path::HostPacket::new(inner.clone());
    if etherip_xdp_common::data_path::encap(&mut pkt, &etherip_xdp_fuzz::encap_cfg_no_clamp())
        != etherip_xdp_common::data_path::EncapOutcome::Redirect
    {
        // A well-formed etherparse frame always encapsulates; bail defensively
        // rather than asserting, so a future builder change can't wedge the fuzzer.
        return;
    }

    let dec_cfg = etherip_xdp_fuzz::decap_cfg();
    let outcome = etherip_xdp_common::data_path::decap(&mut pkt, |_key| Some(dec_cfg));

    match outcome {
        etherip_xdp_common::data_path::DecapOutcome::Redirect { internal_ifindex } => {
            assert_eq!(internal_ifindex, dec_cfg.internal_ifindex);
            let mut expected = inner.clone();
            expected[0..6].copy_from_slice(&dec_cfg.tunnel_mac);
            assert_eq!(
                pkt.as_slice(),
                expected.as_slice(),
                "encap+decap must round-trip the inner frame (dst MAC aside)"
            );
        }
        other => panic!("expected a round-trip redirect, got {other:?}"),
    }
});

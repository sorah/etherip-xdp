//! Fuzz `data_path::decap` with arbitrary outer frames. The tunnel lookup always
//! resolves (`Some(decap_cfg())`) so the fuzzer can drive the full strip/rewrite
//! path: IPv6 extension-header walking, the EtherIP header check, and the
//! headroom adjustment. The core must never panic, and on a redirect the output
//! must be a stripped inner frame whose destination MAC is the tunnel MAC.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let cfg = etherip_xdp_fuzz::decap_cfg();
    let mut pkt = etherip_xdp_common::data_path::HostPacket::new(data.to_vec());
    let outcome = etherip_xdp_common::data_path::decap(&mut pkt, |_key| Some(cfg));

    if let etherip_xdp_common::data_path::DecapOutcome::Redirect { internal_ifindex } = outcome {
        assert_eq!(internal_ifindex, cfg.internal_ifindex);
        let out = pkt.as_slice();
        // An inner Ethernet header is present and its dst MAC was rewritten.
        assert!(
            out.len() >= 14,
            "redirected frame shorter than an Ethernet header"
        );
        assert_eq!(&out[0..6], &cfg.tunnel_mac, "inner dst MAC not rewritten");
        // The outer Ethernet + IPv6 + EtherIP headers (>= 56 bytes) were stripped.
        assert!(
            data.len() >= out.len() + etherip_xdp_common::OUTER_OVERHEAD,
            "fewer than OUTER_OVERHEAD bytes stripped"
        );
    }
});

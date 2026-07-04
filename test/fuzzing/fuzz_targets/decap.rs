//! Fuzz `data_path::decap` with arbitrary outer frames. The demux table holds
//! two masking rules and the lookup resolves on the second, so every EtherIP
//! frame drives the pair loop and the prefix masking as well as the full strip
//! path: IPv6 extension-header walking, the EtherIP header check, and the
//! headroom adjustment. The core must never panic, and on a redirect the output
//! must be the inner frame delivered unchanged — i.e. only outer headers were
//! stripped. Frames sourced from inside the config's local prefix exercise the
//! prefix loopback guard instead.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let cfg = etherip_xdp_fuzz::decap_cfg_prefixed();
    let table = etherip_xdp_fuzz::plens(&[
        (128, 128),
        (etherip_xdp_fuzz::PLEN_A, etherip_xdp_fuzz::PLEN_B),
    ]);
    let mut pkt = etherip_xdp_common::data_path::HostPacket::new(data.to_vec());
    let mut calls = 0usize;
    let outcome = etherip_xdp_common::data_path::decap(&mut pkt, &table, |key| {
        calls += 1;
        match calls {
            // First pair is (128, 128): the key must be the packet's own
            // unmasked (saddr, daddr). Reported as a miss to reach pair two.
            1 => None,
            // Second pair: the key must be masked down to the table's prefix
            // lengths, whatever the addresses were.
            2 => {
                assert_eq!(
                    key.remote,
                    etherip_xdp_common::mask_addr(key.remote, etherip_xdp_fuzz::PLEN_A),
                    "pair-2 remote key not masked"
                );
                assert_eq!(
                    key.local,
                    etherip_xdp_common::mask_addr(key.local, etherip_xdp_fuzz::PLEN_B),
                    "pair-2 local key not masked"
                );
                Some(cfg)
            }
            _ => panic!("find called more times than the table has entries"),
        }
    });

    if let etherip_xdp_common::data_path::DecapOutcome::Redirect { internal_ifindex } = outcome {
        assert_eq!(internal_ifindex, cfg.internal_ifindex);
        let out = pkt.as_slice();
        // An inner Ethernet header is present and was delivered unchanged: decap
        // only strips a prefix, so the output is a suffix of the input.
        assert!(
            out.len() >= 14,
            "redirected frame shorter than an Ethernet header"
        );
        assert!(
            data.ends_with(out),
            "decap mutated the inner frame instead of only stripping outer headers"
        );
        // The outer Ethernet + IPv6 + EtherIP headers (>= 56 bytes) were stripped.
        assert!(
            data.len() >= out.len() + etherip_xdp_common::OUTER_OVERHEAD,
            "fewer than OUTER_OVERHEAD bytes stripped"
        );
    }
});

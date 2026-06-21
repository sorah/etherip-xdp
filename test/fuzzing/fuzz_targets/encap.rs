//! Fuzz `data_path::encap` with an arbitrary inner frame. The core must never
//! panic, and on a redirect the grown outer Ethernet/IPv6/EtherIP headers must be
//! exactly correct: addresses and MACs from the config, the payload length and
//! EtherIP markers, and a flow label that matches the independent slice-based
//! reference `inner_flow_hash` over the original inner frame.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let cfg = etherip_xdp_fuzz::encap_cfg();
    let mut pkt = etherip_xdp_common::data_path::HostPacket::new(data.to_vec());
    let outcome = etherip_xdp_common::data_path::encap(&mut pkt, &cfg);

    if outcome == etherip_xdp_common::data_path::EncapOutcome::Redirect {
        let out = pkt.as_slice();
        // Encap grows the frame by exactly the outer overhead.
        assert_eq!(
            out.len(),
            data.len() + etherip_xdp_common::OUTER_OVERHEAD,
            "encap did not grow the frame by OUTER_OVERHEAD"
        );

        // Outer Ethernet header.
        assert_eq!(&out[0..6], &cfg.dst_mac);
        assert_eq!(&out[6..12], &cfg.external_mac);
        assert_eq!(&out[12..14], &[0x86, 0xDD]);

        // Outer IPv6 header: version/traffic-class, payload length, next header,
        // and the source/destination addresses.
        assert_eq!(out[14] & 0xf0, 0x60, "outer IPv6 version nibble");
        let payload_len = u16::from_be_bytes([out[18], out[19]]);
        assert_eq!(
            payload_len as usize,
            out.len() - 14 - 40,
            "outer IPv6 payload length"
        );
        assert_eq!(
            out[20],
            etherip_xdp_common::ETHERIP_PROTO,
            "outer next header"
        );
        assert_eq!(&out[22..38], &cfg.src_addr);
        assert_eq!(&out[38..54], &cfg.dst_addr);

        // EtherIP header.
        assert_eq!(out[54], etherip_xdp_common::ETHERIP_VERSION);
        assert_eq!(out[55], 0x00);

        // The 20-bit flow label embedded in the IPv6 header matches the reference
        // hash over the original inner frame (cross-checking the two impls).
        let flow = etherip_xdp_common::inner_flow_hash(data);
        assert_eq!(out[15] & 0x0f, ((flow >> 16) & 0x0f) as u8, "flow label hi");
        assert_eq!(out[16], ((flow >> 8) & 0xff) as u8, "flow label mid");
        assert_eq!(out[17], (flow & 0xff) as u8, "flow label lo");
    }
});

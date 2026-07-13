#![no_main]

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
    time::{Duration, Instant},
};

use flowweave_lab::{
    VPN_MAX_IP_PACKET_LEN, VpnCertificateFingerprint, VpnIdentity, VpnIdentityLimits, VpnIpNetwork,
    VpnPacketDirection, VpnReassembler, VpnReassemblyLimits, decode_vpn_control_message,
    decode_vpn_ip_fragment, inspect_vpn_ip_packet, parse_vpn_identity_registry_json,
    validate_vpn_ip_packet_policy,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let limits = VpnReassemblyLimits {
        max_inflight_packets: 16,
        max_buffered_bytes: VPN_MAX_IP_PACKET_LEN * 4,
        fragment_timeout: Duration::from_millis(50),
    };
    let mut reassembler = VpnReassembler::new(limits).expect("fixed fuzz limits are valid");
    let started = Instant::now();

    for (sequence, datagram) in input.chunks(2048).take(256).enumerate() {
        let now = started + Duration::from_millis(sequence as u64);
        let _ = decode_vpn_ip_fragment(datagram);
        let _ = decode_vpn_control_message(datagram);
        let _ = parse_vpn_identity_registry_json(datagram);
        let _ = inspect_vpn_ip_packet(datagram);
        let _ =
            validate_vpn_ip_packet_policy(fuzz_identity(), VpnPacketDirection::Uplink, datagram);
        let _ =
            validate_vpn_ip_packet_policy(fuzz_identity(), VpnPacketDirection::Downlink, datagram);
        let _ = reassembler.ingest(now, datagram);
        assert!(reassembler.inflight_packets() <= limits.max_inflight_packets);
        assert!(reassembler.buffered_bytes() <= limits.max_buffered_bytes);
    }
});

fn fuzz_identity() -> &'static VpnIdentity {
    static IDENTITY: OnceLock<VpnIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        VpnIdentity::new(
            "fuzz-client",
            vec![VpnCertificateFingerprint::from_sha256([0xA5; 32])],
            true,
            Some("10.77.0.2".parse().expect("fixed IPv4 address")),
            Some("fd77::2".parse().expect("fixed IPv6 address")),
            vec![
                VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).expect("fixed IPv4 network"),
                VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).expect("fixed IPv6 network"),
            ],
            VpnIdentityLimits::default(),
        )
        .expect("fixed fuzz identity is valid")
    })
}

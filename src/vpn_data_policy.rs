use std::{error::Error, fmt};

use crate::{
    VpnIdentity, VpnIpPacketMeta, VpnPacketDirection, VpnPacketError, VpnQuotaRejection,
    inspect_vpn_ip_packet,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnDataPolicyError {
    StaleGeneration,
    Packet(VpnPacketError),
    UplinkSourceSpoofed,
    DestinationPolicyRejected,
    DownlinkDestinationMismatch,
    Quota(VpnQuotaRejection),
}

impl fmt::Display for VpnDataPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(error) => write!(formatter, "vpn_data_policy_packet:{error}"),
            Self::Quota(error) => write!(formatter, "vpn_data_policy_quota:{error}"),
            other => formatter.write_str(match other {
                Self::StaleGeneration => "vpn_data_policy_stale_generation",
                Self::UplinkSourceSpoofed => "vpn_data_policy_uplink_source_spoofed",
                Self::DestinationPolicyRejected => "vpn_data_policy_destination_rejected",
                Self::DownlinkDestinationMismatch => {
                    "vpn_data_policy_downlink_destination_mismatch"
                }
                Self::Packet(_) | Self::Quota(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnDataPolicyError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnDataPolicyMetricsSnapshot {
    pub forwarded_uplink_packets: u64,
    pub forwarded_uplink_bytes: u64,
    pub forwarded_downlink_packets: u64,
    pub forwarded_downlink_bytes: u64,
    pub malformed_packet_rejections: u64,
    pub uplink_source_spoof_rejections: u64,
    pub destination_policy_rejections: u64,
    pub downlink_destination_rejections: u64,
}

pub fn validate_vpn_ip_packet_policy(
    identity: &VpnIdentity,
    direction: VpnPacketDirection,
    packet: &[u8],
) -> Result<VpnIpPacketMeta, VpnDataPolicyError> {
    let metadata = inspect_vpn_ip_packet(packet).map_err(VpnDataPolicyError::Packet)?;
    match direction {
        VpnPacketDirection::Uplink => {
            if !identity.permits_source(metadata.source) {
                return Err(VpnDataPolicyError::UplinkSourceSpoofed);
            }
            if !identity.allows_destination(metadata.destination) {
                return Err(VpnDataPolicyError::DestinationPolicyRejected);
            }
        }
        VpnPacketDirection::Downlink => {
            if !identity.permits_source(metadata.destination) {
                return Err(VpnDataPolicyError::DownlinkDestinationMismatch);
            }
            if !identity.allows_destination(metadata.source) {
                return Err(VpnDataPolicyError::DestinationPolicyRejected);
            }
        }
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{VpnCertificateFingerprint, VpnIdentityLimits, VpnIpNetwork};

    use super::*;

    #[test]
    fn uplink_requires_exact_assigned_source_and_explicit_destination_policy() {
        let identity = identity();
        let allowed = ipv4_packet("10.77.0.2", "198.51.100.8");
        assert!(
            validate_vpn_ip_packet_policy(&identity, VpnPacketDirection::Uplink, &allowed).is_ok()
        );
        assert_eq!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Uplink,
                &ipv4_packet("10.77.0.9", "198.51.100.8"),
            )
            .unwrap_err(),
            VpnDataPolicyError::UplinkSourceSpoofed
        );
        assert_eq!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Uplink,
                &ipv4_packet("10.77.0.2", "203.0.113.8"),
            )
            .unwrap_err(),
            VpnDataPolicyError::DestinationPolicyRejected
        );
    }

    #[test]
    fn downlink_requires_assigned_destination_and_allowed_return_source() {
        let identity = identity();
        let allowed = ipv4_packet("198.51.100.8", "10.77.0.2");
        assert!(
            validate_vpn_ip_packet_policy(&identity, VpnPacketDirection::Downlink, &allowed)
                .is_ok()
        );
        assert_eq!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Downlink,
                &ipv4_packet("198.51.100.8", "10.77.0.9"),
            )
            .unwrap_err(),
            VpnDataPolicyError::DownlinkDestinationMismatch
        );
        assert_eq!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Downlink,
                &ipv4_packet("203.0.113.8", "10.77.0.2"),
            )
            .unwrap_err(),
            VpnDataPolicyError::DestinationPolicyRejected
        );
    }

    #[test]
    fn ipv6_uses_the_same_source_and_return_path_contract() {
        let identity = identity();
        assert!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Uplink,
                &ipv6_packet("fd77::2", "2001:db8::8"),
            )
            .is_ok()
        );
        assert_eq!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Uplink,
                &ipv6_packet("fd77::9", "2001:db8::8"),
            )
            .unwrap_err(),
            VpnDataPolicyError::UplinkSourceSpoofed
        );
        assert!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Downlink,
                &ipv6_packet("2001:db8::8", "fd77::2"),
            )
            .is_ok()
        );
        assert_eq!(
            validate_vpn_ip_packet_policy(
                &identity,
                VpnPacketDirection::Downlink,
                &ipv6_packet("2001:db9::8", "fd77::2"),
            )
            .unwrap_err(),
            VpnDataPolicyError::DestinationPolicyRejected
        );
    }

    fn identity() -> VpnIdentity {
        VpnIdentity::new(
            "client-a",
            vec![VpnCertificateFingerprint::from_sha256([1; 32])],
            true,
            Some("10.77.0.2".parse().unwrap()),
            Some("fd77::2".parse::<Ipv6Addr>().unwrap()),
            vec![
                VpnIpNetwork::v4("198.51.100.0".parse::<Ipv4Addr>().unwrap(), 24).unwrap(),
                VpnIpNetwork::v6("2001:db8::".parse::<Ipv6Addr>().unwrap(), 32).unwrap(),
            ],
            VpnIdentityLimits::default(),
        )
        .unwrap()
    }

    fn ipv4_packet(source: &str, destination: &str) -> Vec<u8> {
        let source = source.parse::<Ipv4Addr>().unwrap().octets();
        let destination = destination.parse::<Ipv4Addr>().unwrap().octets();
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv6_packet(source: &str, destination: &str) -> Vec<u8> {
        let source = source.parse::<Ipv6Addr>().unwrap().octets();
        let destination = destination.parse::<Ipv6Addr>().unwrap().octets();
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet
    }
}

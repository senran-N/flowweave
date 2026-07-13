use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    VpnIdentity, VpnIpPacketMeta, VpnPacketDirection, VpnPacketError, inspect_vpn_ip_packet,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnDataPolicyError {
    Packet(VpnPacketError),
    UplinkSourceSpoofed,
    DestinationPolicyRejected,
    DownlinkDestinationMismatch,
}

impl fmt::Display for VpnDataPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(error) => write!(formatter, "vpn_data_policy_packet:{error}"),
            other => formatter.write_str(match other {
                Self::UplinkSourceSpoofed => "vpn_data_policy_uplink_source_spoofed",
                Self::DestinationPolicyRejected => "vpn_data_policy_destination_rejected",
                Self::DownlinkDestinationMismatch => {
                    "vpn_data_policy_downlink_destination_mismatch"
                }
                Self::Packet(_) => unreachable!(),
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

#[derive(Clone, Default)]
pub(crate) struct VpnDataPolicyMetrics {
    inner: Arc<VpnDataPolicyMetricCounters>,
}

impl VpnDataPolicyMetrics {
    pub(crate) fn snapshot(&self) -> VpnDataPolicyMetricsSnapshot {
        VpnDataPolicyMetricsSnapshot {
            forwarded_uplink_packets: self.inner.forwarded_uplink_packets.load(Ordering::Relaxed),
            forwarded_uplink_bytes: self.inner.forwarded_uplink_bytes.load(Ordering::Relaxed),
            forwarded_downlink_packets: self
                .inner
                .forwarded_downlink_packets
                .load(Ordering::Relaxed),
            forwarded_downlink_bytes: self.inner.forwarded_downlink_bytes.load(Ordering::Relaxed),
            malformed_packet_rejections: self
                .inner
                .malformed_packet_rejections
                .load(Ordering::Relaxed),
            uplink_source_spoof_rejections: self
                .inner
                .uplink_source_spoof_rejections
                .load(Ordering::Relaxed),
            destination_policy_rejections: self
                .inner
                .destination_policy_rejections
                .load(Ordering::Relaxed),
            downlink_destination_rejections: self
                .inner
                .downlink_destination_rejections
                .load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record(
        &self,
        direction: VpnPacketDirection,
        packet_len: usize,
        result: &Result<VpnIpPacketMeta, VpnDataPolicyError>,
    ) {
        match result {
            Ok(_) => {
                let bytes = u64::try_from(packet_len).unwrap_or(u64::MAX);
                match direction {
                    VpnPacketDirection::Uplink => {
                        increment(&self.inner.forwarded_uplink_packets);
                        add(&self.inner.forwarded_uplink_bytes, bytes);
                    }
                    VpnPacketDirection::Downlink => {
                        increment(&self.inner.forwarded_downlink_packets);
                        add(&self.inner.forwarded_downlink_bytes, bytes);
                    }
                }
            }
            Err(VpnDataPolicyError::Packet(_)) => {
                increment(&self.inner.malformed_packet_rejections);
            }
            Err(VpnDataPolicyError::UplinkSourceSpoofed) => {
                increment(&self.inner.uplink_source_spoof_rejections);
            }
            Err(VpnDataPolicyError::DestinationPolicyRejected) => {
                increment(&self.inner.destination_policy_rejections);
            }
            Err(VpnDataPolicyError::DownlinkDestinationMismatch) => {
                increment(&self.inner.downlink_destination_rejections);
            }
        }
    }

    pub(crate) fn record_malformed_packet(&self) {
        increment(&self.inner.malformed_packet_rejections);
    }
}

#[derive(Default)]
struct VpnDataPolicyMetricCounters {
    forwarded_uplink_packets: AtomicU64,
    forwarded_uplink_bytes: AtomicU64,
    forwarded_downlink_packets: AtomicU64,
    forwarded_downlink_bytes: AtomicU64,
    malformed_packet_rejections: AtomicU64,
    uplink_source_spoof_rejections: AtomicU64,
    destination_policy_rejections: AtomicU64,
    downlink_destination_rejections: AtomicU64,
}

fn increment(counter: &AtomicU64) {
    add(counter, 1);
}

fn add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
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

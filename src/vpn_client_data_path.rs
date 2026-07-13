use std::{error::Error, fmt, sync::Arc, time::Instant};

use crate::{
    VPN_DEFAULT_GLOBAL_INFLIGHT_PACKETS, VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES,
    VPN_MAX_GLOBAL_INFLIGHT_PACKETS, VPN_MAX_GLOBAL_REASSEMBLY_BYTES, VPN_MAX_IP_PACKET_LEN,
    VpnAccept, VpnControlError, VpnDataPathHandle, VpnDataPolicy, VpnDataPolicyMetricsSnapshot,
    VpnIdentityError, VpnIdentityLimits, VpnIpNetwork, VpnPacketError, VpnQuotaMetricsSnapshot,
    vpn_data_policy::VpnDataPolicyMetrics,
    vpn_quota::{VpnGlobalReassemblyBudget, VpnIdentityRateLimiter, VpnQuotaMetrics},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientDataPathConfigError {
    InvalidGlobalReassemblyBytes,
    InvalidGlobalInflightPackets,
}

impl fmt::Display for VpnClientDataPathConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGlobalReassemblyBytes => {
                "vpn_client_data_path_invalid_global_reassembly_bytes"
            }
            Self::InvalidGlobalInflightPackets => {
                "vpn_client_data_path_invalid_global_inflight_packets"
            }
        })
    }
}

impl Error for VpnClientDataPathConfigError {}

#[derive(Clone, PartialEq, Eq)]
pub struct VpnClientDataPathConfig {
    allowed_destinations: Vec<VpnIpNetwork>,
    limits: VpnIdentityLimits,
    global_reassembly_bytes: usize,
    global_inflight_packets: usize,
}

impl VpnClientDataPathConfig {
    pub fn new(allowed_destinations: Vec<VpnIpNetwork>, limits: VpnIdentityLimits) -> Self {
        Self {
            allowed_destinations,
            limits,
            global_reassembly_bytes: VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES,
            global_inflight_packets: VPN_DEFAULT_GLOBAL_INFLIGHT_PACKETS,
        }
    }

    pub fn with_global_reassembly_limits(
        mut self,
        bytes: usize,
        packets: usize,
    ) -> Result<Self, VpnClientDataPathConfigError> {
        self.global_reassembly_bytes = bytes;
        self.global_inflight_packets = packets;
        self.validate()?;
        Ok(self)
    }

    pub fn allowed_destinations(&self) -> &[VpnIpNetwork] {
        &self.allowed_destinations
    }

    pub const fn limits(&self) -> VpnIdentityLimits {
        self.limits
    }

    pub const fn global_reassembly_bytes(&self) -> usize {
        self.global_reassembly_bytes
    }

    pub const fn global_inflight_packets(&self) -> usize {
        self.global_inflight_packets
    }

    fn validate(&self) -> Result<(), VpnClientDataPathConfigError> {
        if !(VPN_MAX_IP_PACKET_LEN..=VPN_MAX_GLOBAL_REASSEMBLY_BYTES)
            .contains(&self.global_reassembly_bytes)
        {
            return Err(VpnClientDataPathConfigError::InvalidGlobalReassemblyBytes);
        }
        if self.global_inflight_packets == 0
            || self.global_inflight_packets > VPN_MAX_GLOBAL_INFLIGHT_PACKETS
        {
            return Err(VpnClientDataPathConfigError::InvalidGlobalInflightPackets);
        }
        Ok(())
    }
}

impl fmt::Debug for VpnClientDataPathConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnClientDataPathConfig")
            .field(
                "destination_network_count",
                &self.allowed_destinations.len(),
            )
            .field("limits", &self.limits)
            .field("global_reassembly_bytes", &self.global_reassembly_bytes)
            .field("global_inflight_packets", &self.global_inflight_packets)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientDataPathError {
    InvalidAccept(VpnControlError),
    InvalidPolicy(VpnIdentityError),
    DataPath(VpnPacketError),
}

impl fmt::Display for VpnClientDataPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAccept(error) => write!(formatter, "vpn_client_data_path_accept:{error}"),
            Self::InvalidPolicy(error) => write!(formatter, "vpn_client_data_path_policy:{error}"),
            Self::DataPath(error) => write!(formatter, "vpn_client_data_path_core:{error}"),
        }
    }
}

impl Error for VpnClientDataPathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidAccept(error) => Some(error),
            Self::InvalidPolicy(error) => Some(error),
            Self::DataPath(error) => Some(error),
        }
    }
}

#[derive(Clone)]
pub struct VpnClientDataPathFactory {
    config: VpnClientDataPathConfig,
    rate_limiter: Arc<VpnIdentityRateLimiter>,
    global_budget: VpnGlobalReassemblyBudget,
    quota_metrics: VpnQuotaMetrics,
    policy_metrics: VpnDataPolicyMetrics,
}

impl VpnClientDataPathFactory {
    pub fn new(config: VpnClientDataPathConfig) -> Result<Self, VpnClientDataPathConfigError> {
        Self::new_at(config, Instant::now())
    }

    fn new_at(
        config: VpnClientDataPathConfig,
        now: Instant,
    ) -> Result<Self, VpnClientDataPathConfigError> {
        config.validate()?;
        let quota_metrics = VpnQuotaMetrics::default();
        let global_budget = VpnGlobalReassemblyBudget::new(
            config.global_reassembly_bytes,
            config.global_inflight_packets,
            quota_metrics.clone(),
        )
        .ok_or_else(|| {
            if !(VPN_MAX_IP_PACKET_LEN..=VPN_MAX_GLOBAL_REASSEMBLY_BYTES)
                .contains(&config.global_reassembly_bytes)
            {
                VpnClientDataPathConfigError::InvalidGlobalReassemblyBytes
            } else {
                VpnClientDataPathConfigError::InvalidGlobalInflightPackets
            }
        })?;
        let rate_limiter = Arc::new(VpnIdentityRateLimiter::new(
            config.limits,
            now,
            quota_metrics.clone(),
        ));
        Ok(Self {
            config,
            rate_limiter,
            global_budget,
            quota_metrics,
            policy_metrics: VpnDataPolicyMetrics::default(),
        })
    }

    pub fn build(&self, accept: VpnAccept) -> Result<VpnDataPathHandle, VpnClientDataPathError> {
        accept
            .validate()
            .map_err(VpnClientDataPathError::InvalidAccept)?;
        let policy = VpnDataPolicy::new(
            accept.client_ipv4,
            accept.client_ipv6,
            self.config.allowed_destinations.clone(),
        )
        .map_err(VpnClientDataPathError::InvalidPolicy)?;
        let handle = VpnDataPathHandle::new_policy_inactive(
            policy,
            self.config.limits,
            usize::from(accept.max_ip_packet_len),
            accept.session_generation,
            self.rate_limiter.clone(),
            self.global_budget.clone(),
            self.quota_metrics.clone(),
            self.policy_metrics.clone(),
        )
        .map_err(VpnClientDataPathError::DataPath)?;
        handle.activate();
        Ok(handle)
    }

    pub fn config(&self) -> &VpnClientDataPathConfig {
        &self.config
    }

    pub fn quota_metrics_snapshot(&self) -> VpnQuotaMetricsSnapshot {
        self.quota_metrics.snapshot()
    }

    pub fn data_policy_metrics_snapshot(&self) -> VpnDataPolicyMetricsSnapshot {
        self.policy_metrics.snapshot()
    }
}

impl fmt::Debug for VpnClientDataPathFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnClientDataPathFactory")
            .field("config", &self.config)
            .field("quota", &self.quota_metrics.snapshot())
            .field("policy", &self.policy_metrics.snapshot())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{
        VPN_CAP_FRAGMENTATION, VPN_CAP_IPV4, VPN_CAP_IPV6, VPN_CAP_MULTIPATH_REQUIRED,
        VPN_WIRE_VERSION_V1, VpnDataPathError, VpnPacketDirection,
    };

    use super::*;

    #[test]
    fn builds_active_client_path_from_accept_without_fake_identity() {
        let accept = valid_accept(VPN_CAP_IPV4 | VPN_CAP_IPV6);
        let factory = VpnClientDataPathFactory::new_at(
            VpnClientDataPathConfig::new(
                vec![
                    VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                    VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
                ],
                VpnIdentityLimits::default(),
            ),
            Instant::now(),
        )
        .unwrap();
        let handle = factory.build(accept).unwrap();

        let snapshot = handle.snapshot();
        assert!(snapshot.active);
        assert_eq!(snapshot.session_generation, accept.session_generation);
        let packet = ipv4_packet(1280, "10.77.0.2", "198.51.100.8");
        assert_eq!(
            handle
                .encode_ip_packet(
                    VpnPacketDirection::Uplink,
                    1,
                    &packet,
                    usize::from(accept.max_datagram_len),
                    Instant::now(),
                )
                .unwrap()
                .len(),
            2
        );
        let oversized = ipv4_packet(1281, "10.77.0.2", "198.51.100.8");
        assert_eq!(
            handle
                .encode_ip_packet(
                    VpnPacketDirection::Uplink,
                    2,
                    &oversized,
                    usize::from(accept.max_datagram_len),
                    Instant::now(),
                )
                .unwrap_err(),
            VpnDataPathError::NegotiatedPacketTooLarge
        );
    }

    #[test]
    fn rejects_invalid_accept_family_mismatch_and_duplicate_acl() {
        let ipv4_factory = VpnClientDataPathFactory::new_at(
            VpnClientDataPathConfig::new(
                vec![VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap()],
                VpnIdentityLimits::default(),
            ),
            Instant::now(),
        )
        .unwrap();
        let mut invalid_accept = valid_accept(VPN_CAP_IPV4);
        invalid_accept.session_generation = 0;
        assert_eq!(
            ipv4_factory.build(invalid_accept).unwrap_err(),
            VpnClientDataPathError::InvalidAccept(VpnControlError::InvalidAccept)
        );

        let ipv6_network = VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).unwrap();
        let ipv6_factory = VpnClientDataPathFactory::new_at(
            VpnClientDataPathConfig::new(vec![ipv6_network], VpnIdentityLimits::default()),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(
            ipv6_factory.build(valid_accept(VPN_CAP_IPV4)).unwrap_err(),
            VpnClientDataPathError::InvalidPolicy(VpnIdentityError::AddressFamilyUnavailable)
        );

        let ipv4_network = VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        let duplicate_factory = VpnClientDataPathFactory::new_at(
            VpnClientDataPathConfig::new(
                vec![ipv4_network, ipv4_network],
                VpnIdentityLimits::default(),
            ),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(
            duplicate_factory
                .build(valid_accept(VPN_CAP_IPV4))
                .unwrap_err(),
            VpnClientDataPathError::InvalidPolicy(VpnIdentityError::DuplicateDestinationNetwork)
        );
    }

    #[test]
    fn rejects_invalid_global_resource_limits_even_if_config_is_constructed_internally() {
        let network = VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        let mut invalid_bytes =
            VpnClientDataPathConfig::new(vec![network], VpnIdentityLimits::default());
        invalid_bytes.global_reassembly_bytes = VPN_MAX_IP_PACKET_LEN - 1;
        assert_eq!(
            VpnClientDataPathFactory::new_at(invalid_bytes, Instant::now()).unwrap_err(),
            VpnClientDataPathConfigError::InvalidGlobalReassemblyBytes
        );

        let mut invalid_packets =
            VpnClientDataPathConfig::new(vec![network], VpnIdentityLimits::default());
        invalid_packets.global_inflight_packets = 0;
        assert_eq!(
            VpnClientDataPathFactory::new_at(invalid_packets, Instant::now()).unwrap_err(),
            VpnClientDataPathConfigError::InvalidGlobalInflightPackets
        );
    }

    #[test]
    fn reconnect_generations_share_client_rate_and_global_budgets() {
        let started = Instant::now();
        let network = VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        let rate_factory = VpnClientDataPathFactory::new_at(
            VpnClientDataPathConfig::new(
                vec![network],
                VpnIdentityLimits::new(1, 1, 1_000_000, VPN_MAX_IP_PACKET_LEN).unwrap(),
            ),
            started,
        )
        .unwrap();
        let first = rate_factory.build(valid_accept(VPN_CAP_IPV4)).unwrap();
        let mut replacement_accept = valid_accept(VPN_CAP_IPV4);
        replacement_accept.session_generation = 8;
        let replacement = rate_factory.build(replacement_accept).unwrap();
        assert_eq!(
            first
                .ingest_datagram(VpnPacketDirection::Uplink, &[0], started)
                .unwrap_err(),
            crate::VpnDataPathError::Fragment(crate::VpnPacketError::FragmentEmpty)
        );
        assert_eq!(
            replacement
                .ingest_datagram(VpnPacketDirection::Uplink, &[0], started)
                .unwrap_err(),
            crate::VpnDataPathError::Quota(crate::VpnQuotaRejection::PacketRateExceeded)
        );

        let global_factory = VpnClientDataPathFactory::new_at(
            VpnClientDataPathConfig::new(vec![network], VpnIdentityLimits::default())
                .with_global_reassembly_limits(VPN_MAX_IP_PACKET_LEN, 1)
                .unwrap(),
            started,
        )
        .unwrap();
        let first = global_factory.build(valid_accept(VPN_CAP_IPV4)).unwrap();
        let replacement = global_factory.build(replacement_accept).unwrap();
        let partial = raw_fragment(1, 1280, 0, &[0x44; 100]);
        first
            .ingest_datagram(VpnPacketDirection::Uplink, &partial, started)
            .unwrap();
        assert_eq!(
            replacement
                .ingest_datagram(
                    VpnPacketDirection::Uplink,
                    &raw_fragment(2, 1280, 0, &[0x45; 100]),
                    started,
                )
                .unwrap_err(),
            crate::VpnDataPathError::Quota(crate::VpnQuotaRejection::GlobalInflightLimit)
        );
        assert_eq!(
            global_factory
                .quota_metrics_snapshot()
                .current_reassembly_bytes,
            100
        );
        assert_eq!(
            global_factory
                .quota_metrics_snapshot()
                .active_reassembly_packets,
            1
        );
        first.deactivate();
        assert_eq!(
            global_factory
                .quota_metrics_snapshot()
                .current_reassembly_bytes,
            0
        );
        assert_eq!(
            global_factory
                .quota_metrics_snapshot()
                .active_reassembly_packets,
            0
        );
    }

    #[test]
    fn config_debug_redacts_destination_networks() {
        let config = VpnClientDataPathConfig::new(
            vec![
                VpnIpNetwork::v4("198.51.100.0".parse().unwrap(), 24).unwrap(),
                VpnIpNetwork::v6("2001:db8::".parse().unwrap(), 32).unwrap(),
            ],
            VpnIdentityLimits::default(),
        );
        let debug = format!("{config:?}");
        assert!(debug.contains("destination_network_count: 2"));
        assert!(!debug.contains("198.51.100"));
        assert!(!debug.contains("2001:db8"));
    }

    fn valid_accept(address_capabilities: u32) -> VpnAccept {
        VpnAccept {
            selected_wire_version: VPN_WIRE_VERSION_V1,
            capabilities: VPN_CAP_FRAGMENTATION | VPN_CAP_MULTIPATH_REQUIRED | address_capabilities,
            max_ip_packet_len: 1280,
            max_datagram_len: 1200,
            session_generation: 7,
            client_ipv4: (address_capabilities & VPN_CAP_IPV4 != 0)
                .then_some("10.77.0.2".parse().unwrap()),
            server_ipv4: (address_capabilities & VPN_CAP_IPV4 != 0)
                .then_some("10.77.0.1".parse().unwrap()),
            client_ipv6: (address_capabilities & VPN_CAP_IPV6 != 0)
                .then_some("fd77::2".parse().unwrap()),
            server_ipv6: (address_capabilities & VPN_CAP_IPV6 != 0)
                .then_some("fd77::1".parse().unwrap()),
        }
    }

    fn ipv4_packet(len: usize, source: &str, destination: &str) -> Vec<u8> {
        let source = source.parse::<Ipv4Addr>().unwrap().octets();
        let destination = destination.parse::<Ipv4Addr>().unwrap().octets();
        let mut packet = vec![0x5a; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn raw_fragment(packet_id: u32, total_len: usize, offset: usize, payload: &[u8]) -> Vec<u8> {
        let mut datagram = Vec::with_capacity(crate::VPN_IP_DATAGRAM_HEADER_LEN + payload.len());
        datagram.extend_from_slice(crate::VPN_IP_DATAGRAM_MAGIC);
        datagram.extend_from_slice(&packet_id.to_be_bytes());
        datagram.extend_from_slice(&(total_len as u16).to_be_bytes());
        datagram.extend_from_slice(&(offset as u16).to_be_bytes());
        datagram.extend_from_slice(payload);
        datagram
    }
}

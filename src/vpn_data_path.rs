use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use crate::{
    VpnDataPolicyError, VpnDataPolicyMetricsSnapshot, VpnIdentity, VpnIpPacketMeta,
    VpnPacketDirection, VpnPacketError, VpnQuotaMetricsSnapshot, VpnQuotaRejection, VpnReassembler,
    VpnReassemblyLimits, VpnReassemblyStats, decode_vpn_ip_fragment, encode_vpn_ip_fragments,
    validate_vpn_ip_packet_policy,
    vpn::{VPN_DEFAULT_FRAGMENT_TIMEOUT, VPN_DEFAULT_MAX_INFLIGHT_PACKETS},
    vpn_data_policy::VpnDataPolicyMetrics,
    vpn_quota::{VpnGlobalReassemblyBudget, VpnIdentityRateLimiter, VpnQuotaMetrics},
};

#[derive(PartialEq, Eq)]
pub struct VpnDataPacket {
    bytes: Vec<u8>,
    metadata: VpnIpPacketMeta,
}

impl fmt::Debug for VpnDataPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnDataPacket")
            .field("len", &self.bytes.len())
            .field("metadata", &"[redacted]")
            .finish()
    }
}

impl VpnDataPacket {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub const fn metadata(&self) -> VpnIpPacketMeta {
        self.metadata
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnDataPathError {
    StaleGeneration,
    Quota(VpnQuotaRejection),
    Fragment(VpnPacketError),
    Policy(VpnDataPolicyError),
    ResourceAccountingInvariant,
}

impl fmt::Display for VpnDataPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleGeneration => formatter.write_str("vpn_data_path_stale_generation"),
            Self::Quota(error) => write!(formatter, "vpn_data_path_quota:{error}"),
            Self::Fragment(error) => write!(formatter, "vpn_data_path_fragment:{error}"),
            Self::Policy(error) => write!(formatter, "vpn_data_path_policy:{error}"),
            Self::ResourceAccountingInvariant => {
                formatter.write_str("vpn_data_path_resource_accounting_invariant")
            }
        }
    }
}

impl Error for VpnDataPathError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnDataPathSnapshot {
    pub session_generation: u64,
    pub active: bool,
    pub buffered_reassembly_bytes: usize,
    pub inflight_reassembly_packets: usize,
    pub uplink_reassembly: VpnReassemblyStats,
    pub downlink_reassembly: VpnReassemblyStats,
}

#[derive(Clone)]
pub struct VpnDataPathHandle {
    inner: Arc<VpnDataPathInner>,
}

impl VpnDataPathHandle {
    pub(crate) fn new_inactive(
        identity: VpnIdentity,
        session_generation: u64,
        rate_limiter: Arc<VpnIdentityRateLimiter>,
        global_budget: VpnGlobalReassemblyBudget,
        quota_metrics: VpnQuotaMetrics,
        policy_metrics: VpnDataPolicyMetrics,
    ) -> Result<Self, VpnPacketError> {
        let limits = VpnReassemblyLimits {
            max_inflight_packets: VPN_DEFAULT_MAX_INFLIGHT_PACKETS,
            max_buffered_bytes: identity.limits().max_reassembly_bytes(),
            fragment_timeout: VPN_DEFAULT_FRAGMENT_TIMEOUT,
        };
        Ok(Self {
            inner: Arc::new(VpnDataPathInner {
                identity,
                session_generation,
                rate_limiter,
                global_budget,
                quota_metrics,
                policy_metrics,
                runtime_bound: AtomicBool::new(false),
                state: Mutex::new(VpnDataPathState {
                    active: false,
                    uplink: VpnReassembler::new(limits)?,
                    downlink: VpnReassembler::new(limits)?,
                    accounted_bytes: 0,
                    accounted_packets: 0,
                }),
            }),
        })
    }

    pub fn session_generation(&self) -> u64 {
        self.inner.session_generation
    }

    pub fn encode_ip_packet(
        &self,
        direction: VpnPacketDirection,
        packet_id: u32,
        packet: &[u8],
        max_datagram_len: usize,
        now: Instant,
    ) -> Result<Vec<Vec<u8>>, VpnDataPathError> {
        let state = self.lock_state();
        if !state.active {
            self.inner.quota_metrics.record_stale_generation();
            return Err(VpnDataPathError::StaleGeneration);
        }

        let policy = validate_vpn_ip_packet_policy(&self.inner.identity, direction, packet);
        let metadata = match policy {
            Ok(metadata) => metadata,
            Err(error) => {
                self.inner
                    .policy_metrics
                    .record(direction, packet.len(), &Err(error));
                return Err(VpnDataPathError::Policy(error));
            }
        };
        let fragments = encode_vpn_ip_fragments(packet_id, packet, max_datagram_len)
            .map_err(VpnDataPathError::Fragment)?;
        let lengths = fragments.iter().map(Vec::len).collect::<Vec<_>>();
        self.inner
            .rate_limiter
            .admit_datagrams(direction, &lengths, now)
            .map_err(VpnDataPathError::Quota)?;
        self.inner
            .policy_metrics
            .record(direction, packet.len(), &Ok(metadata));
        drop(state);
        Ok(fragments)
    }

    pub fn ingest_datagram(
        &self,
        direction: VpnPacketDirection,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Option<VpnDataPacket>, VpnDataPathError> {
        let mut state = self.lock_state();
        if !state.active {
            self.inner.quota_metrics.record_stale_generation();
            return Err(VpnDataPathError::StaleGeneration);
        }
        self.inner
            .rate_limiter
            .admit_datagram(direction, datagram.len(), now)
            .map_err(VpnDataPathError::Quota)?;

        state.expire(now);
        if !self.reconcile_shrink(&mut state) {
            return Err(self.fail_accounting(&mut state));
        }

        let fragment = match decode_vpn_ip_fragment(datagram) {
            Ok(fragment) => fragment,
            Err(expected) => {
                let actual = state.reassembler_mut(direction).ingest(now, datagram);
                if !self.reconcile_shrink(&mut state) {
                    return Err(self.fail_accounting(&mut state));
                }
                return Err(VpnDataPathError::Fragment(actual.err().unwrap_or(expected)));
            }
        };
        let existing_packet = state
            .reassembler(direction)
            .contains_packet(fragment.packet_id);
        let additional_bytes = state
            .reassembler(direction)
            .additional_buffered_bytes(fragment);

        let result = match additional_bytes {
            Ok(0) => {
                let result = state.reassembler_mut(direction).ingest(now, datagram);
                if !self.reconcile_shrink(&mut state) {
                    return Err(self.fail_accounting(&mut state));
                }
                result
            }
            Ok(additional_bytes) => {
                let completes_packet = state
                    .reassembler(direction)
                    .fragment_will_complete(fragment);
                if let Err(error) = self.make_identity_room(
                    &mut state,
                    direction,
                    fragment.packet_id,
                    existing_packet,
                    if completes_packet {
                        0
                    } else {
                        additional_bytes
                    },
                    usize::from(!existing_packet && !completes_packet),
                ) {
                    return Err(VpnDataPathError::Quota(error));
                }
                if !self.reconcile_shrink(&mut state) {
                    return Err(self.fail_accounting(&mut state));
                }

                let additional_packets = usize::from(!existing_packet);
                let reservation = self
                    .inner
                    .global_budget
                    .try_reserve(additional_bytes, additional_packets)
                    .map_err(VpnDataPathError::Quota)?;
                let result = state.reassembler_mut(direction).ingest(now, datagram);
                let (actual_bytes, actual_packets) = state.usage();
                let mut accounted_bytes = state.accounted_bytes;
                let mut accounted_packets = state.accounted_packets;
                if !reservation.reconcile(
                    &mut accounted_bytes,
                    &mut accounted_packets,
                    actual_bytes,
                    actual_packets,
                ) {
                    return Err(self.fail_accounting(&mut state));
                }
                state.accounted_bytes = accounted_bytes;
                state.accounted_packets = accounted_packets;
                result
            }
            Err(_) => {
                let result = state.reassembler_mut(direction).ingest(now, datagram);
                if !self.reconcile_shrink(&mut state) {
                    return Err(self.fail_accounting(&mut state));
                }
                result
            }
        };
        drop(state);

        match result {
            Ok(Some(packet)) => {
                let policy =
                    validate_vpn_ip_packet_policy(&self.inner.identity, direction, &packet);
                self.inner
                    .policy_metrics
                    .record(direction, packet.len(), &policy);
                let metadata = policy.map_err(VpnDataPathError::Policy)?;
                Ok(Some(VpnDataPacket {
                    bytes: packet,
                    metadata,
                }))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                if matches!(
                    error,
                    VpnPacketError::InvalidIpVersion
                        | VpnPacketError::InvalidIpv4Header
                        | VpnPacketError::InvalidIpv4Length
                        | VpnPacketError::InvalidIpv6Length
                        | VpnPacketError::Ipv6JumbogramUnsupported
                ) {
                    self.inner.policy_metrics.record_malformed_packet();
                }
                Err(VpnDataPathError::Fragment(error))
            }
        }
    }

    pub fn expire_reassembly(&self, now: Instant) -> usize {
        let mut state = self.lock_state();
        let before = state.inflight_packets();
        state.expire(now);
        if !self.reconcile_shrink(&mut state) {
            let _ = self.fail_accounting(&mut state);
        }
        before.saturating_sub(state.inflight_packets())
    }

    pub fn snapshot(&self) -> VpnDataPathSnapshot {
        let state = self.lock_state();
        VpnDataPathSnapshot {
            session_generation: self.inner.session_generation,
            active: state.active,
            buffered_reassembly_bytes: state.buffered_bytes(),
            inflight_reassembly_packets: state.inflight_packets(),
            uplink_reassembly: state.uplink.stats(),
            downlink_reassembly: state.downlink.stats(),
        }
    }

    pub fn quota_metrics_snapshot(&self) -> VpnQuotaMetricsSnapshot {
        self.inner.quota_metrics.snapshot()
    }

    pub fn data_policy_metrics_snapshot(&self) -> VpnDataPolicyMetricsSnapshot {
        self.inner.policy_metrics.snapshot()
    }

    pub(crate) fn activate(&self) {
        self.lock_state().active = true;
    }

    pub(crate) fn deactivate(&self) {
        let mut state = self.lock_state();
        state.active = false;
        state.clear();
        self.release_all_accounted(&mut state);
    }

    pub(crate) fn try_bind_runtime(&self) -> bool {
        self.inner
            .runtime_bound
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn unbind_runtime(&self) {
        self.inner.runtime_bound.store(false, Ordering::Release);
    }

    fn make_identity_room(
        &self,
        state: &mut VpnDataPathState,
        direction: VpnPacketDirection,
        packet_id: u32,
        existing_packet: bool,
        additional_bytes: usize,
        additional_packets: usize,
    ) -> Result<(), VpnQuotaRejection> {
        let byte_limit = self.inner.identity.limits().max_reassembly_bytes();
        loop {
            let count_exceeded = state
                .inflight_packets()
                .checked_add(additional_packets)
                .is_none_or(|count| count > VPN_DEFAULT_MAX_INFLIGHT_PACKETS);
            let bytes_exceeded = state
                .buffered_bytes()
                .checked_add(additional_bytes)
                .is_none_or(|bytes| bytes > byte_limit);
            if !count_exceeded && !bytes_exceeded {
                return Ok(());
            }

            if !state.evict_oldest(direction, packet_id, existing_packet) {
                if count_exceeded {
                    self.inner
                        .quota_metrics
                        .record_identity_inflight_rejection();
                    return Err(VpnQuotaRejection::IdentityInflightLimit);
                }
                self.inner
                    .quota_metrics
                    .record_identity_reassembly_rejection();
                return Err(VpnQuotaRejection::IdentityReassemblyLimit);
            }
        }
    }

    fn reconcile_shrink(&self, state: &mut VpnDataPathState) -> bool {
        let (actual_bytes, actual_packets) = state.usage();
        if actual_bytes > state.accounted_bytes || actual_packets > state.accounted_packets {
            return false;
        }
        self.inner.global_budget.release_accounted(
            state.accounted_bytes - actual_bytes,
            state.accounted_packets - actual_packets,
        );
        state.accounted_bytes = actual_bytes;
        state.accounted_packets = actual_packets;
        true
    }

    fn fail_accounting(&self, state: &mut VpnDataPathState) -> VpnDataPathError {
        state.clear();
        self.release_all_accounted(state);
        VpnDataPathError::ResourceAccountingInvariant
    }

    fn release_all_accounted(&self, state: &mut VpnDataPathState) {
        self.inner
            .global_budget
            .release_accounted(state.accounted_bytes, state.accounted_packets);
        state.accounted_bytes = 0;
        state.accounted_packets = 0;
    }

    fn lock_state(&self) -> MutexGuard<'_, VpnDataPathState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for VpnDataPathHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnDataPathHandle")
            .field("client_id", &"[redacted]")
            .field("session_generation", &self.inner.session_generation)
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

struct VpnDataPathInner {
    identity: VpnIdentity,
    session_generation: u64,
    rate_limiter: Arc<VpnIdentityRateLimiter>,
    global_budget: VpnGlobalReassemblyBudget,
    quota_metrics: VpnQuotaMetrics,
    policy_metrics: VpnDataPolicyMetrics,
    runtime_bound: AtomicBool,
    state: Mutex<VpnDataPathState>,
}

impl Drop for VpnDataPathInner {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.global_budget
            .release_accounted(state.accounted_bytes, state.accounted_packets);
        state.accounted_bytes = 0;
        state.accounted_packets = 0;
    }
}

struct VpnDataPathState {
    active: bool,
    uplink: VpnReassembler,
    downlink: VpnReassembler,
    accounted_bytes: usize,
    accounted_packets: usize,
}

impl VpnDataPathState {
    fn reassembler(&self, direction: VpnPacketDirection) -> &VpnReassembler {
        match direction {
            VpnPacketDirection::Uplink => &self.uplink,
            VpnPacketDirection::Downlink => &self.downlink,
        }
    }

    fn reassembler_mut(&mut self, direction: VpnPacketDirection) -> &mut VpnReassembler {
        match direction {
            VpnPacketDirection::Uplink => &mut self.uplink,
            VpnPacketDirection::Downlink => &mut self.downlink,
        }
    }

    fn buffered_bytes(&self) -> usize {
        self.uplink
            .buffered_bytes()
            .saturating_add(self.downlink.buffered_bytes())
    }

    fn inflight_packets(&self) -> usize {
        self.uplink
            .inflight_packets()
            .saturating_add(self.downlink.inflight_packets())
    }

    fn usage(&self) -> (usize, usize) {
        (self.buffered_bytes(), self.inflight_packets())
    }

    fn expire(&mut self, now: Instant) {
        self.uplink.expire(now);
        self.downlink.expire(now);
    }

    fn clear(&mut self) {
        self.uplink.clear();
        self.downlink.clear();
    }

    fn evict_oldest(
        &mut self,
        direction: VpnPacketDirection,
        packet_id: u32,
        existing_packet: bool,
    ) -> bool {
        let uplink_excluded =
            (direction == VpnPacketDirection::Uplink && existing_packet).then_some(packet_id);
        let downlink_excluded =
            (direction == VpnPacketDirection::Downlink && existing_packet).then_some(packet_id);
        let uplink = self.uplink.oldest_packet_updated_at(uplink_excluded);
        let downlink = self.downlink.oldest_packet_updated_at(downlink_excluded);
        match (uplink, downlink) {
            (Some((packet_id, _)), None) => self.uplink.evict_packet(packet_id),
            (None, Some((packet_id, _))) => self.downlink.evict_packet(packet_id),
            (Some((uplink_id, uplink_at)), Some((downlink_id, downlink_at))) => {
                if uplink_at <= downlink_at {
                    self.uplink.evict_packet(uplink_id)
                } else {
                    self.downlink.evict_packet(downlink_id)
                }
            }
            (None, None) => false,
        }
    }
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_vpn_data_path(input: &[u8]) {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{
        VPN_MAX_BYTES_PER_SECOND, VPN_MAX_IP_PACKET_LEN, VPN_MAX_PACKETS_PER_SECOND,
        VpnCertificateFingerprint, VpnIdentityLimits, VpnIpNetwork,
    };

    let started = Instant::now();
    let limits = VpnIdentityLimits::new(
        1,
        VPN_MAX_PACKETS_PER_SECOND,
        VPN_MAX_BYTES_PER_SECOND,
        4 * VPN_MAX_IP_PACKET_LEN,
    )
    .expect("fixed fuzz limits are valid");
    let identity = VpnIdentity::new(
        "fuzz-client",
        vec![VpnCertificateFingerprint::from_sha256([0xa5; 32])],
        true,
        Some("10.77.0.2".parse().expect("fixed IPv4 address")),
        Some("fd77::2".parse().expect("fixed IPv6 address")),
        vec![
            VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).expect("fixed IPv4 network"),
            VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).expect("fixed IPv6 network"),
        ],
        limits,
    )
    .expect("fixed fuzz identity is valid");
    let quota_metrics = VpnQuotaMetrics::default();
    let policy_metrics = VpnDataPolicyMetrics::default();
    let budget =
        VpnGlobalReassemblyBudget::new(8 * VPN_MAX_IP_PACKET_LEN, 2048, quota_metrics.clone())
            .expect("fixed fuzz global limits are valid");
    let rate_limiter = Arc::new(VpnIdentityRateLimiter::new(
        limits,
        started,
        quota_metrics.clone(),
    ));
    let handle = VpnDataPathHandle::new_inactive(
        identity,
        1,
        rate_limiter,
        budget,
        quota_metrics.clone(),
        policy_metrics,
    )
    .expect("fixed fuzz data path is valid");
    handle.activate();

    for (sequence, datagram) in input.chunks(2048).take(256).enumerate() {
        let direction = if sequence % 2 == 0 {
            VpnPacketDirection::Uplink
        } else {
            VpnPacketDirection::Downlink
        };
        let now = started + std::time::Duration::from_millis(sequence as u64);
        let _ = handle.ingest_datagram(direction, datagram, now);
        let path = handle.snapshot();
        let global = quota_metrics.snapshot();
        assert!(path.buffered_reassembly_bytes <= limits.max_reassembly_bytes());
        assert!(path.inflight_reassembly_packets <= VPN_DEFAULT_MAX_INFLIGHT_PACKETS);
        assert_eq!(
            global.current_reassembly_bytes,
            path.buffered_reassembly_bytes
        );
        assert_eq!(
            global.active_reassembly_packets,
            path.inflight_reassembly_packets
        );
    }

    handle.deactivate();
    let global = quota_metrics.snapshot();
    assert_eq!(global.current_reassembly_bytes, 0);
    assert_eq!(global.active_reassembly_packets, 0);
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::{Arc, mpsc},
        time::Duration,
    };

    use crate::{
        VPN_MAX_IP_PACKET_LEN, VpnCertificateFingerprint, VpnIdentityLimits, VpnIpNetwork,
        encode_vpn_ip_fragments,
    };

    use super::*;

    #[test]
    fn packet_debug_redacts_payload_and_addresses() {
        let packet = VpnDataPacket {
            bytes: b"FLOWWEAVE_PRIVATE_PAYLOAD".to_vec(),
            metadata: VpnIpPacketMeta {
                source: "10.77.0.2".parse().unwrap(),
                destination: "198.51.100.8".parse().unwrap(),
            },
        };
        let debug = format!("{packet:?}");
        assert!(debug.contains("len: 25"));
        assert!(!debug.contains("FLOWWEAVE_PRIVATE_PAYLOAD"));
        assert!(!debug.contains("10.77.0.2"));
        assert!(!debug.contains("198.51.100.8"));
    }

    #[test]
    fn outer_datagram_rate_limit_runs_before_fragment_parsing() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 1, 1_000_000, VPN_MAX_IP_PACKET_LEN).unwrap();
        let (handle, quota, _) = active_handle(limits, "0.0.0.0/0", 1, 8 * 1024 * 1024, 16);

        assert_eq!(
            handle
                .ingest_datagram(VpnPacketDirection::Uplink, &[0], started)
                .unwrap_err(),
            VpnDataPathError::Fragment(VpnPacketError::FragmentEmpty)
        );
        assert_eq!(handle.snapshot().uplink_reassembly.fragments_received, 1);
        assert_eq!(handle.snapshot().uplink_reassembly.fragments_rejected, 1);
        let packet = ipv4_packet(20, "10.77.0.2", "198.51.100.8", 0x11);
        let datagram = encode_vpn_ip_fragments(1, &packet, 1200).unwrap().remove(0);
        assert_eq!(
            handle
                .ingest_datagram(VpnPacketDirection::Uplink, &datagram, started)
                .unwrap_err(),
            VpnDataPathError::Quota(VpnQuotaRejection::PacketRateExceeded)
        );
        let snapshot = quota.snapshot();
        assert_eq!(snapshot.admitted_uplink_datagrams, 1);
        assert_eq!(snapshot.packet_rate_rejections, 1);
    }

    #[test]
    fn outbound_fragment_batch_is_all_or_nothing_for_rate_tokens() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 2, 1_000_000, VPN_MAX_IP_PACKET_LEN).unwrap();
        let (handle, quota, policy) = active_handle(limits, "0.0.0.0/0", 1, 8 * 1024 * 1024, 16);
        let fragmented = ipv4_packet(2500, "10.77.0.2", "198.51.100.8", 0x41);
        assert_eq!(
            handle
                .encode_ip_packet(VpnPacketDirection::Uplink, 1, &fragmented, 1200, started,)
                .unwrap_err(),
            VpnDataPathError::Quota(VpnQuotaRejection::PacketRateExceeded)
        );

        let packet = ipv4_packet(20, "10.77.0.2", "198.51.100.8", 0x42);
        assert_eq!(
            handle
                .encode_ip_packet(VpnPacketDirection::Uplink, 2, &packet, 1200, started)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            handle
                .encode_ip_packet(VpnPacketDirection::Uplink, 3, &packet, 1200, started)
                .unwrap()
                .len(),
            1
        );
        let quota = quota.snapshot();
        assert_eq!(quota.admitted_uplink_datagrams, 2);
        assert_eq!(quota.packet_rate_rejections, 1);
        assert_eq!(policy.snapshot().forwarded_uplink_packets, 2);
    }

    #[test]
    fn real_reassembler_completes_out_of_order_then_applies_policy() {
        let started = Instant::now();
        let (handle, quota, policy) = active_handle(
            VpnIdentityLimits::default(),
            "198.51.100.0/24",
            1,
            8 * 1024 * 1024,
            16,
        );
        let packet = ipv4_packet(1500, "10.77.0.2", "198.51.100.8", 0x22);
        let mut fragments = encode_vpn_ip_fragments(7, &packet, 1200).unwrap();
        fragments.reverse();
        let mut completed = None;
        for fragment in &fragments {
            if let Some(packet) = handle
                .ingest_datagram(VpnPacketDirection::Uplink, fragment, started)
                .unwrap()
            {
                assert!(completed.replace(packet).is_none());
            }
        }
        let completed = completed.unwrap();
        assert_eq!(completed.as_bytes(), packet);
        assert_eq!(
            completed.metadata().source,
            "10.77.0.2".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(quota.snapshot().current_reassembly_bytes, 0);
        assert_eq!(quota.snapshot().active_reassembly_packets, 0);
        assert_eq!(policy.snapshot().forwarded_uplink_packets, 1);
    }

    #[test]
    fn duplicates_conflicts_and_total_changes_release_exact_memory() {
        let started = Instant::now();
        let (handle, quota, _) = active_handle(
            VpnIdentityLimits::default(),
            "0.0.0.0/0",
            1,
            8 * 1024 * 1024,
            16,
        );
        let packet = ipv4_packet(1500, "10.77.0.2", "198.51.100.8", 0x33);
        let fragments = encode_vpn_ip_fragments(8, &packet, 1200).unwrap();
        let first = &fragments[0];
        handle
            .ingest_datagram(VpnPacketDirection::Uplink, first, started)
            .unwrap();
        let buffered = first.len() - crate::VPN_IP_DATAGRAM_HEADER_LEN;
        assert_eq!(quota.snapshot().current_reassembly_bytes, buffered);
        handle
            .ingest_datagram(VpnPacketDirection::Uplink, first, started)
            .unwrap();
        assert_eq!(quota.snapshot().current_reassembly_bytes, buffered);
        assert_eq!(handle.snapshot().uplink_reassembly.duplicate_fragments, 1);

        let mut conflict = first.clone();
        *conflict.last_mut().unwrap() ^= 0xff;
        assert_eq!(
            handle
                .ingest_datagram(VpnPacketDirection::Uplink, &conflict, started)
                .unwrap_err(),
            VpnDataPathError::Fragment(VpnPacketError::FragmentOverlap)
        );
        assert_eq!(quota.snapshot().current_reassembly_bytes, 0);

        handle
            .ingest_datagram(VpnPacketDirection::Uplink, first, started)
            .unwrap();
        let mut changed_total = first.clone();
        changed_total[8..10].copy_from_slice(&1499_u16.to_be_bytes());
        assert_eq!(
            handle
                .ingest_datagram(VpnPacketDirection::Uplink, &changed_total, started)
                .unwrap_err(),
            VpnDataPathError::Fragment(VpnPacketError::FragmentTotalChanged)
        );
        assert_eq!(quota.snapshot().current_reassembly_bytes, 0);
        assert_eq!(quota.snapshot().active_reassembly_packets, 0);
    }

    #[test]
    fn identity_eviction_and_timeout_release_global_budget() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 1000, 100_000_000, VPN_MAX_IP_PACKET_LEN).unwrap();
        let (handle, quota, _) = active_handle(limits, "0.0.0.0/0", 1, 8 * 1024 * 1024, 16);

        for packet_id in 1..=4 {
            let packet = ipv4_packet(40_000, "10.77.0.2", "198.51.100.8", packet_id as u8);
            let first = encode_vpn_ip_fragments(packet_id, &packet, 20_012)
                .unwrap()
                .remove(0);
            handle
                .ingest_datagram(VpnPacketDirection::Uplink, &first, started)
                .unwrap();
        }
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.inflight_reassembly_packets, 3);
        assert_eq!(snapshot.buffered_reassembly_bytes, 60_000);
        assert_eq!(snapshot.uplink_reassembly.packets_evicted, 1);
        assert_eq!(quota.snapshot().current_reassembly_bytes, 60_000);

        assert_eq!(
            handle.expire_reassembly(started + VPN_DEFAULT_FRAGMENT_TIMEOUT),
            3
        );
        assert_eq!(quota.snapshot().current_reassembly_bytes, 0);
        assert_eq!(quota.snapshot().active_reassembly_packets, 0);
    }

    #[test]
    fn completing_packet_does_not_evict_unrelated_partial_packet() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 1000, 10_000_000, VPN_MAX_IP_PACKET_LEN).unwrap();
        let (handle, quota, _) = active_handle(limits, "0.0.0.0/0", 1, 100_000, 16);

        let unrelated = ipv4_packet(30_000, "10.77.0.2", "198.51.100.8", 0x61);
        let unrelated_first = encode_vpn_ip_fragments(1, &unrelated, 25_012)
            .unwrap()
            .remove(0);
        handle
            .ingest_datagram(VpnPacketDirection::Uplink, &unrelated_first, started)
            .unwrap();

        let completing = ipv4_packet(65_000, "10.77.0.2", "198.51.100.8", 0x62);
        let completing_fragments = encode_vpn_ip_fragments(2, &completing, 40_012).unwrap();
        handle
            .ingest_datagram(
                VpnPacketDirection::Uplink,
                &completing_fragments[0],
                started,
            )
            .unwrap();
        assert_eq!(handle.snapshot().buffered_reassembly_bytes, 65_000);

        let completed = handle
            .ingest_datagram(
                VpnPacketDirection::Uplink,
                &completing_fragments[1],
                started,
            )
            .unwrap()
            .unwrap();
        assert_eq!(completed.as_bytes(), completing);
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.buffered_reassembly_bytes, 25_000);
        assert_eq!(snapshot.inflight_reassembly_packets, 1);
        assert_eq!(snapshot.uplink_reassembly.packets_evicted, 0);
        assert_eq!(quota.snapshot().current_reassembly_bytes, 25_000);
    }

    #[test]
    fn identities_share_only_atomic_global_budget() {
        let started = Instant::now();
        let metrics = VpnQuotaMetrics::default();
        let policy = VpnDataPolicyMetrics::default();
        let budget = VpnGlobalReassemblyBudget::new(70_000, 8, metrics.clone()).unwrap();
        let first = make_handle(
            identity(
                "client-a",
                "10.77.0.2",
                VpnIdentityLimits::default(),
                "0.0.0.0/0",
            ),
            1,
            budget.clone(),
            metrics.clone(),
            policy.clone(),
            started,
        );
        let second = make_handle(
            identity(
                "client-b",
                "10.77.0.3",
                VpnIdentityLimits::default(),
                "0.0.0.0/0",
            ),
            1,
            budget,
            metrics.clone(),
            policy,
            started,
        );

        let first_packet = ipv4_packet(50_000, "10.77.0.2", "198.51.100.8", 1);
        let first_fragment = encode_vpn_ip_fragments(1, &first_packet, 40_012)
            .unwrap()
            .remove(0);
        first
            .ingest_datagram(VpnPacketDirection::Uplink, &first_fragment, started)
            .unwrap();

        let second_packet = ipv4_packet(50_000, "10.77.0.3", "198.51.100.8", 2);
        let too_large = encode_vpn_ip_fragments(2, &second_packet, 40_012)
            .unwrap()
            .remove(0);
        assert_eq!(
            second
                .ingest_datagram(VpnPacketDirection::Uplink, &too_large, started)
                .unwrap_err(),
            VpnDataPathError::Quota(VpnQuotaRejection::GlobalReassemblyLimit)
        );
        assert_eq!(metrics.snapshot().current_reassembly_bytes, 40_000);

        let fits = encode_vpn_ip_fragments(3, &second_packet, 30_012)
            .unwrap()
            .remove(0);
        second
            .ingest_datagram(VpnPacketDirection::Uplink, &fits, started)
            .unwrap();
        assert_eq!(metrics.snapshot().current_reassembly_bytes, 70_000);
        drop(first);
        assert_eq!(metrics.snapshot().current_reassembly_bytes, 30_000);
        drop(second);
        assert_eq!(metrics.snapshot().current_reassembly_bytes, 0);
    }

    #[test]
    fn directions_have_independent_packet_id_namespaces() {
        let started = Instant::now();
        let (handle, quota, _) = active_handle(
            VpnIdentityLimits::default(),
            "0.0.0.0/0",
            1,
            8 * 1024 * 1024,
            16,
        );
        let uplink = ipv4_packet(1500, "10.77.0.2", "198.51.100.8", 1);
        let downlink = ipv4_packet(1500, "198.51.100.8", "10.77.0.2", 2);
        let uplink_first = encode_vpn_ip_fragments(9, &uplink, 1200).unwrap().remove(0);
        let downlink_first = encode_vpn_ip_fragments(9, &downlink, 1200)
            .unwrap()
            .remove(0);
        handle
            .ingest_datagram(VpnPacketDirection::Uplink, &uplink_first, started)
            .unwrap();
        handle
            .ingest_datagram(VpnPacketDirection::Downlink, &downlink_first, started)
            .unwrap();
        assert_eq!(handle.snapshot().inflight_reassembly_packets, 2);
        assert_eq!(quota.snapshot().active_reassembly_packets, 2);
    }

    #[test]
    fn one_identity_lock_cannot_block_another_identity() {
        let started = Instant::now();
        let metrics = VpnQuotaMetrics::default();
        let policy = VpnDataPolicyMetrics::default();
        let budget = VpnGlobalReassemblyBudget::new(8 * 1024 * 1024, 16, metrics.clone()).unwrap();
        let first = make_handle(
            identity(
                "client-a",
                "10.77.0.2",
                VpnIdentityLimits::default(),
                "0.0.0.0/0",
            ),
            1,
            budget.clone(),
            metrics.clone(),
            policy.clone(),
            started,
        );
        let second = make_handle(
            identity(
                "client-b",
                "10.77.0.3",
                VpnIdentityLimits::default(),
                "0.0.0.0/0",
            ),
            1,
            budget,
            metrics,
            policy,
            started,
        );
        let first_guard = first.lock_state();
        let packet = ipv4_packet(20, "10.77.0.3", "198.51.100.8", 3);
        let datagram = encode_vpn_ip_fragments(1, &packet, 1200).unwrap().remove(0);
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            sender
                .send(second.ingest_datagram(VpnPacketDirection::Uplink, &datagram, started))
                .unwrap();
        });
        assert!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .is_some()
        );
        drop(first_guard);
    }

    #[test]
    fn adversarial_datagram_sequence_preserves_every_accounting_bound() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(
            1,
            crate::VPN_MAX_PACKETS_PER_SECOND,
            crate::VPN_MAX_BYTES_PER_SECOND,
            4 * VPN_MAX_IP_PACKET_LEN,
        )
        .unwrap();
        let (handle, quota, _) =
            active_handle(limits, "0.0.0.0/0", 1, 8 * VPN_MAX_IP_PACKET_LEN, 2048);
        let mut random = 0x9e37_79b9_7f4a_7c15_u64;

        for sequence in 0..20_000_u64 {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let payload_len = 1 + usize::try_from(random % 1024).unwrap();
            let total_len = payload_len
                .saturating_add(usize::try_from((random >> 12) % 4096).unwrap())
                .min(VPN_MAX_IP_PACKET_LEN);
            let max_offset = total_len.saturating_sub(payload_len);
            let offset = if max_offset == 0 {
                0
            } else {
                usize::try_from((random >> 24) % (max_offset as u64 + 1)).unwrap()
            };
            let payload = vec![(random >> 56) as u8; payload_len];
            let mut datagram =
                raw_fragment((random >> 32) as u32 % 256, total_len, offset, &payload);
            if sequence % 7 == 0 {
                datagram[0] ^= 0xff;
            }
            let direction = if sequence % 2 == 0 {
                VpnPacketDirection::Uplink
            } else {
                VpnPacketDirection::Downlink
            };
            let now = started + Duration::from_micros(sequence);
            let _ = handle.ingest_datagram(direction, &datagram, now);

            let path = handle.snapshot();
            let global = quota.snapshot();
            assert!(path.buffered_reassembly_bytes <= limits.max_reassembly_bytes());
            assert!(path.inflight_reassembly_packets <= VPN_DEFAULT_MAX_INFLIGHT_PACKETS);
            assert_eq!(
                global.current_reassembly_bytes,
                path.buffered_reassembly_bytes
            );
            assert_eq!(
                global.active_reassembly_packets,
                path.inflight_reassembly_packets
            );
        }

        handle.deactivate();
        assert_eq!(quota.snapshot().current_reassembly_bytes, 0);
        assert_eq!(quota.snapshot().active_reassembly_packets, 0);
    }

    fn active_handle(
        limits: VpnIdentityLimits,
        policy: &str,
        generation: u64,
        global_bytes: usize,
        global_packets: usize,
    ) -> (VpnDataPathHandle, VpnQuotaMetrics, VpnDataPolicyMetrics) {
        let started = Instant::now();
        let quota = VpnQuotaMetrics::default();
        let policy_metrics = VpnDataPolicyMetrics::default();
        let budget =
            VpnGlobalReassemblyBudget::new(global_bytes, global_packets, quota.clone()).unwrap();
        let handle = make_handle(
            identity("client-a", "10.77.0.2", limits, policy),
            generation,
            budget,
            quota.clone(),
            policy_metrics.clone(),
            started,
        );
        (handle, quota, policy_metrics)
    }

    fn make_handle(
        identity: VpnIdentity,
        generation: u64,
        budget: VpnGlobalReassemblyBudget,
        quota_metrics: VpnQuotaMetrics,
        policy_metrics: VpnDataPolicyMetrics,
        now: Instant,
    ) -> VpnDataPathHandle {
        let rate_limiter = Arc::new(VpnIdentityRateLimiter::new(
            identity.limits(),
            now,
            quota_metrics.clone(),
        ));
        let handle = VpnDataPathHandle::new_inactive(
            identity,
            generation,
            rate_limiter,
            budget,
            quota_metrics,
            policy_metrics,
        )
        .unwrap();
        handle.activate();
        handle
    }

    fn identity(
        client_id: &str,
        client_ipv4: &str,
        limits: VpnIdentityLimits,
        policy: &str,
    ) -> VpnIdentity {
        let (network, prefix) = policy.split_once('/').unwrap();
        VpnIdentity::new(
            client_id,
            vec![VpnCertificateFingerprint::from_sha256(
                [client_ipv4.as_bytes().last().copied().unwrap_or(1); 32],
            )],
            true,
            Some(client_ipv4.parse().unwrap()),
            Some(if client_ipv4.ends_with('2') {
                "fd77::2".parse::<Ipv6Addr>().unwrap()
            } else {
                "fd77::3".parse::<Ipv6Addr>().unwrap()
            }),
            vec![
                VpnIpNetwork::v4(
                    network.parse::<Ipv4Addr>().unwrap(),
                    prefix.parse().unwrap(),
                )
                .unwrap(),
                VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
            ],
            limits,
        )
        .unwrap()
    }

    fn ipv4_packet(len: usize, source: &str, destination: &str, fill: u8) -> Vec<u8> {
        let source = source.parse::<Ipv4Addr>().unwrap().octets();
        let destination = destination.parse::<Ipv4Addr>().unwrap().octets();
        let mut packet = vec![fill; len];
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

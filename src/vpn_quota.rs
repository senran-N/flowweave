use std::{collections::HashMap, error::Error, fmt, time::Instant};

use crate::{
    VPN_DEFAULT_MAX_INFLIGHT_PACKETS, VPN_MAX_IP_PACKET_LEN, VpnIdentityLimits, VpnIdentityRegistry,
};

pub const VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;
pub const VPN_MAX_GLOBAL_REASSEMBLY_BYTES: usize = 1024 * 1024 * 1024;
pub const VPN_DEFAULT_GLOBAL_REASSEMBLY_RESERVATIONS: usize = 8192;
pub const VPN_MAX_GLOBAL_REASSEMBLY_RESERVATIONS: usize = 65_536;

const TOKEN_SCALE: u128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPacketDirection {
    Uplink,
    Downlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnQuotaRejection {
    StaleGeneration,
    InvalidPacketSize,
    PacketRateExceeded,
    ByteRateExceeded,
    IdentityReassemblyLimit,
    GlobalReassemblyLimit,
    IdentityReservationLimit,
    GlobalReservationLimit,
    ReservationIdExhausted,
}

impl fmt::Display for VpnQuotaRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StaleGeneration => "vpn_quota_stale_generation",
            Self::InvalidPacketSize => "vpn_quota_invalid_packet_size",
            Self::PacketRateExceeded => "vpn_quota_packet_rate_exceeded",
            Self::ByteRateExceeded => "vpn_quota_byte_rate_exceeded",
            Self::IdentityReassemblyLimit => "vpn_quota_identity_reassembly_limit",
            Self::GlobalReassemblyLimit => "vpn_quota_global_reassembly_limit",
            Self::IdentityReservationLimit => "vpn_quota_identity_reservation_limit",
            Self::GlobalReservationLimit => "vpn_quota_global_reservation_limit",
            Self::ReservationIdExhausted => "vpn_quota_reservation_id_exhausted",
        })
    }
}

impl Error for VpnQuotaRejection {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnQuotaMetricsSnapshot {
    pub admitted_uplink_packets: u64,
    pub admitted_uplink_bytes: u64,
    pub admitted_downlink_packets: u64,
    pub admitted_downlink_bytes: u64,
    pub stale_generation_rejections: u64,
    pub invalid_packet_rejections: u64,
    pub packet_rate_rejections: u64,
    pub byte_rate_rejections: u64,
    pub identity_reassembly_rejections: u64,
    pub global_reassembly_rejections: u64,
    pub identity_reservation_rejections: u64,
    pub global_reservation_rejections: u64,
    pub reservation_id_rejections: u64,
    pub current_reassembly_bytes: usize,
    pub peak_reassembly_bytes: usize,
    pub active_reassembly_reservations: usize,
}

pub(crate) struct VpnQuotaBook {
    identities: HashMap<String, IdentityQuota>,
    reservations: HashMap<u64, ReassemblyReservationRecord>,
    next_reservation_id: u64,
    global_reassembly_limit: usize,
    global_reservation_limit: usize,
    global_reassembly_bytes: usize,
    metrics: VpnQuotaMetricsSnapshot,
}

impl VpnQuotaBook {
    pub(crate) fn new(
        global_reassembly_limit: usize,
        global_reservation_limit: usize,
    ) -> Option<Self> {
        if !(VPN_MAX_IP_PACKET_LEN..=VPN_MAX_GLOBAL_REASSEMBLY_BYTES)
            .contains(&global_reassembly_limit)
            || global_reservation_limit == 0
            || global_reservation_limit > VPN_MAX_GLOBAL_REASSEMBLY_RESERVATIONS
        {
            return None;
        }
        Some(Self {
            identities: HashMap::new(),
            reservations: HashMap::new(),
            next_reservation_id: 1,
            global_reassembly_limit,
            global_reservation_limit,
            global_reassembly_bytes: 0,
            metrics: VpnQuotaMetricsSnapshot::default(),
        })
    }

    pub(crate) fn activate(
        &mut self,
        client_id: &str,
        generation: u64,
        limits: VpnIdentityLimits,
        now: Instant,
    ) {
        let quota = self
            .identities
            .entry(client_id.to_owned())
            .or_insert_with(|| IdentityQuota::new(limits, now));
        quota.reconfigure(limits, now);
        quota.allowed = true;
        quota.active_generation = Some(generation);
    }

    pub(crate) fn deactivate(&mut self, client_id: &str, generation: u64) {
        if let Some(quota) = self.identities.get_mut(client_id)
            && quota.active_generation == Some(generation)
        {
            quota.active_generation = None;
        }
        self.remove_unused_tombstone(client_id);
    }

    pub(crate) fn reconcile(
        &mut self,
        registry: &VpnIdentityRegistry,
        active_generations: &HashMap<String, u64>,
        now: Instant,
    ) {
        let client_ids = self.identities.keys().cloned().collect::<Vec<_>>();
        for client_id in client_ids {
            let identity = registry
                .identity_by_client_id(&client_id)
                .filter(|identity| identity.enabled());
            if let Some(identity) = identity {
                let quota = self
                    .identities
                    .get_mut(&client_id)
                    .expect("quota key came from the same map");
                quota.reconfigure(identity.limits(), now);
                quota.allowed = true;
                quota.active_generation = active_generations.get(&client_id).copied();
            } else if let Some(quota) = self.identities.get_mut(&client_id) {
                quota.allowed = false;
                quota.active_generation = None;
            }
            self.remove_unused_tombstone(&client_id);
        }
    }

    pub(crate) fn admit_packet(
        &mut self,
        client_id: &str,
        generation: u64,
        direction: VpnPacketDirection,
        packet_len: usize,
        now: Instant,
    ) -> Result<(), VpnQuotaRejection> {
        if packet_len == 0 || packet_len > VPN_MAX_IP_PACKET_LEN {
            self.metrics.invalid_packet_rejections =
                self.metrics.invalid_packet_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::InvalidPacketSize);
        }
        let Some(quota) = self.identities.get_mut(client_id) else {
            self.metrics.stale_generation_rejections =
                self.metrics.stale_generation_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::StaleGeneration);
        };
        if !quota.allowed || quota.active_generation != Some(generation) {
            self.metrics.stale_generation_rejections =
                self.metrics.stale_generation_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::StaleGeneration);
        }
        quota.refill(now);
        let packet_cost = TOKEN_SCALE;
        let byte_cost = (packet_len as u128).saturating_mul(TOKEN_SCALE);
        if quota.packet_tokens < packet_cost {
            self.metrics.packet_rate_rejections =
                self.metrics.packet_rate_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::PacketRateExceeded);
        }
        if quota.byte_tokens < byte_cost {
            self.metrics.byte_rate_rejections = self.metrics.byte_rate_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::ByteRateExceeded);
        }
        quota.packet_tokens -= packet_cost;
        quota.byte_tokens -= byte_cost;
        let bytes = u64::try_from(packet_len).unwrap_or(u64::MAX);
        match direction {
            VpnPacketDirection::Uplink => {
                self.metrics.admitted_uplink_packets =
                    self.metrics.admitted_uplink_packets.saturating_add(1);
                self.metrics.admitted_uplink_bytes =
                    self.metrics.admitted_uplink_bytes.saturating_add(bytes);
            }
            VpnPacketDirection::Downlink => {
                self.metrics.admitted_downlink_packets =
                    self.metrics.admitted_downlink_packets.saturating_add(1);
                self.metrics.admitted_downlink_bytes =
                    self.metrics.admitted_downlink_bytes.saturating_add(bytes);
            }
        }
        Ok(())
    }

    pub(crate) fn reserve_reassembly(
        &mut self,
        client_id: &str,
        generation: u64,
        bytes: usize,
    ) -> Result<u64, VpnQuotaRejection> {
        if bytes == 0 {
            self.metrics.identity_reassembly_rejections = self
                .metrics
                .identity_reassembly_rejections
                .saturating_add(1);
            return Err(VpnQuotaRejection::IdentityReassemblyLimit);
        }
        let Some(quota) = self.identities.get(client_id) else {
            self.metrics.stale_generation_rejections =
                self.metrics.stale_generation_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::StaleGeneration);
        };
        if !quota.allowed || quota.active_generation != Some(generation) {
            self.metrics.stale_generation_rejections =
                self.metrics.stale_generation_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::StaleGeneration);
        }
        if quota.reassembly_reservations >= VPN_DEFAULT_MAX_INFLIGHT_PACKETS {
            self.metrics.identity_reservation_rejections = self
                .metrics
                .identity_reservation_rejections
                .saturating_add(1);
            return Err(VpnQuotaRejection::IdentityReservationLimit);
        }
        if self.reservations.len() >= self.global_reservation_limit {
            self.metrics.global_reservation_rejections =
                self.metrics.global_reservation_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::GlobalReservationLimit);
        }
        if quota
            .reassembly_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > quota.limits.max_reassembly_bytes())
        {
            self.metrics.identity_reassembly_rejections = self
                .metrics
                .identity_reassembly_rejections
                .saturating_add(1);
            return Err(VpnQuotaRejection::IdentityReassemblyLimit);
        }
        if self
            .global_reassembly_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > self.global_reassembly_limit)
        {
            self.metrics.global_reassembly_rejections =
                self.metrics.global_reassembly_rejections.saturating_add(1);
            return Err(VpnQuotaRejection::GlobalReassemblyLimit);
        }
        let reservation_id = self.allocate_reservation_id()?;
        let quota = self
            .identities
            .get_mut(client_id)
            .expect("reservation checks require an existing identity quota");
        quota.reassembly_bytes += bytes;
        quota.reassembly_reservations += 1;
        self.global_reassembly_bytes += bytes;
        self.reservations.insert(
            reservation_id,
            ReassemblyReservationRecord {
                client_id: client_id.to_owned(),
                bytes,
            },
        );
        self.metrics.current_reassembly_bytes = self.global_reassembly_bytes;
        self.metrics.peak_reassembly_bytes = self
            .metrics
            .peak_reassembly_bytes
            .max(self.global_reassembly_bytes);
        self.metrics.active_reassembly_reservations = self.reservations.len();
        Ok(reservation_id)
    }

    pub(crate) fn release_reassembly(&mut self, reservation_id: u64) {
        let Some(reservation) = self.reservations.remove(&reservation_id) else {
            return;
        };
        if let Some(quota) = self.identities.get_mut(&reservation.client_id) {
            quota.reassembly_bytes = quota.reassembly_bytes.saturating_sub(reservation.bytes);
            quota.reassembly_reservations = quota.reassembly_reservations.saturating_sub(1);
        }
        self.global_reassembly_bytes = self
            .global_reassembly_bytes
            .saturating_sub(reservation.bytes);
        self.metrics.current_reassembly_bytes = self.global_reassembly_bytes;
        self.metrics.active_reassembly_reservations = self.reservations.len();
        self.remove_unused_tombstone(&reservation.client_id);
    }

    pub(crate) const fn metrics(&self) -> VpnQuotaMetricsSnapshot {
        self.metrics
    }

    pub(crate) fn record_stale_generation(&mut self) {
        self.metrics.stale_generation_rejections =
            self.metrics.stale_generation_rejections.saturating_add(1);
    }

    fn allocate_reservation_id(&mut self) -> Result<u64, VpnQuotaRejection> {
        for _ in 0..=self.reservations.len().saturating_add(1) {
            let candidate = self.next_reservation_id;
            self.next_reservation_id = self.next_reservation_id.wrapping_add(1);
            if candidate != 0 && !self.reservations.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        self.metrics.reservation_id_rejections =
            self.metrics.reservation_id_rejections.saturating_add(1);
        Err(VpnQuotaRejection::ReservationIdExhausted)
    }

    fn remove_unused_tombstone(&mut self, client_id: &str) {
        let remove = self.identities.get(client_id).is_some_and(|quota| {
            !quota.allowed
                && quota.active_generation.is_none()
                && quota.reassembly_reservations == 0
        });
        if remove {
            self.identities.remove(client_id);
        }
    }
}

struct IdentityQuota {
    limits: VpnIdentityLimits,
    allowed: bool,
    active_generation: Option<u64>,
    packet_tokens: u128,
    byte_tokens: u128,
    last_refill: Instant,
    reassembly_bytes: usize,
    reassembly_reservations: usize,
}

impl IdentityQuota {
    fn new(limits: VpnIdentityLimits, now: Instant) -> Self {
        Self {
            limits,
            allowed: true,
            active_generation: None,
            packet_tokens: packet_capacity(limits),
            byte_tokens: byte_capacity(limits),
            last_refill: now,
            reassembly_bytes: 0,
            reassembly_reservations: 0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let Some(elapsed) = now.checked_duration_since(self.last_refill) else {
            return;
        };
        let elapsed_nanos = elapsed.as_nanos();
        self.packet_tokens = self
            .packet_tokens
            .saturating_add(
                elapsed_nanos.saturating_mul(u128::from(self.limits.max_packets_per_second())),
            )
            .min(packet_capacity(self.limits));
        self.byte_tokens = self
            .byte_tokens
            .saturating_add(
                elapsed_nanos.saturating_mul(u128::from(self.limits.max_bytes_per_second())),
            )
            .min(byte_capacity(self.limits));
        self.last_refill = now;
    }

    fn reconfigure(&mut self, limits: VpnIdentityLimits, now: Instant) {
        self.refill(now);
        self.limits = limits;
        self.packet_tokens = self.packet_tokens.min(packet_capacity(limits));
        self.byte_tokens = self.byte_tokens.min(byte_capacity(limits));
    }
}

fn packet_capacity(limits: VpnIdentityLimits) -> u128 {
    u128::from(limits.max_packets_per_second()).saturating_mul(TOKEN_SCALE)
}

fn byte_capacity(limits: VpnIdentityLimits) -> u128 {
    let burst_bytes = limits
        .max_bytes_per_second()
        .max(VPN_MAX_IP_PACKET_LEN as u64);
    u128::from(burst_bytes).saturating_mul(TOKEN_SCALE)
}

struct ReassemblyReservationRecord {
    client_id: String,
    bytes: usize,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn packet_bucket_is_exact_and_does_not_consume_bytes_on_rejection() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 2, 65_535, VPN_MAX_IP_PACKET_LEN).unwrap();
        let mut book = VpnQuotaBook::new(VPN_MAX_IP_PACKET_LEN, 16).unwrap();
        book.activate("client-a", 7, limits, started);
        assert_eq!(
            book.admit_packet("client-a", 7, VpnPacketDirection::Uplink, 100, started),
            Ok(())
        );
        assert_eq!(
            book.admit_packet("client-a", 7, VpnPacketDirection::Downlink, 100, started),
            Ok(())
        );
        assert_eq!(
            book.admit_packet("client-a", 7, VpnPacketDirection::Uplink, 100, started),
            Err(VpnQuotaRejection::PacketRateExceeded)
        );
        assert_eq!(
            book.admit_packet(
                "client-a",
                7,
                VpnPacketDirection::Uplink,
                100,
                started + Duration::from_millis(500),
            ),
            Ok(())
        );
        let metrics = book.metrics();
        assert_eq!(metrics.admitted_uplink_packets, 2);
        assert_eq!(metrics.admitted_downlink_packets, 1);
        assert_eq!(metrics.packet_rate_rejections, 1);
    }

    #[test]
    fn byte_bucket_and_generation_are_shared_across_directions() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 100, 65_535, VPN_MAX_IP_PACKET_LEN).unwrap();
        let mut book = VpnQuotaBook::new(VPN_MAX_IP_PACKET_LEN, 16).unwrap();
        book.activate("client-a", 1, limits, started);
        book.admit_packet(
            "client-a",
            1,
            VpnPacketDirection::Uplink,
            VPN_MAX_IP_PACKET_LEN,
            started,
        )
        .unwrap();
        assert_eq!(
            book.admit_packet("client-a", 1, VpnPacketDirection::Downlink, 1, started,),
            Err(VpnQuotaRejection::ByteRateExceeded)
        );
        assert_eq!(
            book.admit_packet(
                "client-a",
                2,
                VpnPacketDirection::Downlink,
                1,
                started + Duration::from_secs(1),
            ),
            Err(VpnQuotaRejection::StaleGeneration)
        );
        book.activate("client-a", 2, limits, started + Duration::from_secs(1));
        assert_eq!(
            book.admit_packet(
                "client-a",
                2,
                VpnPacketDirection::Downlink,
                VPN_MAX_IP_PACKET_LEN,
                started + Duration::from_secs(1),
            ),
            Ok(())
        );
    }

    #[test]
    fn reassembly_reservations_enforce_identity_and_global_bytes_until_release() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 100, 100_000, 100_000).unwrap();
        let mut book = VpnQuotaBook::new(120_000, 2).unwrap();
        book.activate("client-a", 1, limits, started);
        let first = book.reserve_reassembly("client-a", 1, 70_000).unwrap();
        assert_eq!(
            book.reserve_reassembly("client-a", 1, 40_000),
            Err(VpnQuotaRejection::IdentityReassemblyLimit)
        );
        let second = book.reserve_reassembly("client-a", 1, 30_000).unwrap();
        assert_eq!(
            book.reserve_reassembly("client-a", 1, 1),
            Err(VpnQuotaRejection::GlobalReservationLimit)
        );
        book.release_reassembly(first);
        book.release_reassembly(second);
        let metrics = book.metrics();
        assert_eq!(metrics.current_reassembly_bytes, 0);
        assert_eq!(metrics.active_reassembly_reservations, 0);
        assert_eq!(metrics.peak_reassembly_bytes, 100_000);
    }

    #[test]
    fn identities_have_independent_rate_buckets_but_share_global_memory() {
        let started = Instant::now();
        let limits = VpnIdentityLimits::new(1, 1, 65_535, 100_000).unwrap();
        let mut book = VpnQuotaBook::new(100_000, 4).unwrap();
        book.activate("client-a", 1, limits, started);
        book.activate("client-b", 1, limits, started);

        book.admit_packet("client-a", 1, VpnPacketDirection::Uplink, 1, started)
            .unwrap();
        assert_eq!(
            book.admit_packet("client-a", 1, VpnPacketDirection::Uplink, 1, started,),
            Err(VpnQuotaRejection::PacketRateExceeded)
        );
        book.admit_packet("client-b", 1, VpnPacketDirection::Uplink, 1, started)
            .unwrap();

        let first = book.reserve_reassembly("client-a", 1, 70_000).unwrap();
        assert_eq!(
            book.reserve_reassembly("client-b", 1, 40_000),
            Err(VpnQuotaRejection::GlobalReassemblyLimit)
        );
        let second = book.reserve_reassembly("client-b", 1, 30_000).unwrap();
        book.release_reassembly(first);
        book.release_reassembly(second);
        assert_eq!(book.metrics().current_reassembly_bytes, 0);
    }
}

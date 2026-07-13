use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};

use crate::{VPN_MAX_IP_DATAGRAM_LEN, VpnIdentityLimits};

pub const VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;
pub const VPN_MAX_GLOBAL_REASSEMBLY_BYTES: usize = 1024 * 1024 * 1024;
pub const VPN_DEFAULT_GLOBAL_INFLIGHT_PACKETS: usize = 8192;
pub const VPN_MAX_GLOBAL_INFLIGHT_PACKETS: usize = 65_536;

const TOKEN_SCALE: u128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPacketDirection {
    Uplink,
    Downlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnQuotaRejection {
    InvalidDatagramSize,
    PacketRateExceeded,
    ByteRateExceeded,
    IdentityReassemblyLimit,
    GlobalReassemblyLimit,
    IdentityInflightLimit,
    GlobalInflightLimit,
}

impl fmt::Display for VpnQuotaRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDatagramSize => "vpn_quota_invalid_datagram_size",
            Self::PacketRateExceeded => "vpn_quota_packet_rate_exceeded",
            Self::ByteRateExceeded => "vpn_quota_byte_rate_exceeded",
            Self::IdentityReassemblyLimit => "vpn_quota_identity_reassembly_limit",
            Self::GlobalReassemblyLimit => "vpn_quota_global_reassembly_limit",
            Self::IdentityInflightLimit => "vpn_quota_identity_inflight_limit",
            Self::GlobalInflightLimit => "vpn_quota_global_inflight_limit",
        })
    }
}

impl Error for VpnQuotaRejection {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnQuotaMetricsSnapshot {
    pub admitted_uplink_datagrams: u64,
    pub admitted_uplink_bytes: u64,
    pub admitted_downlink_datagrams: u64,
    pub admitted_downlink_bytes: u64,
    pub stale_generation_rejections: u64,
    pub invalid_datagram_rejections: u64,
    pub packet_rate_rejections: u64,
    pub byte_rate_rejections: u64,
    pub identity_reassembly_rejections: u64,
    pub global_reassembly_rejections: u64,
    pub identity_inflight_rejections: u64,
    pub global_inflight_rejections: u64,
    pub current_reassembly_bytes: usize,
    pub peak_reassembly_bytes: usize,
    pub active_reassembly_packets: usize,
    pub peak_reassembly_packets: usize,
}

#[derive(Clone, Default)]
pub(crate) struct VpnQuotaMetrics {
    inner: Arc<VpnQuotaMetricCounters>,
}

impl VpnQuotaMetrics {
    pub(crate) fn snapshot(&self) -> VpnQuotaMetricsSnapshot {
        VpnQuotaMetricsSnapshot {
            admitted_uplink_datagrams: self.inner.admitted_uplink_datagrams.load(Ordering::Relaxed),
            admitted_uplink_bytes: self.inner.admitted_uplink_bytes.load(Ordering::Relaxed),
            admitted_downlink_datagrams: self
                .inner
                .admitted_downlink_datagrams
                .load(Ordering::Relaxed),
            admitted_downlink_bytes: self.inner.admitted_downlink_bytes.load(Ordering::Relaxed),
            stale_generation_rejections: self
                .inner
                .stale_generation_rejections
                .load(Ordering::Relaxed),
            invalid_datagram_rejections: self
                .inner
                .invalid_datagram_rejections
                .load(Ordering::Relaxed),
            packet_rate_rejections: self.inner.packet_rate_rejections.load(Ordering::Relaxed),
            byte_rate_rejections: self.inner.byte_rate_rejections.load(Ordering::Relaxed),
            identity_reassembly_rejections: self
                .inner
                .identity_reassembly_rejections
                .load(Ordering::Relaxed),
            global_reassembly_rejections: self
                .inner
                .global_reassembly_rejections
                .load(Ordering::Relaxed),
            identity_inflight_rejections: self
                .inner
                .identity_inflight_rejections
                .load(Ordering::Relaxed),
            global_inflight_rejections: self
                .inner
                .global_inflight_rejections
                .load(Ordering::Relaxed),
            current_reassembly_bytes: self.inner.current_reassembly_bytes.load(Ordering::Relaxed),
            peak_reassembly_bytes: self.inner.peak_reassembly_bytes.load(Ordering::Relaxed),
            active_reassembly_packets: self.inner.active_reassembly_packets.load(Ordering::Relaxed),
            peak_reassembly_packets: self.inner.peak_reassembly_packets.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record_stale_generation(&self) {
        increment(&self.inner.stale_generation_rejections);
    }

    pub(crate) fn record_identity_reassembly_rejection(&self) {
        increment(&self.inner.identity_reassembly_rejections);
    }

    pub(crate) fn record_identity_inflight_rejection(&self) {
        increment(&self.inner.identity_inflight_rejections);
    }

    fn record_admitted(&self, direction: VpnPacketDirection, datagram_len: usize) {
        let bytes = u64::try_from(datagram_len).unwrap_or(u64::MAX);
        match direction {
            VpnPacketDirection::Uplink => {
                increment(&self.inner.admitted_uplink_datagrams);
                add(&self.inner.admitted_uplink_bytes, bytes);
            }
            VpnPacketDirection::Downlink => {
                increment(&self.inner.admitted_downlink_datagrams);
                add(&self.inner.admitted_downlink_bytes, bytes);
            }
        }
    }

    fn record_invalid_datagram(&self) {
        increment(&self.inner.invalid_datagram_rejections);
    }

    fn record_packet_rate_rejection(&self) {
        increment(&self.inner.packet_rate_rejections);
    }

    fn record_byte_rate_rejection(&self) {
        increment(&self.inner.byte_rate_rejections);
    }

    fn record_global_reassembly_rejection(&self) {
        increment(&self.inner.global_reassembly_rejections);
    }

    fn record_global_inflight_rejection(&self) {
        increment(&self.inner.global_inflight_rejections);
    }

    fn update_reassembly_peaks(&self, bytes: usize, packets: usize) {
        self.inner
            .peak_reassembly_bytes
            .fetch_max(bytes, Ordering::Relaxed);
        self.inner
            .peak_reassembly_packets
            .fetch_max(packets, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct VpnQuotaMetricCounters {
    admitted_uplink_datagrams: AtomicU64,
    admitted_uplink_bytes: AtomicU64,
    admitted_downlink_datagrams: AtomicU64,
    admitted_downlink_bytes: AtomicU64,
    stale_generation_rejections: AtomicU64,
    invalid_datagram_rejections: AtomicU64,
    packet_rate_rejections: AtomicU64,
    byte_rate_rejections: AtomicU64,
    identity_reassembly_rejections: AtomicU64,
    global_reassembly_rejections: AtomicU64,
    identity_inflight_rejections: AtomicU64,
    global_inflight_rejections: AtomicU64,
    current_reassembly_bytes: AtomicUsize,
    peak_reassembly_bytes: AtomicUsize,
    active_reassembly_packets: AtomicUsize,
    peak_reassembly_packets: AtomicUsize,
}

pub(crate) struct VpnIdentityRateLimiter {
    state: Mutex<IdentityRateState>,
    metrics: VpnQuotaMetrics,
}

impl VpnIdentityRateLimiter {
    pub(crate) fn new(limits: VpnIdentityLimits, now: Instant, metrics: VpnQuotaMetrics) -> Self {
        Self {
            state: Mutex::new(IdentityRateState::new(limits, now)),
            metrics,
        }
    }

    pub(crate) fn reconfigure(&self, limits: VpnIdentityLimits, now: Instant) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reconfigure(limits, now);
    }

    pub(crate) fn admit_datagram(
        &self,
        direction: VpnPacketDirection,
        datagram_len: usize,
        now: Instant,
    ) -> Result<(), VpnQuotaRejection> {
        if datagram_len == 0 || datagram_len > VPN_MAX_IP_DATAGRAM_LEN {
            self.metrics.record_invalid_datagram();
            return Err(VpnQuotaRejection::InvalidDatagramSize);
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.refill(now);
        let packet_cost = TOKEN_SCALE;
        let byte_cost = (datagram_len as u128).saturating_mul(TOKEN_SCALE);
        if state.packet_tokens < packet_cost {
            self.metrics.record_packet_rate_rejection();
            return Err(VpnQuotaRejection::PacketRateExceeded);
        }
        if state.byte_tokens < byte_cost {
            self.metrics.record_byte_rate_rejection();
            return Err(VpnQuotaRejection::ByteRateExceeded);
        }
        state.packet_tokens -= packet_cost;
        state.byte_tokens -= byte_cost;
        drop(state);
        self.metrics.record_admitted(direction, datagram_len);
        Ok(())
    }
}

struct IdentityRateState {
    limits: VpnIdentityLimits,
    packet_tokens: u128,
    byte_tokens: u128,
    last_refill: Instant,
}

impl IdentityRateState {
    fn new(limits: VpnIdentityLimits, now: Instant) -> Self {
        Self {
            limits,
            packet_tokens: packet_capacity(limits),
            byte_tokens: byte_capacity(limits),
            last_refill: now,
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
        .max(VPN_MAX_IP_DATAGRAM_LEN as u64);
    u128::from(burst_bytes).saturating_mul(TOKEN_SCALE)
}

#[derive(Clone)]
pub(crate) struct VpnGlobalReassemblyBudget {
    inner: Arc<GlobalReassemblyBudgetInner>,
}

impl VpnGlobalReassemblyBudget {
    pub(crate) fn new(
        byte_limit: usize,
        packet_limit: usize,
        metrics: VpnQuotaMetrics,
    ) -> Option<Self> {
        if !(crate::VPN_MAX_IP_PACKET_LEN..=VPN_MAX_GLOBAL_REASSEMBLY_BYTES).contains(&byte_limit)
            || packet_limit == 0
            || packet_limit > VPN_MAX_GLOBAL_INFLIGHT_PACKETS
        {
            return None;
        }
        Some(Self {
            inner: Arc::new(GlobalReassemblyBudgetInner {
                byte_limit,
                packet_limit,
                metrics,
            }),
        })
    }

    pub(crate) fn try_reserve(
        &self,
        bytes: usize,
        packets: usize,
    ) -> Result<VpnGlobalReassemblyReservation, VpnQuotaRejection> {
        let Some(current_bytes) = try_add_bounded(
            &self.inner.metrics.inner.current_reassembly_bytes,
            bytes,
            self.inner.byte_limit,
        ) else {
            self.inner.metrics.record_global_reassembly_rejection();
            return Err(VpnQuotaRejection::GlobalReassemblyLimit);
        };
        let Some(current_packets) = try_add_bounded(
            &self.inner.metrics.inner.active_reassembly_packets,
            packets,
            self.inner.packet_limit,
        ) else {
            subtract(&self.inner.metrics.inner.current_reassembly_bytes, bytes);
            self.inner.metrics.record_global_inflight_rejection();
            return Err(VpnQuotaRejection::GlobalInflightLimit);
        };
        self.inner
            .metrics
            .update_reassembly_peaks(current_bytes, current_packets);
        Ok(VpnGlobalReassemblyReservation {
            budget: self.clone(),
            bytes,
            packets,
        })
    }

    pub(crate) fn release_accounted(&self, bytes: usize, packets: usize) {
        self.release(bytes, packets);
    }

    fn release(&self, bytes: usize, packets: usize) {
        subtract(&self.inner.metrics.inner.current_reassembly_bytes, bytes);
        subtract(&self.inner.metrics.inner.active_reassembly_packets, packets);
    }
}

struct GlobalReassemblyBudgetInner {
    byte_limit: usize,
    packet_limit: usize,
    metrics: VpnQuotaMetrics,
}

pub(crate) struct VpnGlobalReassemblyReservation {
    budget: VpnGlobalReassemblyBudget,
    bytes: usize,
    packets: usize,
}

impl VpnGlobalReassemblyReservation {
    pub(crate) fn reconcile(
        mut self,
        accounted_bytes: &mut usize,
        accounted_packets: &mut usize,
        actual_bytes: usize,
        actual_packets: usize,
    ) -> bool {
        let Some(total_bytes) = accounted_bytes.checked_add(self.bytes) else {
            return false;
        };
        let Some(total_packets) = accounted_packets.checked_add(self.packets) else {
            return false;
        };
        if actual_bytes > total_bytes || actual_packets > total_packets {
            return false;
        }

        self.budget
            .release(total_bytes - actual_bytes, total_packets - actual_packets);
        *accounted_bytes = actual_bytes;
        *accounted_packets = actual_packets;
        self.bytes = 0;
        self.packets = 0;
        true
    }
}

impl Drop for VpnGlobalReassemblyReservation {
    fn drop(&mut self) {
        self.budget.release(self.bytes, self.packets);
    }
}

fn try_add_bounded(counter: &AtomicUsize, amount: usize, limit: usize) -> Option<usize> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(amount).filter(|next| *next <= limit)
        })
        .ok()
        .and_then(|previous| previous.checked_add(amount))
}

fn subtract(counter: &AtomicUsize, amount: usize) {
    if amount == 0 {
        return;
    }
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_sub(amount)
        })
        .expect("VPN reassembly accounting cannot underflow");
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(1))
    });
}

fn add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;
    use crate::VPN_MAX_IP_PACKET_LEN;

    #[test]
    fn identity_bucket_is_exact_and_shared_by_directions() {
        let started = Instant::now();
        let metrics = VpnQuotaMetrics::default();
        let limits = VpnIdentityLimits::new(1, 2, 65_535, VPN_MAX_IP_PACKET_LEN).unwrap();
        let limiter = VpnIdentityRateLimiter::new(limits, started, metrics.clone());

        limiter
            .admit_datagram(VpnPacketDirection::Uplink, 100, started)
            .unwrap();
        limiter
            .admit_datagram(VpnPacketDirection::Downlink, 100, started)
            .unwrap();
        assert_eq!(
            limiter.admit_datagram(VpnPacketDirection::Uplink, 100, started),
            Err(VpnQuotaRejection::PacketRateExceeded)
        );
        limiter
            .admit_datagram(
                VpnPacketDirection::Uplink,
                100,
                started + Duration::from_millis(500),
            )
            .unwrap();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.admitted_uplink_datagrams, 2);
        assert_eq!(snapshot.admitted_downlink_datagrams, 1);
        assert_eq!(snapshot.packet_rate_rejections, 1);
    }

    #[test]
    fn failed_admission_does_not_partially_consume_other_bucket() {
        let started = Instant::now();
        let metrics = VpnQuotaMetrics::default();
        let limits = VpnIdentityLimits::new(1, 2, 65_535, VPN_MAX_IP_PACKET_LEN).unwrap();
        let limiter = VpnIdentityRateLimiter::new(limits, started, metrics.clone());

        assert_eq!(
            limiter.admit_datagram(
                VpnPacketDirection::Uplink,
                VPN_MAX_IP_DATAGRAM_LEN + 1,
                started,
            ),
            Err(VpnQuotaRejection::InvalidDatagramSize)
        );
        limiter
            .admit_datagram(VpnPacketDirection::Uplink, VPN_MAX_IP_DATAGRAM_LEN, started)
            .unwrap();
        assert_eq!(metrics.snapshot().invalid_datagram_rejections, 1);
    }

    #[test]
    fn global_budget_reconciles_provisional_bytes_and_packets_exactly() {
        let metrics = VpnQuotaMetrics::default();
        let budget = VpnGlobalReassemblyBudget::new(100_000, 2, metrics.clone()).unwrap();
        let mut accounted_bytes = 0;
        let mut accounted_packets = 0;

        assert!(budget.try_reserve(70_000, 1).unwrap().reconcile(
            &mut accounted_bytes,
            &mut accounted_packets,
            60_000,
            1,
        ));
        assert!(matches!(
            budget.try_reserve(50_000, 1),
            Err(VpnQuotaRejection::GlobalReassemblyLimit)
        ));
        assert!(budget.try_reserve(40_000, 1).unwrap().reconcile(
            &mut accounted_bytes,
            &mut accounted_packets,
            100_000,
            2,
        ));
        budget.release_accounted(accounted_bytes, accounted_packets);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.current_reassembly_bytes, 0);
        assert_eq!(snapshot.active_reassembly_packets, 0);
        assert_eq!(snapshot.peak_reassembly_bytes, 100_000);
        assert_eq!(snapshot.peak_reassembly_packets, 2);
        assert_eq!(snapshot.global_reassembly_rejections, 1);
    }

    #[test]
    fn concurrent_global_reservations_cannot_cross_the_cap() {
        let metrics = VpnQuotaMetrics::default();
        let budget = Arc::new(
            VpnGlobalReassemblyBudget::new(VPN_MAX_IP_PACKET_LEN, 10, metrics.clone()).unwrap(),
        );
        let workers = (0..32)
            .map(|_| {
                let budget = budget.clone();
                std::thread::spawn(move || budget.try_reserve(6_553, 1).ok())
            })
            .collect::<Vec<_>>();
        let reservations = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(reservations.len(), 10);
        assert_eq!(metrics.snapshot().current_reassembly_bytes, 65_530);
        drop(reservations);
        assert_eq!(metrics.snapshot().current_reassembly_bytes, 0);
        assert_eq!(metrics.snapshot().active_reassembly_packets, 0);
    }

    #[test]
    fn identities_have_independent_rate_locks_and_tokens() {
        let started = Instant::now();
        let metrics = VpnQuotaMetrics::default();
        let limits = VpnIdentityLimits::new(1, 1, 65_535, VPN_MAX_IP_PACKET_LEN).unwrap();
        let first = VpnIdentityRateLimiter::new(limits, started, metrics.clone());
        let second = VpnIdentityRateLimiter::new(limits, started, metrics.clone());

        first
            .admit_datagram(VpnPacketDirection::Uplink, 1, started)
            .unwrap();
        assert_eq!(
            first.admit_datagram(VpnPacketDirection::Uplink, 1, started),
            Err(VpnQuotaRejection::PacketRateExceeded)
        );
        second
            .admit_datagram(VpnPacketDirection::Uplink, 1, started)
            .unwrap();
    }
}

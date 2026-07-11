//! Small, deterministic building blocks for multipath application-data scheduling.

use crate::{Duration, Instant, TIMER_GRANULARITY};

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const MIN_RATE_SAMPLE_INTERVAL: Duration = Duration::from_millis(20);
const RATE_SAMPLE_OLD_WEIGHT: u128 = 4;
const RATE_SAMPLE_TOTAL_WEIGHT: u128 = 5;
const MIN_RATE_SAMPLE_PACKETS: u64 = 4;
const RATE_IDLE_RESET_FLOOR: Duration = Duration::from_secs(2);
const WAIT_FEEDBACK_FLOOR: Duration = Duration::from_millis(200);

/// Maximum amount of unmeasured application traffic kept in flight on a path.
pub(super) const PROBE_PACKETS: u64 = 8;

/// ACK-clocked application delivery-rate estimate for one network-path generation.
///
/// Pure control packets never enter this estimator. Samples use complete ACK events rather than
/// individual packets so a compressed ACK batch cannot create a zero-duration rate spike.
#[derive(Debug, Default)]
pub(super) struct AckDeliveryRateEstimator {
    bytes_per_second: Option<u64>,
    sample_started: Option<Instant>,
    sample_bytes: u64,
    last_application_ack: Option<Instant>,
    application_bytes_in_flight: u64,
}

impl AckDeliveryRateEstimator {
    pub(super) fn on_application_sent(&mut self, bytes: u64) {
        self.application_bytes_in_flight = self.application_bytes_in_flight.saturating_add(bytes);
    }

    pub(super) fn on_application_removed(&mut self, bytes: u64) {
        self.application_bytes_in_flight = self.application_bytes_in_flight.saturating_sub(bytes);
    }

    pub(super) fn application_bytes_in_flight(&self) -> u64 {
        self.application_bytes_in_flight
    }

    pub(super) fn needs_probe(&self, now: Instant, rtt: Duration, mtu: u16) -> bool {
        self.effective_rate(now, rtt).is_none()
            && self.application_bytes_in_flight < u64::from(mtu).saturating_mul(PROBE_PACKETS)
    }

    /// Records all application-bearing packet bytes newly acknowledged by one ACK frame.
    pub(super) fn on_ack_event(
        &mut self,
        now: Instant,
        acknowledged_bytes: u64,
        app_limited: bool,
        mtu: u16,
        rtt: Duration,
    ) {
        if acknowledged_bytes == 0 {
            return;
        }

        if self
            .last_application_ack
            .is_some_and(|last| now.saturating_duration_since(last) > rate_idle_reset_after(rtt))
        {
            self.bytes_per_second = None;
            self.sample_started = None;
            self.sample_bytes = 0;
        }
        self.last_application_ack = Some(now);

        // Sparse application traffic measures application idleness, not path capacity.
        if app_limited {
            self.sample_started = None;
            self.sample_bytes = 0;
            return;
        }

        let Some(started) = self.sample_started else {
            // The first ACK event establishes the clock. Its bytes arrived before that clock and
            // are deliberately excluded from the next sample.
            self.sample_started = Some(now);
            return;
        };

        let elapsed = now.saturating_duration_since(started);
        if elapsed.is_zero() {
            // All packets acknowledged by the same ACK frame share a timestamp. The caller
            // aggregates them, but keep this guard for malformed or synthetic timestamps.
            return;
        }

        self.sample_bytes = self.sample_bytes.saturating_add(acknowledged_bytes);
        let minimum_bytes = u64::from(mtu).saturating_mul(MIN_RATE_SAMPLE_PACKETS);
        if elapsed < MIN_RATE_SAMPLE_INTERVAL || self.sample_bytes < minimum_bytes {
            return;
        }

        let raw_sample = bytes_per_second(self.sample_bytes, elapsed);
        let sample = match self.bytes_per_second {
            Some(previous) => {
                raw_sample.clamp((previous / 4).max(1), previous.saturating_mul(4).max(1))
            }
            None => raw_sample,
        };

        self.bytes_per_second = Some(match self.bytes_per_second {
            Some(previous) => {
                let weighted = u128::from(previous)
                    .saturating_mul(RATE_SAMPLE_OLD_WEIGHT)
                    .saturating_add(u128::from(sample));
                u64::try_from(weighted / RATE_SAMPLE_TOTAL_WEIGHT).unwrap_or(u64::MAX)
            }
            None => sample,
        });
        self.sample_started = Some(now);
        self.sample_bytes = 0;
    }

    pub(super) fn effective_rate(&self, now: Instant, rtt: Duration) -> Option<u64> {
        let last_ack = self.last_application_ack?;
        (now.saturating_duration_since(last_ack) <= rate_idle_reset_after(rtt))
            .then_some(self.bytes_per_second?)
    }

    pub(super) fn has_recent_feedback(&self, now: Instant, rtt: Duration) -> bool {
        self.last_application_ack.is_some_and(|last_ack| {
            now.saturating_duration_since(last_ack) <= wait_feedback_fresh_for(rtt)
        })
    }

    #[cfg(test)]
    pub(super) fn set_rate_for_test(&mut self, now: Instant, bytes_per_second: u64) {
        self.bytes_per_second = Some(bytes_per_second.max(1));
        self.last_application_ack = Some(now);
        self.sample_started = Some(now);
        self.sample_bytes = 0;
    }
}

/// Predicted arrival of one new packet on a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CompletionEstimate {
    nanos: u128,
    uncertainty_nanos: u128,
}

impl CompletionEstimate {
    pub(super) fn new(
        minimum_rtt: Duration,
        queued_bytes: u64,
        packet_bytes: u16,
        delivery_rate: u64,
    ) -> Self {
        let delivery_rate = delivery_rate.max(1);
        let queued = queued_bytes.saturating_add(u64::from(packet_bytes));
        let serialization = serialization_nanos(queued, delivery_rate);
        let one_packet = serialization_nanos(u64::from(packet_bytes), delivery_rate);

        Self {
            nanos: (minimum_rtt.as_nanos() / 2).saturating_add(serialization),
            // Predictions closer than one packet's service time (or the timer granularity) are
            // indistinguishable enough that keeping another path idle is not justified.
            uncertainty_nanos: one_packet.max(TIMER_GRANULARITY.as_nanos()),
        }
    }

    pub(super) fn nanos(self) -> u128 {
        self.nanos
    }
}

/// Whether an ECF scheduler should wait for its preferred blocked path instead of using the next
/// candidate immediately.
pub(super) fn should_wait_for_preferred(
    preferred: CompletionEstimate,
    alternate: CompletionEstimate,
    preferred_feedback_is_recent: bool,
) -> bool {
    preferred_feedback_is_recent
        && alternate.nanos > preferred.nanos.saturating_add(preferred.uncertainty_nanos)
}

fn bytes_per_second(bytes: u64, elapsed: Duration) -> u64 {
    if elapsed.is_zero() {
        return 0;
    }
    let rate = u128::from(bytes)
        .saturating_mul(NANOS_PER_SECOND)
        .checked_div(elapsed.as_nanos())
        .unwrap_or(0);
    u64::try_from(rate).unwrap_or(u64::MAX).max(1)
}

fn serialization_nanos(bytes: u64, delivery_rate: u64) -> u128 {
    u128::from(bytes)
        .saturating_mul(NANOS_PER_SECOND)
        .checked_div(u128::from(delivery_rate.max(1)))
        .unwrap_or(u128::MAX)
}

fn rate_idle_reset_after(rtt: Duration) -> Duration {
    rtt.checked_mul(8)
        .unwrap_or(Duration::MAX)
        .max(RATE_IDLE_RESET_FLOOR)
}

fn wait_feedback_fresh_for(rtt: Duration) -> Duration {
    rtt.checked_mul(3)
        .unwrap_or(Duration::MAX)
        .max(WAIT_FEEDBACK_FLOOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: u16 = 1_200;

    fn feed_rate(
        estimator: &mut AckDeliveryRateEstimator,
        start: Instant,
        first_step: u32,
        steps: u32,
        bytes_per_step: u64,
    ) {
        for step in first_step..first_step + steps {
            estimator.on_ack_event(
                start + Duration::from_millis(u64::from(step) * 25),
                bytes_per_step,
                false,
                MTU,
                Duration::from_millis(40),
            );
        }
    }

    #[test]
    fn ack_rate_converges_after_capacity_changes() {
        let start = Instant::now();
        let mut estimator = AckDeliveryRateEstimator::default();
        estimator.on_ack_event(start, 25_000, false, MTU, Duration::from_millis(40));

        feed_rate(&mut estimator, start, 1, 12, 25_000);
        let first = estimator
            .effective_rate(
                start + Duration::from_millis(300),
                Duration::from_millis(40),
            )
            .unwrap();
        assert!(first.abs_diff(1_000_000) < 20_000);

        feed_rate(&mut estimator, start, 13, 18, 75_000);
        let faster = estimator
            .effective_rate(
                start + Duration::from_millis(750),
                Duration::from_millis(40),
            )
            .unwrap();
        assert!(faster.abs_diff(3_000_000) < 120_000);

        feed_rate(&mut estimator, start, 31, 24, 12_500);
        let slower = estimator
            .effective_rate(
                start + Duration::from_millis(1_350),
                Duration::from_millis(40),
            )
            .unwrap();
        assert!(slower.abs_diff(500_000) < 45_000);
    }

    #[test]
    fn controls_and_app_limited_acks_do_not_create_rate_samples() {
        let start = Instant::now();
        let mut estimator = AckDeliveryRateEstimator::default();

        estimator.on_ack_event(start, 0, false, MTU, Duration::from_millis(20));
        estimator.on_ack_event(
            start + Duration::from_millis(25),
            20_000,
            true,
            MTU,
            Duration::from_millis(20),
        );

        assert_eq!(
            estimator.effective_rate(start + Duration::from_millis(25), Duration::from_millis(20)),
            None
        );
    }

    #[test]
    fn probing_is_bounded_and_feedback_freshness_expires() {
        let now = Instant::now();
        let rtt = Duration::from_millis(40);
        let mut estimator = AckDeliveryRateEstimator::default();

        assert!(estimator.needs_probe(now, rtt, MTU));
        estimator.on_application_sent(u64::from(MTU) * PROBE_PACKETS);
        assert_eq!(
            estimator.application_bytes_in_flight(),
            u64::from(MTU) * PROBE_PACKETS
        );
        assert!(!estimator.needs_probe(now, rtt, MTU));

        estimator.on_application_removed(u64::from(MTU));
        assert!(estimator.needs_probe(now, rtt, MTU));

        estimator.set_rate_for_test(now, 1_000_000);
        assert!(!estimator.needs_probe(now, rtt, MTU));
        assert!(estimator.has_recent_feedback(now + Duration::from_millis(100), rtt));
        assert!(!estimator.has_recent_feedback(now + Duration::from_secs(1), rtt));
        assert_eq!(
            estimator.effective_rate(now + Duration::from_secs(3), rtt),
            None
        );
    }

    #[test]
    fn equal_latency_allocation_converges_to_eight_to_twenty_five() {
        let rates = [1_000_000, 3_125_000];
        let mut assigned = [0_u64; 2];

        for _ in 0..100_000 {
            let estimates = [
                CompletionEstimate::new(Duration::from_millis(40), assigned[0], MTU, rates[0]),
                CompletionEstimate::new(Duration::from_millis(40), assigned[1], MTU, rates[1]),
            ];
            let selected = usize::from(estimates[1].nanos() < estimates[0].nanos());
            assigned[selected] = assigned[selected].saturating_add(u64::from(MTU));
        }

        let ratio = assigned[1] as f64 / assigned[0] as f64;
        assert!((ratio - 25.0 / 8.0).abs() < 0.01, "ratio was {ratio}");
    }

    #[test]
    fn heterogeneous_path_predictions_remain_in_arrival_order() {
        let rtts = [Duration::from_millis(20), Duration::from_millis(80)];
        let rates = [1_000_000, 3_125_000];
        let mut assigned = [0_u64; 2];
        let mut previous_arrival = 0;

        for _ in 0..20_000 {
            let estimates = [
                CompletionEstimate::new(rtts[0], assigned[0], MTU, rates[0]),
                CompletionEstimate::new(rtts[1], assigned[1], MTU, rates[1]),
            ];
            let selected = usize::from(estimates[1].nanos() < estimates[0].nanos());
            let arrival = estimates[selected].nanos();
            assert!(arrival >= previous_arrival);
            previous_arrival = arrival;
            assigned[selected] = assigned[selected].saturating_add(u64::from(MTU));
        }
    }

    #[test]
    fn wait_requires_a_meaningful_and_recent_advantage() {
        let preferred = CompletionEstimate::new(Duration::from_millis(10), 0, MTU, 10_000_000);
        let close_alternate =
            CompletionEstimate::new(Duration::from_millis(11), 0, MTU, 10_000_000);
        let late_alternate = CompletionEstimate::new(Duration::from_millis(80), 0, MTU, 1_000_000);

        assert!(!should_wait_for_preferred(preferred, close_alternate, true));
        assert!(should_wait_for_preferred(preferred, late_alternate, true));
        assert!(!should_wait_for_preferred(preferred, late_alternate, false));
    }

    #[test]
    fn zero_and_extreme_inputs_saturate_without_panicking() {
        assert_eq!(bytes_per_second(10, Duration::ZERO), 0);
        let estimate = CompletionEstimate::new(Duration::MAX, u64::MAX, u16::MAX, 0);
        assert!(estimate.nanos() > 0);

        let now = Instant::now();
        let mut estimator = AckDeliveryRateEstimator::default();
        estimator.on_ack_event(now, u64::MAX, false, u16::MAX, Duration::ZERO);
        estimator.on_ack_event(now, u64::MAX, false, u16::MAX, Duration::ZERO);
        assert_eq!(estimator.effective_rate(now, Duration::ZERO), None);
    }
}

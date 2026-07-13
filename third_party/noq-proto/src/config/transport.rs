#[cfg(feature = "qlog")]
use std::path::Path;
use std::{
    fmt,
    net::SocketAddr,
    num::{NonZeroU8, NonZeroU32},
    sync::Arc,
};

use crate::{
    ConnectionId, Duration, INITIAL_MTU, Instant, MAX_UDP_PAYLOAD, Side, VarInt,
    VarIntBoundsExceeded, address_discovery, congestion, connection::qlog::QlogSink,
};
#[cfg(feature = "qlog")]
use crate::{QlogFactory, QlogFileFactory};

/// Parameters governing the core QUIC state machine
///
/// Default values should be suitable for most internet applications. Applications protocols which
/// forbid remotely-initiated streams should set `max_concurrent_bidi_streams` and
/// `max_concurrent_uni_streams` to zero.
///
/// In some cases, performance or resource requirements can be improved by tuning these values to
/// suit a particular application and/or network connection. In particular, data window sizes can be
/// tuned for a particular expected round trip time, link capacity, and memory availability. Tuning
/// for higher bandwidths and latencies increases worst-case memory consumption, but does not impair
/// performance at lower bandwidths and latencies. The default configuration is tuned for a 100Mbps
/// link with a 100ms round trip time.
#[derive(Clone)]
pub struct TransportConfig {
    pub(crate) max_concurrent_bidi_streams: VarInt,
    pub(crate) max_concurrent_uni_streams: VarInt,
    pub(crate) max_idle_timeout: Option<VarInt>,
    pub(crate) stream_receive_window: VarInt,
    pub(crate) receive_window: VarInt,
    pub(crate) send_window: u64,
    pub(crate) send_fairness: bool,

    pub(crate) packet_threshold: u32,
    pub(crate) time_threshold: f32,
    pub(crate) initial_rtt: Duration,
    pub(crate) initial_mtu: u16,
    pub(crate) min_mtu: u16,
    pub(crate) mtu_discovery_config: Option<MtuDiscoveryConfig>,
    pub(crate) pad_to_mtu: bool,
    pub(crate) ack_frequency_config: Option<AckFrequencyConfig>,
    pub(crate) max_outgoing_bytes_per_second: Option<u64>,

    pub(crate) persistent_congestion_threshold: u32,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) crypto_buffer_size: usize,
    pub(crate) allow_spin: bool,
    pub(crate) datagram_receive_buffer_size: Option<usize>,
    pub(crate) datagram_send_buffer_size: usize,
    #[cfg(test)]
    pub(crate) deterministic_packet_numbers: bool,

    pub(crate) congestion_controller_factory: Arc<dyn congestion::ControllerFactory + Send + Sync>,

    pub(crate) enable_segmentation_offload: bool,

    pub(crate) address_discovery_role: address_discovery::Role,

    pub(crate) max_concurrent_multipath_paths: Option<NonZeroU32>,

    pub(crate) cross_path_pto_reinjection: bool,
    pub(crate) cross_path_abandon_reinjection: bool,
    pub(crate) cross_path_ack_progress_reinjection: bool,
    pub(crate) cross_path_ack_progress_stream_obligation: bool,
    pub(crate) cross_path_ack_progress_service_deadline: Option<Duration>,
    pub(crate) cross_path_ack_progress_service_recovery_flights: u32,
    pub(crate) cross_path_ack_progress_fresh_alternative: bool,
    pub(crate) cross_path_ack_progress_feedback_stability: bool,
    pub(crate) cross_path_ack_progress_alternative_stability: bool,
    pub(crate) cross_path_stream_progress: bool,
    pub(crate) cross_path_ack_progress_feedback_probe: bool,
    pub(crate) cross_path_ack_progress_feedback_evidence_reinjection: bool,
    pub(crate) stream_gap_rescue: bool,
    pub(crate) stream_gap_watch_rescue: bool,
    pub(crate) stream_gap_delivery_watch_rescue: bool,
    pub(crate) cross_path_ack_escape: bool,
    pub(crate) cross_path_feedback_handoff: bool,
    pub(crate) cross_path_feedback_credit_snapshot: bool,
    pub(crate) cross_path_feedback_stream_progress_snapshot: bool,
    pub(crate) cross_path_blocked_credit_handoff: bool,
    pub(crate) declared_backlogged_epoch_sensor: bool,

    pub(crate) default_path_max_idle_timeout: Option<Duration>,
    pub(crate) default_path_keep_alive_interval: Option<Duration>,

    pub(crate) max_remote_nat_traversal_addresses: Option<NonZeroU8>,
    pub(crate) server_handshake_migration: bool,

    #[cfg(feature = "qlog")]
    pub(crate) qlog_factory: Option<Arc<dyn QlogFactory>>,
}

impl TransportConfig {
    /// Maximum number of incoming bidirectional streams that may be open concurrently
    ///
    /// Must be nonzero for the peer to open any bidirectional streams.
    ///
    /// Worst-case memory use is directly proportional to `max_concurrent_bidi_streams *
    /// stream_receive_window`, with an upper bound proportional to `receive_window`.
    pub fn max_concurrent_bidi_streams(&mut self, value: VarInt) -> &mut Self {
        self.max_concurrent_bidi_streams = value;
        self
    }

    /// Variant of `max_concurrent_bidi_streams` affecting unidirectional streams
    pub fn max_concurrent_uni_streams(&mut self, value: VarInt) -> &mut Self {
        self.max_concurrent_uni_streams = value;
        self
    }

    /// Maximum duration of inactivity to accept before timing out the connection.
    ///
    /// The true idle timeout is the minimum of this and the peer's own max idle timeout. `None`
    /// represents an infinite timeout. Defaults to 30 seconds.
    ///
    /// **WARNING**: If a peer or its network path malfunctions or acts maliciously, an infinite
    /// idle timeout can result in permanently hung futures!
    ///
    /// ```
    /// # use std::{convert::TryInto, time::Duration};
    /// # use noq_proto::{TransportConfig, VarInt, VarIntBoundsExceeded};
    /// # fn main() -> Result<(), VarIntBoundsExceeded> {
    /// let mut config = TransportConfig::default();
    ///
    /// // Set the idle timeout as `VarInt`-encoded milliseconds
    /// config.max_idle_timeout(Some(VarInt::from_u32(10_000).into()));
    ///
    /// // Set the idle timeout as a `Duration`
    /// config.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    /// # Ok(())
    /// # }
    /// ```
    pub fn max_idle_timeout(&mut self, value: Option<IdleTimeout>) -> &mut Self {
        self.max_idle_timeout = value.map(|t| t.0);
        self
    }

    /// Maximum number of bytes the peer may transmit without acknowledgement on any one stream
    /// before becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Setting this smaller than `receive_window` helps ensure that a single
    /// stream doesn't monopolize receive buffers, which may otherwise occur if the application
    /// chooses not to read from a large stream for a time while still requiring data on other
    /// streams.
    pub fn stream_receive_window(&mut self, value: VarInt) -> &mut Self {
        self.stream_receive_window = value;
        self
    }

    /// Maximum number of bytes the peer may transmit across all streams of a connection before
    /// becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Larger values can be useful to allow maximum throughput within a
    /// stream while another is blocked.
    pub fn receive_window(&mut self, value: VarInt) -> &mut Self {
        self.receive_window = value;
        self
    }

    /// Maximum number of bytes to transmit to a peer without acknowledgment
    ///
    /// Provides an upper bound on memory when communicating with peers that issue large amounts of
    /// flow control credit. Endpoints that wish to handle large numbers of connections robustly
    /// should take care to set this low enough to guarantee memory exhaustion does not occur if
    /// every connection uses the entire window.
    pub fn send_window(&mut self, value: u64) -> &mut Self {
        self.send_window = value;
        self
    }

    /// Whether to implement fair queuing for send streams having the same priority.
    ///
    /// When enabled, connections schedule data from outgoing streams having the same priority in a
    /// round-robin fashion. When disabled, streams are scheduled in the order they are written to.
    ///
    /// Note that this only affects streams with the same priority. Higher priority streams always
    /// take precedence over lower priority streams.
    ///
    /// Disabling fairness can reduce fragmentation and protocol overhead for workloads that use
    /// many small streams.
    pub fn send_fairness(&mut self, value: bool) -> &mut Self {
        self.send_fairness = value;
        self
    }

    /// Maximum reordering in packet number space before FACK style loss detection considers a
    /// packet lost. Should not be less than 3, per RFC5681.
    pub fn packet_threshold(&mut self, value: u32) -> &mut Self {
        self.packet_threshold = value;
        self
    }

    /// Maximum reordering in time space before time based loss detection considers a packet lost,
    /// as a factor of RTT
    pub fn time_threshold(&mut self, value: f32) -> &mut Self {
        self.time_threshold = value;
        self
    }

    /// The RTT used before an RTT sample is taken
    pub fn initial_rtt(&mut self, value: Duration) -> &mut Self {
        self.initial_rtt = value;
        self
    }

    /// The initial value to be used as the maximum UDP payload size before running MTU discovery
    /// (see [`TransportConfig::mtu_discovery_config`]).
    ///
    /// Must be at least 1200, which is the default, and known to be safe for typical internet
    /// applications. Larger values are more efficient, but increase the risk of packet loss due to
    /// exceeding the network path's IP MTU. If the provided value is higher than what the network
    /// path actually supports, packet loss will eventually trigger black hole detection and bring
    /// it down to [`TransportConfig::min_mtu`].
    pub fn initial_mtu(&mut self, value: u16) -> &mut Self {
        self.initial_mtu = value.max(INITIAL_MTU);
        self
    }

    pub(crate) fn get_initial_mtu(&self) -> u16 {
        self.initial_mtu.max(self.min_mtu)
    }

    /// The maximum UDP payload size guaranteed to be supported by the network.
    ///
    /// Must be at least 1200, which is the default, and lower than or equal to
    /// [`TransportConfig::initial_mtu`].
    ///
    /// Real-world MTUs can vary according to ISP, VPN, and properties of intermediate network links
    /// outside of either endpoint's control. Extreme care should be used when raising this value
    /// outside of private networks where these factors are fully controlled. If the provided value
    /// is higher than what the network path actually supports, the result will be unpredictable and
    /// catastrophic packet loss, without a possibility of repair. Prefer
    /// [`TransportConfig::initial_mtu`] together with
    /// [`TransportConfig::mtu_discovery_config`] to set a maximum UDP payload size that robustly
    /// adapts to the network.
    pub fn min_mtu(&mut self, value: u16) -> &mut Self {
        self.min_mtu = value.max(INITIAL_MTU);
        self
    }

    /// Specifies the MTU discovery config (see [`MtuDiscoveryConfig`] for details).
    ///
    /// Enabled by default.
    pub fn mtu_discovery_config(&mut self, value: Option<MtuDiscoveryConfig>) -> &mut Self {
        self.mtu_discovery_config = value;
        self
    }

    /// Pad UDP datagrams carrying application data to current maximum UDP payload size
    ///
    /// Disabled by default. UDP datagrams containing loss probes are exempt from padding.
    ///
    /// Enabling this helps mitigate traffic analysis by network observers, but it increases
    /// bandwidth usage. Without this mitigation precise plain text size of application datagrams as
    /// well as the total size of stream write bursts can be inferred by observers under certain
    /// conditions. This analysis requires either an uncongested connection or application datagrams
    /// too large to be coalesced.
    pub fn pad_to_mtu(&mut self, value: bool) -> &mut Self {
        self.pad_to_mtu = value;
        self
    }

    /// Specifies the ACK frequency config (see [`AckFrequencyConfig`] for details)
    ///
    /// The provided configuration will be ignored if the peer does not support the acknowledgement
    /// frequency QUIC extension.
    ///
    /// Defaults to `None`, which disables controlling the peer's acknowledgement frequency. Even
    /// if set to `None`, the local side still supports the acknowledgement frequency QUIC
    /// extension and may use it in other ways.
    pub fn ack_frequency_config(&mut self, value: Option<AckFrequencyConfig>) -> &mut Self {
        self.ack_frequency_config = value;
        self
    }

    /// Configures an outbound rate limit (in bytes per second) for each connection.
    ///
    /// Defaults to `None`, which disables rate limiting.
    pub fn max_outgoing_bytes_per_second(&mut self, value: Option<u64>) -> &mut Self {
        self.max_outgoing_bytes_per_second = value;
        self
    }

    /// Number of consecutive PTOs after which network is considered to be experiencing persistent congestion.
    pub fn persistent_congestion_threshold(&mut self, value: u32) -> &mut Self {
        self.persistent_congestion_threshold = value;
        self
    }

    /// Period of inactivity before sending a keep-alive packet
    ///
    /// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
    ///
    /// `None` to disable, which is the default. Only one side of any given connection needs keep-alive
    /// enabled for the connection to be preserved. Must be set lower than the idle_timeout of both
    /// peers to be effective.
    pub fn keep_alive_interval(&mut self, value: Option<Duration>) -> &mut Self {
        self.keep_alive_interval = value;
        self
    }

    /// Maximum quantity of out-of-order crypto layer data to buffer
    pub fn crypto_buffer_size(&mut self, value: usize) -> &mut Self {
        self.crypto_buffer_size = value;
        self
    }

    /// Whether the implementation is permitted to set the spin bit on this connection
    ///
    /// This allows passive observers to easily judge the round trip time of a connection, which can
    /// be useful for network administration but sacrifices a small amount of privacy.
    pub fn allow_spin(&mut self, value: bool) -> &mut Self {
        self.allow_spin = value;
        self
    }

    /// Maximum number of incoming application datagram bytes to buffer, or None to disable
    /// incoming datagrams
    ///
    /// The peer is forbidden to send single datagrams larger than this size. If the aggregate size
    /// of all datagrams that have been received from the peer but not consumed by the application
    /// exceeds this value, old datagrams are dropped until it is no longer exceeded.
    pub fn datagram_receive_buffer_size(&mut self, value: Option<usize>) -> &mut Self {
        self.datagram_receive_buffer_size = value;
        self
    }

    /// Maximum number of outgoing application datagram bytes to buffer
    ///
    /// While datagrams are sent ASAP, it is possible for an application to generate data faster
    /// than the link, or even the underlying hardware, can transmit them. This limits the amount of
    /// memory that may be consumed in that case. When the send buffer is full and a new datagram is
    /// sent, older datagrams are dropped until sufficient space is available.
    pub fn datagram_send_buffer_size(&mut self, value: usize) -> &mut Self {
        self.datagram_send_buffer_size = value;
        self
    }

    /// Whether to force every packet number to be used
    ///
    /// By default, packet numbers are occasionally skipped to ensure peers aren't ACKing packets
    /// before they see them.
    #[cfg(test)]
    pub(crate) fn deterministic_packet_numbers(&mut self, enabled: bool) -> &mut Self {
        self.deterministic_packet_numbers = enabled;
        self
    }

    /// How to construct new `congestion::Controller`s
    ///
    /// Typically the refcounted configuration of a `congestion::Controller`,
    /// e.g. a `congestion::NewRenoConfig`.
    ///
    /// # Example
    /// ```
    /// # use noq_proto::*; use std::sync::Arc;
    /// let mut config = TransportConfig::default();
    /// config.congestion_controller_factory(Arc::new(congestion::NewRenoConfig::default()));
    /// ```
    pub fn congestion_controller_factory(
        &mut self,
        factory: Arc<dyn congestion::ControllerFactory + Send + Sync + 'static>,
    ) -> &mut Self {
        self.congestion_controller_factory = factory;
        self
    }

    /// Whether to use "Generic Segmentation Offload" to accelerate transmits, when supported by the
    /// environment
    ///
    /// Defaults to `true`.
    ///
    /// GSO dramatically reduces CPU consumption when sending large numbers of packets with the same
    /// headers, such as when transmitting bulk data on a connection. However, it is not supported
    /// by all network interface drivers or packet inspection tools. `noq-udp` will attempt to
    /// disable GSO automatically when unavailable, but this can lead to spurious packet loss at
    /// startup, temporarily degrading performance.
    pub fn enable_segmentation_offload(&mut self, enabled: bool) -> &mut Self {
        self.enable_segmentation_offload = enabled;
        self
    }

    /// Whether to send observed address reports to peers.
    ///
    /// This will aid peers in inferring their reachable address, which in most NATd networks
    /// will not be easily available to them.
    pub fn send_observed_address_reports(&mut self, enabled: bool) -> &mut Self {
        self.address_discovery_role.send = enabled;
        self
    }

    /// Whether to receive observed address reports from other peers.
    ///
    /// Peers with the address discovery extension enabled that are willing to provide observed
    /// address reports will do so if this transport parameter is set. In general, observed address
    /// reports cannot be trusted. This, however, can aid the current endpoint in inferring its
    /// reachable address, which in most NATd networks will not be easily available.
    pub fn receive_observed_address_reports(&mut self, enabled: bool) -> &mut Self {
        self.address_discovery_role.receive = enabled;
        self
    }

    /// Enables the Multipath Extension for QUIC.
    ///
    /// Setting this to any nonzero value will enable the Multipath Extension for QUIC,
    /// <https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/>.
    ///
    /// The value provided specifies the number maximum number of paths this endpoint may open
    /// concurrently when multipath is negotiated. For any path to be opened, the remote must
    /// enable multipath as well.
    pub fn max_concurrent_multipath_paths(&mut self, max_concurrent: u32) -> &mut Self {
        self.max_concurrent_multipath_paths = NonZeroU32::new(max_concurrent);
        self
    }

    /// Whether the first data PTO on a multipath path may queue its outstanding STREAM data for
    /// retransmission over another validated path.
    ///
    /// This follows the cross-path recovery option described by Multipath QUIC section 5.7 while
    /// leaving final path abandonment to the normal idle and validation machinery. Retransmitted
    /// data remains subject to the destination path's congestion window and pacing.
    ///
    /// Disabled by default.
    pub fn cross_path_pto_reinjection(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_pto_reinjection = enabled;
        self
    }

    /// Whether abandoning a multipath path may immediately queue its outstanding STREAM data for
    /// retransmission over another validated path.
    ///
    /// Packet-number state for the abandoned path is still retained for the normal Multipath QUIC
    /// drain period. This only separates application-data recovery from final path-state removal;
    /// retransmitted data remains subject to the destination path's congestion window and pacing.
    ///
    /// Disabled by default.
    pub fn cross_path_abandon_reinjection(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_abandon_reinjection = enabled;
        self
    }

    /// Whether a multipath path with outstanding STREAM data may start one cross-path recovery
    /// episode after a full PTO interval without any newly acknowledged ack-eliciting packet.
    ///
    /// Unlike the standard QUIC PTO timer, the recovery deadline is anchored to the start of the
    /// current ACK-progress epoch and is not postponed by sending more packets. Standard loss
    /// detection and final path abandonment are unchanged. Reinjected data remains subject to the
    /// destination path's congestion window and pacing.
    ///
    /// Disabled by default.
    pub fn cross_path_ack_progress_reinjection(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_ack_progress_reinjection = enabled;
        self
    }

    /// Whether ACK-progress recovery should age the oldest retained STREAM obligation instead of
    /// treating every newly acknowledged ack-eliciting packet as application progress.
    ///
    /// When enabled, ACKs for later packets do not postpone recovery while the same
    /// `(stream_id, offset)` remains in the suspected path's sent-packet table. This option has no
    /// effect unless ACK-progress reinjection is also enabled. Disabled by default so earlier
    /// experiments retain their packet-level epoch semantics.
    pub fn cross_path_ack_progress_stream_obligation(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_ack_progress_stream_obligation = enabled;
        self
    }

    /// Sets an optional application-level service target for cross-path STREAM recovery.
    ///
    /// When configured, the complete-recovery trigger is capped so that one PTO on the selected
    /// alternative path, plus timer granularity, remains before this duration has elapsed since
    /// the watched STREAM obligation was originally sent. The ordinary per-path PTO remains an
    /// upper bound, and standard QUIC loss detection, congestion control, path-idle handling, and
    /// Multipath QUIC's packet-number-space drain are unchanged.
    ///
    /// This is a recovery scheduling target rather than a delivery guarantee: actual completion
    /// still depends on the validated alternative path's service. Disabled by default.
    pub fn cross_path_ack_progress_service_deadline(
        &mut self,
        deadline: Option<Duration>,
    ) -> &mut Self {
        self.cross_path_ack_progress_service_deadline = deadline;
        self
    }

    /// Sets how many alternative-path PTO service intervals are reserved before an application
    /// recovery target expires.
    ///
    /// A value of one preserves the historical single-flight budget. Larger values move only the
    /// experimental complete-recovery trigger earlier; they do not alter RTT, congestion control,
    /// path-idle handling, or Multipath QUIC's three-PTO packet-number-space drain. Values below
    /// one are clamped to one. Defaults to one.
    pub fn cross_path_ack_progress_service_recovery_flights(&mut self, flights: u32) -> &mut Self {
        self.cross_path_ack_progress_service_recovery_flights = flights.max(1);
        self
    }

    /// Whether ACK-progress recovery may only move toward an alternative path with strictly newer
    /// authenticated feedback than the suspected path.
    ///
    /// This gives recovery a monotonic direction: a path that is still receiving authenticated
    /// packets can rescue a path whose feedback version is older, while the healthy path cannot
    /// immediately send speculative recovery back toward that stale route. It changes neither
    /// path-idle abandonment nor Multipath QUIC's packet-number-space drain. Disabled by default.
    pub fn cross_path_ack_progress_fresh_alternative(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_ack_progress_fresh_alternative = enabled;
        self
    }

    /// Whether ACK-progress recovery must first observe a source-path feedback silence interval.
    ///
    /// The interval is the source path's smoothed RTT, plus the peer's advertised maximum ACK
    /// delay and timer granularity, measured from the latest authenticated packet on that path.
    /// Authenticated feedback refreshes the interval, and recovery actions recheck it before
    /// probing or reinjecting. This prevents a transient ordering inversion between two live path
    /// feedback versions from sending recovery toward the route that is actually stale.
    ///
    /// This option changes only the experimental ACK-progress recovery schedule. It does not
    /// change standard loss detection, congestion control, path-idle handling, or Multipath
    /// QUIC's three-PTO packet-number-space drain. Disabled by default.
    pub fn cross_path_ack_progress_feedback_stability(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_ack_progress_feedback_stability = enabled;
        self
    }

    /// Whether ACK-progress recovery must observe one continuously newer alternative path before
    /// using it for a feedback probe or STREAM reinjection.
    ///
    /// The candidate is bound to the source path's authenticated-feedback version and current
    /// ACK-progress obligation epoch. It must remain the same strictly newer validated path for
    /// that candidate path's smoothed RTT, plus the peer's advertised maximum ACK delay and timer
    /// granularity. Further authenticated packets on the same candidate do not restart the
    /// interval; source feedback, a candidate change or disappearance, and an obligation-epoch
    /// change do.
    ///
    /// This option changes only the experimental ACK-progress recovery schedule. It does not
    /// change RTT estimation, congestion control, standard loss detection, path-idle handling, or
    /// Multipath QUIC's three-PTO packet-number-space drain. Disabled by default.
    pub fn cross_path_ack_progress_alternative_stability(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_ack_progress_alternative_stability = enabled;
        self
    }

    /// Whether this endpoint advertises and, when negotiated, emits data-level STREAM progress.
    ///
    /// `STREAM_PROGRESS` reports only the contiguous prefix consumed by the receiving application.
    /// It can retire duplicate STREAM retransmission debt across packet-number spaces while packet
    /// ACK, RTT, congestion control, and loss accounting remain unchanged. Disabled by default.
    pub fn cross_path_stream_progress(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_stream_progress = enabled;
        self
    }

    /// Whether ACK-progress recovery may first send one bounded STREAM feedback probe on the
    /// validated alternative path.
    ///
    /// The probe is scheduled one alternative-path PTO before the existing full recovery
    /// deadline. Its purpose is to obtain cumulative PATH_ACK and other monotonic feedback before
    /// the sender snapshots the whole uncertain STREAM set. If feedback does not arrive, the
    /// existing full recovery still runs at its original deadline. This option has no effect
    /// unless ACK-progress reinjection and cross-path ACK escape are also enabled.
    ///
    /// Disabled by default.
    pub fn cross_path_ack_progress_feedback_probe(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_ack_progress_feedback_probe = enabled;
        self
    }

    /// Whether a cumulative ACK returned on the feedback-probe path may immediately trigger
    /// selective reinjection of the STREAM frames still retained on the suspected path.
    ///
    /// ACK processing first removes every range the peer proved delivered. The remaining
    /// sent-packet metadata is therefore the current recovery obligation, so waiting until the
    /// original full-recovery deadline only adds latency after uncertainty has already collapsed.
    /// If no cross-path evidence arrives, the original deadline remains unchanged. This option
    /// has no effect unless the bounded feedback probe is also enabled.
    ///
    /// Disabled by default.
    pub fn cross_path_ack_progress_feedback_evidence_reinjection(
        &mut self,
        enabled: bool,
    ) -> &mut Self {
        self.cross_path_ack_progress_feedback_evidence_reinjection = enabled;
        self
    }

    /// Whether a recovery feedback-path handoff also requeues the newest STREAM_PROGRESS value
    /// already carried by an unacknowledged packet on another path.
    ///
    /// STREAM_PROGRESS is cumulative and monotonic. Reissuing its maximum in-flight offset on the
    /// preferred feedback path lets the sender retire stale retransmission debt without waiting
    /// for standard loss detection on a blackholed route. This option has no effect unless stream
    /// progress and feedback-path handoff are also enabled.
    ///
    /// It changes neither packet acknowledgment, RTT estimation, congestion control, standard
    /// loss detection, path-idle handling, nor Multipath QUIC's three-PTO drain. Disabled by
    /// default.
    pub fn cross_path_feedback_stream_progress_snapshot(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_feedback_stream_progress_snapshot = enabled;
        self
    }

    /// Whether loss detection may arm one congestion-exempt, pacing-limited STREAM rescue packet
    /// per newly advanced ACK frontier when no other validated path is usable.
    ///
    /// This is a bounded analogue of RACK-TLP/PRR rescue transmission. It applies only after
    /// STREAM data has already been declared lost and queued for retransmission, and only when the
    /// next datagram would otherwise remain congestion-window blocked. Ordinary congestion-window
    /// accounting and reduction are unchanged; the exemption covers at most one datagram for that
    /// ACK frontier. Disabled by default.
    pub fn stream_gap_rescue(&mut self, enabled: bool) -> &mut Self {
        self.stream_gap_rescue = enabled;
        self
    }

    /// Whether the sole usable path may watch a stable lowest STREAM retransmit offset and send
    /// one paced, congestion-exempt rescue packet after that exact gap remains queued for one RTT
    /// plus the peer's ACK delay.
    ///
    /// ACKs for later packets do not postpone this timer, but transmitting or acknowledging the
    /// watched retransmit removes the gap and cancels the rescue. This targets persistent
    /// application head-of-line blocking without applying a congestion exemption to every loss.
    /// Disabled by default.
    pub fn stream_gap_watch_rescue(&mut self, enabled: bool) -> &mut Self {
        self.stream_gap_watch_rescue = enabled;
        self
    }

    /// Whether a stable STREAM-gap watch remains active after the retransmit is packetized until
    /// that exact byte obligation is acknowledged.
    ///
    /// The historical gap watch observes only retransmits still queued for transmission. This
    /// extension also recognizes the same `(stream, offset)` in the path's sent-packet table. If
    /// it remains outstanding for one RTT plus the peer's ACK delay, one paced loss-probe copy is
    /// permitted. Each exact gap identity can trigger at most once before ordered progress exposes
    /// a new gap. It does not acknowledge packets, change congestion-window accounting, or alter
    /// standard loss detection. Disabled by default.
    pub fn stream_gap_delivery_watch_rescue(&mut self, enabled: bool) -> &mut Self {
        self.stream_gap_delivery_watch_rescue = enabled;
        self
    }

    /// Whether a cross-path recovery episode may request one cumulative PATH_ACK response on the
    /// same validated alternative path that carries the recovery data.
    ///
    /// This uses the existing IMMEDIATE_ACK and PATH_ACK frames. Ordinary acknowledgments still
    /// prefer their own path; the exception is armed only by an explicit PTO or ACK-progress
    /// recovery episode. Path status, idle detection, and path-state drain periods are unchanged.
    ///
    /// Disabled by default.
    pub fn cross_path_ack_escape(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_ack_escape = enabled;
        self
    }

    /// Whether a recovery packet carrying STREAM data and IMMEDIATE_ACK may promote its validated
    /// path for the receiver's own outbound feedback while demoting the other open paths to
    /// backup status.
    ///
    /// The handoff uses standard PATH_STATUS frames and local multipath scheduling. It does not
    /// abandon any path, shorten path timers, or bypass congestion control. Disabled by default.
    pub fn cross_path_feedback_handoff(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_feedback_handoff = enabled;
        self
    }

    /// Whether feedback handoff also snapshots monotonic flow-control frames which are still
    /// retained in packets on non-preferred paths and queues their latest values for the promoted
    /// path.
    ///
    /// This is intentionally separate from [`Self::cross_path_feedback_handoff`] so experiments
    /// using the earlier handoff behavior remain reproducible. Disabled by default.
    pub fn cross_path_feedback_credit_snapshot(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_feedback_credit_snapshot = enabled;
        self
    }

    /// Whether a stale `DATA_BLOCKED` or `STREAM_DATA_BLOCKED` frame received on a validated path
    /// may promote that path for feedback and requeue the newest monotonic flow-control credit.
    ///
    /// A requeue occurs only when local credit is strictly greater than the limit reported by the
    /// peer. The standard blocked frame therefore acts as an explicit negative acknowledgment for
    /// already-generated credit; no new wire format or larger receive window is introduced.
    /// Disabled by default.
    pub fn cross_path_blocked_credit_handoff(&mut self, enabled: bool) -> &mut Self {
        self.cross_path_blocked_credit_handoff = enabled;
        self
    }

    /// Enables the default-off diagnostic sensor for an application-declared backlogged epoch.
    /// The sensor records service observations but never changes scheduling or congestion control.
    pub fn declared_backlogged_epoch_sensor(&mut self, enabled: bool) -> &mut Self {
        self.declared_backlogged_epoch_sensor = enabled;
        self
    }

    /// Sets a default per-path maximum idle timeout
    ///
    /// If the path is idle for this long the path will be abandoned. Bear in mind this will
    /// interact with the [`TransportConfig::max_idle_timeout`], if the last path is
    /// abandoned the entire connection will be closed.
    ///
    /// You can also change this using [`Connection::set_path_max_idle_timeout`] for
    /// existing paths.
    ///
    /// [`Connection::set_path_max_idle_timeout`]: crate::Connection::set_path_max_idle_timeout
    pub fn default_path_max_idle_timeout(&mut self, timeout: Option<Duration>) -> &mut Self {
        self.default_path_max_idle_timeout = timeout;
        self
    }

    /// Sets a default per-path keep alive interval
    ///
    /// Note that this does not interact with the connection-wide
    /// [`TransportConfig::keep_alive_interval`].  This setting will keep this path active,
    /// [`TransportConfig::keep_alive_interval`] will keep the connection active, with no
    /// control over which path is used for this.
    ///
    /// You can also change this using [`Connection::set_path_keep_alive_interval`] for
    /// existing path.
    ///
    /// [`Connection::set_path_keep_alive_interval`]: crate::Connection::set_path_keep_alive_interval
    pub fn default_path_keep_alive_interval(&mut self, interval: Option<Duration>) -> &mut Self {
        self.default_path_keep_alive_interval = interval;
        self
    }

    /// Get the initial max [`crate::PathId`] this endpoint allows.
    ///
    /// Returns `None` if multipath is disabled.
    pub(crate) fn get_initial_max_path_id(&self) -> Option<crate::PathId> {
        self.max_concurrent_multipath_paths
            // a max_concurrent_multipath_paths value of 1 only allows the first path, which
            // has id 0
            .map(|nonzero_concurrent| nonzero_concurrent.get() - 1)
            .map(Into::into)
    }

    /// Sets the maximum number of nat traversal addresses this endpoint allows the remote to
    /// advertise
    ///
    /// Setting this to any nonzero value will enable n0's nat traversal protocol, loosely based in
    /// the Nat Traversal Extension for QUIC, see
    /// <https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-02.html>
    ///
    /// This implementation expects the multipath extension to be enabled as well. if not yet
    /// enabled via [`Self::max_concurrent_multipath_paths`], then that setting is set to 8.
    pub fn max_remote_nat_traversal_addresses(&mut self, max_addresses: u8) -> &mut Self {
        self.max_remote_nat_traversal_addresses = NonZeroU8::new(max_addresses);
        if max_addresses != 0 && self.max_concurrent_multipath_paths.is_none() {
            self.max_concurrent_multipath_paths(8);
        }
        self
    }

    /// Sets whether the server is allowed to migrate once during the handshake.
    ///
    /// **Enabling this is not RFC9000 compliant.**
    ///
    /// Defaults to `false`.
    ///
    /// Enabling this allows the server to migrate once during the handshake: it can send a
    /// response from a different address than the client's initial packet was sent to. Once
    /// an authenticated Handshake packet is received the server can no longer migrate
    /// during the handshake (or after the handshake if not other extension enables this).
    ///
    /// This can be used to duplicate the client's initial packet to multiple addresses for
    /// the server and accept the fastest response. The server will discard all but the
    /// first such initial, considering any remaining as duplicates.
    pub fn server_handshake_migration(&mut self, allow_migration: bool) -> &mut Self {
        self.server_handshake_migration = allow_migration;
        self
    }

    /// Configures qlog capturing by setting a [`QlogFactory`].
    ///
    /// This assigns a [`QlogFactory`] that produces qlog capture configurations for
    /// individual connections.
    #[cfg(feature = "qlog")]
    pub fn qlog_factory(&mut self, factory: Arc<dyn QlogFactory>) -> &mut Self {
        self.qlog_factory = Some(factory);
        self
    }

    /// Configures qlog capturing through the `QLOGDIR` environment variable.
    ///
    /// This uses [`QlogFileFactory::from_env`] to create a factory to write qlog traces
    /// into the directory set through the `QLOGDIR` environment variable.
    ///
    /// If `QLOGDIR` is not set, no traces will be written. If `QLOGDIR` is set to a path
    /// that does not exist, it will be created.
    ///
    /// The files will be prefixed with `prefix`.
    #[cfg(feature = "qlog")]
    pub fn qlog_from_env(&mut self, prefix: &str) -> &mut Self {
        self.qlog_factory(Arc::new(QlogFileFactory::from_env().with_prefix(prefix)))
    }

    /// Configures qlog capturing into a directory.
    ///
    /// This uses [`QlogFileFactory`] to create a factory to write qlog traces into
    /// the specified directory.  The files will be prefixed with `prefix`.
    #[cfg(feature = "qlog")]
    pub fn qlog_from_path(&mut self, path: impl AsRef<Path>, prefix: &str) -> &mut Self {
        self.qlog_factory(Arc::new(
            QlogFileFactory::new(path.as_ref().to_owned()).with_prefix(prefix),
        ))
    }

    pub(crate) fn create_qlog_sink(
        &self,
        side: Side,
        remote: SocketAddr,
        initial_dst_cid: ConnectionId,
        now: Instant,
    ) -> QlogSink {
        #[cfg(not(feature = "qlog"))]
        let sink = {
            let _ = (side, remote, initial_dst_cid, now);
            QlogSink::default()
        };

        #[cfg(feature = "qlog")]
        let sink = {
            if let Some(config) = self
                .qlog_factory
                .as_ref()
                .and_then(|factory| factory.for_connection(side, remote, initial_dst_cid, now))
            {
                QlogSink::new(config, initial_dst_cid, side, now)
            } else {
                QlogSink::default()
            }
        };

        sink
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        const EXPECTED_RTT: u32 = 100; // ms
        const MAX_STREAM_BANDWIDTH: u32 = 12500 * 1000; // bytes/s
        // Window size needed to avoid pipeline
        // stalls
        const STREAM_RWND: u32 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;

        Self {
            max_concurrent_bidi_streams: 100u32.into(),
            max_concurrent_uni_streams: 100u32.into(),
            // 30 second default recommended by RFC 9308 § 3.2
            max_idle_timeout: Some(VarInt(30_000)),
            stream_receive_window: STREAM_RWND.into(),
            receive_window: VarInt::MAX,
            send_window: (8 * STREAM_RWND).into(),
            send_fairness: true,

            packet_threshold: 3,
            time_threshold: 9.0 / 8.0,
            initial_rtt: Duration::from_millis(333), // per spec, intentionally distinct from EXPECTED_RTT
            initial_mtu: INITIAL_MTU,
            min_mtu: INITIAL_MTU,
            mtu_discovery_config: Some(MtuDiscoveryConfig::default()),
            pad_to_mtu: false,
            ack_frequency_config: None,
            max_outgoing_bytes_per_second: None,

            persistent_congestion_threshold: 3,
            keep_alive_interval: None,
            crypto_buffer_size: 16 * 1024,
            allow_spin: true,
            datagram_receive_buffer_size: Some(STREAM_RWND as usize),
            datagram_send_buffer_size: 1024 * 1024,
            #[cfg(test)]
            deterministic_packet_numbers: false,

            congestion_controller_factory: Arc::new(congestion::CubicConfig::default()),

            enable_segmentation_offload: true,

            address_discovery_role: address_discovery::Role::default(),

            // disabled multipath by default
            max_concurrent_multipath_paths: None,
            cross_path_pto_reinjection: false,
            cross_path_abandon_reinjection: false,
            cross_path_ack_progress_reinjection: false,
            cross_path_ack_progress_stream_obligation: false,
            cross_path_ack_progress_service_deadline: None,
            cross_path_ack_progress_service_recovery_flights: 1,
            cross_path_ack_progress_fresh_alternative: false,
            cross_path_ack_progress_feedback_stability: false,
            cross_path_ack_progress_alternative_stability: false,
            cross_path_stream_progress: false,
            cross_path_ack_progress_feedback_probe: false,
            cross_path_ack_progress_feedback_evidence_reinjection: false,
            stream_gap_rescue: false,
            stream_gap_watch_rescue: false,
            stream_gap_delivery_watch_rescue: false,
            cross_path_ack_escape: false,
            cross_path_feedback_handoff: false,
            cross_path_feedback_credit_snapshot: false,
            cross_path_feedback_stream_progress_snapshot: false,
            cross_path_blocked_credit_handoff: false,
            declared_backlogged_epoch_sensor: false,
            default_path_max_idle_timeout: None,
            default_path_keep_alive_interval: None,

            // nat traversal disabled by default
            max_remote_nat_traversal_addresses: None,
            server_handshake_migration: false,

            #[cfg(feature = "qlog")]
            qlog_factory: None,
        }
    }
}

impl fmt::Debug for TransportConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            max_concurrent_bidi_streams,
            max_concurrent_uni_streams,
            max_idle_timeout,
            stream_receive_window,
            receive_window,
            send_window,
            send_fairness,
            packet_threshold,
            time_threshold,
            initial_rtt,
            initial_mtu,
            min_mtu,
            mtu_discovery_config,
            pad_to_mtu,
            ack_frequency_config,
            max_outgoing_bytes_per_second,
            persistent_congestion_threshold,
            keep_alive_interval,
            crypto_buffer_size,
            allow_spin,
            datagram_receive_buffer_size,
            datagram_send_buffer_size,
            #[cfg(test)]
                deterministic_packet_numbers: _,
            congestion_controller_factory: _,
            enable_segmentation_offload,
            address_discovery_role,
            max_concurrent_multipath_paths,
            cross_path_pto_reinjection,
            cross_path_abandon_reinjection,
            cross_path_ack_progress_reinjection,
            cross_path_ack_progress_stream_obligation,
            cross_path_ack_progress_service_deadline,
            cross_path_ack_progress_service_recovery_flights,
            cross_path_ack_progress_fresh_alternative,
            cross_path_ack_progress_feedback_stability,
            cross_path_ack_progress_alternative_stability,
            cross_path_stream_progress,
            cross_path_ack_progress_feedback_probe,
            cross_path_ack_progress_feedback_evidence_reinjection,
            stream_gap_rescue,
            stream_gap_watch_rescue,
            stream_gap_delivery_watch_rescue,
            cross_path_ack_escape,
            cross_path_feedback_handoff,
            cross_path_feedback_credit_snapshot,
            cross_path_feedback_stream_progress_snapshot,
            cross_path_blocked_credit_handoff,
            declared_backlogged_epoch_sensor,
            default_path_max_idle_timeout,
            default_path_keep_alive_interval,
            max_remote_nat_traversal_addresses,
            server_handshake_migration,
            #[cfg(feature = "qlog")]
            qlog_factory,
        } = self;
        let mut s = fmt.debug_struct("TransportConfig");

        s.field("max_concurrent_bidi_streams", max_concurrent_bidi_streams)
            .field("max_concurrent_uni_streams", max_concurrent_uni_streams)
            .field("max_idle_timeout", max_idle_timeout)
            .field("stream_receive_window", stream_receive_window)
            .field("receive_window", receive_window)
            .field("send_window", send_window)
            .field("send_fairness", send_fairness)
            .field("packet_threshold", packet_threshold)
            .field("time_threshold", time_threshold)
            .field("initial_rtt", initial_rtt)
            .field("initial_mtu", initial_mtu)
            .field("min_mtu", min_mtu)
            .field("mtu_discovery_config", mtu_discovery_config)
            .field("pad_to_mtu", pad_to_mtu)
            .field("ack_frequency_config", ack_frequency_config)
            .field(
                "max_outgoing_bytes_per_second",
                max_outgoing_bytes_per_second,
            )
            .field(
                "persistent_congestion_threshold",
                persistent_congestion_threshold,
            )
            .field("keep_alive_interval", keep_alive_interval)
            .field("crypto_buffer_size", crypto_buffer_size)
            .field("allow_spin", allow_spin)
            .field("datagram_receive_buffer_size", datagram_receive_buffer_size)
            .field("datagram_send_buffer_size", datagram_send_buffer_size)
            // congestion_controller_factory not debug
            .field("enable_segmentation_offload", enable_segmentation_offload)
            .field("address_discovery_role", address_discovery_role)
            .field(
                "max_concurrent_multipath_paths",
                max_concurrent_multipath_paths,
            )
            .field("cross_path_pto_reinjection", cross_path_pto_reinjection)
            .field(
                "cross_path_abandon_reinjection",
                cross_path_abandon_reinjection,
            )
            .field(
                "cross_path_ack_progress_reinjection",
                cross_path_ack_progress_reinjection,
            )
            .field(
                "cross_path_ack_progress_stream_obligation",
                cross_path_ack_progress_stream_obligation,
            )
            .field(
                "cross_path_ack_progress_service_deadline",
                cross_path_ack_progress_service_deadline,
            )
            .field(
                "cross_path_ack_progress_service_recovery_flights",
                cross_path_ack_progress_service_recovery_flights,
            )
            .field(
                "cross_path_ack_progress_fresh_alternative",
                cross_path_ack_progress_fresh_alternative,
            )
            .field(
                "cross_path_ack_progress_feedback_stability",
                cross_path_ack_progress_feedback_stability,
            )
            .field(
                "cross_path_ack_progress_alternative_stability",
                cross_path_ack_progress_alternative_stability,
            )
            .field("cross_path_stream_progress", cross_path_stream_progress)
            .field(
                "cross_path_ack_progress_feedback_probe",
                cross_path_ack_progress_feedback_probe,
            )
            .field(
                "cross_path_ack_progress_feedback_evidence_reinjection",
                cross_path_ack_progress_feedback_evidence_reinjection,
            )
            .field("stream_gap_rescue", stream_gap_rescue)
            .field("stream_gap_watch_rescue", stream_gap_watch_rescue)
            .field(
                "stream_gap_delivery_watch_rescue",
                stream_gap_delivery_watch_rescue,
            )
            .field("cross_path_ack_escape", cross_path_ack_escape)
            .field("cross_path_feedback_handoff", cross_path_feedback_handoff)
            .field(
                "cross_path_feedback_credit_snapshot",
                cross_path_feedback_credit_snapshot,
            )
            .field(
                "cross_path_feedback_stream_progress_snapshot",
                cross_path_feedback_stream_progress_snapshot,
            )
            .field(
                "cross_path_blocked_credit_handoff",
                cross_path_blocked_credit_handoff,
            )
            .field(
                "declared_backlogged_epoch_sensor",
                declared_backlogged_epoch_sensor,
            )
            .field(
                "default_path_max_idle_timeout",
                default_path_max_idle_timeout,
            )
            .field(
                "default_path_keep_alive_interval",
                default_path_keep_alive_interval,
            )
            .field(
                "max_remote_nat_traversal_addresses",
                max_remote_nat_traversal_addresses,
            )
            .field("server_handshake_migration", server_handshake_migration);
        #[cfg(feature = "qlog")]
        s.field("qlog_factory", &qlog_factory.is_some());

        s.finish_non_exhaustive()
    }
}

/// Parameters for controlling the peer's acknowledgement frequency
///
/// The parameters provided in this config will be sent to the peer at the beginning of the
/// connection, so it can take them into account when sending acknowledgements (see each parameter's
/// description for details on how it influences acknowledgement frequency).
///
/// noq's implementation follows the fourth draft of the
/// [QUIC Acknowledgement Frequency extension](https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-04).
/// The defaults produce behavior slightly different than the behavior without this extension,
/// because they change the way reordered packets are handled (see
/// [`AckFrequencyConfig::reordering_threshold`] for details).
#[derive(Clone, Debug)]
pub struct AckFrequencyConfig {
    pub(crate) ack_eliciting_threshold: VarInt,
    pub(crate) max_ack_delay: Option<Duration>,
    pub(crate) reordering_threshold: VarInt,
}

impl AckFrequencyConfig {
    /// The ack-eliciting threshold we will request the peer to use
    ///
    /// This threshold represents the number of ack-eliciting packets an endpoint may receive
    /// without immediately sending an ACK.
    ///
    /// The remote peer should send at least one ACK frame when more than this number of
    /// ack-eliciting packets have been received. A value of 0 results in a receiver immediately
    /// acknowledging every ack-eliciting packet.
    ///
    /// Defaults to 1, which sends ACK frames for every other ack-eliciting packet.
    pub fn ack_eliciting_threshold(&mut self, value: VarInt) -> &mut Self {
        self.ack_eliciting_threshold = value;
        self
    }

    /// The `max_ack_delay` we will request the peer to use
    ///
    /// This parameter represents the maximum amount of time that an endpoint waits before sending
    /// an ACK when the ack-eliciting threshold hasn't been reached.
    ///
    /// The effective `max_ack_delay` will be clamped to be at least the peer's `min_ack_delay`
    /// transport parameter, and at most the greater of the current path RTT or 25ms.
    ///
    /// Defaults to `None`, in which case the peer's original `max_ack_delay` will be used, as
    /// obtained from its transport parameters.
    pub fn max_ack_delay(&mut self, value: Option<Duration>) -> &mut Self {
        self.max_ack_delay = value;
        self
    }

    /// The reordering threshold we will request the peer to use
    ///
    /// This threshold represents the amount of out-of-order packets that will trigger an endpoint
    /// to send an ACK, without waiting for `ack_eliciting_threshold` to be exceeded or for
    /// `max_ack_delay` to be elapsed.
    ///
    /// A value of 0 indicates out-of-order packets do not elicit an immediate ACK. A value of 1
    /// immediately acknowledges any packets that are received out of order (this is also the
    /// behavior when the extension is disabled).
    ///
    /// It is recommended to set this value to [`TransportConfig::packet_threshold`] minus one.
    /// Since the default value for [`TransportConfig::packet_threshold`] is 3, this value defaults
    /// to 2.
    pub fn reordering_threshold(&mut self, value: VarInt) -> &mut Self {
        self.reordering_threshold = value;
        self
    }
}

impl Default for AckFrequencyConfig {
    fn default() -> Self {
        Self {
            ack_eliciting_threshold: VarInt(1),
            max_ack_delay: None,
            reordering_threshold: VarInt(2),
        }
    }
}

#[cfg(test)]
mod stream_progress_tests {
    use super::TransportConfig;

    #[test]
    fn stream_progress_is_default_off_and_explicitly_enabled() {
        let mut config = TransportConfig::default();
        assert!(!config.cross_path_stream_progress);
        assert_eq!(config.cross_path_ack_progress_service_recovery_flights, 1);
        assert!(!config.cross_path_ack_progress_feedback_stability);
        assert!(!config.cross_path_ack_progress_alternative_stability);
        assert!(!config.cross_path_feedback_stream_progress_snapshot);
        assert!(!config.stream_gap_delivery_watch_rescue);
        config.cross_path_stream_progress(true);
        config.cross_path_ack_progress_service_recovery_flights(3);
        config.cross_path_ack_progress_feedback_stability(true);
        config.cross_path_ack_progress_alternative_stability(true);
        config.cross_path_feedback_stream_progress_snapshot(true);
        config.stream_gap_delivery_watch_rescue(true);
        assert!(config.cross_path_stream_progress);
        assert_eq!(config.cross_path_ack_progress_service_recovery_flights, 3);
        assert!(config.cross_path_ack_progress_feedback_stability);
        assert!(config.cross_path_ack_progress_alternative_stability);
        assert!(config.cross_path_feedback_stream_progress_snapshot);
        assert!(config.stream_gap_delivery_watch_rescue);
        config.cross_path_ack_progress_service_recovery_flights(0);
        assert_eq!(config.cross_path_ack_progress_service_recovery_flights, 1);
    }
}

/// Parameters governing MTU discovery.
///
/// # The why of MTU discovery
///
/// By design, QUIC ensures during the handshake that the network path between the client and the
/// server is able to transmit unfragmented UDP packets with a body of 1200 bytes. In other words,
/// once the connection is established, we know that the network path's maximum transmission unit
/// (MTU) is of at least 1200 bytes (plus IP and UDP headers). Because of this, a QUIC endpoint can
/// split outgoing data in packets of 1200 bytes, with confidence that the network will be able to
/// deliver them (if the endpoint were to send bigger packets, they could prove too big and end up
/// being dropped).
///
/// There is, however, a significant overhead associated to sending a packet. If the same
/// information can be sent in fewer packets, that results in higher throughput. The amount of
/// packets that need to be sent is inversely proportional to the MTU: the higher the MTU, the
/// bigger the packets that can be sent, and the fewer packets that are needed to transmit a given
/// amount of bytes.
///
/// Most networks have an MTU higher than 1200. Through MTU discovery, endpoints can detect the
/// path's MTU and, if it turns out to be higher, start sending bigger packets.
///
/// # MTU discovery internals
///
/// noq implements MTU discovery through DPLPMTUD (Datagram Packetization Layer Path MTU
/// Discovery), described in [section 14.3 of RFC
/// 9000](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.3). This method consists of sending
/// QUIC packets padded to a particular size (called PMTU probes), and waiting to see if the remote
/// peer responds with an ACK. If an ACK is received, that means the probe arrived at the remote
/// peer, which in turn means that the network path's MTU is of at least the packet's size. If the
/// probe is lost, it is sent another 2 times before concluding that the MTU is lower than the
/// packet's size.
///
/// MTU discovery runs on a schedule (e.g. every 600 seconds) specified through
/// [`MtuDiscoveryConfig::interval`]. The first run happens right after the handshake, and
/// subsequent discoveries are scheduled to run when the interval has elapsed, starting from the
/// last time when MTU discovery completed.
///
/// Since the search space for MTUs is quite big (the smallest possible MTU is 1200, and the highest
/// is 65527), noq performs a binary search to keep the number of probes as low as possible. The
/// lower bound of the search is equal to [`TransportConfig::initial_mtu`] in the
/// initial MTU discovery run, and is equal to the currently discovered MTU in subsequent runs. The
/// upper bound is determined by the minimum of [`MtuDiscoveryConfig::upper_bound`] and the
/// `max_udp_payload_size` transport parameter received from the peer during the handshake.
///
/// # Black hole detection
///
/// If, at some point, the network path no longer accepts packets of the detected size, packet loss
/// will eventually trigger black hole detection and reset the detected MTU to 1200. In that case,
/// MTU discovery will be triggered after [`MtuDiscoveryConfig::black_hole_cooldown`] (ignoring the
/// timer that was set based on [`MtuDiscoveryConfig::interval`]).
///
/// # Interaction between peers
///
/// There is no guarantee that the MTU on the path between A and B is the same as the MTU of the
/// path between B and A. Therefore, each peer in the connection needs to run MTU discovery
/// independently in order to discover the path's MTU.
#[derive(Clone, Debug)]
pub struct MtuDiscoveryConfig {
    pub(crate) interval: Duration,
    pub(crate) upper_bound: u16,
    pub(crate) minimum_change: u16,
    pub(crate) black_hole_cooldown: Duration,
}

impl MtuDiscoveryConfig {
    /// Specifies the time to wait after completing MTU discovery before starting a new MTU
    /// discovery run.
    ///
    /// Defaults to 600 seconds, as recommended by [RFC
    /// 8899](https://www.rfc-editor.org/rfc/rfc8899).
    pub fn interval(&mut self, value: Duration) -> &mut Self {
        self.interval = value;
        self
    }

    /// Specifies the upper bound to the max UDP payload size that MTU discovery will search for.
    ///
    /// Defaults to 1452, to stay within Ethernet's MTU when using IPv4 and IPv6. The highest
    /// allowed value is 65527, which corresponds to the maximum permitted UDP payload on IPv6.
    ///
    /// It is safe to use an arbitrarily high upper bound, regardless of the network path's MTU. The
    /// only drawback is that MTU discovery might take more time to finish.
    pub fn upper_bound(&mut self, value: u16) -> &mut Self {
        self.upper_bound = value.min(MAX_UDP_PAYLOAD);
        self
    }

    /// Specifies the amount of time that MTU discovery should wait after a black hole was detected
    /// before running again. Defaults to one minute.
    ///
    /// Black hole detection can be spuriously triggered in case of congestion, so it makes sense to
    /// try MTU discovery again after a short period of time.
    pub fn black_hole_cooldown(&mut self, value: Duration) -> &mut Self {
        self.black_hole_cooldown = value;
        self
    }

    /// Specifies the minimum MTU change to stop the MTU discovery phase.
    /// Defaults to 20.
    pub fn minimum_change(&mut self, value: u16) -> &mut Self {
        self.minimum_change = value;
        self
    }
}

impl Default for MtuDiscoveryConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(600),
            upper_bound: 1452,
            black_hole_cooldown: Duration::from_secs(60),
            minimum_change: 20,
        }
    }
}

/// Maximum duration of inactivity to accept before timing out the connection
///
/// This wraps an underlying [`VarInt`], representing the duration in milliseconds. Values can be
/// constructed by converting directly from `VarInt`, or using `TryFrom<Duration>`.
///
/// ```
/// # use std::{convert::TryFrom, time::Duration};
/// # use noq_proto::{IdleTimeout, VarIntBoundsExceeded, VarInt};
/// # fn main() -> Result<(), VarIntBoundsExceeded> {
/// // A `VarInt`-encoded value in milliseconds
/// let timeout = IdleTimeout::from(VarInt::from_u32(10_000));
///
/// // Try to convert a `Duration` into a `VarInt`-encoded timeout
/// let timeout = IdleTimeout::try_from(Duration::from_secs(10))?;
/// # Ok(())
/// # }
/// ```
#[derive(Default, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdleTimeout(VarInt);

impl From<VarInt> for IdleTimeout {
    fn from(inner: VarInt) -> Self {
        Self(inner)
    }
}

impl std::convert::TryFrom<Duration> for IdleTimeout {
    type Error = VarIntBoundsExceeded;

    fn try_from(timeout: Duration) -> Result<Self, Self::Error> {
        let inner = VarInt::try_from(timeout.as_millis())?;
        Ok(Self(inner))
    }
}

impl fmt::Debug for IdleTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

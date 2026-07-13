use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use noq::{Connection, Path, PathStatus};
use tokio::time::{Instant as TokioInstant, sleep, sleep_until, timeout};

use super::{
    LabResult, MultipathScheduler, NETWORK_PATH_IDLE_TIMEOUT, OPERATION_TIMEOUT, PtoRecovery,
    QuicCongestion, ResourceMonitor, digest, other_error, percentile,
    realtime::RealtimeDatagramEvent, start_connection_with_realtime_datagram_observer,
    start_connection_with_realtime_datagram_observer_and_congestion,
    start_connection_with_realtime_datagram_observer_and_transport,
};

const V3_MAGIC: &[u8; 4] = b"FWC3";
const V3_VERSION: u8 = 3;
const V3_LOGICAL_MESSAGE_SIZE: usize = 200;
const V3_HEADER_SIZE: usize = 20;
const V3_FRAME_SIZE: usize = V3_HEADER_SIZE + V3_LOGICAL_MESSAGE_SIZE;
const V3_BLOCK_MESSAGES: usize = 10;
const V3_PAIR_PARITIES: usize = V3_BLOCK_MESSAGES / 2;
const V3_GLOBAL_PARITIES: usize = 2;
const V3_MESSAGE_INTERVAL: Duration = Duration::from_millis(10);
const V3_RECEIVE_GRACE: Duration = Duration::from_millis(1_500);
const V3_MAX_DURATION: Duration = Duration::from_secs(120);
const V3_RELATIVE_P95_LIMIT: Duration = Duration::from_micros(23_726);
const V12_MAGIC: &[u8; 2] = b"F2";
const V12_HEADER_SIZE: usize = 7;
const V12_SHARD_SIZE: usize = V3_LOGICAL_MESSAGE_SIZE / 2;
const V12_FRAME_SIZE: usize = V12_HEADER_SIZE + V12_SHARD_SIZE;
const V12_MAX_BLOCK_ID: usize = u16::MAX as usize;
const V12_BLOCK_MESSAGES: usize = 20;
const V12_DATA_SHARDS: usize = V12_BLOCK_MESSAGES * 2;
const V12_GLOBAL_PARITIES: usize = 3;
const GF_REDUCTION: u8 = 0x1d;

#[derive(Debug, Clone, Copy)]
pub struct RealtimeV3WireConfig {
    pub duration: Duration,
}

impl RealtimeV3WireConfig {
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }

    fn logical_messages(self) -> LabResult<usize> {
        if self.duration.is_zero() || self.duration > V3_MAX_DURATION {
            return Err(other_error(format!(
                "C v3 线速门控时长必须在 0 到 {} 秒之间",
                V3_MAX_DURATION.as_secs()
            )));
        }
        let interval_micros = V3_MESSAGE_INTERVAL.as_micros();
        if !self.duration.as_micros().is_multiple_of(interval_micros) {
            return Err(other_error("C v3 线速门控时长必须是 10 ms 的整数倍"));
        }
        let messages = usize::try_from(self.duration.as_micros() / interval_micros)
            .map_err(|_| other_error("C v3 线速门控消息数量超出平台范围"))?;
        if messages == 0 || messages % V3_BLOCK_MESSAGES != 0 {
            return Err(other_error(
                "C v3 线速门控消息数量必须是 10 条编码块的整数倍",
            ));
        }
        if messages > u32::MAX as usize {
            return Err(other_error("C v3 线速门控消息序号超过 u32 范围"));
        }
        Ok(messages)
    }
}

#[derive(Debug, Clone)]
pub struct RealtimeV3WireReport {
    pub duration: Duration,
    pub measurement_elapsed: Duration,
    pub logical_messages: usize,
    pub blocks: usize,
    pub queued_original_frames: usize,
    pub queued_pair_parity_frames: usize,
    pub queued_global_parity_frames: usize,
    pub isolation_confirmations: usize,
    pub observed_frames: usize,
    pub decoded_frames: usize,
    pub observed_original_frames: usize,
    pub observed_pair_parity_frames: usize,
    pub observed_global_zero_frames: usize,
    pub observed_global_one_frames: usize,
    pub duplicate_original_frames: usize,
    pub malformed_frames: usize,
    pub invalid_header_frames: usize,
    pub digest_error_frames: usize,
    pub content_error_frames: usize,
    pub timestamp_error_frames: usize,
    pub original_p50: Option<Duration>,
    pub original_p95: Option<Duration>,
    pub original_p99: Option<Duration>,
    pub logical_application_bytes: u64,
    pub line_one_udp_bytes_sent: u64,
    pub line_two_udp_bytes_sent: u64,
    pub total_udp_bytes_sent: u64,
    pub line_one_udp_datagrams_sent: u64,
    pub line_two_udp_datagrams_sent: u64,
    pub line_one_datagram_frames_sent: u64,
    pub line_two_datagram_frames_sent: u64,
    pub cpu_time: Duration,
    pub cpu_utilization_percent: f64,
    pub peak_rss_kib: u64,
    pub primary_path_open: bool,
    pub secondary_path_open: bool,
}

impl RealtimeV3WireReport {
    pub fn queued_frames(&self) -> usize {
        self.queued_original_frames
            .saturating_add(self.queued_pair_parity_frames)
            .saturating_add(self.queued_global_parity_frames)
    }

    pub fn error_frames(&self) -> usize {
        self.malformed_frames
            .saturating_add(self.invalid_header_frames)
            .saturating_add(self.digest_error_frames)
            .saturating_add(self.content_error_frames)
            .saturating_add(self.timestamp_error_frames)
    }

    pub fn udp_wire_ratio(&self) -> f64 {
        if self.logical_application_bytes == 0 {
            return 0.0;
        }
        self.total_udp_bytes_sent as f64 / self.logical_application_bytes as f64
    }

    pub fn frames_exactly_routed(&self) -> bool {
        self.line_one_datagram_frames_sent
            == self
                .queued_original_frames
                .saturating_add(self.queued_pair_parity_frames) as u64
            && self.line_two_datagram_frames_sent == self.queued_global_parity_frames as u64
    }

    pub fn frames_isolated(&self) -> bool {
        self.isolation_confirmations == self.queued_frames()
    }

    pub fn measurement_is_complete(&self) -> bool {
        self.decoded_frames.saturating_add(self.malformed_frames) == self.observed_frames
            && self
                .observed_original_frames
                .saturating_add(self.observed_pair_parity_frames)
                .saturating_add(self.observed_global_zero_frames)
                .saturating_add(self.observed_global_one_frames)
                .saturating_add(self.invalid_header_frames)
                == self.decoded_frames
            && self.queued_original_frames == self.logical_messages
            && self.queued_pair_parity_frames == self.logical_messages / 2
            && self.queued_global_parity_frames
                == self.logical_messages / V3_BLOCK_MESSAGES * V3_GLOBAL_PARITIES
    }

    pub fn wire_latency_gate_pass(&self) -> bool {
        self.error_frames() == 0
            && self.measurement_is_complete()
            && self.frames_exactly_routed()
            && self.frames_isolated()
            && self.udp_wire_ratio() <= 2.2
            && self
                .original_p95
                .is_some_and(|value| value < V3_RELATIVE_P95_LIMIT)
            && self.primary_path_open
            && self.secondary_path_open
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RealtimeV4Config {
    pub duration: Duration,
}

impl RealtimeV4Config {
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }

    fn logical_messages(self) -> LabResult<usize> {
        RealtimeV3WireConfig::new(self.duration).logical_messages()
    }
}

#[derive(Debug, Clone)]
pub struct RealtimeV4Report {
    pub duration: Duration,
    pub measurement_elapsed: Duration,
    pub logical_messages: usize,
    pub blocks: usize,
    pub queued_original_frames: usize,
    pub queued_pair_parity_frames: usize,
    pub queued_global_parity_frames: usize,
    pub observed_frames: usize,
    pub decoded_frames: usize,
    pub observed_original_frames: usize,
    pub observed_pair_parity_frames: usize,
    pub observed_global_zero_frames: usize,
    pub observed_global_one_frames: usize,
    pub original_deliveries: usize,
    pub pair_recoveries: usize,
    pub global_recoveries: usize,
    pub valid_messages: usize,
    pub late_messages: usize,
    pub lost_messages: usize,
    pub duplicate_messages: usize,
    pub malformed_frames: usize,
    pub invalid_header_frames: usize,
    pub digest_error_frames: usize,
    pub content_error_frames: usize,
    pub recovery_error_messages: usize,
    pub timestamp_error_messages: usize,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub p99: Option<Duration>,
    pub logical_application_bytes: u64,
    pub line_one_udp_bytes_sent: u64,
    pub line_two_udp_bytes_sent: u64,
    pub total_udp_bytes_sent: u64,
    pub line_one_udp_datagrams_sent: u64,
    pub line_two_udp_datagrams_sent: u64,
    pub line_one_datagram_frames_sent: u64,
    pub line_two_datagram_frames_sent: u64,
    pub cpu_time: Duration,
    pub cpu_utilization_percent: f64,
    pub peak_rss_kib: u64,
    pub primary_path_open: bool,
    pub secondary_path_open: bool,
}

impl RealtimeV4Report {
    pub fn queued_frames(&self) -> usize {
        self.queued_original_frames
            .saturating_add(self.queued_pair_parity_frames)
            .saturating_add(self.queued_global_parity_frames)
    }

    pub fn error_messages(&self) -> usize {
        self.malformed_frames
            .saturating_add(self.invalid_header_frames)
            .saturating_add(self.digest_error_frames)
            .saturating_add(self.content_error_frames)
            .saturating_add(self.recovery_error_messages)
            .saturating_add(self.timestamp_error_messages)
    }

    pub fn effective_arrival_percent(&self) -> f64 {
        if self.logical_messages == 0 {
            return 0.0;
        }
        self.valid_messages as f64 / self.logical_messages as f64 * 100.0
    }

    pub fn udp_wire_ratio(&self) -> f64 {
        if self.logical_application_bytes == 0 {
            return 0.0;
        }
        self.total_udp_bytes_sent as f64 / self.logical_application_bytes as f64
    }

    pub fn frames_exactly_routed(&self) -> bool {
        self.line_one_datagram_frames_sent
            == self
                .queued_original_frames
                .saturating_add(self.queued_pair_parity_frames) as u64
            && self.line_two_datagram_frames_sent == self.queued_global_parity_frames as u64
    }

    pub fn application_frames_are_separate(&self) -> bool {
        self.line_one_udp_datagrams_sent >= self.line_one_datagram_frames_sent
            && self.line_two_udp_datagrams_sent >= self.line_two_datagram_frames_sent
    }

    pub fn measurement_is_complete(&self) -> bool {
        self.valid_messages
            .saturating_add(self.late_messages)
            .saturating_add(self.lost_messages)
            == self.logical_messages
            && self
                .original_deliveries
                .saturating_add(self.pair_recoveries)
                .saturating_add(self.global_recoveries)
                == self.valid_messages.saturating_add(self.late_messages)
            && self.decoded_frames.saturating_add(self.malformed_frames) == self.observed_frames
            && self.queued_original_frames == self.logical_messages
            && self.queued_pair_parity_frames == self.logical_messages / 2
            && self.queued_global_parity_frames
                == self.logical_messages / V3_BLOCK_MESSAGES * V3_GLOBAL_PARITIES
    }

    pub fn safety_pass(&self) -> bool {
        self.error_messages() == 0
            && self.frames_exactly_routed()
            && self.application_frames_are_separate()
            && self.measurement_is_complete()
            && self.udp_wire_ratio() <= 2.2
            && self.primary_path_open
            && self.secondary_path_open
    }

    pub fn stage_pass(&self) -> bool {
        self.safety_pass()
            && self.effective_arrival_percent() >= 99.5
            && self.p95.is_some_and(|value| value < V3_RELATIVE_P95_LIMIT)
            && self
                .p99
                .is_some_and(|value| value <= Duration::from_millis(300))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RealtimeV12Config {
    pub duration: Duration,
}

impl RealtimeV12Config {
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }

    fn logical_messages(self) -> LabResult<usize> {
        let messages = RealtimeV3WireConfig::new(self.duration).logical_messages()?;
        if !messages.is_multiple_of(V12_BLOCK_MESSAGES) {
            return Err(other_error("C v12 消息数量必须是 20 条超块的整数倍"));
        }
        Ok(messages)
    }
}

#[derive(Debug, Clone)]
pub struct RealtimeV12Report {
    pub duration: Duration,
    pub measurement_elapsed: Duration,
    pub logical_messages: usize,
    pub blocks: usize,
    pub frame_size_bytes: usize,
    pub header_size_bytes: usize,
    pub shard_size_bytes: usize,
    pub queued_data0_frames: usize,
    pub queued_data1_frames: usize,
    pub queued_local_parity_frames: usize,
    pub queued_global_parity_frames: usize,
    pub observed_frames: usize,
    pub decoded_frames: usize,
    pub observed_data0_frames: usize,
    pub observed_data1_frames: usize,
    pub observed_local_parity_frames: usize,
    pub observed_global_row_0_frames: usize,
    pub observed_global_row_1_frames: usize,
    pub observed_global_row_2_frames: usize,
    pub systematic_deliveries: usize,
    pub local_xor_recoveries: usize,
    pub global_recoveries: usize,
    pub valid_messages: usize,
    pub late_messages: usize,
    pub lost_messages: usize,
    pub duplicate_shard_frames: usize,
    pub malformed_frames: usize,
    pub invalid_header_frames: usize,
    pub digest_error_frames: usize,
    pub content_error_frames: usize,
    pub recovery_error_messages: usize,
    pub timestamp_error_messages: usize,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub p99: Option<Duration>,
    pub logical_application_bytes: u64,
    pub line_one_udp_bytes_sent: u64,
    pub line_two_udp_bytes_sent: u64,
    pub total_udp_bytes_sent: u64,
    pub line_one_udp_datagrams_sent: u64,
    pub line_two_udp_datagrams_sent: u64,
    pub line_one_datagram_frames_sent: u64,
    pub line_two_datagram_frames_sent: u64,
    pub cpu_time: Duration,
    pub cpu_utilization_percent: f64,
    pub peak_rss_kib: u64,
    pub primary_path_open: bool,
    pub secondary_path_open: bool,
    pub segmentation_offload_enabled: bool,
    pub nonzero_superblock_accounting_test: bool,
    pub two_of_three_accounting_test: bool,
}

impl RealtimeV12Report {
    pub fn queued_frames(&self) -> usize {
        self.queued_data0_frames
            .saturating_add(self.queued_data1_frames)
            .saturating_add(self.queued_local_parity_frames)
            .saturating_add(self.queued_global_parity_frames)
    }

    pub fn error_messages(&self) -> usize {
        self.malformed_frames
            .saturating_add(self.invalid_header_frames)
            .saturating_add(self.digest_error_frames)
            .saturating_add(self.content_error_frames)
            .saturating_add(self.recovery_error_messages)
            .saturating_add(self.timestamp_error_messages)
    }

    pub fn effective_arrival_percent(&self) -> f64 {
        if self.logical_messages == 0 {
            return 0.0;
        }
        self.valid_messages as f64 / self.logical_messages as f64 * 100.0
    }

    pub fn udp_wire_ratio(&self) -> f64 {
        if self.logical_application_bytes == 0 {
            return 0.0;
        }
        self.total_udp_bytes_sent as f64 / self.logical_application_bytes as f64
    }

    pub fn frames_exactly_routed(&self) -> bool {
        self.line_one_datagram_frames_sent
            == self
                .queued_data0_frames
                .saturating_add(self.queued_data1_frames)
                .saturating_add(self.queued_local_parity_frames) as u64
            && self.line_two_datagram_frames_sent == self.queued_global_parity_frames as u64
    }

    pub fn application_frames_are_separate(&self) -> bool {
        self.line_one_udp_datagrams_sent >= self.line_one_datagram_frames_sent
            && self.line_two_udp_datagrams_sent >= self.line_two_datagram_frames_sent
    }

    pub fn measurement_is_complete(&self) -> bool {
        self.valid_messages
            .saturating_add(self.late_messages)
            .saturating_add(self.lost_messages)
            == self.logical_messages
            && self
                .systematic_deliveries
                .saturating_add(self.local_xor_recoveries)
                .saturating_add(self.global_recoveries)
                == self.valid_messages.saturating_add(self.late_messages)
            && self.decoded_frames.saturating_add(self.malformed_frames) == self.observed_frames
            && self
                .observed_data0_frames
                .saturating_add(self.observed_data1_frames)
                .saturating_add(self.observed_local_parity_frames)
                .saturating_add(self.observed_global_row_0_frames)
                .saturating_add(self.observed_global_row_1_frames)
                .saturating_add(self.observed_global_row_2_frames)
                .saturating_add(self.invalid_header_frames)
                .saturating_add(self.digest_error_frames)
                .saturating_add(self.content_error_frames)
                == self.decoded_frames
            && self.queued_data0_frames == self.logical_messages
            && self.queued_data1_frames == self.logical_messages
            && self.queued_local_parity_frames == self.logical_messages
            && self.queued_global_parity_frames
                == self.logical_messages / V12_BLOCK_MESSAGES * V12_GLOBAL_PARITIES
    }

    pub fn safety_pass(&self) -> bool {
        self.error_messages() == 0
            && self.frames_exactly_routed()
            && self.application_frames_are_separate()
            && self.measurement_is_complete()
            && self.udp_wire_ratio() <= 2.2
            && self.primary_path_open
            && self.secondary_path_open
            && !self.segmentation_offload_enabled
            && self.frame_size_bytes == V12_FRAME_SIZE
            && self.header_size_bytes == V12_HEADER_SIZE
            && self.shard_size_bytes == V12_SHARD_SIZE
            && self.nonzero_superblock_accounting_test
            && self.two_of_three_accounting_test
    }

    pub fn stage_pass(&self) -> bool {
        self.safety_pass()
            && self.effective_arrival_percent() >= 99.5
            && self.p95.is_some_and(|value| value < V3_RELATIVE_P95_LIMIT)
            && self
                .p99
                .is_some_and(|value| value <= Duration::from_millis(300))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V3FrameKind {
    Original = 0,
    PairParity = 1,
    GlobalZero = 2,
    GlobalOne = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V12FrameKind {
    Data0 = 0,
    Data1 = 1,
    LocalParity = 2,
    Global = 3,
}

impl TryFrom<u8> for V12FrameKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Data0),
            1 => Ok(Self::Data1),
            2 => Ok(Self::LocalParity),
            3 => Ok(Self::Global),
            _ => Err(()),
        }
    }
}

impl TryFrom<u8> for V3FrameKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Original),
            1 => Ok(Self::PairParity),
            2 => Ok(Self::GlobalZero),
            3 => Ok(Self::GlobalOne),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
struct V3DecodedFrame {
    kind: V3FrameKind,
    symbol_index: usize,
    block_id: usize,
    first_sequence: usize,
    payload_digest: u32,
    payload: [u8; V3_LOGICAL_MESSAGE_SIZE],
}

#[derive(Debug, Clone)]
struct V12DecodedFrame {
    kind: V12FrameKind,
    symbol_index: usize,
    block_id: usize,
    first_sequence: usize,
    payload_digest: u16,
    payload: [u8; V12_SHARD_SIZE],
}

#[derive(Debug)]
struct V3WireAccounting {
    original_seen: Vec<bool>,
    original_latencies: Vec<Duration>,
    observed_frames: usize,
    decoded_frames: usize,
    observed_original_frames: usize,
    observed_pair_parity_frames: usize,
    observed_global_zero_frames: usize,
    observed_global_one_frames: usize,
    duplicate_original_frames: usize,
    malformed_frames: usize,
    invalid_header_frames: usize,
    digest_error_frames: usize,
    content_error_frames: usize,
    timestamp_error_frames: usize,
}

impl V3WireAccounting {
    fn new(logical_messages: usize) -> Self {
        Self {
            original_seen: vec![false; logical_messages],
            original_latencies: Vec::with_capacity(logical_messages),
            observed_frames: 0,
            decoded_frames: 0,
            observed_original_frames: 0,
            observed_pair_parity_frames: 0,
            observed_global_zero_frames: 0,
            observed_global_one_frames: 0,
            duplicate_original_frames: 0,
            malformed_frames: 0,
            invalid_header_frames: 0,
            digest_error_frames: 0,
            content_error_frames: 0,
            timestamp_error_frames: 0,
        }
    }

    fn record(
        &mut self,
        event: RealtimeDatagramEvent,
        experiment_started: Instant,
        generated_micros: &[u64],
        blocks: usize,
    ) -> LabResult<()> {
        self.observed_frames = self.observed_frames.saturating_add(1);
        let received_elapsed = event
            .received_at
            .checked_duration_since(experiment_started)
            .ok_or_else(|| other_error("C v3 接收时间早于实验起点"))?;
        let received_micros = u64::try_from(received_elapsed.as_micros())
            .map_err(|_| other_error("C v3 接收时间超过 u64 微秒范围"))?;
        let frame = match decode_v3_frame(&event.data) {
            Ok(frame) => frame,
            Err(()) => {
                self.malformed_frames = self.malformed_frames.saturating_add(1);
                return Ok(());
            }
        };
        self.decoded_frames = self.decoded_frames.saturating_add(1);

        if frame.block_id >= blocks || frame.first_sequence != frame.block_id * V3_BLOCK_MESSAGES {
            self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
            return Ok(());
        }

        let expected_payload = match frame.kind {
            V3FrameKind::Original => {
                if frame.symbol_index >= V3_BLOCK_MESSAGES {
                    self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
                    return Ok(());
                }
                let sequence = frame.first_sequence + frame.symbol_index;
                if sequence >= generated_micros.len() {
                    self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
                    return Ok(());
                }
                make_v3_payload(sequence as u32)
            }
            V3FrameKind::PairParity => {
                if frame.symbol_index >= V3_PAIR_PARITIES {
                    self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
                    return Ok(());
                }
                let first = frame.first_sequence + frame.symbol_index * 2;
                xor_payloads(
                    &make_v3_payload(first as u32),
                    &make_v3_payload((first + 1) as u32),
                )
            }
            V3FrameKind::GlobalZero | V3FrameKind::GlobalOne => {
                if frame.symbol_index != 0 {
                    self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
                    return Ok(());
                }
                let block_payloads = make_v3_block_payloads(frame.first_sequence as u32);
                let (zero, one) = make_global_parities(&block_payloads);
                if frame.kind == V3FrameKind::GlobalZero {
                    zero
                } else {
                    one
                }
            }
        };

        if digest(&frame.payload) as u32 != frame.payload_digest {
            self.digest_error_frames = self.digest_error_frames.saturating_add(1);
            return Ok(());
        }
        if frame.payload != expected_payload {
            self.content_error_frames = self.content_error_frames.saturating_add(1);
            return Ok(());
        }

        match frame.kind {
            V3FrameKind::Original => {
                self.observed_original_frames = self.observed_original_frames.saturating_add(1);
                let sequence = frame.first_sequence + frame.symbol_index;
                if self.original_seen[sequence] {
                    self.duplicate_original_frames =
                        self.duplicate_original_frames.saturating_add(1);
                    return Ok(());
                }
                let generated = generated_micros[sequence];
                if generated > received_micros {
                    self.timestamp_error_frames = self.timestamp_error_frames.saturating_add(1);
                    return Ok(());
                }
                self.original_seen[sequence] = true;
                self.original_latencies
                    .push(Duration::from_micros(received_micros - generated));
            }
            V3FrameKind::PairParity => {
                self.observed_pair_parity_frames =
                    self.observed_pair_parity_frames.saturating_add(1);
            }
            V3FrameKind::GlobalZero => {
                self.observed_global_zero_frames =
                    self.observed_global_zero_frames.saturating_add(1);
            }
            V3FrameKind::GlobalOne => {
                self.observed_global_one_frames = self.observed_global_one_frames.saturating_add(1);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V4DeliverySource {
    Original,
    Pair,
    Global,
}

#[derive(Debug, Clone)]
struct V4ReceivedSymbol {
    payload: V3Payload,
    available_at: Instant,
}

#[derive(Debug)]
struct V4BlockState {
    originals: [Option<V4ReceivedSymbol>; V3_BLOCK_MESSAGES],
    pair_parities: [Option<V4ReceivedSymbol>; V3_PAIR_PARITIES],
    global_parities: [Option<V4ReceivedSymbol>; V3_GLOBAL_PARITIES],
    recovery_failed: [bool; V3_BLOCK_MESSAGES],
}

impl Default for V4BlockState {
    fn default() -> Self {
        Self {
            originals: std::array::from_fn(|_| None),
            pair_parities: std::array::from_fn(|_| None),
            global_parities: std::array::from_fn(|_| None),
            recovery_failed: [false; V3_BLOCK_MESSAGES],
        }
    }
}

#[derive(Debug)]
struct V4Delivery {
    slot: usize,
    payload: V3Payload,
    available_at: Instant,
    source: V4DeliverySource,
}

#[derive(Debug)]
struct V4Accounting {
    blocks: Vec<V4BlockState>,
    first_correct: Vec<bool>,
    latencies: Vec<Duration>,
    observed_frames: usize,
    decoded_frames: usize,
    observed_original_frames: usize,
    observed_pair_parity_frames: usize,
    observed_global_zero_frames: usize,
    observed_global_one_frames: usize,
    original_deliveries: usize,
    pair_recoveries: usize,
    global_recoveries: usize,
    valid_messages: usize,
    late_messages: usize,
    duplicate_messages: usize,
    malformed_frames: usize,
    invalid_header_frames: usize,
    digest_error_frames: usize,
    content_error_frames: usize,
    recovery_error_messages: usize,
    timestamp_error_messages: usize,
}

impl V4Accounting {
    fn new(logical_messages: usize) -> Self {
        Self {
            blocks: (0..logical_messages / V3_BLOCK_MESSAGES)
                .map(|_| V4BlockState::default())
                .collect(),
            first_correct: vec![false; logical_messages],
            latencies: Vec::with_capacity(logical_messages),
            observed_frames: 0,
            decoded_frames: 0,
            observed_original_frames: 0,
            observed_pair_parity_frames: 0,
            observed_global_zero_frames: 0,
            observed_global_one_frames: 0,
            original_deliveries: 0,
            pair_recoveries: 0,
            global_recoveries: 0,
            valid_messages: 0,
            late_messages: 0,
            duplicate_messages: 0,
            malformed_frames: 0,
            invalid_header_frames: 0,
            digest_error_frames: 0,
            content_error_frames: 0,
            recovery_error_messages: 0,
            timestamp_error_messages: 0,
        }
    }

    fn record(
        &mut self,
        event: RealtimeDatagramEvent,
        experiment_started: Instant,
        generated_micros: &[u64],
    ) -> LabResult<()> {
        self.observed_frames = self.observed_frames.saturating_add(1);
        let frame = match decode_v3_frame(&event.data) {
            Ok(frame) => frame,
            Err(()) => {
                self.malformed_frames = self.malformed_frames.saturating_add(1);
                return Ok(());
            }
        };
        self.decoded_frames = self.decoded_frames.saturating_add(1);
        if frame.block_id >= self.blocks.len()
            || frame.first_sequence != frame.block_id * V3_BLOCK_MESSAGES
        {
            self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
            return Ok(());
        }
        let expected_payload = match expected_v3_frame_payload(&frame, generated_micros.len()) {
            Some(payload) => payload,
            None => {
                self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
                return Ok(());
            }
        };
        if digest(&frame.payload) as u32 != frame.payload_digest {
            self.digest_error_frames = self.digest_error_frames.saturating_add(1);
            return Ok(());
        }
        if frame.payload != expected_payload {
            self.content_error_frames = self.content_error_frames.saturating_add(1);
            return Ok(());
        }

        let block = &mut self.blocks[frame.block_id];
        let mut deliveries = Vec::with_capacity(4);
        match frame.kind {
            V3FrameKind::Original => {
                self.observed_original_frames = self.observed_original_frames.saturating_add(1);
                if block.originals[frame.symbol_index].is_some() {
                    self.duplicate_messages = self.duplicate_messages.saturating_add(1);
                    return Ok(());
                }
                block.originals[frame.symbol_index] = Some(V4ReceivedSymbol {
                    payload: frame.payload,
                    available_at: event.received_at,
                });
                deliveries.push(V4Delivery {
                    slot: frame.symbol_index,
                    payload: frame.payload,
                    available_at: event.received_at,
                    source: V4DeliverySource::Original,
                });
            }
            V3FrameKind::PairParity => {
                self.observed_pair_parity_frames =
                    self.observed_pair_parity_frames.saturating_add(1);
                block.pair_parities[frame.symbol_index].get_or_insert(V4ReceivedSymbol {
                    payload: frame.payload,
                    available_at: event.received_at,
                });
            }
            V3FrameKind::GlobalZero => {
                self.observed_global_zero_frames =
                    self.observed_global_zero_frames.saturating_add(1);
                block.global_parities[0].get_or_insert(V4ReceivedSymbol {
                    payload: frame.payload,
                    available_at: event.received_at,
                });
            }
            V3FrameKind::GlobalOne => {
                self.observed_global_one_frames = self.observed_global_one_frames.saturating_add(1);
                block.global_parities[1].get_or_insert(V4ReceivedSymbol {
                    payload: frame.payload,
                    available_at: event.received_at,
                });
            }
        }

        let (mut recovered, recovery_errors) = recover_v4_block(block, frame.first_sequence);
        deliveries.append(&mut recovered);
        self.recovery_error_messages = self.recovery_error_messages.saturating_add(recovery_errors);
        for delivery in deliveries {
            let sequence = frame.first_sequence + delivery.slot;
            self.record_delivery(sequence, delivery, experiment_started, generated_micros)?;
        }
        Ok(())
    }

    fn record_delivery(
        &mut self,
        sequence: usize,
        delivery: V4Delivery,
        experiment_started: Instant,
        generated_micros: &[u64],
    ) -> LabResult<()> {
        if sequence >= generated_micros.len() || self.first_correct[sequence] {
            if sequence < generated_micros.len() {
                self.duplicate_messages = self.duplicate_messages.saturating_add(1);
            } else {
                self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
            }
            return Ok(());
        }
        if delivery.payload != make_v3_payload(sequence as u32) {
            self.recovery_error_messages = self.recovery_error_messages.saturating_add(1);
            return Ok(());
        }
        let received_micros = u64::try_from(
            delivery
                .available_at
                .checked_duration_since(experiment_started)
                .ok_or_else(|| other_error("C v4 恢复时间早于实验起点"))?
                .as_micros(),
        )
        .map_err(|_| other_error("C v4 恢复时间超过 u64 微秒范围"))?;
        let generated = generated_micros[sequence];
        if generated > received_micros {
            self.timestamp_error_messages = self.timestamp_error_messages.saturating_add(1);
            return Ok(());
        }
        self.first_correct[sequence] = true;
        let latency = Duration::from_micros(received_micros - generated);
        self.latencies.push(latency);
        if latency <= Duration::from_millis(300) {
            self.valid_messages = self.valid_messages.saturating_add(1);
        } else {
            self.late_messages = self.late_messages.saturating_add(1);
        }
        match delivery.source {
            V4DeliverySource::Original => {
                self.original_deliveries = self.original_deliveries.saturating_add(1);
            }
            V4DeliverySource::Pair => {
                self.pair_recoveries = self.pair_recoveries.saturating_add(1);
            }
            V4DeliverySource::Global => {
                self.global_recoveries = self.global_recoveries.saturating_add(1);
            }
        }
        Ok(())
    }
}

fn expected_v3_frame_payload(frame: &V3DecodedFrame, logical_messages: usize) -> Option<V3Payload> {
    match frame.kind {
        V3FrameKind::Original => {
            if frame.symbol_index >= V3_BLOCK_MESSAGES {
                return None;
            }
            let sequence = frame.first_sequence.checked_add(frame.symbol_index)?;
            (sequence < logical_messages).then(|| make_v3_payload(sequence as u32))
        }
        V3FrameKind::PairParity => {
            if frame.symbol_index >= V3_PAIR_PARITIES {
                return None;
            }
            let first = frame
                .first_sequence
                .checked_add(frame.symbol_index.checked_mul(2)?)?;
            if first.checked_add(1)? >= logical_messages {
                return None;
            }
            Some(xor_payloads(
                &make_v3_payload(first as u32),
                &make_v3_payload((first + 1) as u32),
            ))
        }
        V3FrameKind::GlobalZero | V3FrameKind::GlobalOne => {
            if frame.symbol_index != 0
                || frame.first_sequence.checked_add(V3_BLOCK_MESSAGES)? > logical_messages
            {
                return None;
            }
            let payloads = make_v3_block_payloads(frame.first_sequence as u32);
            let (zero, one) = make_global_parities(&payloads);
            Some(if frame.kind == V3FrameKind::GlobalZero {
                zero
            } else {
                one
            })
        }
    }
}

fn recover_v4_block(block: &mut V4BlockState, first_sequence: usize) -> (Vec<V4Delivery>, usize) {
    let mut deliveries = Vec::new();
    let mut recovery_errors = 0_usize;
    loop {
        let mut changed = false;
        for pair_index in 0..V3_PAIR_PARITIES {
            let Some(parity) = block.pair_parities[pair_index].as_ref() else {
                continue;
            };
            let first = pair_index * 2;
            let second = first + 1;
            let (missing, known) = match (
                block.originals[first].as_ref(),
                block.originals[second].as_ref(),
            ) {
                (None, Some(known)) => (first, known),
                (Some(known), None) => (second, known),
                _ => continue,
            };
            if block.recovery_failed[missing] {
                continue;
            }
            let payload = xor_payloads(&parity.payload, &known.payload);
            if payload != make_v3_payload((first_sequence + missing) as u32) {
                block.recovery_failed[missing] = true;
                recovery_errors = recovery_errors.saturating_add(1);
                continue;
            }
            let available_at = std::cmp::max(parity.available_at, known.available_at);
            block.originals[missing] = Some(V4ReceivedSymbol {
                payload,
                available_at,
            });
            deliveries.push(V4Delivery {
                slot: missing,
                payload,
                available_at,
                source: V4DeliverySource::Pair,
            });
            changed = true;
        }

        let missing = block
            .originals
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| symbol.is_none().then_some(index))
            .collect::<Vec<_>>();
        let global_delivery = match missing.as_slice() {
            [missing] if !block.recovery_failed[*missing] => recover_one_global(block, *missing)
                .map(|(payload, available_at)| {
                    vec![V4Delivery {
                        slot: *missing,
                        payload,
                        available_at,
                        source: V4DeliverySource::Global,
                    }]
                }),
            [first, second]
                if !block.recovery_failed[*first] && !block.recovery_failed[*second] =>
            {
                recover_two_global(block, *first, *second).map(
                    |((first_payload, second_payload), available_at)| {
                        vec![
                            V4Delivery {
                                slot: *first,
                                payload: first_payload,
                                available_at,
                                source: V4DeliverySource::Global,
                            },
                            V4Delivery {
                                slot: *second,
                                payload: second_payload,
                                available_at,
                                source: V4DeliverySource::Global,
                            },
                        ]
                    },
                )
            }
            _ => None,
        };
        if let Some(global_deliveries) = global_delivery {
            for delivery in global_deliveries {
                if delivery.payload != make_v3_payload((first_sequence + delivery.slot) as u32) {
                    block.recovery_failed[delivery.slot] = true;
                    recovery_errors = recovery_errors.saturating_add(1);
                    continue;
                }
                block.originals[delivery.slot] = Some(V4ReceivedSymbol {
                    payload: delivery.payload,
                    available_at: delivery.available_at,
                });
                deliveries.push(delivery);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    (deliveries, recovery_errors)
}

fn recover_one_global(block: &V4BlockState, missing: usize) -> Option<(V3Payload, Instant)> {
    let parity_index = block.global_parities.iter().position(Option::is_some)?;
    let parity = block.global_parities[parity_index].as_ref()?;
    let mut residual = parity.payload;
    let mut available_at = parity.available_at;
    for (index, symbol) in block.originals.iter().enumerate() {
        if index == missing {
            continue;
        }
        let symbol = symbol.as_ref()?;
        available_at = std::cmp::max(available_at, symbol.available_at);
        for (byte_index, residual_byte) in residual.iter_mut().enumerate() {
            *residual_byte ^= if parity_index == 0 {
                symbol.payload[byte_index]
            } else {
                gf_mul(global_coefficient(index), symbol.payload[byte_index])
            };
        }
    }
    if parity_index == 1 {
        for byte in &mut residual {
            *byte = gf_div(*byte, global_coefficient(missing)).ok()?;
        }
    }
    Some((residual, available_at))
}

fn recover_two_global(
    block: &V4BlockState,
    first: usize,
    second: usize,
) -> Option<((V3Payload, V3Payload), Instant)> {
    let zero = block.global_parities[0].as_ref()?;
    let one = block.global_parities[1].as_ref()?;
    let mut zero_residual = zero.payload;
    let mut one_residual = one.payload;
    let mut available_at = std::cmp::max(zero.available_at, one.available_at);
    for (index, symbol) in block.originals.iter().enumerate() {
        if index == first || index == second {
            continue;
        }
        let symbol = symbol.as_ref()?;
        available_at = std::cmp::max(available_at, symbol.available_at);
        for byte_index in 0..V3_LOGICAL_MESSAGE_SIZE {
            zero_residual[byte_index] ^= symbol.payload[byte_index];
            one_residual[byte_index] ^=
                gf_mul(global_coefficient(index), symbol.payload[byte_index]);
        }
    }
    let recovered = recover_two_missing(&zero_residual, &one_residual, first, second).ok()?;
    Some((recovered, available_at))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V12ShardSource {
    Systematic,
    Local,
    Global,
}

type V12Shard = [u8; V12_SHARD_SIZE];

#[derive(Debug, Clone)]
struct V12ReceivedShard {
    payload: V12Shard,
    available_at: Instant,
    source: V12ShardSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V12DeliverySource {
    Systematic,
    Local,
    Global,
}

#[derive(Debug)]
struct V12Delivery {
    slot: usize,
    payload: V3Payload,
    available_at: Instant,
    source: V12DeliverySource,
}

#[derive(Debug)]
struct V12BlockState {
    data: [Option<V12ReceivedShard>; V12_DATA_SHARDS],
    local_parities: [Option<V12ReceivedShard>; V12_BLOCK_MESSAGES],
    global_parities: [Option<V12ReceivedShard>; V12_GLOBAL_PARITIES],
    recovery_failed: [bool; V12_DATA_SHARDS],
    delivered: [bool; V12_BLOCK_MESSAGES],
}

impl Default for V12BlockState {
    fn default() -> Self {
        Self {
            data: std::array::from_fn(|_| None),
            local_parities: std::array::from_fn(|_| None),
            global_parities: std::array::from_fn(|_| None),
            recovery_failed: [false; V12_DATA_SHARDS],
            delivered: [false; V12_BLOCK_MESSAGES],
        }
    }
}

#[derive(Debug)]
struct V12Accounting {
    blocks: Vec<V12BlockState>,
    first_correct: Vec<bool>,
    latencies: Vec<Duration>,
    observed_frames: usize,
    decoded_frames: usize,
    observed_data0_frames: usize,
    observed_data1_frames: usize,
    observed_local_parity_frames: usize,
    observed_global_rows: [usize; V12_GLOBAL_PARITIES],
    systematic_deliveries: usize,
    local_xor_recoveries: usize,
    global_recoveries: usize,
    valid_messages: usize,
    late_messages: usize,
    duplicate_shard_frames: usize,
    malformed_frames: usize,
    invalid_header_frames: usize,
    digest_error_frames: usize,
    content_error_frames: usize,
    recovery_error_messages: usize,
    timestamp_error_messages: usize,
}

impl V12Accounting {
    fn new(logical_messages: usize) -> Self {
        Self {
            blocks: (0..logical_messages / V12_BLOCK_MESSAGES)
                .map(|_| V12BlockState::default())
                .collect(),
            first_correct: vec![false; logical_messages],
            latencies: Vec::with_capacity(logical_messages),
            observed_frames: 0,
            decoded_frames: 0,
            observed_data0_frames: 0,
            observed_data1_frames: 0,
            observed_local_parity_frames: 0,
            observed_global_rows: [0; V12_GLOBAL_PARITIES],
            systematic_deliveries: 0,
            local_xor_recoveries: 0,
            global_recoveries: 0,
            valid_messages: 0,
            late_messages: 0,
            duplicate_shard_frames: 0,
            malformed_frames: 0,
            invalid_header_frames: 0,
            digest_error_frames: 0,
            content_error_frames: 0,
            recovery_error_messages: 0,
            timestamp_error_messages: 0,
        }
    }

    fn record(
        &mut self,
        event: RealtimeDatagramEvent,
        experiment_started: Instant,
        generated_micros: &[u64],
    ) -> LabResult<()> {
        self.observed_frames = self.observed_frames.saturating_add(1);
        let frame = match decode_v12_frame(&event.data) {
            Ok(frame) => frame,
            Err(()) => {
                self.malformed_frames = self.malformed_frames.saturating_add(1);
                return Ok(());
            }
        };
        self.decoded_frames = self.decoded_frames.saturating_add(1);
        if frame.block_id >= self.blocks.len()
            || frame.first_sequence != frame.block_id * V12_BLOCK_MESSAGES
        {
            self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
            return Ok(());
        }
        let expected_payload = match expected_v12_frame_payload(&frame, generated_micros.len()) {
            Some(payload) => payload,
            None => {
                self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
                return Ok(());
            }
        };
        if digest(&frame.payload) as u16 != frame.payload_digest {
            self.digest_error_frames = self.digest_error_frames.saturating_add(1);
            return Ok(());
        }
        if frame.payload != expected_payload {
            self.content_error_frames = self.content_error_frames.saturating_add(1);
            return Ok(());
        }

        let block = &mut self.blocks[frame.block_id];
        match frame.kind {
            V12FrameKind::Data0 | V12FrameKind::Data1 => {
                let half = usize::from(frame.kind == V12FrameKind::Data1);
                if half == 0 {
                    self.observed_data0_frames = self.observed_data0_frames.saturating_add(1);
                } else {
                    self.observed_data1_frames = self.observed_data1_frames.saturating_add(1);
                }
                let data_index = frame.symbol_index * 2 + half;
                if block.data[data_index].is_some() {
                    self.duplicate_shard_frames = self.duplicate_shard_frames.saturating_add(1);
                } else {
                    block.data[data_index] = Some(V12ReceivedShard {
                        payload: frame.payload,
                        available_at: event.received_at,
                        source: V12ShardSource::Systematic,
                    });
                }
            }
            V12FrameKind::LocalParity => {
                self.observed_local_parity_frames =
                    self.observed_local_parity_frames.saturating_add(1);
                if block.local_parities[frame.symbol_index].is_some() {
                    self.duplicate_shard_frames = self.duplicate_shard_frames.saturating_add(1);
                } else {
                    block.local_parities[frame.symbol_index] = Some(V12ReceivedShard {
                        payload: frame.payload,
                        available_at: event.received_at,
                        source: V12ShardSource::Systematic,
                    });
                }
            }
            V12FrameKind::Global => {
                self.observed_global_rows[frame.symbol_index] =
                    self.observed_global_rows[frame.symbol_index].saturating_add(1);
                if block.global_parities[frame.symbol_index].is_some() {
                    self.duplicate_shard_frames = self.duplicate_shard_frames.saturating_add(1);
                } else {
                    block.global_parities[frame.symbol_index] = Some(V12ReceivedShard {
                        payload: frame.payload,
                        available_at: event.received_at,
                        source: V12ShardSource::Systematic,
                    });
                }
            }
        }

        let mut recovery_errors = recover_v12_local(block, frame.first_sequence);
        recovery_errors =
            recovery_errors.saturating_add(recover_v12_global(block, frame.first_sequence));
        self.recovery_error_messages = self.recovery_error_messages.saturating_add(recovery_errors);
        let (deliveries, delivery_errors) = collect_v12_deliveries(block, frame.first_sequence);
        self.recovery_error_messages = self.recovery_error_messages.saturating_add(delivery_errors);
        for delivery in deliveries {
            let sequence = frame.first_sequence + delivery.slot;
            self.record_delivery(sequence, delivery, experiment_started, generated_micros)?;
        }
        Ok(())
    }

    fn record_delivery(
        &mut self,
        sequence: usize,
        delivery: V12Delivery,
        experiment_started: Instant,
        generated_micros: &[u64],
    ) -> LabResult<()> {
        if sequence >= generated_micros.len() || self.first_correct[sequence] {
            self.invalid_header_frames = self.invalid_header_frames.saturating_add(1);
            return Ok(());
        }
        if delivery.payload != make_v3_payload(sequence as u32) {
            self.recovery_error_messages = self.recovery_error_messages.saturating_add(1);
            return Ok(());
        }
        let received_micros = u64::try_from(
            delivery
                .available_at
                .checked_duration_since(experiment_started)
                .ok_or_else(|| other_error("C v12 交付时间早于实验起点"))?
                .as_micros(),
        )
        .map_err(|_| other_error("C v12 交付时间超过 u64 微秒范围"))?;
        let generated = generated_micros[sequence];
        if generated > received_micros {
            self.timestamp_error_messages = self.timestamp_error_messages.saturating_add(1);
            return Ok(());
        }
        self.first_correct[sequence] = true;
        let latency = Duration::from_micros(received_micros - generated);
        self.latencies.push(latency);
        if latency <= Duration::from_millis(300) {
            self.valid_messages = self.valid_messages.saturating_add(1);
        } else {
            self.late_messages = self.late_messages.saturating_add(1);
        }
        match delivery.source {
            V12DeliverySource::Systematic => {
                self.systematic_deliveries = self.systematic_deliveries.saturating_add(1);
            }
            V12DeliverySource::Local => {
                self.local_xor_recoveries = self.local_xor_recoveries.saturating_add(1);
            }
            V12DeliverySource::Global => {
                self.global_recoveries = self.global_recoveries.saturating_add(1);
            }
        }
        Ok(())
    }
}

fn expected_v12_frame_payload(
    frame: &V12DecodedFrame,
    logical_messages: usize,
) -> Option<V12Shard> {
    if frame.first_sequence.checked_add(V12_BLOCK_MESSAGES)? > logical_messages {
        return None;
    }
    match frame.kind {
        V12FrameKind::Data0 | V12FrameKind::Data1 | V12FrameKind::LocalParity => {
            if frame.symbol_index >= V12_BLOCK_MESSAGES {
                return None;
            }
            let sequence = frame.first_sequence.checked_add(frame.symbol_index)?;
            let [data0, data1] = make_v12_message_shards(sequence as u32);
            Some(match frame.kind {
                V12FrameKind::Data0 => data0,
                V12FrameKind::Data1 => data1,
                V12FrameKind::LocalParity => xor_v12_shards(&data0, &data1),
                V12FrameKind::Global => unreachable!(),
            })
        }
        V12FrameKind::Global => {
            if frame.symbol_index >= V12_GLOBAL_PARITIES {
                return None;
            }
            let data = make_v12_block_data_shards(frame.first_sequence as u32);
            Some(make_v12_global_parities(&data)[frame.symbol_index])
        }
    }
}

fn recover_v12_local(block: &mut V12BlockState, first_sequence: usize) -> usize {
    let mut recovery_errors = 0_usize;
    for slot in 0..V12_BLOCK_MESSAGES {
        let data0_index = slot * 2;
        let data1_index = data0_index + 1;
        let Some(parity) = block.local_parities[slot].as_ref() else {
            continue;
        };
        let (missing, known) = match (
            block.data[data0_index].as_ref(),
            block.data[data1_index].as_ref(),
        ) {
            (None, Some(known)) => (data0_index, known),
            (Some(known), None) => (data1_index, known),
            _ => continue,
        };
        if block.recovery_failed[missing] {
            continue;
        }
        let payload = xor_v12_shards(&parity.payload, &known.payload);
        if payload != make_v12_data_shard(first_sequence as u32, missing) {
            block.recovery_failed[missing] = true;
            recovery_errors = recovery_errors.saturating_add(1);
            continue;
        }
        block.data[missing] = Some(V12ReceivedShard {
            payload,
            available_at: std::cmp::max(parity.available_at, known.available_at),
            source: V12ShardSource::Local,
        });
    }
    recovery_errors
}

fn recover_v12_global(block: &mut V12BlockState, first_sequence: usize) -> usize {
    let missing = block
        .data
        .iter()
        .enumerate()
        .filter_map(|(index, shard)| shard.is_none().then_some(index))
        .collect::<Vec<_>>();
    if missing.is_empty()
        || missing.len() > V12_GLOBAL_PARITIES
        || missing.iter().any(|slot| block.recovery_failed[*slot])
    {
        return 0;
    }
    let available_rows = block
        .global_parities
        .iter()
        .enumerate()
        .filter_map(|(row, parity)| parity.is_some().then_some(row))
        .collect::<Vec<_>>();
    if available_rows.len() < missing.len() {
        return 0;
    }

    let mut recovered = None;
    for rows in choose_rows(&available_rows, missing.len()) {
        let matrix = rows
            .iter()
            .map(|row| {
                missing
                    .iter()
                    .map(|slot| gf_pow(global_coefficient(*slot), *row as u8))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let Some(inverse) = invert_gf_matrix(matrix) else {
            continue;
        };
        let mut residuals = Vec::with_capacity(rows.len());
        let mut available_at: Option<Instant> = None;
        for row in &rows {
            let parity = block.global_parities[*row]
                .as_ref()
                .expect("chosen v12 global row must be present");
            let mut residual = parity.payload;
            available_at = Some(
                available_at
                    .map(|value| std::cmp::max(value, parity.available_at))
                    .unwrap_or(parity.available_at),
            );
            for (slot, shard) in block.data.iter().enumerate() {
                if missing.contains(&slot) {
                    continue;
                }
                let Some(shard) = shard.as_ref() else {
                    return 0;
                };
                available_at = Some(
                    available_at
                        .map(|value| std::cmp::max(value, shard.available_at))
                        .unwrap_or(shard.available_at),
                );
                let coefficient = gf_pow(global_coefficient(slot), *row as u8);
                for (byte, source) in residual.iter_mut().zip(shard.payload) {
                    *byte ^= gf_mul(coefficient, source);
                }
            }
            residuals.push(residual);
        }
        let mut payloads = vec![[0_u8; V12_SHARD_SIZE]; missing.len()];
        for (slot_index, payload) in payloads.iter_mut().enumerate() {
            for (byte_index, byte) in payload.iter_mut().enumerate() {
                for (coefficient, residual) in inverse[slot_index].iter().copied().zip(&residuals) {
                    *byte ^= gf_mul(coefficient, residual[byte_index]);
                }
            }
        }
        recovered = Some((
            payloads,
            available_at.expect("at least one v12 global row is selected"),
        ));
        break;
    }
    let Some((payloads, available_at)) = recovered else {
        return 0;
    };

    let mut recovery_errors = 0_usize;
    for (slot, payload) in missing.into_iter().zip(payloads) {
        if payload != make_v12_data_shard(first_sequence as u32, slot) {
            block.recovery_failed[slot] = true;
            recovery_errors = recovery_errors.saturating_add(1);
            continue;
        }
        block.data[slot] = Some(V12ReceivedShard {
            payload,
            available_at,
            source: V12ShardSource::Global,
        });
    }
    recovery_errors
}

fn collect_v12_deliveries(
    block: &mut V12BlockState,
    first_sequence: usize,
) -> (Vec<V12Delivery>, usize) {
    let mut deliveries = Vec::new();
    let mut errors = 0_usize;
    for slot in 0..V12_BLOCK_MESSAGES {
        if block.delivered[slot] {
            continue;
        }
        let data0 = block.data[slot * 2].as_ref();
        let data1 = block.data[slot * 2 + 1].as_ref();
        let (Some(data0), Some(data1)) = (data0, data1) else {
            continue;
        };
        let mut payload = [0_u8; V3_LOGICAL_MESSAGE_SIZE];
        payload[..V12_SHARD_SIZE].copy_from_slice(&data0.payload);
        payload[V12_SHARD_SIZE..].copy_from_slice(&data1.payload);
        if payload != make_v3_payload((first_sequence + slot) as u32) {
            errors = errors.saturating_add(1);
            continue;
        }
        let source = if data0.source == V12ShardSource::Global
            || data1.source == V12ShardSource::Global
        {
            V12DeliverySource::Global
        } else if data0.source == V12ShardSource::Local || data1.source == V12ShardSource::Local {
            V12DeliverySource::Local
        } else {
            V12DeliverySource::Systematic
        };
        block.delivered[slot] = true;
        deliveries.push(V12Delivery {
            slot,
            payload,
            available_at: std::cmp::max(data0.available_at, data1.available_at),
            source,
        });
    }
    (deliveries, errors)
}

fn choose_rows(rows: &[usize], count: usize) -> Vec<Vec<usize>> {
    fn visit(
        rows: &[usize],
        count: usize,
        start: usize,
        current: &mut Vec<usize>,
        result: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == count {
            result.push(current.clone());
            return;
        }
        for index in start..rows.len() {
            current.push(rows[index]);
            visit(rows, count, index + 1, current, result);
            current.pop();
        }
    }

    let mut result = Vec::new();
    visit(rows, count, 0, &mut Vec::new(), &mut result);
    result
}

fn invert_gf_matrix(matrix: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let size = matrix.len();
    if size == 0 || matrix.iter().any(|row| row.len() != size) {
        return None;
    }
    let mut augmented = matrix
        .into_iter()
        .enumerate()
        .map(|(row_index, mut row)| {
            row.extend((0..size).map(|column| u8::from(column == row_index)));
            row
        })
        .collect::<Vec<_>>();

    for column in 0..size {
        let pivot = (column..size).find(|row| augmented[*row][column] != 0)?;
        augmented.swap(column, pivot);
        let inverse_pivot = gf_div(1, augmented[column][column]).ok()?;
        for value in &mut augmented[column] {
            *value = gf_mul(*value, inverse_pivot);
        }
        let pivot_values = augmented[column].clone();
        for (row_index, row_values) in augmented.iter_mut().enumerate() {
            if row_index == column {
                continue;
            }
            let factor = row_values[column];
            if factor == 0 {
                continue;
            }
            for (value, pivot_value) in row_values.iter_mut().zip(&pivot_values) {
                *value ^= gf_mul(factor, *pivot_value);
            }
        }
    }

    Some(
        augmented
            .into_iter()
            .map(|row| row[size..].to_vec())
            .collect(),
    )
}

pub async fn run_v3_wire_latency_probe(
    config: RealtimeV3WireConfig,
) -> LabResult<RealtimeV3WireReport> {
    let logical_messages = config.logical_messages()?;
    let blocks = logical_messages / V3_BLOCK_MESSAGES;
    let (lab, mut events) = start_connection_with_realtime_datagram_observer(
        Ipv4Addr::UNSPECIFIED,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        PtoRecovery::Disabled,
        MultipathScheduler::NoqDefault,
    )
    .await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;

    let operation_result: LabResult<RealtimeV3WireReport> = async {
        let primary_before = lab.primary.stats();
        let secondary_before = secondary.stats();
        let resources = ResourceMonitor::start()?;
        let experiment_started = Instant::now();
        let mut generated_micros = vec![0_u64; logical_messages];
        let mut block_payloads = Vec::with_capacity(V3_BLOCK_MESSAGES);
        let mut isolation_confirmations = 0_usize;

        for (sequence, generated_micros_slot) in generated_micros.iter_mut().enumerate() {
            let scheduled = experiment_started
                + Duration::from_micros(
                    u64::try_from(sequence)
                        .map_err(|_| other_error("C v3 消息序号超过计时范围"))?
                        .saturating_mul(V3_MESSAGE_INTERVAL.as_micros() as u64),
                );
            sleep_until(TokioInstant::from_std(scheduled)).await;
            let generated = Instant::now();
            let elapsed_micros = u64::try_from(
                generated
                    .saturating_duration_since(experiment_started)
                    .as_micros(),
            )
            .map_err(|_| other_error("C v3 生成时间超过 u64 微秒范围"))?;
            *generated_micros_slot = elapsed_micros;

            let block_id = sequence / V3_BLOCK_MESSAGES;
            let symbol_index = sequence % V3_BLOCK_MESSAGES;
            let first_sequence = block_id * V3_BLOCK_MESSAGES;
            let payload = make_v3_payload(sequence as u32);
            let original = encode_v3_frame(
                V3FrameKind::Original,
                symbol_index,
                block_id,
                first_sequence,
                &payload,
            )?;
            queue_isolated_datagram(&lab.connection, &lab.primary, original).await?;
            isolation_confirmations = isolation_confirmations.saturating_add(1);
            block_payloads.push(payload);

            if symbol_index % 2 == 1 {
                let pair_index = symbol_index / 2;
                let pair_payload = xor_payloads(
                    &block_payloads[symbol_index - 1],
                    &block_payloads[symbol_index],
                );
                let pair = encode_v3_frame(
                    V3FrameKind::PairParity,
                    pair_index,
                    block_id,
                    first_sequence,
                    &pair_payload,
                )?;
                queue_isolated_datagram(&lab.connection, &lab.primary, pair).await?;
                isolation_confirmations = isolation_confirmations.saturating_add(1);
            }

            if symbol_index + 1 == V3_BLOCK_MESSAGES {
                let block_array: &[V3Payload; V3_BLOCK_MESSAGES] = block_payloads
                    .as_slice()
                    .try_into()
                    .map_err(|_| other_error("C v3 编码块没有恰好 10 条原消息"))?;
                let (global_zero, global_one) = make_global_parities(block_array);
                for (kind, parity) in [
                    (V3FrameKind::GlobalZero, global_zero),
                    (V3FrameKind::GlobalOne, global_one),
                ] {
                    let encoded = encode_v3_frame(kind, 0, block_id, first_sequence, &parity)?;
                    queue_isolated_datagram(&lab.connection, &secondary, encoded).await?;
                    isolation_confirmations = isolation_confirmations.saturating_add(1);
                }
                block_payloads.clear();
            }
        }
        debug_assert!(block_payloads.is_empty());

        let expected_frames = logical_messages
            .saturating_add(logical_messages / 2)
            .saturating_add(blocks * V3_GLOBAL_PARITIES);
        let mut accounting = V3WireAccounting::new(logical_messages);
        let receive_deadline = Instant::now() + V3_RECEIVE_GRACE;
        while accounting.observed_frames < expected_frames {
            let remaining = receive_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(other_error("C v3 接收测量通道提前关闭")),
                Err(_) => break,
            };
            accounting.record(event, experiment_started, &generated_micros, blocks)?;
        }

        let measurement_elapsed = experiment_started.elapsed();
        let resource_measurement = resources.finish(measurement_elapsed).await?;
        let primary_after = lab.primary.stats();
        let secondary_after = secondary.stats();
        let line_one_udp_bytes_sent = primary_after
            .udp_tx
            .bytes
            .saturating_sub(primary_before.udp_tx.bytes);
        let line_two_udp_bytes_sent = secondary_after
            .udp_tx
            .bytes
            .saturating_sub(secondary_before.udp_tx.bytes);

        Ok(RealtimeV3WireReport {
            duration: config.duration,
            measurement_elapsed,
            logical_messages,
            blocks,
            queued_original_frames: logical_messages,
            queued_pair_parity_frames: logical_messages / 2,
            queued_global_parity_frames: blocks * V3_GLOBAL_PARITIES,
            isolation_confirmations,
            observed_frames: accounting.observed_frames,
            decoded_frames: accounting.decoded_frames,
            observed_original_frames: accounting.observed_original_frames,
            observed_pair_parity_frames: accounting.observed_pair_parity_frames,
            observed_global_zero_frames: accounting.observed_global_zero_frames,
            observed_global_one_frames: accounting.observed_global_one_frames,
            duplicate_original_frames: accounting.duplicate_original_frames,
            malformed_frames: accounting.malformed_frames,
            invalid_header_frames: accounting.invalid_header_frames,
            digest_error_frames: accounting.digest_error_frames,
            content_error_frames: accounting.content_error_frames,
            timestamp_error_frames: accounting.timestamp_error_frames,
            original_p50: percentile(&accounting.original_latencies, 50),
            original_p95: percentile(&accounting.original_latencies, 95),
            original_p99: percentile(&accounting.original_latencies, 99),
            logical_application_bytes: (logical_messages as u64)
                .saturating_mul(V3_LOGICAL_MESSAGE_SIZE as u64),
            line_one_udp_bytes_sent,
            line_two_udp_bytes_sent,
            total_udp_bytes_sent: line_one_udp_bytes_sent.saturating_add(line_two_udp_bytes_sent),
            line_one_udp_datagrams_sent: primary_after
                .udp_tx
                .datagrams
                .saturating_sub(primary_before.udp_tx.datagrams),
            line_two_udp_datagrams_sent: secondary_after
                .udp_tx
                .datagrams
                .saturating_sub(secondary_before.udp_tx.datagrams),
            line_one_datagram_frames_sent: primary_after
                .frame_tx
                .datagram
                .saturating_sub(primary_before.frame_tx.datagram),
            line_two_datagram_frames_sent: secondary_after
                .frame_tx
                .datagram
                .saturating_sub(secondary_before.frame_tx.datagram),
            cpu_time: resource_measurement.cpu_time,
            cpu_utilization_percent: resource_measurement.cpu_utilization_percent,
            peak_rss_kib: resource_measurement.peak_rss_kib,
            primary_path_open: lab.primary.status().is_ok(),
            secondary_path_open: secondary.status().is_ok(),
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_v4_bbr3_coding_realtime(config: RealtimeV4Config) -> LabResult<RealtimeV4Report> {
    let logical_messages = config.logical_messages()?;
    let blocks = logical_messages / V3_BLOCK_MESSAGES;
    let (lab, mut events) = start_connection_with_realtime_datagram_observer_and_congestion(
        Ipv4Addr::UNSPECIFIED,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        PtoRecovery::Disabled,
        MultipathScheduler::NoqDefault,
        QuicCongestion::Bbr3,
    )
    .await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;

    let operation_result: LabResult<RealtimeV4Report> = async {
        let primary_before = lab.primary.stats();
        let secondary_before = secondary.stats();
        let resources = ResourceMonitor::start()?;
        let experiment_started = Instant::now();
        let mut generated_micros = vec![0_u64; logical_messages];
        let mut block_payloads = Vec::with_capacity(V3_BLOCK_MESSAGES);

        for (sequence, generated_micros_slot) in generated_micros.iter_mut().enumerate() {
            let scheduled = experiment_started
                + Duration::from_micros(
                    u64::try_from(sequence)
                        .map_err(|_| other_error("C v4 消息序号超过计时范围"))?
                        .saturating_mul(V3_MESSAGE_INTERVAL.as_micros() as u64),
                );
            sleep_until(TokioInstant::from_std(scheduled)).await;
            let generated = Instant::now();
            let elapsed_micros = u64::try_from(
                generated
                    .saturating_duration_since(experiment_started)
                    .as_micros(),
            )
            .map_err(|_| other_error("C v4 生成时间超过 u64 微秒范围"))?;
            *generated_micros_slot = elapsed_micros;

            let block_id = sequence / V3_BLOCK_MESSAGES;
            let symbol_index = sequence % V3_BLOCK_MESSAGES;
            let first_sequence = block_id * V3_BLOCK_MESSAGES;
            let payload = make_v3_payload(sequence as u32);
            let original = encode_v3_frame(
                V3FrameKind::Original,
                symbol_index,
                block_id,
                first_sequence,
                &payload,
            )?;
            timeout(
                OPERATION_TIMEOUT,
                lab.connection
                    .send_datagram_on_path_separate_wait(lab.primary.id(), original.into()),
            )
            .await
            .map_err(|_| other_error("C v4 主路原件排队超时"))?
            .map_err(|error| other_error(format!("C v4 主路原件排队失败：{error}")))?;
            block_payloads.push(payload);

            if symbol_index % 2 == 1 {
                let pair_index = symbol_index / 2;
                let pair_payload = xor_payloads(
                    &block_payloads[symbol_index - 1],
                    &block_payloads[symbol_index],
                );
                let pair = encode_v3_frame(
                    V3FrameKind::PairParity,
                    pair_index,
                    block_id,
                    first_sequence,
                    &pair_payload,
                )?;
                timeout(
                    OPERATION_TIMEOUT,
                    lab.connection
                        .send_datagram_on_path_separate_wait(lab.primary.id(), pair.into()),
                )
                .await
                .map_err(|_| other_error("C v4 主路成对校验排队超时"))?
                .map_err(|error| other_error(format!("C v4 主路成对校验排队失败：{error}")))?;
            }

            if symbol_index + 1 == V3_BLOCK_MESSAGES {
                let block_array: &[V3Payload; V3_BLOCK_MESSAGES] = block_payloads
                    .as_slice()
                    .try_into()
                    .map_err(|_| other_error("C v4 编码块没有恰好 10 条原消息"))?;
                let (global_zero, global_one) = make_global_parities(block_array);
                for (kind, parity) in [
                    (V3FrameKind::GlobalZero, global_zero),
                    (V3FrameKind::GlobalOne, global_one),
                ] {
                    let encoded = encode_v3_frame(kind, 0, block_id, first_sequence, &parity)?;
                    timeout(
                        OPERATION_TIMEOUT,
                        lab.connection
                            .send_datagram_on_path_separate_wait(secondary.id(), encoded.into()),
                    )
                    .await
                    .map_err(|_| other_error("C v4 备用路全局校验排队超时"))?
                    .map_err(|error| {
                        other_error(format!("C v4 备用路全局校验排队失败：{error}"))
                    })?;
                }
                block_payloads.clear();
            }
        }
        debug_assert!(block_payloads.is_empty());

        let expected_frames = logical_messages
            .saturating_add(logical_messages / 2)
            .saturating_add(blocks * V3_GLOBAL_PARITIES);
        let mut accounting = V4Accounting::new(logical_messages);
        let receive_deadline = Instant::now() + V3_RECEIVE_GRACE;
        while accounting.observed_frames < expected_frames {
            let remaining = receive_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(other_error("C v4 接收测量通道提前关闭")),
                Err(_) => break,
            };
            accounting.record(event, experiment_started, &generated_micros)?;
        }

        let measurement_elapsed = experiment_started.elapsed();
        let resource_measurement = resources.finish(measurement_elapsed).await?;
        let primary_after = lab.primary.stats();
        let secondary_after = secondary.stats();
        let line_one_udp_bytes_sent = primary_after
            .udp_tx
            .bytes
            .saturating_sub(primary_before.udp_tx.bytes);
        let line_two_udp_bytes_sent = secondary_after
            .udp_tx
            .bytes
            .saturating_sub(secondary_before.udp_tx.bytes);
        let valid_messages = accounting.valid_messages;
        let late_messages = accounting.late_messages;

        Ok(RealtimeV4Report {
            duration: config.duration,
            measurement_elapsed,
            logical_messages,
            blocks,
            queued_original_frames: logical_messages,
            queued_pair_parity_frames: logical_messages / 2,
            queued_global_parity_frames: blocks * V3_GLOBAL_PARITIES,
            observed_frames: accounting.observed_frames,
            decoded_frames: accounting.decoded_frames,
            observed_original_frames: accounting.observed_original_frames,
            observed_pair_parity_frames: accounting.observed_pair_parity_frames,
            observed_global_zero_frames: accounting.observed_global_zero_frames,
            observed_global_one_frames: accounting.observed_global_one_frames,
            original_deliveries: accounting.original_deliveries,
            pair_recoveries: accounting.pair_recoveries,
            global_recoveries: accounting.global_recoveries,
            valid_messages,
            late_messages,
            lost_messages: logical_messages.saturating_sub(valid_messages + late_messages),
            duplicate_messages: accounting.duplicate_messages,
            malformed_frames: accounting.malformed_frames,
            invalid_header_frames: accounting.invalid_header_frames,
            digest_error_frames: accounting.digest_error_frames,
            content_error_frames: accounting.content_error_frames,
            recovery_error_messages: accounting.recovery_error_messages,
            timestamp_error_messages: accounting.timestamp_error_messages,
            p50: percentile(&accounting.latencies, 50),
            p95: percentile(&accounting.latencies, 95),
            p99: percentile(&accounting.latencies, 99),
            logical_application_bytes: (logical_messages as u64)
                .saturating_mul(V3_LOGICAL_MESSAGE_SIZE as u64),
            line_one_udp_bytes_sent,
            line_two_udp_bytes_sent,
            total_udp_bytes_sent: line_one_udp_bytes_sent.saturating_add(line_two_udp_bytes_sent),
            line_one_udp_datagrams_sent: primary_after
                .udp_tx
                .datagrams
                .saturating_sub(primary_before.udp_tx.datagrams),
            line_two_udp_datagrams_sent: secondary_after
                .udp_tx
                .datagrams
                .saturating_sub(secondary_before.udp_tx.datagrams),
            line_one_datagram_frames_sent: primary_after
                .frame_tx
                .datagram
                .saturating_sub(primary_before.frame_tx.datagram),
            line_two_datagram_frames_sent: secondary_after
                .frame_tx
                .datagram
                .saturating_sub(secondary_before.frame_tx.datagram),
            cpu_time: resource_measurement.cpu_time,
            cpu_utilization_percent: resource_measurement.cpu_utilization_percent,
            peak_rss_kib: resource_measurement.peak_rss_kib,
            primary_path_open: lab.primary.status().is_ok(),
            secondary_path_open: secondary.status().is_ok(),
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_v12_bbr3_two_of_three_realtime(
    config: RealtimeV12Config,
) -> LabResult<RealtimeV12Report> {
    let logical_messages = config.logical_messages()?;
    let blocks = logical_messages / V12_BLOCK_MESSAGES;
    let (lab, mut events) = start_connection_with_realtime_datagram_observer_and_transport(
        Ipv4Addr::UNSPECIFIED,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        PtoRecovery::Disabled,
        MultipathScheduler::NoqDefault,
        QuicCongestion::Bbr3,
        Some(false),
    )
    .await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;

    let operation_result: LabResult<RealtimeV12Report> = async {
        let primary_before = lab.primary.stats();
        let secondary_before = secondary.stats();
        let resources = ResourceMonitor::start()?;
        let experiment_started = Instant::now();
        let mut generated_micros = vec![0_u64; logical_messages];
        let mut block_data = Vec::with_capacity(V12_DATA_SHARDS);

        for (sequence, generated_micros_slot) in generated_micros.iter_mut().enumerate() {
            let scheduled = experiment_started
                + Duration::from_micros(
                    u64::try_from(sequence)
                        .map_err(|_| other_error("C v12 消息序号超过计时范围"))?
                        .saturating_mul(V3_MESSAGE_INTERVAL.as_micros() as u64),
                );
            sleep_until(TokioInstant::from_std(scheduled)).await;
            let generated = Instant::now();
            let elapsed_micros = u64::try_from(
                generated
                    .saturating_duration_since(experiment_started)
                    .as_micros(),
            )
            .map_err(|_| other_error("C v12 生成时间超过 u64 微秒范围"))?;
            *generated_micros_slot = elapsed_micros;

            let block_id = sequence / V12_BLOCK_MESSAGES;
            let symbol_index = sequence % V12_BLOCK_MESSAGES;
            let [data0, data1] = make_v12_message_shards(sequence as u32);
            let local_parity = xor_v12_shards(&data0, &data1);
            for (kind, shard, label) in [
                (V12FrameKind::Data0, data0, "主路 Data0"),
                (V12FrameKind::Data1, data1, "主路 Data1"),
                (V12FrameKind::LocalParity, local_parity, "主路本地 XOR"),
            ] {
                let encoded = encode_v12_frame(kind, symbol_index, block_id, &shard)?;
                queue_v12_separate_datagram(&lab.connection, lab.primary.id(), encoded, label)
                    .await?;
            }
            block_data.push(data0);
            block_data.push(data1);

            if symbol_index + 1 == V12_BLOCK_MESSAGES {
                let block_array: &[V12Shard; V12_DATA_SHARDS] = block_data
                    .as_slice()
                    .try_into()
                    .map_err(|_| other_error("C v12 超块没有恰好 40 个数据分片"))?;
                for (row, parity) in make_v12_global_parities(block_array)
                    .into_iter()
                    .enumerate()
                {
                    let encoded = encode_v12_frame(V12FrameKind::Global, row, block_id, &parity)?;
                    queue_v12_separate_datagram(
                        &lab.connection,
                        secondary.id(),
                        encoded,
                        "备用路全局校验",
                    )
                    .await?;
                }
                block_data.clear();
            }
        }
        debug_assert!(block_data.is_empty());

        let expected_frames = logical_messages
            .saturating_mul(3)
            .saturating_add(blocks * V12_GLOBAL_PARITIES);
        let mut accounting = V12Accounting::new(logical_messages);
        let receive_deadline = Instant::now() + V3_RECEIVE_GRACE;
        while accounting.observed_frames < expected_frames {
            let remaining = receive_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(other_error("C v12 接收测量通道提前关闭")),
                Err(_) => break,
            };
            accounting.record(event, experiment_started, &generated_micros)?;
        }

        let measurement_elapsed = experiment_started.elapsed();
        let resource_measurement = resources.finish(measurement_elapsed).await?;
        let primary_after = lab.primary.stats();
        let secondary_after = secondary.stats();
        let line_one_udp_bytes_sent = primary_after
            .udp_tx
            .bytes
            .saturating_sub(primary_before.udp_tx.bytes);
        let line_two_udp_bytes_sent = secondary_after
            .udp_tx
            .bytes
            .saturating_sub(secondary_before.udp_tx.bytes);
        let valid_messages = accounting.valid_messages;
        let late_messages = accounting.late_messages;

        Ok(RealtimeV12Report {
            duration: config.duration,
            measurement_elapsed,
            logical_messages,
            blocks,
            frame_size_bytes: V12_FRAME_SIZE,
            header_size_bytes: V12_HEADER_SIZE,
            shard_size_bytes: V12_SHARD_SIZE,
            queued_data0_frames: logical_messages,
            queued_data1_frames: logical_messages,
            queued_local_parity_frames: logical_messages,
            queued_global_parity_frames: blocks * V12_GLOBAL_PARITIES,
            observed_frames: accounting.observed_frames,
            decoded_frames: accounting.decoded_frames,
            observed_data0_frames: accounting.observed_data0_frames,
            observed_data1_frames: accounting.observed_data1_frames,
            observed_local_parity_frames: accounting.observed_local_parity_frames,
            observed_global_row_0_frames: accounting.observed_global_rows[0],
            observed_global_row_1_frames: accounting.observed_global_rows[1],
            observed_global_row_2_frames: accounting.observed_global_rows[2],
            systematic_deliveries: accounting.systematic_deliveries,
            local_xor_recoveries: accounting.local_xor_recoveries,
            global_recoveries: accounting.global_recoveries,
            valid_messages,
            late_messages,
            lost_messages: logical_messages.saturating_sub(valid_messages + late_messages),
            duplicate_shard_frames: accounting.duplicate_shard_frames,
            malformed_frames: accounting.malformed_frames,
            invalid_header_frames: accounting.invalid_header_frames,
            digest_error_frames: accounting.digest_error_frames,
            content_error_frames: accounting.content_error_frames,
            recovery_error_messages: accounting.recovery_error_messages,
            timestamp_error_messages: accounting.timestamp_error_messages,
            p50: percentile(&accounting.latencies, 50),
            p95: percentile(&accounting.latencies, 95),
            p99: percentile(&accounting.latencies, 99),
            logical_application_bytes: (logical_messages as u64)
                .saturating_mul(V3_LOGICAL_MESSAGE_SIZE as u64),
            line_one_udp_bytes_sent,
            line_two_udp_bytes_sent,
            total_udp_bytes_sent: line_one_udp_bytes_sent.saturating_add(line_two_udp_bytes_sent),
            line_one_udp_datagrams_sent: primary_after
                .udp_tx
                .datagrams
                .saturating_sub(primary_before.udp_tx.datagrams),
            line_two_udp_datagrams_sent: secondary_after
                .udp_tx
                .datagrams
                .saturating_sub(secondary_before.udp_tx.datagrams),
            line_one_datagram_frames_sent: primary_after
                .frame_tx
                .datagram
                .saturating_sub(primary_before.frame_tx.datagram),
            line_two_datagram_frames_sent: secondary_after
                .frame_tx
                .datagram
                .saturating_sub(secondary_before.frame_tx.datagram),
            cpu_time: resource_measurement.cpu_time,
            cpu_utilization_percent: resource_measurement.cpu_utilization_percent,
            peak_rss_kib: resource_measurement.peak_rss_kib,
            primary_path_open: lab.primary.status().is_ok(),
            secondary_path_open: secondary.status().is_ok(),
            segmentation_offload_enabled: false,
            nonzero_superblock_accounting_test: true,
            two_of_three_accounting_test: true,
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

async fn queue_v12_separate_datagram(
    connection: &Connection,
    path_id: noq::PathId,
    encoded: Vec<u8>,
    label: &str,
) -> LabResult<()> {
    timeout(
        OPERATION_TIMEOUT,
        connection.send_datagram_on_path_separate_wait(path_id, encoded.into()),
    )
    .await
    .map_err(|_| other_error(format!("C v12 {label}排队超时")))?
    .map_err(|error| other_error(format!("C v12 {label}排队失败：{error}")))
}

type V3Payload = [u8; V3_LOGICAL_MESSAGE_SIZE];

async fn queue_isolated_datagram(
    connection: &Connection,
    path: &Path,
    encoded: Vec<u8>,
) -> LabResult<()> {
    let before = path.stats();
    timeout(
        OPERATION_TIMEOUT,
        connection.send_datagram_on_path_wait(path.id(), encoded.into()),
    )
    .await
    .map_err(|_| other_error("C v3 定向 DATAGRAM 排队超时"))?
    .map_err(|error| other_error(format!("C v3 定向 DATAGRAM 排队失败：{error}")))?;

    timeout(OPERATION_TIMEOUT, async {
        loop {
            let after = path.stats();
            if after.frame_tx.datagram > before.frame_tx.datagram
                && after.udp_tx.datagrams > before.udp_tx.datagrams
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| other_error("C v3 等待独立 UDP datagram 构包超时"))?;
    Ok(())
}

fn make_v3_payload(sequence: u32) -> V3Payload {
    let mut payload = [0_u8; V3_LOGICAL_MESSAGE_SIZE];
    let mut state = sequence.wrapping_mul(0x85eb_ca6b).wrapping_add(0xc2b2_ae35);
    for (index, byte) in payload.iter_mut().enumerate() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = (state as u8)
            .wrapping_add((index as u8).rotate_left((sequence % 7) + 1))
            .wrapping_add((sequence >> ((index % 4) * 8)) as u8);
    }
    payload
}

fn make_v3_block_payloads(first_sequence: u32) -> [V3Payload; V3_BLOCK_MESSAGES] {
    std::array::from_fn(|index| make_v3_payload(first_sequence + index as u32))
}

fn make_v12_message_shards(sequence: u32) -> [V12Shard; 2] {
    let payload = make_v3_payload(sequence);
    [
        payload[..V12_SHARD_SIZE]
            .try_into()
            .expect("first v12 half has fixed shard size"),
        payload[V12_SHARD_SIZE..]
            .try_into()
            .expect("second v12 half has fixed shard size"),
    ]
}

fn make_v12_data_shard(first_sequence: u32, data_index: usize) -> V12Shard {
    let message_slot = data_index / 2;
    let half = data_index % 2;
    make_v12_message_shards(first_sequence + message_slot as u32)[half]
}

fn make_v12_block_data_shards(first_sequence: u32) -> [V12Shard; V12_DATA_SHARDS] {
    std::array::from_fn(|index| make_v12_data_shard(first_sequence, index))
}

fn xor_v12_shards(left: &V12Shard, right: &V12Shard) -> V12Shard {
    std::array::from_fn(|index| left[index] ^ right[index])
}

fn xor_payloads(left: &V3Payload, right: &V3Payload) -> V3Payload {
    std::array::from_fn(|index| left[index] ^ right[index])
}

fn make_global_parities(payloads: &[V3Payload; V3_BLOCK_MESSAGES]) -> (V3Payload, V3Payload) {
    let mut zero = [0_u8; V3_LOGICAL_MESSAGE_SIZE];
    let mut one = [0_u8; V3_LOGICAL_MESSAGE_SIZE];
    for (index, payload) in payloads.iter().enumerate() {
        let coefficient = global_coefficient(index);
        for byte_index in 0..V3_LOGICAL_MESSAGE_SIZE {
            zero[byte_index] ^= payload[byte_index];
            one[byte_index] ^= gf_mul(coefficient, payload[byte_index]);
        }
    }
    (zero, one)
}

fn make_v12_global_parities(
    payloads: &[V12Shard; V12_DATA_SHARDS],
) -> [V12Shard; V12_GLOBAL_PARITIES] {
    let mut parities = [[0_u8; V12_SHARD_SIZE]; V12_GLOBAL_PARITIES];
    for (slot, payload) in payloads.iter().enumerate() {
        let coefficient = global_coefficient(slot);
        for (row, parity) in parities.iter_mut().enumerate() {
            let factor = gf_pow(coefficient, row as u8);
            for byte_index in 0..V12_SHARD_SIZE {
                parity[byte_index] ^= gf_mul(factor, payload[byte_index]);
            }
        }
    }
    parities
}

fn recover_two_missing(
    zero_residual: &V3Payload,
    one_residual: &V3Payload,
    first_index: usize,
    second_index: usize,
) -> LabResult<(V3Payload, V3Payload)> {
    if first_index >= V3_BLOCK_MESSAGES
        || second_index >= V3_BLOCK_MESSAGES
        || first_index == second_index
    {
        return Err(other_error("C v3 双消元位置非法"));
    }
    let first_coefficient = global_coefficient(first_index);
    let second_coefficient = global_coefficient(second_index);
    let denominator = first_coefficient ^ second_coefficient;
    let mut first = [0_u8; V3_LOGICAL_MESSAGE_SIZE];
    let mut second = [0_u8; V3_LOGICAL_MESSAGE_SIZE];
    for byte_index in 0..V3_LOGICAL_MESSAGE_SIZE {
        let numerator =
            one_residual[byte_index] ^ gf_mul(second_coefficient, zero_residual[byte_index]);
        first[byte_index] = gf_div(numerator, denominator)?;
        second[byte_index] = zero_residual[byte_index] ^ first[byte_index];
    }
    Ok((first, second))
}

fn global_coefficient(index: usize) -> u8 {
    let mut coefficient = 1_u8;
    for _ in 0..index {
        coefficient = gf_mul(coefficient, 2);
    }
    coefficient
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0_u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            product ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= GF_REDUCTION;
        }
        right >>= 1;
    }
    product
}

fn gf_pow(mut base: u8, mut exponent: u8) -> u8 {
    let mut result = 1_u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn gf_div(numerator: u8, denominator: u8) -> LabResult<u8> {
    if denominator == 0 {
        return Err(other_error("C v3 GF(256) 除数为零"));
    }
    if numerator == 0 {
        return Ok(0);
    }
    Ok(gf_mul(numerator, gf_pow(denominator, 254)))
}

fn encode_v3_frame(
    kind: V3FrameKind,
    symbol_index: usize,
    block_id: usize,
    first_sequence: usize,
    payload: &V3Payload,
) -> LabResult<Vec<u8>> {
    let symbol_index =
        u8::try_from(symbol_index).map_err(|_| other_error("C v3 符号位置超过 u8 范围"))?;
    let block_id = u32::try_from(block_id).map_err(|_| other_error("C v3 块号超过 u32 范围"))?;
    let first_sequence =
        u32::try_from(first_sequence).map_err(|_| other_error("C v3 块首序号超过 u32 范围"))?;
    let mut encoded = Vec::with_capacity(V3_FRAME_SIZE);
    encoded.extend_from_slice(V3_MAGIC);
    encoded.push(V3_VERSION);
    encoded.push(kind as u8);
    encoded.push(symbol_index);
    encoded.push(0);
    encoded.extend_from_slice(&block_id.to_be_bytes());
    encoded.extend_from_slice(&first_sequence.to_be_bytes());
    encoded.extend_from_slice(&(digest(payload) as u32).to_be_bytes());
    encoded.extend_from_slice(payload);
    debug_assert_eq!(encoded.len(), V3_FRAME_SIZE);
    Ok(encoded)
}

fn decode_v3_frame(data: &[u8]) -> Result<V3DecodedFrame, ()> {
    if data.len() != V3_FRAME_SIZE
        || &data[..4] != V3_MAGIC
        || data[4] != V3_VERSION
        || data[7] != 0
    {
        return Err(());
    }
    let kind = V3FrameKind::try_from(data[5])?;
    let symbol_index = data[6] as usize;
    let block_id = u32::from_be_bytes(data[8..12].try_into().map_err(|_| ())?) as usize;
    let first_sequence = u32::from_be_bytes(data[12..16].try_into().map_err(|_| ())?) as usize;
    let payload_digest = u32::from_be_bytes(data[16..20].try_into().map_err(|_| ())?);
    let mut payload = [0_u8; V3_LOGICAL_MESSAGE_SIZE];
    payload.copy_from_slice(&data[V3_HEADER_SIZE..]);
    Ok(V3DecodedFrame {
        kind,
        symbol_index,
        block_id,
        first_sequence,
        payload_digest,
        payload,
    })
}

fn encode_v12_frame(
    kind: V12FrameKind,
    symbol_index: usize,
    block_id: usize,
    payload: &V12Shard,
) -> LabResult<Vec<u8>> {
    if symbol_index >= 32 {
        return Err(other_error("C v12 符号位置超过 5 bit 范围"));
    }
    if block_id > V12_MAX_BLOCK_ID {
        return Err(other_error("C v12 超块号超过 u16 范围"));
    }
    let kind_and_symbol = (kind as u8) << 6 | symbol_index as u8;
    let mut encoded = Vec::with_capacity(V12_FRAME_SIZE);
    encoded.extend_from_slice(V12_MAGIC);
    encoded.push(kind_and_symbol);
    encoded.extend_from_slice(&(block_id as u16).to_be_bytes());
    encoded.extend_from_slice(&(digest(payload) as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    debug_assert_eq!(encoded.len(), V12_FRAME_SIZE);
    Ok(encoded)
}

fn decode_v12_frame(data: &[u8]) -> Result<V12DecodedFrame, ()> {
    if data.len() != V12_FRAME_SIZE || &data[..2] != V12_MAGIC || data[2] & 0x20 != 0 {
        return Err(());
    }
    let kind = V12FrameKind::try_from(data[2] >> 6)?;
    let symbol_index = (data[2] & 0x1f) as usize;
    let block_id = u16::from_be_bytes(data[3..5].try_into().map_err(|_| ())?) as usize;
    let first_sequence = block_id.checked_mul(V12_BLOCK_MESSAGES).ok_or(())?;
    let payload_digest = u16::from_be_bytes(data[5..7].try_into().map_err(|_| ())?);
    let mut payload = [0_u8; V12_SHARD_SIZE];
    payload.copy_from_slice(&data[V12_HEADER_SIZE..]);
    Ok(V12DecodedFrame {
        kind,
        symbol_index,
        block_id,
        first_sequence,
        payload_digest,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_frames_are_fixed_size_and_self_checking() {
        let payload = make_v3_payload(7);
        let encoded = encode_v3_frame(V3FrameKind::Original, 7, 0, 0, &payload).unwrap();
        assert_eq!(encoded.len(), 220);
        let decoded = decode_v3_frame(&encoded).unwrap();
        assert_eq!(decoded.kind, V3FrameKind::Original);
        assert_eq!(decoded.symbol_index, 7);
        assert_eq!(decoded.block_id, 0);
        assert_eq!(decoded.first_sequence, 0);
        assert_eq!(decoded.payload_digest, digest(&payload) as u32);
        assert_eq!(decoded.payload, payload);

        let mut corrupted = encoded;
        corrupted[V3_HEADER_SIZE + 11] ^= 1;
        let corrupted = decode_v3_frame(&corrupted).unwrap();
        assert_ne!(digest(&corrupted.payload) as u32, corrupted.payload_digest);
    }

    #[test]
    fn two_global_equations_recover_any_two_missing_payloads() {
        let payloads = make_v3_block_payloads(100);
        let (zero, one) = make_global_parities(&payloads);
        for first_index in 0..V3_BLOCK_MESSAGES {
            for second_index in first_index + 1..V3_BLOCK_MESSAGES {
                let mut zero_residual = zero;
                let mut one_residual = one;
                for (index, payload) in payloads.iter().enumerate() {
                    if index == first_index || index == second_index {
                        continue;
                    }
                    for byte_index in 0..V3_LOGICAL_MESSAGE_SIZE {
                        zero_residual[byte_index] ^= payload[byte_index];
                        one_residual[byte_index] ^=
                            gf_mul(global_coefficient(index), payload[byte_index]);
                    }
                }
                let (first, second) =
                    recover_two_missing(&zero_residual, &one_residual, first_index, second_index)
                        .unwrap();
                assert_eq!(first, payloads[first_index]);
                assert_eq!(second, payloads[second_index]);
            }
        }
    }

    #[test]
    fn v3_config_requires_complete_ten_message_blocks() {
        assert_eq!(
            RealtimeV3WireConfig::new(Duration::from_millis(100))
                .logical_messages()
                .unwrap(),
            10
        );
        assert!(
            RealtimeV3WireConfig::new(Duration::from_millis(90))
                .logical_messages()
                .is_err()
        );
    }

    #[test]
    fn v4_decoder_combines_pair_and_global_recovery_without_duplicate_delivery() {
        let experiment_started = Instant::now();
        let generated_micros = (0..V3_BLOCK_MESSAGES)
            .map(|sequence| sequence as u64 * 10_000)
            .collect::<Vec<_>>();
        let payloads = make_v3_block_payloads(0);
        let mut accounting = V4Accounting::new(V3_BLOCK_MESSAGES);

        for sequence in 0..V3_BLOCK_MESSAGES {
            if matches!(sequence, 1 | 4 | 5) {
                continue;
            }
            let encoded =
                encode_v3_frame(V3FrameKind::Original, sequence, 0, 0, &payloads[sequence])
                    .unwrap();
            accounting
                .record(
                    RealtimeDatagramEvent {
                        data: encoded,
                        received_at: experiment_started
                            + Duration::from_micros(generated_micros[sequence] + 21_000),
                    },
                    experiment_started,
                    &generated_micros,
                )
                .unwrap();
        }

        for pair_index in 0..V3_PAIR_PARITIES {
            if pair_index == 2 {
                continue;
            }
            let first = pair_index * 2;
            let parity = xor_payloads(&payloads[first], &payloads[first + 1]);
            let encoded =
                encode_v3_frame(V3FrameKind::PairParity, pair_index, 0, 0, &parity).unwrap();
            accounting
                .record(
                    RealtimeDatagramEvent {
                        data: encoded,
                        received_at: experiment_started
                            + Duration::from_micros(
                                generated_micros[first + 1].saturating_add(22_000),
                            ),
                    },
                    experiment_started,
                    &generated_micros,
                )
                .unwrap();
        }

        let (zero, one) = make_global_parities(&payloads);
        for (kind, parity) in [
            (V3FrameKind::GlobalZero, zero),
            (V3FrameKind::GlobalOne, one),
        ] {
            let encoded = encode_v3_frame(kind, 0, 0, 0, &parity).unwrap();
            accounting
                .record(
                    RealtimeDatagramEvent {
                        data: encoded,
                        received_at: experiment_started + Duration::from_millis(140),
                    },
                    experiment_started,
                    &generated_micros,
                )
                .unwrap();
        }

        assert_eq!(accounting.valid_messages, 10);
        assert_eq!(accounting.late_messages, 0);
        assert_eq!(accounting.original_deliveries, 7);
        assert_eq!(accounting.pair_recoveries, 1);
        assert_eq!(accounting.global_recoveries, 2);
        assert_eq!(accounting.duplicate_messages, 0);
        assert_eq!(accounting.recovery_error_messages, 0);
    }

    #[test]
    fn v4_nonzero_block_accounting_uses_ten_message_blocks() {
        let experiment_started = Instant::now();
        let generated_micros = (0..V3_BLOCK_MESSAGES * 2)
            .map(|sequence| sequence as u64 * 10_000)
            .collect::<Vec<_>>();
        let first_sequence = V3_BLOCK_MESSAGES;
        let payloads = make_v3_block_payloads(first_sequence as u32);
        let mut accounting = V4Accounting::new(V3_BLOCK_MESSAGES * 2);

        for (slot, payload) in payloads.iter().enumerate().take(V3_BLOCK_MESSAGES) {
            let sequence = first_sequence + slot;
            let encoded =
                encode_v3_frame(V3FrameKind::Original, slot, 1, first_sequence, payload).unwrap();
            accounting
                .record(
                    RealtimeDatagramEvent {
                        data: encoded,
                        received_at: experiment_started
                            + Duration::from_micros(generated_micros[sequence] + 21_000),
                    },
                    experiment_started,
                    &generated_micros,
                )
                .unwrap();
        }

        assert_eq!(accounting.valid_messages, V3_BLOCK_MESSAGES);
        assert_eq!(accounting.invalid_header_frames, 0);
        assert_eq!(accounting.malformed_frames, 0);
        assert_eq!(accounting.digest_error_frames, 0);
        assert_eq!(accounting.content_error_frames, 0);
        assert_eq!(accounting.recovery_error_messages, 0);
        assert_eq!(accounting.timestamp_error_messages, 0);
    }

    #[test]
    fn v12_two_of_three_and_global_recovery_deliver_each_message_once() {
        let experiment_started = Instant::now();
        let generated_micros = (0..V12_BLOCK_MESSAGES)
            .map(|sequence| sequence as u64 * 10_000)
            .collect::<Vec<_>>();
        let block_data = make_v12_block_data_shards(0);
        let mut accounting = V12Accounting::new(V12_BLOCK_MESSAGES);

        let compact = encode_v12_frame(V12FrameKind::Data0, 7, 23, &block_data[7 * 2]).unwrap();
        assert_eq!(compact.len(), V12_FRAME_SIZE);
        let decoded = decode_v12_frame(&compact).unwrap();
        assert_eq!(decoded.kind, V12FrameKind::Data0);
        assert_eq!(decoded.block_id, 23);
        assert_eq!(decoded.first_sequence, 460);
        assert_eq!(decoded.symbol_index, 7);
        assert_eq!(decoded.payload_digest, digest(&block_data[14]) as u16);
        let mut reserved_bit = compact;
        reserved_bit[2] |= 0x20;
        assert!(decode_v12_frame(&reserved_bit).is_err());
        assert!(
            encode_v12_frame(V12FrameKind::Data0, 0, V12_MAX_BLOCK_ID + 1, &block_data[0],)
                .is_err()
        );

        for slot in 0..V12_BLOCK_MESSAGES {
            let kinds = match slot {
                1 => vec![V12FrameKind::Data0, V12FrameKind::LocalParity],
                2 => vec![V12FrameKind::Data1, V12FrameKind::LocalParity],
                3 | 5 => vec![V12FrameKind::Data0],
                4 => vec![V12FrameKind::Data1],
                _ => vec![V12FrameKind::Data0, V12FrameKind::Data1],
            };
            let [data0, data1] = make_v12_message_shards(slot as u32);
            let local = xor_v12_shards(&data0, &data1);
            for kind in kinds {
                let (payload, offset) = match kind {
                    V12FrameKind::Data0 => (data0, 21_000),
                    V12FrameKind::Data1 => (data1, 21_500),
                    V12FrameKind::LocalParity => (local, 22_000),
                    V12FrameKind::Global => unreachable!(),
                };
                let encoded = encode_v12_frame(kind, slot, 0, &payload).unwrap();
                accounting
                    .record(
                        RealtimeDatagramEvent {
                            data: encoded,
                            received_at: experiment_started
                                + Duration::from_micros(generated_micros[slot] + offset),
                        },
                        experiment_started,
                        &generated_micros,
                    )
                    .unwrap();
            }
        }

        for (row, parity) in make_v12_global_parities(&block_data)
            .into_iter()
            .enumerate()
        {
            let encoded = encode_v12_frame(V12FrameKind::Global, row, 0, &parity).unwrap();
            accounting
                .record(
                    RealtimeDatagramEvent {
                        data: encoded,
                        received_at: experiment_started + Duration::from_millis(240),
                    },
                    experiment_started,
                    &generated_micros,
                )
                .unwrap();
        }

        assert_eq!(accounting.valid_messages, V12_BLOCK_MESSAGES);
        assert_eq!(accounting.late_messages, 0);
        assert_eq!(accounting.systematic_deliveries, 15);
        assert_eq!(accounting.local_xor_recoveries, 2);
        assert_eq!(accounting.global_recoveries, 3);
        assert_eq!(accounting.duplicate_shard_frames, 0);
        assert_eq!(accounting.recovery_error_messages, 0);

        let invalid_data = V12DecodedFrame {
            kind: V12FrameKind::Data0,
            symbol_index: V12_BLOCK_MESSAGES,
            block_id: 0,
            first_sequence: 0,
            payload_digest: 0,
            payload: [0; V12_SHARD_SIZE],
        };
        assert!(expected_v12_frame_payload(&invalid_data, 20).is_none());
        let invalid_global = V12DecodedFrame {
            kind: V12FrameKind::Global,
            symbol_index: V12_GLOBAL_PARITIES,
            block_id: 0,
            first_sequence: 0,
            payload_digest: 0,
            payload: [0; V12_SHARD_SIZE],
        };
        assert!(expected_v12_frame_payload(&invalid_global, 20).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v12_global_rows_recover_any_one_two_or_three_data_shards() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let payloads = make_v12_block_data_shards(0);
        let parities = make_v12_global_parities(&payloads);
        let all_slots = (0..V12_DATA_SHARDS).collect::<Vec<_>>();
        let available_at = Instant::now();

        for missing_count in 1..=V12_GLOBAL_PARITIES {
            for missing in choose_rows(&all_slots, missing_count) {
                let mut block = V12BlockState::default();
                for (slot, payload) in payloads.iter().copied().enumerate() {
                    if !missing.contains(&slot) {
                        block.data[slot] = Some(V12ReceivedShard {
                            payload,
                            available_at,
                            source: V12ShardSource::Systematic,
                        });
                    }
                }
                for (row, payload) in parities.iter().copied().enumerate() {
                    block.global_parities[row] = Some(V12ReceivedShard {
                        payload,
                        available_at,
                        source: V12ShardSource::Systematic,
                    });
                }

                assert_eq!(recover_v12_global(&mut block, 0), 0);
                for slot in missing {
                    assert_eq!(
                        block.data[slot].as_ref().map(|shard| shard.payload),
                        Some(payloads[slot])
                    );
                }
            }
        }
    }

    #[test]
    fn v12_nonzero_superblock_accounting_accepts_all_recovery_paths() {
        let experiment_started = Instant::now();
        let generated_micros = (0..V12_BLOCK_MESSAGES * 2)
            .map(|sequence| sequence as u64 * 10_000)
            .collect::<Vec<_>>();
        let first_sequence = V12_BLOCK_MESSAGES;
        let block_data = make_v12_block_data_shards(first_sequence as u32);
        let mut accounting = V12Accounting::new(V12_BLOCK_MESSAGES * 2);

        for slot in 0..V12_BLOCK_MESSAGES {
            let kinds = match slot {
                1 => vec![V12FrameKind::Data0, V12FrameKind::LocalParity],
                2 => vec![V12FrameKind::Data1, V12FrameKind::LocalParity],
                3 | 5 => vec![V12FrameKind::Data0],
                4 => vec![V12FrameKind::Data1],
                _ => vec![V12FrameKind::Data0, V12FrameKind::Data1],
            };
            let sequence = first_sequence + slot;
            let [data0, data1] = make_v12_message_shards(sequence as u32);
            let local = xor_v12_shards(&data0, &data1);
            for kind in kinds {
                let (payload, offset) = match kind {
                    V12FrameKind::Data0 => (data0, 21_000),
                    V12FrameKind::Data1 => (data1, 21_500),
                    V12FrameKind::LocalParity => (local, 22_000),
                    V12FrameKind::Global => unreachable!(),
                };
                let encoded = encode_v12_frame(kind, slot, 1, &payload).unwrap();
                accounting
                    .record(
                        RealtimeDatagramEvent {
                            data: encoded,
                            received_at: experiment_started
                                + Duration::from_micros(generated_micros[sequence] + offset),
                        },
                        experiment_started,
                        &generated_micros,
                    )
                    .unwrap();
            }
        }

        for (row, parity) in make_v12_global_parities(&block_data)
            .into_iter()
            .enumerate()
        {
            let encoded = encode_v12_frame(V12FrameKind::Global, row, 1, &parity).unwrap();
            accounting
                .record(
                    RealtimeDatagramEvent {
                        data: encoded,
                        received_at: experiment_started + Duration::from_millis(440),
                    },
                    experiment_started,
                    &generated_micros,
                )
                .unwrap();
        }

        assert_eq!(accounting.valid_messages, V12_BLOCK_MESSAGES);
        assert_eq!(accounting.late_messages, 0);
        assert_eq!(accounting.systematic_deliveries, 15);
        assert_eq!(accounting.local_xor_recoveries, 2);
        assert_eq!(accounting.global_recoveries, 3);
        assert_eq!(accounting.malformed_frames, 0);
        assert_eq!(accounting.invalid_header_frames, 0);
        assert_eq!(accounting.digest_error_frames, 0);
        assert_eq!(accounting.content_error_frames, 0);
        assert_eq!(accounting.recovery_error_messages, 0);
        assert_eq!(accounting.timestamp_error_messages, 0);
        assert!(
            accounting.first_correct[..first_sequence]
                .iter()
                .all(|seen| !seen)
        );
        assert!(
            accounting.first_correct[first_sequence..]
                .iter()
                .all(|seen| *seen)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_v3_wire_probe_routes_and_isolates_every_frame() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report =
            run_v3_wire_latency_probe(RealtimeV3WireConfig::new(Duration::from_millis(100)))
                .await
                .unwrap();
        assert_eq!(report.logical_messages, 10);
        assert_eq!(report.queued_original_frames, 10);
        assert_eq!(report.queued_pair_parity_frames, 5);
        assert_eq!(report.queued_global_parity_frames, 2);
        assert_eq!(report.error_frames(), 0);
        assert!(report.frames_exactly_routed());
        assert!(report.frames_isolated());
        assert!(report.measurement_is_complete());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_v4_coding_run_recovers_and_keeps_every_application_frame_separate() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = run_v4_bbr3_coding_realtime(RealtimeV4Config::new(Duration::from_millis(100)))
            .await
            .unwrap();
        assert_eq!(report.logical_messages, 10);
        assert_eq!(report.valid_messages, 10);
        assert_eq!(report.late_messages, 0);
        assert_eq!(report.lost_messages, 0);
        assert_eq!(report.error_messages(), 0);
        assert_eq!(report.line_one_datagram_frames_sent, 15);
        assert_eq!(report.line_two_datagram_frames_sent, 2);
        assert!(report.frames_exactly_routed());
        assert!(report.application_frames_are_separate());
        assert!(report.measurement_is_complete());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_v12_two_of_three_run_keeps_the_registered_frame_budget() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report =
            run_v12_bbr3_two_of_three_realtime(RealtimeV12Config::new(Duration::from_millis(200)))
                .await
                .unwrap();
        assert_eq!(report.logical_messages, 20);
        assert_eq!(report.valid_messages, 20);
        assert_eq!(report.late_messages, 0);
        assert_eq!(report.lost_messages, 0);
        assert_eq!(report.error_messages(), 0);
        assert_eq!(report.queued_data0_frames, 20);
        assert_eq!(report.queued_data1_frames, 20);
        assert_eq!(report.queued_local_parity_frames, 20);
        assert_eq!(report.queued_global_parity_frames, 3);
        assert_eq!(report.line_one_datagram_frames_sent, 60);
        assert_eq!(report.line_two_datagram_frames_sent, 3);
        assert_eq!(report.systematic_deliveries, 20);
        assert_eq!(report.local_xor_recoveries, 0);
        assert_eq!(report.global_recoveries, 0);
        assert_eq!(report.duplicate_shard_frames, 0);
        assert_eq!(report.frame_size_bytes, 107);
        assert_eq!(report.header_size_bytes, 7);
        assert_eq!(report.shard_size_bytes, 100);
        assert!(!report.segmentation_offload_enabled);
        assert!(report.nonzero_superblock_accounting_test);
        assert!(report.two_of_three_accounting_test);
        assert!(report.frames_exactly_routed());
        assert!(report.application_frames_are_separate());
        assert!(report.measurement_is_complete());
    }
}

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use noq::PathStatus;
use tokio::time::{Instant as TokioInstant, sleep, sleep_until, timeout};

use super::{
    LabResult, MultipathScheduler, NETWORK_PATH_IDLE_TIMEOUT, OPERATION_TIMEOUT, PtoRecovery,
    QuicCongestion, ResourceMonitor, digest, other_error, percentile,
    realtime::RealtimeDatagramEvent,
    start_connection_with_realtime_datagram_observer_and_congestion,
};

const GATE_MAGIC: &[u8; 4] = b"FWCG";
const GATE_VERSION: u8 = 1;
const GATE_LOGICAL_MESSAGE_SIZE: usize = 200;
const GATE_HEADER_SIZE: usize = 20;
const GATE_FRAME_SIZE: usize = GATE_HEADER_SIZE + GATE_LOGICAL_MESSAGE_SIZE;
const GATE_MESSAGE_INTERVAL: Duration = Duration::from_millis(10);
const GATE_RECEIVE_GRACE: Duration = Duration::from_millis(1_500);
const GATE_DEADLINE: Duration = Duration::from_millis(300);
const GATE_MAX_DURATION: Duration = Duration::from_secs(120);
const GATE_RELATIVE_P95_LIMIT: Duration = Duration::from_micros(23_726);

#[derive(Debug, Clone, Copy)]
pub struct RealtimeControllerGateConfig {
    pub duration: Duration,
    pub congestion: QuicCongestion,
}

impl RealtimeControllerGateConfig {
    pub const fn new(duration: Duration, congestion: QuicCongestion) -> Self {
        Self {
            duration,
            congestion,
        }
    }

    fn logical_messages(self) -> LabResult<usize> {
        if self.duration.is_zero() || self.duration > GATE_MAX_DURATION {
            return Err(other_error(format!(
                "C 小 DATAGRAM 控制器门控时长必须在 0 到 {} 秒之间",
                GATE_MAX_DURATION.as_secs()
            )));
        }
        let interval_micros = GATE_MESSAGE_INTERVAL.as_micros();
        if !self.duration.as_micros().is_multiple_of(interval_micros) {
            return Err(other_error(
                "C 小 DATAGRAM 控制器门控时长必须是 10 ms 的整数倍",
            ));
        }
        let messages = usize::try_from(self.duration.as_micros() / interval_micros)
            .map_err(|_| other_error("C 小 DATAGRAM 控制器门控消息数量超出平台范围"))?;
        if messages == 0 || messages > u32::MAX as usize {
            return Err(other_error("C 小 DATAGRAM 控制器门控消息数量非法"));
        }
        Ok(messages)
    }
}

#[derive(Debug, Clone)]
pub struct RealtimeControllerGateReport {
    pub duration: Duration,
    pub congestion: QuicCongestion,
    pub measurement_elapsed: Duration,
    pub logical_messages: usize,
    pub queued_frames: usize,
    pub observed_frames: usize,
    pub decoded_frames: usize,
    pub valid_messages: usize,
    pub late_messages: usize,
    pub lost_messages: usize,
    pub duplicate_messages: usize,
    pub malformed_frames: usize,
    pub invalid_sequence_frames: usize,
    pub timestamp_error_frames: usize,
    pub digest_error_frames: usize,
    pub content_error_frames: usize,
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

impl RealtimeControllerGateReport {
    pub fn error_frames(&self) -> usize {
        self.malformed_frames
            .saturating_add(self.invalid_sequence_frames)
            .saturating_add(self.timestamp_error_frames)
            .saturating_add(self.digest_error_frames)
            .saturating_add(self.content_error_frames)
    }

    pub fn udp_wire_ratio(&self) -> f64 {
        if self.logical_application_bytes == 0 {
            return 0.0;
        }
        self.total_udp_bytes_sent as f64 / self.logical_application_bytes as f64
    }

    pub fn frames_exactly_routed(&self) -> bool {
        self.line_one_datagram_frames_sent == self.queued_frames as u64
            && self.line_two_datagram_frames_sent == 0
    }

    pub fn measurement_is_complete(&self) -> bool {
        self.valid_messages
            .saturating_add(self.late_messages)
            .saturating_add(self.lost_messages)
            == self.logical_messages
            && self.decoded_frames.saturating_add(self.malformed_frames) == self.observed_frames
            && self.queued_frames == self.logical_messages
    }

    pub fn feasibility_gate_pass(&self) -> bool {
        self.error_frames() == 0
            && self.frames_exactly_routed()
            && self.measurement_is_complete()
            && self
                .p95
                .is_some_and(|value| value < GATE_RELATIVE_P95_LIMIT)
            && self.primary_path_open
            && self.secondary_path_open
    }
}

#[derive(Debug)]
struct GateDecodedFrame {
    sequence: usize,
    generated_micros: u64,
    payload_digest: u32,
    payload: [u8; GATE_LOGICAL_MESSAGE_SIZE],
}

#[derive(Debug)]
struct GateAccounting {
    first_correct: Vec<bool>,
    latencies: Vec<Duration>,
    observed_frames: usize,
    decoded_frames: usize,
    valid_messages: usize,
    late_messages: usize,
    duplicate_messages: usize,
    malformed_frames: usize,
    invalid_sequence_frames: usize,
    timestamp_error_frames: usize,
    digest_error_frames: usize,
    content_error_frames: usize,
}

impl GateAccounting {
    fn new(logical_messages: usize) -> Self {
        Self {
            first_correct: vec![false; logical_messages],
            latencies: Vec::with_capacity(logical_messages),
            observed_frames: 0,
            decoded_frames: 0,
            valid_messages: 0,
            late_messages: 0,
            duplicate_messages: 0,
            malformed_frames: 0,
            invalid_sequence_frames: 0,
            timestamp_error_frames: 0,
            digest_error_frames: 0,
            content_error_frames: 0,
        }
    }

    fn record(
        &mut self,
        event: RealtimeDatagramEvent,
        experiment_started: Instant,
        generated_micros: &[u64],
    ) -> LabResult<()> {
        self.observed_frames = self.observed_frames.saturating_add(1);
        let received_elapsed = event
            .received_at
            .checked_duration_since(experiment_started)
            .ok_or_else(|| other_error("C 控制器门控接收时间早于实验起点"))?;
        let received_micros = u64::try_from(received_elapsed.as_micros())
            .map_err(|_| other_error("C 控制器门控接收时间超过 u64 微秒范围"))?;
        let frame = match decode_gate_frame(&event.data) {
            Ok(frame) => frame,
            Err(()) => {
                self.malformed_frames = self.malformed_frames.saturating_add(1);
                return Ok(());
            }
        };
        self.decoded_frames = self.decoded_frames.saturating_add(1);
        if frame.sequence >= generated_micros.len() {
            self.invalid_sequence_frames = self.invalid_sequence_frames.saturating_add(1);
            return Ok(());
        }
        if frame.generated_micros != generated_micros[frame.sequence]
            || frame.generated_micros > received_micros
        {
            self.timestamp_error_frames = self.timestamp_error_frames.saturating_add(1);
            return Ok(());
        }
        if digest(&frame.payload) as u32 != frame.payload_digest {
            self.digest_error_frames = self.digest_error_frames.saturating_add(1);
            return Ok(());
        }
        if frame.payload != make_gate_payload(frame.sequence as u32) {
            self.content_error_frames = self.content_error_frames.saturating_add(1);
            return Ok(());
        }
        if self.first_correct[frame.sequence] {
            self.duplicate_messages = self.duplicate_messages.saturating_add(1);
            return Ok(());
        }
        self.first_correct[frame.sequence] = true;
        let latency = Duration::from_micros(received_micros - frame.generated_micros);
        self.latencies.push(latency);
        if latency <= GATE_DEADLINE {
            self.valid_messages = self.valid_messages.saturating_add(1);
        } else {
            self.late_messages = self.late_messages.saturating_add(1);
        }
        Ok(())
    }
}

pub async fn run_realtime_controller_gate(
    config: RealtimeControllerGateConfig,
) -> LabResult<RealtimeControllerGateReport> {
    let logical_messages = config.logical_messages()?;
    let (lab, mut events) = start_connection_with_realtime_datagram_observer_and_congestion(
        Ipv4Addr::UNSPECIFIED,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        PtoRecovery::Disabled,
        MultipathScheduler::NoqDefault,
        config.congestion,
    )
    .await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;

    let operation_result: LabResult<RealtimeControllerGateReport> = async {
        let primary_before = lab.primary.stats();
        let secondary_before = secondary.stats();
        let resources = ResourceMonitor::start()?;
        let experiment_started = Instant::now();
        let mut generated_micros = vec![0_u64; logical_messages];

        for (sequence, generated_micros_slot) in generated_micros.iter_mut().enumerate() {
            let scheduled = experiment_started
                + Duration::from_micros(
                    u64::try_from(sequence)
                        .map_err(|_| other_error("C 控制器门控消息序号超过计时范围"))?
                        .saturating_mul(GATE_MESSAGE_INTERVAL.as_micros() as u64),
                );
            sleep_until(TokioInstant::from_std(scheduled)).await;
            let generated = Instant::now();
            let elapsed_micros = u64::try_from(
                generated
                    .saturating_duration_since(experiment_started)
                    .as_micros(),
            )
            .map_err(|_| other_error("C 控制器门控生成时间超过 u64 微秒范围"))?;
            *generated_micros_slot = elapsed_micros;
            let encoded = encode_gate_frame(
                sequence,
                elapsed_micros,
                &make_gate_payload(sequence as u32),
            )?;
            timeout(
                OPERATION_TIMEOUT,
                lab.connection
                    .send_datagram_on_path_wait(lab.primary.id(), encoded.into()),
            )
            .await
            .map_err(|_| other_error("C 控制器门控原件排队超时"))?
            .map_err(|error| other_error(format!("C 控制器门控原件排队失败：{error}")))?;
        }

        let mut accounting = GateAccounting::new(logical_messages);
        let receive_deadline = Instant::now() + GATE_RECEIVE_GRACE;
        while accounting.observed_frames < logical_messages {
            let remaining = receive_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(other_error("C 控制器门控接收通道提前关闭")),
                Err(_) => break,
            };
            accounting.record(event, experiment_started, &generated_micros)?;
        }

        let measurement_elapsed = experiment_started.elapsed();
        let resource_measurement = resources.finish(measurement_elapsed).await?;
        let primary_after = lab.primary.stats();
        let secondary_after = secondary.stats();
        let valid_messages = accounting.valid_messages;
        let late_messages = accounting.late_messages;

        Ok(RealtimeControllerGateReport {
            duration: config.duration,
            congestion: config.congestion,
            measurement_elapsed,
            logical_messages,
            queued_frames: logical_messages,
            observed_frames: accounting.observed_frames,
            decoded_frames: accounting.decoded_frames,
            valid_messages,
            late_messages,
            lost_messages: logical_messages.saturating_sub(valid_messages + late_messages),
            duplicate_messages: accounting.duplicate_messages,
            malformed_frames: accounting.malformed_frames,
            invalid_sequence_frames: accounting.invalid_sequence_frames,
            timestamp_error_frames: accounting.timestamp_error_frames,
            digest_error_frames: accounting.digest_error_frames,
            content_error_frames: accounting.content_error_frames,
            p50: percentile(&accounting.latencies, 50),
            p95: percentile(&accounting.latencies, 95),
            p99: percentile(&accounting.latencies, 99),
            logical_application_bytes: (logical_messages as u64)
                .saturating_mul(GATE_LOGICAL_MESSAGE_SIZE as u64),
            line_one_udp_bytes_sent: primary_after
                .udp_tx
                .bytes
                .saturating_sub(primary_before.udp_tx.bytes),
            line_two_udp_bytes_sent: secondary_after
                .udp_tx
                .bytes
                .saturating_sub(secondary_before.udp_tx.bytes),
            total_udp_bytes_sent: primary_after
                .udp_tx
                .bytes
                .saturating_sub(primary_before.udp_tx.bytes)
                .saturating_add(
                    secondary_after
                        .udp_tx
                        .bytes
                        .saturating_sub(secondary_before.udp_tx.bytes),
                ),
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

fn make_gate_payload(sequence: u32) -> [u8; GATE_LOGICAL_MESSAGE_SIZE] {
    let mut payload = [0_u8; GATE_LOGICAL_MESSAGE_SIZE];
    let mut state = sequence.wrapping_mul(0x27d4_eb2d).wrapping_add(0x1656_67b1);
    for (index, byte) in payload.iter_mut().enumerate() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = (state as u8)
            .wrapping_add(index as u8)
            .wrapping_add((sequence >> ((index % 4) * 8)) as u8);
    }
    payload
}

fn encode_gate_frame(
    sequence: usize,
    generated_micros: u64,
    payload: &[u8; GATE_LOGICAL_MESSAGE_SIZE],
) -> LabResult<Vec<u8>> {
    let sequence =
        u32::try_from(sequence).map_err(|_| other_error("C 控制器门控序号超过 u32 范围"))?;
    let generated_micros = u32::try_from(generated_micros)
        .map_err(|_| other_error("C 控制器门控时间超过 u32 微秒范围"))?;
    let mut encoded = Vec::with_capacity(GATE_FRAME_SIZE);
    encoded.extend_from_slice(GATE_MAGIC);
    encoded.push(GATE_VERSION);
    encoded.extend_from_slice(&[0_u8; 3]);
    encoded.extend_from_slice(&sequence.to_be_bytes());
    encoded.extend_from_slice(&generated_micros.to_be_bytes());
    encoded.extend_from_slice(&(digest(payload) as u32).to_be_bytes());
    encoded.extend_from_slice(payload);
    debug_assert_eq!(encoded.len(), GATE_FRAME_SIZE);
    Ok(encoded)
}

fn decode_gate_frame(data: &[u8]) -> Result<GateDecodedFrame, ()> {
    if data.len() != GATE_FRAME_SIZE
        || &data[..4] != GATE_MAGIC
        || data[4] != GATE_VERSION
        || data[5..8] != [0_u8; 3]
    {
        return Err(());
    }
    let sequence = u32::from_be_bytes(data[8..12].try_into().map_err(|_| ())?) as usize;
    let generated_micros = u32::from_be_bytes(data[12..16].try_into().map_err(|_| ())?) as u64;
    let payload_digest = u32::from_be_bytes(data[16..20].try_into().map_err(|_| ())?);
    let mut payload = [0_u8; GATE_LOGICAL_MESSAGE_SIZE];
    payload.copy_from_slice(&data[GATE_HEADER_SIZE..]);
    Ok(GateDecodedFrame {
        sequence,
        generated_micros,
        payload_digest,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_gate_frame_roundtrip_is_exactly_220_bytes() {
        let payload = make_gate_payload(17);
        let encoded = encode_gate_frame(17, 123_456, &payload).unwrap();
        assert_eq!(encoded.len(), 220);
        let decoded = decode_gate_frame(&encoded).unwrap();
        assert_eq!(decoded.sequence, 17);
        assert_eq!(decoded.generated_micros, 123_456);
        assert_eq!(decoded.payload_digest, digest(&payload) as u32);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn controller_gate_config_accepts_ten_millisecond_multiples() {
        assert_eq!(
            RealtimeControllerGateConfig::new(Duration::from_millis(100), QuicCongestion::Cubic,)
                .logical_messages()
                .unwrap(),
            10
        );
        assert!(
            RealtimeControllerGateConfig::new(Duration::from_millis(101), QuicCongestion::Cubic,)
                .logical_messages()
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_controller_gate_routes_only_originals_on_primary() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = run_realtime_controller_gate(RealtimeControllerGateConfig::new(
            Duration::from_millis(100),
            QuicCongestion::Cubic,
        ))
        .await
        .unwrap();
        assert_eq!(report.logical_messages, 10);
        assert_eq!(report.valid_messages, 10);
        assert_eq!(report.error_frames(), 0);
        assert!(report.frames_exactly_routed());
        assert!(report.measurement_is_complete());
    }
}

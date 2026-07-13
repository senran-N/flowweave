use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use noq::PathStatus;
use tokio::time::{Instant as TokioInstant, sleep, sleep_until, timeout};

use super::{
    LabResult, MultipathScheduler, NETWORK_PATH_IDLE_TIMEOUT, OPERATION_TIMEOUT, PtoRecovery,
    ResourceMonitor, digest, other_error, percentile,
    start_connection_with_realtime_datagram_observer,
};

const REALTIME_MAGIC: &[u8; 4] = b"FWC1";
const REALTIME_VERSION: u8 = 1;
const REALTIME_MESSAGE_SIZE: usize = 200;
const REALTIME_BATCH_MESSAGES: usize = 5;
const REALTIME_MESSAGE_INTERVAL: Duration = Duration::from_millis(10);
const REALTIME_DEADLINE: Duration = Duration::from_millis(300);
const REALTIME_RECEIVE_GRACE: Duration = Duration::from_millis(1_500);
const REALTIME_MAX_DURATION: Duration = Duration::from_secs(120);
const REALTIME_TIMESTAMP_QUANTUM_MICROS: u64 = 4;
const REALTIME_BATCH_HEADER_SIZE: usize = 20
    + (REALTIME_BATCH_MESSAGES - 1) * std::mem::size_of::<u16>()
    + REALTIME_BATCH_MESSAGES * std::mem::size_of::<u32>();
const REALTIME_BATCH_SIZE: usize =
    REALTIME_BATCH_HEADER_SIZE + REALTIME_BATCH_MESSAGES * REALTIME_MESSAGE_SIZE;

#[derive(Debug, Clone, Copy)]
pub struct RealtimeDatagramConfig {
    pub duration: Duration,
}

impl RealtimeDatagramConfig {
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }

    fn logical_messages(self) -> LabResult<usize> {
        if self.duration.is_zero() || self.duration > REALTIME_MAX_DURATION {
            return Err(other_error(format!(
                "C 组实时实验时长必须在 0 到 {} 秒之间",
                REALTIME_MAX_DURATION.as_secs()
            )));
        }
        let interval_micros = REALTIME_MESSAGE_INTERVAL.as_micros();
        if !self.duration.as_micros().is_multiple_of(interval_micros) {
            return Err(other_error("C 组实时实验时长必须是 10 ms 的整数倍"));
        }
        let messages = usize::try_from(self.duration.as_micros() / interval_micros)
            .map_err(|_| other_error("C 组实时实验消息数量超出平台范围"))?;
        if messages == 0 || messages % REALTIME_BATCH_MESSAGES != 0 {
            return Err(other_error("C 组实时实验消息数量必须是五消息批次的整数倍"));
        }
        if messages > u32::MAX as usize {
            return Err(other_error("C 组实时实验消息序号超过 u32 范围"));
        }
        Ok(messages)
    }
}

#[derive(Debug, Clone)]
pub struct RealtimeDatagramReport {
    pub duration: Duration,
    pub measurement_elapsed: Duration,
    pub logical_messages: usize,
    pub batches: usize,
    pub queued_copy_datagrams: usize,
    pub observed_copy_datagrams: usize,
    pub decoded_copy_datagrams: usize,
    pub valid_messages: usize,
    pub late_messages: usize,
    pub lost_messages: usize,
    pub duplicate_messages: usize,
    pub error_messages: usize,
    pub malformed_copy_datagrams: usize,
    pub invalid_batch_messages: usize,
    pub invalid_sequence_messages: usize,
    pub timestamp_error_messages: usize,
    pub digest_error_messages: usize,
    pub content_error_messages: usize,
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

impl RealtimeDatagramReport {
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

    pub fn copies_used_distinct_paths(&self) -> bool {
        let expected = self.batches as u64;
        self.line_one_datagram_frames_sent == expected
            && self.line_two_datagram_frames_sent == expected
    }

    pub fn measurement_is_complete(&self) -> bool {
        self.valid_messages + self.late_messages + self.lost_messages == self.logical_messages
            && self.error_messages
                == self
                    .malformed_copy_datagrams
                    .saturating_mul(REALTIME_BATCH_MESSAGES)
                    .saturating_add(self.invalid_batch_messages)
                    .saturating_add(self.invalid_sequence_messages)
                    .saturating_add(self.timestamp_error_messages)
                    .saturating_add(self.digest_error_messages)
                    .saturating_add(self.content_error_messages)
    }

    pub fn smoke_safety_pass(&self) -> bool {
        self.copies_used_distinct_paths()
            && self.error_messages == 0
            && self.measurement_is_complete()
            && self.udp_wire_ratio() <= 2.2
            && self.primary_path_open
            && self.secondary_path_open
    }

    pub fn stage_pass(&self) -> bool {
        self.smoke_safety_pass()
            && self.effective_arrival_percent() >= 99.5
            && self
                .p95
                .is_some_and(|value| value <= Duration::from_millis(150))
            && self.p99.is_some_and(|value| value <= REALTIME_DEADLINE)
    }
}

#[derive(Debug)]
pub(crate) struct RealtimeDatagramEvent {
    pub(crate) data: Vec<u8>,
    pub(crate) received_at: Instant,
}

#[derive(Debug)]
struct RealtimeMessage {
    sequence: u32,
    generated_micros: u64,
    payload: [u8; REALTIME_MESSAGE_SIZE],
}

#[derive(Debug)]
struct DecodedRealtimeMessage {
    sequence: u32,
    generated_micros: u64,
    payload_digest: u32,
    payload: [u8; REALTIME_MESSAGE_SIZE],
}

#[derive(Debug)]
struct DecodedRealtimeBatch {
    batch_id: u32,
    messages: Vec<DecodedRealtimeMessage>,
}

#[derive(Debug)]
struct ReceiveAccounting {
    first_correct: Vec<bool>,
    latencies: Vec<Duration>,
    observed_copy_datagrams: usize,
    decoded_copy_datagrams: usize,
    valid_messages: usize,
    late_messages: usize,
    duplicate_messages: usize,
    malformed_copy_datagrams: usize,
    invalid_batch_messages: usize,
    invalid_sequence_messages: usize,
    timestamp_error_messages: usize,
    digest_error_messages: usize,
    content_error_messages: usize,
}

impl ReceiveAccounting {
    fn new(logical_messages: usize) -> Self {
        Self {
            first_correct: vec![false; logical_messages],
            latencies: Vec::with_capacity(logical_messages),
            observed_copy_datagrams: 0,
            decoded_copy_datagrams: 0,
            valid_messages: 0,
            late_messages: 0,
            duplicate_messages: 0,
            malformed_copy_datagrams: 0,
            invalid_batch_messages: 0,
            invalid_sequence_messages: 0,
            timestamp_error_messages: 0,
            digest_error_messages: 0,
            content_error_messages: 0,
        }
    }

    fn error_messages(&self) -> usize {
        self.malformed_copy_datagrams
            .saturating_mul(REALTIME_BATCH_MESSAGES)
            .saturating_add(self.invalid_batch_messages)
            .saturating_add(self.invalid_sequence_messages)
            .saturating_add(self.timestamp_error_messages)
            .saturating_add(self.digest_error_messages)
            .saturating_add(self.content_error_messages)
    }

    fn record(
        &mut self,
        event: RealtimeDatagramEvent,
        experiment_started: Instant,
        generated_micros: &[u64],
        batches: usize,
    ) -> LabResult<()> {
        self.observed_copy_datagrams = self.observed_copy_datagrams.saturating_add(1);
        let received_elapsed = event
            .received_at
            .checked_duration_since(experiment_started)
            .ok_or_else(|| other_error("C 组接收时间早于实验起点"))?;
        let received_micros = u64::try_from(received_elapsed.as_micros())
            .map_err(|_| other_error("C 组接收时间超过 u64 微秒范围"))?;
        let batch = match decode_realtime_batch(&event.data) {
            Ok(batch) => batch,
            Err(()) => {
                self.malformed_copy_datagrams = self.malformed_copy_datagrams.saturating_add(1);
                return Ok(());
            }
        };
        self.decoded_copy_datagrams = self.decoded_copy_datagrams.saturating_add(1);

        let batch_id = batch.batch_id as usize;
        if batch_id >= batches {
            self.invalid_batch_messages = self
                .invalid_batch_messages
                .saturating_add(REALTIME_BATCH_MESSAGES);
            return Ok(());
        }

        for (slot, message) in batch.messages.into_iter().enumerate() {
            let expected_sequence = batch_id * REALTIME_BATCH_MESSAGES + slot;
            if message.sequence as usize != expected_sequence
                || expected_sequence >= generated_micros.len()
            {
                self.invalid_sequence_messages = self.invalid_sequence_messages.saturating_add(1);
                continue;
            }
            if message.generated_micros != generated_micros[expected_sequence]
                || message.generated_micros > received_micros
            {
                self.timestamp_error_messages = self.timestamp_error_messages.saturating_add(1);
                continue;
            }
            if digest(&message.payload) as u32 != message.payload_digest {
                self.digest_error_messages = self.digest_error_messages.saturating_add(1);
                continue;
            }
            if message.payload != make_realtime_payload(message.sequence) {
                self.content_error_messages = self.content_error_messages.saturating_add(1);
                continue;
            }

            if self.first_correct[expected_sequence] {
                self.duplicate_messages = self.duplicate_messages.saturating_add(1);
                continue;
            }
            self.first_correct[expected_sequence] = true;
            let latency = Duration::from_micros(received_micros - message.generated_micros);
            self.latencies.push(latency);
            if latency <= REALTIME_DEADLINE {
                self.valid_messages = self.valid_messages.saturating_add(1);
            } else {
                self.late_messages = self.late_messages.saturating_add(1);
            }
        }
        Ok(())
    }
}

pub async fn run_batched_duplication_realtime(
    config: RealtimeDatagramConfig,
) -> LabResult<RealtimeDatagramReport> {
    let logical_messages = config.logical_messages()?;
    let batches = logical_messages / REALTIME_BATCH_MESSAGES;
    let (lab, mut events) = start_connection_with_realtime_datagram_observer(
        Ipv4Addr::UNSPECIFIED,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        PtoRecovery::Disabled,
        MultipathScheduler::NoqDefault,
    )
    .await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;

    let operation_result: LabResult<RealtimeDatagramReport> = async {
        let primary_before = lab.primary.stats();
        let secondary_before = secondary.stats();
        let resources = ResourceMonitor::start()?;
        let experiment_started = Instant::now();
        let mut generated_micros = vec![0_u64; logical_messages];
        let mut pending_batch = Vec::with_capacity(REALTIME_BATCH_MESSAGES);

        for (sequence, generated_micros_slot) in generated_micros.iter_mut().enumerate() {
            let scheduled = experiment_started
                + Duration::from_millis(
                    u64::try_from(sequence)
                        .map_err(|_| other_error("C 组消息序号超过计时范围"))?
                        .saturating_mul(10),
                );
            sleep_until(TokioInstant::from_std(scheduled)).await;
            let generated = Instant::now();
            let elapsed_micros = u64::try_from(
                generated
                    .saturating_duration_since(experiment_started)
                    .as_micros(),
            )
            .map_err(|_| other_error("C 组生成时间超过 u64 微秒范围"))?
                / REALTIME_TIMESTAMP_QUANTUM_MICROS
                * REALTIME_TIMESTAMP_QUANTUM_MICROS;
            *generated_micros_slot = elapsed_micros;
            pending_batch.push(RealtimeMessage {
                sequence: sequence as u32,
                generated_micros: elapsed_micros,
                payload: make_realtime_payload(sequence as u32),
            });

            if pending_batch.len() != REALTIME_BATCH_MESSAGES {
                continue;
            }
            let batch_id = u32::try_from(sequence / REALTIME_BATCH_MESSAGES)
                .map_err(|_| other_error("C 组批次编号超过 u32 范围"))?;
            let encoded = encode_realtime_batch(batch_id, &pending_batch)?;
            let primary_send = lab
                .connection
                .send_datagram_on_path_wait(lab.primary.id(), encoded.clone().into());
            let secondary_send = lab
                .connection
                .send_datagram_on_path_wait(secondary.id(), encoded.into());
            let (primary_result, secondary_result) = timeout(OPERATION_TIMEOUT, async {
                tokio::join!(primary_send, secondary_send)
            })
            .await
            .map_err(|_| other_error("C 组双路径副本排队超时"))?;
            primary_result
                .map_err(|error| other_error(format!("C 组主路径副本排队失败：{error}")))?;
            secondary_result
                .map_err(|error| other_error(format!("C 组备用路径副本排队失败：{error}")))?;
            pending_batch.clear();
        }
        debug_assert!(pending_batch.is_empty());

        let mut accounting = ReceiveAccounting::new(logical_messages);
        let expected_copy_datagrams = batches.saturating_mul(2);
        let receive_deadline = Instant::now() + REALTIME_RECEIVE_GRACE;
        while accounting.observed_copy_datagrams < expected_copy_datagrams {
            let remaining = receive_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(other_error("C 组接收测量通道提前关闭")),
                Err(_) => break,
            };
            accounting.record(event, experiment_started, &generated_micros, batches)?;
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
        let lost_messages = logical_messages.saturating_sub(valid_messages + late_messages);

        Ok(RealtimeDatagramReport {
            duration: config.duration,
            measurement_elapsed,
            logical_messages,
            batches,
            queued_copy_datagrams: expected_copy_datagrams,
            observed_copy_datagrams: accounting.observed_copy_datagrams,
            decoded_copy_datagrams: accounting.decoded_copy_datagrams,
            valid_messages,
            late_messages,
            lost_messages,
            duplicate_messages: accounting.duplicate_messages,
            error_messages: accounting.error_messages(),
            malformed_copy_datagrams: accounting.malformed_copy_datagrams,
            invalid_batch_messages: accounting.invalid_batch_messages,
            invalid_sequence_messages: accounting.invalid_sequence_messages,
            timestamp_error_messages: accounting.timestamp_error_messages,
            digest_error_messages: accounting.digest_error_messages,
            content_error_messages: accounting.content_error_messages,
            p50: percentile(&accounting.latencies, 50),
            p95: percentile(&accounting.latencies, 95),
            p99: percentile(&accounting.latencies, 99),
            logical_application_bytes: (logical_messages as u64)
                .saturating_mul(REALTIME_MESSAGE_SIZE as u64),
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

fn make_realtime_payload(sequence: u32) -> [u8; REALTIME_MESSAGE_SIZE] {
    let mut payload = [0_u8; REALTIME_MESSAGE_SIZE];
    let mut state = sequence.wrapping_mul(0x9e37_79b9).wrapping_add(0xa5a5_5a5a);
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

fn encode_realtime_batch(batch_id: u32, messages: &[RealtimeMessage]) -> LabResult<Vec<u8>> {
    if messages.len() != REALTIME_BATCH_MESSAGES {
        return Err(other_error("C 组编码器只接受完整五消息批次"));
    }
    let expected_first_sequence = batch_id
        .checked_mul(REALTIME_BATCH_MESSAGES as u32)
        .ok_or_else(|| other_error("C 组批次首序号溢出"))?;
    if messages[0].sequence != expected_first_sequence {
        return Err(other_error("C 组批次编号与首序号不一致"));
    }
    let base_generated_micros = u32::try_from(messages[0].generated_micros)
        .map_err(|_| other_error("C 组批次基准时间超过 u32 微秒范围"))?;
    let mut encoded = Vec::with_capacity(REALTIME_BATCH_SIZE);
    encoded.extend_from_slice(REALTIME_MAGIC);
    encoded.push(REALTIME_VERSION);
    encoded.push(REALTIME_BATCH_MESSAGES as u8);
    encoded.extend_from_slice(&[0_u8; 2]);
    encoded.extend_from_slice(&batch_id.to_be_bytes());
    encoded.extend_from_slice(&messages[0].sequence.to_be_bytes());
    encoded.extend_from_slice(&base_generated_micros.to_be_bytes());
    for pair in messages.windows(2) {
        let delta = pair[1]
            .generated_micros
            .checked_sub(pair[0].generated_micros)
            .ok_or_else(|| other_error("C 组批内生成时间不是单调递增"))?;
        if delta % REALTIME_TIMESTAMP_QUANTUM_MICROS != 0 {
            return Err(other_error("C 组批内生成时间没有按 4 微秒量化"));
        }
        let ticks = u16::try_from(delta / REALTIME_TIMESTAMP_QUANTUM_MICROS)
            .map_err(|_| other_error("C 组相邻消息生成间隔超过 262 ms"))?;
        encoded.extend_from_slice(&ticks.to_be_bytes());
    }
    for message in messages {
        encoded.extend_from_slice(&(digest(&message.payload) as u32).to_be_bytes());
    }
    for message in messages {
        encoded.extend_from_slice(&message.payload);
    }
    assert_eq!(encoded.len(), REALTIME_BATCH_SIZE);
    Ok(encoded)
}

fn decode_realtime_batch(data: &[u8]) -> Result<DecodedRealtimeBatch, ()> {
    if data.len() != REALTIME_BATCH_SIZE
        || &data[..4] != REALTIME_MAGIC
        || data[4] != REALTIME_VERSION
        || data[5] != REALTIME_BATCH_MESSAGES as u8
        || data[6..8] != [0_u8; 2]
    {
        return Err(());
    }
    let batch_id = u32::from_be_bytes(data[8..12].try_into().map_err(|_| ())?);
    let first_sequence = u32::from_be_bytes(data[12..16].try_into().map_err(|_| ())?);
    let base_generated_micros = u32::from_be_bytes(data[16..20].try_into().map_err(|_| ())?) as u64;
    let mut generated_micros = [0_u64; REALTIME_BATCH_MESSAGES];
    generated_micros[0] = base_generated_micros;
    for slot in 1..REALTIME_BATCH_MESSAGES {
        let offset = 20 + (slot - 1) * 2;
        let ticks = u16::from_be_bytes(data[offset..offset + 2].try_into().map_err(|_| ())?);
        generated_micros[slot] = generated_micros[slot - 1]
            .checked_add(u64::from(ticks) * REALTIME_TIMESTAMP_QUANTUM_MICROS)
            .ok_or(())?;
    }
    let mut messages = Vec::with_capacity(REALTIME_BATCH_MESSAGES);
    let digest_start = 20 + (REALTIME_BATCH_MESSAGES - 1) * 2;
    for (slot, generated_micros) in generated_micros.into_iter().enumerate() {
        let sequence = first_sequence.checked_add(slot as u32).ok_or(())?;
        let digest_offset = digest_start + slot * 4;
        let payload_digest = u32::from_be_bytes(
            data[digest_offset..digest_offset + 4]
                .try_into()
                .map_err(|_| ())?,
        );
        let payload_offset = REALTIME_BATCH_HEADER_SIZE + slot * REALTIME_MESSAGE_SIZE;
        let mut payload = [0_u8; REALTIME_MESSAGE_SIZE];
        payload.copy_from_slice(&data[payload_offset..payload_offset + REALTIME_MESSAGE_SIZE]);
        messages.push(DecodedRealtimeMessage {
            sequence,
            generated_micros,
            payload_digest,
            payload,
        });
    }
    Ok(DecodedRealtimeBatch { batch_id, messages })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realtime_batch_roundtrip_is_fixed_size_and_self_checking() {
        let messages = (0..REALTIME_BATCH_MESSAGES)
            .map(|sequence| RealtimeMessage {
                sequence: sequence as u32,
                generated_micros: sequence as u64 * 10_000,
                payload: make_realtime_payload(sequence as u32),
            })
            .collect::<Vec<_>>();
        let encoded = encode_realtime_batch(0, &messages).unwrap();
        assert_eq!(encoded.len(), 1048);
        let decoded = decode_realtime_batch(&encoded).unwrap();
        assert_eq!(decoded.batch_id, 0);
        for (expected, actual) in messages.iter().zip(decoded.messages) {
            assert_eq!(actual.sequence, expected.sequence);
            assert_eq!(actual.generated_micros, expected.generated_micros);
            assert_eq!(actual.payload_digest, digest(&expected.payload) as u32);
            assert_eq!(actual.payload, expected.payload);
        }
    }

    #[test]
    fn realtime_config_requires_complete_five_message_batches() {
        assert_eq!(
            RealtimeDatagramConfig::new(Duration::from_millis(50))
                .logical_messages()
                .unwrap(),
            5
        );
        assert!(
            RealtimeDatagramConfig::new(Duration::from_millis(40))
                .logical_messages()
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_realtime_run_uses_both_paths_without_duplicate_delivery() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = run_batched_duplication_realtime(RealtimeDatagramConfig::new(
            Duration::from_millis(100),
        ))
        .await
        .unwrap();
        assert_eq!(report.logical_messages, 10);
        assert_eq!(report.valid_messages, 10);
        assert_eq!(report.late_messages, 0);
        assert_eq!(report.lost_messages, 0);
        assert_eq!(report.error_messages, 0);
        assert_eq!(report.duplicate_messages, 10);
        assert!(report.copies_used_distinct_paths());
        assert!(report.measurement_is_complete());
    }
}

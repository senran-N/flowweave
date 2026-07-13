use std::{
    env,
    fmt::Write as _,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, tcp::OwnedReadHalf, tcp::OwnedWriteHalf},
    sync::{mpsc, oneshot},
    time::{Instant as TokioInstant, sleep, sleep_until, timeout},
};

use super::{FailoverDirection, LabResult, digest, other_error, percentile, throughput_mbps};

const HYSTERIA_EXPECTED_SHA256: &str =
    "66dbdb0608f25f3057b433afe975a9fc1af2ca8e512479e294988b3ef363d6c1";
const HYSTERIA_EXPECTED_VERSION: &str = "Version:\tv2.9.3";
const HYSTERIA_LINE_ONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const HYSTERIA_LINE_TWO_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const HYSTERIA_CLIENT_ACCESS_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const HYSTERIA_SERVER_ACCESS_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
const HYSTERIA_REALTIME_MAGIC: &[u8; 4] = b"HYC1";
const HYSTERIA_READY_MAGIC: &[u8; 4] = b"HYC+";
const HYSTERIA_REALTIME_MESSAGE_SIZE: usize = 200;
const HYSTERIA_REALTIME_INTERVAL: Duration = Duration::from_millis(10);
const HYSTERIA_REALTIME_DEADLINE: Duration = Duration::from_millis(300);
const HYSTERIA_REALTIME_RECEIVE_GRACE: Duration = Duration::from_millis(1_500);
const HYSTERIA_READY_TIMEOUT: Duration = Duration::from_secs(8);
const HYSTERIA_MAX_REALTIME_DURATION: Duration = Duration::from_secs(120);
const IPV4_UDP_HEADER_SIZE: u64 = 28;
const HYSTERIA_DEFAULT_SINGLE_LINE_BANDWIDTH_MBPS: u32 = 20;
const HYSTERIA_SUSTAINED_HEADER_SIZE: usize = 16;
const HYSTERIA_SUSTAINED_END: u64 = u64::MAX;
const HYSTERIA_SUSTAINED_RESPONSE_MAGIC: &[u8; 4] = b"HYA=";
const HYSTERIA_SUSTAINED_RESPONSE_SIZE: usize = 20;
const HYSTERIA_FAILOVER_COMPLETION_GRACE: Duration = Duration::from_secs(2);
const HYSTERIA_MAX_FAILOVER_DURATION: Duration = Duration::from_secs(120);
const HYSTERIA_THROUGHPUT_COMPLETION_GRACE: Duration = Duration::from_secs(30);

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(1);
static NEXT_NFT_TABLE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HysteriaCongestion {
    Bbr,
    Brutal,
}

impl HysteriaCongestion {
    pub const ALL: [Self; 2] = [Self::Bbr, Self::Brutal];

    pub const fn description(self) -> &'static str {
        match self {
            Self::Bbr => "BBR",
            Self::Brutal => "Brutal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HysteriaLine {
    One,
    Two,
}

impl HysteriaLine {
    pub const ALL: [Self; 2] = [Self::One, Self::Two];

    pub const fn description(self) -> &'static str {
        match self {
            Self::One => "线路一",
            Self::Two => "线路二",
        }
    }

    const fn server_ip(self) -> Ipv4Addr {
        match self {
            Self::One => HYSTERIA_LINE_ONE_IP,
            Self::Two => HYSTERIA_LINE_TWO_IP,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HysteriaRealtimeConfig {
    pub binary: PathBuf,
    pub congestion: HysteriaCongestion,
    pub line: HysteriaLine,
    pub duration: Duration,
}

impl HysteriaRealtimeConfig {
    pub fn new(
        binary: impl Into<PathBuf>,
        congestion: HysteriaCongestion,
        line: HysteriaLine,
        duration: Duration,
    ) -> Self {
        Self {
            binary: binary.into(),
            congestion,
            line,
            duration,
        }
    }

    fn logical_messages(&self) -> LabResult<usize> {
        if self.duration.is_zero() || self.duration > HYSTERIA_MAX_REALTIME_DURATION {
            return Err(other_error(format!(
                "Hysteria C 组实验时长必须在 0 到 {} 秒之间",
                HYSTERIA_MAX_REALTIME_DURATION.as_secs()
            )));
        }
        let interval_micros = HYSTERIA_REALTIME_INTERVAL.as_micros();
        if !self.duration.as_micros().is_multiple_of(interval_micros) {
            return Err(other_error("Hysteria C 组实验时长必须是 10 ms 的整数倍"));
        }
        let messages = usize::try_from(self.duration.as_micros() / interval_micros)
            .map_err(|_| other_error("Hysteria C 组消息数量超出平台范围"))?;
        if messages == 0 || messages > u32::MAX as usize {
            return Err(other_error("Hysteria C 组消息数量超出 u32 序号范围"));
        }
        Ok(messages)
    }
}

#[derive(Debug, Clone)]
pub struct HysteriaRealtimeReport {
    pub congestion: HysteriaCongestion,
    pub line: HysteriaLine,
    pub duration: Duration,
    pub measurement_elapsed: Duration,
    pub logical_messages: usize,
    pub observed_datagrams: usize,
    pub decoded_datagrams: usize,
    pub valid_messages: usize,
    pub late_messages: usize,
    pub lost_messages: usize,
    pub duplicate_messages: usize,
    pub malformed_messages: usize,
    pub invalid_sequence_messages: usize,
    pub digest_error_messages: usize,
    pub content_error_messages: usize,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub p99: Option<Duration>,
    pub logical_application_bytes: u64,
    pub line_one_udp_payload_bytes: u64,
    pub line_two_udp_payload_bytes: u64,
    pub line_one_client_packets: u64,
    pub line_two_client_packets: u64,
    pub processes_alive_at_end: bool,
}

impl HysteriaRealtimeReport {
    pub fn error_messages(&self) -> usize {
        self.malformed_messages
            .saturating_add(self.invalid_sequence_messages)
            .saturating_add(self.digest_error_messages)
            .saturating_add(self.content_error_messages)
    }

    pub fn effective_arrival_percent(&self) -> f64 {
        if self.logical_messages == 0 {
            return 0.0;
        }
        self.valid_messages as f64 / self.logical_messages as f64 * 100.0
    }

    pub fn total_udp_payload_bytes(&self) -> u64 {
        self.line_one_udp_payload_bytes
            .saturating_add(self.line_two_udp_payload_bytes)
    }

    pub fn udp_wire_ratio(&self) -> f64 {
        if self.logical_application_bytes == 0 {
            return 0.0;
        }
        self.total_udp_payload_bytes() as f64 / self.logical_application_bytes as f64
    }

    pub fn measurement_is_complete(&self) -> bool {
        self.valid_messages + self.late_messages + self.lost_messages == self.logical_messages
    }

    pub fn used_only_target_line(&self) -> bool {
        match self.line {
            HysteriaLine::One => {
                self.line_one_udp_payload_bytes > 0 && self.line_two_udp_payload_bytes == 0
            }
            HysteriaLine::Two => {
                self.line_two_udp_payload_bytes > 0 && self.line_one_udp_payload_bytes == 0
            }
        }
    }

    pub fn smoke_safety_pass(&self) -> bool {
        self.measurement_is_complete()
            && self.error_messages() == 0
            && self.used_only_target_line()
            && self.processes_alive_at_end
    }
}

#[derive(Debug, Clone)]
pub struct HysteriaThroughputConfig {
    pub binary: PathBuf,
    pub congestion: HysteriaCongestion,
    pub line: HysteriaLine,
    pub bandwidth_mbps: u32,
    pub warmup_duration: Duration,
    pub measurement_duration: Duration,
    pub chunk_size: usize,
    pub seed: u8,
}

impl HysteriaThroughputConfig {
    pub fn new(
        binary: impl Into<PathBuf>,
        congestion: HysteriaCongestion,
        line: HysteriaLine,
        bandwidth_mbps: u32,
        warmup_duration: Duration,
        measurement_duration: Duration,
        chunk_size: usize,
    ) -> Self {
        Self {
            binary: binary.into(),
            congestion,
            line,
            bandwidth_mbps,
            warmup_duration,
            measurement_duration,
            chunk_size,
            seed: 197,
        }
    }

    pub fn with_seed(mut self, seed: u8) -> Self {
        self.seed = seed;
        self
    }

    fn validate(&self) -> LabResult<()> {
        if self.bandwidth_mbps == 0 || self.bandwidth_mbps > 10_000 {
            return Err(other_error(
                "Hysteria B 组真实单线路带宽必须在 1 到 10000 Mbit/s 之间",
            ));
        }
        if self.warmup_duration.is_zero() || self.warmup_duration > Duration::from_secs(30) {
            return Err(other_error("Hysteria B 组预热必须在 0 到 30 秒之间"));
        }
        if self.measurement_duration.is_zero()
            || self.measurement_duration > HYSTERIA_MAX_FAILOVER_DURATION
        {
            return Err(other_error(format!(
                "Hysteria B 组测量时长必须在 0 到 {} 秒之间",
                HYSTERIA_MAX_FAILOVER_DURATION.as_secs(),
            )));
        }
        if self.chunk_size < HYSTERIA_SUSTAINED_HEADER_SIZE || self.chunk_size > 1024 * 1024 {
            return Err(other_error(
                "Hysteria B 组记录载荷必须在 16 字节到 1 MiB 之间",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HysteriaThroughputReport {
    pub congestion: HysteriaCongestion,
    pub line: HysteriaLine,
    pub bandwidth_mbps: u32,
    pub warmup_duration: Duration,
    pub measurement_duration: Duration,
    pub measurement_elapsed: Duration,
    pub chunk_size: usize,
    pub data_intact: bool,
    pub exchange_complete: bool,
    pub writer_alive_at_measurement_start: bool,
    pub writer_alive_at_measurement_end: bool,
    pub records_received_in_window: u64,
    pub application_bytes_received_in_window: u64,
    pub throughput_mbps: f64,
    pub total_records_received: u64,
    pub total_application_bytes_received: u64,
    pub client_line_one_udp_payload_bytes: u64,
    pub client_line_two_udp_payload_bytes: u64,
    pub server_line_one_udp_payload_bytes: u64,
    pub server_line_two_udp_payload_bytes: u64,
    pub client_line_one_packets: u64,
    pub client_line_two_packets: u64,
    pub server_line_one_packets: u64,
    pub server_line_two_packets: u64,
    pub processes_alive_at_end: bool,
}

impl HysteriaThroughputReport {
    pub fn target_client_udp_payload_bytes(&self) -> u64 {
        match self.line {
            HysteriaLine::One => self.client_line_one_udp_payload_bytes,
            HysteriaLine::Two => self.client_line_two_udp_payload_bytes,
        }
    }

    pub fn non_target_udp_payload_bytes(&self) -> u64 {
        match self.line {
            HysteriaLine::One => self
                .client_line_two_udp_payload_bytes
                .saturating_add(self.server_line_two_udp_payload_bytes),
            HysteriaLine::Two => self
                .client_line_one_udp_payload_bytes
                .saturating_add(self.server_line_one_udp_payload_bytes),
        }
    }

    pub fn target_server_udp_payload_bytes(&self) -> u64 {
        match self.line {
            HysteriaLine::One => self.server_line_one_udp_payload_bytes,
            HysteriaLine::Two => self.server_line_two_udp_payload_bytes,
        }
    }

    pub fn udp_wire_ratio(&self) -> f64 {
        if self.application_bytes_received_in_window == 0 {
            return 0.0;
        }
        self.target_client_udp_payload_bytes() as f64
            / self.application_bytes_received_in_window as f64
    }

    pub fn extra_wire_ratio(&self) -> f64 {
        if self.application_bytes_received_in_window == 0 {
            return 0.0;
        }
        self.target_client_udp_payload_bytes()
            .saturating_sub(self.application_bytes_received_in_window) as f64
            / self.application_bytes_received_in_window as f64
    }

    pub fn infrastructure_pass(&self) -> bool {
        self.data_intact
            && self.exchange_complete
            && self.writer_alive_at_measurement_start
            && self.writer_alive_at_measurement_end
            && self.measurement_elapsed >= self.measurement_duration
            && self.records_received_in_window > 0
            && self.application_bytes_received_in_window
                == self
                    .records_received_in_window
                    .saturating_mul(self.chunk_size as u64)
            && self.total_application_bytes_received
                == self
                    .total_records_received
                    .saturating_mul(self.chunk_size as u64)
            && self.target_client_udp_payload_bytes() > 0
            && self.target_server_udp_payload_bytes() > 0
            && self.non_target_udp_payload_bytes() == 0
            && self.processes_alive_at_end
    }
}

#[derive(Debug, Clone)]
pub struct HysteriaFailoverConfig {
    pub binary: PathBuf,
    pub congestion: HysteriaCongestion,
    pub direction: FailoverDirection,
    pub total_duration: Duration,
    pub failure_after: Duration,
    pub chunk_size: usize,
    pub seed: u8,
}

impl HysteriaFailoverConfig {
    pub fn new(
        binary: impl Into<PathBuf>,
        congestion: HysteriaCongestion,
        direction: FailoverDirection,
        total_duration: Duration,
        failure_after: Duration,
        chunk_size: usize,
        seed: u8,
    ) -> Self {
        Self {
            binary: binary.into(),
            congestion,
            direction,
            total_duration,
            failure_after,
            chunk_size,
            seed,
        }
    }

    fn validate(&self) -> LabResult<()> {
        if self.total_duration.is_zero() || self.total_duration > HYSTERIA_MAX_FAILOVER_DURATION {
            return Err(other_error(format!(
                "Hysteria A 组总时长必须在 0 到 {} 秒之间",
                HYSTERIA_MAX_FAILOVER_DURATION.as_secs()
            )));
        }
        if self.failure_after.is_zero() || self.failure_after >= self.total_duration {
            return Err(other_error("Hysteria A 组黑洞时刻必须位于业务窗口内部"));
        }
        if self.chunk_size < HYSTERIA_SUSTAINED_HEADER_SIZE || self.chunk_size > 1024 * 1024 {
            return Err(other_error(
                "Hysteria A 组记录载荷必须在 16 字节到 1 MiB 之间",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HysteriaFailoverReport {
    pub congestion: HysteriaCongestion,
    pub direction: FailoverDirection,
    pub total_duration: Duration,
    pub failure_after: Duration,
    pub original_connection_reused: bool,
    pub recovered_after_failure: bool,
    pub data_intact: bool,
    pub exchange_complete: bool,
    pub continuity_pass: bool,
    pub recovery_gap: Option<Duration>,
    pub records_received: u64,
    pub records_before_failure: u64,
    pub records_after_failure: u64,
    pub application_bytes_received: u64,
    pub protocol_error: Option<String>,
    pub failure_reason: Option<String>,
    pub application_connection_open_at_deadline: bool,
    pub measurement_timed_out: bool,
    pub client_line_one_udp_payload_bytes_after_failure: u64,
    pub client_line_two_udp_payload_bytes_after_failure: u64,
    pub server_line_one_udp_payload_bytes_after_failure: u64,
    pub server_line_two_udp_payload_bytes_after_failure: u64,
    pub client_line_one_packets_after_failure: u64,
    pub client_line_two_packets_after_failure: u64,
    pub server_line_one_packets_after_failure: u64,
    pub server_line_two_packets_after_failure: u64,
    pub processes_alive_at_end: bool,
}

impl HysteriaFailoverReport {
    pub fn target_line_udp_payload_bytes_after_failure(&self) -> u64 {
        self.client_line_one_udp_payload_bytes_after_failure
            .saturating_add(self.server_line_one_udp_payload_bytes_after_failure)
    }

    pub fn non_target_line_udp_payload_bytes_after_failure(&self) -> u64 {
        self.client_line_two_udp_payload_bytes_after_failure
            .saturating_add(self.server_line_two_udp_payload_bytes_after_failure)
    }

    pub fn infrastructure_pass(&self) -> bool {
        self.original_connection_reused
            && self.records_before_failure > 0
            && self.protocol_error.is_none()
            && self.target_line_udp_payload_bytes_after_failure() > 0
            && self.non_target_line_udp_payload_bytes_after_failure() == 0
            && self.processes_alive_at_end
    }
}

pub fn verify_hysteria_binary(path: impl AsRef<Path>) -> LabResult<()> {
    let path = path.as_ref();
    if !path.is_file() {
        return Err(other_error(format!(
            "找不到 Hysteria 2.9.3 二进制：{}",
            path.display()
        )));
    }
    let hash_output = Command::new("sha256sum").arg(path).output()?;
    if !hash_output.status.success() {
        return Err(other_error("无法计算 Hysteria 二进制 SHA-256"));
    }
    let actual_hash = String::from_utf8_lossy(&hash_output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if actual_hash != HYSTERIA_EXPECTED_SHA256 {
        return Err(other_error(format!(
            "Hysteria 二进制哈希不匹配：期望 {HYSTERIA_EXPECTED_SHA256}，实际 {actual_hash}"
        )));
    }

    let version_output = Command::new(path).arg("version").output()?;
    if !version_output.status.success()
        || !String::from_utf8_lossy(&version_output.stdout).contains(HYSTERIA_EXPECTED_VERSION)
    {
        return Err(other_error("Hysteria 二进制没有报告固定版本 v2.9.3"));
    }
    Ok(())
}

pub async fn run_hysteria_realtime(
    config: HysteriaRealtimeConfig,
) -> LabResult<HysteriaRealtimeReport> {
    let logical_messages = config.logical_messages()?;
    verify_hysteria_binary(&config.binary)?;

    let backend =
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(HYSTERIA_SERVER_ACCESS_IP), 0)).await?;
    let backend_addr = backend.local_addr()?;
    let mut lab = HysteriaLab::start_udp(&config, backend_addr).await?;
    let sender = UdpSocket::bind(SocketAddr::new(IpAddr::V4(HYSTERIA_CLIENT_ACCESS_IP), 0)).await?;
    sender.connect(lab.forward_addr).await?;
    wait_for_udp_forwarding(&sender, &backend, &mut lab).await?;
    drain_udp_socket(&backend).await?;

    let nft = NftClientCounters::new(lab.server_addr.port())?;
    let counters_before = nft.snapshot()?;
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let receive_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let (length, _) = backend.recv_from(&mut buffer).await?;
            if events_tx
                .send(HysteriaDatagramEvent {
                    data: buffer[..length].to_vec(),
                    received_at: Instant::now(),
                })
                .is_err()
            {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    });

    let operation_result: LabResult<HysteriaRealtimeReport> = async {
        let experiment_started = Instant::now();
        let mut generated_at = Vec::with_capacity(logical_messages);
        for sequence in 0..logical_messages {
            let scheduled = experiment_started
                + Duration::from_millis(
                    u64::try_from(sequence)
                        .map_err(|_| other_error("Hysteria C 组消息序号超过计时范围"))?
                        .saturating_mul(10),
                );
            sleep_until(TokioInstant::from_std(scheduled)).await;
            generated_at.push(Instant::now());
            let message = make_hysteria_realtime_message(sequence as u32);
            let sent = sender.send(&message).await?;
            if sent != message.len() {
                return Err(other_error("Hysteria C 组本地 UDP 发送发生截断"));
            }
        }

        let receive_deadline = Instant::now() + HYSTERIA_REALTIME_RECEIVE_GRACE;
        let mut accounting = HysteriaReceiveAccounting::new(logical_messages);
        loop {
            let remaining = receive_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, events_rx.recv()).await {
                Ok(Some(event)) => accounting.record(event, &generated_at),
                Ok(None) => return Err(other_error("Hysteria C 组接收任务提前关闭")),
                Err(_) => break,
            }
        }

        let counters_after = nft.snapshot()?;
        let counter_delta = counters_after.saturating_sub(counters_before);
        let measurement_elapsed = experiment_started.elapsed();
        let processes_alive_at_end = lab.processes_running()?;
        let valid_messages = accounting.valid_messages;
        let late_messages = accounting.late_messages;
        let lost_messages = logical_messages.saturating_sub(valid_messages + late_messages);

        Ok(HysteriaRealtimeReport {
            congestion: config.congestion,
            line: config.line,
            duration: config.duration,
            measurement_elapsed,
            logical_messages,
            observed_datagrams: accounting.observed_datagrams,
            decoded_datagrams: accounting.decoded_datagrams,
            valid_messages,
            late_messages,
            lost_messages,
            duplicate_messages: accounting.duplicate_messages,
            malformed_messages: accounting.malformed_messages,
            invalid_sequence_messages: accounting.invalid_sequence_messages,
            digest_error_messages: accounting.digest_error_messages,
            content_error_messages: accounting.content_error_messages,
            p50: percentile(&accounting.latencies, 50),
            p95: percentile(&accounting.latencies, 95),
            p99: percentile(&accounting.latencies, 99),
            logical_application_bytes: (logical_messages as u64)
                .saturating_mul(HYSTERIA_REALTIME_MESSAGE_SIZE as u64),
            line_one_udp_payload_bytes: counter_delta.line_one.udp_payload_bytes(),
            line_two_udp_payload_bytes: counter_delta.line_two.udp_payload_bytes(),
            line_one_client_packets: counter_delta.line_one.packets,
            line_two_client_packets: counter_delta.line_two.packets,
            processes_alive_at_end,
        })
    }
    .await;

    receive_task.abort();
    let _ = receive_task.await;
    operation_result
}

pub async fn run_hysteria_throughput(
    config: HysteriaThroughputConfig,
) -> LabResult<HysteriaThroughputReport> {
    config.validate()?;
    verify_hysteria_binary(&config.binary)?;

    let backend_listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(HYSTERIA_SERVER_ACCESS_IP), 0)).await?;
    let backend_addr = backend_listener.local_addr()?;
    let mut lab = HysteriaLab::start_tcp_on_line(
        &config.binary,
        config.congestion,
        config.line,
        config.bandwidth_mbps,
        backend_addr,
    )
    .await?;
    let (client_stream, backend_stream) =
        wait_for_tcp_forwarding(lab.forward_addr, &backend_listener, &mut lab).await?;
    let nft = NftClientCounters::new(lab.server_addr.port())?;

    let operation_result: LabResult<HysteriaThroughputReport> = async {
        let (client_read, client_write) = client_stream.into_split();
        let (backend_read, backend_write) = backend_stream.into_split();
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let (started_tx, started_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let sender_events = events_tx.clone();
        let receiver_events = events_tx.clone();
        drop(events_tx);
        let mut sender_task = tokio::spawn(run_hysteria_continuous_tcp_sender(
            client_read,
            client_write,
            stop_rx,
            config.chunk_size,
            config.seed,
            started_tx,
            sender_events,
        ));
        let mut receiver_task = tokio::spawn(run_hysteria_tcp_receiver(
            backend_read,
            backend_write,
            config.chunk_size,
            config.seed,
            receiver_events,
        ));

        let started_at = timeout(HYSTERIA_READY_TIMEOUT, started_rx)
            .await
            .map_err(|_| other_error("Hysteria B 组业务发送任务没有按时启动"))?
            .map_err(|_| other_error("Hysteria B 组业务发送任务提前退出"))?;
        sleep_until(TokioInstant::from_std(started_at + config.warmup_duration)).await;
        let writer_alive_at_measurement_start = !sender_task.is_finished();
        if !writer_alive_at_measurement_start {
            return Err(other_error("Hysteria B 组 writer 在测量前意外完成"));
        }

        let counters_before = nft.snapshot()?;
        let measurement_started = Instant::now();
        sleep_until(TokioInstant::from_std(
            measurement_started + config.measurement_duration,
        ))
        .await;
        let measurement_ended = Instant::now();
        let measurement_elapsed = measurement_ended.saturating_duration_since(measurement_started);
        let counters_after = nft.snapshot()?;
        let writer_alive_at_measurement_end = !sender_task.is_finished();
        let _ = stop_tx.send(());

        let sender_result = timeout(HYSTERIA_THROUGHPUT_COMPLETION_GRACE, &mut sender_task).await;
        if sender_result.is_err() {
            sender_task.abort();
            receiver_task.abort();
            return Err(other_error("Hysteria B 组持续 sender 完整收尾超时"));
        }
        sender_result
            .expect("checked timeout result")
            .map_err(|error| other_error(format!("Hysteria B 组 sender task 异常：{error}")))??;
        timeout(HYSTERIA_THROUGHPUT_COMPLETION_GRACE, &mut receiver_task)
            .await
            .map_err(|_| {
                receiver_task.abort();
                other_error("Hysteria B 组持续 receiver 完整收尾超时")
            })?
            .map_err(|error| other_error(format!("Hysteria B 组 receiver task 异常：{error}")))??;

        let trace = collect_hysteria_throughput_events(&mut events_rx, config.chunk_size).await?;
        let records_received_in_window = count_hysteria_records_in_window(
            &trace.received_at,
            measurement_started,
            measurement_ended,
        )?;
        let application_bytes_received_in_window = records_received_in_window
            .checked_mul(config.chunk_size as u64)
            .ok_or_else(|| other_error("Hysteria B 组测量窗口业务字节数溢出"))?;
        let throughput_size = usize::try_from(application_bytes_received_in_window)
            .map_err(|_| other_error("Hysteria B 组测量窗口业务字节数超出平台范围"))?;
        let counter_delta = counters_after.saturating_sub(counters_before);
        let processes_alive_at_end = lab.processes_running()?;

        Ok(HysteriaThroughputReport {
            congestion: config.congestion,
            line: config.line,
            bandwidth_mbps: config.bandwidth_mbps,
            warmup_duration: config.warmup_duration,
            measurement_duration: config.measurement_duration,
            measurement_elapsed,
            chunk_size: config.chunk_size,
            data_intact: true,
            exchange_complete: true,
            writer_alive_at_measurement_start,
            writer_alive_at_measurement_end,
            records_received_in_window,
            application_bytes_received_in_window,
            throughput_mbps: throughput_mbps(throughput_size, measurement_elapsed),
            total_records_received: trace.records,
            total_application_bytes_received: trace.bytes,
            client_line_one_udp_payload_bytes: counter_delta.line_one.udp_payload_bytes(),
            client_line_two_udp_payload_bytes: counter_delta.line_two.udp_payload_bytes(),
            server_line_one_udp_payload_bytes: counter_delta.server_line_one.udp_payload_bytes(),
            server_line_two_udp_payload_bytes: counter_delta.server_line_two.udp_payload_bytes(),
            client_line_one_packets: counter_delta.line_one.packets,
            client_line_two_packets: counter_delta.line_two.packets,
            server_line_one_packets: counter_delta.server_line_one.packets,
            server_line_two_packets: counter_delta.server_line_two.packets,
            processes_alive_at_end,
        })
    }
    .await;

    operation_result
}

pub async fn run_hysteria_failover<Activate, Restore>(
    config: HysteriaFailoverConfig,
    activate_blackhole: Activate,
    restore_network: Restore,
) -> LabResult<HysteriaFailoverReport>
where
    Activate: FnOnce() -> LabResult<()>,
    Restore: FnOnce() -> LabResult<()>,
{
    config.validate()?;
    verify_hysteria_binary(&config.binary)?;
    let backend_listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(HYSTERIA_SERVER_ACCESS_IP), 0)).await?;
    let backend_addr = backend_listener.local_addr()?;
    let mut lab = HysteriaLab::start_tcp(&config.binary, config.congestion, backend_addr).await?;
    let (client_stream, backend_stream) =
        wait_for_tcp_forwarding(lab.forward_addr, &backend_listener, &mut lab).await?;
    let nft = NftClientCounters::new(lab.server_addr.port())?;

    let operation_result: LabResult<HysteriaFailoverReport> = async {
        let (client_read, client_write) = client_stream.into_split();
        let (backend_read, backend_write) = backend_stream.into_split();
        let (sender_read, sender_write, receiver_read, receiver_write) = match config.direction {
            FailoverDirection::ClientToServer => {
                (client_read, client_write, backend_read, backend_write)
            }
            FailoverDirection::ServerToClient => {
                (backend_read, backend_write, client_read, client_write)
            }
        };
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let (started_tx, started_rx) = oneshot::channel();
        let sender_events = events_tx.clone();
        let receiver_events = events_tx.clone();
        drop(events_tx);
        let sender_task = tokio::spawn(run_hysteria_tcp_sender(
            sender_read,
            sender_write,
            config.total_duration,
            config.chunk_size,
            config.seed,
            started_tx,
            sender_events,
        ));
        let receiver_task = tokio::spawn(run_hysteria_tcp_receiver(
            receiver_read,
            receiver_write,
            config.chunk_size,
            config.seed,
            receiver_events,
        ));

        let started_at = timeout(HYSTERIA_READY_TIMEOUT, started_rx)
            .await
            .map_err(|_| other_error("Hysteria A 组业务发送任务没有按时启动"))?
            .map_err(|_| other_error("Hysteria A 组业务发送任务提前退出"))?;
        sleep_until(TokioInstant::from_std(started_at + config.failure_after)).await;
        let counters_at_failure = nft.snapshot()?;
        activate_blackhole()?;
        let failure_started = Instant::now();
        let deadline = started_at
            + config.total_duration
            + HYSTERIA_FAILOVER_COMPLETION_GRACE;
        let mut received_at = Vec::new();
        let mut records_received = 0_u64;
        let mut application_bytes_received = 0_u64;
        let mut receiver_finished = false;
        let mut exchange_complete = false;
        let mut protocol_error = None;
        let mut task_failure = None;
        let mut channel_closed = false;

        while Instant::now() < deadline {
            if channel_closed {
                sleep_until(TokioInstant::from_std(deadline)).await;
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match timeout(remaining, events_rx.recv()).await {
                Ok(Some(HysteriaTcpEvent::Record {
                    sequence,
                    received_at: timestamp,
                })) => {
                    if sequence != records_received {
                        protocol_error.get_or_insert_with(|| {
                            format!(
                                "Hysteria A 组事件序号错误：期望 {records_received}，实际 {sequence}"
                            )
                        });
                    } else {
                        records_received = records_received.saturating_add(1);
                        application_bytes_received = application_bytes_received
                            .saturating_add(config.chunk_size as u64);
                        received_at.push(timestamp);
                    }
                }
                Ok(Some(HysteriaTcpEvent::Finished { records, bytes })) => {
                    receiver_finished = records == records_received
                        && bytes == application_bytes_received
                        && protocol_error.is_none();
                    if !receiver_finished {
                        protocol_error.get_or_insert_with(|| {
                            "Hysteria A 组完成事件与已校验记录不一致".to_owned()
                        });
                    }
                }
                Ok(Some(HysteriaTcpEvent::ExchangeComplete { records, bytes })) => {
                    exchange_complete = records == records_received
                        && bytes == application_bytes_received
                        && protocol_error.is_none();
                    if !exchange_complete {
                        protocol_error.get_or_insert_with(|| {
                            "Hysteria A 组最终响应与已校验记录不一致".to_owned()
                        });
                    }
                }
                Ok(Some(HysteriaTcpEvent::Failed {
                    protocol,
                    reason,
                })) => {
                    if protocol {
                        protocol_error.get_or_insert(reason);
                    } else {
                        task_failure.get_or_insert(reason);
                    }
                }
                Ok(None) => channel_closed = true,
                Err(_) => break,
            }
        }

        let measurement_timed_out =
            Instant::now() >= deadline && (!receiver_finished || !exchange_complete);
        let application_connection_open_at_deadline =
            !sender_task.is_finished() || !receiver_task.is_finished();
        if !sender_task.is_finished() {
            sender_task.abort();
        }
        if !receiver_task.is_finished() {
            receiver_task.abort();
        }
        collect_tcp_task_result(&mut task_failure, "发送端", sender_task.await);
        collect_tcp_task_result(&mut task_failure, "接收端", receiver_task.await);

        let counters_after = nft.snapshot()?;
        let counter_delta = counters_after.saturating_sub(counters_at_failure);
        let processes_alive_at_end = lab.processes_running()?;
        let records_before_failure = received_at
            .iter()
            .filter(|timestamp| **timestamp <= failure_started)
            .count() as u64;
        let records_after_failure = records_received.saturating_sub(records_before_failure);
        let data_intact = receiver_finished && protocol_error.is_none();
        let recovered_after_failure = records_after_failure > 0 && data_intact;
        let recovery_gap = if recovered_after_failure {
            recovery_gap_after_failure(&received_at, failure_started)
        } else {
            None
        };
        let continuity_pass = recovered_after_failure
            && data_intact
            && exchange_complete
            && processes_alive_at_end;
        let failure_reason = if continuity_pass {
            None
        } else if let Some(error) = protocol_error.as_ref() {
            Some(format!("业务数据校验失败：{error}"))
        } else if let Some(error) = task_failure.as_ref() {
            Some(error.clone())
        } else if !recovered_after_failure {
            Some("故障后的业务数据没有在原 TCP 连接上恢复".to_owned())
        } else if !data_intact {
            Some("故障后虽有数据到达，但 30 秒业务没有完整闭合".to_owned())
        } else if !exchange_complete {
            Some("业务数据完整，但最终反向校验响应没有闭合".to_owned())
        } else if !processes_alive_at_end {
            Some("Hysteria 客户端或服务端进程异常退出".to_owned())
        } else {
            Some("Hysteria A 组未满足连续性合同".to_owned())
        };

        Ok(HysteriaFailoverReport {
            congestion: config.congestion,
            direction: config.direction,
            total_duration: config.total_duration,
            failure_after: config.failure_after,
            original_connection_reused: true,
            recovered_after_failure,
            data_intact,
            exchange_complete,
            continuity_pass,
            recovery_gap,
            records_received,
            records_before_failure,
            records_after_failure,
            application_bytes_received,
            protocol_error,
            failure_reason,
            application_connection_open_at_deadline,
            measurement_timed_out,
            client_line_one_udp_payload_bytes_after_failure: counter_delta
                .line_one
                .udp_payload_bytes(),
            client_line_two_udp_payload_bytes_after_failure: counter_delta
                .line_two
                .udp_payload_bytes(),
            server_line_one_udp_payload_bytes_after_failure: counter_delta
                .server_line_one
                .udp_payload_bytes(),
            server_line_two_udp_payload_bytes_after_failure: counter_delta
                .server_line_two
                .udp_payload_bytes(),
            client_line_one_packets_after_failure: counter_delta.line_one.packets,
            client_line_two_packets_after_failure: counter_delta.line_two.packets,
            server_line_one_packets_after_failure: counter_delta.server_line_one.packets,
            server_line_two_packets_after_failure: counter_delta.server_line_two.packets,
            processes_alive_at_end,
        })
    }
    .await;

    let restore_result = restore_network();
    let report = operation_result?;
    restore_result?;
    Ok(report)
}

fn collect_tcp_task_result(
    failure: &mut Option<String>,
    label: &str,
    result: Result<LabResult<()>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            failure.get_or_insert_with(|| format!("Hysteria A 组{label}失败：{error}"));
        }
        Err(error) if error.is_cancelled() => {}
        Err(error) => {
            failure.get_or_insert_with(|| format!("Hysteria A 组{label}任务异常：{error}"));
        }
    }
}

fn recovery_gap_after_failure(
    received_at: &[Instant],
    failure_started: Instant,
) -> Option<Duration> {
    let mut previous = received_at
        .iter()
        .copied()
        .take_while(|timestamp| *timestamp <= failure_started)
        .last()?;
    let mut maximum = None;
    for timestamp in received_at
        .iter()
        .copied()
        .filter(|timestamp| *timestamp > failure_started)
    {
        let gap = timestamp.saturating_duration_since(previous);
        maximum = Some(maximum.map_or(gap, |current: Duration| current.max(gap)));
        previous = timestamp;
    }
    maximum
}

#[derive(Debug)]
enum HysteriaTcpEvent {
    Record { sequence: u64, received_at: Instant },
    Finished { records: u64, bytes: u64 },
    ExchangeComplete { records: u64, bytes: u64 },
    Failed { protocol: bool, reason: String },
}

#[derive(Debug)]
struct HysteriaThroughputTrace {
    received_at: Vec<Instant>,
    records: u64,
    bytes: u64,
}

async fn collect_hysteria_throughput_events(
    events: &mut mpsc::UnboundedReceiver<HysteriaTcpEvent>,
    chunk_size: usize,
) -> LabResult<HysteriaThroughputTrace> {
    let mut received_at = Vec::new();
    let mut expected_sequence = 0_u64;
    let mut finished = None;
    let mut exchange_complete = None;

    while let Some(event) = events.recv().await {
        match event {
            HysteriaTcpEvent::Record {
                sequence,
                received_at: at,
            } => {
                if sequence != expected_sequence {
                    return Err(other_error(format!(
                        "Hysteria B 组事件序号错误：期望 {expected_sequence}，实际 {sequence}",
                    )));
                }
                received_at.push(at);
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or_else(|| other_error("Hysteria B 组事件记录数溢出"))?;
            }
            HysteriaTcpEvent::Finished { records, bytes } => {
                finished = Some((records, bytes));
            }
            HysteriaTcpEvent::ExchangeComplete { records, bytes } => {
                exchange_complete = Some((records, bytes));
            }
            HysteriaTcpEvent::Failed { protocol, reason } => {
                return Err(other_error(format!(
                    "Hysteria B 组{}失败：{reason}",
                    if protocol { "协议" } else { "任务" },
                )));
            }
        }
    }

    let finished = finished.ok_or_else(|| other_error("Hysteria B 组缺少接收完成事件"))?;
    let exchange_complete =
        exchange_complete.ok_or_else(|| other_error("Hysteria B 组缺少最终响应闭合事件"))?;
    let expected_bytes = expected_sequence
        .checked_mul(chunk_size as u64)
        .ok_or_else(|| other_error("Hysteria B 组事件业务字节数溢出"))?;
    if finished != (expected_sequence, expected_bytes)
        || exchange_complete != (expected_sequence, expected_bytes)
    {
        return Err(other_error(
            "Hysteria B 组接收完成或最终响应与逐记录事件不一致",
        ));
    }

    Ok(HysteriaThroughputTrace {
        received_at,
        records: expected_sequence,
        bytes: expected_bytes,
    })
}

fn count_hysteria_records_in_window(
    received_at: &[Instant],
    started: Instant,
    ended: Instant,
) -> LabResult<u64> {
    if ended < started {
        return Err(other_error("Hysteria B 组测量窗口结束早于开始"));
    }
    u64::try_from(
        received_at
            .iter()
            .filter(|received_at| **received_at >= started && **received_at < ended)
            .count(),
    )
    .map_err(|_| other_error("Hysteria B 组测量窗口记录数超出 u64"))
}

#[derive(Debug)]
struct HysteriaDatagramEvent {
    data: Vec<u8>,
    received_at: Instant,
}

#[derive(Debug)]
struct HysteriaReceiveAccounting {
    first_correct: Vec<bool>,
    latencies: Vec<Duration>,
    observed_datagrams: usize,
    decoded_datagrams: usize,
    valid_messages: usize,
    late_messages: usize,
    duplicate_messages: usize,
    malformed_messages: usize,
    invalid_sequence_messages: usize,
    digest_error_messages: usize,
    content_error_messages: usize,
}

impl HysteriaReceiveAccounting {
    fn new(logical_messages: usize) -> Self {
        Self {
            first_correct: vec![false; logical_messages],
            latencies: Vec::with_capacity(logical_messages),
            observed_datagrams: 0,
            decoded_datagrams: 0,
            valid_messages: 0,
            late_messages: 0,
            duplicate_messages: 0,
            malformed_messages: 0,
            invalid_sequence_messages: 0,
            digest_error_messages: 0,
            content_error_messages: 0,
        }
    }

    fn record(&mut self, event: HysteriaDatagramEvent, generated_at: &[Instant]) {
        if event.data.len() == HYSTERIA_REALTIME_MESSAGE_SIZE
            && event.data[..4] == HYSTERIA_READY_MAGIC[..]
        {
            return;
        }
        self.observed_datagrams = self.observed_datagrams.saturating_add(1);
        let Some(sequence) = decode_hysteria_realtime_message(&event.data, self) else {
            return;
        };
        self.decoded_datagrams = self.decoded_datagrams.saturating_add(1);
        let sequence = sequence as usize;
        if sequence >= generated_at.len() {
            self.invalid_sequence_messages = self.invalid_sequence_messages.saturating_add(1);
            return;
        }
        if self.first_correct[sequence] {
            self.duplicate_messages = self.duplicate_messages.saturating_add(1);
            return;
        }
        self.first_correct[sequence] = true;
        let Some(latency) = event
            .received_at
            .checked_duration_since(generated_at[sequence])
        else {
            self.content_error_messages = self.content_error_messages.saturating_add(1);
            return;
        };
        self.latencies.push(latency);
        if latency <= HYSTERIA_REALTIME_DEADLINE {
            self.valid_messages = self.valid_messages.saturating_add(1);
        } else {
            self.late_messages = self.late_messages.saturating_add(1);
        }
    }
}

fn make_hysteria_realtime_message(sequence: u32) -> [u8; HYSTERIA_REALTIME_MESSAGE_SIZE] {
    let mut message = [0_u8; HYSTERIA_REALTIME_MESSAGE_SIZE];
    message[..4].copy_from_slice(HYSTERIA_REALTIME_MAGIC);
    message[4..8].copy_from_slice(&sequence.to_be_bytes());
    let mut state = sequence.wrapping_mul(0x9e37_79b9).wrapping_add(0x5aa5_a55a);
    for (index, byte) in message[12..].iter_mut().enumerate() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = (state as u8).wrapping_add(index as u8);
    }
    let payload_digest = digest(&message[12..]) as u32;
    message[8..12].copy_from_slice(&payload_digest.to_be_bytes());
    message
}

fn make_ready_message() -> [u8; HYSTERIA_REALTIME_MESSAGE_SIZE] {
    let mut message = [0_u8; HYSTERIA_REALTIME_MESSAGE_SIZE];
    message[..4].copy_from_slice(HYSTERIA_READY_MAGIC);
    message
}

fn decode_hysteria_realtime_message(
    data: &[u8],
    accounting: &mut HysteriaReceiveAccounting,
) -> Option<u32> {
    if data.len() != HYSTERIA_REALTIME_MESSAGE_SIZE || data[..4] != HYSTERIA_REALTIME_MAGIC[..] {
        accounting.malformed_messages = accounting.malformed_messages.saturating_add(1);
        return None;
    }
    let sequence = u32::from_be_bytes(data[4..8].try_into().ok()?);
    let expected_digest = u32::from_be_bytes(data[8..12].try_into().ok()?);
    if digest(&data[12..]) as u32 != expected_digest {
        accounting.digest_error_messages = accounting.digest_error_messages.saturating_add(1);
        return None;
    }
    if data != make_hysteria_realtime_message(sequence) {
        accounting.content_error_messages = accounting.content_error_messages.saturating_add(1);
        return None;
    }
    Some(sequence)
}

async fn wait_for_tcp_forwarding(
    forward_addr: SocketAddr,
    backend_listener: &TcpListener,
    lab: &mut HysteriaLab,
) -> LabResult<(TcpStream, TcpStream)> {
    let deadline = Instant::now() + HYSTERIA_READY_TIMEOUT;
    loop {
        lab.ensure_running()?;
        match TcpStream::connect(forward_addr).await {
            Ok(client) => {
                client.set_nodelay(true)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(other_error(
                        "Hysteria TCP 转发建立本地连接后没有剩余后端等待时间",
                    ));
                }
                let (backend, _) = timeout(remaining, backend_listener.accept())
                    .await
                    .map_err(|_| other_error("Hysteria TCP 转发在 8 秒内没有连接后端"))??;
                backend.set_nodelay(true)?;
                return Ok((client, backend));
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                if Instant::now() >= deadline {
                    return Err(other_error("Hysteria TCP 转发器在 8 秒内没有完成本地监听"));
                }
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn run_hysteria_tcp_sender(
    mut response_reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    duration: Duration,
    chunk_size: usize,
    seed: u8,
    started_tx: oneshot::Sender<Instant>,
    events: mpsc::UnboundedSender<HysteriaTcpEvent>,
) -> LabResult<()> {
    let result: LabResult<()> = async {
        let started_at = Instant::now();
        started_tx
            .send(started_at)
            .map_err(|_| other_error("Hysteria A 组启动时刻无人接收"))?;
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        let mut payload = vec![0_u8; chunk_size];
        while started_at.elapsed() < duration {
            fill_hysteria_sustained_payload(&mut payload, seed, sequence);
            let mut header = [0_u8; HYSTERIA_SUSTAINED_HEADER_SIZE];
            header[..8].copy_from_slice(&sequence.to_be_bytes());
            header[8..].copy_from_slice(&digest(&payload).to_be_bytes());
            writer.write_all(&header).await?;
            writer.write_all(&payload).await?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| other_error("Hysteria A 组发送记录编号溢出"))?;
            bytes = bytes
                .checked_add(chunk_size as u64)
                .ok_or_else(|| other_error("Hysteria A 组发送字节数溢出"))?;
        }

        let mut end = [0_u8; HYSTERIA_SUSTAINED_HEADER_SIZE];
        end[..8].copy_from_slice(&HYSTERIA_SUSTAINED_END.to_be_bytes());
        end[8..].copy_from_slice(&sequence.to_be_bytes());
        writer.write_all(&end).await?;
        writer.shutdown().await?;

        let mut response = [0_u8; HYSTERIA_SUSTAINED_RESPONSE_SIZE];
        response_reader.read_exact(&mut response).await?;
        if &response[..4] != HYSTERIA_SUSTAINED_RESPONSE_MAGIC {
            return Err(other_error("Hysteria A 组最终响应 magic 错误"));
        }
        let response_records = u64::from_be_bytes(
            response[4..12]
                .try_into()
                .expect("Hysteria A 组响应记录数固定为 8 字节"),
        );
        let response_bytes = u64::from_be_bytes(
            response[12..20]
                .try_into()
                .expect("Hysteria A 组响应字节数固定为 8 字节"),
        );
        if (response_records, response_bytes) != (sequence, bytes) {
            return Err(other_error("Hysteria A 组最终响应总量不一致"));
        }
        let _ = events.send(HysteriaTcpEvent::ExchangeComplete {
            records: sequence,
            bytes,
        });
        Ok(())
    }
    .await;

    if let Err(error) = &result {
        let _ = events.send(HysteriaTcpEvent::Failed {
            protocol: false,
            reason: format!("发送端：{error}"),
        });
    }
    result
}

async fn run_hysteria_continuous_tcp_sender(
    mut response_reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    mut stop: oneshot::Receiver<()>,
    chunk_size: usize,
    seed: u8,
    started_tx: oneshot::Sender<Instant>,
    events: mpsc::UnboundedSender<HysteriaTcpEvent>,
) -> LabResult<()> {
    let result: LabResult<()> = async {
        started_tx
            .send(Instant::now())
            .map_err(|_| other_error("Hysteria B 组启动时刻无人接收"))?;
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        let mut payload = vec![0_u8; chunk_size];
        loop {
            match stop.try_recv() {
                Ok(()) | Err(oneshot::error::TryRecvError::Closed) => break,
                Err(oneshot::error::TryRecvError::Empty) => {}
            }

            fill_hysteria_sustained_payload(&mut payload, seed, sequence);
            let mut header = [0_u8; HYSTERIA_SUSTAINED_HEADER_SIZE];
            header[..8].copy_from_slice(&sequence.to_be_bytes());
            header[8..].copy_from_slice(&digest(&payload).to_be_bytes());
            writer.write_all(&header).await?;
            writer.write_all(&payload).await?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| other_error("Hysteria B 组发送记录编号溢出"))?;
            bytes = bytes
                .checked_add(chunk_size as u64)
                .ok_or_else(|| other_error("Hysteria B 组发送字节数溢出"))?;
        }

        let mut end = [0_u8; HYSTERIA_SUSTAINED_HEADER_SIZE];
        end[..8].copy_from_slice(&HYSTERIA_SUSTAINED_END.to_be_bytes());
        end[8..].copy_from_slice(&sequence.to_be_bytes());
        writer.write_all(&end).await?;

        let mut response = [0_u8; HYSTERIA_SUSTAINED_RESPONSE_SIZE];
        response_reader.read_exact(&mut response).await?;
        if &response[..4] != HYSTERIA_SUSTAINED_RESPONSE_MAGIC {
            return Err(other_error("Hysteria B 组最终响应 magic 错误"));
        }
        let response_records = u64::from_be_bytes(
            response[4..12]
                .try_into()
                .expect("Hysteria B 组响应记录数固定为 8 字节"),
        );
        let response_bytes = u64::from_be_bytes(
            response[12..20]
                .try_into()
                .expect("Hysteria B 组响应字节数固定为 8 字节"),
        );
        if (response_records, response_bytes) != (sequence, bytes) {
            return Err(other_error("Hysteria B 组最终响应总量不一致"));
        }
        let _ = events.send(HysteriaTcpEvent::ExchangeComplete {
            records: sequence,
            bytes,
        });
        Ok(())
    }
    .await;

    if let Err(error) = &result {
        let _ = events.send(HysteriaTcpEvent::Failed {
            protocol: false,
            reason: format!("发送端：{error}"),
        });
    }
    result
}

async fn run_hysteria_tcp_receiver(
    mut reader: OwnedReadHalf,
    mut response_writer: OwnedWriteHalf,
    chunk_size: usize,
    seed: u8,
    events: mpsc::UnboundedSender<HysteriaTcpEvent>,
) -> LabResult<()> {
    let result: LabResult<()> = async {
        let mut expected_sequence = 0_u64;
        let mut bytes = 0_u64;
        let mut payload = vec![0_u8; chunk_size];
        loop {
            let mut header = [0_u8; HYSTERIA_SUSTAINED_HEADER_SIZE];
            reader.read_exact(&mut header).await?;
            let sequence = u64::from_be_bytes(
                header[..8]
                    .try_into()
                    .expect("Hysteria A 组记录编号固定为 8 字节"),
            );
            let expected_digest = u64::from_be_bytes(
                header[8..]
                    .try_into()
                    .expect("Hysteria A 组摘要固定为 8 字节"),
            );
            if sequence == HYSTERIA_SUSTAINED_END {
                if expected_digest != expected_sequence {
                    return Err(other_error("Hysteria A 组结束标记总记录数错误"));
                }
                let mut response = [0_u8; HYSTERIA_SUSTAINED_RESPONSE_SIZE];
                response[..4].copy_from_slice(HYSTERIA_SUSTAINED_RESPONSE_MAGIC);
                response[4..12].copy_from_slice(&expected_sequence.to_be_bytes());
                response[12..20].copy_from_slice(&bytes.to_be_bytes());
                response_writer.write_all(&response).await?;
                response_writer.shutdown().await?;
                let _ = events.send(HysteriaTcpEvent::Finished {
                    records: expected_sequence,
                    bytes,
                });
                return Ok(());
            }
            if sequence != expected_sequence {
                return Err(other_error(format!(
                    "Hysteria A 组记录编号错误：期望 {expected_sequence}，实际 {sequence}"
                )));
            }
            reader.read_exact(&mut payload).await?;
            if digest(&payload) != expected_digest
                || !hysteria_sustained_payload_is_valid(&payload, seed, sequence)
            {
                return Err(other_error(format!(
                    "Hysteria A 组记录 {sequence} 内容或摘要错误"
                )));
            }
            let _ = events.send(HysteriaTcpEvent::Record {
                sequence,
                received_at: Instant::now(),
            });
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or_else(|| other_error("Hysteria A 组接收记录编号溢出"))?;
            bytes = bytes
                .checked_add(chunk_size as u64)
                .ok_or_else(|| other_error("Hysteria A 组接收字节数溢出"))?;
        }
    }
    .await;

    if let Err(error) = &result {
        let reason = error.to_string();
        let protocol = reason.contains("编号")
            || reason.contains("内容")
            || reason.contains("摘要")
            || reason.contains("结束标记");
        let _ = events.send(HysteriaTcpEvent::Failed {
            protocol,
            reason: format!("接收端：{reason}"),
        });
    }
    result
}

fn fill_hysteria_sustained_payload(payload: &mut [u8], seed: u8, sequence: u64) {
    let sequence = sequence as u8;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add(sequence)
            .wrapping_add((index as u8).wrapping_mul(31));
    }
}

fn hysteria_sustained_payload_is_valid(payload: &[u8], seed: u8, sequence: u64) -> bool {
    let sequence = sequence as u8;
    payload.iter().enumerate().all(|(index, byte)| {
        *byte
            == seed
                .wrapping_add(sequence)
                .wrapping_add((index as u8).wrapping_mul(31))
    })
}

async fn wait_for_udp_forwarding(
    sender: &UdpSocket,
    backend: &UdpSocket,
    lab: &mut HysteriaLab,
) -> LabResult<()> {
    let ready_message = make_ready_message();
    let deadline = Instant::now() + HYSTERIA_READY_TIMEOUT;
    let mut buffer = [0_u8; HYSTERIA_REALTIME_MESSAGE_SIZE];
    while Instant::now() < deadline {
        lab.ensure_running()?;
        match sender.send(&ready_message).await {
            Ok(length) if length == ready_message.len() => {}
            Ok(_) => return Err(other_error("Hysteria UDP 就绪探针发生截断")),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                sleep(Duration::from_millis(50)).await;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        match timeout(Duration::from_millis(250), backend.recv_from(&mut buffer)).await {
            Ok(Ok((length, _))) if buffer[..length] == ready_message[..] => return Ok(()),
            Ok(Ok(_)) | Err(_) => sleep(Duration::from_millis(50)).await,
            Ok(Err(error)) => return Err(error.into()),
        }
    }
    Err(other_error(
        "Hysteria UDP 转发在 8 秒内没有通过端到端就绪探针",
    ))
}

async fn drain_udp_socket(socket: &UdpSocket) -> LabResult<()> {
    sleep(Duration::from_millis(350)).await;
    let mut buffer = [0_u8; 2_048];
    while let Ok(Ok(_)) = timeout(Duration::from_millis(10), socket.recv_from(&mut buffer)).await {}
    Ok(())
}

#[derive(Debug)]
struct HysteriaLab {
    _directory: TempDirectory,
    server: ChildGuard,
    client: ChildGuard,
    server_addr: SocketAddr,
    forward_addr: SocketAddr,
    auth: String,
}

impl HysteriaLab {
    async fn start_udp(
        config: &HysteriaRealtimeConfig,
        backend_addr: SocketAddr,
    ) -> LabResult<Self> {
        Self::start(
            &config.binary,
            config.congestion,
            config.line,
            HYSTERIA_DEFAULT_SINGLE_LINE_BANDWIDTH_MBPS,
            HysteriaForwarding::Udp(backend_addr),
        )
        .await
    }

    async fn start_tcp(
        binary: &Path,
        congestion: HysteriaCongestion,
        backend_addr: SocketAddr,
    ) -> LabResult<Self> {
        Self::start(
            binary,
            congestion,
            HysteriaLine::One,
            HYSTERIA_DEFAULT_SINGLE_LINE_BANDWIDTH_MBPS,
            HysteriaForwarding::Tcp(backend_addr),
        )
        .await
    }

    async fn start_tcp_on_line(
        binary: &Path,
        congestion: HysteriaCongestion,
        line: HysteriaLine,
        bandwidth_mbps: u32,
        backend_addr: SocketAddr,
    ) -> LabResult<Self> {
        Self::start(
            binary,
            congestion,
            line,
            bandwidth_mbps,
            HysteriaForwarding::Tcp(backend_addr),
        )
        .await
    }

    async fn start(
        binary: &Path,
        congestion: HysteriaCongestion,
        line: HysteriaLine,
        bandwidth_mbps: u32,
        forwarding: HysteriaForwarding,
    ) -> LabResult<Self> {
        let directory = TempDirectory::new()?;
        let cert_path = directory.path().join("server.crt");
        let key_path = directory.path().join("server.key");
        let cert_status = Command::new(binary)
            .arg("--disable-update-check")
            .arg("cert")
            .args(["--host", "localhost"])
            .arg("--cert")
            .arg(&cert_path)
            .arg("--key")
            .arg(&key_path)
            .arg("--overwrite")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !cert_status.success() {
            return Err(other_error("Hysteria 无法生成临时 TLS 证书"));
        }

        let auth = random_auth_token()?;
        let server_addr = reserve_udp_addr(line.server_ip())?;
        let forward_addr = match forwarding {
            HysteriaForwarding::Udp(_) => reserve_udp_addr(HYSTERIA_CLIENT_ACCESS_IP)?,
            HysteriaForwarding::Tcp(_) => reserve_tcp_addr(HYSTERIA_CLIENT_ACCESS_IP)?,
        };
        let server_config_path = directory.path().join("server.yaml");
        let client_config_path = directory.path().join("client.yaml");
        write_private(
            &server_config_path,
            &render_server_config(
                server_addr,
                &cert_path,
                &key_path,
                &auth,
                congestion,
                bandwidth_mbps,
            ),
        )?;
        let client_config = match forwarding {
            HysteriaForwarding::Udp(backend_addr) => render_client_udp_config(
                server_addr,
                forward_addr,
                backend_addr,
                &cert_path,
                &auth,
                congestion,
                bandwidth_mbps,
            ),
            HysteriaForwarding::Tcp(backend_addr) => render_client_tcp_config(
                server_addr,
                forward_addr,
                backend_addr,
                &cert_path,
                &auth,
                congestion,
                bandwidth_mbps,
            ),
        };
        write_private(&client_config_path, &client_config)?;

        let server_log = directory.path().join("server.log");
        let client_log = directory.path().join("client.log");
        let mut server = spawn_hysteria(
            binary,
            "server",
            &server_config_path,
            &server_log,
            "Hysteria 服务端",
        )?;
        sleep(Duration::from_millis(200)).await;
        server.ensure_running(&auth)?;
        let mut client = spawn_hysteria(
            binary,
            "client",
            &client_config_path,
            &client_log,
            "Hysteria 客户端",
        )?;
        sleep(Duration::from_millis(350)).await;
        client.ensure_running(&auth)?;

        Ok(Self {
            _directory: directory,
            server,
            client,
            server_addr,
            forward_addr,
            auth,
        })
    }

    fn ensure_running(&mut self) -> LabResult<()> {
        self.server.ensure_running(&self.auth)?;
        self.client.ensure_running(&self.auth)
    }

    fn processes_running(&mut self) -> LabResult<bool> {
        Ok(self.server.is_running()? && self.client.is_running()?)
    }
}

#[derive(Debug, Clone, Copy)]
enum HysteriaForwarding {
    Udp(SocketAddr),
    Tcp(SocketAddr),
}

#[derive(Debug)]
struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> LabResult<Self> {
        for _ in 0..32 {
            let id = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path =
                env::temp_dir().join(format!("flowweave-hysteria-{}-{id}", std::process::id()));
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(other_error("无法创建唯一的 Hysteria 临时目录"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct ChildGuard {
    child: Child,
    label: &'static str,
    log_path: PathBuf,
}

impl ChildGuard {
    fn is_running(&mut self) -> LabResult<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    fn ensure_running(&mut self, secret: &str) -> LabResult<()> {
        let Some(status) = self.child.try_wait()? else {
            return Ok(());
        };
        let log = fs::read_to_string(&self.log_path)
            .unwrap_or_default()
            .replace(secret, "[redacted]");
        let excerpt = log.chars().take(2_000).collect::<String>();
        Err(other_error(format!(
            "{}异常退出（{status}）：{}",
            self.label,
            excerpt.trim()
        )))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_hysteria(
    binary: &Path,
    mode: &'static str,
    config_path: &Path,
    log_path: &Path,
    label: &'static str,
) -> LabResult<ChildGuard> {
    let log = create_private_file(log_path)?;
    let child = Command::new(binary)
        .arg(mode)
        .arg("--config")
        .arg(config_path)
        .arg("--disable-update-check")
        .args(["--log-level", "warn", "--log-format", "json"])
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    Ok(ChildGuard {
        child,
        label,
        log_path: log_path.to_owned(),
    })
}

fn render_server_config(
    server_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    auth: &str,
    congestion: HysteriaCongestion,
    bandwidth_mbps: u32,
) -> String {
    let bandwidth = match congestion {
        HysteriaCongestion::Bbr => String::new(),
        HysteriaCongestion::Brutal => {
            format!("bandwidth:\n  up: {bandwidth_mbps} mbps\n  down: {bandwidth_mbps} mbps\n")
        }
    };
    format!(
        "listen: {server_addr}\n\
tls:\n  cert: '{}'\n  key: '{}'\n  sniGuard: strict\n\
congestion:\n  type: bbr\n\
{bandwidth}\
disableUDP: false\n\
udpIdleTimeout: 10s\n\
auth:\n  type: password\n  password: {auth}\n\
masquerade:\n  type: string\n  string:\n    content: flowweave benchmark\n    statusCode: 404\n",
        cert_path.display(),
        key_path.display(),
    )
}

fn render_client_udp_config(
    server_addr: SocketAddr,
    forward_addr: SocketAddr,
    backend_addr: SocketAddr,
    cert_path: &Path,
    auth: &str,
    congestion: HysteriaCongestion,
    bandwidth_mbps: u32,
) -> String {
    let bandwidth = match congestion {
        HysteriaCongestion::Bbr => String::new(),
        HysteriaCongestion::Brutal => {
            format!("bandwidth:\n  up: {bandwidth_mbps} mbps\n  down: {bandwidth_mbps} mbps\n")
        }
    };
    format!(
        "server: {server_addr}\n\
auth: {auth}\n\
tls:\n  sni: localhost\n  ca: '{}'\n\
congestion:\n  type: bbr\n\
{bandwidth}\
udpForwarding:\n  - listen: {forward_addr}\n    remote: {backend_addr}\n    timeout: 10s\n",
        cert_path.display(),
    )
}

fn render_client_tcp_config(
    server_addr: SocketAddr,
    forward_addr: SocketAddr,
    backend_addr: SocketAddr,
    cert_path: &Path,
    auth: &str,
    congestion: HysteriaCongestion,
    bandwidth_mbps: u32,
) -> String {
    let bandwidth = match congestion {
        HysteriaCongestion::Bbr => String::new(),
        HysteriaCongestion::Brutal => {
            format!("bandwidth:\n  up: {bandwidth_mbps} mbps\n  down: {bandwidth_mbps} mbps\n")
        }
    };
    format!(
        "server: {server_addr}\n\
auth: {auth}\n\
tls:\n  sni: localhost\n  ca: '{}'\n\
congestion:\n  type: bbr\n\
{bandwidth}\
tcpForwarding:\n  - listen: {forward_addr}\n    remote: {backend_addr}\n",
        cert_path.display(),
    )
}

fn random_auth_token() -> LabResult<String> {
    let mut random = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut token = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(token)
}

fn reserve_udp_addr(ip: Ipv4Addr) -> LabResult<SocketAddr> {
    let socket = StdUdpSocket::bind(SocketAddr::new(IpAddr::V4(ip), 0))?;
    Ok(socket.local_addr()?)
}

fn reserve_tcp_addr(ip: Ipv4Addr) -> LabResult<SocketAddr> {
    let listener = StdTcpListener::bind(SocketAddr::new(IpAddr::V4(ip), 0))?;
    Ok(listener.local_addr()?)
}

fn write_private(path: &Path, contents: &str) -> LabResult<()> {
    let mut file = create_private_file(path)?;
    file.write_all(contents.as_bytes())?;
    file.flush()?;
    Ok(())
}

fn create_private_file(path: &Path) -> LabResult<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[derive(Debug, Clone, Copy, Default)]
struct NftCounter {
    packets: u64,
    ipv4_bytes: u64,
}

impl NftCounter {
    fn saturating_sub(self, before: Self) -> Self {
        Self {
            packets: self.packets.saturating_sub(before.packets),
            ipv4_bytes: self.ipv4_bytes.saturating_sub(before.ipv4_bytes),
        }
    }

    fn udp_payload_bytes(self) -> u64 {
        self.ipv4_bytes
            .saturating_sub(self.packets.saturating_mul(IPV4_UDP_HEADER_SIZE))
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct NftSnapshot {
    line_one: NftCounter,
    line_two: NftCounter,
    server_line_one: NftCounter,
    server_line_two: NftCounter,
}

impl NftSnapshot {
    fn saturating_sub(self, before: Self) -> Self {
        Self {
            line_one: self.line_one.saturating_sub(before.line_one),
            line_two: self.line_two.saturating_sub(before.line_two),
            server_line_one: self.server_line_one.saturating_sub(before.server_line_one),
            server_line_two: self.server_line_two.saturating_sub(before.server_line_two),
        }
    }
}

#[derive(Debug)]
struct NftClientCounters {
    table: String,
}

impl NftClientCounters {
    fn new(server_port: u16) -> LabResult<Self> {
        let id = NEXT_NFT_TABLE.fetch_add(1, Ordering::Relaxed);
        let table = format!("fwhy{:x}{id:x}", std::process::id());
        run_nft(&["add", "table", "ip", &table])?;
        let setup = (|| -> LabResult<()> {
            run_nft(&[
                "add",
                "chain",
                "ip",
                &table,
                "output",
                "{ type filter hook output priority -100; policy accept; }",
            ])?;
            let port = server_port.to_string();
            add_nft_client_counter_rule(&table, HYSTERIA_LINE_ONE_IP, &port, "line_one")?;
            add_nft_client_counter_rule(&table, HYSTERIA_LINE_TWO_IP, &port, "line_two")?;
            add_nft_server_counter_rule(&table, HYSTERIA_LINE_ONE_IP, &port, "server_line_one")?;
            add_nft_server_counter_rule(&table, HYSTERIA_LINE_TWO_IP, &port, "server_line_two")
        })();
        if let Err(error) = setup {
            let _ = run_nft(&["delete", "table", "ip", &table]);
            return Err(error);
        }
        Ok(Self { table })
    }

    fn snapshot(&self) -> LabResult<NftSnapshot> {
        let output = Command::new("nft")
            .args(["list", "chain", "ip", &self.table, "output"])
            .output()?;
        if !output.status.success() {
            return Err(other_error(format!(
                "无法读取 Hysteria nft 计数器：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(NftSnapshot {
            line_one: parse_nft_counter(&text, "line_one")?,
            line_two: parse_nft_counter(&text, "line_two")?,
            server_line_one: parse_nft_counter(&text, "server_line_one")?,
            server_line_two: parse_nft_counter(&text, "server_line_two")?,
        })
    }
}

impl Drop for NftClientCounters {
    fn drop(&mut self) {
        let _ = run_nft(&["delete", "table", "ip", &self.table]);
    }
}

fn add_nft_client_counter_rule(
    table: &str,
    destination: Ipv4Addr,
    port: &str,
    label: &str,
) -> LabResult<()> {
    run_nft(&[
        "add",
        "rule",
        "ip",
        table,
        "output",
        "ip",
        "daddr",
        &destination.to_string(),
        "udp",
        "dport",
        port,
        "counter",
        "comment",
        label,
    ])
}

fn add_nft_server_counter_rule(
    table: &str,
    source: Ipv4Addr,
    port: &str,
    label: &str,
) -> LabResult<()> {
    run_nft(&[
        "add",
        "rule",
        "ip",
        table,
        "output",
        "ip",
        "saddr",
        &source.to_string(),
        "udp",
        "sport",
        port,
        "counter",
        "comment",
        label,
    ])
}

fn parse_nft_counter(text: &str, label: &str) -> LabResult<NftCounter> {
    let marker = format!("comment \"{label}\"");
    let line = text
        .lines()
        .find(|line| line.contains(&marker))
        .ok_or_else(|| other_error(format!("找不到 Hysteria nft 计数器 {label}")))?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let packets = value_after(&fields, "packets")?;
    let ipv4_bytes = value_after(&fields, "bytes")?;
    Ok(NftCounter {
        packets,
        ipv4_bytes,
    })
}

fn value_after(fields: &[&str], key: &str) -> LabResult<u64> {
    let index = fields
        .iter()
        .position(|field| *field == key)
        .ok_or_else(|| other_error(format!("nft 计数器缺少 {key} 字段")))?;
    fields
        .get(index + 1)
        .ok_or_else(|| other_error(format!("nft 计数器 {key} 字段没有值")))?
        .parse()
        .map_err(|_| other_error(format!("nft 计数器 {key} 字段不是整数")))
}

fn run_nft(arguments: &[&str]) -> LabResult<()> {
    let output = Command::new("nft").args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(other_error(format!(
        "nft 命令失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteria_realtime_message_roundtrip_is_exactly_200_bytes() {
        let message = make_hysteria_realtime_message(17);
        assert_eq!(message.len(), HYSTERIA_REALTIME_MESSAGE_SIZE);
        let mut accounting = HysteriaReceiveAccounting::new(18);
        assert_eq!(
            decode_hysteria_realtime_message(&message, &mut accounting),
            Some(17)
        );
        assert_eq!(accounting.malformed_messages, 0);
        assert_eq!(accounting.digest_error_messages, 0);
        assert_eq!(accounting.content_error_messages, 0);
    }

    #[test]
    fn hysteria_client_config_requires_exact_tls_validation() {
        let config = render_client_udp_config(
            "127.0.0.1:8443".parse().unwrap(),
            "127.0.0.3:9000".parse().unwrap(),
            "127.0.0.4:9001".parse().unwrap(),
            Path::new("/tmp/flowweave-test.crt"),
            "runtime-only-token",
            HysteriaCongestion::Bbr,
            HYSTERIA_DEFAULT_SINGLE_LINE_BANDWIDTH_MBPS,
        );
        assert!(config.contains("sni: localhost"));
        assert!(config.contains("ca: '/tmp/flowweave-test.crt'"));
        assert!(!config.contains("insecure"));
        assert!(!config.contains("obfs"));
    }

    #[test]
    fn hysteria_brutal_config_uses_the_locked_real_bandwidth() {
        let config = render_server_config(
            "127.0.0.1:8443".parse().unwrap(),
            Path::new("/tmp/server.crt"),
            Path::new("/tmp/server.key"),
            "runtime-only-token",
            HysteriaCongestion::Brutal,
            25,
        );
        assert!(config.contains("up: 25 mbps"));
        assert!(config.contains("down: 25 mbps"));
    }

    #[test]
    fn hysteria_throughput_config_rejects_invalid_bandwidth_and_window() {
        let invalid_bandwidth = HysteriaThroughputConfig::new(
            "/tmp/hysteria",
            HysteriaCongestion::Brutal,
            HysteriaLine::One,
            0,
            Duration::from_secs(2),
            Duration::from_secs(20),
            16 * 1024,
        );
        assert!(invalid_bandwidth.validate().is_err());

        let invalid_measurement = HysteriaThroughputConfig::new(
            "/tmp/hysteria",
            HysteriaCongestion::Bbr,
            HysteriaLine::Two,
            25,
            Duration::from_secs(2),
            Duration::ZERO,
            16 * 1024,
        );
        assert!(invalid_measurement.validate().is_err());
    }

    #[tokio::test]
    async fn hysteria_throughput_events_and_half_open_window_close_exactly() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let started = Instant::now();
        let ended = started + Duration::from_millis(100);
        let timestamps = [
            started - Duration::from_nanos(1),
            started,
            started + Duration::from_millis(50),
            ended,
        ];
        for (sequence, received_at) in timestamps.into_iter().enumerate() {
            tx.send(HysteriaTcpEvent::Record {
                sequence: sequence as u64,
                received_at,
            })
            .unwrap();
        }
        tx.send(HysteriaTcpEvent::Finished {
            records: 4,
            bytes: 4 * 16 * 1024,
        })
        .unwrap();
        tx.send(HysteriaTcpEvent::ExchangeComplete {
            records: 4,
            bytes: 4 * 16 * 1024,
        })
        .unwrap();
        drop(tx);

        let trace = collect_hysteria_throughput_events(&mut rx, 16 * 1024)
            .await
            .expect("完整事件应闭合");
        assert_eq!(trace.records, 4);
        assert_eq!(
            count_hysteria_records_in_window(&trace.received_at, started, ended)
                .expect("合法半开窗口应能计数"),
            2
        );
        assert!(count_hysteria_records_in_window(&trace.received_at, ended, started).is_err());
    }

    #[test]
    fn nft_counter_parser_reads_named_rules() {
        let text = r#"
table ip fwhy1 {
    chain output {
        ip daddr 127.0.0.1 udp dport 8443 counter packets 19 bytes 23000 comment "line_one"
        ip daddr 127.0.0.2 udp dport 8443 counter packets 0 bytes 0 comment "line_two"
    }
}
"#;
        assert_eq!(parse_nft_counter(text, "line_one").unwrap().packets, 19);
        assert_eq!(
            parse_nft_counter(text, "line_one")
                .unwrap()
                .udp_payload_bytes(),
            23_000 - 19 * IPV4_UDP_HEADER_SIZE
        );
        assert_eq!(parse_nft_counter(text, "line_two").unwrap().packets, 0);
    }
}

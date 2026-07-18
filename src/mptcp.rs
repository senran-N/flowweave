use std::{
    fs, io,
    mem::{size_of, zeroed},
    net::{Ipv4Addr, SocketAddrV4, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::{Instant as TokioInstant, sleep, sleep_until, timeout},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    client::TlsStream as ClientTlsStream,
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    },
    server::TlsStream as ServerTlsStream,
};

use crate::{FailoverDirection, LabError, LabResult, digest, other_error, throughput_mbps};

const IPPROTO_MPTCP: libc::c_int = 262;
const SOL_MPTCP: libc::c_int = 284;
const MPTCP_INFO: libc::c_int = 1;
const MPTCP_INFO_FLAG_FALLBACK: u32 = 1 << 0;
const MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED: u32 = 1 << 1;
const MIN_MPTCP_INFO_WITH_SUBFLOW_TOTAL: usize = 81;
const MPTCP_SERVER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const MPTCP_LINE_ONE_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const MPTCP_LINE_TWO_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
const MPTCP_TLS_ALPN: &[u8] = b"flowweave-mptcp-benchmark/1";
const MPTCP_READY_MAGIC: &[u8; 4] = b"MPT+";
const MPTCP_RESPONSE_MAGIC: &[u8; 4] = b"MPT=";
const MPTCP_RECORD_HEADER_SIZE: usize = 16;
const MPTCP_RESPONSE_SIZE: usize = 20;
const MPTCP_RECORD_END: u64 = u64::MAX;
const MPTCP_READY_TIMEOUT: Duration = Duration::from_secs(8);
const MPTCP_SUBFLOW_TIMEOUT: Duration = Duration::from_secs(5);
const MPTCP_FAILOVER_COMPLETION_GRACE: Duration = Duration::from_secs(2);
const MPTCP_THROUGHPUT_COMPLETION_GRACE: Duration = Duration::from_secs(30);
const MPTCP_MAX_FAILOVER_DURATION: Duration = Duration::from_secs(120);
const MPTCP_MAX_MEASUREMENT_DURATION: Duration = Duration::from_secs(120);

static NEXT_NFT_TABLE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MptcpPathMode {
    LineOneOnly,
    LineTwoOnly,
    Multipath,
}

impl MptcpPathMode {
    pub const ALL: [Self; 3] = [Self::LineOneOnly, Self::LineTwoOnly, Self::Multipath];

    pub const fn description(self) -> &'static str {
        match self {
            Self::LineOneOnly => "MPTCP 仅线路一",
            Self::LineTwoOnly => "MPTCP 仅线路二",
            Self::Multipath => "MPTCP 默认双路",
        }
    }

    const fn client_ip(self) -> Ipv4Addr {
        match self {
            Self::LineOneOnly | Self::Multipath => MPTCP_LINE_ONE_CLIENT_IP,
            Self::LineTwoOnly => MPTCP_LINE_TWO_CLIENT_IP,
        }
    }

    const fn expected_subflows(self) -> u8 {
        match self {
            Self::LineOneOnly | Self::LineTwoOnly => 1,
            Self::Multipath => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MptcpRuntimeIdentity {
    pub kernel_release: String,
    pub iproute2_version: String,
    pub path_manager: String,
    pub scheduler: String,
    pub congestion_control: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MptcpInfoSnapshot {
    pub extra_subflows: u8,
    pub subflows_total: u8,
    pub fallback: bool,
    pub remote_key_received: bool,
    pub retransmits: u32,
    pub bytes_retransmitted: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_acked: u64,
}

impl MptcpInfoSnapshot {
    pub const fn negotiated(self) -> bool {
        !self.fallback && self.remote_key_received && self.subflows_total > 0
    }
}

#[derive(Debug, Clone)]
pub struct MptcpThroughputConfig {
    pub mode: MptcpPathMode,
    pub warmup_duration: Duration,
    pub measurement_duration: Duration,
    pub chunk_size: usize,
    pub seed: u8,
}

impl MptcpThroughputConfig {
    pub const fn new(
        mode: MptcpPathMode,
        warmup_duration: Duration,
        measurement_duration: Duration,
        chunk_size: usize,
        seed: u8,
    ) -> Self {
        Self {
            mode,
            warmup_duration,
            measurement_duration,
            chunk_size,
            seed,
        }
    }

    fn validate(&self) -> LabResult<()> {
        if self.warmup_duration.is_zero()
            || self.measurement_duration.is_zero()
            || self.measurement_duration > MPTCP_MAX_MEASUREMENT_DURATION
        {
            return Err(other_error(
                "MPTCP B 组预热和测量时长必须为正，测量不得超过 120 秒",
            ));
        }
        validate_chunk_size(self.chunk_size, "MPTCP B 组")
    }
}

#[derive(Debug, Clone)]
pub struct MptcpThroughputReport {
    pub runtime: MptcpRuntimeIdentity,
    pub mode: MptcpPathMode,
    pub warmup_duration: Duration,
    pub measurement_duration: Duration,
    pub measurement_elapsed: Duration,
    pub chunk_size: usize,
    pub tls13_exact: bool,
    pub strict_certificate_validation: bool,
    pub info_at_start: MptcpInfoSnapshot,
    pub info_at_end: MptcpInfoSnapshot,
    pub line_one_packets_before_workload: u64,
    pub line_two_packets_before_workload: u64,
    pub data_intact: bool,
    pub exchange_complete: bool,
    pub writer_alive_at_measurement_start: bool,
    pub writer_alive_at_measurement_end: bool,
    pub records_received_in_window: u64,
    pub application_bytes_received_in_window: u64,
    pub throughput_mbps: f64,
    pub total_records_received: u64,
    pub total_application_bytes_received: u64,
    pub client_line_one_ipv4_bytes: u64,
    pub client_line_two_ipv4_bytes: u64,
    pub server_line_one_ipv4_bytes: u64,
    pub server_line_two_ipv4_bytes: u64,
    pub client_line_one_packets: u64,
    pub client_line_two_packets: u64,
    pub server_line_one_packets: u64,
    pub server_line_two_packets: u64,
}

impl MptcpThroughputReport {
    pub const fn line_one_ipv4_bytes(&self) -> u64 {
        self.client_line_one_ipv4_bytes
            .saturating_add(self.server_line_one_ipv4_bytes)
    }

    pub const fn line_two_ipv4_bytes(&self) -> u64 {
        self.client_line_two_ipv4_bytes
            .saturating_add(self.server_line_two_ipv4_bytes)
    }

    pub const fn total_ipv4_bytes(&self) -> u64 {
        self.line_one_ipv4_bytes()
            .saturating_add(self.line_two_ipv4_bytes())
    }

    pub fn ipv4_wire_ratio(&self) -> f64 {
        if self.application_bytes_received_in_window == 0 {
            return 0.0;
        }
        self.total_ipv4_bytes() as f64 / self.application_bytes_received_in_window as f64
    }

    pub fn line_one_share_percent(&self) -> f64 {
        percentage(self.line_one_ipv4_bytes(), self.total_ipv4_bytes())
    }

    pub fn line_two_share_percent(&self) -> f64 {
        percentage(self.line_two_ipv4_bytes(), self.total_ipv4_bytes())
    }

    pub fn infrastructure_pass(&self) -> bool {
        let expected_subflows = self.mode.expected_subflows();
        let subflows_match = self.info_at_start.subflows_total == expected_subflows
            && self.info_at_end.subflows_total == expected_subflows;
        let wiring_match = match self.mode {
            MptcpPathMode::LineOneOnly => {
                self.line_one_packets_before_workload > 0
                    && self.line_two_packets_before_workload == 0
                    && self.line_one_ipv4_bytes() > 0
                    && self.line_two_ipv4_bytes() == 0
            }
            MptcpPathMode::LineTwoOnly => {
                self.line_two_packets_before_workload > 0
                    && self.line_one_packets_before_workload == 0
                    && self.line_two_ipv4_bytes() > 0
                    && self.line_one_ipv4_bytes() == 0
            }
            MptcpPathMode::Multipath => {
                self.line_one_packets_before_workload > 0
                    && self.line_two_packets_before_workload > 0
                    && self.line_one_ipv4_bytes() > 0
            }
        };
        self.tls13_exact
            && self.strict_certificate_validation
            && self.info_at_start.negotiated()
            && self.info_at_end.negotiated()
            && subflows_match
            && wiring_match
            && self.data_intact
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
    }
}

#[derive(Debug, Clone)]
pub struct MptcpFailoverConfig {
    pub direction: FailoverDirection,
    pub total_duration: Duration,
    pub failure_after: Duration,
    pub chunk_size: usize,
    pub seed: u8,
}

impl MptcpFailoverConfig {
    pub const fn new(
        direction: FailoverDirection,
        total_duration: Duration,
        failure_after: Duration,
        chunk_size: usize,
        seed: u8,
    ) -> Self {
        Self {
            direction,
            total_duration,
            failure_after,
            chunk_size,
            seed,
        }
    }

    fn validate(&self) -> LabResult<()> {
        if self.total_duration.is_zero() || self.total_duration > MPTCP_MAX_FAILOVER_DURATION {
            return Err(other_error("MPTCP A 组总时长必须为正且不得超过 120 秒"));
        }
        if self.failure_after.is_zero() || self.failure_after >= self.total_duration {
            return Err(other_error("MPTCP A 组故障时刻必须位于业务窗口内部"));
        }
        validate_chunk_size(self.chunk_size, "MPTCP A 组")
    }
}

#[derive(Debug, Clone)]
pub struct MptcpFailoverReport {
    pub runtime: MptcpRuntimeIdentity,
    pub direction: FailoverDirection,
    pub total_duration: Duration,
    pub failure_after: Duration,
    pub tls13_exact: bool,
    pub strict_certificate_validation: bool,
    pub info_before_failure: MptcpInfoSnapshot,
    pub info_after_run: MptcpInfoSnapshot,
    pub line_one_packets_before_failure: u64,
    pub line_two_packets_before_failure: u64,
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
    pub client_line_one_ipv4_bytes_after_failure: u64,
    pub client_line_two_ipv4_bytes_after_failure: u64,
    pub server_line_one_ipv4_bytes_after_failure: u64,
    pub server_line_two_ipv4_bytes_after_failure: u64,
    pub client_line_one_packets_after_failure: u64,
    pub client_line_two_packets_after_failure: u64,
    pub server_line_one_packets_after_failure: u64,
    pub server_line_two_packets_after_failure: u64,
}

impl MptcpFailoverReport {
    pub const fn line_one_ipv4_bytes_after_failure(&self) -> u64 {
        self.client_line_one_ipv4_bytes_after_failure
            .saturating_add(self.server_line_one_ipv4_bytes_after_failure)
    }

    pub const fn line_two_ipv4_bytes_after_failure(&self) -> u64 {
        self.client_line_two_ipv4_bytes_after_failure
            .saturating_add(self.server_line_two_ipv4_bytes_after_failure)
    }

    pub fn infrastructure_pass(&self) -> bool {
        self.tls13_exact
            && self.strict_certificate_validation
            && self.info_before_failure.negotiated()
            && self.info_before_failure.subflows_total == 2
            && self.info_after_run.negotiated()
            && self.info_after_run.subflows_total == 2
            && self.line_one_packets_before_failure > 0
            && self.line_two_packets_before_failure > 0
            && self.records_before_failure > 0
            && self.protocol_error.is_none()
    }
}

pub async fn run_mptcp_throughput(
    config: MptcpThroughputConfig,
) -> LabResult<MptcpThroughputReport> {
    config.validate()?;
    let runtime = verify_mptcp_runtime()?;
    configure_mptcp_path_manager(config.mode)?;
    let RunningMptcpPair {
        client,
        server,
        listener_guard,
        client_info_fd,
        counters,
        tls13_exact,
        info_after_ready,
        counters_after_ready,
    } = start_mptcp_tls_pair(config.mode).await?;

    let (client_read, client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (started_tx, started_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let sender_events = events_tx.clone();
    let receiver_events = events_tx.clone();
    drop(events_tx);
    let mut sender_task = tokio::spawn(run_continuous_sender(
        client_read,
        client_write,
        stop_rx,
        config.chunk_size,
        config.seed,
        started_tx,
        sender_events,
    ));
    let mut receiver_task = tokio::spawn(run_receiver(
        server_read,
        server_write,
        config.chunk_size,
        config.seed,
        receiver_events,
    ));

    let operation_result: LabResult<MptcpThroughputReport> = async {
        let started_at = timeout(MPTCP_READY_TIMEOUT, started_rx)
            .await
            .map_err(|_| other_error("MPTCP B 组业务 sender 没有按时启动"))?
            .map_err(|_| other_error("MPTCP B 组业务 sender 提前退出"))?;
        sleep_until(TokioInstant::from_std(started_at + config.warmup_duration)).await;
        let writer_alive_at_measurement_start = !sender_task.is_finished();
        if !writer_alive_at_measurement_start {
            return Err(other_error("MPTCP B 组 writer 在测量前意外完成"));
        }

        let info_at_start = mptcp_info(client_info_fd.as_raw_fd())?;
        let counters_before = counters.snapshot()?;
        let measurement_started = Instant::now();
        sleep_until(TokioInstant::from_std(
            measurement_started + config.measurement_duration,
        ))
        .await;
        let measurement_ended = Instant::now();
        let measurement_elapsed = measurement_ended.saturating_duration_since(measurement_started);
        let info_at_end = mptcp_info(client_info_fd.as_raw_fd())?;
        let counters_after = counters.snapshot()?;
        let writer_alive_at_measurement_end = !sender_task.is_finished();
        let _ = stop_tx.send(());

        let sender_result = timeout(MPTCP_THROUGHPUT_COMPLETION_GRACE, &mut sender_task).await;
        if sender_result.is_err() {
            sender_task.abort();
            receiver_task.abort();
            return Err(other_error("MPTCP B 组持续 sender 完整收尾超时"));
        }
        sender_result
            .expect("checked timeout result")
            .map_err(|error| other_error(format!("MPTCP B 组 sender task 异常：{error}")))??;
        timeout(MPTCP_THROUGHPUT_COMPLETION_GRACE, &mut receiver_task)
            .await
            .map_err(|_| {
                receiver_task.abort();
                other_error("MPTCP B 组持续 receiver 完整收尾超时")
            })?
            .map_err(|error| other_error(format!("MPTCP B 组 receiver task 异常：{error}")))??;

        let trace = collect_throughput_events(&mut events_rx, config.chunk_size).await?;
        let records_received_in_window =
            count_records_in_window(&trace.received_at, measurement_started, measurement_ended)?;
        let application_bytes_received_in_window = records_received_in_window
            .checked_mul(config.chunk_size as u64)
            .ok_or_else(|| other_error("MPTCP B 组测量窗口业务字节数溢出"))?;
        let throughput_size = usize::try_from(application_bytes_received_in_window)
            .map_err(|_| other_error("MPTCP B 组测量窗口业务字节数超出平台范围"))?;
        let delta = counters_after.saturating_sub(counters_before);

        Ok(MptcpThroughputReport {
            runtime,
            mode: config.mode,
            warmup_duration: config.warmup_duration,
            measurement_duration: config.measurement_duration,
            measurement_elapsed,
            chunk_size: config.chunk_size,
            tls13_exact,
            strict_certificate_validation: true,
            info_at_start,
            info_at_end,
            line_one_packets_before_workload: counters_after_ready.line_one_packets(),
            line_two_packets_before_workload: counters_after_ready.line_two_packets(),
            data_intact: true,
            exchange_complete: true,
            writer_alive_at_measurement_start,
            writer_alive_at_measurement_end,
            records_received_in_window,
            application_bytes_received_in_window,
            throughput_mbps: throughput_mbps(throughput_size, measurement_elapsed),
            total_records_received: trace.records,
            total_application_bytes_received: trace.bytes,
            client_line_one_ipv4_bytes: delta.client_line_one.ipv4_bytes,
            client_line_two_ipv4_bytes: delta.client_line_two.ipv4_bytes,
            server_line_one_ipv4_bytes: delta.server_line_one.ipv4_bytes,
            server_line_two_ipv4_bytes: delta.server_line_two.ipv4_bytes,
            client_line_one_packets: delta.client_line_one.packets,
            client_line_two_packets: delta.client_line_two.packets,
            server_line_one_packets: delta.server_line_one.packets,
            server_line_two_packets: delta.server_line_two.packets,
        })
    }
    .await;

    if !sender_task.is_finished() {
        sender_task.abort();
    }
    if !receiver_task.is_finished() {
        receiver_task.abort();
    }
    let _ = info_after_ready;
    drop(listener_guard);
    operation_result
}

pub async fn run_mptcp_failover<Activate, Restore>(
    config: MptcpFailoverConfig,
    activate_blackhole: Activate,
    restore_network: Restore,
) -> LabResult<MptcpFailoverReport>
where
    Activate: FnOnce() -> LabResult<()>,
    Restore: FnOnce() -> LabResult<()>,
{
    config.validate()?;
    let runtime = verify_mptcp_runtime()?;
    configure_mptcp_path_manager(MptcpPathMode::Multipath)?;
    let RunningMptcpPair {
        client,
        server,
        listener_guard,
        client_info_fd,
        counters,
        tls13_exact,
        info_after_ready,
        counters_after_ready,
    } = start_mptcp_tls_pair(MptcpPathMode::Multipath).await?;

    let operation_result = match config.direction {
        FailoverDirection::ClientToServer => {
            run_failover_over_streams(
                client,
                server,
                &client_info_fd,
                &counters,
                runtime,
                tls13_exact,
                info_after_ready,
                counters_after_ready,
                config,
                activate_blackhole,
            )
            .await
        }
        FailoverDirection::ServerToClient => {
            run_failover_over_streams(
                server,
                client,
                &client_info_fd,
                &counters,
                runtime,
                tls13_exact,
                info_after_ready,
                counters_after_ready,
                config,
                activate_blackhole,
            )
            .await
        }
    };

    let restore_result = restore_network();
    drop(listener_guard);
    let report = operation_result?;
    restore_result?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn run_failover_over_streams<Sender, Receiver, Activate>(
    sender: Sender,
    receiver: Receiver,
    info_fd: &OwnedFd,
    counters: &MptcpNftCounters,
    runtime: MptcpRuntimeIdentity,
    tls13_exact: bool,
    info_after_ready: MptcpInfoSnapshot,
    _counters_after_ready: MptcpCounterSnapshot,
    config: MptcpFailoverConfig,
    activate_blackhole: Activate,
) -> LabResult<MptcpFailoverReport>
where
    Sender: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Receiver: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Activate: FnOnce() -> LabResult<()>,
{
    let (sender_read, sender_write) = tokio::io::split(sender);
    let (receiver_read, receiver_write) = tokio::io::split(receiver);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (started_tx, started_rx) = oneshot::channel();
    let sender_events = events_tx.clone();
    let receiver_events = events_tx.clone();
    drop(events_tx);
    let sender_task = tokio::spawn(run_timed_sender(
        sender_read,
        sender_write,
        config.total_duration,
        config.chunk_size,
        config.seed,
        started_tx,
        sender_events,
    ));
    let receiver_task = tokio::spawn(run_receiver(
        receiver_read,
        receiver_write,
        config.chunk_size,
        config.seed,
        receiver_events,
    ));

    let started_at = timeout(MPTCP_READY_TIMEOUT, started_rx)
        .await
        .map_err(|_| other_error("MPTCP A 组业务 sender 没有按时启动"))?
        .map_err(|_| other_error("MPTCP A 组业务 sender 提前退出"))?;
    sleep_until(TokioInstant::from_std(started_at + config.failure_after)).await;
    let counters_at_failure = counters.snapshot()?;
    let info_before_failure = mptcp_info(info_fd.as_raw_fd())?;
    activate_blackhole()?;
    let failure_started = Instant::now();
    let deadline = started_at + config.total_duration + MPTCP_FAILOVER_COMPLETION_GRACE;
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
            Ok(Some(MptcpStreamEvent::Record {
                sequence,
                received_at: timestamp,
            })) => {
                if sequence != records_received {
                    protocol_error.get_or_insert_with(|| {
                        format!("MPTCP A 组事件序号错误：期望 {records_received}，实际 {sequence}")
                    });
                } else {
                    records_received = records_received.saturating_add(1);
                    application_bytes_received =
                        application_bytes_received.saturating_add(config.chunk_size as u64);
                    received_at.push(timestamp);
                }
            }
            Ok(Some(MptcpStreamEvent::Finished { records, bytes })) => {
                receiver_finished = records == records_received
                    && bytes == application_bytes_received
                    && protocol_error.is_none();
                if !receiver_finished {
                    protocol_error
                        .get_or_insert_with(|| "MPTCP A 组完成事件与逐记录计数不一致".to_owned());
                }
            }
            Ok(Some(MptcpStreamEvent::ExchangeComplete { records, bytes })) => {
                exchange_complete = records == records_received
                    && bytes == application_bytes_received
                    && protocol_error.is_none();
                if !exchange_complete {
                    protocol_error
                        .get_or_insert_with(|| "MPTCP A 组最终响应与逐记录计数不一致".to_owned());
                }
            }
            Ok(Some(MptcpStreamEvent::Failed { protocol, reason })) => {
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
    collect_task_result(&mut task_failure, "发送端", sender_task.await);
    collect_task_result(&mut task_failure, "接收端", receiver_task.await);

    let counters_after = counters.snapshot()?;
    let counter_delta = counters_after.saturating_sub(counters_at_failure);
    let info_after_run = mptcp_info(info_fd.as_raw_fd()).unwrap_or(info_after_ready);
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
    let continuity_pass = recovered_after_failure && data_intact && exchange_complete;
    let failure_reason = if continuity_pass {
        None
    } else if let Some(error) = protocol_error.as_ref() {
        Some(format!("业务数据校验失败：{error}"))
    } else if let Some(error) = task_failure.as_ref() {
        Some(error.clone())
    } else if !recovered_after_failure {
        Some("故障后的业务数据没有在原 MPTCP meta socket 上恢复".to_owned())
    } else if !data_intact {
        Some("故障后虽有数据到达，但 30 秒业务没有完整闭合".to_owned())
    } else if !exchange_complete {
        Some("业务数据完整，但最终反向校验响应没有闭合".to_owned())
    } else {
        Some("MPTCP A 组未满足连续性合同".to_owned())
    };

    Ok(MptcpFailoverReport {
        runtime,
        direction: config.direction,
        total_duration: config.total_duration,
        failure_after: config.failure_after,
        tls13_exact,
        strict_certificate_validation: true,
        info_before_failure,
        info_after_run,
        line_one_packets_before_failure: counters_at_failure.line_one_packets(),
        line_two_packets_before_failure: counters_at_failure.line_two_packets(),
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
        client_line_one_ipv4_bytes_after_failure: counter_delta.client_line_one.ipv4_bytes,
        client_line_two_ipv4_bytes_after_failure: counter_delta.client_line_two.ipv4_bytes,
        server_line_one_ipv4_bytes_after_failure: counter_delta.server_line_one.ipv4_bytes,
        server_line_two_ipv4_bytes_after_failure: counter_delta.server_line_two.ipv4_bytes,
        client_line_one_packets_after_failure: counter_delta.client_line_one.packets,
        client_line_two_packets_after_failure: counter_delta.client_line_two.packets,
        server_line_one_packets_after_failure: counter_delta.server_line_one.packets,
        server_line_two_packets_after_failure: counter_delta.server_line_two.packets,
    })
}

struct RunningMptcpPair {
    client: ClientTlsStream<TcpStream>,
    server: ServerTlsStream<TcpStream>,
    listener_guard: Arc<TcpListener>,
    client_info_fd: OwnedFd,
    counters: MptcpNftCounters,
    tls13_exact: bool,
    info_after_ready: MptcpInfoSnapshot,
    counters_after_ready: MptcpCounterSnapshot,
}

async fn start_mptcp_tls_pair(mode: MptcpPathMode) -> LabResult<RunningMptcpPair> {
    let listener = Arc::new(create_mptcp_listener(SocketAddrV4::new(
        MPTCP_SERVER_IP,
        0,
    ))?);
    let server_port = listener.local_addr()?.port();
    let counters = MptcpNftCounters::new(server_port)?;
    let (server_config, client_config) = make_tls_configs()?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let accepting_listener = listener.clone();
    let server_task = tokio::spawn(async move {
        let (stream, _) = timeout(MPTCP_READY_TIMEOUT, accepting_listener.accept())
            .await
            .map_err(|_| other_error("MPTCP 服务端没有按时接受连接"))??;
        stream.set_nodelay(true)?;
        let tls = timeout(MPTCP_READY_TIMEOUT, acceptor.accept(stream))
            .await
            .map_err(|_| other_error("MPTCP 服务端 TLS 1.3 握手超时"))??;
        Ok::<_, LabError>(tls)
    });

    let client_tcp = connect_mptcp(
        SocketAddrV4::new(mode.client_ip(), 0),
        SocketAddrV4::new(MPTCP_SERVER_IP, server_port),
    )
    .await?;
    client_tcp.set_nodelay(true)?;
    let client_info_fd = duplicate_fd(client_tcp.as_raw_fd())?;
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost".to_owned())?;
    let mut client = timeout(
        MPTCP_READY_TIMEOUT,
        connector.connect(server_name, client_tcp),
    )
    .await
    .map_err(|_| other_error("MPTCP 客户端 TLS 1.3 握手超时"))??;
    let mut server = timeout(MPTCP_READY_TIMEOUT, server_task)
        .await
        .map_err(|_| other_error("MPTCP 服务端 TLS 任务超时"))?
        .map_err(|error| other_error(format!("MPTCP 服务端 TLS 任务异常：{error}")))??;

    client.write_all(MPTCP_READY_MAGIC).await?;
    let mut ready = [0_u8; MPTCP_READY_MAGIC.len()];
    server.read_exact(&mut ready).await?;
    if ready != *MPTCP_READY_MAGIC {
        return Err(other_error("MPTCP TLS 就绪请求内容错误"));
    }
    server.write_all(MPTCP_READY_MAGIC).await?;
    client.read_exact(&mut ready).await?;
    if ready != *MPTCP_READY_MAGIC {
        return Err(other_error("MPTCP TLS 就绪响应内容错误"));
    }

    let tls13_exact = client.get_ref().1.protocol_version()
        == Some(rustls::ProtocolVersion::TLSv1_3)
        && server.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
        && client.get_ref().1.alpn_protocol() == Some(MPTCP_TLS_ALPN)
        && server.get_ref().1.alpn_protocol() == Some(MPTCP_TLS_ALPN);
    if !tls13_exact {
        return Err(other_error("MPTCP 对照没有协商精确 TLS 1.3/固定 ALPN"));
    }

    let info_after_ready =
        wait_for_subflows(client_info_fd.as_raw_fd(), mode.expected_subflows()).await?;
    let counters_after_ready = counters.snapshot()?;
    Ok(RunningMptcpPair {
        client,
        server,
        listener_guard: listener,
        client_info_fd,
        counters,
        tls13_exact,
        info_after_ready,
        counters_after_ready,
    })
}

fn make_tls_configs() -> LabResult<(rustls::ServerConfig, rustls::ClientConfig)> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = CertificateDer::from(generated.cert);
    let private_key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], PrivateKeyDer::Pkcs8(private_key))?;
    server.alpn_protocols = vec![MPTCP_TLS_ALPN.to_vec()];
    server.max_early_data_size = 0;

    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![MPTCP_TLS_ALPN.to_vec()];
    client.enable_early_data = false;
    Ok((server, client))
}

fn create_mptcp_listener(bind_addr: SocketAddrV4) -> LabResult<TcpListener> {
    let fd = create_mptcp_socket()?;
    set_reuseaddr(fd.as_raw_fd())?;
    bind_ipv4(fd.as_raw_fd(), bind_addr)?;
    // SAFETY: fd is a valid MPTCP stream socket owned by this function.
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let raw_fd = fd.into_raw_fd();
    // SAFETY: ownership of raw_fd is transferred exactly once to StdTcpListener.
    let listener = unsafe { StdTcpListener::from_raw_fd(raw_fd) };
    listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(listener)?)
}

async fn connect_mptcp(local: SocketAddrV4, remote: SocketAddrV4) -> LabResult<TcpStream> {
    let fd = create_mptcp_socket()?;
    bind_ipv4(fd.as_raw_fd(), local)?;
    let remote_addr = sockaddr_in(remote);
    // SAFETY: remote_addr is a fully initialized IPv4 sockaddr with the correct length.
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const remote_addr).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.into());
        }
    }

    let raw_fd = fd.into_raw_fd();
    // SAFETY: ownership of raw_fd is transferred exactly once to StdTcpStream.
    let stream = unsafe { StdTcpStream::from_raw_fd(raw_fd) };
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;
    timeout(MPTCP_READY_TIMEOUT, stream.writable())
        .await
        .map_err(|_| other_error("MPTCP connect 等待可写超时"))??;
    if let Some(error) = stream.take_error()? {
        return Err(error.into());
    }
    let _ = stream.peer_addr()?;
    Ok(stream)
}

fn create_mptcp_socket() -> LabResult<OwnedFd> {
    // SAFETY: socket has no borrowed pointers; on success the returned descriptor is uniquely owned.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            IPPROTO_MPTCP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: fd was just returned by socket and has not been wrapped elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_reuseaddr(fd: RawFd) -> LabResult<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: enabled points to a valid c_int and the descriptor is a live socket.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const enabled).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

fn bind_ipv4(fd: RawFd, address: SocketAddrV4) -> LabResult<()> {
    let address = sockaddr_in(address);
    // SAFETY: address is a fully initialized IPv4 sockaddr with the correct length.
    let result = unsafe {
        libc::bind(
            fd,
            (&raw const address).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

fn sockaddr_in(address: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn duplicate_fd(fd: RawFd) -> LabResult<OwnedFd> {
    // SAFETY: dup does not consume fd and returns a new independently owned descriptor.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: duplicate is a fresh descriptor returned by fcntl.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawMptcpInfo {
    subflows: u8,
    add_addr_signal: u8,
    add_addr_accepted: u8,
    subflows_max: u8,
    add_addr_signal_max: u8,
    add_addr_accepted_max: u8,
    padding0: [u8; 2],
    flags: u32,
    token: u32,
    write_seq: u64,
    snd_una: u64,
    rcv_nxt: u64,
    local_addr_used: u8,
    local_addr_max: u8,
    csum_enabled: u8,
    padding1: u8,
    retransmits: u32,
    bytes_retrans: u64,
    bytes_sent: u64,
    bytes_received: u64,
    bytes_acked: u64,
    subflows_total: u8,
    endp_laminar_max: u8,
    endp_fullmesh_max: u8,
    reserved: u8,
    last_data_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,
}

fn mptcp_info(fd: RawFd) -> LabResult<MptcpInfoSnapshot> {
    // SAFETY: RawMptcpInfo is a plain C-compatible output buffer and zero is valid initialization.
    let mut raw: RawMptcpInfo = unsafe { zeroed() };
    let mut length = size_of::<RawMptcpInfo>() as libc::socklen_t;
    // SAFETY: raw and length are valid writable buffers for getsockopt on a live socket.
    let result = unsafe {
        libc::getsockopt(
            fd,
            SOL_MPTCP,
            MPTCP_INFO,
            (&raw mut raw).cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if (length as usize) < MIN_MPTCP_INFO_WITH_SUBFLOW_TOTAL {
        return Err(other_error(format!("内核 MPTCP_INFO 长度过短：{length}")));
    }
    Ok(MptcpInfoSnapshot {
        extra_subflows: raw.subflows,
        subflows_total: raw.subflows_total,
        fallback: raw.flags & MPTCP_INFO_FLAG_FALLBACK != 0,
        remote_key_received: raw.flags & MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED != 0,
        retransmits: raw.retransmits,
        bytes_retransmitted: raw.bytes_retrans,
        bytes_sent: raw.bytes_sent,
        bytes_received: raw.bytes_received,
        bytes_acked: raw.bytes_acked,
    })
}

async fn wait_for_subflows(fd: RawFd, expected: u8) -> LabResult<MptcpInfoSnapshot> {
    let deadline = Instant::now() + MPTCP_SUBFLOW_TIMEOUT;
    loop {
        let info = mptcp_info(fd)?;
        if info.negotiated() && info.subflows_total == expected {
            return Ok(info);
        }
        if Instant::now() >= deadline {
            return Err(other_error(format!(
                "MPTCP 子流没有按时达到 {expected} 条：fallback={} remote_key={} total={} extra={}",
                info.fallback, info.remote_key_received, info.subflows_total, info.extra_subflows,
            )));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn configure_mptcp_path_manager(mode: MptcpPathMode) -> LabResult<()> {
    run_command("ip", &["mptcp", "endpoint", "flush"])?;
    run_command(
        "ip",
        &[
            "mptcp",
            "limits",
            "set",
            "subflows",
            "2",
            "add_addr_accepted",
            "2",
        ],
    )?;
    if mode == MptcpPathMode::Multipath {
        run_command(
            "ip",
            &[
                "mptcp",
                "endpoint",
                "add",
                "127.0.0.4",
                "dev",
                "lo",
                "id",
                "1",
                "subflow",
            ],
        )?;
    }
    Ok(())
}

fn verify_mptcp_runtime() -> LabResult<MptcpRuntimeIdentity> {
    let enabled = read_sysctl("/proc/sys/net/mptcp/enabled")?;
    let path_manager = read_sysctl("/proc/sys/net/mptcp/path_manager")?;
    let scheduler = read_sysctl("/proc/sys/net/mptcp/scheduler")?;
    let congestion_control = read_sysctl("/proc/sys/net/ipv4/tcp_congestion_control")?;
    if enabled != "1" {
        return Err(other_error("隔离环境没有启用 Linux MPTCP"));
    }
    if path_manager != "kernel" || scheduler != "default" || congestion_control != "cubic" {
        return Err(other_error(format!(
            "MPTCP 运行身份漂移：path_manager={path_manager} scheduler={scheduler} congestion={congestion_control}"
        )));
    }
    Ok(MptcpRuntimeIdentity {
        kernel_release: command_stdout("uname", &["-r"])?,
        iproute2_version: command_stdout("ip", &["-Version"])?,
        path_manager,
        scheduler,
        congestion_control,
    })
}

fn read_sysctl(path: &str) -> LabResult<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn command_stdout(command: &str, arguments: &[&str]) -> LabResult<String> {
    let output = Command::new(command).args(arguments).output()?;
    if !output.status.success() {
        return Err(other_error(format!(
            "{command} 命令失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn run_command(command: &str, arguments: &[&str]) -> LabResult<()> {
    command_stdout(command, arguments).map(|_| ())
}

#[derive(Debug)]
enum MptcpStreamEvent {
    Record { sequence: u64, received_at: Instant },
    Finished { records: u64, bytes: u64 },
    ExchangeComplete { records: u64, bytes: u64 },
    Failed { protocol: bool, reason: String },
}

#[derive(Debug)]
struct ThroughputTrace {
    received_at: Vec<Instant>,
    records: u64,
    bytes: u64,
}

async fn collect_throughput_events(
    events: &mut mpsc::UnboundedReceiver<MptcpStreamEvent>,
    chunk_size: usize,
) -> LabResult<ThroughputTrace> {
    let mut received_at = Vec::new();
    let mut expected_sequence = 0_u64;
    let mut finished = None;
    let mut exchange_complete = None;
    while let Some(event) = events.recv().await {
        match event {
            MptcpStreamEvent::Record {
                sequence,
                received_at: at,
            } => {
                if sequence != expected_sequence {
                    return Err(other_error(format!(
                        "MPTCP B 组事件序号错误：期望 {expected_sequence}，实际 {sequence}"
                    )));
                }
                received_at.push(at);
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or_else(|| other_error("MPTCP B 组事件记录数溢出"))?;
            }
            MptcpStreamEvent::Finished { records, bytes } => finished = Some((records, bytes)),
            MptcpStreamEvent::ExchangeComplete { records, bytes } => {
                exchange_complete = Some((records, bytes));
            }
            MptcpStreamEvent::Failed { protocol, reason } => {
                return Err(other_error(format!(
                    "MPTCP B 组{}失败：{reason}",
                    if protocol { "协议" } else { "任务" }
                )));
            }
        }
    }
    let expected_bytes = expected_sequence
        .checked_mul(chunk_size as u64)
        .ok_or_else(|| other_error("MPTCP B 组事件业务字节数溢出"))?;
    if finished != Some((expected_sequence, expected_bytes))
        || exchange_complete != Some((expected_sequence, expected_bytes))
    {
        return Err(other_error(
            "MPTCP B 组接收完成或最终响应与逐记录事件不一致",
        ));
    }
    Ok(ThroughputTrace {
        received_at,
        records: expected_sequence,
        bytes: expected_bytes,
    })
}

async fn run_timed_sender<R, W>(
    mut response_reader: R,
    mut writer: W,
    duration: Duration,
    chunk_size: usize,
    seed: u8,
    started_tx: oneshot::Sender<Instant>,
    events: mpsc::UnboundedSender<MptcpStreamEvent>,
) -> LabResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result: LabResult<()> = async {
        let started_at = Instant::now();
        started_tx
            .send(started_at)
            .map_err(|_| other_error("MPTCP A 组启动时刻无人接收"))?;
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        let mut payload = vec![0_u8; chunk_size];
        while started_at.elapsed() < duration {
            write_record(&mut writer, &mut payload, seed, sequence).await?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| other_error("MPTCP A 组发送记录编号溢出"))?;
            bytes = bytes
                .checked_add(chunk_size as u64)
                .ok_or_else(|| other_error("MPTCP A 组发送字节数溢出"))?;
        }
        finish_sender(
            &mut response_reader,
            &mut writer,
            sequence,
            bytes,
            "MPTCP A 组",
            &events,
        )
        .await
    }
    .await;
    send_stream_failure(&events, "发送端", &result);
    result
}

async fn run_continuous_sender<R, W>(
    mut response_reader: R,
    mut writer: W,
    mut stop: oneshot::Receiver<()>,
    chunk_size: usize,
    seed: u8,
    started_tx: oneshot::Sender<Instant>,
    events: mpsc::UnboundedSender<MptcpStreamEvent>,
) -> LabResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result: LabResult<()> = async {
        started_tx
            .send(Instant::now())
            .map_err(|_| other_error("MPTCP B 组启动时刻无人接收"))?;
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        let mut payload = vec![0_u8; chunk_size];
        loop {
            match stop.try_recv() {
                Ok(()) | Err(oneshot::error::TryRecvError::Closed) => break,
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            write_record(&mut writer, &mut payload, seed, sequence).await?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| other_error("MPTCP B 组发送记录编号溢出"))?;
            bytes = bytes
                .checked_add(chunk_size as u64)
                .ok_or_else(|| other_error("MPTCP B 组发送字节数溢出"))?;
        }
        finish_sender(
            &mut response_reader,
            &mut writer,
            sequence,
            bytes,
            "MPTCP B 组",
            &events,
        )
        .await
    }
    .await;
    send_stream_failure(&events, "发送端", &result);
    result
}

async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &mut [u8],
    seed: u8,
    sequence: u64,
) -> LabResult<()> {
    fill_payload(payload, seed, sequence);
    let mut header = [0_u8; MPTCP_RECORD_HEADER_SIZE];
    header[..8].copy_from_slice(&sequence.to_be_bytes());
    header[8..].copy_from_slice(&digest(payload).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    Ok(())
}

async fn finish_sender<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    response_reader: &mut R,
    writer: &mut W,
    records: u64,
    bytes: u64,
    label: &str,
    events: &mpsc::UnboundedSender<MptcpStreamEvent>,
) -> LabResult<()> {
    let mut end = [0_u8; MPTCP_RECORD_HEADER_SIZE];
    end[..8].copy_from_slice(&MPTCP_RECORD_END.to_be_bytes());
    end[8..].copy_from_slice(&records.to_be_bytes());
    writer.write_all(&end).await?;
    writer.shutdown().await?;

    let mut response = [0_u8; MPTCP_RESPONSE_SIZE];
    response_reader.read_exact(&mut response).await?;
    if &response[..4] != MPTCP_RESPONSE_MAGIC {
        return Err(other_error(format!("{label}最终响应 magic 错误")));
    }
    let response_records = u64::from_be_bytes(response[4..12].try_into().expect("fixed width"));
    let response_bytes = u64::from_be_bytes(response[12..20].try_into().expect("fixed width"));
    if (response_records, response_bytes) != (records, bytes) {
        return Err(other_error(format!("{label}最终响应总量不一致")));
    }
    let _ = events.send(MptcpStreamEvent::ExchangeComplete { records, bytes });
    Ok(())
}

async fn run_receiver<R, W>(
    mut reader: R,
    mut response_writer: W,
    chunk_size: usize,
    seed: u8,
    events: mpsc::UnboundedSender<MptcpStreamEvent>,
) -> LabResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result: LabResult<()> = async {
        let mut expected_sequence = 0_u64;
        let mut bytes = 0_u64;
        let mut payload = vec![0_u8; chunk_size];
        loop {
            let mut header = [0_u8; MPTCP_RECORD_HEADER_SIZE];
            reader.read_exact(&mut header).await?;
            let sequence = u64::from_be_bytes(header[..8].try_into().expect("fixed width"));
            let expected_digest = u64::from_be_bytes(header[8..].try_into().expect("fixed width"));
            if sequence == MPTCP_RECORD_END {
                if expected_digest != expected_sequence {
                    return Err(other_error("MPTCP 结束标记总记录数错误"));
                }
                let mut response = [0_u8; MPTCP_RESPONSE_SIZE];
                response[..4].copy_from_slice(MPTCP_RESPONSE_MAGIC);
                response[4..12].copy_from_slice(&expected_sequence.to_be_bytes());
                response[12..20].copy_from_slice(&bytes.to_be_bytes());
                response_writer.write_all(&response).await?;
                response_writer.shutdown().await?;
                let _ = events.send(MptcpStreamEvent::Finished {
                    records: expected_sequence,
                    bytes,
                });
                return Ok(());
            }
            if sequence != expected_sequence {
                return Err(other_error(format!(
                    "MPTCP 记录编号错误：期望 {expected_sequence}，实际 {sequence}"
                )));
            }
            reader.read_exact(&mut payload).await?;
            if digest(&payload) != expected_digest || !payload_is_valid(&payload, seed, sequence) {
                return Err(other_error(format!("MPTCP 记录 {sequence} 内容或摘要错误")));
            }
            let _ = events.send(MptcpStreamEvent::Record {
                sequence,
                received_at: Instant::now(),
            });
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or_else(|| other_error("MPTCP 接收记录编号溢出"))?;
            bytes = bytes
                .checked_add(chunk_size as u64)
                .ok_or_else(|| other_error("MPTCP 接收字节数溢出"))?;
        }
    }
    .await;
    send_stream_failure(&events, "接收端", &result);
    result
}

fn send_stream_failure(
    events: &mpsc::UnboundedSender<MptcpStreamEvent>,
    role: &str,
    result: &LabResult<()>,
) {
    if let Err(error) = result {
        let reason = error.to_string();
        let protocol = reason.contains("编号")
            || reason.contains("内容")
            || reason.contains("摘要")
            || reason.contains("结束标记")
            || reason.contains("响应");
        let _ = events.send(MptcpStreamEvent::Failed {
            protocol,
            reason: format!("{role}：{reason}"),
        });
    }
}

fn collect_task_result(
    failure: &mut Option<String>,
    label: &str,
    result: Result<LabResult<()>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            failure.get_or_insert_with(|| format!("MPTCP A 组{label}失败：{error}"));
        }
        Err(error) if error.is_cancelled() => {}
        Err(error) => {
            failure.get_or_insert_with(|| format!("MPTCP A 组{label}任务异常：{error}"));
        }
    }
}

fn fill_payload(payload: &mut [u8], seed: u8, sequence: u64) {
    let sequence = sequence as u8;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add(sequence)
            .wrapping_add((index as u8).wrapping_mul(31));
    }
}

fn payload_is_valid(payload: &[u8], seed: u8, sequence: u64) -> bool {
    let sequence = sequence as u8;
    payload.iter().enumerate().all(|(index, byte)| {
        *byte
            == seed
                .wrapping_add(sequence)
                .wrapping_add((index as u8).wrapping_mul(31))
    })
}

fn validate_chunk_size(chunk_size: usize, label: &str) -> LabResult<()> {
    if !(MPTCP_RECORD_HEADER_SIZE..=1024 * 1024).contains(&chunk_size) {
        return Err(other_error(format!(
            "{label}记录载荷必须在 16 字节到 1 MiB 之间"
        )));
    }
    Ok(())
}

fn count_records_in_window(
    received_at: &[Instant],
    started: Instant,
    ended: Instant,
) -> LabResult<u64> {
    if ended < started {
        return Err(other_error("MPTCP B 组测量窗口结束早于开始"));
    }
    u64::try_from(
        received_at
            .iter()
            .filter(|received_at| **received_at >= started && **received_at < ended)
            .count(),
    )
    .map_err(|_| other_error("MPTCP B 组测量窗口记录数超出 u64"))
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

fn percentage(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 / total as f64 * 100.0
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct NftCounter {
    packets: u64,
    ipv4_bytes: u64,
}

impl NftCounter {
    const fn saturating_sub(self, before: Self) -> Self {
        Self {
            packets: self.packets.saturating_sub(before.packets),
            ipv4_bytes: self.ipv4_bytes.saturating_sub(before.ipv4_bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct MptcpCounterSnapshot {
    client_line_one: NftCounter,
    client_line_two: NftCounter,
    server_line_one: NftCounter,
    server_line_two: NftCounter,
}

impl MptcpCounterSnapshot {
    const fn saturating_sub(self, before: Self) -> Self {
        Self {
            client_line_one: self.client_line_one.saturating_sub(before.client_line_one),
            client_line_two: self.client_line_two.saturating_sub(before.client_line_two),
            server_line_one: self.server_line_one.saturating_sub(before.server_line_one),
            server_line_two: self.server_line_two.saturating_sub(before.server_line_two),
        }
    }

    const fn line_one_packets(self) -> u64 {
        self.client_line_one
            .packets
            .saturating_add(self.server_line_one.packets)
    }

    const fn line_two_packets(self) -> u64 {
        self.client_line_two
            .packets
            .saturating_add(self.server_line_two.packets)
    }
}

#[derive(Debug)]
struct MptcpNftCounters {
    table: String,
}

impl MptcpNftCounters {
    fn new(server_port: u16) -> LabResult<Self> {
        let id = NEXT_NFT_TABLE.fetch_add(1, Ordering::Relaxed);
        let table = format!("fwmp{:x}{id:x}", std::process::id());
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
            add_nft_counter_rule(
                &table,
                "saddr",
                MPTCP_LINE_ONE_CLIENT_IP,
                "dport",
                &port,
                "client_line_one",
            )?;
            add_nft_counter_rule(
                &table,
                "saddr",
                MPTCP_LINE_TWO_CLIENT_IP,
                "dport",
                &port,
                "client_line_two",
            )?;
            add_nft_counter_rule(
                &table,
                "daddr",
                MPTCP_LINE_ONE_CLIENT_IP,
                "sport",
                &port,
                "server_line_one",
            )?;
            add_nft_counter_rule(
                &table,
                "daddr",
                MPTCP_LINE_TWO_CLIENT_IP,
                "sport",
                &port,
                "server_line_two",
            )
        })();
        if let Err(error) = setup {
            let _ = run_nft(&["delete", "table", "ip", &table]);
            return Err(error);
        }
        Ok(Self { table })
    }

    fn snapshot(&self) -> LabResult<MptcpCounterSnapshot> {
        let output = Command::new("nft")
            .args(["list", "chain", "ip", &self.table, "output"])
            .output()?;
        if !output.status.success() {
            return Err(other_error(format!(
                "无法读取 MPTCP nft 计数器：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(MptcpCounterSnapshot {
            client_line_one: parse_nft_counter(&text, "client_line_one")?,
            client_line_two: parse_nft_counter(&text, "client_line_two")?,
            server_line_one: parse_nft_counter(&text, "server_line_one")?,
            server_line_two: parse_nft_counter(&text, "server_line_two")?,
        })
    }
}

impl Drop for MptcpNftCounters {
    fn drop(&mut self) {
        let _ = run_nft(&["delete", "table", "ip", &self.table]);
    }
}

fn add_nft_counter_rule(
    table: &str,
    address_field: &str,
    address: Ipv4Addr,
    port_field: &str,
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
        address_field,
        &address.to_string(),
        "tcp",
        port_field,
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
        .ok_or_else(|| other_error(format!("找不到 MPTCP nft 计数器 {label}")))?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    Ok(NftCounter {
        packets: value_after(&fields, "packets")?,
        ipv4_bytes: value_after(&fields, "bytes")?,
    })
}

fn value_after(fields: &[&str], key: &str) -> LabResult<u64> {
    let index = fields
        .iter()
        .position(|field| *field == key)
        .ok_or_else(|| other_error(format!("MPTCP nft 计数器缺少 {key} 字段")))?;
    fields
        .get(index + 1)
        .ok_or_else(|| other_error(format!("MPTCP nft 计数器 {key} 字段没有值")))?
        .parse()
        .map_err(|_| other_error(format!("MPTCP nft 计数器 {key} 字段不是整数")))
}

fn run_nft(arguments: &[&str]) -> LabResult<()> {
    let output = Command::new("nft").args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(other_error(format!(
        "MPTCP nft 命令失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_mptcp_info_layout_contains_linux_v7_fields() {
        assert_eq!(size_of::<RawMptcpInfo>(), 96);
        let raw = RawMptcpInfo {
            subflows: 1,
            add_addr_signal: 0,
            add_addr_accepted: 0,
            subflows_max: 2,
            add_addr_signal_max: 0,
            add_addr_accepted_max: 2,
            padding0: [0; 2],
            flags: MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED,
            token: 0,
            write_seq: 0,
            snd_una: 0,
            rcv_nxt: 0,
            local_addr_used: 1,
            local_addr_max: 1,
            csum_enabled: 0,
            padding1: 0,
            retransmits: 3,
            bytes_retrans: 17,
            bytes_sent: 100,
            bytes_received: 200,
            bytes_acked: 90,
            subflows_total: 2,
            endp_laminar_max: 0,
            endp_fullmesh_max: 0,
            reserved: 0,
            last_data_sent: 0,
            last_data_recv: 0,
            last_ack_recv: 0,
        };
        assert_eq!(raw.subflows_total, 2);
        assert_eq!(raw.bytes_retrans, 17);
    }

    #[test]
    fn mptcp_configs_reject_invalid_windows_and_chunks() {
        assert!(
            MptcpThroughputConfig::new(
                MptcpPathMode::Multipath,
                Duration::from_secs(2),
                Duration::ZERO,
                16 * 1024,
                1,
            )
            .validate()
            .is_err()
        );
        assert!(
            MptcpFailoverConfig::new(
                FailoverDirection::ClientToServer,
                Duration::from_secs(30),
                Duration::from_secs(30),
                16 * 1024,
                1,
            )
            .validate()
            .is_err()
        );
    }

    #[test]
    fn mptcp_payload_validation_detects_corruption() {
        let mut payload = vec![0_u8; 16 * 1024];
        fill_payload(&mut payload, 17, 23);
        assert!(payload_is_valid(&payload, 17, 23));
        payload[777] ^= 1;
        assert!(!payload_is_valid(&payload, 17, 23));
    }

    #[test]
    fn mptcp_nft_counter_parser_reads_all_fields() {
        let text = r#"
table ip fwmp1 {
    chain output {
        ip saddr 127.0.0.3 tcp dport 45123 counter packets 19 bytes 23000 comment "client_line_one"
        ip saddr 127.0.0.4 tcp dport 45123 counter packets 7 bytes 9000 comment "client_line_two"
    }
}
"#;
        let line_one = parse_nft_counter(text, "client_line_one").unwrap();
        assert_eq!(line_one.packets, 19);
        assert_eq!(line_one.ipv4_bytes, 23_000);
        let line_two = parse_nft_counter(text, "client_line_two").unwrap();
        assert_eq!(line_two.packets, 7);
        assert_eq!(line_two.ipv4_bytes, 9_000);
    }

    #[test]
    fn mptcp_record_window_is_half_open() {
        let started = Instant::now();
        let ended = started + Duration::from_millis(100);
        let timestamps = [
            started - Duration::from_nanos(1),
            started,
            started + Duration::from_millis(50),
            ended,
        ];
        assert_eq!(
            count_records_in_window(&timestamps, started, ended).unwrap(),
            2
        );
        assert!(count_records_in_window(&timestamps, ended, started).is_err());
    }
}

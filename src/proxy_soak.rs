use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, watch},
    task::JoinSet,
    time::{Instant, interval_at, sleep, sleep_until, timeout},
};

use super::{
    LabResult, ProxyClientConfig, ProxyHealthPolicy, ProxyHealthReport, ProxyMetricsSnapshot,
    ProxyObservation, ProxyServerConfig, other_error,
    proxy::{ProxyEventSink, start_proxy_client_with_sink, start_proxy_server_with_sink},
};

pub const PROXY_SOAK_REPORT_SCHEMA: &str = "flowweave.proxy-soak.v1";
pub const PROXY_PUBLIC_SOAK_REPORT_SCHEMA: &str = "flowweave.proxy-public-soak.v1";
const FLOW_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SOAK_DURATION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_SOAK_WORKERS: usize = 64;
const MAX_SOAK_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_PUBLIC_SOAK_WORKERS: usize = 8;
const MAX_PUBLIC_SOAK_UPLOAD_RATE_BPS: u64 = 1_000_000_000;
const MAX_PUBLIC_SOAK_APPLICATION_BYTE_BUDGET: u64 = 1_u64 << 40;
const MAX_PUBLIC_SOAK_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(60 * 60);
const MAX_PUBLIC_SOAK_PACING_WINDOW: Duration = Duration::from_secs(10);
const PUBLIC_SOAK_WRITE_CHUNK_BYTES: usize = 16 * 1024;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxySoakConfig {
    pub duration: Duration,
    pub workers: usize,
    pub payload_bytes: usize,
    pub inter_flow_delay: Duration,
    pub multipath: bool,
}

impl Default for ProxySoakConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(60),
            workers: 4,
            payload_bytes: 64 * 1024,
            inter_flow_delay: Duration::from_millis(10),
            multipath: true,
        }
    }
}

impl ProxySoakConfig {
    fn validate(self) -> LabResult<Self> {
        if self.duration.is_zero() || self.duration > MAX_SOAK_DURATION {
            return Err(other_error("soak duration 必须在 1 ns 到 7 天之间"));
        }
        if !(1..=MAX_SOAK_WORKERS).contains(&self.workers) {
            return Err(other_error(format!(
                "soak workers 必须在 1 到 {MAX_SOAK_WORKERS} 之间"
            )));
        }
        if !(1..=MAX_SOAK_PAYLOAD_BYTES).contains(&self.payload_bytes) {
            return Err(other_error(format!(
                "soak payload_bytes 必须在 1 到 {MAX_SOAK_PAYLOAD_BYTES} 之间"
            )));
        }
        if self.inter_flow_delay > Duration::from_secs(60) {
            return Err(other_error("soak inter_flow_delay 不得超过 60 秒"));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyPublicSoakConfig {
    pub client_addr: SocketAddr,
    pub duration: Duration,
    pub workers: usize,
    pub payload_bytes: usize,
    pub upload_rate_bps: u64,
    /// Application bytes in both directions. QUIC, UDP/IP and retransmission overhead is extra.
    pub application_byte_budget: u64,
    pub checkpoint_interval: Duration,
}

impl Default for ProxyPublicSoakConfig {
    fn default() -> Self {
        Self {
            client_addr: SocketAddr::from(([127, 0, 0, 1], 10080)),
            duration: Duration::from_secs(30 * 60),
            workers: 1,
            payload_bytes: 16 * 1024,
            upload_rate_bps: 512_000,
            application_byte_budget: 230_400_000,
            checkpoint_interval: Duration::from_secs(60),
        }
    }
}

impl ProxyPublicSoakConfig {
    fn validate(self) -> LabResult<Self> {
        if !self.client_addr.ip().is_loopback() {
            return Err(other_error(
                "公网 soak workload 只能连接本机 loopback 代理端口",
            ));
        }
        if self.duration.is_zero() || self.duration > MAX_SOAK_DURATION {
            return Err(other_error("公网 soak duration 必须在 1 ns 到 7 天之间"));
        }
        if !(1..=MAX_PUBLIC_SOAK_WORKERS).contains(&self.workers) {
            return Err(other_error(format!(
                "公网 soak workers 必须在 1 到 {MAX_PUBLIC_SOAK_WORKERS} 之间"
            )));
        }
        if !(1..=MAX_SOAK_PAYLOAD_BYTES).contains(&self.payload_bytes) {
            return Err(other_error(format!(
                "公网 soak payload_bytes 必须在 1 到 {MAX_SOAK_PAYLOAD_BYTES} 之间"
            )));
        }
        if !(1..=MAX_PUBLIC_SOAK_UPLOAD_RATE_BPS).contains(&self.upload_rate_bps) {
            return Err(other_error(format!(
                "公网 soak upload_rate_bps 必须在 1 到 {MAX_PUBLIC_SOAK_UPLOAD_RATE_BPS} 之间"
            )));
        }
        let flow_application_bytes = application_bytes_per_flow(self.payload_bytes)?;
        if !(flow_application_bytes..=MAX_PUBLIC_SOAK_APPLICATION_BYTE_BUDGET)
            .contains(&self.application_byte_budget)
        {
            return Err(other_error(format!(
                "公网 soak application_byte_budget 必须至少容纳一条往返流，且不得超过 {MAX_PUBLIC_SOAK_APPLICATION_BYTE_BUDGET}"
            )));
        }
        if self.checkpoint_interval.is_zero()
            || self.checkpoint_interval > MAX_PUBLIC_SOAK_CHECKPOINT_INTERVAL
        {
            return Err(other_error(
                "公网 soak checkpoint_interval 必须大于零且不得超过 1 小时",
            ));
        }
        let paced_bytes = (self.payload_bytes as u128).saturating_mul(self.workers as u128);
        if duration_for_rate(paced_bytes, self.upload_rate_bps) > MAX_PUBLIC_SOAK_PACING_WINDOW {
            return Err(other_error(
                "公网 soak workers × payload_bytes 在当前限速下不得占用超过 10 秒发送窗口",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProxyPublicSoakStopReason {
    DurationElapsed = 1,
    ApplicationByteBudgetExhausted = 2,
    FlowFailed = 3,
    Interrupted = 4,
}

impl ProxyPublicSoakStopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DurationElapsed => "duration_elapsed",
            Self::ApplicationByteBudgetExhausted => "application_byte_budget_exhausted",
            Self::FlowFailed => "flow_failed",
            Self::Interrupted => "interrupted",
        }
    }

    fn from_code(code: u8) -> LabResult<Self> {
        match code {
            1 => Ok(Self::DurationElapsed),
            2 => Ok(Self::ApplicationByteBudgetExhausted),
            3 => Ok(Self::FlowFailed),
            4 => Ok(Self::Interrupted),
            _ => Err(other_error("公网 soak 缺少合法停止原因")),
        }
    }

    const fn is_normal_completion(self) -> bool {
        matches!(
            self,
            Self::DurationElapsed | Self::ApplicationByteBudgetExhausted
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPublicSoakReport {
    pub stage_pass: bool,
    pub stop_reason: ProxyPublicSoakStopReason,
    pub configured_duration_ms: u64,
    pub elapsed_ms: u64,
    pub client_addr: SocketAddr,
    pub workers: usize,
    pub payload_bytes: usize,
    pub upload_rate_bps: u64,
    pub application_byte_budget: u64,
    pub checkpoint_interval_ms: u64,
    pub attempted_flows: u64,
    pub completed_flows: u64,
    pub failed_flows: u64,
    pub timed_out_flows: u64,
    pub reserved_application_bytes: u64,
    pub sent_bytes: u64,
    pub echoed_bytes: u64,
}

impl ProxyPublicSoakReport {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": PROXY_PUBLIC_SOAK_REPORT_SCHEMA,
            "event": "final",
            "stage_pass": self.stage_pass,
            "stop_reason": self.stop_reason.as_str(),
            "configured_duration_ms": self.configured_duration_ms,
            "elapsed_ms": self.elapsed_ms,
            "client_addr": self.client_addr.to_string(),
            "workers": self.workers,
            "payload_bytes": self.payload_bytes,
            "upload_rate_bps": self.upload_rate_bps,
            "application_byte_budget": self.application_byte_budget,
            "checkpoint_interval_ms": self.checkpoint_interval_ms,
            "attempted_flows": self.attempted_flows,
            "completed_flows": self.completed_flows,
            "failed_flows": self.failed_flows,
            "timed_out_flows": self.timed_out_flows,
            "reserved_application_bytes": self.reserved_application_bytes,
            "remaining_application_byte_budget": self
                .application_byte_budget
                .saturating_sub(self.reserved_application_bytes),
            "sent_bytes": self.sent_bytes,
            "echoed_bytes": self.echoed_bytes,
            "average_upload_rate_bps": average_rate_bps(self.sent_bytes, self.elapsed_ms),
            "carrier_overhead_included": false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySoakReport {
    pub stage_pass: bool,
    pub configured_duration_ms: u64,
    pub elapsed_ms: u64,
    pub workers: usize,
    pub payload_bytes: usize,
    pub inter_flow_delay_ms: u64,
    pub multipath: bool,
    pub attempted_flows: u64,
    pub completed_flows: u64,
    pub failed_flows: u64,
    pub sent_bytes: u64,
    pub echoed_bytes: u64,
    pub client_metrics: ProxyMetricsSnapshot,
    pub server_metrics: ProxyMetricsSnapshot,
    pub health: ProxyHealthReport,
}

impl ProxySoakReport {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": PROXY_SOAK_REPORT_SCHEMA,
            "stage_pass": self.stage_pass,
            "configured_duration_ms": self.configured_duration_ms,
            "elapsed_ms": self.elapsed_ms,
            "workers": self.workers,
            "payload_bytes": self.payload_bytes,
            "inter_flow_delay_ms": self.inter_flow_delay_ms,
            "flow_timeout_ms": duration_millis(FLOW_TIMEOUT),
            "multipath": self.multipath,
            "attempted_flows": self.attempted_flows,
            "completed_flows": self.completed_flows,
            "failed_flows": self.failed_flows,
            "sent_bytes": self.sent_bytes,
            "echoed_bytes": self.echoed_bytes,
            "client_metrics": metrics_to_json(self.client_metrics),
            "server_metrics": metrics_to_json(self.server_metrics),
            "health": self.health.to_json(),
        })
    }
}

#[derive(Debug, Default)]
struct WorkloadCounters {
    attempted_flows: AtomicU64,
    completed_flows: AtomicU64,
    failed_flows: AtomicU64,
    timed_out_flows: AtomicU64,
    reserved_application_bytes: AtomicU64,
    sent_bytes: AtomicU64,
    echoed_bytes: AtomicU64,
}

#[derive(Debug)]
struct PublicRatePacer {
    next_send: Instant,
    upload_rate_bps: u64,
}

impl PublicRatePacer {
    fn new(upload_rate_bps: u64) -> Self {
        Self {
            next_send: Instant::now(),
            upload_rate_bps,
        }
    }

    async fn wait_for_bytes(pacer: &AsyncMutex<Self>, bytes: usize) {
        let scheduled = {
            let mut pacer = pacer.lock().await;
            let now = Instant::now();
            let scheduled = pacer.next_send.max(now);
            let spacing = duration_for_rate(bytes as u128, pacer.upload_rate_bps);
            pacer.next_send = scheduled.checked_add(spacing).unwrap_or(scheduled);
            scheduled
        };
        if scheduled > Instant::now() {
            sleep_until(scheduled).await;
        }
    }
}

#[derive(Debug, Default)]
struct ObservationSink(Mutex<ProxyObservation>);

impl ProxyEventSink for ObservationSink {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().ingest_line(line);
    }
}

impl ObservationSink {
    fn snapshot(&self) -> ProxyObservation {
        self.0.lock().unwrap().clone()
    }
}

struct SoakDirectory(PathBuf);

impl SoakDirectory {
    fn new() -> LabResult<Self> {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "flowweave-soak-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        set_directory_permissions(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SoakDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub async fn run_proxy_soak(config: ProxySoakConfig) -> LabResult<ProxySoakReport> {
    let config = config.validate()?;
    let run_started = Instant::now();
    let directory = SoakDirectory::new()?;
    let (certificate_path, key_path, token_path) = write_credentials(&directory)?;
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream.local_addr()?;
    let sink = Arc::new(ObservationSink::default());

    let server = start_proxy_server_with_sink(
        ProxyServerConfig {
            listen: "127.0.0.1:0".parse()?,
            certificate_der: certificate_path.clone(),
            private_key_der: key_path,
            token_file: token_path.clone(),
            allowed_target: upstream_addr,
        },
        sink.clone(),
    )
    .await?;
    let client = match start_proxy_client_with_sink(
        ProxyClientConfig {
            listen: "127.0.0.1:0".parse()?,
            server: server.local_addr().to_string(),
            server_name: "localhost".to_owned(),
            ca_certificate_der: certificate_path,
            token_file: token_path,
            target: upstream_addr,
            primary_local_ip: config.multipath.then_some("127.0.0.1".parse::<IpAddr>()?),
            additional_local_ips: if config.multipath {
                vec!["127.0.0.2".parse()?]
            } else {
                Vec::new()
            },
        },
        sink.clone(),
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            server.shutdown().await;
            return Err(error);
        }
    };

    let (echo_shutdown, echo_shutdown_rx) = watch::channel(false);
    let echo_task = tokio::spawn(run_echo_server(upstream, echo_shutdown_rx));
    let counters = Arc::new(WorkloadCounters::default());
    let (workload_stop, workload_stop_rx) = watch::channel(false);
    let mut workers = JoinSet::new();
    for worker_id in 0..config.workers {
        let mut stop = workload_stop_rx.clone();
        let counters = counters.clone();
        let client_addr = client.local_addr();
        workers.spawn(async move {
            let mut sequence = 0_u64;
            loop {
                if *stop.borrow() {
                    break;
                }
                counters.attempted_flows.fetch_add(1, Ordering::Relaxed);
                let payload = make_payload(worker_id, sequence, config.payload_bytes);
                match timeout(FLOW_TIMEOUT, run_soak_flow(client_addr, &payload)).await {
                    Ok(Ok(())) => {
                        counters.completed_flows.fetch_add(1, Ordering::Relaxed);
                        let bytes = u64::try_from(payload.len()).unwrap_or(u64::MAX);
                        counters.sent_bytes.fetch_add(bytes, Ordering::Relaxed);
                        counters.echoed_bytes.fetch_add(bytes, Ordering::Relaxed);
                    }
                    Ok(Err(_)) | Err(_) => {
                        counters.failed_flows.fetch_add(1, Ordering::Relaxed);
                    }
                }
                sequence = sequence.wrapping_add(1);
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = sleep(config.inter_flow_delay) => {}
                }
            }
        });
    }

    sleep(config.duration).await;
    let _ = workload_stop.send(true);
    while let Some(result) = workers.join_next().await {
        result.map_err(|error| other_error(format!("soak 工作任务异常退出：{error}")))?;
    }

    let client_metrics = client.shutdown().await;
    let server_metrics = server.shutdown().await;
    let _ = echo_shutdown.send(true);
    echo_task
        .await
        .map_err(|error| other_error(format!("soak echo 任务异常退出：{error}")))??;

    let attempted_flows = counters.attempted_flows.load(Ordering::Relaxed);
    let completed_flows = counters.completed_flows.load(Ordering::Relaxed);
    let failed_flows = counters.failed_flows.load(Ordering::Relaxed);
    let sent_bytes = counters.sent_bytes.load(Ordering::Relaxed);
    let echoed_bytes = counters.echoed_bytes.load(Ordering::Relaxed);
    let health = sink.snapshot().evaluate(ProxyHealthPolicy::strict_both());
    let expected_bytes = completed_flows.saturating_mul(config.payload_bytes as u64);
    let metrics_clean = metrics_are_clean(client_metrics, completed_flows, expected_bytes)
        && metrics_are_clean(server_metrics, completed_flows, expected_bytes);
    let stage_pass = attempted_flows != 0
        && completed_flows != 0
        && attempted_flows == completed_flows
        && failed_flows == 0
        && sent_bytes == expected_bytes
        && echoed_bytes == expected_bytes
        && metrics_clean
        && health.healthy;

    Ok(ProxySoakReport {
        stage_pass,
        configured_duration_ms: duration_millis(config.duration),
        elapsed_ms: duration_millis(run_started.elapsed()),
        workers: config.workers,
        payload_bytes: config.payload_bytes,
        inter_flow_delay_ms: duration_millis(config.inter_flow_delay),
        multipath: config.multipath,
        attempted_flows,
        completed_flows,
        failed_flows,
        sent_bytes,
        echoed_bytes,
        client_metrics,
        server_metrics,
        health,
    })
}

pub async fn run_proxy_public_soak(
    config: ProxyPublicSoakConfig,
) -> LabResult<ProxyPublicSoakReport> {
    let (shutdown_hold, shutdown) = watch::channel(false);
    let result = run_proxy_public_soak_with_shutdown(config, shutdown, |_| {}).await;
    drop(shutdown_hold);
    result
}

pub async fn run_proxy_public_soak_with_checkpoints<F>(
    config: ProxyPublicSoakConfig,
    checkpoints: F,
) -> LabResult<ProxyPublicSoakReport>
where
    F: FnMut(Value),
{
    let (shutdown_hold, shutdown) = watch::channel(false);
    let result = run_proxy_public_soak_with_shutdown(config, shutdown, checkpoints).await;
    drop(shutdown_hold);
    result
}

pub async fn run_proxy_public_soak_with_shutdown<F>(
    config: ProxyPublicSoakConfig,
    mut external_shutdown: watch::Receiver<bool>,
    mut checkpoints: F,
) -> LabResult<ProxyPublicSoakReport>
where
    F: FnMut(Value),
{
    let config = config.validate()?;
    let run_started = Instant::now();
    let counters = Arc::new(WorkloadCounters::default());
    let stop_code = Arc::new(AtomicU8::new(0));
    let pacer = Arc::new(AsyncMutex::new(PublicRatePacer::new(
        config.upload_rate_bps,
    )));
    let (workload_stop, mut workload_stop_events) = watch::channel(false);
    let flow_application_bytes = application_bytes_per_flow(config.payload_bytes)?;
    let flow_timeout = duration_for_rate(
        (config.payload_bytes as u128).saturating_mul(config.workers as u128),
        config.upload_rate_bps,
    )
    .saturating_add(FLOW_TIMEOUT);
    checkpoints(public_soak_snapshot_json(
        "started",
        run_started.elapsed(),
        config,
        &counters,
    ));
    let mut workers = JoinSet::new();

    for worker_id in 0..config.workers {
        let stop = workload_stop_events.clone();
        let stop_sender = workload_stop.clone();
        let stop_code = stop_code.clone();
        let counters = counters.clone();
        let pacer = pacer.clone();
        workers.spawn(async move {
            let mut sequence = 0_u64;
            loop {
                if *stop.borrow() {
                    break;
                }
                if !reserve_application_budget(
                    &counters.reserved_application_bytes,
                    flow_application_bytes,
                    config.application_byte_budget,
                ) {
                    request_public_soak_stop(
                        &stop_code,
                        ProxyPublicSoakStopReason::ApplicationByteBudgetExhausted,
                        &stop_sender,
                    );
                    break;
                }
                counters.attempted_flows.fetch_add(1, Ordering::Relaxed);
                let payload = make_payload(worker_id, sequence, config.payload_bytes);
                match timeout(
                    flow_timeout,
                    run_public_soak_flow(config.client_addr, &payload, &pacer, &counters),
                )
                .await
                {
                    Ok(Ok(())) => {
                        counters.completed_flows.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(_)) => {
                        counters.failed_flows.fetch_add(1, Ordering::Relaxed);
                        request_public_soak_stop(
                            &stop_code,
                            ProxyPublicSoakStopReason::FlowFailed,
                            &stop_sender,
                        );
                        break;
                    }
                    Err(_) => {
                        counters.failed_flows.fetch_add(1, Ordering::Relaxed);
                        counters.timed_out_flows.fetch_add(1, Ordering::Relaxed);
                        request_public_soak_stop(
                            &stop_code,
                            ProxyPublicSoakStopReason::FlowFailed,
                            &stop_sender,
                        );
                        break;
                    }
                }
                sequence = sequence.wrapping_add(1);
            }
        });
    }

    let mut deadline = Box::pin(sleep(config.duration));
    let mut checkpoint_timer = interval_at(
        Instant::now()
            .checked_add(config.checkpoint_interval)
            .unwrap_or_else(Instant::now),
        config.checkpoint_interval,
    );
    let mut external_shutdown_open = true;
    loop {
        tokio::select! {
            biased;
            changed = workload_stop_events.changed() => {
                if changed.is_ok() {
                    break;
                }
                return Err(other_error("公网 soak 内部停止通道意外关闭"));
            }
            changed = external_shutdown.changed(), if external_shutdown_open => {
                match changed {
                    Ok(()) if *external_shutdown.borrow() => {
                        request_public_soak_stop(
                            &stop_code,
                            ProxyPublicSoakStopReason::Interrupted,
                            &workload_stop,
                        );
                        break;
                    }
                    Ok(()) => {}
                    Err(_) => external_shutdown_open = false,
                }
            }
            _ = &mut deadline => {
                request_public_soak_stop(
                    &stop_code,
                    ProxyPublicSoakStopReason::DurationElapsed,
                    &workload_stop,
                );
                break;
            }
            _ = checkpoint_timer.tick() => {
                checkpoints(public_soak_snapshot_json(
                    "checkpoint",
                    run_started.elapsed(),
                    config,
                    &counters,
                ));
            }
        }
    }

    let stop_reason = ProxyPublicSoakStopReason::from_code(stop_code.load(Ordering::Relaxed))?;
    let stop_event = match stop_reason {
        ProxyPublicSoakStopReason::DurationElapsed => "duration_elapsed",
        ProxyPublicSoakStopReason::ApplicationByteBudgetExhausted => "budget_exhausted",
        ProxyPublicSoakStopReason::FlowFailed => "failure_detected",
        ProxyPublicSoakStopReason::Interrupted => "interrupted",
    };
    checkpoints(public_soak_snapshot_json(
        stop_event,
        run_started.elapsed(),
        config,
        &counters,
    ));
    let _ = workload_stop.send(true);
    while let Some(result) = workers.join_next().await {
        result.map_err(|error| other_error(format!("公网 soak 工作任务异常退出：{error}")))?;
    }

    let attempted_flows = counters.attempted_flows.load(Ordering::Relaxed);
    let completed_flows = counters.completed_flows.load(Ordering::Relaxed);
    let failed_flows = counters.failed_flows.load(Ordering::Relaxed);
    let timed_out_flows = counters.timed_out_flows.load(Ordering::Relaxed);
    let reserved_application_bytes = counters.reserved_application_bytes.load(Ordering::Relaxed);
    let sent_bytes = counters.sent_bytes.load(Ordering::Relaxed);
    let echoed_bytes = counters.echoed_bytes.load(Ordering::Relaxed);
    let expected_direction_bytes = completed_flows.saturating_mul(config.payload_bytes as u64);
    let stage_pass = stop_reason.is_normal_completion()
        && attempted_flows != 0
        && completed_flows != 0
        && attempted_flows == completed_flows
        && failed_flows == 0
        && timed_out_flows == 0
        && sent_bytes == expected_direction_bytes
        && echoed_bytes == expected_direction_bytes
        && reserved_application_bytes == sent_bytes.saturating_add(echoed_bytes)
        && reserved_application_bytes <= config.application_byte_budget;

    Ok(ProxyPublicSoakReport {
        stage_pass,
        stop_reason,
        configured_duration_ms: duration_millis(config.duration),
        elapsed_ms: duration_millis(run_started.elapsed()),
        client_addr: config.client_addr,
        workers: config.workers,
        payload_bytes: config.payload_bytes,
        upload_rate_bps: config.upload_rate_bps,
        application_byte_budget: config.application_byte_budget,
        checkpoint_interval_ms: duration_millis(config.checkpoint_interval),
        attempted_flows,
        completed_flows,
        failed_flows,
        timed_out_flows,
        reserved_application_bytes,
        sent_bytes,
        echoed_bytes,
    })
}

async fn run_public_soak_flow(
    client_addr: SocketAddr,
    payload: &[u8],
    pacer: &AsyncMutex<PublicRatePacer>,
    counters: &WorkloadCounters,
) -> LabResult<()> {
    let mut stream = TcpStream::connect(client_addr).await?;
    let mut offset = 0;
    while offset < payload.len() {
        let chunk_end = payload
            .len()
            .min(offset.saturating_add(PUBLIC_SOAK_WRITE_CHUNK_BYTES));
        PublicRatePacer::wait_for_bytes(pacer, chunk_end - offset).await;
        while offset < chunk_end {
            let written = stream.write(&payload[offset..chunk_end]).await?;
            if written == 0 {
                return Err(other_error("公网 soak 写入代理时返回零字节"));
            }
            offset = offset.saturating_add(written);
            counters
                .sent_bytes
                .fetch_add(written as u64, Ordering::Relaxed);
        }
    }
    stream.shutdown().await?;

    let mut echoed = Vec::with_capacity(payload.len());
    let mut buffer = [0_u8; PUBLIC_SOAK_WRITE_CHUNK_BYTES];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        if echoed.len().saturating_add(read) > payload.len() {
            return Err(other_error("公网 soak 收到超出请求长度的回显"));
        }
        echoed.extend_from_slice(&buffer[..read]);
        counters
            .echoed_bytes
            .fetch_add(read as u64, Ordering::Relaxed);
    }
    if echoed != payload {
        return Err(other_error("公网 soak 流回显内容不完整"));
    }
    Ok(())
}

fn reserve_application_budget(reserved: &AtomicU64, bytes: u64, budget: u64) -> bool {
    let mut current = reserved.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(bytes) else {
            return false;
        };
        if next > budget {
            return false;
        }
        match reserved.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn request_public_soak_stop(
    stop_code: &AtomicU8,
    reason: ProxyPublicSoakStopReason,
    stop: &watch::Sender<bool>,
) {
    if stop_code
        .compare_exchange(0, reason as u8, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        let _ = stop.send(true);
    }
}

fn public_soak_snapshot_json(
    event: &'static str,
    elapsed: Duration,
    config: ProxyPublicSoakConfig,
    counters: &WorkloadCounters,
) -> Value {
    let elapsed_ms = duration_millis(elapsed);
    let reserved_application_bytes = counters.reserved_application_bytes.load(Ordering::Relaxed);
    let sent_bytes = counters.sent_bytes.load(Ordering::Relaxed);
    json!({
        "schema": PROXY_PUBLIC_SOAK_REPORT_SCHEMA,
        "event": event,
        "ts_unix_ms": system_timestamp_millis(),
        "elapsed_ms": elapsed_ms,
        "attempted_flows": counters.attempted_flows.load(Ordering::Relaxed),
        "completed_flows": counters.completed_flows.load(Ordering::Relaxed),
        "failed_flows": counters.failed_flows.load(Ordering::Relaxed),
        "timed_out_flows": counters.timed_out_flows.load(Ordering::Relaxed),
        "reserved_application_bytes": reserved_application_bytes,
        "remaining_application_byte_budget": config
            .application_byte_budget
            .saturating_sub(reserved_application_bytes),
        "sent_bytes": sent_bytes,
        "echoed_bytes": counters.echoed_bytes.load(Ordering::Relaxed),
        "average_upload_rate_bps": average_rate_bps(sent_bytes, elapsed_ms),
    })
}

async fn run_soak_flow(client_addr: SocketAddr, payload: &[u8]) -> LabResult<()> {
    let mut stream = TcpStream::connect(client_addr).await?;
    stream.write_all(payload).await?;
    stream.shutdown().await?;
    let mut echoed = Vec::with_capacity(payload.len());
    stream
        .take(
            u64::try_from(payload.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut echoed)
        .await?;
    if echoed != payload {
        return Err(other_error("soak 流回显内容不完整"));
    }
    Ok(())
}

async fn run_echo_server(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> LabResult<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            joined = connections.join_next(), if !connections.is_empty() => {
                joined
                    .ok_or_else(|| other_error("soak echo 任务集合意外为空"))?
                    .map_err(|error| other_error(format!("soak echo 连接任务异常退出：{error}")))??;
            }
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                connections.spawn(async move {
                    let (mut read, mut write) = stream.split();
                    tokio::io::copy(&mut read, &mut write).await?;
                    write.shutdown().await
                });
            }
        }
    }
    drop(listener);
    while let Some(result) = connections.join_next().await {
        result.map_err(|error| other_error(format!("soak echo 连接任务异常退出：{error}")))??;
    }
    Ok(())
}

pub async fn run_proxy_soak_echo_server(listen: SocketAddr) -> LabResult<()> {
    if !listen.ip().is_loopback() {
        return Err(other_error(
            "公网 soak echo 服务只能绑定 loopback，由固定目标代理访问",
        ));
    }
    let listener = TcpListener::bind(listen).await?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let mut echo_task = tokio::spawn(run_echo_server(listener, shutdown_rx));
    tokio::select! {
        result = &mut echo_task => {
            result
                .map_err(|error| other_error(format!("公网 soak echo 任务异常退出：{error}")))??;
        }
        signal = wait_for_soak_shutdown_signal() => {
            signal?;
            let _ = shutdown.send(true);
            match timeout(FLOW_TIMEOUT, &mut echo_task).await {
                Ok(result) => {
                    result
                        .map_err(|error| other_error(format!("公网 soak echo 任务异常退出：{error}")))??;
                }
                Err(_) => {
                    echo_task.abort();
                    let _ = echo_task.await;
                    return Err(other_error("公网 soak echo 服务退出 drain 超时"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_for_soak_shutdown_signal() -> LabResult<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_soak_shutdown_signal() -> LabResult<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn make_payload(worker_id: usize, sequence: u64, length: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(length);
    for index in 0..length {
        let mixed = (index as u64)
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(sequence.rotate_left(17))
            .wrapping_add((worker_id as u64).rotate_left(9));
        payload.push((mixed ^ (mixed >> 8) ^ (mixed >> 24)) as u8);
    }
    payload
}

fn application_bytes_per_flow(payload_bytes: usize) -> LabResult<u64> {
    u64::try_from(payload_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(|| other_error("公网 soak 单流应用字节数溢出"))
}

fn duration_for_rate(bytes: u128, bits_per_second: u64) -> Duration {
    let numerator = bytes.saturating_mul(8).saturating_mul(1_000_000_000);
    let denominator = u128::from(bits_per_second.max(1));
    let nanos = numerator.saturating_add(denominator.saturating_sub(1)) / denominator;
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

fn average_rate_bps(bytes: u64, elapsed_ms: u64) -> u64 {
    if elapsed_ms == 0 {
        return 0;
    }
    let bits_millis = u128::from(bytes).saturating_mul(8).saturating_mul(1_000);
    u64::try_from(bits_millis / u128::from(elapsed_ms)).unwrap_or(u64::MAX)
}

fn system_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn metrics_are_clean(metrics: ProxyMetricsSnapshot, completed_flows: u64, bytes: u64) -> bool {
    metrics.active_connections == 0
        && metrics.active_streams == 0
        && metrics.total_connections == 1
        && metrics.total_streams == completed_flows
        && metrics.connection_rejects == 0
        && metrics.stream_rejects == 0
        && metrics.dns_timeouts == 0
        && metrics.handshake_timeouts == 0
        && metrics.request_timeouts == 0
        && metrics.stream_open_timeouts == 0
        && metrics.upstream_connect_timeouts == 0
        && metrics.upstream_errors == 0
        && metrics.upload_bytes == bytes
        && metrics.download_bytes == bytes
        && metrics.graceful_shutdowns == 1
        && metrics.forced_shutdowns == 0
}

fn write_credentials(directory: &SoakDirectory) -> LabResult<(PathBuf, PathBuf, PathBuf)> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate_path = directory.path().join("certificate.der");
    let key_path = directory.path().join("private-key.der");
    let token_path = directory.path().join("token");
    fs::write(&certificate_path, generated.cert.der())?;
    fs::write(&key_path, generated.signing_key.serialize_der())?;
    fs::write(&token_path, [0xA5_u8; 48])?;
    set_private_permissions(&key_path)?;
    set_private_permissions(&token_path)?;
    Ok((certificate_path, key_path, token_path))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn metrics_to_json(metrics: ProxyMetricsSnapshot) -> Value {
    json!({
        "active_connections": metrics.active_connections,
        "total_connections": metrics.total_connections,
        "connection_rejects": metrics.connection_rejects,
        "active_streams": metrics.active_streams,
        "total_streams": metrics.total_streams,
        "stream_rejects": metrics.stream_rejects,
        "dns_timeouts": metrics.dns_timeouts,
        "handshake_timeouts": metrics.handshake_timeouts,
        "request_timeouts": metrics.request_timeouts,
        "stream_open_timeouts": metrics.stream_open_timeouts,
        "upstream_connect_timeouts": metrics.upstream_connect_timeouts,
        "upstream_errors": metrics.upstream_errors,
        "upload_bytes": metrics.upload_bytes,
        "download_bytes": metrics.download_bytes,
        "graceful_shutdowns": metrics.graceful_shutdowns,
        "forced_shutdowns": metrics.forced_shutdowns,
    })
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> LabResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> LabResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> LabResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> LabResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soak_config_rejects_unsafe_resource_values() {
        assert!(
            ProxySoakConfig {
                workers: 0,
                ..ProxySoakConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ProxySoakConfig {
                payload_bytes: MAX_SOAK_PAYLOAD_BYTES + 1,
                ..ProxySoakConfig::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn public_soak_config_requires_loopback_budget_and_bounded_pacing() {
        assert!(
            ProxyPublicSoakConfig {
                client_addr: "192.0.2.1:10080".parse().unwrap(),
                ..ProxyPublicSoakConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ProxyPublicSoakConfig {
                application_byte_budget: 1,
                ..ProxyPublicSoakConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ProxyPublicSoakConfig {
                payload_bytes: MAX_SOAK_PAYLOAD_BYTES,
                upload_rate_bps: 512_000,
                application_byte_budget: (MAX_SOAK_PAYLOAD_BYTES as u64) * 2,
                ..ProxyPublicSoakConfig::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn application_budget_reservation_never_crosses_cap() {
        let reserved = AtomicU64::new(0);
        assert!(reserve_application_budget(&reserved, 2_048, 4_096));
        assert!(reserve_application_budget(&reserved, 2_048, 4_096));
        assert!(!reserve_application_budget(&reserved, 1, 4_096));
        assert_eq!(reserved.load(Ordering::Relaxed), 4_096);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn short_soak_closes_every_lifecycle_and_preserves_bytes() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = timeout(
            Duration::from_secs(10),
            run_proxy_soak(ProxySoakConfig {
                duration: Duration::from_millis(250),
                workers: 2,
                payload_bytes: 4096,
                inter_flow_delay: Duration::from_millis(5),
                multipath: true,
            }),
        )
        .await
        .expect("短时 soak 必须受测试截止约束")
        .unwrap();
        assert!(report.stage_pass, "{}", report.to_json());
        assert!(report.completed_flows > 0);
        assert_eq!(report.failed_flows, 0);
        assert_eq!(report.sent_bytes, report.echoed_bytes);
        assert!(report.health.healthy);
        assert_eq!(report.client_metrics.active_streams, 0);
        assert_eq!(report.server_metrics.active_connections, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn public_soak_stops_at_budget_and_emits_checkpoints() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = listener.local_addr().unwrap();
        let (echo_shutdown, echo_shutdown_rx) = watch::channel(false);
        let echo_task = tokio::spawn(run_echo_server(listener, echo_shutdown_rx));
        let mut checkpoints = Vec::new();
        let report = timeout(
            Duration::from_secs(5),
            run_proxy_public_soak_with_checkpoints(
                ProxyPublicSoakConfig {
                    client_addr,
                    duration: Duration::from_secs(2),
                    workers: 1,
                    payload_bytes: 1_024,
                    upload_rate_bps: 100_000_000,
                    application_byte_budget: 8_192,
                    checkpoint_interval: Duration::from_millis(20),
                },
                |checkpoint| checkpoints.push(checkpoint),
            ),
        )
        .await
        .expect("公网 workload 必须受测试截止约束")
        .unwrap();
        let _ = echo_shutdown.send(true);
        echo_task.await.unwrap().unwrap();

        assert!(report.stage_pass, "{}", report.to_json());
        assert_eq!(
            report.stop_reason,
            ProxyPublicSoakStopReason::ApplicationByteBudgetExhausted
        );
        assert_eq!(report.attempted_flows, 4);
        assert_eq!(report.completed_flows, 4);
        assert_eq!(report.failed_flows, 0);
        assert_eq!(report.reserved_application_bytes, 8_192);
        assert_eq!(report.sent_bytes, 4_096);
        assert_eq!(report.echoed_bytes, 4_096);
        assert_eq!(checkpoints[0]["event"], "started");
        assert!(
            checkpoints
                .iter()
                .any(|checkpoint| checkpoint["event"] == "budget_exhausted")
        );
    }
}

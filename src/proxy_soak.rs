use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::{Instant, sleep, timeout},
};

use super::{
    LabResult, ProxyClientConfig, ProxyHealthPolicy, ProxyHealthReport, ProxyMetricsSnapshot,
    ProxyObservation, ProxyServerConfig, other_error,
    proxy::{ProxyEventSink, start_proxy_client_with_sink, start_proxy_server_with_sink},
};

pub const PROXY_SOAK_REPORT_SCHEMA: &str = "flowweave.proxy-soak.v1";
const FLOW_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SOAK_DURATION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_SOAK_WORKERS: usize = 64;
const MAX_SOAK_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

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
    sent_bytes: AtomicU64,
    echoed_bytes: AtomicU64,
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
}

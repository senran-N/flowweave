use std::{
    collections::{HashMap, HashSet},
    fmt, fs, io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(not(test))]
use std::io::Write as _;

use noq::{
    ClientConfig, Connection, ConnectionError, Endpoint, FourTuple, PathError, PathEvent, PathId,
    PathStatus, ServerConfig, TransportConfig,
    rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};
use noq_proto::PathAbandonReason;
use serde_json::{Map, Value, json};
use subtle::ConstantTimeEq;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, lookup_host},
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, interval_at, sleep, timeout},
};
use tokio_stream::StreamExt;

use super::{
    LabResult, MultipathScheduler, PtoRecovery, QuicCongestion, configure_transport, other_error,
};

const PROXY_MAGIC: &[u8; 4] = b"FWX1";
const MIN_TOKEN_LENGTH: usize = 32;
const MAX_TOKEN_LENGTH: usize = 256;
const MAX_TARGET_LENGTH: usize = 128;
const MAX_PRODUCT_PATHS: usize = 8;
const PRODUCT_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
const PRODUCT_MAX_SERVER_CONNECTIONS: usize = 64;
const PRODUCT_MAX_STREAMS_PER_CONNECTION: u32 = 64;
const PRODUCT_MAX_CLIENT_STREAMS: usize = 64;
const PRODUCT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const PRODUCT_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_METRICS_INTERVAL: Duration = Duration::from_secs(10);
pub const PROXY_EVENT_SCHEMA: &str = "flowweave.runtime.v1";

const STATUS_OK: u8 = 0;
const STATUS_VERSION: u8 = 1;
const STATUS_FORMAT: u8 = 2;
const STATUS_AUTHORIZATION: u8 = 3;
const STATUS_TARGET: u8 = 4;
const STATUS_UPSTREAM: u8 = 5;

const SERVER_REQUIRED_KEYS: [&str; 5] = [
    "listen",
    "certificate_der",
    "private_key_der",
    "token_file",
    "allowed_target",
];
const SERVER_OPTIONAL_KEYS: [&str; 1] = ["previous_token_file"];
const CLIENT_REQUIRED_KEYS: [&str; 6] = [
    "listen",
    "server",
    "server_name",
    "ca_certificate_der",
    "token_file",
    "target",
];
const CLIENT_OPTIONAL_KEYS: [&str; 2] = ["primary_local_ip", "additional_local_ips"];

#[derive(Debug, Clone, Copy)]
struct ProxyRuntimeLimits {
    max_server_connections: usize,
    max_streams_per_connection: u32,
    max_client_streams: usize,
    handshake_timeout: Duration,
    request_timeout: Duration,
    upstream_connect_timeout: Duration,
    stream_open_timeout: Duration,
    shutdown_drain_timeout: Duration,
    metrics_interval: Duration,
}

const PRODUCT_RUNTIME_LIMITS: ProxyRuntimeLimits = ProxyRuntimeLimits {
    max_server_connections: PRODUCT_MAX_SERVER_CONNECTIONS,
    max_streams_per_connection: PRODUCT_MAX_STREAMS_PER_CONNECTION,
    max_client_streams: PRODUCT_MAX_CLIENT_STREAMS,
    handshake_timeout: PRODUCT_HANDSHAKE_TIMEOUT,
    request_timeout: PRODUCT_REQUEST_TIMEOUT,
    upstream_connect_timeout: PRODUCT_UPSTREAM_CONNECT_TIMEOUT,
    stream_open_timeout: PRODUCT_STREAM_OPEN_TIMEOUT,
    shutdown_drain_timeout: PRODUCT_SHUTDOWN_DRAIN_TIMEOUT,
    metrics_interval: PRODUCT_METRICS_INTERVAL,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyMetricsSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    pub connection_rejects: u64,
    pub active_streams: u64,
    pub total_streams: u64,
    pub stream_rejects: u64,
    pub dns_timeouts: u64,
    pub handshake_timeouts: u64,
    pub request_timeouts: u64,
    pub stream_open_timeouts: u64,
    pub upstream_connect_timeouts: u64,
    pub upstream_errors: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub graceful_shutdowns: u64,
    pub forced_shutdowns: u64,
}

#[derive(Debug, Default)]
struct ProxyMetrics {
    active_connections: AtomicU64,
    total_connections: AtomicU64,
    connection_rejects: AtomicU64,
    active_streams: AtomicU64,
    total_streams: AtomicU64,
    stream_rejects: AtomicU64,
    dns_timeouts: AtomicU64,
    handshake_timeouts: AtomicU64,
    request_timeouts: AtomicU64,
    stream_open_timeouts: AtomicU64,
    upstream_connect_timeouts: AtomicU64,
    upstream_errors: AtomicU64,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    graceful_shutdowns: AtomicU64,
    forced_shutdowns: AtomicU64,
}

impl ProxyMetrics {
    fn snapshot(&self) -> ProxyMetricsSnapshot {
        ProxyMetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            connection_rejects: self.connection_rejects.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            total_streams: self.total_streams.load(Ordering::Relaxed),
            stream_rejects: self.stream_rejects.load(Ordering::Relaxed),
            dns_timeouts: self.dns_timeouts.load(Ordering::Relaxed),
            handshake_timeouts: self.handshake_timeouts.load(Ordering::Relaxed),
            request_timeouts: self.request_timeouts.load(Ordering::Relaxed),
            stream_open_timeouts: self.stream_open_timeouts.load(Ordering::Relaxed),
            upstream_connect_timeouts: self.upstream_connect_timeouts.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            upload_bytes: self.upload_bytes.load(Ordering::Relaxed),
            download_bytes: self.download_bytes.load(Ordering::Relaxed),
            graceful_shutdowns: self.graceful_shutdowns.load(Ordering::Relaxed),
            forced_shutdowns: self.forced_shutdowns.load(Ordering::Relaxed),
        }
    }

    fn start_connection(self: &Arc<Self>) -> ActiveMetricGuard {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ActiveMetricGuard {
            metrics: self.clone(),
            kind: ActiveMetricKind::Connection,
        }
    }

    fn start_stream(self: &Arc<Self>) -> ActiveMetricGuard {
        self.total_streams.fetch_add(1, Ordering::Relaxed);
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        ActiveMetricGuard {
            metrics: self.clone(),
            kind: ActiveMetricKind::Stream,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ActiveMetricKind {
    Connection,
    Stream,
}

#[derive(Debug)]
struct ActiveMetricGuard {
    metrics: Arc<ProxyMetrics>,
    kind: ActiveMetricKind,
}

impl Drop for ActiveMetricGuard {
    fn drop(&mut self) {
        let metric = match self.kind {
            ActiveMetricKind::Connection => &self.metrics.active_connections,
            ActiveMetricKind::Stream => &self.metrics.active_streams,
        };
        metric.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) trait ProxyEventSink: Send + Sync {
    fn write_line(&self, line: &str);
}

#[cfg(not(test))]
#[derive(Debug)]
struct StderrEventSink;

#[cfg(not(test))]
impl ProxyEventSink for StderrEventSink {
    fn write_line(&self, line: &str) {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        let _ = stderr.write_all(line.as_bytes());
        let _ = stderr.write_all(b"\n");
    }
}

#[cfg(test)]
#[derive(Debug)]
struct NullEventSink;

#[cfg(test)]
impl ProxyEventSink for NullEventSink {
    fn write_line(&self, _line: &str) {}
}

#[cfg(not(test))]
fn default_event_sink() -> Arc<dyn ProxyEventSink> {
    Arc::new(StderrEventSink)
}

#[cfg(test)]
fn default_event_sink() -> Arc<dyn ProxyEventSink> {
    Arc::new(NullEventSink)
}

#[derive(Clone)]
struct ProxyEventLog {
    role: &'static str,
    sink: Arc<dyn ProxyEventSink>,
}

struct ProxyRuntimeContext {
    limits: ProxyRuntimeLimits,
    shutdown: watch::Receiver<bool>,
    metrics: Arc<ProxyMetrics>,
    events: ProxyEventLog,
}

impl ProxyEventLog {
    fn new(role: &'static str, sink: Arc<dyn ProxyEventSink>) -> Self {
        Self { role, sink }
    }

    fn emit(&self, level: &'static str, event: &'static str, fields: Value) {
        let mut record = Map::new();
        record.insert(
            "schema".to_owned(),
            Value::String(PROXY_EVENT_SCHEMA.to_owned()),
        );
        record.insert("ts_unix_ms".to_owned(), json!(unix_timestamp_millis()));
        record.insert("level".to_owned(), Value::String(level.to_owned()));
        record.insert("role".to_owned(), Value::String(self.role.to_owned()));
        record.insert("event".to_owned(), Value::String(event.to_owned()));
        if let Value::Object(fields) = fields {
            record.extend(fields);
        }
        if let Ok(line) = serde_json::to_string(&record) {
            self.sink.write_line(&line);
        }
    }

    fn emit_metrics(&self, metrics: &ProxyMetrics) {
        self.emit(
            "info",
            "metrics_snapshot",
            metrics_snapshot_json(metrics.snapshot()),
        );
    }
}

fn unix_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn metrics_snapshot_json(snapshot: ProxyMetricsSnapshot) -> Value {
    json!({
        "active_connections": snapshot.active_connections,
        "total_connections": snapshot.total_connections,
        "connection_rejects": snapshot.connection_rejects,
        "active_streams": snapshot.active_streams,
        "total_streams": snapshot.total_streams,
        "stream_rejects": snapshot.stream_rejects,
        "dns_timeouts": snapshot.dns_timeouts,
        "handshake_timeouts": snapshot.handshake_timeouts,
        "request_timeouts": snapshot.request_timeouts,
        "stream_open_timeouts": snapshot.stream_open_timeouts,
        "upstream_connect_timeouts": snapshot.upstream_connect_timeouts,
        "upstream_errors": snapshot.upstream_errors,
        "upload_bytes": snapshot.upload_bytes,
        "download_bytes": snapshot.download_bytes,
        "graceful_shutdowns": snapshot.graceful_shutdowns,
        "forced_shutdowns": snapshot.forced_shutdowns,
    })
}

#[derive(Debug, Clone, Copy)]
struct ProxyTaskError {
    code: &'static str,
}

impl ProxyTaskError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

impl fmt::Display for ProxyTaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for ProxyTaskError {}

type ProxyTaskResult<T> = Result<T, ProxyTaskError>;

trait RuntimeCode<T> {
    fn runtime_code(self, code: &'static str) -> ProxyTaskResult<T>;
}

impl<T, E> RuntimeCode<T> for Result<T, E> {
    fn runtime_code(self, code: &'static str) -> ProxyTaskResult<T> {
        self.map_err(|_| ProxyTaskError::new(code))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyServerConfig {
    pub listen: SocketAddr,
    pub certificate_der: PathBuf,
    pub private_key_der: PathBuf,
    pub token_file: PathBuf,
    pub previous_token_file: Option<PathBuf>,
    pub allowed_target: SocketAddr,
}

impl ProxyServerConfig {
    pub fn load(path: impl AsRef<Path>) -> LabResult<Self> {
        let path = path.as_ref();
        let values = load_key_values(path, &SERVER_REQUIRED_KEYS, &SERVER_OPTIONAL_KEYS)?;
        let base = config_base(path);
        Ok(Self {
            listen: parse_socket_addr(required(&values, "listen")?, "listen")?,
            certificate_der: resolve_path(&base, required(&values, "certificate_der")?),
            private_key_der: resolve_path(&base, required(&values, "private_key_der")?),
            token_file: resolve_path(&base, required(&values, "token_file")?),
            previous_token_file: values
                .get("previous_token_file")
                .map(|value| resolve_path(&base, value)),
            allowed_target: parse_socket_addr(
                required(&values, "allowed_target")?,
                "allowed_target",
            )?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyClientConfig {
    pub listen: SocketAddr,
    pub server: String,
    pub server_name: String,
    pub ca_certificate_der: PathBuf,
    pub token_file: PathBuf,
    pub target: SocketAddr,
    pub primary_local_ip: Option<IpAddr>,
    pub additional_local_ips: Vec<IpAddr>,
}

impl ProxyClientConfig {
    pub fn load(path: impl AsRef<Path>) -> LabResult<Self> {
        let path = path.as_ref();
        let values = load_key_values(path, &CLIENT_REQUIRED_KEYS, &CLIENT_OPTIONAL_KEYS)?;
        let base = config_base(path);
        let listen = parse_socket_addr(required(&values, "listen")?, "listen")?;
        if !listen.ip().is_loopback() {
            return Err(other_error("客户端 listen 必须是 loopback 地址"));
        }

        let primary_local_ip = values
            .get("primary_local_ip")
            .map(|value| parse_local_ip(value, "primary_local_ip"))
            .transpose()?;
        let additional_local_ips = match values.get("additional_local_ips") {
            Some(value) => parse_additional_ips(value)?,
            None => Vec::new(),
        };
        validate_local_ips(primary_local_ip, &additional_local_ips)?;

        Ok(Self {
            listen,
            server: required(&values, "server")?.to_owned(),
            server_name: required(&values, "server_name")?.to_owned(),
            ca_certificate_der: resolve_path(&base, required(&values, "ca_certificate_der")?),
            token_file: resolve_path(&base, required(&values, "token_file")?),
            target: parse_socket_addr(required(&values, "target")?, "target")?,
            primary_local_ip,
            additional_local_ips,
        })
    }
}

type SharedServerTokens = Arc<RwLock<Vec<Vec<u8>>>>;
type SharedClientToken = Arc<RwLock<Vec<u8>>>;

enum ProxyTokenReloader {
    Server {
        token_file: PathBuf,
        previous_token_file: Option<PathBuf>,
        tokens: SharedServerTokens,
    },
    Client {
        token_file: PathBuf,
        token: SharedClientToken,
    },
}

impl ProxyTokenReloader {
    fn reload(&self) -> LabResult<usize> {
        match self {
            Self::Server {
                token_file,
                previous_token_file,
                tokens,
            } => {
                let replacement = read_server_tokens(token_file, previous_token_file.as_deref())?;
                let accepted_token_count = replacement.len();
                let mut current = tokens
                    .write()
                    .map_err(|_| other_error("服务端令牌状态锁已损坏"))?;
                *current = replacement;
                Ok(accepted_token_count)
            }
            Self::Client { token_file, token } => {
                let replacement = read_token(token_file)?;
                let mut current = token
                    .write()
                    .map_err(|_| other_error("客户端令牌状态锁已损坏"))?;
                *current = replacement;
                Ok(1)
            }
        }
    }
}

pub struct ProxyRuntime {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    metrics: Arc<ProxyMetrics>,
    token_reloader: ProxyTokenReloader,
    events: ProxyEventLog,
    task: Option<JoinHandle<LabResult<()>>>,
}

impl fmt::Debug for ProxyRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyRuntime")
            .field("local_addr", &self.local_addr)
            .field("metrics", &self.metrics.snapshot())
            .field("task_running", &self.task.is_some())
            .finish_non_exhaustive()
    }
}

impl ProxyRuntime {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn metrics_snapshot(&self) -> ProxyMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn reload_tokens(&self) -> LabResult<usize> {
        match self.token_reloader.reload() {
            Ok(accepted_token_count) => {
                self.events.emit(
                    "info",
                    "credentials_reloaded",
                    json!({
                        "kind": "token",
                        "accepted_token_count": accepted_token_count,
                    }),
                );
                Ok(accepted_token_count)
            }
            Err(error) => {
                self.events.emit(
                    "error",
                    "credentials_reload_failed",
                    json!({"kind": "token", "reason": "token_reload_failed"}),
                );
                Err(error)
            }
        }
    }

    async fn join(&mut self) -> LabResult<()> {
        let result = self
            .task
            .as_mut()
            .ok_or_else(|| other_error("代理运行任务已经结束"))?
            .await
            .map_err(|error| other_error(format!("代理运行任务异常退出：{error}")))?;
        self.task.take();
        result
    }

    pub async fn wait(mut self) -> LabResult<()> {
        self.join().await
    }

    pub async fn shutdown(mut self) -> ProxyMetricsSnapshot {
        self.request_shutdown();
        let _ = self.join().await;
        self.metrics.snapshot()
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

pub async fn run_proxy_server(path: impl AsRef<Path>) -> LabResult<()> {
    let runtime = start_proxy_server(ProxyServerConfig::load(path)?).await?;
    run_runtime_until_signal(runtime).await
}

pub async fn run_proxy_client(path: impl AsRef<Path>) -> LabResult<()> {
    let runtime = start_proxy_client(ProxyClientConfig::load(path)?).await?;
    run_runtime_until_signal(runtime).await
}

#[cfg(unix)]
async fn run_runtime_until_signal(mut runtime: ProxyRuntime) -> LabResult<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    loop {
        tokio::select! {
            biased;
            result = runtime.join() => return result,
            result = &mut interrupt => {
                result?;
                break;
            }
            received = terminate.recv() => {
                if received.is_none() {
                    return Err(other_error("SIGTERM 监听流意外结束"));
                }
                break;
            }
            received = hangup.recv() => {
                if received.is_none() {
                    return Err(other_error("SIGHUP 监听流意外结束"));
                }
                let _ = runtime.reload_tokens();
            }
        }
    }
    runtime.request_shutdown();
    runtime.join().await
}

#[cfg(not(unix))]
async fn run_runtime_until_signal(mut runtime: ProxyRuntime) -> LabResult<()> {
    tokio::select! {
        result = runtime.join() => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            runtime.request_shutdown();
            runtime.join().await
        }
    }
}

pub async fn start_proxy_server(config: ProxyServerConfig) -> LabResult<ProxyRuntime> {
    start_proxy_server_with_limits(config, PRODUCT_RUNTIME_LIMITS).await
}

pub(crate) async fn start_proxy_server_with_sink(
    config: ProxyServerConfig,
    sink: Arc<dyn ProxyEventSink>,
) -> LabResult<ProxyRuntime> {
    start_proxy_server_with_limits_and_sink(config, PRODUCT_RUNTIME_LIMITS, sink).await
}

async fn start_proxy_server_with_limits(
    config: ProxyServerConfig,
    limits: ProxyRuntimeLimits,
) -> LabResult<ProxyRuntime> {
    start_proxy_server_with_limits_and_sink(config, limits, default_event_sink()).await
}

async fn start_proxy_server_with_limits_and_sink(
    config: ProxyServerConfig,
    limits: ProxyRuntimeLimits,
    sink: Arc<dyn ProxyEventSink>,
) -> LabResult<ProxyRuntime> {
    let metrics = Arc::new(ProxyMetrics::default());
    let events = ProxyEventLog::new("server", sink);
    let certificate = read_certificate(&config.certificate_der)?;
    let private_key = read_private_key(&config.private_key_der)?;
    let tokens = Arc::new(RwLock::new(read_server_tokens(
        &config.token_file,
        config.previous_token_file.as_deref(),
    )?));
    let token_reloader = ProxyTokenReloader::Server {
        token_file: config.token_file.clone(),
        previous_token_file: config.previous_token_file.clone(),
        tokens: tokens.clone(),
    };

    let mut server_config = ServerConfig::with_single_cert(vec![certificate], private_key.into())?;
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| other_error("无法配置服务端产品传输参数"))?;
    configure_product_transport(
        transport,
        (MAX_PRODUCT_PATHS + 1) as u32,
        limits.max_streams_per_connection,
    );

    let endpoint = Endpoint::server(server_config, config.listen)?;
    let local_addr = endpoint.local_addr()?;
    let allowed_target = config.allowed_target;
    let (shutdown, shutdown_rx) = watch::channel(false);
    events.emit(
        "info",
        "runtime_started",
        json!({"listen": local_addr.to_string(), "transport": "udp"}),
    );
    let task_metrics = metrics.clone();
    let runtime_events = events.clone();
    let task = tokio::spawn(async move {
        run_server_accept_loop(
            endpoint,
            tokens,
            allowed_target,
            ProxyRuntimeContext {
                limits,
                shutdown: shutdown_rx,
                metrics: task_metrics,
                events,
            },
        )
        .await
    });
    Ok(ProxyRuntime {
        local_addr,
        shutdown,
        metrics,
        token_reloader,
        events: runtime_events,
        task: Some(task),
    })
}

pub async fn start_proxy_client(config: ProxyClientConfig) -> LabResult<ProxyRuntime> {
    start_proxy_client_with_limits(config, PRODUCT_RUNTIME_LIMITS).await
}

pub(crate) async fn start_proxy_client_with_sink(
    config: ProxyClientConfig,
    sink: Arc<dyn ProxyEventSink>,
) -> LabResult<ProxyRuntime> {
    start_proxy_client_with_limits_and_sink(config, PRODUCT_RUNTIME_LIMITS, sink).await
}

async fn start_proxy_client_with_limits(
    config: ProxyClientConfig,
    limits: ProxyRuntimeLimits,
) -> LabResult<ProxyRuntime> {
    start_proxy_client_with_limits_and_sink(config, limits, default_event_sink()).await
}

async fn start_proxy_client_with_limits_and_sink(
    config: ProxyClientConfig,
    limits: ProxyRuntimeLimits,
    sink: Arc<dyn ProxyEventSink>,
) -> LabResult<ProxyRuntime> {
    let metrics = Arc::new(ProxyMetrics::default());
    let events = ProxyEventLog::new("client", sink);
    let certificate = read_certificate(&config.ca_certificate_der)?;
    let token = Arc::new(RwLock::new(read_token(&config.token_file)?));
    let token_reloader = ProxyTokenReloader::Client {
        token_file: config.token_file.clone(),
        token: token.clone(),
    };
    let server_addr = match timeout(limits.handshake_timeout, resolve_server_addr(&config)).await {
        Ok(result) => result?,
        Err(_) => {
            metrics.dns_timeouts.fetch_add(1, Ordering::Relaxed);
            events.emit("error", "startup_failed", json!({"reason": "dns_timeout"}));
            return Err(other_error("解析服务端地址超时"));
        }
    };
    let replace_bootstrap_path =
        config.primary_local_ip.is_some() && !config.additional_local_ips.is_empty();
    let bind_ip = if replace_bootstrap_path {
        unspecified_for(server_addr.ip())
    } else {
        config
            .primary_local_ip
            .unwrap_or_else(|| unspecified_for(server_addr.ip()))
    };
    let endpoint = Endpoint::client(SocketAddr::new(bind_ip, 0))?;

    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;
    let mut transport = TransportConfig::default();
    let transient_path_count =
        config.additional_local_ips.len() + 1 + usize::from(replace_bootstrap_path);
    let path_count = u32::try_from(transient_path_count)
        .map_err(|_| other_error("additional_local_ips 数量过多"))?;
    configure_product_transport(&mut transport, path_count, 0);
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(server_addr, &config.server_name)
        .map_err(|error| other_error(format!("客户端无法开始 TLS 连接：{error}")))?;
    let connection = match timeout(limits.handshake_timeout, connecting).await {
        Ok(result) => result?,
        Err(_) => {
            metrics.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
            events.emit(
                "error",
                "startup_failed",
                json!({"reason": "handshake_timeout"}),
            );
            return Err(other_error("客户端 TLS 连接超时"));
        }
    };
    if !connection.is_multipath_enabled() {
        connection.close(0_u8.into(), b"multipath negotiation failed");
        return Err(other_error("客户端和服务端没有协商成功 MPQUIC"));
    }
    match timeout(limits.handshake_timeout, connection.handshake_confirmed()).await {
        Ok(result) => result?,
        Err(_) => {
            metrics.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
            events.emit(
                "error",
                "startup_failed",
                json!({"reason": "handshake_confirmation_timeout"}),
            );
            return Err(other_error("客户端等待 TLS 确认超时"));
        }
    }

    let configured_paths = config
        .primary_local_ip
        .filter(|_| replace_bootstrap_path)
        .into_iter()
        .chain(config.additional_local_ips.iter().copied());
    for local_ip in configured_paths {
        open_configured_path(&connection, server_addr, local_ip)
            .await
            .inspect_err(|_| {
                connection.close(0_u8.into(), b"configured path failed");
            })?;
    }
    if replace_bootstrap_path {
        connection
            .path(PathId::ZERO)
            .ok_or_else(|| other_error("多路径启动后找不到临时引导路径"))?
            .close()
            .map_err(|error| {
                connection.close(0_u8.into(), b"bootstrap path close failed");
                other_error(format!("无法释放临时引导路径：{error}"))
            })?;
    }

    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let target = config.target;
    let (shutdown, shutdown_rx) = watch::channel(false);
    events.emit(
        "info",
        "runtime_started",
        json!({"listen": local_addr.to_string(), "transport": "tcp"}),
    );
    let task_metrics = metrics.clone();
    let runtime_events = events.clone();
    let task = tokio::spawn(async move {
        run_client_accept_loop(
            endpoint,
            connection,
            listener,
            token,
            target,
            ProxyRuntimeContext {
                limits,
                shutdown: shutdown_rx,
                metrics: task_metrics,
                events,
            },
        )
        .await
    });
    Ok(ProxyRuntime {
        local_addr,
        shutdown,
        metrics,
        token_reloader,
        events: runtime_events,
        task: Some(task),
    })
}

async fn open_configured_path(
    connection: &Connection,
    server_addr: SocketAddr,
    local_ip: IpAddr,
) -> LabResult<()> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match connection
            .open_path(
                FourTuple::new(server_addr, Some(local_ip)),
                PathStatus::Available,
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(PathError::RemoteCidsExhausted) if Instant::now() < deadline => {
                sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(other_error(format!(
                    "无法打开配置的本地路径 {local_ip}：{error}"
                )));
            }
        }
    }
}

async fn run_server_accept_loop(
    endpoint: Endpoint,
    tokens: SharedServerTokens,
    allowed_target: SocketAddr,
    runtime: ProxyRuntimeContext,
) -> LabResult<()> {
    let ProxyRuntimeContext {
        limits,
        mut shutdown,
        metrics,
        events,
    } = runtime;
    let connection_slots = Arc::new(Semaphore::new(limits.max_server_connections));
    let mut connection_tasks = JoinSet::new();
    let mut metrics_tick = interval_at(
        Instant::now() + limits.metrics_interval,
        limits.metrics_interval,
    );
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            joined = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    events.emit(
                        "error",
                        "connection_task_failed",
                        json!({"reason": "task_panic"}),
                    );
                }
            }
            _ = metrics_tick.tick() => events.emit_metrics(&metrics),
            incoming = endpoint.accept() => {
                let incoming = incoming.ok_or_else(|| other_error("服务端 Endpoint 已停止监听"))?;
                let connection_slot = match connection_slots.clone().try_acquire_owned() {
                    Ok(slot) => slot,
                    Err(_) => {
                        metrics.connection_rejects.fetch_add(1, Ordering::Relaxed);
                        events.emit(
                            "warn",
                            "connection_rejected",
                            json!({"reason": "connection_limit"}),
                        );
                        incoming.refuse();
                        continue;
                    }
                };
                let tokens = tokens.clone();
                let task_metrics = metrics.clone();
                let task_events = events.clone();
                let mut task_shutdown = shutdown.clone();
                connection_tasks.spawn(async move {
                    let _connection_slot = connection_slot;
                    let _connection_metric = task_metrics.start_connection();
                    let connecting = match incoming.accept() {
                        Ok(connecting) => connecting,
                        Err(_) => {
                            task_events.emit(
                                "warn",
                                "connection_failed",
                                json!({"reason": "handshake_failed"}),
                            );
                            return;
                        }
                    };
                    let connection = tokio::select! {
                        biased;
                        _ = task_shutdown.changed() => {
                            task_events.emit(
                                "info",
                                "connection_failed",
                                json!({"reason": "shutdown"}),
                            );
                            return;
                        }
                        result = timeout(limits.handshake_timeout, connecting) => match result {
                            Ok(Ok(connection)) => connection,
                            Ok(Err(_)) => {
                                task_events.emit(
                                    "warn",
                                    "connection_failed",
                                    json!({"reason": "handshake_failed"}),
                                );
                                return;
                            }
                            Err(_) => {
                                task_metrics
                                    .handshake_timeouts
                                    .fetch_add(1, Ordering::Relaxed);
                                task_events.emit(
                                    "warn",
                                    "connection_failed",
                                    json!({"reason": "handshake_timeout"}),
                                );
                                return;
                            }
                        }
                    };
                    if !connection.is_multipath_enabled() {
                        connection.close(0_u8.into(), b"multipath required");
                        task_events.emit(
                            "warn",
                            "connection_failed",
                            json!({"reason": "multipath_required"}),
                        );
                        return;
                    }

                    let connection_id = connection.stable_id();
                    task_events.emit(
                        "info",
                        "connection_started",
                        json!({"connection_id": connection_id}),
                    );
                    let result = serve_proxy_connection(
                        &connection,
                        tokens,
                        allowed_target,
                        limits,
                        task_shutdown,
                        task_metrics.clone(),
                        task_events.clone(),
                    )
                    .await;
                    let stats = connection.stats();
                    match result {
                        Ok(reason) => task_events.emit(
                            "info",
                            "connection_finished",
                            json!({
                                "connection_id": connection_id,
                                "reason": reason,
                                "udp_tx_bytes": stats.udp_tx.bytes,
                                "udp_rx_bytes": stats.udp_rx.bytes,
                                "lost_bytes": stats.lost_bytes,
                            }),
                        ),
                        Err(error) => task_events.emit(
                            "warn",
                            "connection_finished",
                            json!({
                                "connection_id": connection_id,
                                "reason": error.code,
                                "udp_tx_bytes": stats.udp_tx.bytes,
                                "udp_rx_bytes": stats.udp_rx.bytes,
                                "lost_bytes": stats.lost_bytes,
                            }),
                        ),
                    }
                });
            }
        }
    }

    endpoint.set_server_config(None);
    events.emit(
        "info",
        "shutdown_started",
        json!({"drain_timeout_ms": duration_millis(limits.shutdown_drain_timeout)}),
    );
    let drain_started = Instant::now();
    let graceful = timeout(
        limits.shutdown_drain_timeout,
        drain_join_set(&mut connection_tasks),
    )
    .await
    .is_ok();
    if graceful {
        metrics.graceful_shutdowns.fetch_add(1, Ordering::Relaxed);
    } else {
        metrics.forced_shutdowns.fetch_add(1, Ordering::Relaxed);
        events.emit(
            "warn",
            "shutdown_forced",
            json!({"reason": "drain_timeout"}),
        );
        endpoint.close(0_u8.into(), b"shutdown drain timeout");
        connection_tasks.abort_all();
        drain_join_set(&mut connection_tasks).await;
    }
    endpoint.close(0_u8.into(), b"shutdown complete");
    events.emit_metrics(&metrics);
    events.emit(
        "info",
        "shutdown_complete",
        json!({
            "forced": !graceful,
            "drain_ms": duration_millis(drain_started.elapsed()),
        }),
    );
    Ok(())
}

async fn serve_proxy_connection(
    connection: &Connection,
    tokens: SharedServerTokens,
    allowed_target: SocketAddr,
    limits: ProxyRuntimeLimits,
    mut shutdown: watch::Receiver<bool>,
    metrics: Arc<ProxyMetrics>,
    events: ProxyEventLog,
) -> ProxyTaskResult<&'static str> {
    let connection_id = connection.stable_id();
    let mut stream_tasks = JoinSet::new();
    let mut path_events = connection.path_events();
    let mut path_events_open = true;
    let (finish_reason, drain_streams) = loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break ("shutdown", true),
            joined = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    events.emit(
                        "error",
                        "stream_task_failed",
                        json!({"connection_id": connection_id, "reason": "task_panic"}),
                    );
                }
            }
            event = path_events.next(), if path_events_open => {
                match event {
                    Some(Ok(event)) => emit_path_event(&events, connection_id, event),
                    Some(Err(error)) => events.emit(
                        "warn",
                        "path_events_lagged",
                        json!({"connection_id": connection_id, "lost_events": error.0}),
                    ),
                    None => path_events_open = false,
                }
            }
            accepted = connection.accept_bi() => {
                let (send, receive) = match accepted {
                    Ok(streams) => streams,
                    Err(ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed) => {
                        break ("peer_closed", false);
                    }
                    Err(_) => {
                        stream_tasks.abort_all();
                        drain_join_set(&mut stream_tasks).await;
                        return Err(ProxyTaskError::new("stream_accept_failed"));
                    }
                };
                let stream_tokens = tokens.clone();
                let stream_metrics = metrics.clone();
                let stream_events = events.clone();
                stream_tasks.spawn(async move {
                    let _stream_metric = stream_metrics.start_stream();
                    stream_events.emit(
                        "info",
                        "stream_started",
                        json!({"connection_id": connection_id}),
                    );
                    match handle_server_stream(
                        send,
                        receive,
                        &stream_tokens,
                        allowed_target,
                        limits,
                        &stream_metrics,
                    )
                    .await
                    {
                        Ok(bytes) => {
                            stream_metrics
                                .upload_bytes
                                .fetch_add(bytes.quic_to_tcp, Ordering::Relaxed);
                            stream_metrics
                                .download_bytes
                                .fetch_add(bytes.tcp_to_quic, Ordering::Relaxed);
                            stream_events.emit(
                                "info",
                                "stream_finished",
                                json!({
                                    "connection_id": connection_id,
                                    "reason": "completed",
                                    "upload_bytes": bytes.quic_to_tcp,
                                    "download_bytes": bytes.tcp_to_quic,
                                }),
                            );
                        }
                        Err(error) => stream_events.emit(
                            "warn",
                            "stream_finished",
                            json!({"connection_id": connection_id, "reason": error.code}),
                        ),
                    }
                });
            }
        }
    };

    if drain_streams {
        drain_join_set(&mut stream_tasks).await;
        connection.close(0_u8.into(), b"shutdown complete");
    } else {
        stream_tasks.abort_all();
        drain_join_set(&mut stream_tasks).await;
    }
    Ok(finish_reason)
}

async fn drain_join_set(tasks: &mut JoinSet<()>) {
    while tasks.join_next().await.is_some() {}
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn emit_path_event(events: &ProxyEventLog, connection_id: usize, event: PathEvent) {
    match event {
        PathEvent::Established { id, .. } => events.emit(
            "info",
            "path_changed",
            json!({
                "connection_id": connection_id,
                "path_id": id.to_string(),
                "change": "established",
            }),
        ),
        PathEvent::Abandoned { id, reason, .. } => events.emit(
            "warn",
            "path_changed",
            json!({
                "connection_id": connection_id,
                "path_id": id.to_string(),
                "change": "abandoned",
                "reason": path_abandon_reason(&reason),
            }),
        ),
        PathEvent::Discarded { id, path_stats, .. } => events.emit(
            "info",
            "path_changed",
            json!({
                "connection_id": connection_id,
                "path_id": id.to_string(),
                "change": "discarded",
                "lost_packets": path_stats.lost_packets,
                "lost_bytes": path_stats.lost_bytes,
            }),
        ),
        PathEvent::RemoteStatus { id, status, .. } => events.emit(
            "info",
            "path_changed",
            json!({
                "connection_id": connection_id,
                "path_id": id.to_string(),
                "change": "remote_status",
                "status": path_status_name(status),
            }),
        ),
        PathEvent::ObservedAddr { id, addr: _, .. } => events.emit(
            "info",
            "path_changed",
            json!({
                "connection_id": connection_id,
                "path_id": id.to_string(),
                "change": "observed_address",
            }),
        ),
        _ => events.emit(
            "info",
            "path_changed",
            json!({"connection_id": connection_id, "change": "unknown"}),
        ),
    }
}

fn path_status_name(status: PathStatus) -> &'static str {
    match status {
        PathStatus::Available => "available",
        PathStatus::Backup => "backup",
    }
}

fn path_abandon_reason(reason: &PathAbandonReason) -> &'static str {
    match reason {
        PathAbandonReason::ApplicationClosed { .. } => "application_closed",
        PathAbandonReason::ValidationFailed => "validation_failed",
        PathAbandonReason::TimedOut => "timed_out",
        PathAbandonReason::UnusableAfterNetworkChange => "network_changed",
        PathAbandonReason::RemoteAbandoned { .. } => "remote_abandoned",
    }
}

async fn handle_server_stream(
    mut send: noq::SendStream,
    mut receive: noq::RecvStream,
    expected_tokens: &RwLock<Vec<Vec<u8>>>,
    allowed_target: SocketAddr,
    limits: ProxyRuntimeLimits,
    metrics: &ProxyMetrics,
) -> ProxyTaskResult<RelayBytes> {
    let request = match timeout(limits.request_timeout, read_proxy_request(&mut receive)).await {
        Ok(Ok(request)) => request,
        Ok(Err(rejection)) => {
            send_status(&mut send, rejection.status)
                .await
                .runtime_code("status_write_failed")?;
            let code = rejection_code(rejection.status);
            let _ = rejection.message;
            return Err(ProxyTaskError::new(code));
        }
        Err(_) => {
            metrics.request_timeouts.fetch_add(1, Ordering::Relaxed);
            send_status(&mut send, STATUS_FORMAT)
                .await
                .runtime_code("status_write_failed")?;
            return Err(ProxyTaskError::new("request_timeout"));
        }
    };

    let authorized = {
        let expected_tokens = expected_tokens
            .read()
            .map_err(|_| ProxyTaskError::new("token_state_unavailable"))?;
        token_set_matches(&expected_tokens, &request.token)
    };
    if !authorized {
        send_status(&mut send, STATUS_AUTHORIZATION)
            .await
            .runtime_code("status_write_failed")?;
        return Err(ProxyTaskError::new("authorization_rejected"));
    }
    if request.target != allowed_target {
        send_status(&mut send, STATUS_TARGET)
            .await
            .runtime_code("status_write_failed")?;
        return Err(ProxyTaskError::new("target_rejected"));
    }

    let upstream = match timeout(
        limits.upstream_connect_timeout,
        TcpStream::connect(allowed_target),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(_)) => {
            metrics.upstream_errors.fetch_add(1, Ordering::Relaxed);
            send_status(&mut send, STATUS_UPSTREAM)
                .await
                .runtime_code("status_write_failed")?;
            return Err(ProxyTaskError::new("upstream_connect_failed"));
        }
        Err(_) => {
            metrics
                .upstream_connect_timeouts
                .fetch_add(1, Ordering::Relaxed);
            send_status(&mut send, STATUS_UPSTREAM)
                .await
                .runtime_code("status_write_failed")?;
            return Err(ProxyTaskError::new("upstream_connect_timeout"));
        }
    };
    send.write_all(&[STATUS_OK])
        .await
        .runtime_code("status_write_failed")?;
    relay_tcp_and_quic(upstream, send, receive).await
}

fn rejection_code(status: u8) -> &'static str {
    match status {
        STATUS_VERSION => "protocol_version_rejected",
        STATUS_FORMAT => "request_format_rejected",
        _ => "request_rejected",
    }
}

async fn run_client_accept_loop(
    endpoint: Endpoint,
    connection: Connection,
    listener: TcpListener,
    token: SharedClientToken,
    target: SocketAddr,
    runtime: ProxyRuntimeContext,
) -> LabResult<()> {
    let ProxyRuntimeContext {
        limits,
        mut shutdown,
        metrics,
        events,
    } = runtime;
    let connection_metric = metrics.start_connection();
    let connection_id = connection.stable_id();
    events.emit(
        "info",
        "connection_started",
        json!({"connection_id": connection_id}),
    );
    let stream_slots = Arc::new(Semaphore::new(limits.max_client_streams));
    let mut stream_tasks = JoinSet::new();
    let mut path_events = connection.path_events();
    let mut path_events_open = true;
    let mut metrics_tick = interval_at(
        Instant::now() + limits.metrics_interval,
        limits.metrics_interval,
    );
    let stop_reason = loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break "shutdown",
            _ = connection.closed() => break "connection_closed",
            joined = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    events.emit(
                        "error",
                        "stream_task_failed",
                        json!({"connection_id": connection_id, "reason": "task_panic"}),
                    );
                }
            }
            event = path_events.next(), if path_events_open => {
                match event {
                    Some(Ok(event)) => emit_path_event(&events, connection_id, event),
                    Some(Err(error)) => events.emit(
                        "warn",
                        "path_events_lagged",
                        json!({"connection_id": connection_id, "lost_events": error.0}),
                    ),
                    None => path_events_open = false,
                }
            }
            _ = metrics_tick.tick() => events.emit_metrics(&metrics),
            accepted = listener.accept() => {
                let (local, _) = accepted?;
                let stream_slot = match stream_slots.clone().try_acquire_owned() {
                    Ok(slot) => slot,
                    Err(_) => {
                        metrics.stream_rejects.fetch_add(1, Ordering::Relaxed);
                        events.emit(
                            "warn",
                            "stream_rejected",
                            json!({"connection_id": connection_id, "reason": "client_stream_limit"}),
                        );
                        drop(local);
                        continue;
                    }
                };
                let stream_connection = connection.clone();
                let stream_token = token
                    .read()
                    .map_err(|_| other_error("客户端令牌状态锁已损坏"))?
                    .clone();
                let stream_metrics = metrics.clone();
                let stream_events = events.clone();
                stream_tasks.spawn(async move {
                    let _stream_slot = stream_slot;
                    let _stream_metric = stream_metrics.start_stream();
                    stream_events.emit(
                        "info",
                        "stream_started",
                        json!({"connection_id": connection_id}),
                    );
                    match handle_client_stream(
                        stream_connection,
                        local,
                        &stream_token,
                        target,
                        limits,
                        &stream_metrics,
                    )
                    .await
                    {
                        Ok(bytes) => {
                            stream_metrics
                                .upload_bytes
                                .fetch_add(bytes.tcp_to_quic, Ordering::Relaxed);
                            stream_metrics
                                .download_bytes
                                .fetch_add(bytes.quic_to_tcp, Ordering::Relaxed);
                            stream_events.emit(
                                "info",
                                "stream_finished",
                                json!({
                                    "connection_id": connection_id,
                                    "reason": "completed",
                                    "upload_bytes": bytes.tcp_to_quic,
                                    "download_bytes": bytes.quic_to_tcp,
                                }),
                            );
                        }
                        Err(error) => stream_events.emit(
                            "warn",
                            "stream_finished",
                            json!({"connection_id": connection_id, "reason": error.code}),
                        ),
                    }
                });
            }
        }
    };

    drop(listener);
    if stop_reason == "connection_closed" {
        stream_tasks.abort_all();
        drain_join_set(&mut stream_tasks).await;
        let stats = connection.stats();
        events.emit(
            "error",
            "connection_finished",
            json!({
                "connection_id": connection_id,
                "reason": "transport_closed",
                "udp_tx_bytes": stats.udp_tx.bytes,
                "udp_rx_bytes": stats.udp_rx.bytes,
                "lost_bytes": stats.lost_bytes,
            }),
        );
        drop(connection_metric);
        events.emit_metrics(&metrics);
        events.emit(
            "error",
            "runtime_failed",
            json!({"reason": "server_connection_closed"}),
        );
        return Err(other_error("到服务端的 FlowWeave 连接已关闭"));
    }

    events.emit(
        "info",
        "shutdown_started",
        json!({"drain_timeout_ms": duration_millis(limits.shutdown_drain_timeout)}),
    );
    let drain_started = Instant::now();
    let graceful = timeout(
        limits.shutdown_drain_timeout,
        drain_join_set(&mut stream_tasks),
    )
    .await
    .is_ok();
    if graceful {
        metrics.graceful_shutdowns.fetch_add(1, Ordering::Relaxed);
    } else {
        metrics.forced_shutdowns.fetch_add(1, Ordering::Relaxed);
        events.emit(
            "warn",
            "shutdown_forced",
            json!({"reason": "drain_timeout"}),
        );
        stream_tasks.abort_all();
        drain_join_set(&mut stream_tasks).await;
    }
    connection.close(0_u8.into(), b"shutdown complete");
    endpoint.close(0_u8.into(), b"shutdown complete");
    let stats = connection.stats();
    events.emit(
        "info",
        "connection_finished",
        json!({
            "connection_id": connection_id,
            "reason": if graceful { "shutdown" } else { "shutdown_forced" },
            "udp_tx_bytes": stats.udp_tx.bytes,
            "udp_rx_bytes": stats.udp_rx.bytes,
            "lost_bytes": stats.lost_bytes,
        }),
    );
    drop(connection_metric);
    events.emit_metrics(&metrics);
    events.emit(
        "info",
        "shutdown_complete",
        json!({
            "forced": !graceful,
            "drain_ms": duration_millis(drain_started.elapsed()),
        }),
    );
    Ok(())
}

async fn handle_client_stream(
    connection: Connection,
    local: TcpStream,
    token: &[u8],
    target: SocketAddr,
    limits: ProxyRuntimeLimits,
    metrics: &ProxyMetrics,
) -> ProxyTaskResult<RelayBytes> {
    let streams = match timeout(limits.stream_open_timeout, connection.open_bi()).await {
        Ok(streams) => streams.runtime_code("stream_open_failed")?,
        Err(_) => {
            metrics.stream_open_timeouts.fetch_add(1, Ordering::Relaxed);
            return Err(ProxyTaskError::new("stream_open_timeout"));
        }
    };
    let (mut send, mut receive) = streams;
    let request = encode_proxy_request(token, target).runtime_code("request_encode_failed")?;

    let mut status = [0_u8; 1];
    let negotiation = async {
        send.write_all(&request)
            .await
            .runtime_code("request_write_failed")?;
        receive
            .read_exact(&mut status)
            .await
            .runtime_code("status_read_failed")?;
        Ok::<(), ProxyTaskError>(())
    };
    match timeout(limits.request_timeout, negotiation).await {
        Ok(result) => result?,
        Err(_) => {
            metrics.request_timeouts.fetch_add(1, Ordering::Relaxed);
            return Err(ProxyTaskError::new("request_negotiation_timeout"));
        }
    }
    if status[0] != STATUS_OK {
        return Err(ProxyTaskError::new(match status[0] {
            STATUS_VERSION => "server_rejected_version",
            STATUS_FORMAT => "server_rejected_format",
            STATUS_AUTHORIZATION => "server_rejected_authorization",
            STATUS_TARGET => "server_rejected_target",
            STATUS_UPSTREAM => "server_rejected_upstream",
            _ => "server_rejected_unknown",
        }));
    }
    relay_tcp_and_quic(local, send, receive).await
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RelayBytes {
    tcp_to_quic: u64,
    quic_to_tcp: u64,
}

async fn relay_tcp_and_quic(
    tcp: TcpStream,
    mut quic_send: noq::SendStream,
    mut quic_receive: noq::RecvStream,
) -> ProxyTaskResult<RelayBytes> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let tcp_to_quic = async {
        let bytes = tokio::io::copy(&mut tcp_read, &mut quic_send).await?;
        quic_send.shutdown().await?;
        Ok::<u64, io::Error>(bytes)
    };
    let quic_to_tcp = async {
        let bytes = tokio::io::copy(&mut quic_receive, &mut tcp_write).await?;
        tcp_write.shutdown().await?;
        Ok::<u64, io::Error>(bytes)
    };
    let (tcp_to_quic, quic_to_tcp) =
        tokio::try_join!(tcp_to_quic, quic_to_tcp).runtime_code("relay_io_failed")?;
    Ok(RelayBytes {
        tcp_to_quic,
        quic_to_tcp,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ProxyRequest {
    token: Vec<u8>,
    target: SocketAddr,
}

#[derive(Debug)]
struct RequestRejection {
    status: u8,
    message: String,
}

impl RequestRejection {
    fn new(status: u8, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

fn encode_proxy_request(token: &[u8], target: SocketAddr) -> LabResult<Vec<u8>> {
    validate_token_length(token.len())?;
    let target = target.to_string();
    if target.is_empty() || target.len() > MAX_TARGET_LENGTH {
        return Err(other_error("代理目标编码长度不合法"));
    }
    let token_len = u16::try_from(token.len()).map_err(|_| other_error("代理令牌过长"))?;
    let target_len = u16::try_from(target.len()).map_err(|_| other_error("代理目标编码过长"))?;
    let mut request = Vec::with_capacity(8 + token.len() + target.len());
    request.extend_from_slice(PROXY_MAGIC);
    request.extend_from_slice(&token_len.to_be_bytes());
    request.extend_from_slice(&target_len.to_be_bytes());
    request.extend_from_slice(token);
    request.extend_from_slice(target.as_bytes());
    Ok(request)
}

async fn read_proxy_request(
    receive: &mut noq::RecvStream,
) -> Result<ProxyRequest, RequestRejection> {
    let mut header = [0_u8; 8];
    receive.read_exact(&mut header).await.map_err(|error| {
        RequestRejection::new(STATUS_FORMAT, format!("代理请求头读取失败：{error}"))
    })?;
    if &header[..4] != PROXY_MAGIC {
        return Err(RequestRejection::new(
            STATUS_VERSION,
            "代理协议版本不受支持",
        ));
    }
    let token_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let target_len = u16::from_be_bytes([header[6], header[7]]) as usize;
    if !(MIN_TOKEN_LENGTH..=MAX_TOKEN_LENGTH).contains(&token_len)
        || !(1..=MAX_TARGET_LENGTH).contains(&target_len)
    {
        return Err(RequestRejection::new(
            STATUS_FORMAT,
            "代理请求长度字段不合法",
        ));
    }

    let mut request = Vec::with_capacity(8 + token_len + target_len);
    request.extend_from_slice(&header);
    request.resize(8 + token_len + target_len, 0);
    receive
        .read_exact(&mut request[8..])
        .await
        .map_err(|error| {
            RequestRejection::new(STATUS_FORMAT, format!("代理请求正文读取失败：{error}"))
        })?;
    decode_proxy_request(&request)
}

fn decode_proxy_request(request: &[u8]) -> Result<ProxyRequest, RequestRejection> {
    if request.len() < 8 {
        return Err(RequestRejection::new(STATUS_FORMAT, "代理请求头不完整"));
    }
    if &request[..4] != PROXY_MAGIC {
        return Err(RequestRejection::new(
            STATUS_VERSION,
            "代理协议版本不受支持",
        ));
    }
    let token_len = u16::from_be_bytes([request[4], request[5]]) as usize;
    let target_len = u16::from_be_bytes([request[6], request[7]]) as usize;
    if !(MIN_TOKEN_LENGTH..=MAX_TOKEN_LENGTH).contains(&token_len)
        || !(1..=MAX_TARGET_LENGTH).contains(&target_len)
    {
        return Err(RequestRejection::new(
            STATUS_FORMAT,
            "代理请求长度字段不合法",
        ));
    }
    let expected = 8 + token_len + target_len;
    if request.len() != expected {
        return Err(RequestRejection::new(
            STATUS_FORMAT,
            "代理请求实际长度与声明不一致",
        ));
    }
    let target_bytes = &request[8 + token_len..expected];
    let target_text = std::str::from_utf8(target_bytes)
        .map_err(|_| RequestRejection::new(STATUS_FORMAT, "代理目标不是 UTF-8"))?;
    let target = target_text
        .parse::<SocketAddr>()
        .map_err(|_| RequestRejection::new(STATUS_FORMAT, "代理目标不是显式 IP:port"))?;
    Ok(ProxyRequest {
        token: request[8..8 + token_len].to_vec(),
        target,
    })
}

fn token_matches(expected: &[u8], provided: &[u8]) -> bool {
    expected.ct_eq(provided).unwrap_u8() == 1
}

fn token_set_matches(expected: &[Vec<u8>], provided: &[u8]) -> bool {
    let mut matched = 0_u8;
    for token in expected {
        matched |= token.ct_eq(provided).unwrap_u8();
    }
    matched == 1
}

async fn send_status(send: &mut noq::SendStream, status: u8) -> LabResult<()> {
    send.write_all(&[status]).await?;
    send.shutdown().await?;
    Ok(())
}

fn configure_product_transport(
    transport: &mut TransportConfig,
    path_count: u32,
    incoming_bidi_streams: u32,
) {
    configure_transport(
        transport,
        Some(PRODUCT_PATH_IDLE_TIMEOUT),
        PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot,
        MultipathScheduler::NoqDefault,
        QuicCongestion::Cubic,
        false,
    );
    transport.max_concurrent_multipath_paths(path_count.max(1));
    transport.max_concurrent_bidi_streams(incoming_bidi_streams.into());
    transport.max_concurrent_uni_streams(0_u8.into());
}

fn read_certificate(path: &Path) -> LabResult<CertificateDer<'static>> {
    let bytes = read_regular_file(path, false, "证书")?;
    if bytes.is_empty() {
        return Err(other_error(format!("证书文件为空：{}", path.display())));
    }
    Ok(CertificateDer::from(bytes))
}

fn read_private_key(path: &Path) -> LabResult<PrivatePkcs8KeyDer<'static>> {
    let bytes = read_regular_file(path, true, "私钥")?;
    if bytes.is_empty() {
        return Err(other_error(format!("私钥文件为空：{}", path.display())));
    }
    Ok(PrivatePkcs8KeyDer::from(bytes))
}

fn read_token(path: &Path) -> LabResult<Vec<u8>> {
    let token = read_regular_file(path, true, "令牌")?;
    validate_token_length(token.len())?;
    Ok(token)
}

fn read_server_tokens(
    token_file: &Path,
    previous_token_file: Option<&Path>,
) -> LabResult<Vec<Vec<u8>>> {
    let current = read_token(token_file)?;
    let mut tokens = vec![current];
    if let Some(previous_token_file) = previous_token_file {
        let previous = read_token(previous_token_file)?;
        if !token_matches(&tokens[0], &previous) {
            tokens.push(previous);
        }
    }
    Ok(tokens)
}

fn validate_token_length(length: usize) -> LabResult<()> {
    if !(MIN_TOKEN_LENGTH..=MAX_TOKEN_LENGTH).contains(&length) {
        return Err(other_error(format!(
            "令牌长度必须在 {MIN_TOKEN_LENGTH} 到 {MAX_TOKEN_LENGTH} 字节之间"
        )));
    }
    Ok(())
}

fn read_regular_file(path: &Path, private: bool, label: &str) -> LabResult<Vec<u8>> {
    let metadata = fs::metadata(path).map_err(|error| {
        other_error(format!(
            "无法读取{label}文件元数据 {}：{error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(other_error(format!(
            "{label}路径不是普通文件：{}",
            path.display()
        )));
    }
    if private {
        enforce_private_permissions(path, &metadata, label)?;
    }
    fs::read(path)
        .map_err(|error| other_error(format!("无法读取{label}文件 {}：{error}", path.display())))
}

#[cfg(unix)]
fn enforce_private_permissions(path: &Path, metadata: &fs::Metadata, label: &str) -> LabResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(other_error(format!(
            "{label}文件不得授予 group/other 权限：{}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
    _label: &str,
) -> LabResult<()> {
    Ok(())
}

async fn resolve_server_addr(config: &ProxyClientConfig) -> LabResult<SocketAddr> {
    let preferred_family = config
        .primary_local_ip
        .or_else(|| config.additional_local_ips.first().copied());
    let mut addresses = lookup_host(config.server.as_str())
        .await
        .map_err(|error| other_error(format!("无法解析服务端地址：{error}")))?;
    addresses
        .find(|address| {
            preferred_family
                .map(|local| local.is_ipv4() == address.is_ipv4())
                .unwrap_or(true)
        })
        .ok_or_else(|| other_error("服务端地址没有与本地路径同地址族的解析结果"))
}

fn unspecified_for(ip: IpAddr) -> IpAddr {
    if ip.is_ipv4() {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    }
}

fn load_key_values(
    path: &Path,
    required_keys: &[&str],
    optional_keys: &[&str],
) -> LabResult<HashMap<String, String>> {
    let contents = fs::read_to_string(path)
        .map_err(|error| other_error(format!("无法读取配置文件 {}：{error}", path.display())))?;
    let allowed: HashSet<&str> = required_keys
        .iter()
        .chain(optional_keys.iter())
        .copied()
        .collect();
    let mut values = HashMap::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| other_error(format!("配置第 {} 行不是 key=value", index + 1)))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(other_error(format!(
                "配置第 {} 行包含空键或空值",
                index + 1
            )));
        }
        if !allowed.contains(key) {
            return Err(other_error(format!("配置包含未知键：{key}")));
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(other_error(format!("配置包含重复键：{key}")));
        }
    }
    for key in required_keys {
        if !values.contains_key(*key) {
            return Err(other_error(format!("配置缺少必需键：{key}")));
        }
    }
    Ok(values)
}

fn required<'a>(values: &'a HashMap<String, String>, key: &str) -> LabResult<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| other_error(format!("配置缺少必需键：{key}")))
}

fn parse_socket_addr(value: &str, key: &str) -> LabResult<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .map_err(|error| other_error(format!("配置键 {key} 必须是显式 IP:port：{error}")))
}

fn parse_local_ip(value: &str, key: &str) -> LabResult<IpAddr> {
    let ip = value
        .parse::<IpAddr>()
        .map_err(|error| other_error(format!("配置键 {key} 不是 IP 地址：{error}")))?;
    if ip.is_unspecified() {
        return Err(other_error(format!("配置键 {key} 不能是未指定地址")));
    }
    Ok(ip)
}

fn parse_additional_ips(value: &str) -> LabResult<Vec<IpAddr>> {
    value
        .split(',')
        .enumerate()
        .map(|(index, value)| {
            let value = value.trim();
            if value.is_empty() {
                return Err(other_error(format!(
                    "additional_local_ips 第 {} 项为空",
                    index + 1
                )));
            }
            parse_local_ip(value, "additional_local_ips")
        })
        .collect()
}

fn validate_local_ips(primary: Option<IpAddr>, additional: &[IpAddr]) -> LabResult<()> {
    if additional.len() + 1 > MAX_PRODUCT_PATHS {
        return Err(other_error(format!(
            "产品代理最多允许 {MAX_PRODUCT_PATHS} 条并发路径"
        )));
    }
    let mut seen = HashSet::new();
    if let Some(primary) = primary {
        seen.insert(primary);
    }
    let expected_family = primary.or_else(|| additional.first().copied());
    for address in additional {
        if !seen.insert(*address) {
            return Err(other_error(format!("本地路径地址重复：{address}")));
        }
        if let Some(expected) = expected_family
            && expected.is_ipv4() != address.is_ipv4()
        {
            return Err(other_error("所有本地路径地址必须属于同一地址族"));
        }
    }
    Ok(())
}

fn config_base(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use tokio::io::AsyncReadExt;
    use tokio::sync::Notify;
    use tokio::time::{sleep, timeout};

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn runtime_join_remains_available_when_select_cancels_wait() {
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let task: JoinHandle<LabResult<()>> = tokio::spawn(async move {
            shutdown_rx
                .changed()
                .await
                .map_err(|_| other_error("测试关闭通道意外结束"))?;
            Ok(())
        });
        let mut runtime = ProxyRuntime {
            local_addr: "127.0.0.1:1".parse().unwrap(),
            shutdown,
            metrics: Arc::new(ProxyMetrics::default()),
            token_reloader: ProxyTokenReloader::Client {
                token_file: PathBuf::new(),
                token: Arc::new(RwLock::new(vec![0_u8; MIN_TOKEN_LENGTH])),
            },
            events: ProxyEventLog::new("client", default_event_sink()),
            task: Some(task),
        };

        tokio::select! {
            biased;
            result = runtime.join() => panic!("运行任务不应提前结束：{result:?}"),
            _ = sleep(Duration::from_millis(20)) => {}
        }
        assert!(runtime.task.is_some());
        runtime.request_shutdown();
        runtime.join().await.unwrap();
        assert!(runtime.task.is_none());
    }

    fn test_runtime_limits() -> ProxyRuntimeLimits {
        ProxyRuntimeLimits {
            max_server_connections: 4,
            max_streams_per_connection: 4,
            max_client_streams: 4,
            handshake_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            upstream_connect_timeout: Duration::from_secs(2),
            stream_open_timeout: Duration::from_secs(2),
            shutdown_drain_timeout: Duration::from_secs(2),
            metrics_interval: Duration::from_secs(60),
        }
    }

    #[derive(Default)]
    struct TestEventSink {
        lines: Mutex<Vec<String>>,
        notify: Notify,
    }

    impl ProxyEventSink for TestEventSink {
        fn write_line(&self, line: &str) {
            self.lines.lock().unwrap().push(line.to_owned());
            self.notify.notify_waiters();
        }
    }

    impl TestEventSink {
        fn lines(&self) -> Vec<String> {
            self.lines.lock().unwrap().clone()
        }

        async fn wait_for_event(&self, role: &str, event: &str) {
            timeout(Duration::from_secs(2), async {
                loop {
                    let notified = self.notify.notified();
                    let found = self.lines.lock().unwrap().iter().any(|line| {
                        serde_json::from_str::<Value>(line)
                            .is_ok_and(|record| record["role"] == role && record["event"] == event)
                    });
                    if found {
                        return;
                    }
                    notified.await;
                }
            })
            .await
            .expect("应在截止时间内收到指定运行事件");
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("flowweave-proxy-{}-{sequence}", std::process::id()));
            fs::create_dir_all(&path).expect("应能创建代理测试目录");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn strict_config_rejects_unknown_duplicate_and_non_loopback() {
        let directory = TestDirectory::new();
        let server = directory.path().join("server.conf");
        fs::write(
            &server,
            "listen=127.0.0.1:4433\ncertificate_der=cert.der\nprivate_key_der=key.der\ntoken_file=token\nallowed_target=127.0.0.1:22\nunknown=yes\n",
        )
        .unwrap();
        assert!(ProxyServerConfig::load(&server).is_err());

        let client = directory.path().join("client.conf");
        fs::write(
            &client,
            "listen=127.0.0.1:10022\nlisten=127.0.0.1:10023\nserver=localhost:4433\nserver_name=localhost\nca_certificate_der=ca.der\ntoken_file=token\ntarget=127.0.0.1:22\n",
        )
        .unwrap();
        assert!(ProxyClientConfig::load(&client).is_err());

        fs::write(
            &client,
            "listen=0.0.0.0:10022\nserver=localhost:4433\nserver_name=localhost\nca_certificate_der=ca.der\ntoken_file=token\ntarget=127.0.0.1:22\n",
        )
        .unwrap();
        assert!(ProxyClientConfig::load(&client).is_err());
    }

    #[test]
    fn relative_paths_and_local_path_validation_are_deterministic() {
        let directory = TestDirectory::new();
        let server_path = directory.path().join("server.conf");
        fs::write(
            &server_path,
            "listen=127.0.0.1:4433\ncertificate_der=pki/cert.der\nprivate_key_der=secrets/key.der\ntoken_file=secrets/current-token\nprevious_token_file=secrets/previous-token\nallowed_target=127.0.0.1:22\n",
        )
        .unwrap();
        let server = ProxyServerConfig::load(&server_path).unwrap();
        assert_eq!(
            server.previous_token_file,
            Some(directory.path().join("secrets/previous-token"))
        );

        let config_path = directory.path().join("client.conf");
        fs::write(
            &config_path,
            "listen=127.0.0.1:10022\nserver=localhost:4433\nserver_name=localhost\nca_certificate_der=pki/ca.der\ntoken_file=secrets/token\ntarget=127.0.0.1:22\nprimary_local_ip=127.0.0.1\nadditional_local_ips=127.0.0.2,127.0.0.3\n",
        )
        .unwrap();
        let config = ProxyClientConfig::load(&config_path).unwrap();
        assert_eq!(
            config.ca_certificate_der,
            directory.path().join("pki/ca.der")
        );
        assert_eq!(config.token_file, directory.path().join("secrets/token"));
        assert_eq!(config.additional_local_ips.len(), 2);

        fs::write(
            &config_path,
            "listen=127.0.0.1:10022\nserver=localhost:4433\nserver_name=localhost\nca_certificate_der=ca.der\ntoken_file=token\ntarget=127.0.0.1:22\nprimary_local_ip=127.0.0.1\nadditional_local_ips=127.0.0.1\n",
        )
        .unwrap();
        assert!(ProxyClientConfig::load(&config_path).is_err());
    }

    #[test]
    fn deployment_examples_follow_the_strict_config_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let server = ProxyServerConfig::load(root.join("deploy/server.conf.example")).unwrap();
        assert_eq!(server.listen, "0.0.0.0:4433".parse().unwrap());
        assert_eq!(server.allowed_target, "127.0.0.1:22".parse().unwrap());
        assert_eq!(
            server.previous_token_file,
            Some(PathBuf::from("/etc/flowweave/token.previous"))
        );

        let client = ProxyClientConfig::load(root.join("deploy/client.conf.example")).unwrap();
        assert_eq!(client.listen, "127.0.0.1:10022".parse().unwrap());
        assert_eq!(client.server_name, "proxy.example.com");
        assert!(client.primary_local_ip.is_none());
        assert!(client.additional_local_ips.is_empty());

        for (unit_name, mode) in [
            ("flowweave-server.service", "server"),
            ("flowweave-client.service", "client"),
        ] {
            let unit = fs::read_to_string(root.join("deploy").join(unit_name)).unwrap();
            assert!(unit.contains(&format!(
                "ExecStart=/usr/local/bin/flowweave-proxy {mode} /etc/flowweave/"
            )));
            assert!(unit.contains("ExecReload=/bin/kill -HUP $MAINPID"));
            for required_line in [
                "User=flowweave",
                "UMask=0077",
                "TimeoutStopSec=15s",
                "TasksMax=512",
                "MemoryMax=1G",
                "CapabilityBoundingSet=",
                "NoNewPrivileges=true",
                "ProtectHostname=true",
                "ProtectSystem=strict",
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                "RestrictNamespaces=true",
                "MemoryDenyWriteExecute=true",
            ] {
                assert!(
                    unit.lines().any(|line| line == required_line),
                    "{unit_name} 缺少加固项 {required_line}"
                );
            }
        }
    }

    #[test]
    fn request_codec_rejects_version_lengths_and_non_ip_targets() {
        let token = vec![7_u8; MIN_TOKEN_LENGTH];
        let target = "127.0.0.1:22".parse().unwrap();
        let encoded = encode_proxy_request(&token, target).unwrap();
        assert_eq!(
            decode_proxy_request(&encoded).unwrap(),
            ProxyRequest { token, target }
        );

        let mut wrong_magic = encoded.clone();
        wrong_magic[..4].copy_from_slice(b"BAD1");
        assert_eq!(
            decode_proxy_request(&wrong_magic).unwrap_err().status,
            STATUS_VERSION
        );

        let mut short_token = encoded.clone();
        short_token[4..6].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_proxy_request(&short_token).unwrap_err().status,
            STATUS_FORMAT
        );

        let target_text = b"example.com:22";
        let mut domain_request = Vec::new();
        domain_request.extend_from_slice(PROXY_MAGIC);
        domain_request.extend_from_slice(&(MIN_TOKEN_LENGTH as u16).to_be_bytes());
        domain_request.extend_from_slice(&(target_text.len() as u16).to_be_bytes());
        domain_request.extend_from_slice(&[1_u8; MIN_TOKEN_LENGTH]);
        domain_request.extend_from_slice(target_text);
        assert_eq!(
            decode_proxy_request(&domain_request).unwrap_err().status,
            STATUS_FORMAT
        );
        assert!(token_matches(&[5_u8; 32], &[5_u8; 32]));
        assert!(!token_matches(&[5_u8; 32], &[4_u8; 32]));
    }

    #[test]
    fn product_transport_enables_v69_without_b_sensor() {
        let mut transport = TransportConfig::default();
        configure_product_transport(&mut transport, 3, PRODUCT_MAX_STREAMS_PER_CONNECTION);
        let debug = format!("{transport:?}");
        assert!(debug.contains("max_concurrent_multipath_paths: Some(3)"));
        assert!(debug.contains("max_concurrent_bidi_streams: 64"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("cross_path_pto_reinjection: true"));
        assert!(debug.contains("cross_path_abandon_reinjection: true"));
        assert!(debug.contains("cross_path_ack_progress_reinjection: true"));
        assert!(debug.contains("cross_path_feedback_stream_progress_snapshot: true"));
        assert!(debug.contains("declared_backlogged_epoch_sensor: false"));
        assert!(debug.contains("default_path_max_idle_timeout: Some(3s)"));
        assert!(debug.contains("default_path_keep_alive_interval: Some(200ms)"));
    }

    #[cfg(unix)]
    #[test]
    fn private_files_reject_group_or_other_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let token = directory.path().join("token");
        fs::write(&token, vec![9_u8; MIN_TOKEN_LENGTH]).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&token).is_err());
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token(&token).unwrap().len(), MIN_TOKEN_LENGTH);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn server_accepts_current_and_previous_tokens_and_deduplicates_equal_files() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, current_token_path) = write_test_credentials(&directory);
        let previous_token_path = directory.path().join("previous-token");
        let previous_token = vec![0x5A; 48];
        write_test_token(&previous_token_path, &previous_token);

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = upstream.accept().await.unwrap();
                drop(stream);
            }
        });
        let server = start_proxy_server(ProxyServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate_der: certificate_path.clone(),
            private_key_der: key_path,
            token_file: current_token_path.clone(),
            previous_token_file: Some(previous_token_path.clone()),
            allowed_target: upstream_addr,
        })
        .await
        .unwrap();
        let (raw_endpoint, connection) =
            connect_raw_proxy(server.local_addr(), &certificate_path).await;

        let current_request = encode_proxy_request(&[0xA5; 48], upstream_addr).unwrap();
        assert_eq!(
            send_raw_request(&connection, &current_request).await,
            STATUS_OK
        );
        let previous_request = encode_proxy_request(&previous_token, upstream_addr).unwrap();
        assert_eq!(
            send_raw_request(&connection, &previous_request).await,
            STATUS_OK
        );

        write_test_token(&previous_token_path, &[0xA5; 48]);
        assert_eq!(server.reload_tokens().unwrap(), 1);

        connection.close(0_u8.into(), b"test complete");
        raw_endpoint.close(0_u8.into(), b"test complete");
        server.shutdown().await;
        upstream_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn token_rotation_revokes_new_old_flows_without_restarting_quic_or_existing_streams() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, server_token_path) = write_test_credentials(&directory);
        let previous_token_path = directory.path().join("previous-token");
        let client_token_path = directory.path().join("client-token");
        let old_token = vec![0xA5; 48];
        let new_token = vec![0x5A; 48];
        write_test_token(&previous_token_path, &new_token);
        write_test_token(&client_token_path, &old_token);

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = echo_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                });
            }
        });

        let server = start_proxy_server(ProxyServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate_der: certificate_path.clone(),
            private_key_der: key_path,
            token_file: server_token_path.clone(),
            previous_token_file: Some(previous_token_path),
            allowed_target: echo_addr,
        })
        .await
        .unwrap();
        let client = start_proxy_client(ProxyClientConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server: server.local_addr().to_string(),
            server_name: "localhost".to_owned(),
            ca_certificate_der: certificate_path,
            token_file: client_token_path.clone(),
            target: echo_addr,
            primary_local_ip: None,
            additional_local_ips: Vec::new(),
        })
        .await
        .unwrap();

        let mut existing_old_stream = TcpStream::connect(client.local_addr()).await.unwrap();
        existing_old_stream.write_all(b"old-before").await.unwrap();
        let mut old_before = [0_u8; 10];
        existing_old_stream
            .read_exact(&mut old_before)
            .await
            .unwrap();
        assert_eq!(&old_before, b"old-before");

        write_test_token(&client_token_path, b"too-short");
        assert!(client.reload_tokens().is_err());
        assert_proxy_echo(client.local_addr(), b"old-after-failed-client-reload").await;

        write_test_token(&client_token_path, &new_token);
        assert_eq!(client.reload_tokens().unwrap(), 1);
        assert_proxy_echo(client.local_addr(), b"new-during-overlap").await;

        write_test_token(&server_token_path, &new_token);
        assert_eq!(server.reload_tokens().unwrap(), 1);

        existing_old_stream.write_all(b"old-after").await.unwrap();
        let mut old_after = [0_u8; 9];
        existing_old_stream
            .read_exact(&mut old_after)
            .await
            .unwrap();
        assert_eq!(&old_after, b"old-after");

        write_test_token(&client_token_path, &old_token);
        assert_eq!(client.reload_tokens().unwrap(), 1);
        let mut rejected = TcpStream::connect(client.local_addr()).await.unwrap();
        rejected.write_all(b"revoked").await.unwrap();
        rejected.shutdown().await.unwrap();
        let mut rejected_response = Vec::new();
        let rejected_result = timeout(
            Duration::from_secs(2),
            rejected.read_to_end(&mut rejected_response),
        )
        .await
        .expect("撤销后的旧令牌新流应及时关闭");
        assert!(rejected_response.is_empty());
        assert!(matches!(rejected_result, Ok(0) | Err(_)));

        write_test_token(&client_token_path, &new_token);
        assert_eq!(client.reload_tokens().unwrap(), 1);
        assert_proxy_echo(client.local_addr(), b"new-after-revoke").await;
        assert_eq!(client.metrics_snapshot().total_connections, 1);

        existing_old_stream.shutdown().await.unwrap();
        let mut remaining = Vec::new();
        existing_old_stream
            .read_to_end(&mut remaining)
            .await
            .unwrap();
        assert!(remaining.is_empty());
        client.shutdown().await;
        server.shutdown().await;
        echo_task.abort();
        let _ = echo_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn failed_token_reload_preserves_state_and_redacts_runtime_event() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, current_token_path) = write_test_credentials(&directory);
        let current_token = b"FLOWWEAVE_CURRENT_TOKEN_0123456789_ABCDEFG";
        let previous_token = b"FLOWWEAVE_PREVIOUS_TOKEN_0123456789_ABCDE";
        write_test_token(&current_token_path, current_token);
        let previous_token_path = directory.path().join("private-previous-token");
        write_test_token(&previous_token_path, previous_token);

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            drop(stream);
        });
        let sink = Arc::new(TestEventSink::default());
        let server = start_proxy_server_with_limits_and_sink(
            ProxyServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_der: certificate_path.clone(),
                private_key_der: key_path,
                token_file: current_token_path,
                previous_token_file: Some(previous_token_path.clone()),
                allowed_target: upstream_addr,
            },
            test_runtime_limits(),
            sink.clone(),
        )
        .await
        .unwrap();
        let (raw_endpoint, connection) =
            connect_raw_proxy(server.local_addr(), &certificate_path).await;

        write_test_token(&previous_token_path, b"too-short");
        assert!(server.reload_tokens().is_err());
        let previous_request = encode_proxy_request(previous_token, upstream_addr).unwrap();
        assert_eq!(
            send_raw_request(&connection, &previous_request).await,
            STATUS_OK,
            "失败重载后必须继续使用完整的旧内存状态"
        );

        connection.close(0_u8.into(), b"test complete");
        raw_endpoint.close(0_u8.into(), b"test complete");
        server.shutdown().await;
        upstream_task.await.unwrap();

        let logs = sink.lines().join("\n");
        assert!(logs.contains("credentials_reload_failed"));
        assert!(!logs.contains(std::str::from_utf8(current_token).unwrap()));
        assert!(!logs.contains(std::str::from_utf8(previous_token).unwrap()));
        assert!(!logs.contains(&previous_token_path.display().to_string()));
        let observation = crate::analyze_proxy_jsonl(std::io::Cursor::new(logs)).unwrap();
        assert_eq!(observation.server.credential_reload_failures, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_tls_proxy_supports_multipath_and_concurrent_streams() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = echo_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                });
            }
        });

        let server = start_proxy_server(ProxyServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate_der: certificate_path.clone(),
            private_key_der: key_path,
            token_file: token_path.clone(),
            previous_token_file: None,
            allowed_target: echo_addr,
        })
        .await
        .unwrap();
        let client = start_proxy_client(ProxyClientConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server: server.local_addr().to_string(),
            server_name: "localhost".to_owned(),
            ca_certificate_der: certificate_path,
            token_file: token_path,
            target: echo_addr,
            primary_local_ip: Some("127.0.0.1".parse().unwrap()),
            additional_local_ips: vec!["127.0.0.2".parse().unwrap()],
        })
        .await
        .unwrap();

        let mut tasks = Vec::new();
        for sequence in 0_u8..8 {
            let client_addr = client.local_addr();
            tasks.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(client_addr).await.unwrap();
                let payload = vec![sequence; 32 * 1024 + usize::from(sequence)];
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                stream.read_to_end(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
            }));
        }
        timeout(Duration::from_secs(15), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect("并发代理流应在超时前闭合");

        client.shutdown().await;
        server.shutdown().await;
        echo_task.abort();
        let _ = echo_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn live_server_rejects_bad_magic_token_and_target_before_upstream_connect() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let allowed_target = upstream.local_addr().unwrap();
        let server = start_proxy_server(ProxyServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate_der: certificate_path.clone(),
            private_key_der: key_path,
            token_file: token_path,
            previous_token_file: None,
            allowed_target,
        })
        .await
        .unwrap();
        let (raw_endpoint, connection) =
            connect_raw_proxy(server.local_addr(), &certificate_path).await;

        let mut wrong_magic = encode_proxy_request(&[0xA5; 48], allowed_target).unwrap();
        wrong_magic[..4].copy_from_slice(b"BAD1");
        assert_eq!(
            send_raw_request(&connection, &wrong_magic).await,
            STATUS_VERSION
        );

        let wrong_token = encode_proxy_request(&[0x5A; 48], allowed_target).unwrap();
        assert_eq!(
            send_raw_request(&connection, &wrong_token).await,
            STATUS_AUTHORIZATION
        );

        let wrong_target =
            encode_proxy_request(&[0xA5; 48], "127.0.0.1:1".parse().unwrap()).unwrap();
        assert_eq!(
            send_raw_request(&connection, &wrong_target).await,
            STATUS_TARGET
        );
        assert!(
            timeout(Duration::from_millis(100), upstream.accept())
                .await
                .is_err(),
            "拒绝请求不得触发固定上游连接"
        );

        connection.close(0_u8.into(), b"test complete");
        raw_endpoint.close(0_u8.into(), b"test complete");
        server.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_proxy_request_is_rejected_before_upstream_connect() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let limits = ProxyRuntimeLimits {
            request_timeout: Duration::from_millis(50),
            ..test_runtime_limits()
        };
        let server = start_proxy_server_with_limits(
            ProxyServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_der: certificate_path.clone(),
                private_key_der: key_path,
                token_file: token_path,
                previous_token_file: None,
                allowed_target: upstream.local_addr().unwrap(),
            },
            limits,
        )
        .await
        .unwrap();
        let (raw_endpoint, connection) =
            connect_raw_proxy(server.local_addr(), &certificate_path).await;

        let (mut send_guard, mut receive) = connection.open_bi().await.unwrap();
        send_guard.write_all(&[0_u8]).await.unwrap();
        let mut status = [0_u8; 1];
        timeout(Duration::from_secs(1), receive.read_exact(&mut status))
            .await
            .expect("慢请求应在产品截止时间内被拒绝")
            .unwrap();
        assert_eq!(status[0], STATUS_FORMAT);
        assert!(
            timeout(Duration::from_millis(100), upstream.accept())
                .await
                .is_err(),
            "请求超时不得连接固定上游"
        );

        connection.close(0_u8.into(), b"test complete");
        raw_endpoint.close(0_u8.into(), b"test complete");
        server.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_connection_limit_refuses_a_second_handshake() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let limits = ProxyRuntimeLimits {
            max_server_connections: 1,
            ..test_runtime_limits()
        };
        let server = start_proxy_server_with_limits(
            ProxyServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_der: certificate_path.clone(),
                private_key_der: key_path,
                token_file: token_path,
                previous_token_file: None,
                allowed_target: "127.0.0.1:9".parse().unwrap(),
            },
            limits,
        )
        .await
        .unwrap();
        let (first_endpoint, first_connection) =
            connect_raw_proxy(server.local_addr(), &certificate_path).await;

        let second = timeout(
            Duration::from_secs(2),
            try_connect_raw_proxy(server.local_addr(), &certificate_path),
        )
        .await
        .expect("第二次握手应被立即拒绝");
        assert!(second.is_err());

        first_connection.close(0_u8.into(), b"test complete");
        first_endpoint.close(0_u8.into(), b"test complete");
        server.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn client_stream_limit_closes_excess_local_connections() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        use tokio::sync::oneshot;

        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            drop(stream);
        });

        let server = start_proxy_server_with_limits(
            ProxyServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_der: certificate_path.clone(),
                private_key_der: key_path,
                token_file: token_path.clone(),
                previous_token_file: None,
                allowed_target: upstream_addr,
            },
            test_runtime_limits(),
        )
        .await
        .unwrap();
        let client_limits = ProxyRuntimeLimits {
            max_client_streams: 1,
            ..test_runtime_limits()
        };
        let client = start_proxy_client_with_limits(
            ProxyClientConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server: server.local_addr().to_string(),
                server_name: "localhost".to_owned(),
                ca_certificate_der: certificate_path,
                token_file: token_path,
                target: upstream_addr,
                primary_local_ip: None,
                additional_local_ips: Vec::new(),
            },
            client_limits,
        )
        .await
        .unwrap();

        let first = TcpStream::connect(client.local_addr()).await.unwrap();
        timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("首个代理流应连接固定上游")
            .unwrap();

        let mut second = TcpStream::connect(client.local_addr()).await.unwrap();
        let mut buffer = [0_u8; 1];
        let closed = timeout(Duration::from_secs(1), second.read(&mut buffer))
            .await
            .expect("超额本地连接应被及时关闭");
        assert!(matches!(closed, Ok(0) | Err(_)));

        drop(first);
        let _ = release_tx.send(());
        upstream_task.await.unwrap();
        client.shutdown().await;
        server.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_upstream_stream_does_not_terminate_existing_stream() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        use tokio::sync::oneshot;

        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            drop(upstream);
            let _ = accepted_tx.send(());
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });

        let server = start_proxy_server(ProxyServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate_der: certificate_path.clone(),
            private_key_der: key_path,
            token_file: token_path.clone(),
            previous_token_file: None,
            allowed_target: upstream_addr,
        })
        .await
        .unwrap();
        let client = start_proxy_client(ProxyClientConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server: server.local_addr().to_string(),
            server_name: "localhost".to_owned(),
            ca_certificate_der: certificate_path,
            token_file: token_path,
            target: upstream_addr,
            primary_local_ip: None,
            additional_local_ips: Vec::new(),
        })
        .await
        .unwrap();

        let mut first = TcpStream::connect(client.local_addr()).await.unwrap();
        first.write_all(b"before").await.unwrap();
        let mut first_echo = [0_u8; 6];
        first.read_exact(&mut first_echo).await.unwrap();
        assert_eq!(&first_echo, b"before");
        accepted_rx.await.unwrap();

        let mut rejected = TcpStream::connect(client.local_addr()).await.unwrap();
        rejected.write_all(b"must fail").await.unwrap();
        let mut rejected_response = Vec::new();
        timeout(
            Duration::from_secs(3),
            rejected.read_to_end(&mut rejected_response),
        )
        .await
        .expect("上游失败的数据流应及时关闭")
        .ok();
        assert!(rejected_response.is_empty());

        first.write_all(b"after").await.unwrap();
        first.shutdown().await.unwrap();
        let mut remaining = Vec::new();
        first.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(&remaining, b"after");

        client.shutdown().await;
        server.shutdown().await;
        upstream_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn jsonl_events_are_parseable_and_do_not_expose_secrets_or_payloads() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let secret_token = b"FLOWWEAVE_TEST_TOKEN_0123456789_ABCDEFGHIJKLMN";
        fs::write(&token_path, secret_token).unwrap();
        set_private_permissions(&token_path);
        let private_key_bytes = fs::read(&key_path).unwrap();
        let private_key_marker = format!("{:?}", &private_key_bytes[..16]);
        let payload = b"FLOWWEAVE_APPLICATION_PAYLOAD_MUST_NOT_APPEAR";

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        let sink = Arc::new(TestEventSink::default());
        let server = start_proxy_server_with_limits_and_sink(
            ProxyServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_der: certificate_path.clone(),
                private_key_der: key_path.clone(),
                token_file: token_path.clone(),
                previous_token_file: None,
                allowed_target: upstream_addr,
            },
            test_runtime_limits(),
            sink.clone(),
        )
        .await
        .unwrap();
        let client = start_proxy_client_with_limits_and_sink(
            ProxyClientConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server: server.local_addr().to_string(),
                server_name: "localhost".to_owned(),
                ca_certificate_der: certificate_path,
                token_file: token_path,
                target: upstream_addr,
                primary_local_ip: None,
                additional_local_ips: Vec::new(),
            },
            test_runtime_limits(),
            sink.clone(),
        )
        .await
        .unwrap();

        assert_eq!(server.reload_tokens().unwrap(), 1);
        assert_eq!(client.reload_tokens().unwrap(), 1);

        let mut stream = TcpStream::connect(client.local_addr()).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        let client_snapshot = client.shutdown().await;
        let server_snapshot = server.shutdown().await;
        upstream_task.await.unwrap();
        assert_eq!(client_snapshot.active_connections, 0);
        assert_eq!(client_snapshot.active_streams, 0);
        assert_eq!(client_snapshot.total_streams, 1);
        assert_eq!(client_snapshot.upload_bytes, payload.len() as u64);
        assert_eq!(client_snapshot.download_bytes, payload.len() as u64);
        assert_eq!(server_snapshot.active_connections, 0);
        assert_eq!(server_snapshot.active_streams, 0);

        let lines = sink.lines();
        assert!(!lines.is_empty());
        let mut saw_connection_id = false;
        let mut saw_metrics = false;
        for line in &lines {
            assert!(!line.contains('\n'), "单条事件不得包含嵌入换行");
            let record: Value = serde_json::from_str(line).expect("每行都必须是有效 JSON");
            assert_eq!(record["schema"], PROXY_EVENT_SCHEMA);
            assert!(record["ts_unix_ms"].as_u64().is_some());
            assert!(record["level"].as_str().is_some());
            assert!(record["role"].as_str().is_some());
            assert!(record["event"].as_str().is_some());
            if record["event"] == "connection_started" {
                saw_connection_id |= record["connection_id"].as_u64().is_some();
            }
            saw_metrics |= record["event"] == "metrics_snapshot";
        }
        assert!(saw_connection_id);
        assert!(saw_metrics);

        let logs = lines.join("\n");
        assert!(logs.contains("credentials_reloaded"));
        assert!(!logs.contains(std::str::from_utf8(secret_token).unwrap()));
        assert!(!logs.contains(std::str::from_utf8(payload).unwrap()));
        assert!(!logs.contains(&key_path.display().to_string()));
        assert!(!logs.contains("private-key.der"));
        assert!(!logs.contains(&private_key_marker));
        let health = crate::analyze_proxy_jsonl(std::io::Cursor::new(logs))
            .unwrap()
            .evaluate(crate::ProxyHealthPolicy::strict_both());
        assert!(health.healthy, "{:?}", health.violations);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn graceful_shutdown_stops_accepting_and_drains_an_existing_stream() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        let sink = Arc::new(TestEventSink::default());
        let server = start_proxy_server_with_limits_and_sink(
            ProxyServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_der: certificate_path.clone(),
                private_key_der: key_path,
                token_file: token_path.clone(),
                previous_token_file: None,
                allowed_target: upstream_addr,
            },
            test_runtime_limits(),
            sink.clone(),
        )
        .await
        .unwrap();
        let client = start_proxy_client_with_limits_and_sink(
            ProxyClientConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server: server.local_addr().to_string(),
                server_name: "localhost".to_owned(),
                ca_certificate_der: certificate_path,
                token_file: token_path,
                target: upstream_addr,
                primary_local_ip: None,
                additional_local_ips: Vec::new(),
            },
            test_runtime_limits(),
            sink.clone(),
        )
        .await
        .unwrap();

        let client_addr = client.local_addr();
        let mut stream = TcpStream::connect(client_addr).await.unwrap();
        stream.write_all(b"before-shutdown").await.unwrap();
        let mut first_echo = [0_u8; 15];
        stream.read_exact(&mut first_echo).await.unwrap();
        assert_eq!(&first_echo, b"before-shutdown");

        let shutdown_task = tokio::spawn(async move { client.shutdown().await });
        sink.wait_for_event("client", "shutdown_started").await;
        let new_connection = timeout(Duration::from_secs(1), TcpStream::connect(client_addr))
            .await
            .expect("关闭接入后连接尝试必须及时结束");
        assert!(new_connection.is_err(), "关闭接入后不得接受新的本地 TCP");

        stream.write_all(b"during-drain").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut remaining = Vec::new();
        stream.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(&remaining, b"during-drain");

        let snapshot = timeout(Duration::from_secs(3), shutdown_task)
            .await
            .expect("现有流应在 drain 截止内结束")
            .unwrap();
        assert_eq!(snapshot.graceful_shutdowns, 1);
        assert_eq!(snapshot.forced_shutdowns, 0);
        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.active_streams, 0);
        server.shutdown().await;
        upstream_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_timeout_forces_remaining_streams_and_clears_active_gauges() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        use tokio::sync::oneshot;

        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            drop(stream);
        });

        let server = start_proxy_server_with_limits(
            ProxyServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                certificate_der: certificate_path.clone(),
                private_key_der: key_path,
                token_file: token_path.clone(),
                previous_token_file: None,
                allowed_target: upstream_addr,
            },
            test_runtime_limits(),
        )
        .await
        .unwrap();
        let client_limits = ProxyRuntimeLimits {
            shutdown_drain_timeout: Duration::from_millis(75),
            ..test_runtime_limits()
        };
        let client = start_proxy_client_with_limits(
            ProxyClientConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server: server.local_addr().to_string(),
                server_name: "localhost".to_owned(),
                ca_certificate_der: certificate_path,
                token_file: token_path,
                target: upstream_addr,
                primary_local_ip: None,
                additional_local_ips: Vec::new(),
            },
            client_limits,
        )
        .await
        .unwrap();

        let client_addr = client.local_addr();
        let mut stream = TcpStream::connect(client_addr).await.unwrap();
        stream.write_all(b"keep-open").await.unwrap();
        timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("代理流应连接固定上游")
            .unwrap();

        let shutdown_started = Instant::now();
        let snapshot = timeout(Duration::from_secs(1), client.shutdown())
            .await
            .expect("强制关闭必须受 drain 截止约束");
        assert!(shutdown_started.elapsed() < Duration::from_secs(1));
        assert_eq!(snapshot.graceful_shutdowns, 0);
        assert_eq!(snapshot.forced_shutdowns, 1);
        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.active_streams, 0);
        assert_eq!(snapshot.total_streams, 1);
        assert!(TcpStream::connect(client_addr).await.is_err());

        let mut closed = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), stream.read(&mut closed))
            .await
            .expect("强制关闭后本地流必须及时结束");
        assert!(matches!(read, Ok(0) | Err(_)));
        let _ = release_tx.send(());
        upstream_task.await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_ca_or_server_name_fails_tls() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let directory = TestDirectory::new();
        let (certificate_path, key_path, token_path) = write_test_credentials(&directory);
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other_ca = directory.path().join("other-ca.der");
        fs::write(&other_ca, other.cert.der()).unwrap();

        let server = start_proxy_server(ProxyServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate_der: certificate_path.clone(),
            private_key_der: key_path,
            token_file: token_path.clone(),
            previous_token_file: None,
            allowed_target: "127.0.0.1:9".parse().unwrap(),
        })
        .await
        .unwrap();
        let base = ProxyClientConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server: server.local_addr().to_string(),
            server_name: "localhost".to_owned(),
            ca_certificate_der: other_ca,
            token_file: token_path,
            target: "127.0.0.1:9".parse().unwrap(),
            primary_local_ip: None,
            additional_local_ips: Vec::new(),
        };
        assert!(start_proxy_client(base.clone()).await.is_err());

        let wrong_name = ProxyClientConfig {
            ca_certificate_der: certificate_path,
            server_name: "not-localhost.invalid".to_owned(),
            ..base
        };
        assert!(start_proxy_client(wrong_name).await.is_err());
        server.shutdown().await;
    }

    async fn connect_raw_proxy(
        server_addr: SocketAddr,
        certificate_path: &Path,
    ) -> (Endpoint, Connection) {
        try_connect_raw_proxy(server_addr, certificate_path)
            .await
            .unwrap()
    }

    async fn try_connect_raw_proxy(
        server_addr: SocketAddr,
        certificate_path: &Path,
    ) -> LabResult<(Endpoint, Connection)> {
        let mut roots = RootCertStore::empty();
        roots.add(read_certificate(certificate_path)?)?;
        let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;
        let mut transport = TransportConfig::default();
        configure_product_transport(&mut transport, 1, 0);
        client_config.transport_config(Arc::new(transport));
        let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(server_addr, "localhost")
            .map_err(|error| other_error(format!("测试客户端无法开始连接：{error}")))?
            .await?;
        connection.handshake_confirmed().await?;
        Ok((endpoint, connection))
    }

    async fn send_raw_request(connection: &Connection, request: &[u8]) -> u8 {
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        send.write_all(request).await.unwrap();
        let mut status = [0_u8; 1];
        receive.read_exact(&mut status).await.unwrap();
        status[0]
    }

    async fn assert_proxy_echo(client_addr: SocketAddr, payload: &[u8]) {
        let mut stream = TcpStream::connect(client_addr).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        timeout(Duration::from_secs(3), stream.read_to_end(&mut echoed))
            .await
            .expect("代理回显应在截止时间内完成")
            .unwrap();
        assert_eq!(echoed, payload);
    }

    fn write_test_credentials(directory: &TestDirectory) -> (PathBuf, PathBuf, PathBuf) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_path = directory.path().join("certificate.der");
        let key_path = directory.path().join("private-key.der");
        let token_path = directory.path().join("token");
        fs::write(&certificate_path, generated.cert.der()).unwrap();
        fs::write(&key_path, generated.signing_key.serialize_der()).unwrap();
        fs::write(&token_path, vec![0xA5; 48]).unwrap();
        set_private_permissions(&key_path);
        set_private_permissions(&token_path);
        (certificate_path, key_path, token_path)
    }

    fn write_test_token(path: &Path, token: &[u8]) {
        fs::write(path, token).unwrap();
        set_private_permissions(path);
    }

    #[cfg(unix)]
    fn set_private_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_private_permissions(_path: &Path) {}
}

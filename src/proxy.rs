use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use noq::{
    ClientConfig, Connection, ConnectionError, Endpoint, FourTuple, PathError, PathId, PathStatus,
    ServerConfig, TransportConfig,
    rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};
use subtle::ConstantTimeEq;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, lookup_host},
    sync::Semaphore,
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

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
}

const PRODUCT_RUNTIME_LIMITS: ProxyRuntimeLimits = ProxyRuntimeLimits {
    max_server_connections: PRODUCT_MAX_SERVER_CONNECTIONS,
    max_streams_per_connection: PRODUCT_MAX_STREAMS_PER_CONNECTION,
    max_client_streams: PRODUCT_MAX_CLIENT_STREAMS,
    handshake_timeout: PRODUCT_HANDSHAKE_TIMEOUT,
    request_timeout: PRODUCT_REQUEST_TIMEOUT,
    upstream_connect_timeout: PRODUCT_UPSTREAM_CONNECT_TIMEOUT,
    stream_open_timeout: PRODUCT_STREAM_OPEN_TIMEOUT,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyServerConfig {
    pub listen: SocketAddr,
    pub certificate_der: PathBuf,
    pub private_key_der: PathBuf,
    pub token_file: PathBuf,
    pub allowed_target: SocketAddr,
}

impl ProxyServerConfig {
    pub fn load(path: impl AsRef<Path>) -> LabResult<Self> {
        let path = path.as_ref();
        let values = load_key_values(path, &SERVER_REQUIRED_KEYS, &[])?;
        let base = config_base(path);
        Ok(Self {
            listen: parse_socket_addr(required(&values, "listen")?, "listen")?,
            certificate_der: resolve_path(&base, required(&values, "certificate_der")?),
            private_key_der: resolve_path(&base, required(&values, "private_key_der")?),
            token_file: resolve_path(&base, required(&values, "token_file")?),
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

#[derive(Debug)]
pub struct ProxyRuntime {
    local_addr: SocketAddr,
    task: Option<JoinHandle<LabResult<()>>>,
}

impl ProxyRuntime {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn wait(mut self) -> LabResult<()> {
        let task = self
            .task
            .take()
            .ok_or_else(|| other_error("代理运行任务已经结束"))?;
        task.await
            .map_err(|error| other_error(format!("代理运行任务异常退出：{error}")))?
    }

    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

pub async fn run_proxy_server(path: impl AsRef<Path>) -> LabResult<()> {
    let runtime = start_proxy_server(ProxyServerConfig::load(path)?).await?;
    eprintln!("FlowWeave 服务端正在监听 UDP {}", runtime.local_addr());
    runtime.wait().await
}

pub async fn run_proxy_client(path: impl AsRef<Path>) -> LabResult<()> {
    let runtime = start_proxy_client(ProxyClientConfig::load(path)?).await?;
    eprintln!("FlowWeave 客户端正在监听 TCP {}", runtime.local_addr());
    runtime.wait().await
}

pub async fn start_proxy_server(config: ProxyServerConfig) -> LabResult<ProxyRuntime> {
    start_proxy_server_with_limits(config, PRODUCT_RUNTIME_LIMITS).await
}

async fn start_proxy_server_with_limits(
    config: ProxyServerConfig,
    limits: ProxyRuntimeLimits,
) -> LabResult<ProxyRuntime> {
    let certificate = read_certificate(&config.certificate_der)?;
    let private_key = read_private_key(&config.private_key_der)?;
    let token = Arc::new(read_token(&config.token_file)?);

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
    let task = tokio::spawn(async move {
        run_server_accept_loop(endpoint, token, allowed_target, limits).await
    });
    Ok(ProxyRuntime {
        local_addr,
        task: Some(task),
    })
}

pub async fn start_proxy_client(config: ProxyClientConfig) -> LabResult<ProxyRuntime> {
    start_proxy_client_with_limits(config, PRODUCT_RUNTIME_LIMITS).await
}

async fn start_proxy_client_with_limits(
    config: ProxyClientConfig,
    limits: ProxyRuntimeLimits,
) -> LabResult<ProxyRuntime> {
    let certificate = read_certificate(&config.ca_certificate_der)?;
    let token = Arc::new(read_token(&config.token_file)?);
    let server_addr = timeout(limits.handshake_timeout, resolve_server_addr(&config))
        .await
        .map_err(|_| other_error("解析服务端地址超时"))??;
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
    let connection = timeout(limits.handshake_timeout, connecting)
        .await
        .map_err(|_| other_error("客户端 TLS 连接超时"))??;
    if !connection.is_multipath_enabled() {
        connection.close(0_u8.into(), b"multipath negotiation failed");
        return Err(other_error("客户端和服务端没有协商成功 MPQUIC"));
    }
    timeout(limits.handshake_timeout, connection.handshake_confirmed())
        .await
        .map_err(|_| other_error("客户端等待 TLS 确认超时"))??;

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
    let task = tokio::spawn(async move {
        run_client_accept_loop(endpoint, connection, listener, token, target, limits).await
    });
    Ok(ProxyRuntime {
        local_addr,
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
    token: Arc<Vec<u8>>,
    allowed_target: SocketAddr,
    limits: ProxyRuntimeLimits,
) -> LabResult<()> {
    let connection_slots = Arc::new(Semaphore::new(limits.max_server_connections));
    loop {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| other_error("服务端 Endpoint 已停止监听"))?;
        let connection_slot = match connection_slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                eprintln!("event=proxy_connection_refused reason=connection_limit");
                incoming.refuse();
                continue;
            }
        };
        let token = token.clone();
        tokio::spawn(async move {
            let _connection_slot = connection_slot;
            let result = async {
                let connection = timeout(limits.handshake_timeout, async move { incoming.await })
                    .await
                    .map_err(|_| other_error("服务端 TLS 握手超时"))??;
                if !connection.is_multipath_enabled() {
                    connection.close(0_u8.into(), b"multipath required");
                    return Err(other_error("入站连接没有协商 MPQUIC"));
                }
                serve_proxy_connection(connection, token, allowed_target, limits).await
            }
            .await;
            if let Err(error) = result {
                eprintln!("FlowWeave 服务端连接结束：{error}");
            }
        });
    }
}

async fn serve_proxy_connection(
    connection: Connection,
    token: Arc<Vec<u8>>,
    allowed_target: SocketAddr,
    limits: ProxyRuntimeLimits,
) -> LabResult<()> {
    loop {
        let (send, receive) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_server_stream(send, receive, &token, allowed_target, limits).await
            {
                eprintln!("FlowWeave 服务端数据流结束：{error}");
            }
        });
    }
}

async fn handle_server_stream(
    mut send: noq::SendStream,
    mut receive: noq::RecvStream,
    expected_token: &[u8],
    allowed_target: SocketAddr,
    limits: ProxyRuntimeLimits,
) -> LabResult<()> {
    let request = match timeout(limits.request_timeout, read_proxy_request(&mut receive)).await {
        Ok(Ok(request)) => request,
        Ok(Err(rejection)) => {
            send_status(&mut send, rejection.status).await?;
            return Err(other_error(rejection.message));
        }
        Err(_) => {
            send_status(&mut send, STATUS_FORMAT).await?;
            return Err(other_error("代理请求读取超时"));
        }
    };

    if !token_matches(expected_token, &request.token) {
        send_status(&mut send, STATUS_AUTHORIZATION).await?;
        return Err(other_error("代理令牌验证失败"));
    }
    if request.target != allowed_target {
        send_status(&mut send, STATUS_TARGET).await?;
        return Err(other_error("代理请求目标不在允许范围内"));
    }

    let upstream = match timeout(
        limits.upstream_connect_timeout,
        TcpStream::connect(allowed_target),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(error)) => {
            send_status(&mut send, STATUS_UPSTREAM).await?;
            return Err(other_error(format!("无法连接固定上游：{error}")));
        }
        Err(_) => {
            send_status(&mut send, STATUS_UPSTREAM).await?;
            return Err(other_error("连接固定上游超时"));
        }
    };
    send.write_all(&[STATUS_OK]).await?;
    relay_tcp_and_quic(upstream, send, receive).await
}

async fn run_client_accept_loop(
    _endpoint: Endpoint,
    connection: Connection,
    listener: TcpListener,
    token: Arc<Vec<u8>>,
    target: SocketAddr,
    limits: ProxyRuntimeLimits,
) -> LabResult<()> {
    let stream_slots = Arc::new(Semaphore::new(limits.max_client_streams));
    loop {
        tokio::select! {
            error = connection.closed() => {
                return Err(other_error(format!("到服务端的 FlowWeave 连接已关闭：{error}")));
            }
            accepted = listener.accept() => {
                let (local, _) = accepted?;
                let stream_slot = match stream_slots.clone().try_acquire_owned() {
                    Ok(slot) => slot,
                    Err(_) => {
                        eprintln!("event=proxy_stream_refused reason=client_stream_limit");
                        drop(local);
                        continue;
                    }
                };
                let connection = connection.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    let _stream_slot = stream_slot;
                    if let Err(error) =
                        handle_client_stream(connection, local, &token, target, limits).await
                    {
                        eprintln!("FlowWeave 客户端数据流结束：{error}");
                    }
                });
            }
        }
    }
}

async fn handle_client_stream(
    connection: Connection,
    local: TcpStream,
    token: &[u8],
    target: SocketAddr,
    limits: ProxyRuntimeLimits,
) -> LabResult<()> {
    let streams = timeout(limits.stream_open_timeout, connection.open_bi())
        .await
        .map_err(|_| other_error("打开代理 QUIC 数据流超时"))?;
    let (mut send, mut receive) = streams?;
    let request = encode_proxy_request(token, target)?;

    let mut status = [0_u8; 1];
    timeout(limits.request_timeout, async {
        send.write_all(&request).await?;
        receive.read_exact(&mut status).await?;
        Ok::<(), super::LabError>(())
    })
    .await
    .map_err(|_| other_error("代理数据流协商超时"))??;
    if status[0] != STATUS_OK {
        return Err(other_error(format!(
            "服务端拒绝代理数据流（状态 {}）",
            status[0]
        )));
    }
    relay_tcp_and_quic(local, send, receive).await
}

async fn relay_tcp_and_quic(
    tcp: TcpStream,
    mut quic_send: noq::SendStream,
    mut quic_receive: noq::RecvStream,
) -> LabResult<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let upload = async {
        tokio::io::copy(&mut tcp_read, &mut quic_send).await?;
        quic_send.shutdown().await?;
        Ok::<(), io::Error>(())
    };
    let download = async {
        tokio::io::copy(&mut quic_receive, &mut tcp_write).await?;
        tcp_write.shutdown().await?;
        Ok::<(), io::Error>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
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
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use tokio::io::AsyncReadExt;
    use tokio::time::timeout;

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_runtime_limits() -> ProxyRuntimeLimits {
        ProxyRuntimeLimits {
            max_server_connections: 4,
            max_streams_per_connection: 4,
            max_client_streams: 4,
            handshake_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            upstream_connect_timeout: Duration::from_secs(2),
            stream_open_timeout: Duration::from_secs(2),
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
            for required_line in [
                "User=flowweave",
                "UMask=0077",
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

    #[cfg(unix)]
    fn set_private_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_private_permissions(_path: &Path) {}
}

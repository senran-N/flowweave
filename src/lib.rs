use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use noq::{
    ClientConfig, Connection, ConnectionError, Endpoint, FourTuple, Path, PathError, PathId,
    PathStats, PathStatus, ServerConfig, TransportConfig,
    rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};

pub type LabError = Box<dyn Error + Send + Sync + 'static>;
pub type LabResult<T> = Result<T, LabError>;

const MAGIC: &[u8; 4] = b"FWL1";
const DATAGRAM_MAGIC: &[u8; 4] = b"FWDG";
const DATAGRAM_PROBE_SIZE: usize = 8;
const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;
const MAX_FRAME_SIZE: usize = MAX_PAYLOAD_SIZE + 8;
const MAX_DATAGRAM_PROBES: usize = 2_000;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const FAILOVER_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(8);
const NETWORK_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
const DATAGRAM_SEND_INTERVAL: Duration = Duration::from_millis(5);
const DATAGRAM_RECEIVE_GRACE: Duration = Duration::from_millis(1_500);
const LINE_ONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LINE_TWO_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

#[derive(Debug)]
pub struct BasicLabReport {
    pub multipath_negotiated: bool,
    pub primary_carried_data: bool,
    pub primary_bytes_sent: u64,
    pub secondary_carried_data: bool,
    pub secondary_bytes_sent: u64,
    pub failover_transfer_ok: bool,
    pub datagram_echoes: usize,
    pub datagram_p95: Duration,
    pub path_limit_rejected: bool,
    pub malformed_frame_rejected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    LineOneOnly,
    LineTwoOnly,
    MultipathAvailable,
}

impl PathMode {
    pub fn description(self) -> &'static str {
        match self {
            Self::LineOneOnly => "仅线路一",
            Self::LineTwoOnly => "仅线路二",
            Self::MultipathAvailable => "NoQ 默认多路径",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkBenchmarkConfig {
    pub mode: PathMode,
    pub transfer_size: usize,
    pub datagram_count: usize,
}

impl NetworkBenchmarkConfig {
    pub fn new(mode: PathMode, transfer_size: usize, datagram_count: usize) -> Self {
        Self {
            mode,
            transfer_size,
            datagram_count,
        }
    }

    fn validate(self) -> LabResult<()> {
        if self.transfer_size == 0 {
            return Err(other_error("网络实验的传输大小不能为 0"));
        }
        if self.transfer_size > MAX_PAYLOAD_SIZE {
            return Err(other_error(format!(
                "网络实验的传输大小不能超过 {MAX_PAYLOAD_SIZE} 字节"
            )));
        }
        if self.datagram_count > MAX_DATAGRAM_PROBES {
            return Err(other_error(format!(
                "Datagram 探针数量不能超过 {MAX_DATAGRAM_PROBES}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PathMeasurement {
    pub udp_bytes_sent: u64,
    pub udp_datagrams_sent: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub final_rtt: Duration,
}

#[derive(Debug, Clone)]
pub struct DatagramMeasurement {
    pub sent: usize,
    pub echoed: usize,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub p99: Option<Duration>,
}

impl DatagramMeasurement {
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        ((self.sent - self.echoed) as f64 / self.sent as f64) * 100.0
    }
}

#[derive(Debug, Clone)]
pub struct NetworkBenchmarkReport {
    pub mode: PathMode,
    pub multipath_negotiated: bool,
    pub transfer_size: usize,
    pub transfer_duration: Duration,
    pub throughput_mbps: f64,
    pub datagrams: DatagramMeasurement,
    pub line_one: PathMeasurement,
    pub line_two: PathMeasurement,
    pub total_udp_bytes_sent: u64,
    pub extra_udp_bytes_sent: u64,
}

impl NetworkBenchmarkReport {
    pub fn both_paths_carried_meaningful_traffic(&self) -> bool {
        if self.mode != PathMode::MultipathAvailable {
            return false;
        }
        let threshold = (self.transfer_size as u64 / 20).max(16 * 1024);
        self.line_one.udp_bytes_sent >= threshold && self.line_two.udp_bytes_sent >= threshold
    }
}

#[derive(Debug, Clone)]
pub struct FailoverReport {
    pub recovered: bool,
    pub recovery_time: Option<Duration>,
    pub failure_reason: Option<String>,
    pub configured_path_idle_timeout: Duration,
    pub primary_bytes_after_blackhole: u64,
    pub secondary_bytes_after_blackhole: u64,
    pub primary_lost_packets: u64,
    pub secondary_lost_packets: u64,
}

struct RunningLab {
    server_task: JoinHandle<LabResult<()>>,
    client_endpoint: Endpoint,
    connection: Connection,
    server_addr: SocketAddr,
    primary: Path,
}

impl RunningLab {
    async fn open_second_path(&self, status: PathStatus) -> LabResult<Path> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(other_error("等待新路径所需的连接标识超时"));
            }

            match timeout(
                remaining,
                self.connection.open_path(
                    FourTuple::new(self.server_addr, Some(IpAddr::V4(LINE_TWO_IP))),
                    status,
                ),
            )
            .await
            {
                Ok(Ok(path)) => return Ok(path),
                Ok(Err(PathError::RemoteCidsExhausted)) => {
                    sleep(Duration::from_millis(50).min(remaining)).await;
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => return Err(other_error("建立第二条 MPQUIC 路径超时")),
            }
        }
    }

    async fn shutdown(self) -> LabResult<()> {
        self.connection.close(0_u8.into(), b"lab complete");
        self.client_endpoint.wait_all_draining().await;

        match timeout(OPERATION_TIMEOUT, self.server_task).await {
            Ok(joined) => {
                joined.map_err(|error| other_error(format!("服务端任务异常退出：{error}")))??;
                Ok(())
            }
            Err(_) => Err(other_error("服务端没有在连接关闭后及时退出")),
        }
    }
}

pub async fn run_basic_lab() -> LabResult<BasicLabReport> {
    let lab = start_connection(Ipv4Addr::UNSPECIFIED, None).await?;

    let report_result: LabResult<BasicLabReport> = async {
        let connection = &lab.connection;
        let primary = lab.primary.clone();
        let multipath_negotiated = connection.is_multipath_enabled();

        let primary_before = primary.stats().udp_tx.bytes;
        transfer_and_verify(connection, 256 * 1024, 11).await?;
        let primary_bytes_sent = primary.stats().udp_tx.bytes.saturating_sub(primary_before);
        let primary_carried_data = primary_bytes_sent >= 256 * 1024;

        let secondary = lab.open_second_path(PathStatus::Available).await?;

        let path_limit_rejected = matches!(
            timeout(
                OPERATION_TIMEOUT,
                connection.open_path(
                    FourTuple::new(
                        lab.server_addr,
                        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))),
                    ),
                    PathStatus::Available,
                ),
            )
            .await
            .map_err(|_| other_error("路径上限测试超时"))?,
            Err(PathError::MaxPathIdReached)
        );

        primary.set_status(PathStatus::Backup)?;
        secondary.set_status(PathStatus::Available)?;
        sleep(Duration::from_millis(100)).await;

        let secondary_before = secondary.stats().udp_tx.bytes;
        transfer_and_verify(connection, 512 * 1024, 29).await?;
        let secondary_bytes_sent = secondary
            .stats()
            .udp_tx
            .bytes
            .saturating_sub(secondary_before);
        let secondary_carried_data = secondary_bytes_sent >= 512 * 1024;

        let malformed_frame_rejected = send_malformed_frame(connection).await?;

        primary.close()?;
        sleep(Duration::from_millis(100)).await;
        transfer_and_verify(connection, 256 * 1024, 47).await?;

        let datagram_latencies = datagram_echo_test(connection, 24).await?;

        Ok(BasicLabReport {
            multipath_negotiated,
            primary_carried_data,
            primary_bytes_sent,
            secondary_carried_data,
            secondary_bytes_sent,
            failover_transfer_ok: true,
            datagram_echoes: datagram_latencies.len(),
            datagram_p95: percentile(&datagram_latencies, 95).expect("基础实验固定发送了 Datagram"),
            path_limit_rejected,
            malformed_frame_rejected,
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = report_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_network_benchmark(
    config: NetworkBenchmarkConfig,
) -> LabResult<NetworkBenchmarkReport> {
    config.validate()?;

    let client_ip = match config.mode {
        PathMode::LineOneOnly => LINE_ONE_IP,
        PathMode::LineTwoOnly => LINE_TWO_IP,
        PathMode::MultipathAvailable => Ipv4Addr::UNSPECIFIED,
    };
    let lab = start_connection(client_ip, Some(NETWORK_PATH_IDLE_TIMEOUT)).await?;

    let secondary = if config.mode == PathMode::MultipathAvailable {
        Some(lab.open_second_path(PathStatus::Available).await?)
    } else {
        None
    };
    sleep(Duration::from_millis(150)).await;

    let operation_result: LabResult<NetworkBenchmarkReport> = async {
        let primary_before = lab.primary.stats();
        let secondary_before = secondary.as_ref().map(Path::stats);

        let transfer_started = Instant::now();
        transfer_and_verify(&lab.connection, config.transfer_size, 83).await?;
        let transfer_duration = transfer_started.elapsed();

        let datagrams = datagram_echo_probe(&lab.connection, config.datagram_count).await?;

        let primary_after = lab.primary.stats();
        let secondary_after = secondary.as_ref().map(Path::stats);
        let primary_measurement = path_delta(primary_before, primary_after);
        let secondary_measurement = match (secondary_before, secondary_after) {
            (Some(before), Some(after)) => path_delta(before, after),
            _ => PathMeasurement::default(),
        };

        let (line_one, line_two) = match config.mode {
            PathMode::LineOneOnly => (primary_measurement, PathMeasurement::default()),
            PathMode::LineTwoOnly => (PathMeasurement::default(), primary_measurement),
            PathMode::MultipathAvailable => (primary_measurement, secondary_measurement),
        };
        let total_udp_bytes_sent = line_one
            .udp_bytes_sent
            .saturating_add(line_two.udp_bytes_sent);
        let application_bytes_sent = (config.transfer_size as u64).saturating_add(
            (config.datagram_count as u64).saturating_mul(DATAGRAM_PROBE_SIZE as u64),
        );

        Ok(NetworkBenchmarkReport {
            mode: config.mode,
            multipath_negotiated: lab.connection.is_multipath_enabled(),
            transfer_size: config.transfer_size,
            transfer_duration,
            throughput_mbps: throughput_mbps(config.transfer_size, transfer_duration),
            datagrams,
            line_one,
            line_two,
            total_udp_bytes_sent,
            extra_udp_bytes_sent: total_udp_bytes_sent.saturating_sub(application_bytes_sent),
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_blackhole_failover<F>(activate_blackhole: F) -> LabResult<FailoverReport>
where
    F: FnOnce() -> LabResult<()>,
{
    let lab = start_connection(Ipv4Addr::UNSPECIFIED, Some(NETWORK_PATH_IDLE_TIMEOUT)).await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;

    let operation_result: LabResult<FailoverReport> = async {
        transfer_and_verify(&lab.connection, 128 * 1024, 101).await?;

        let primary_before = lab.primary.stats();
        let secondary_before = secondary.stats();
        activate_blackhole()?;

        let failure_started = Instant::now();
        let transfer_result = timeout(
            FAILOVER_OBSERVATION_TIMEOUT,
            transfer_and_verify(&lab.connection, 256 * 1024, 113),
        )
        .await;

        let (recovered, recovery_time, failure_reason) = match transfer_result {
            Ok(Ok(())) => (true, Some(failure_started.elapsed()), None),
            Ok(Err(error)) => (false, None, Some(error.to_string())),
            Err(_) => (
                false,
                None,
                Some(format!(
                    "{} 秒观察窗口内没有恢复传输",
                    FAILOVER_OBSERVATION_TIMEOUT.as_secs()
                )),
            ),
        };

        let primary_after = lab.primary.stats();
        let secondary_after = secondary.stats();
        let primary_delta = path_delta(primary_before, primary_after);
        let secondary_delta = path_delta(secondary_before, secondary_after);

        Ok(FailoverReport {
            recovered,
            recovery_time,
            failure_reason,
            configured_path_idle_timeout: NETWORK_PATH_IDLE_TIMEOUT,
            primary_bytes_after_blackhole: primary_delta.udp_bytes_sent,
            secondary_bytes_after_blackhole: secondary_delta.udp_bytes_sent,
            primary_lost_packets: primary_delta.lost_packets,
            secondary_lost_packets: secondary_delta.lost_packets,
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

async fn start_connection(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
) -> LabResult<RunningLab> {
    let (server_config, client_config) = make_configs(path_idle_timeout)?;
    let server_endpoint =
        Endpoint::server(server_config, SocketAddr::new(IpAddr::V4(LINE_ONE_IP), 0))?;
    let server_addr = server_endpoint.local_addr()?;

    let server_task = tokio::spawn(async move {
        let incoming = timeout(OPERATION_TIMEOUT, server_endpoint.accept())
            .await
            .map_err(|_| other_error("服务端等待连接超时"))?
            .ok_or_else(|| other_error("服务端提前停止监听"))?;
        let connection = timeout(OPERATION_TIMEOUT, incoming)
            .await
            .map_err(|_| other_error("服务端握手超时"))??;
        serve_connection(connection).await
    });

    let client_endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(client_ip), 0))?;
    client_endpoint.set_default_client_config(client_config);

    let connection = timeout(
        OPERATION_TIMEOUT,
        client_endpoint
            .connect(server_addr, "localhost")
            .map_err(|error| other_error(format!("客户端无法开始连接：{error}")))?,
    )
    .await
    .map_err(|_| other_error("客户端握手超时"))??;

    if !connection.is_multipath_enabled() {
        connection.close(0_u8.into(), b"multipath negotiation failed");
        return Err(other_error("客户端和服务端没有协商成功 MPQUIC"));
    }

    let primary = connection
        .path(PathId::ZERO)
        .ok_or_else(|| other_error("连接成功后找不到主路径"))?;

    Ok(RunningLab {
        server_task,
        client_endpoint,
        connection,
        server_addr,
        primary,
    })
}

fn make_configs(path_idle_timeout: Option<Duration>) -> LabResult<(ServerConfig, ClientConfig)> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = CertificateDer::from(generated.cert);
    let private_key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())?;
    let server_transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| other_error("无法配置服务端传输参数"))?;
    configure_transport(server_transport, path_idle_timeout);

    let mut roots = noq::rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;
    let mut client_transport = TransportConfig::default();
    configure_transport(&mut client_transport, path_idle_timeout);
    client_config.transport_config(Arc::new(client_transport));

    Ok((server_config, client_config))
}

fn configure_transport(transport: &mut TransportConfig, path_idle_timeout: Option<Duration>) {
    transport
        .max_concurrent_multipath_paths(2)
        .default_path_max_idle_timeout(path_idle_timeout)
        .default_path_keep_alive_interval(Some(Duration::from_millis(200)))
        .datagram_receive_buffer_size(Some(1024 * 1024))
        .datagram_send_buffer_size(1024 * 1024);
}

async fn serve_connection(connection: Connection) -> LabResult<()> {
    let datagram_connection = connection.clone();
    let datagram_task = tokio::spawn(async move {
        loop {
            let data = match datagram_connection.read_datagram().await {
                Ok(data) => data,
                Err(ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed) => {
                    return Ok::<(), LabError>(());
                }
                Err(error) => return Err(error.into()),
            };

            datagram_connection
                .send_datagram_wait(data)
                .await
                .map_err(|error| other_error(format!("服务端回显 Datagram 失败：{error}")))?;
        }
    });

    loop {
        let (send, receive) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed) => break,
            Err(error) => return Err(error.into()),
        };

        tokio::spawn(async move {
            if let Err(error) = handle_stream(send, receive).await {
                eprintln!("服务端处理数据流失败：{error}");
            }
        });
    }

    match datagram_task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(other_error(format!("Datagram 回显任务异常退出：{error}"))),
    }
}

async fn handle_stream(mut send: noq::SendStream, mut receive: noq::RecvStream) -> LabResult<()> {
    let request = receive.read_to_end(MAX_FRAME_SIZE).await?;
    let response = match parse_frame(&request) {
        Ok(payload) => make_success_response(payload),
        Err(reason) => make_error_response(reason),
    };

    send.write_all(&response).await?;
    send.finish()?;
    Ok(())
}

async fn transfer_and_verify(connection: &Connection, size: usize, seed: u8) -> LabResult<()> {
    let payload = make_payload(size, seed);
    let request = make_frame(&payload);
    let expected_digest = digest(&payload);

    let (mut send, mut receive) = timeout(OPERATION_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| other_error("打开数据流超时"))??;
    timeout(OPERATION_TIMEOUT, send.write_all(&request))
        .await
        .map_err(|_| other_error("发送测试数据超时"))??;
    send.finish()?;

    let response = timeout(OPERATION_TIMEOUT, receive.read_to_end(64))
        .await
        .map_err(|_| other_error("等待服务端校验结果超时"))??;
    verify_success_response(&response, size, expected_digest)
}

async fn send_malformed_frame(connection: &Connection) -> LabResult<bool> {
    let (mut send, mut receive) = timeout(OPERATION_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| other_error("打开错误输入测试流超时"))??;
    send.write_all(b"this is not a FlowWeave frame").await?;
    send.finish()?;

    let response = timeout(OPERATION_TIMEOUT, receive.read_to_end(256))
        .await
        .map_err(|_| other_error("等待错误输入响应超时"))??;
    Ok(response.starts_with(b"ER:"))
}

async fn datagram_echo_test(connection: &Connection, count: usize) -> LabResult<Vec<Duration>> {
    let mut latencies = Vec::with_capacity(count);

    for sequence in 0..count {
        let payload = format!("FW-DATAGRAM-{sequence:04}").into_bytes();
        let started = Instant::now();
        timeout(
            OPERATION_TIMEOUT,
            connection.send_datagram_wait(payload.clone().into()),
        )
        .await
        .map_err(|_| other_error("发送 Datagram 超时"))??;

        let echoed = timeout(OPERATION_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| other_error("等待 Datagram 回显超时"))??;
        if echoed.as_ref() != payload {
            return Err(other_error("Datagram 回显内容与发送内容不一致"));
        }
        latencies.push(started.elapsed());
    }

    Ok(latencies)
}

async fn datagram_echo_probe(
    connection: &Connection,
    count: usize,
) -> LabResult<DatagramMeasurement> {
    if count == 0 {
        return Ok(DatagramMeasurement {
            sent: 0,
            echoed: 0,
            p50: None,
            p95: None,
            p99: None,
        });
    }

    let read_connection = connection.clone();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        loop {
            let data = match read_connection.read_datagram().await {
                Ok(data) => data,
                Err(error) => {
                    let _ = event_sender
                        .send(Err(other_error(format!("读取 Datagram 探针失败：{error}"))));
                    break;
                }
            };

            let event = parse_datagram_probe(&data).map(|sequence| (sequence, Instant::now()));
            if event_sender.send(event).is_err() {
                break;
            }
        }
    });

    let probe_result: LabResult<DatagramMeasurement> = async {
        let mut sent_at = Vec::with_capacity(count);
        for sequence in 0..count {
            let mut payload = Vec::with_capacity(DATAGRAM_PROBE_SIZE);
            payload.extend_from_slice(DATAGRAM_MAGIC);
            payload.extend_from_slice(&(sequence as u32).to_be_bytes());

            sent_at.push(Instant::now());
            timeout(
                OPERATION_TIMEOUT,
                connection.send_datagram_wait(payload.into()),
            )
            .await
            .map_err(|_| other_error("发送 Datagram 探针超时"))??;
            sleep(DATAGRAM_SEND_INTERVAL).await;
        }

        let deadline = Instant::now() + DATAGRAM_RECEIVE_GRACE;
        let mut received = vec![false; count];
        let mut latencies = Vec::with_capacity(count);

        while latencies.len() < count {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event?,
                Ok(None) => return Err(other_error("Datagram 探针读取任务提前退出")),
                Err(_) => break,
            };
            let (sequence, received_at) = event;
            if sequence >= count {
                return Err(other_error("收到超出范围的 Datagram 探针编号"));
            }
            if !received[sequence] {
                received[sequence] = true;
                latencies.push(received_at.saturating_duration_since(sent_at[sequence]));
            }
        }

        Ok(DatagramMeasurement {
            sent: count,
            echoed: latencies.len(),
            p50: percentile(&latencies, 50),
            p95: percentile(&latencies, 95),
            p99: percentile(&latencies, 99),
        })
    }
    .await;

    reader.abort();
    let _ = reader.await;
    probe_result
}

fn parse_datagram_probe(data: &[u8]) -> LabResult<usize> {
    if data.len() != DATAGRAM_PROBE_SIZE || &data[..4] != DATAGRAM_MAGIC {
        return Err(other_error("Datagram 探针格式不正确"));
    }
    Ok(u32::from_be_bytes(
        data[4..8]
            .try_into()
            .expect("Datagram 探针编号固定为 4 字节"),
    ) as usize)
}

fn make_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn parse_frame(frame: &[u8]) -> Result<&[u8], &'static str> {
    if frame.len() < 8 {
        return Err("数据太短");
    }
    if &frame[..4] != MAGIC {
        return Err("标识不正确");
    }

    let declared =
        u32::from_be_bytes(frame[4..8].try_into().expect("长度字段固定为 4 字节")) as usize;
    if declared > MAX_PAYLOAD_SIZE {
        return Err("数据超过实验上限");
    }
    if frame.len() != declared + 8 {
        return Err("声明长度与实际长度不一致");
    }
    Ok(&frame[8..])
}

fn make_success_response(payload: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(18);
    response.extend_from_slice(b"OK");
    response.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    response.extend_from_slice(&digest(payload).to_be_bytes());
    response
}

fn make_error_response(reason: &str) -> Vec<u8> {
    format!("ER:{reason}").into_bytes()
}

fn verify_success_response(
    response: &[u8],
    expected_size: usize,
    expected_digest: u64,
) -> LabResult<()> {
    if response.len() != 18 || &response[..2] != b"OK" {
        return Err(other_error("服务端没有返回有效的成功响应"));
    }

    let received_size = u64::from_be_bytes(
        response[2..10]
            .try_into()
            .expect("成功响应中的长度字段固定为 8 字节"),
    ) as usize;
    let received_digest = u64::from_be_bytes(
        response[10..18]
            .try_into()
            .expect("成功响应中的摘要字段固定为 8 字节"),
    );

    if received_size != expected_size || received_digest != expected_digest {
        return Err(other_error("服务端收到的数据与客户端发送的数据不一致"));
    }
    Ok(())
}

fn make_payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|index| seed.wrapping_add((index as u8).wrapping_mul(31)))
        .collect()
}

fn digest(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        hash.wrapping_mul(0x100000001b3) ^ u64::from(*byte)
    })
}

fn percentile(samples: &[Duration], percentage: usize) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() * percentage).div_ceil(100)).saturating_sub(1);
    sorted.get(index).copied()
}

fn path_delta(before: PathStats, after: PathStats) -> PathMeasurement {
    PathMeasurement {
        udp_bytes_sent: after.udp_tx.bytes.saturating_sub(before.udp_tx.bytes),
        udp_datagrams_sent: after
            .udp_tx
            .datagrams
            .saturating_sub(before.udp_tx.datagrams),
        lost_packets: after.lost_packets.saturating_sub(before.lost_packets),
        lost_bytes: after.lost_bytes.saturating_sub(before.lost_bytes),
        final_rtt: after.rtt,
    }
}

fn throughput_mbps(bytes: usize, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        return 0.0;
    }
    (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0
}

pub fn verify_basic_report(report: &BasicLabReport) -> LabResult<()> {
    if !report.multipath_negotiated {
        return Err(other_error("MPQUIC 没有协商成功"));
    }
    if !report.primary_carried_data || !report.secondary_carried_data {
        return Err(other_error("两条路径没有分别承载实际数据"));
    }
    if !report.failover_transfer_ok {
        return Err(other_error("关闭主路径后无法继续传输"));
    }
    if report.datagram_echoes != 24 {
        return Err(other_error("Datagram 回显数量不正确"));
    }
    if !report.path_limit_rejected {
        return Err(other_error("超过路径数量上限时没有被正确拒绝"));
    }
    if !report.malformed_frame_rejected {
        return Err(other_error("格式错误的数据没有被明确拒绝"));
    }
    Ok(())
}

pub fn print_basic_report(report: &BasicLabReport) {
    println!("FlowWeave / 织流 第一阶段实验通过");
    println!("- MPQUIC 协商：{}", pass(report.multipath_negotiated));
    println!(
        "- 主路径承载数据：{}（发送 {} 字节）",
        pass(report.primary_carried_data),
        report.primary_bytes_sent
    );
    println!(
        "- 第二路径承载数据：{}（发送 {} 字节）",
        pass(report.secondary_carried_data),
        report.secondary_bytes_sent
    );
    println!(
        "- 主路径关闭后继续传输：{}",
        pass(report.failover_transfer_ok)
    );
    println!("- Datagram 回显：{} 个", report.datagram_echoes);
    println!("- Datagram 往返延迟 P95：{:?}", report.datagram_p95);
    println!("- 超过路径上限被拒绝：{}", pass(report.path_limit_rejected));
    println!(
        "- 错误格式数据被拒绝：{}",
        pass(report.malformed_frame_rejected)
    );
    println!("注意：本阶段尚未实现真正的带宽聚合算法和 FEC。");
}

fn pass(value: bool) -> &'static str {
    if value { "通过" } else { "失败" }
}

fn other_error(message: impl Into<String>) -> LabError {
    io::Error::other(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn true_mpquic_two_path_lab_passes() {
        let report = run_basic_lab().await.expect("MPQUIC 双路径实验应成功运行");
        verify_basic_report(&report).expect("实验报告中的全部基础条件都应通过");
    }

    #[test]
    fn malformed_application_frame_is_rejected() {
        assert_eq!(parse_frame(b"bad"), Err("数据太短"));

        let mut wrong_length = make_frame(b"hello");
        wrong_length[7] = 9;
        assert_eq!(parse_frame(&wrong_length), Err("声明长度与实际长度不一致"));
    }

    #[test]
    fn unsafe_network_benchmark_sizes_are_rejected() {
        let empty = NetworkBenchmarkConfig::new(PathMode::LineOneOnly, 0, 1);
        assert!(empty.validate().is_err());

        let oversized = NetworkBenchmarkConfig::new(PathMode::LineOneOnly, MAX_PAYLOAD_SIZE + 1, 1);
        assert!(oversized.validate().is_err());

        let too_many_probes =
            NetworkBenchmarkConfig::new(PathMode::LineOneOnly, 1024, MAX_DATAGRAM_PROBES + 1);
        assert!(too_many_probes.validate().is_err());
    }
}

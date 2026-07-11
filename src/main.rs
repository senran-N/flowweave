use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use noq::{
    ClientConfig, Connection, ConnectionError, Endpoint, FourTuple, PathError, PathId, PathStatus,
    ServerConfig, TransportConfig,
    rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::time::{sleep, timeout};

type LabError = Box<dyn Error + Send + Sync + 'static>;
type LabResult<T> = Result<T, LabError>;

const MAGIC: &[u8; 4] = b"FWL1";
const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;
const MAX_FRAME_SIZE: usize = MAX_PAYLOAD_SIZE + 8;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct LabReport {
    multipath_negotiated: bool,
    primary_carried_data: bool,
    primary_bytes_sent: u64,
    secondary_carried_data: bool,
    secondary_bytes_sent: u64,
    failover_transfer_ok: bool,
    datagram_echoes: usize,
    datagram_p95: Duration,
    path_limit_rejected: bool,
    malformed_frame_rejected: bool,
}

#[tokio::main]
async fn main() -> LabResult<()> {
    let report = run_lab(true).await?;
    verify_report(&report)?;
    Ok(())
}

async fn run_lab(verbose: bool) -> LabResult<LabReport> {
    let (server_config, client_config) = make_configs()?;
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let server_port = server_endpoint.local_addr()?.port();

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

    let client_endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);

    let primary_server = loopback_addr(1, server_port);
    let client_secondary_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

    let connection = timeout(
        OPERATION_TIMEOUT,
        client_endpoint
            .connect(primary_server, "localhost")
            .map_err(|error| other_error(format!("客户端无法开始连接：{error}")))?,
    )
    .await
    .map_err(|_| other_error("客户端握手超时"))??;

    let multipath_negotiated = connection.is_multipath_enabled();
    if !multipath_negotiated {
        return Err(other_error("客户端和服务端没有协商成功 MPQUIC"));
    }

    let primary = connection
        .path(PathId::ZERO)
        .ok_or_else(|| other_error("连接成功后找不到主路径"))?;

    let primary_before = primary.stats().udp_tx.bytes;
    transfer_and_verify(&connection, 256 * 1024, 11).await?;
    let primary_bytes_sent = primary.stats().udp_tx.bytes.saturating_sub(primary_before);
    let primary_carried_data = primary_bytes_sent >= 256 * 1024;

    let secondary = timeout(
        OPERATION_TIMEOUT,
        connection.open_path(
            FourTuple::new(primary_server, Some(client_secondary_ip)),
            PathStatus::Available,
        ),
    )
    .await
    .map_err(|_| other_error("建立第二条 MPQUIC 路径超时"))??;

    let path_limit_rejected = matches!(
        timeout(
            OPERATION_TIMEOUT,
            connection.open_path(
                FourTuple::new(
                    primary_server,
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
    transfer_and_verify(&connection, 512 * 1024, 29).await?;
    let secondary_bytes_sent = secondary
        .stats()
        .udp_tx
        .bytes
        .saturating_sub(secondary_before);
    let secondary_carried_data = secondary_bytes_sent >= 512 * 1024;

    let malformed_frame_rejected = send_malformed_frame(&connection).await?;

    primary.close()?;
    sleep(Duration::from_millis(100)).await;
    transfer_and_verify(&connection, 256 * 1024, 47).await?;
    let failover_transfer_ok = true;

    let datagram_latencies = datagram_echo_test(&connection, 24).await?;
    let datagram_p95 = percentile_95(&datagram_latencies);

    let report = LabReport {
        multipath_negotiated,
        primary_carried_data,
        primary_bytes_sent,
        secondary_carried_data,
        secondary_bytes_sent,
        failover_transfer_ok,
        datagram_echoes: datagram_latencies.len(),
        datagram_p95,
        path_limit_rejected,
        malformed_frame_rejected,
    };

    connection.close(0_u8.into(), b"lab complete");
    client_endpoint.wait_all_draining().await;

    match timeout(OPERATION_TIMEOUT, server_task).await {
        Ok(joined) => {
            joined.map_err(|error| other_error(format!("服务端任务异常退出：{error}")))??
        }
        Err(_) => return Err(other_error("服务端没有在连接关闭后及时退出")),
    }

    if verbose {
        print_report(&report);
    }

    Ok(report)
}

fn make_configs() -> LabResult<(ServerConfig, ClientConfig)> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = CertificateDer::from(generated.cert);
    let private_key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())?;
    let server_transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| other_error("无法配置服务端传输参数"))?;
    configure_transport(server_transport);

    let mut roots = noq::rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;
    let mut client_transport = TransportConfig::default();
    configure_transport(&mut client_transport);
    client_config.transport_config(Arc::new(client_transport));

    Ok((server_config, client_config))
}

fn configure_transport(transport: &mut TransportConfig) {
    transport
        .max_concurrent_multipath_paths(2)
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

fn percentile_95(samples: &[Duration]) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() * 95).div_ceil(100)).saturating_sub(1);
    sorted[index]
}

fn loopback_addr(last_octet: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last_octet)), port)
}

fn verify_report(report: &LabReport) -> LabResult<()> {
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

fn print_report(report: &LabReport) {
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
        let report = run_lab(false).await.expect("MPQUIC 双路径实验应成功运行");
        verify_report(&report).expect("实验报告中的全部基础条件都应通过");
    }

    #[test]
    fn malformed_application_frame_is_rejected() {
        assert_eq!(parse_frame(b"bad"), Err("数据太短"));

        let mut wrong_length = make_frame(b"hello");
        wrong_length[7] = 9;
        assert_eq!(parse_frame(&wrong_length), Err("声明长度与实际长度不一致"));
    }
}

#![cfg(target_os = "linux")]

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};

use flowweave_lab::{
    VpnProductEndpointLimits, VpnServerProductEndpointStopReason, VpnTunAttachError,
    attach_existing_vpn_tun, connect_vpn_client_product_endpoint,
    load_vpn_client_product_bootstrap, load_vpn_server_product_bootstrap,
    start_vpn_server_product_endpoint, vpn_certificate_fingerprint,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, tcp::OwnedReadHalf, tcp::OwnedWriteHalf},
    task::spawn_blocking,
    time::{sleep, timeout},
};

const SERVER_OUTER_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const CLIENT_OUTER_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const SERVER_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const CLIENT_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const SERVER_TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 1);
const CLIENT_TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 2);
const SERVER_QUIC_PORT: u16 = 4433;
const SERVER_CONTROL_PORT: u16 = 49000;
const SERVER_UPLINK_IPV4_PORT: u16 = 6100;
const SERVER_UPLINK_IPV6_PORT: u16 = 6101;
const SERVER_TCP_IPV4_PORT: u16 = 6200;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
fn root_process_is_rejected_before_tun_access() {
    assert_isolated_lab();
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1500).unwrap_err(),
        VpnTunAttachError::RunningAsRoot
    );
}

#[test]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
fn process_without_no_new_privileges_is_rejected() {
    assert_isolated_lab();
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1500).unwrap_err(),
        VpnTunAttachError::NoNewPrivilegesDisabled
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
async fn down_tun_is_rejected_before_attach() {
    assert_isolated_lab();
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1500).unwrap_err(),
        VpnTunAttachError::InterfaceDown
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
async fn existing_tun_is_attached_only_by_unprivileged_owner() {
    assert_isolated_lab();
    assert_ne!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1400).unwrap_err(),
        VpnTunAttachError::InterfaceMtuMismatch
    );
    let attached = attach_existing_vpn_tun("fwvpn0", 1500).unwrap();
    assert_eq!(attached.name(), "fwvpn0");
    assert!(attached.interface_index() > 0);
    assert_eq!(attached.mtu(), 1500);
    assert_ne!(attached.flags() as i32 & libc::IFF_TUN, 0);
    assert_ne!(attached.flags() as i32 & libc::IFF_NO_PI, 0);
    assert_eq!(attached.flags() as i32 & libc::IFF_VNET_HDR, 0);
    assert!(Path::new("/dev/net/tun").exists());
    drop(attached);

    assert_eq!(
        attach_existing_vpn_tun("fw-missing0", 1500).unwrap_err(),
        VpnTunAttachError::InterfaceNotFound
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性双 network namespace 中运行"]
async fn real_tun_and_endpoint_complete_two_generations() {
    assert_isolated_lab();
    let directory = endpoint_lab_directory();
    match std::env::var("FLOWWEAVE_TUN_ENDPOINT_ROLE").as_deref() {
        Ok("prepare") => prepare_endpoint_deployment(&directory),
        Ok("server") => run_endpoint_server(&directory).await,
        Ok("client") => run_endpoint_client(&directory).await,
        _ => panic!("missing or invalid FLOWWEAVE_TUN_ENDPOINT_ROLE"),
    }
}

async fn run_endpoint_server(directory: &Path) {
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let attached = attach_existing_vpn_tun("fwvpn0", 1500).unwrap();
    let bootstrap =
        Arc::new(load_vpn_server_product_bootstrap(&directory.join("vpn-server.json")).unwrap());
    let limits = endpoint_limits();
    let runtime =
        start_vpn_server_product_endpoint(bootstrap.clone(), attached.device(), limits).unwrap();
    assert_eq!(
        runtime.local_addr(),
        SocketAddr::new(IpAddr::V4(SERVER_OUTER_IPV4), SERVER_QUIC_PORT)
    );

    let uplink_ipv4 = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(SERVER_TUN_IPV4),
        SERVER_UPLINK_IPV4_PORT,
    ))
    .await
    .unwrap();
    let uplink_ipv6 = UdpSocket::bind(SocketAddr::new(
        IpAddr::V6(SERVER_TUN_IPV6),
        SERVER_UPLINK_IPV6_PORT,
    ))
    .await
    .unwrap();
    let tcp_ipv4 = TcpListener::bind(SocketAddr::new(
        IpAddr::V4(SERVER_TUN_IPV4),
        SERVER_TCP_IPV4_PORT,
    ))
    .await
    .unwrap();
    let control = TcpListener::bind(SocketAddr::new(
        IpAddr::V4(SERVER_OUTER_IPV4),
        SERVER_CONTROL_PORT,
    ))
    .await
    .unwrap();
    fs::write(directory.join("server.ready"), b"ready").unwrap();

    let (stream, peer) = timeout(IO_TIMEOUT, control.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.ip(), IpAddr::V4(CLIENT_OUTER_IPV4));
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    send_line(&mut write, "READY").await;

    recv_udp_payload(
        &uplink_ipv4,
        &payload(1400, 0x41),
        IpAddr::V4(CLIENT_TUN_IPV4),
    )
    .await;
    send_line(&mut write, "UP4_OK").await;

    let downlink_ipv4_port = parse_port(&read_line(&mut read).await, "DOWN4");
    let downlink_ipv4 = payload(1390, 0x52);
    assert_eq!(
        uplink_ipv4
            .send_to(
                &downlink_ipv4,
                SocketAddr::new(IpAddr::V4(CLIENT_TUN_IPV4), downlink_ipv4_port),
            )
            .await
            .unwrap(),
        downlink_ipv4.len()
    );
    send_line(&mut write, "DOWN4_SENT").await;

    recv_udp_payload(
        &uplink_ipv6,
        &payload(1380, 0x63),
        IpAddr::V6(CLIENT_TUN_IPV6),
    )
    .await;
    send_line(&mut write, "UP6_OK").await;

    let downlink_ipv6_port = parse_port(&read_line(&mut read).await, "DOWN6");
    let downlink_ipv6 = payload(1370, 0x74);
    assert_eq!(
        uplink_ipv6
            .send_to(
                &downlink_ipv6,
                SocketAddr::new(IpAddr::V6(CLIENT_TUN_IPV6), downlink_ipv6_port),
            )
            .await
            .unwrap(),
        downlink_ipv6.len()
    );
    send_line(&mut write, "DOWN6_SENT").await;

    recv_udp_payload(
        &uplink_ipv4,
        &payload(1472, 0x91),
        IpAddr::V4(CLIENT_TUN_IPV4),
    )
    .await;
    send_line(&mut write, "MTU4_UP_OK").await;
    let mtu_ipv4_port = parse_port(&read_line(&mut read).await, "MTU4_DOWN");
    let mtu_ipv4 = payload(1472, 0x92);
    assert_eq!(
        uplink_ipv4
            .send_to(
                &mtu_ipv4,
                SocketAddr::new(IpAddr::V4(CLIENT_TUN_IPV4), mtu_ipv4_port),
            )
            .await
            .unwrap(),
        mtu_ipv4.len()
    );
    send_line(&mut write, "MTU4_DOWN_SENT").await;

    recv_udp_payload(
        &uplink_ipv6,
        &payload(1452, 0x93),
        IpAddr::V6(CLIENT_TUN_IPV6),
    )
    .await;
    send_line(&mut write, "MTU6_UP_OK").await;
    let mtu_ipv6_port = parse_port(&read_line(&mut read).await, "MTU6_DOWN");
    let mtu_ipv6 = payload(1452, 0x94);
    assert_eq!(
        uplink_ipv6
            .send_to(
                &mtu_ipv6,
                SocketAddr::new(IpAddr::V6(CLIENT_TUN_IPV6), mtu_ipv6_port),
            )
            .await
            .unwrap(),
        mtu_ipv6.len()
    );
    send_line(&mut write, "MTU6_DOWN_SENT").await;

    let (mut tcp_stream, tcp_peer) = timeout(IO_TIMEOUT, tcp_ipv4.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tcp_peer.ip(), IpAddr::V4(CLIENT_TUN_IPV4));
    let mut tcp_payload = Vec::new();
    timeout(IO_TIMEOUT, tcp_stream.read_to_end(&mut tcp_payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tcp_payload, payload(256 * 1024, 0xa5));
    timeout(IO_TIMEOUT, async {
        tcp_stream.write_all(&tcp_payload).await?;
        tcp_stream.shutdown().await
    })
    .await
    .unwrap()
    .unwrap();
    send_line(&mut write, "TCP4_OK").await;

    assert_eq!(read_line(&mut read).await, "PING_OK");
    send_line(&mut write, "PING_ACK").await;

    assert_eq!(read_line(&mut read).await, "GEN1_DONE");
    wait_for_server_session_release(&bootstrap).await;
    send_line(&mut write, "GEN1_RELEASED").await;

    recv_udp_payload(
        &uplink_ipv4,
        &payload(1300, 0x85),
        IpAddr::V4(CLIENT_TUN_IPV4),
    )
    .await;
    send_line(&mut write, "GEN2_UP4_OK").await;
    assert_eq!(read_line(&mut read).await, "GEN2_DONE");
    wait_for_server_session_release(&bootstrap).await;
    send_line(&mut write, "GEN2_RELEASED").await;

    let report = runtime.shutdown().await.unwrap();
    assert_eq!(
        report.stop_reason,
        VpnServerProductEndpointStopReason::ShutdownRequested
    );
    assert_eq!(report.completed_sessions, 2);
    assert_eq!(report.session_rejections, 0);
    assert_eq!(report.runtime_start_failures, 0);
    assert_eq!(report.worker_failures, 0);
    assert_eq!(report.forced_session_shutdowns, 0);
    assert!(report.endpoint_drained);
    assert!(
        report
            .last_connection
            .is_some_and(|connection| connection.session_released)
    );
    drop(attached);
    drop(attach_existing_vpn_tun("fwvpn0", 1500).unwrap());
}

async fn run_endpoint_client(directory: &Path) {
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let attached = attach_existing_vpn_tun("fwvpn0", 1500).unwrap();
    let bootstrap = load_vpn_client_product_bootstrap(&directory.join("vpn-client.json")).unwrap();
    let limits = endpoint_limits();
    let control = timeout(
        IO_TIMEOUT,
        TcpStream::connect(SocketAddr::new(
            IpAddr::V4(SERVER_OUTER_IPV4),
            SERVER_CONTROL_PORT,
        )),
    )
    .await
    .unwrap()
    .unwrap();
    let (read, mut write) = control.into_split();
    let mut read = BufReader::new(read);
    assert_eq!(read_line(&mut read).await, "READY");

    let uplink_ipv4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(CLIENT_TUN_IPV4), 0))
        .await
        .unwrap();
    let downlink_ipv4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(CLIENT_TUN_IPV4), 0))
        .await
        .unwrap();
    let uplink_ipv6 = UdpSocket::bind(SocketAddr::new(IpAddr::V6(CLIENT_TUN_IPV6), 0))
        .await
        .unwrap();
    let downlink_ipv6 = UdpSocket::bind(SocketAddr::new(IpAddr::V6(CLIENT_TUN_IPV6), 0))
        .await
        .unwrap();

    let first = connect_vpn_client_product_endpoint(&bootstrap, attached.device(), limits)
        .await
        .unwrap();
    assert_eq!(first.established_path_count(), 1);
    let uplink_ipv4_payload = payload(1400, 0x41);
    assert_eq!(
        uplink_ipv4
            .send_to(
                &uplink_ipv4_payload,
                SocketAddr::new(IpAddr::V4(SERVER_TUN_IPV4), SERVER_UPLINK_IPV4_PORT),
            )
            .await
            .unwrap(),
        uplink_ipv4_payload.len()
    );
    assert_eq!(read_line(&mut read).await, "UP4_OK");

    let downlink_ipv4_port = downlink_ipv4.local_addr().unwrap().port();
    send_line(&mut write, &format!("DOWN4 {downlink_ipv4_port}")).await;
    assert_eq!(read_line(&mut read).await, "DOWN4_SENT");
    recv_udp_payload(
        &downlink_ipv4,
        &payload(1390, 0x52),
        IpAddr::V4(SERVER_TUN_IPV4),
    )
    .await;

    let uplink_ipv6_payload = payload(1380, 0x63);
    assert_eq!(
        uplink_ipv6
            .send_to(
                &uplink_ipv6_payload,
                SocketAddr::new(IpAddr::V6(SERVER_TUN_IPV6), SERVER_UPLINK_IPV6_PORT),
            )
            .await
            .unwrap(),
        uplink_ipv6_payload.len()
    );
    assert_eq!(read_line(&mut read).await, "UP6_OK");

    let downlink_ipv6_port = downlink_ipv6.local_addr().unwrap().port();
    send_line(&mut write, &format!("DOWN6 {downlink_ipv6_port}")).await;
    assert_eq!(read_line(&mut read).await, "DOWN6_SENT");
    recv_udp_payload(
        &downlink_ipv6,
        &payload(1370, 0x74),
        IpAddr::V6(SERVER_TUN_IPV6),
    )
    .await;

    let mtu_ipv4_payload = payload(1472, 0x91);
    assert_eq!(
        uplink_ipv4
            .send_to(
                &mtu_ipv4_payload,
                SocketAddr::new(IpAddr::V4(SERVER_TUN_IPV4), SERVER_UPLINK_IPV4_PORT),
            )
            .await
            .unwrap(),
        mtu_ipv4_payload.len()
    );
    assert_eq!(read_line(&mut read).await, "MTU4_UP_OK");
    send_line(
        &mut write,
        &format!("MTU4_DOWN {}", downlink_ipv4.local_addr().unwrap().port()),
    )
    .await;
    assert_eq!(read_line(&mut read).await, "MTU4_DOWN_SENT");
    recv_udp_payload(
        &downlink_ipv4,
        &payload(1472, 0x92),
        IpAddr::V4(SERVER_TUN_IPV4),
    )
    .await;

    let mtu_ipv6_payload = payload(1452, 0x93);
    assert_eq!(
        uplink_ipv6
            .send_to(
                &mtu_ipv6_payload,
                SocketAddr::new(IpAddr::V6(SERVER_TUN_IPV6), SERVER_UPLINK_IPV6_PORT),
            )
            .await
            .unwrap(),
        mtu_ipv6_payload.len()
    );
    assert_eq!(read_line(&mut read).await, "MTU6_UP_OK");
    send_line(
        &mut write,
        &format!("MTU6_DOWN {}", downlink_ipv6.local_addr().unwrap().port()),
    )
    .await;
    assert_eq!(read_line(&mut read).await, "MTU6_DOWN_SENT");
    recv_udp_payload(
        &downlink_ipv6,
        &payload(1452, 0x94),
        IpAddr::V6(SERVER_TUN_IPV6),
    )
    .await;

    enable_strict_pmtu(&uplink_ipv4, false);
    let ipv4_oversize = uplink_ipv4
        .send_to(
            &payload(1473, 0x95),
            SocketAddr::new(IpAddr::V4(SERVER_TUN_IPV4), SERVER_UPLINK_IPV4_PORT),
        )
        .await
        .unwrap_err();
    assert_eq!(ipv4_oversize.raw_os_error(), Some(libc::EMSGSIZE));
    enable_strict_pmtu(&uplink_ipv6, true);
    let ipv6_oversize = uplink_ipv6
        .send_to(
            &payload(1453, 0x96),
            SocketAddr::new(IpAddr::V6(SERVER_TUN_IPV6), SERVER_UPLINK_IPV6_PORT),
        )
        .await
        .unwrap_err();
    assert_eq!(ipv6_oversize.raw_os_error(), Some(libc::EMSGSIZE));

    let tcp_socket = TcpSocket::new_v4().unwrap();
    tcp_socket
        .bind(SocketAddr::new(IpAddr::V4(CLIENT_TUN_IPV4), 0))
        .unwrap();
    let mut tcp_stream = timeout(
        IO_TIMEOUT,
        tcp_socket.connect(SocketAddr::new(
            IpAddr::V4(SERVER_TUN_IPV4),
            SERVER_TCP_IPV4_PORT,
        )),
    )
    .await
    .unwrap()
    .unwrap();
    let tcp_payload = payload(256 * 1024, 0xa5);
    timeout(IO_TIMEOUT, async {
        tcp_stream.write_all(&tcp_payload).await?;
        tcp_stream.shutdown().await
    })
    .await
    .unwrap()
    .unwrap();
    let mut tcp_echo = Vec::new();
    timeout(IO_TIMEOUT, tcp_stream.read_to_end(&mut tcp_echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tcp_echo, tcp_payload);
    assert_eq!(read_line(&mut read).await, "TCP4_OK");

    run_unprivileged_ping(false).await;
    run_unprivileged_ping(true).await;
    send_line(&mut write, "PING_OK").await;
    assert_eq!(read_line(&mut read).await, "PING_ACK");

    let first_report = first.shutdown().await;
    assert!(first_report.endpoint_drained);
    send_line(&mut write, "GEN1_DONE").await;
    assert_eq!(read_line(&mut read).await, "GEN1_RELEASED");

    let second = connect_vpn_client_product_endpoint(&bootstrap, attached.device(), limits)
        .await
        .unwrap();
    let second_payload = payload(1300, 0x85);
    assert_eq!(
        uplink_ipv4
            .send_to(
                &second_payload,
                SocketAddr::new(IpAddr::V4(SERVER_TUN_IPV4), SERVER_UPLINK_IPV4_PORT),
            )
            .await
            .unwrap(),
        second_payload.len()
    );
    assert_eq!(read_line(&mut read).await, "GEN2_UP4_OK");
    let second_report = second.shutdown().await;
    assert!(second_report.endpoint_drained);
    send_line(&mut write, "GEN2_DONE").await;
    assert_eq!(read_line(&mut read).await, "GEN2_RELEASED");

    drop(attached);
    drop(attach_existing_vpn_tun("fwvpn0", 1500).unwrap());
}

fn prepare_endpoint_deployment(directory: &Path) {
    fs::create_dir_all(directory).unwrap();
    let server_ca = test_ca("server-ca");
    let client_ca = test_ca("client-ca");
    let (server_certificate, server_key) = test_leaf(
        "vpn.test",
        ExtendedKeyUsagePurpose::ServerAuth,
        &server_ca.1,
    );
    let (client_certificate, client_key) = test_leaf(
        "flowweave-client",
        ExtendedKeyUsagePurpose::ClientAuth,
        &client_ca.1,
    );
    write_private_file(&directory.join("server-ca.cert.der"), server_ca.0.der());
    write_private_file(&directory.join("client-ca.cert.der"), client_ca.0.der());
    write_private_file(&directory.join("server.cert.der"), &server_certificate);
    write_private_file(&directory.join("server.key.der"), &server_key);
    write_private_file(&directory.join("client.cert.der"), &client_certificate);
    write_private_file(&directory.join("client.key.der"), &client_key);

    write_private_json(
        &directory.join("vpn-identities.json"),
        &json!({
            "config_version": 1,
            "server_ipv4": SERVER_TUN_IPV4.to_string(),
            "server_ipv6": SERVER_TUN_IPV6.to_string(),
            "identities": [{
                "client_id": "client-a",
                "fingerprints": [vpn_certificate_fingerprint(&client_certificate).to_hex()],
                "enabled": true,
                "client_ipv4": CLIENT_TUN_IPV4.to_string(),
                "client_ipv6": CLIENT_TUN_IPV6.to_string(),
                "allowed_destinations": ["0.0.0.0/0", "::/0"],
                "limits": {
                    "max_connections": 1,
                    "max_packets_per_second": 100000,
                    "max_bytes_per_second": 134217728_u64,
                    "max_reassembly_bytes": 8388608
                }
            }]
        }),
    );
    write_private_json(
        &directory.join("vpn-server.json"),
        &json!({
            "config_version": 1,
            "listen": SocketAddr::new(IpAddr::V4(SERVER_OUTER_IPV4), SERVER_QUIC_PORT).to_string(),
            "certificate_der": "server.cert.der",
            "private_key_der": "server.key.der",
            "client_ca_der": "client-ca.cert.der",
            "identity_file": "vpn-identities.json",
            "tun_name": "fwvpn0",
            "tun_mtu": 1500,
            "max_datagram_len": 1200,
            "global_reassembly_bytes": 67108864,
            "global_inflight_packets": 8192
        }),
    );
    write_private_json(
        &directory.join("vpn-client.json"),
        &json!({
            "config_version": 1,
            "server": SocketAddr::new(IpAddr::V4(SERVER_OUTER_IPV4), SERVER_QUIC_PORT).to_string(),
            "server_name": "vpn.test",
            "server_ca_der": "server-ca.cert.der",
            "certificate_der": "client.cert.der",
            "private_key_der": "client.key.der",
            "tun_name": "fwvpn0",
            "tun_mtu": 1500,
            "max_datagram_len": 1200,
            "expected_client_ipv4": CLIENT_TUN_IPV4.to_string(),
            "expected_server_ipv4": SERVER_TUN_IPV4.to_string(),
            "expected_client_ipv6": CLIENT_TUN_IPV6.to_string(),
            "expected_server_ipv6": SERVER_TUN_IPV6.to_string(),
            "allowed_destinations": ["0.0.0.0/0", "::/0"],
            "limits": {
                "max_packets_per_second": 100000,
                "max_bytes_per_second": 134217728_u64,
                "max_reassembly_bytes": 8388608
            },
            "global_reassembly_bytes": 67108864,
            "global_inflight_packets": 8192,
            "primary_local_ip": CLIENT_OUTER_IPV4.to_string(),
            "additional_local_ips": []
        }),
    );
}

fn endpoint_limits() -> VpnProductEndpointLimits {
    VpnProductEndpointLimits::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(3),
        1,
    )
    .unwrap()
}

async fn recv_udp_payload(socket: &UdpSocket, expected: &[u8], expected_peer: IpAddr) {
    let mut buffer = vec![0_u8; 2048];
    let (received, peer) = timeout(IO_TIMEOUT, socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.ip(), expected_peer);
    assert_eq!(&buffer[..received], expected);
}

async fn send_line(write: &mut OwnedWriteHalf, value: &str) {
    timeout(IO_TIMEOUT, async {
        write.write_all(value.as_bytes()).await?;
        write.write_all(b"\n").await?;
        write.flush().await
    })
    .await
    .unwrap()
    .unwrap();
}

async fn read_line(read: &mut BufReader<OwnedReadHalf>) -> String {
    let mut line = String::new();
    let bytes = timeout(IO_TIMEOUT, read.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes > 0, "control stream closed before the next command");
    line.trim_end().to_owned()
}

fn parse_port(line: &str, command: &str) -> u16 {
    let (actual_command, port) = line
        .split_once(' ')
        .unwrap_or_else(|| panic!("invalid {command} control command"));
    assert_eq!(actual_command, command);
    port.parse::<u16>().unwrap()
}

async fn wait_for_server_session_release(bootstrap: &flowweave_lab::VpnServerProductBootstrap) {
    timeout(IO_TIMEOUT, async {
        loop {
            if bootstrap.coordinator().active_session("client-a").is_none() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

fn payload(length: usize, fill: u8) -> Vec<u8> {
    (0..length)
        .map(|index| fill.wrapping_add((index % 17) as u8))
        .collect()
}

fn enable_strict_pmtu(socket: &UdpSocket, ipv6: bool) {
    let value = libc::IP_PMTUDISC_DO;
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
    };
    // SAFETY: socket is live and value points to a correctly sized integer option.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "failed to enable strict PMTU discovery");
}

async fn run_unprivileged_ping(ipv6: bool) {
    let destination = if ipv6 {
        SERVER_TUN_IPV6.to_string()
    } else {
        SERVER_TUN_IPV4.to_string()
    };
    let output = timeout(
        IO_TIMEOUT,
        spawn_blocking(move || {
            Command::new("ping")
                .args([
                    if ipv6 { "-6" } else { "-4" },
                    "-n",
                    "-c",
                    "2",
                    "-W",
                    "2",
                    "-w",
                    "5",
                    &destination,
                ])
                .output()
        }),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "ping failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn endpoint_lab_directory() -> PathBuf {
    let directory = PathBuf::from(std::env::var_os("FLOWWEAVE_TUN_ENDPOINT_DIR").unwrap());
    assert!(
        directory
            .to_string_lossy()
            .starts_with("/tmp/flowweave-vpn-endpoint-lab.")
    );
    directory
}

fn write_private_json(path: &Path, value: &serde_json::Value) {
    write_private_file(path, &serde_json::to_vec(value).unwrap());
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn test_ca(name: &str) -> (Certificate, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    (certificate, Issuer::new(params, key))
}

fn test_leaf(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    issuer: &Issuer<'_, KeyPair>,
) -> (noq::rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, issuer).unwrap();
    (certificate.der().clone(), key.serialize_der())
}

fn assert_isolated_lab() {
    assert_eq!(std::env::var("FLOWWEAVE_TUN_LAB").as_deref(), Ok("1"));
    let host_netns = PathBuf::from(std::env::var_os("FLOWWEAVE_HOST_NETNS").unwrap());
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        host_netns,
        "TUN attach lab refuses to run in the host network namespace"
    );
}

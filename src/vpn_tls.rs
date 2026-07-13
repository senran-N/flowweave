use std::sync::Arc;

use noq::{
    ClientConfig, Connection, ServerConfig,
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer},
        server::WebPkiClientVerifier,
    },
};
use ring::digest::{SHA256, digest};

use crate::{LabResult, VPN_ALPN, VpnCertificateFingerprint, other_error};

pub fn build_vpn_server_tls_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
) -> LabResult<ServerConfig> {
    if client_roots.is_empty() {
        return Err(other_error("VPN 客户端 CA 集合不能为空"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider.clone())
            .build()?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificate_chain, private_key)?;
    tls.alpn_protocols = vec![VPN_ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let quic = QuicServerConfig::try_from(tls)
        .map_err(|_| other_error("VPN 服务端 TLS 配置缺少 QUIC 初始密码套件"))?;
    Ok(ServerConfig::with_crypto(Arc::new(quic)))
}

pub fn build_vpn_client_tls_config(
    server_roots: RootCertStore,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> LabResult<ClientConfig> {
    if server_roots.is_empty() {
        return Err(other_error("VPN 服务端 CA 集合不能为空"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(server_roots)
        .with_client_auth_cert(certificate_chain, private_key)?;
    tls.alpn_protocols = vec![VPN_ALPN.to_vec()];
    tls.enable_early_data = false;
    let quic = QuicClientConfig::try_from(tls)
        .map_err(|_| other_error("VPN 客户端 TLS 配置缺少 QUIC 初始密码套件"))?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

pub fn vpn_certificate_sha256(certificate: &CertificateDer<'_>) -> [u8; 32] {
    let value = digest(&SHA256, certificate.as_ref());
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(value.as_ref());
    fingerprint
}

pub fn vpn_certificate_fingerprint(certificate: &CertificateDer<'_>) -> VpnCertificateFingerprint {
    VpnCertificateFingerprint::from_sha256(vpn_certificate_sha256(certificate))
}

pub fn vpn_peer_certificate_sha256(connection: &Connection) -> LabResult<[u8; 32]> {
    let identity = connection
        .peer_identity()
        .ok_or_else(|| other_error("VPN TLS 会话没有对端证书身份"))?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| other_error("VPN TLS 对端身份类型不受支持"))?;
    let leaf = certificates
        .first()
        .ok_or_else(|| other_error("VPN TLS 对端证书链为空"))?;
    Ok(vpn_certificate_sha256(leaf))
}

pub fn vpn_peer_certificate_fingerprint(
    connection: &Connection,
) -> LabResult<VpnCertificateFingerprint> {
    Ok(VpnCertificateFingerprint::from_sha256(
        vpn_peer_certificate_sha256(connection)?,
    ))
}

pub fn verify_vpn_alpn(connection: &Connection) -> LabResult<()> {
    let handshake = connection
        .handshake_data()
        .ok_or_else(|| other_error("VPN TLS 握手数据尚未就绪"))?;
    let handshake = handshake
        .downcast::<HandshakeData>()
        .map_err(|_| other_error("VPN TLS 握手数据类型不受支持"))?;
    if handshake.protocol.as_deref() != Some(VPN_ALPN) {
        return Err(other_error("VPN TLS 没有协商预期 ALPN"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use noq::{Endpoint, TransportConfig, rustls::pki_types::PrivatePkcs8KeyDer};
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };
    use tokio::{sync::oneshot, time::timeout};

    use crate::{
        VPN_CAP_IPV4, VPN_CAP_IPV6, VPN_REQUIRED_CAPABILITIES, VPN_WIRE_VERSION_V1,
        VpnCertificateFingerprint, VpnHello, VpnIdentity, VpnIdentityLimits, VpnIdentityRegistry,
        VpnIpNetwork, VpnManagedServerOutcome, VpnReject, VpnRejectReason, VpnServerControlOutcome,
        VpnServerNegotiationConfig, VpnSessionCoordinator, VpnSessionError, VpnSessionGeneration,
        vpn_client_control_handshake, vpn_server_control_handshake,
        vpn_server_managed_control_handshake,
    };

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn real_quic_mtls_requires_client_identity_and_negotiates_vpn_alpn() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let pki = TestPki::new();
        let expected_client_fingerprint = vpn_certificate_sha256(&pki.client_certificate);
        let expected_server_fingerprint = vpn_certificate_sha256(&pki.server_certificate);

        let mut server_config = build_vpn_server_tls_config(
            vec![pki.server_certificate.clone()],
            private_key(pki.server_key),
            roots(&pki.client_ca),
        )
        .unwrap();
        configure_vpn_transport(
            Arc::get_mut(&mut server_config.transport).expect("server transport is unique"),
        );
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            connection.handshake_confirmed().await.unwrap();
            assert!(connection.is_multipath_enabled());
            verify_vpn_alpn(&connection).unwrap();
            let fingerprint = vpn_peer_certificate_sha256(&connection).unwrap();
            let payload = timeout(Duration::from_secs(2), connection.read_datagram())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload.as_ref(), b"vpn-mtls-ready");
            connection.close(0_u8.into(), b"test complete");
            server_endpoint.close(0_u8.into(), b"test complete");
            fingerprint
        });

        let mut client_config = build_vpn_client_tls_config(
            roots(&pki.server_ca),
            vec![pki.client_certificate],
            private_key(pki.client_key),
        )
        .unwrap();
        let mut transport = TransportConfig::default();
        configure_vpn_transport(&mut transport);
        client_config.transport_config(Arc::new(transport));
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connection = client_endpoint
            .connect(server_addr, "vpn.test")
            .unwrap()
            .await
            .unwrap();
        connection.handshake_confirmed().await.unwrap();
        assert!(connection.is_multipath_enabled());
        verify_vpn_alpn(&connection).unwrap();
        assert_eq!(
            vpn_peer_certificate_sha256(&connection).unwrap(),
            expected_server_fingerprint
        );
        connection
            .send_datagram_wait(Vec::from(&b"vpn-mtls-ready"[..]).into())
            .await
            .unwrap();

        assert_eq!(server_task.await.unwrap(), expected_client_fingerprint);
        client_endpoint.close(0_u8.into(), b"test complete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn untrusted_client_certificate_cannot_complete_vpn_handshake() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let pki = TestPki::new();
        let other_client_ca = test_ca("other-client-ca");
        let (other_client_certificate, other_client_key) = test_leaf(
            "other-client",
            ExtendedKeyUsagePurpose::ClientAuth,
            &other_client_ca.1,
        );

        let mut server_config = build_vpn_server_tls_config(
            vec![pki.server_certificate.clone()],
            private_key(pki.server_key),
            roots(&pki.client_ca),
        )
        .unwrap();
        configure_vpn_transport(
            Arc::get_mut(&mut server_config.transport).expect("server transport is unique"),
        );
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            incoming.accept().unwrap().await
        });

        let mut client_config = build_vpn_client_tls_config(
            roots(&pki.server_ca),
            vec![other_client_certificate],
            private_key(other_client_key),
        )
        .unwrap();
        let mut transport = TransportConfig::default();
        configure_vpn_transport(&mut transport);
        client_config.transport_config(Arc::new(transport));
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connecting = client_endpoint.connect(server_addr, "vpn.test").unwrap();
        let client_result = timeout(Duration::from_secs(2), connecting).await.unwrap();
        let server_result = timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(client_result.is_err() || server_result.is_err());
        client_endpoint.close(0_u8.into(), b"test complete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn real_mtls_control_stream_authorizes_fingerprint_and_returns_bound_addresses() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let pki = TestPki::new();
        let fingerprint = vpn_certificate_fingerprint(&pki.client_certificate);
        let registry = test_registry(fingerprint, true);

        let mut server_config = build_vpn_server_tls_config(
            vec![pki.server_certificate.clone()],
            private_key(pki.server_key),
            roots(&pki.client_ca),
        )
        .unwrap();
        configure_vpn_transport(
            Arc::get_mut(&mut server_config.transport).expect("server transport is unique"),
        );
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            connection.handshake_confirmed().await.unwrap();
            let outcome = vpn_server_control_handshake(
                &connection,
                &registry,
                VpnServerNegotiationConfig::default(),
                VpnSessionGeneration::new(41).unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
            connection.closed().await;
            server_endpoint.close(0_u8.into(), b"test complete");
            outcome
        });

        let mut client_config = build_vpn_client_tls_config(
            roots(&pki.server_ca),
            vec![pki.client_certificate],
            private_key(pki.client_key),
        )
        .unwrap();
        let mut transport = TransportConfig::default();
        configure_vpn_transport(&mut transport);
        client_config.transport_config(Arc::new(transport));
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connection = client_endpoint
            .connect(server_addr, "vpn.test")
            .unwrap()
            .await
            .unwrap();
        connection.handshake_confirmed().await.unwrap();
        let accept =
            vpn_client_control_handshake(&connection, test_hello(), Duration::from_secs(2))
                .await
                .unwrap();
        assert_eq!(accept.session_generation, 41);
        assert_eq!(accept.client_ipv4, Some("10.77.0.2".parse().unwrap()));
        assert_eq!(accept.server_ipv4, Some("10.77.0.1".parse().unwrap()));
        assert_eq!(accept.client_ipv6, Some("fd77::2".parse().unwrap()));
        assert_eq!(accept.server_ipv6, Some("fd77::1".parse().unwrap()));
        connection.close(0_u8.into(), b"test complete");
        client_endpoint.close(0_u8.into(), b"test complete");

        let outcome = timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        let VpnServerControlOutcome::Accepted(session) = outcome else {
            panic!("registered certificate must be accepted");
        };
        assert_eq!(session.identity().client_id(), "client-a");
        assert_eq!(session.fingerprint(), fingerprint);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn ca_valid_but_unregistered_certificate_is_rejected_on_control_stream() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let pki = TestPki::new();
        let registry = test_registry(VpnCertificateFingerprint::from_sha256([0xA5; 32]), true);

        let mut server_config = build_vpn_server_tls_config(
            vec![pki.server_certificate.clone()],
            private_key(pki.server_key),
            roots(&pki.client_ca),
        )
        .unwrap();
        configure_vpn_transport(
            Arc::get_mut(&mut server_config.transport).expect("server transport is unique"),
        );
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            connection.handshake_confirmed().await.unwrap();
            let outcome = vpn_server_control_handshake(
                &connection,
                &registry,
                VpnServerNegotiationConfig::default(),
                VpnSessionGeneration::new(42).unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
            connection.closed().await;
            server_endpoint.close(0_u8.into(), b"test complete");
            outcome
        });

        let mut client_config = build_vpn_client_tls_config(
            roots(&pki.server_ca),
            vec![pki.client_certificate],
            private_key(pki.client_key),
        )
        .unwrap();
        let mut transport = TransportConfig::default();
        configure_vpn_transport(&mut transport);
        client_config.transport_config(Arc::new(transport));
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connection = client_endpoint
            .connect(server_addr, "vpn.test")
            .unwrap()
            .await
            .unwrap();
        connection.handshake_confirmed().await.unwrap();
        let expected_reject = VpnReject {
            reason: VpnRejectReason::Unauthorized,
            retry_after_secs: 0,
        };
        assert_eq!(
            vpn_client_control_handshake(&connection, test_hello(), Duration::from_secs(2))
                .await
                .unwrap_err(),
            VpnSessionError::Rejected(expected_reject)
        );
        connection.close(0_u8.into(), b"test complete");
        client_endpoint.close(0_u8.into(), b"test complete");

        assert_eq!(
            timeout(Duration::from_secs(2), server_task)
                .await
                .unwrap()
                .unwrap(),
            VpnServerControlOutcome::Rejected(expected_reject)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn managed_real_sessions_keep_old_on_reject_then_replace_only_after_accept() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let pki = TestPki::new();
        let fingerprint = vpn_certificate_fingerprint(&pki.client_certificate);
        let coordinator = VpnSessionCoordinator::new(test_registry(fingerprint, true));

        let mut server_config = build_vpn_server_tls_config(
            vec![pki.server_certificate.clone()],
            private_key(pki.server_key.clone()),
            roots(&pki.client_ca),
        )
        .unwrap();
        configure_vpn_transport(
            Arc::get_mut(&mut server_config.transport).expect("server transport is unique"),
        );
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_coordinator = coordinator.clone();
        let (release_server, wait_for_release) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            for index in 0..3 {
                let incoming = server_endpoint.accept().await.unwrap();
                let connection = incoming.accept().unwrap().await.unwrap();
                connection.handshake_confirmed().await.unwrap();
                let outcome = vpn_server_managed_control_handshake(
                    &connection,
                    &server_coordinator,
                    VpnServerNegotiationConfig::default(),
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
                match (index, outcome) {
                    (0, VpnManagedServerOutcome::Active(active)) => {
                        assert_eq!(active.commit_report().replaced_generation, None);
                    }
                    (1, VpnManagedServerOutcome::Rejected(reject)) => {
                        assert_eq!(reject.reason, VpnRejectReason::UnsupportedVersion);
                        connection.closed().await;
                    }
                    (2, VpnManagedServerOutcome::Active(active)) => {
                        assert_eq!(active.commit_report().replaced_generation, Some(1));
                    }
                    _ => panic!("managed server outcome did not follow the test sequence"),
                }
            }
            let _ = wait_for_release.await;
            server_coordinator.close_all();
            server_endpoint.close(0_u8.into(), b"test complete");
        });

        let (first_endpoint, first_connection) = connect_test_client(server_addr, &pki).await;
        let first_accept =
            vpn_client_control_handshake(&first_connection, test_hello(), Duration::from_secs(2))
                .await
                .unwrap();
        assert_eq!(first_accept.session_generation, 1);

        let (rejected_endpoint, rejected_connection) = connect_test_client(server_addr, &pki).await;
        let mut unsupported = test_hello();
        unsupported.min_wire_version = 2;
        unsupported.max_wire_version = 2;
        assert_eq!(
            vpn_client_control_handshake(&rejected_connection, unsupported, Duration::from_secs(2))
                .await
                .unwrap_err(),
            VpnSessionError::Rejected(VpnReject {
                reason: VpnRejectReason::UnsupportedVersion,
                retry_after_secs: 0,
            })
        );
        rejected_connection.close(0_u8.into(), b"test complete");
        rejected_endpoint.close(0_u8.into(), b"test complete");
        assert!(coordinator.is_current("client-a", first_accept.session_generation));
        assert!(
            timeout(Duration::from_millis(50), first_connection.closed())
                .await
                .is_err()
        );

        let (replacement_endpoint, replacement_connection) =
            connect_test_client(server_addr, &pki).await;
        let replacement_accept = vpn_client_control_handshake(
            &replacement_connection,
            test_hello(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(replacement_accept.session_generation, 3);
        timeout(Duration::from_secs(2), first_connection.closed())
            .await
            .unwrap();
        assert!(!coordinator.is_current("client-a", first_accept.session_generation));
        assert!(coordinator.is_current("client-a", replacement_accept.session_generation));
        let metrics = coordinator.metrics_snapshot();
        assert_eq!(metrics.active_sessions, 1);
        assert_eq!(metrics.total_committed, 2);
        assert_eq!(metrics.replacements, 1);
        assert_eq!(metrics.commit_rejections, 0);

        let _ = release_server.send(());
        replacement_connection.close(0_u8.into(), b"test complete");
        replacement_endpoint.close(0_u8.into(), b"test complete");
        first_endpoint.close(0_u8.into(), b"test complete");
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }

    fn configure_vpn_transport(transport: &mut TransportConfig) {
        transport.max_concurrent_multipath_paths(2);
        transport.max_concurrent_bidi_streams(1_u8.into());
        transport.max_concurrent_uni_streams(0_u8.into());
        transport.datagram_receive_buffer_size(Some(256 * 1024));
        transport.datagram_send_buffer_size(256 * 1024);
    }

    fn test_hello() -> VpnHello {
        VpnHello {
            min_wire_version: VPN_WIRE_VERSION_V1,
            max_wire_version: VPN_WIRE_VERSION_V1,
            capabilities: VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4 | VPN_CAP_IPV6,
            max_ip_packet_len: u16::MAX,
            max_datagram_len: 1200,
        }
    }

    fn test_registry(fingerprint: VpnCertificateFingerprint, enabled: bool) -> VpnIdentityRegistry {
        let identity = VpnIdentity::new(
            "client-a",
            vec![fingerprint],
            enabled,
            Some("10.77.0.2".parse().unwrap()),
            Some("fd77::2".parse().unwrap()),
            vec![
                VpnIpNetwork::v4("0.0.0.0".parse().unwrap(), 0).unwrap(),
                VpnIpNetwork::v6("::".parse().unwrap(), 0).unwrap(),
            ],
            VpnIdentityLimits::default(),
        )
        .unwrap();
        VpnIdentityRegistry::new(
            Some("10.77.0.1".parse().unwrap()),
            Some("fd77::1".parse().unwrap()),
            vec![identity],
        )
        .unwrap()
    }

    async fn connect_test_client(server_addr: SocketAddr, pki: &TestPki) -> (Endpoint, Connection) {
        let mut client_config = build_vpn_client_tls_config(
            roots(&pki.server_ca),
            vec![pki.client_certificate.clone()],
            private_key(pki.client_key.clone()),
        )
        .unwrap();
        let mut transport = TransportConfig::default();
        configure_vpn_transport(&mut transport);
        client_config.transport_config(Arc::new(transport));
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(server_addr, "vpn.test")
            .unwrap()
            .await
            .unwrap();
        connection.handshake_confirmed().await.unwrap();
        (endpoint, connection)
    }

    struct TestPki {
        server_ca: Certificate,
        client_ca: Certificate,
        server_certificate: CertificateDer<'static>,
        server_key: Vec<u8>,
        client_certificate: CertificateDer<'static>,
        client_key: Vec<u8>,
    }

    impl TestPki {
        fn new() -> Self {
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
            Self {
                server_ca: server_ca.0,
                client_ca: client_ca.0,
                server_certificate,
                server_key,
                client_certificate,
                client_key,
            }
        }
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
    ) -> (CertificateDer<'static>, Vec<u8>) {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, issuer).unwrap();
        (certificate.der().clone(), key.serialize_der())
    }

    fn roots(certificate: &Certificate) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.der().clone()).unwrap();
        roots
    }

    fn private_key(bytes: Vec<u8>) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(bytes).into()
    }
}

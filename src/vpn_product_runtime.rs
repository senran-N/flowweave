use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::Path,
    sync::Arc,
    time::Duration,
};

use noq::{
    ClientConfig, ServerConfig, TransportConfig,
    rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

use crate::{
    MultipathScheduler, PtoRecovery, QuicCongestion, VPN_CAP_IPV4, VPN_CAP_IPV6,
    VPN_REQUIRED_CAPABILITIES, VPN_WIRE_VERSION_V1, VpnClientDataPathConfig,
    VpnClientDataPathConfigError, VpnClientDataPathFactory, VpnClientProductConfig,
    VpnControlError, VpnDatagramRole, VpnDatagramRuntimeConfig, VpnDatagramRuntimeConfigError,
    VpnHello, VpnIdentityConfigError, VpnManagedSessionError, VpnPacketBridgeConfig,
    VpnPacketBridgeConfigError, VpnProductConfigError, VpnServerNegotiationConfig,
    VpnServerProductConfig, VpnSessionCoordinator, build_vpn_client_tls_config,
    build_vpn_server_tls_config, configure_transport, load_vpn_client_product_config,
    load_vpn_identity_registry, load_vpn_server_product_config,
};

pub const VPN_PRODUCT_CREDENTIAL_MAX_BYTES: usize = 1024 * 1024;

const VPN_PRODUCT_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductCredentialFile {
    ServerCertificate,
    ServerPrivateKey,
    ClientCa,
    ServerCa,
    ClientCertificate,
    ClientPrivateKey,
}

impl VpnProductCredentialFile {
    const fn label(self) -> &'static str {
        match self {
            Self::ServerCertificate => "server_certificate",
            Self::ServerPrivateKey => "server_private_key",
            Self::ClientCa => "client_ca",
            Self::ServerCa => "server_ca",
            Self::ClientCertificate => "client_certificate",
            Self::ClientPrivateKey => "client_private_key",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductCredentialError {
    Io {
        file: VpnProductCredentialFile,
        kind: io::ErrorKind,
    },
    NotRegularFile(VpnProductCredentialFile),
    UnsafePermissions(VpnProductCredentialFile),
    FileTooLarge(VpnProductCredentialFile),
    Empty(VpnProductCredentialFile),
    InvalidCertificate(VpnProductCredentialFile),
}

impl fmt::Display for VpnProductCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { file, kind } => {
                write!(
                    formatter,
                    "vpn_product_credential_io:{}:{kind:?}",
                    file.label()
                )
            }
            Self::NotRegularFile(file) => write!(
                formatter,
                "vpn_product_credential_not_regular:{}",
                file.label()
            ),
            Self::UnsafePermissions(file) => write!(
                formatter,
                "vpn_product_credential_unsafe_permissions:{}",
                file.label()
            ),
            Self::FileTooLarge(file) => write!(
                formatter,
                "vpn_product_credential_too_large:{}",
                file.label()
            ),
            Self::Empty(file) => {
                write!(formatter, "vpn_product_credential_empty:{}", file.label())
            }
            Self::InvalidCertificate(file) => write!(
                formatter,
                "vpn_product_credential_invalid_certificate:{}",
                file.label()
            ),
        }
    }
}

impl Error for VpnProductCredentialError {}

#[derive(Debug)]
pub enum VpnProductBootstrapError {
    ProductConfig(VpnProductConfigError),
    Credential(VpnProductCredentialError),
    Identity(VpnIdentityConfigError),
    IdentityLimitExceedsGlobalBudget,
    TlsConfiguration(crate::LabError),
    TransportConfiguration,
    Negotiation(VpnControlError),
    Coordinator(VpnManagedSessionError),
    ClientDataPath(VpnClientDataPathConfigError),
    Datagram(VpnDatagramRuntimeConfigError),
    PacketBridge(VpnPacketBridgeConfigError),
}

impl fmt::Display for VpnProductBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProductConfig(error) => write!(formatter, "vpn_product_bootstrap_config:{error}"),
            Self::Credential(error) => {
                write!(formatter, "vpn_product_bootstrap_credential:{error}")
            }
            Self::Identity(error) => {
                write!(formatter, "vpn_product_bootstrap_identity:{error}")
            }
            Self::IdentityLimitExceedsGlobalBudget => {
                formatter.write_str("vpn_product_bootstrap_identity_limit_exceeds_global_budget")
            }
            Self::Negotiation(error) => {
                write!(formatter, "vpn_product_bootstrap_negotiation:{error}")
            }
            Self::Coordinator(error) => {
                write!(formatter, "vpn_product_bootstrap_coordinator:{error}")
            }
            Self::ClientDataPath(error) => {
                write!(formatter, "vpn_product_bootstrap_client_data_path:{error}")
            }
            Self::Datagram(error) => {
                write!(formatter, "vpn_product_bootstrap_datagram:{error}")
            }
            Self::PacketBridge(error) => {
                write!(formatter, "vpn_product_bootstrap_packet_bridge:{error}")
            }
            Self::TlsConfiguration(error) => {
                write!(formatter, "vpn_product_bootstrap_tls:{error}")
            }
            Self::TransportConfiguration => formatter.write_str("vpn_product_bootstrap_transport"),
        }
    }
}

impl Error for VpnProductBootstrapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProductConfig(error) => Some(error),
            Self::Credential(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Negotiation(error) => Some(error),
            Self::Coordinator(error) => Some(error),
            Self::ClientDataPath(error) => Some(error),
            Self::Datagram(error) => Some(error),
            Self::PacketBridge(error) => Some(error),
            Self::TlsConfiguration(error) => Some(error.as_ref()),
            Self::IdentityLimitExceedsGlobalBudget | Self::TransportConfiguration => None,
        }
    }
}

pub struct VpnServerProductBootstrap {
    config: VpnServerProductConfig,
    tls_config: ServerConfig,
    coordinator: VpnSessionCoordinator,
    negotiation: VpnServerNegotiationConfig,
    datagram: VpnDatagramRuntimeConfig,
    packet_bridge: VpnPacketBridgeConfig,
}

impl VpnServerProductBootstrap {
    pub fn config(&self) -> &VpnServerProductConfig {
        &self.config
    }

    pub fn tls_config(&self) -> &ServerConfig {
        &self.tls_config
    }

    pub fn coordinator(&self) -> &VpnSessionCoordinator {
        &self.coordinator
    }

    pub const fn negotiation_config(&self) -> VpnServerNegotiationConfig {
        self.negotiation
    }

    pub const fn datagram_config(&self) -> VpnDatagramRuntimeConfig {
        self.datagram
    }

    pub const fn packet_bridge_config(&self) -> VpnPacketBridgeConfig {
        self.packet_bridge
    }
}

impl fmt::Debug for VpnServerProductBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnServerProductBootstrap")
            .field("config", &self.config)
            .field(
                "identity_count",
                &self.coordinator.registry_snapshot().identities().len(),
            )
            .field("negotiation", &self.negotiation)
            .field("datagram", &self.datagram)
            .field("packet_bridge", &self.packet_bridge)
            .finish_non_exhaustive()
    }
}

pub struct VpnClientProductBootstrap {
    config: VpnClientProductConfig,
    tls_config: ClientConfig,
    hello: VpnHello,
    data_path_factory: VpnClientDataPathFactory,
    datagram: VpnDatagramRuntimeConfig,
    packet_bridge: VpnPacketBridgeConfig,
}

impl VpnClientProductBootstrap {
    pub fn config(&self) -> &VpnClientProductConfig {
        &self.config
    }

    pub fn tls_config(&self) -> &ClientConfig {
        &self.tls_config
    }

    pub const fn hello(&self) -> VpnHello {
        self.hello
    }

    pub fn data_path_factory(&self) -> &VpnClientDataPathFactory {
        &self.data_path_factory
    }

    pub const fn datagram_config(&self) -> VpnDatagramRuntimeConfig {
        self.datagram
    }

    pub const fn packet_bridge_config(&self) -> VpnPacketBridgeConfig {
        self.packet_bridge
    }
}

impl fmt::Debug for VpnClientProductBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnClientProductBootstrap")
            .field("config", &self.config)
            .field("hello", &self.hello)
            .field("data_path_factory", &self.data_path_factory)
            .field("datagram", &self.datagram)
            .field("packet_bridge", &self.packet_bridge)
            .finish_non_exhaustive()
    }
}

pub fn load_vpn_server_product_bootstrap(
    path: &Path,
) -> Result<VpnServerProductBootstrap, VpnProductBootstrapError> {
    let config =
        load_vpn_server_product_config(path).map_err(VpnProductBootstrapError::ProductConfig)?;
    build_server_bootstrap(config)
}

pub fn load_vpn_client_product_bootstrap(
    path: &Path,
) -> Result<VpnClientProductBootstrap, VpnProductBootstrapError> {
    let config =
        load_vpn_client_product_config(path).map_err(VpnProductBootstrapError::ProductConfig)?;
    build_client_bootstrap(config)
}

fn build_server_bootstrap(
    config: VpnServerProductConfig,
) -> Result<VpnServerProductBootstrap, VpnProductBootstrapError> {
    let certificate = read_certificate(
        config.certificate_der(),
        VpnProductCredentialFile::ServerCertificate,
    )?;
    let private_key = read_private_key(
        config.private_key_der(),
        VpnProductCredentialFile::ServerPrivateKey,
    )?;
    let client_roots = read_ca_store(config.client_ca_der(), VpnProductCredentialFile::ClientCa)?;
    let mut tls_config = build_vpn_server_tls_config(vec![certificate], private_key, client_roots)
        .map_err(VpnProductBootstrapError::TlsConfiguration)?;
    let transport = Arc::get_mut(&mut tls_config.transport)
        .ok_or(VpnProductBootstrapError::TransportConfiguration)?;
    configure_product_transport(
        transport,
        u32::try_from(crate::VPN_PRODUCT_MAX_EXPLICIT_PATHS + 1)
            .map_err(|_| VpnProductBootstrapError::TransportConfiguration)?,
        1,
    );

    let registry = load_vpn_identity_registry(config.identity_file())
        .map_err(VpnProductBootstrapError::Identity)?;
    if registry
        .identities()
        .iter()
        .any(|identity| identity.limits().max_reassembly_bytes() > config.global_reassembly_bytes())
    {
        return Err(VpnProductBootstrapError::IdentityLimitExceedsGlobalBudget);
    }
    let coordinator = VpnSessionCoordinator::with_resource_limits(
        registry,
        1,
        config.global_reassembly_bytes(),
        config.global_inflight_packets(),
    )
    .map_err(VpnProductBootstrapError::Coordinator)?;
    let negotiation = VpnServerNegotiationConfig::new(
        VPN_WIRE_VERSION_V1,
        VPN_WIRE_VERSION_V1,
        config.tun_mtu(),
        config.max_datagram_len(),
    )
    .map_err(VpnProductBootstrapError::Negotiation)?;
    let datagram = VpnDatagramRuntimeConfig::new(
        VpnDatagramRole::Server,
        usize::from(config.max_datagram_len()),
    )
    .map_err(VpnProductBootstrapError::Datagram)?;
    let packet_bridge = VpnPacketBridgeConfig::new(usize::from(config.tun_mtu()))
        .map_err(VpnProductBootstrapError::PacketBridge)?;

    Ok(VpnServerProductBootstrap {
        config,
        tls_config,
        coordinator,
        negotiation,
        datagram,
        packet_bridge,
    })
}

fn build_client_bootstrap(
    config: VpnClientProductConfig,
) -> Result<VpnClientProductBootstrap, VpnProductBootstrapError> {
    let server_roots = read_ca_store(config.server_ca_der(), VpnProductCredentialFile::ServerCa)?;
    let certificate = read_certificate(
        config.certificate_der(),
        VpnProductCredentialFile::ClientCertificate,
    )?;
    let private_key = read_private_key(
        config.private_key_der(),
        VpnProductCredentialFile::ClientPrivateKey,
    )?;
    let mut tls_config = build_vpn_client_tls_config(server_roots, vec![certificate], private_key)
        .map_err(VpnProductBootstrapError::TlsConfiguration)?;
    let mut transport = TransportConfig::default();
    let transient_paths = client_transient_path_count(
        config.primary_local_ip().is_some(),
        config.additional_local_ips().len(),
    )?;
    configure_product_transport(&mut transport, transient_paths, 0);
    tls_config.transport_config(Arc::new(transport));

    let mut capabilities = VPN_REQUIRED_CAPABILITIES;
    if config.request_ipv4() {
        capabilities |= VPN_CAP_IPV4;
    }
    if config.request_ipv6() {
        capabilities |= VPN_CAP_IPV6;
    }
    let hello = VpnHello {
        min_wire_version: VPN_WIRE_VERSION_V1,
        max_wire_version: VPN_WIRE_VERSION_V1,
        capabilities,
        max_ip_packet_len: config.tun_mtu(),
        max_datagram_len: config.max_datagram_len(),
    };
    hello
        .validate()
        .map_err(VpnProductBootstrapError::Negotiation)?;

    let client_data_path =
        VpnClientDataPathConfig::new(config.allowed_destinations().to_vec(), config.limits())
            .with_global_reassembly_limits(
                config.global_reassembly_bytes(),
                config.global_inflight_packets(),
            )
            .map_err(VpnProductBootstrapError::ClientDataPath)?;
    let data_path_factory = VpnClientDataPathFactory::new(client_data_path)
        .map_err(VpnProductBootstrapError::ClientDataPath)?;
    let datagram = VpnDatagramRuntimeConfig::new(
        VpnDatagramRole::Client,
        usize::from(config.max_datagram_len()),
    )
    .map_err(VpnProductBootstrapError::Datagram)?;
    let packet_bridge = VpnPacketBridgeConfig::new(usize::from(config.tun_mtu()))
        .map_err(VpnProductBootstrapError::PacketBridge)?;

    Ok(VpnClientProductBootstrap {
        config,
        tls_config,
        hello,
        data_path_factory,
        datagram,
        packet_bridge,
    })
}

fn client_transient_path_count(
    has_primary: bool,
    additional_count: usize,
) -> Result<u32, VpnProductBootstrapError> {
    let replace_bootstrap_path = has_primary && additional_count != 0;
    let transient_paths = additional_count
        .checked_add(1)
        .and_then(|count| count.checked_add(usize::from(replace_bootstrap_path)))
        .ok_or(VpnProductBootstrapError::TransportConfiguration)?;
    u32::try_from(transient_paths).map_err(|_| VpnProductBootstrapError::TransportConfiguration)
}

fn configure_product_transport(
    transport: &mut TransportConfig,
    path_count: u32,
    incoming_bidi_streams: u32,
) {
    configure_transport(
        transport,
        Some(VPN_PRODUCT_PATH_IDLE_TIMEOUT),
        PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot,
        MultipathScheduler::NoqDefault,
        QuicCongestion::Cubic,
        false,
    );
    transport.max_concurrent_multipath_paths(path_count.max(1));
    transport.max_concurrent_bidi_streams(incoming_bidi_streams.into());
    transport.max_concurrent_uni_streams(0_u8.into());
}

fn read_certificate(
    path: &Path,
    file: VpnProductCredentialFile,
) -> Result<CertificateDer<'static>, VpnProductBootstrapError> {
    Ok(CertificateDer::from(read_credential(path, file, false)?))
}

fn read_private_key(
    path: &Path,
    file: VpnProductCredentialFile,
) -> Result<PrivateKeyDer<'static>, VpnProductBootstrapError> {
    let bytes = read_credential(path, file, true)?;
    Ok(PrivatePkcs8KeyDer::from(bytes).into())
}

fn read_ca_store(
    path: &Path,
    file: VpnProductCredentialFile,
) -> Result<RootCertStore, VpnProductBootstrapError> {
    let certificate = CertificateDer::from(read_credential(path, file, false)?);
    let mut roots = RootCertStore::empty();
    roots.add(certificate).map_err(|_| {
        VpnProductBootstrapError::Credential(VpnProductCredentialError::InvalidCertificate(file))
    })?;
    Ok(roots)
}

fn read_credential(
    path: &Path,
    credential: VpnProductCredentialFile,
    private: bool,
) -> Result<Vec<u8>, VpnProductBootstrapError> {
    let file = File::open(path).map_err(|error| credential_io(credential, error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| credential_io(credential, error.kind()))?;
    if !metadata.is_file() {
        return Err(VpnProductBootstrapError::Credential(
            VpnProductCredentialError::NotRegularFile(credential),
        ));
    }
    if private {
        enforce_private_permissions(&metadata, credential)?;
    }
    if metadata.len() > VPN_PRODUCT_CREDENTIAL_MAX_BYTES as u64 {
        return Err(VpnProductBootstrapError::Credential(
            VpnProductCredentialError::FileTooLarge(credential),
        ));
    }
    let mut limited = file.take((VPN_PRODUCT_CREDENTIAL_MAX_BYTES + 1) as u64);
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(VPN_PRODUCT_CREDENTIAL_MAX_BYTES)
            .min(VPN_PRODUCT_CREDENTIAL_MAX_BYTES),
    );
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| credential_io(credential, error.kind()))?;
    if bytes.len() > VPN_PRODUCT_CREDENTIAL_MAX_BYTES {
        return Err(VpnProductBootstrapError::Credential(
            VpnProductCredentialError::FileTooLarge(credential),
        ));
    }
    if bytes.is_empty() {
        return Err(VpnProductBootstrapError::Credential(
            VpnProductCredentialError::Empty(credential),
        ));
    }
    Ok(bytes)
}

fn credential_io(file: VpnProductCredentialFile, kind: io::ErrorKind) -> VpnProductBootstrapError {
    VpnProductBootstrapError::Credential(VpnProductCredentialError::Io { file, kind })
}

#[cfg(unix)]
fn enforce_private_permissions(
    metadata: &fs::Metadata,
    file: VpnProductCredentialFile,
) -> Result<(), VpnProductBootstrapError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(VpnProductBootstrapError::Credential(
            VpnProductCredentialError::UnsafePermissions(file),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_permissions(
    _metadata: &fs::Metadata,
    _file: VpnProductCredentialFile,
) -> Result<(), VpnProductBootstrapError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };
    use serde_json::json;

    use crate::{VPN_CAP_IPV4, VPN_CAP_IPV6, vpn_certificate_fingerprint};

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn strict_files_build_server_and_client_static_runtime_contracts() {
        let deployment = TestDeployment::new();
        let server = load_vpn_server_product_bootstrap(&deployment.server_config).unwrap();
        let client = load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();

        assert_eq!(server.config().tun_name(), "fwvpn0");
        assert_eq!(server.negotiation_config().max_ip_packet_len(), 1500);
        assert_eq!(server.datagram_config().role(), VpnDatagramRole::Server);
        assert_eq!(server.packet_bridge_config().max_packet_len(), 1500);
        assert_eq!(
            server.coordinator().registry_snapshot().identities().len(),
            1
        );

        assert_eq!(client.config().server_name(), "vpn.test");
        assert_eq!(client.hello().max_ip_packet_len, 1500);
        assert_ne!(client.hello().capabilities & VPN_CAP_IPV4, 0);
        assert_ne!(client.hello().capabilities & VPN_CAP_IPV6, 0);
        assert_eq!(client.datagram_config().role(), VpnDatagramRole::Client);
        assert_eq!(client.packet_bridge_config().max_packet_len(), 1500);
        assert_eq!(
            client
                .data_path_factory()
                .config()
                .allowed_destinations()
                .len(),
            2
        );

        let server_debug = format!("{server:?}");
        let client_debug = format!("{client:?}");
        assert!(!server_debug.contains(deployment.path.to_string_lossy().as_ref()));
        assert!(!client_debug.contains(deployment.path.to_string_lossy().as_ref()));
        assert!(!client_debug.contains("127.0.0.1:4433"));
    }

    #[cfg(unix)]
    #[test]
    fn private_keys_and_ca_certificates_fail_closed_before_network_start() {
        use std::os::unix::fs::PermissionsExt;

        let deployment = TestDeployment::new();
        fs::set_permissions(
            deployment.path.join("client.key.der"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            load_vpn_client_product_bootstrap(&deployment.client_config),
            Err(VpnProductBootstrapError::Credential(
                VpnProductCredentialError::UnsafePermissions(
                    VpnProductCredentialFile::ClientPrivateKey
                )
            ))
        ));

        fs::set_permissions(
            deployment.path.join("client.key.der"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            deployment.path.join("server-ca.cert.der"),
            b"not-a-certificate",
        )
        .unwrap();
        assert!(matches!(
            load_vpn_client_product_bootstrap(&deployment.client_config),
            Err(VpnProductBootstrapError::Credential(
                VpnProductCredentialError::InvalidCertificate(VpnProductCredentialFile::ServerCa)
            ))
        ));

        let mismatched = TestDeployment::new();
        fs::copy(
            mismatched.path.join("server.key.der"),
            mismatched.path.join("client.key.der"),
        )
        .unwrap();
        fs::set_permissions(
            mismatched.path.join("client.key.der"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            load_vpn_client_product_bootstrap(&mismatched.client_config),
            Err(VpnProductBootstrapError::TlsConfiguration(_))
        ));
    }

    #[test]
    fn client_path_limit_counts_bootstrap_and_temporary_replacement() {
        assert_eq!(client_transient_path_count(false, 0).unwrap(), 1);
        assert_eq!(client_transient_path_count(true, 0).unwrap(), 1);
        assert_eq!(client_transient_path_count(false, 2).unwrap(), 3);
        assert_eq!(client_transient_path_count(true, 2).unwrap(), 4);
    }

    #[test]
    fn server_global_budget_must_cover_each_identity_limit() {
        let deployment = TestDeployment::new();
        let mut server: serde_json::Value =
            serde_json::from_slice(&fs::read(&deployment.server_config).unwrap()).unwrap();
        server["global_reassembly_bytes"] = serde_json::Value::from(65535);
        write_json(&deployment.server_config, &server);
        assert!(matches!(
            load_vpn_server_product_bootstrap(&deployment.server_config),
            Err(VpnProductBootstrapError::IdentityLimitExceedsGlobalBudget)
        ));
    }

    struct TestDeployment {
        path: PathBuf,
        server_config: PathBuf,
        client_config: PathBuf,
    }

    impl TestDeployment {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "flowweave-vpn-product-bootstrap-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();

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
            write_file(&path.join("server-ca.cert.der"), server_ca.0.der(), 0o644);
            write_file(&path.join("client-ca.cert.der"), client_ca.0.der(), 0o644);
            write_file(&path.join("server.cert.der"), &server_certificate, 0o644);
            write_file(&path.join("server.key.der"), &server_key, 0o600);
            write_file(&path.join("client.cert.der"), &client_certificate, 0o644);
            write_file(&path.join("client.key.der"), &client_key, 0o600);

            let identity = json!({
                "config_version": 1,
                "server_ipv4": "10.77.0.1",
                "server_ipv6": "fd77::1",
                "identities": [{
                    "client_id": "client-a",
                    "fingerprints": [vpn_certificate_fingerprint(&client_certificate).to_hex()],
                    "enabled": true,
                    "client_ipv4": "10.77.0.2",
                    "client_ipv6": "fd77::2",
                    "allowed_destinations": ["0.0.0.0/0", "::/0"],
                    "limits": {
                        "max_connections": 1,
                        "max_packets_per_second": 100000,
                        "max_bytes_per_second": 134217728_u64,
                        "max_reassembly_bytes": 8388608
                    }
                }]
            });
            write_json(&path.join("vpn-identities.json"), &identity);

            let server = json!({
                "config_version": 1,
                "listen": "127.0.0.1:4433",
                "certificate_der": "server.cert.der",
                "private_key_der": "server.key.der",
                "client_ca_der": "client-ca.cert.der",
                "identity_file": "vpn-identities.json",
                "tun_name": "fwvpn0",
                "tun_mtu": 1500,
                "max_datagram_len": 1200,
                "global_reassembly_bytes": 67108864,
                "global_inflight_packets": 8192
            });
            let client = json!({
                "config_version": 1,
                "server": "127.0.0.1:4433",
                "server_name": "vpn.test",
                "server_ca_der": "server-ca.cert.der",
                "certificate_der": "client.cert.der",
                "private_key_der": "client.key.der",
                "tun_name": "fwvpn0",
                "tun_mtu": 1500,
                "max_datagram_len": 1200,
                "request_ipv4": true,
                "request_ipv6": true,
                "allowed_destinations": ["0.0.0.0/0", "::/0"],
                "limits": {
                    "max_packets_per_second": 100000,
                    "max_bytes_per_second": 134217728_u64,
                    "max_reassembly_bytes": 8388608
                },
                "global_reassembly_bytes": 67108864,
                "global_inflight_packets": 8192,
                "primary_local_ip": null,
                "additional_local_ips": []
            });
            let server_config = path.join("vpn-server.json");
            let client_config = path.join("vpn-client.json");
            write_json(&server_config, &server);
            write_json(&client_config, &client);

            Self {
                path,
                server_config,
                client_config,
            }
        }
    }

    impl Drop for TestDeployment {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
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

    fn write_json(path: &Path, value: &serde_json::Value) {
        write_file(path, &serde_json::to_vec(value).unwrap(), 0o600);
    }

    fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

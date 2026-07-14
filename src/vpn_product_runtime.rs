use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read},
    net::IpAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use noq::{
    ClientConfig, Connection, ServerConfig, TransportConfig,
    rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

use crate::vpn_packet_bridge::start_vpn_packet_bridge_with_completion_guard;
use crate::{
    MultipathScheduler, PtoRecovery, QuicCongestion, VPN_CAP_IPV4, VPN_CAP_IPV6,
    VPN_REQUIRED_CAPABILITIES, VPN_WIRE_VERSION_V1, VpnClientDataPathConfig,
    VpnClientDataPathConfigError, VpnClientDataPathError, VpnClientDataPathFactory,
    VpnClientProductConfig, VpnControlError, VpnCoordinatorReloadReport, VpnDatagramRole,
    VpnDatagramRuntimeConfig, VpnDatagramRuntimeConfigError, VpnDatagramRuntimeStartError,
    VpnHello, VpnIdentityConfigError, VpnIdentityRegistry, VpnManagedServerOutcome,
    VpnManagedSessionError, VpnPacketBridge, VpnPacketBridgeConfig, VpnPacketBridgeConfigError,
    VpnPacketBridgeMetricsSnapshot, VpnPacketBridgeReport, VpnPacketBridgeStartError,
    VpnPacketDevice, VpnProductConfigError, VpnReject, VpnServerNegotiationConfig,
    VpnServerProductConfig, VpnSessionCoordinator, VpnSessionError, build_vpn_client_tls_config,
    build_vpn_server_tls_config, configure_transport, load_vpn_client_product_config,
    load_vpn_identity_registry, load_vpn_server_product_config, start_vpn_datagram_runtime,
    vpn_client_control_handshake, vpn_server_managed_control_handshake,
};

pub const VPN_PRODUCT_CREDENTIAL_MAX_BYTES: usize = 1024 * 1024;
pub const VPN_PRODUCT_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

const VPN_PRODUCT_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
const PRODUCT_RUNTIME_START_FAILED_REASON: &[u8] = b"product_runtime_start_failed";
const PRODUCT_RUNTIME_STOPPED_REASON: &[u8] = b"product_runtime_stopped";

pub const VPN_CLOSE_PRODUCT_RUNTIME_START_FAILED: u32 = 0x107;
pub const VPN_CLOSE_PRODUCT_RUNTIME_STOPPED: u32 = 0x108;

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

#[derive(Debug)]
pub enum VpnServerIdentityReloadError {
    Identity(VpnIdentityConfigError),
    IdentityLimitExceedsGlobalBudget,
    NetworkTopologyChanged,
    ForwardingIdentitySetChanged,
}

impl fmt::Display for VpnServerIdentityReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => write!(formatter, "vpn_server_identity_reload:{error}"),
            other => formatter.write_str(match other {
                Self::IdentityLimitExceedsGlobalBudget => {
                    "vpn_server_identity_reload_global_budget"
                }
                Self::NetworkTopologyChanged => {
                    "vpn_server_identity_reload_network_change_requires_restart"
                }
                Self::ForwardingIdentitySetChanged => {
                    "vpn_server_identity_reload_forwarding_change_requires_restart"
                }
                Self::Identity(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnServerIdentityReloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::IdentityLimitExceedsGlobalBudget
            | Self::NetworkTopologyChanged
            | Self::ForwardingIdentitySetChanged => None,
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
    runtime_active: Arc<AtomicBool>,
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

    pub fn reload_identities(
        &self,
    ) -> Result<VpnCoordinatorReloadReport, VpnServerIdentityReloadError> {
        let candidate = load_vpn_identity_registry(self.config.identity_file())
            .map_err(VpnServerIdentityReloadError::Identity)?;
        validate_server_identity_budget(&self.config, &candidate)
            .map_err(|_| VpnServerIdentityReloadError::IdentityLimitExceedsGlobalBudget)?;
        let current = self.coordinator.registry_snapshot();
        if server_network_identity_contract(&current)
            != server_network_identity_contract(&candidate)
        {
            return Err(VpnServerIdentityReloadError::NetworkTopologyChanged);
        }
        if self.config.forwarding().is_some()
            && server_forwarding_identity_contract(&current)
                != server_forwarding_identity_contract(&candidate)
        {
            return Err(VpnServerIdentityReloadError::ForwardingIdentitySetChanged);
        }
        Ok(self.coordinator.replace_registry(candidate))
    }

    fn acquire_runtime(&self) -> Option<VpnProductRuntimeLease> {
        VpnProductRuntimeLease::acquire(self.runtime_active.clone())
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
    runtime_active: Arc<AtomicBool>,
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

    fn acquire_runtime(&self) -> Option<VpnProductRuntimeLease> {
        VpnProductRuntimeLease::acquire(self.runtime_active.clone())
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

#[derive(Debug)]
pub enum VpnProductConnectionStartError {
    RuntimeAlreadyActive,
    ServerSession(VpnManagedSessionError),
    ClientSession(VpnSessionError),
    AssignedAddressMismatch,
    ClientDataPath(VpnClientDataPathError),
    DatagramConfig(VpnDatagramRuntimeConfigError),
    DatagramRuntime(VpnDatagramRuntimeStartError),
    PacketBridgeConfig(VpnPacketBridgeConfigError),
    PacketBridgeRuntime(VpnPacketBridgeStartError),
}

impl fmt::Display for VpnProductConnectionStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerSession(error) => {
                write!(formatter, "vpn_product_connection_server_session:{error}")
            }
            Self::ClientSession(error) => {
                write!(formatter, "vpn_product_connection_client_session:{error}")
            }
            Self::ClientDataPath(error) => {
                write!(formatter, "vpn_product_connection_client_data_path:{error}")
            }
            Self::DatagramConfig(error) => {
                write!(formatter, "vpn_product_connection_datagram_config:{error}")
            }
            Self::DatagramRuntime(error) => {
                write!(formatter, "vpn_product_connection_datagram_runtime:{error}")
            }
            Self::PacketBridgeConfig(error) => {
                write!(
                    formatter,
                    "vpn_product_connection_packet_bridge_config:{error}"
                )
            }
            Self::PacketBridgeRuntime(error) => {
                write!(
                    formatter,
                    "vpn_product_connection_packet_bridge_runtime:{error}"
                )
            }
            Self::RuntimeAlreadyActive => {
                formatter.write_str("vpn_product_connection_runtime_already_active")
            }
            Self::AssignedAddressMismatch => {
                formatter.write_str("vpn_product_connection_assigned_address_mismatch")
            }
        }
    }
}

impl Error for VpnProductConnectionStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ServerSession(error) => Some(error),
            Self::ClientSession(error) => Some(error),
            Self::ClientDataPath(error) => Some(error),
            Self::DatagramConfig(error) => Some(error),
            Self::DatagramRuntime(error) => Some(error),
            Self::PacketBridgeConfig(error) => Some(error),
            Self::PacketBridgeRuntime(error) => Some(error),
            Self::RuntimeAlreadyActive | Self::AssignedAddressMismatch => None,
        }
    }
}

#[derive(Debug)]
pub enum VpnServerProductConnectionOutcome {
    Active(Box<VpnServerProductConnectionRuntime>),
    Rejected(VpnReject),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnServerProductConnectionReport {
    pub selected_wire_version: u16,
    pub capabilities: u32,
    pub session_generation: u64,
    pub session_released: bool,
    pub packet_bridge: VpnPacketBridgeReport,
}

pub struct VpnServerProductConnectionRuntime {
    connection: Connection,
    bridge: Option<VpnPacketBridge>,
    coordinator: VpnSessionCoordinator,
    client_id: String,
    selected_wire_version: u16,
    capabilities: u32,
    session_generation: u64,
    finished: bool,
    _lease: VpnProductRuntimeLease,
}

impl VpnServerProductConnectionRuntime {
    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }

    pub fn packet_bridge_metrics(&self) -> VpnPacketBridgeMetricsSnapshot {
        self.bridge
            .as_ref()
            .expect("active product runtime has a packet bridge")
            .metrics_snapshot()
    }

    pub async fn shutdown(mut self) -> VpnServerProductConnectionReport {
        let packet_bridge = self
            .bridge
            .take()
            .expect("active product runtime has a packet bridge")
            .shutdown()
            .await;
        self.report(packet_bridge)
    }

    pub async fn wait(mut self) -> VpnServerProductConnectionReport {
        let packet_bridge = self
            .bridge
            .take()
            .expect("active product runtime has a packet bridge")
            .wait()
            .await;
        self.report(packet_bridge)
    }

    fn report(&mut self, packet_bridge: VpnPacketBridgeReport) -> VpnServerProductConnectionReport {
        let session_released = self.finish();
        VpnServerProductConnectionReport {
            selected_wire_version: self.selected_wire_version,
            capabilities: self.capabilities,
            session_generation: self.session_generation,
            session_released,
            packet_bridge,
        }
    }

    fn finish(&mut self) -> bool {
        if self.finished {
            return false;
        }
        self.finished = true;
        let released = self
            .coordinator
            .release_if_current(&self.client_id, self.session_generation);
        self.connection.close(
            VPN_CLOSE_PRODUCT_RUNTIME_STOPPED.into(),
            PRODUCT_RUNTIME_STOPPED_REASON,
        );
        released
    }
}

impl fmt::Debug for VpnServerProductConnectionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnServerProductConnectionRuntime")
            .field("client_id", &"[redacted]")
            .field("selected_wire_version", &self.selected_wire_version)
            .field("capabilities", &self.capabilities)
            .field("session_generation", &self.session_generation)
            .field("metrics", &self.packet_bridge_metrics())
            .finish_non_exhaustive()
    }
}

impl Drop for VpnServerProductConnectionRuntime {
    fn drop(&mut self) {
        self.finish();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnClientProductConnectionReport {
    pub selected_wire_version: u16,
    pub capabilities: u32,
    pub session_generation: u64,
    pub packet_bridge: VpnPacketBridgeReport,
}

pub struct VpnClientProductConnectionRuntime {
    connection: Connection,
    bridge: Option<VpnPacketBridge>,
    accept: crate::VpnAccept,
    finished: bool,
    _lease: VpnProductRuntimeLease,
}

impl VpnClientProductConnectionRuntime {
    pub const fn accept(&self) -> crate::VpnAccept {
        self.accept
    }

    pub fn packet_bridge_metrics(&self) -> VpnPacketBridgeMetricsSnapshot {
        self.bridge
            .as_ref()
            .expect("active product runtime has a packet bridge")
            .metrics_snapshot()
    }

    pub fn request_shutdown(&self) {
        if let Some(bridge) = self.bridge.as_ref() {
            bridge.request_shutdown();
        }
        self.connection.close(
            VPN_CLOSE_PRODUCT_RUNTIME_STOPPED.into(),
            PRODUCT_RUNTIME_STOPPED_REASON,
        );
    }

    pub async fn shutdown(mut self) -> VpnClientProductConnectionReport {
        self.request_shutdown();
        self.join().await
    }

    pub async fn wait(mut self) -> VpnClientProductConnectionReport {
        self.join().await
    }

    pub async fn join(&mut self) -> VpnClientProductConnectionReport {
        let packet_bridge = self
            .bridge
            .as_mut()
            .expect("active product runtime has a packet bridge")
            .join()
            .await;
        self.bridge.take();
        self.report(packet_bridge)
    }

    fn report(&mut self, packet_bridge: VpnPacketBridgeReport) -> VpnClientProductConnectionReport {
        self.finish();
        VpnClientProductConnectionReport {
            selected_wire_version: self.accept.selected_wire_version,
            capabilities: self.accept.capabilities,
            session_generation: self.accept.session_generation,
            packet_bridge,
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.connection.close(
            VPN_CLOSE_PRODUCT_RUNTIME_STOPPED.into(),
            PRODUCT_RUNTIME_STOPPED_REASON,
        );
    }
}

impl fmt::Debug for VpnClientProductConnectionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnClientProductConnectionRuntime")
            .field("selected_wire_version", &self.accept.selected_wire_version)
            .field("capabilities", &self.accept.capabilities)
            .field("session_generation", &self.accept.session_generation)
            .field("assigned_addresses", &"[redacted]")
            .field("metrics", &self.packet_bridge_metrics())
            .finish_non_exhaustive()
    }
}

impl Drop for VpnClientProductConnectionRuntime {
    fn drop(&mut self) {
        self.finish();
    }
}

struct VpnProductRuntimeLease {
    state: Arc<VpnProductRuntimeLeaseState>,
}

struct VpnProductRuntimeLeaseState {
    active: Arc<AtomicBool>,
}

impl VpnProductRuntimeLease {
    fn acquire(active: Arc<AtomicBool>) -> Option<Self> {
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self {
                state: Arc::new(VpnProductRuntimeLeaseState { active }),
            })
    }
}

impl Clone for VpnProductRuntimeLease {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl Drop for VpnProductRuntimeLeaseState {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

pub async fn start_vpn_server_product_connection(
    bootstrap: &VpnServerProductBootstrap,
    connection: Connection,
    device: &VpnPacketDevice,
    handshake_timeout: Duration,
) -> Result<VpnServerProductConnectionOutcome, VpnProductConnectionStartError> {
    let Some(lease) = bootstrap.acquire_runtime() else {
        close_runtime_start_failed(&connection);
        return Err(VpnProductConnectionStartError::RuntimeAlreadyActive);
    };
    let outcome = vpn_server_managed_control_handshake(
        &connection,
        &bootstrap.coordinator,
        bootstrap.negotiation,
        handshake_timeout,
    )
    .await
    .map_err(|error| {
        close_runtime_start_failed(&connection);
        VpnProductConnectionStartError::ServerSession(error)
    })?;

    let active = match outcome {
        VpnManagedServerOutcome::Active(active) => active,
        VpnManagedServerOutcome::Rejected(reject) => {
            return Ok(VpnServerProductConnectionOutcome::Rejected(reject));
        }
    };
    let accept = active.session().accept();
    let client_id = active.session().identity().client_id().to_owned();
    let data_path = active.data_path().clone();
    let bridge = match start_product_packet_bridge(
        connection.clone(),
        data_path,
        VpnDatagramRole::Server,
        accept,
        device.clone(),
        lease.clone(),
    ) {
        Ok(bridge) => bridge,
        Err(error) => {
            bootstrap
                .coordinator
                .release_if_current(&client_id, accept.session_generation);
            close_runtime_start_failed(&connection);
            return Err(error);
        }
    };

    Ok(VpnServerProductConnectionOutcome::Active(Box::new(
        VpnServerProductConnectionRuntime {
            connection,
            bridge: Some(bridge),
            coordinator: bootstrap.coordinator.clone(),
            client_id,
            selected_wire_version: accept.selected_wire_version,
            capabilities: accept.capabilities,
            session_generation: accept.session_generation,
            finished: false,
            _lease: lease,
        },
    )))
}

pub async fn start_vpn_client_product_connection(
    bootstrap: &VpnClientProductBootstrap,
    connection: Connection,
    device: &VpnPacketDevice,
    handshake_timeout: Duration,
) -> Result<VpnClientProductConnectionRuntime, VpnProductConnectionStartError> {
    let Some(lease) = bootstrap.acquire_runtime() else {
        close_runtime_start_failed(&connection);
        return Err(VpnProductConnectionStartError::RuntimeAlreadyActive);
    };
    let accept = vpn_client_control_handshake(&connection, bootstrap.hello, handshake_timeout)
        .await
        .map_err(VpnProductConnectionStartError::ClientSession)?;
    if !client_accept_addresses_match(&bootstrap.config, accept) {
        close_runtime_start_failed(&connection);
        return Err(VpnProductConnectionStartError::AssignedAddressMismatch);
    }
    let data_path = bootstrap.data_path_factory.build(accept).map_err(|error| {
        close_runtime_start_failed(&connection);
        VpnProductConnectionStartError::ClientDataPath(error)
    })?;
    let bridge = start_product_packet_bridge(
        connection.clone(),
        data_path,
        VpnDatagramRole::Client,
        accept,
        device.clone(),
        lease.clone(),
    )
    .inspect_err(|_| close_runtime_start_failed(&connection))?;

    Ok(VpnClientProductConnectionRuntime {
        connection,
        bridge: Some(bridge),
        accept,
        finished: false,
        _lease: lease,
    })
}

fn start_product_packet_bridge(
    connection: Connection,
    data_path: crate::VpnDataPathHandle,
    role: VpnDatagramRole,
    accept: crate::VpnAccept,
    device: VpnPacketDevice,
    lease: VpnProductRuntimeLease,
) -> Result<VpnPacketBridge, VpnProductConnectionStartError> {
    let datagram_config = VpnDatagramRuntimeConfig::from_accept(role, accept)
        .map_err(VpnProductConnectionStartError::DatagramConfig)?;
    let runtime = start_vpn_datagram_runtime(connection, data_path, datagram_config)
        .map_err(VpnProductConnectionStartError::DatagramRuntime)?;
    let bridge_config = VpnPacketBridgeConfig::new(usize::from(accept.max_ip_packet_len))
        .map_err(VpnProductConnectionStartError::PacketBridgeConfig)?;
    start_vpn_packet_bridge_with_completion_guard(device, runtime, bridge_config, lease)
        .map_err(VpnProductConnectionStartError::PacketBridgeRuntime)
}

fn client_accept_addresses_match(
    config: &VpnClientProductConfig,
    accept: crate::VpnAccept,
) -> bool {
    accept.client_ipv4 == config.expected_client_ipv4()
        && accept.server_ipv4 == config.expected_server_ipv4()
        && accept.client_ipv6 == config.expected_client_ipv6()
        && accept.server_ipv6 == config.expected_server_ipv6()
}

fn close_runtime_start_failed(connection: &Connection) {
    connection.close(
        VPN_CLOSE_PRODUCT_RUNTIME_START_FAILED.into(),
        PRODUCT_RUNTIME_START_FAILED_REASON,
    );
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

fn validate_server_identity_budget(
    config: &VpnServerProductConfig,
    registry: &VpnIdentityRegistry,
) -> Result<(), VpnProductBootstrapError> {
    if registry
        .identities()
        .iter()
        .any(|identity| identity.limits().max_reassembly_bytes() > config.global_reassembly_bytes())
    {
        return Err(VpnProductBootstrapError::IdentityLimitExceedsGlobalBudget);
    }
    Ok(())
}

fn server_network_identity_contract(
    registry: &VpnIdentityRegistry,
) -> (
    Option<std::net::Ipv4Addr>,
    Option<std::net::Ipv6Addr>,
    Vec<IpAddr>,
) {
    let mut client_addresses = registry
        .identities()
        .iter()
        .flat_map(|identity| {
            identity
                .client_ipv4()
                .map(IpAddr::V4)
                .into_iter()
                .chain(identity.client_ipv6().map(IpAddr::V6))
        })
        .collect::<Vec<_>>();
    client_addresses.sort_unstable();
    (
        registry.server_ipv4(),
        registry.server_ipv6(),
        client_addresses,
    )
}

fn server_forwarding_identity_contract(registry: &VpnIdentityRegistry) -> Vec<IpAddr> {
    let mut client_addresses = registry
        .identities()
        .iter()
        .filter(|identity| identity.enabled())
        .flat_map(|identity| {
            identity
                .client_ipv4()
                .map(IpAddr::V4)
                .into_iter()
                .chain(identity.client_ipv6().map(IpAddr::V6))
        })
        .collect::<Vec<_>>();
    client_addresses.sort_unstable();
    client_addresses
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
    validate_server_identity_budget(&config, &registry)?;
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
        runtime_active: Arc::new(AtomicBool::new(false)),
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
        runtime_active: Arc::new(AtomicBool::new(false)),
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
    transport.max_idle_timeout(Some(
        VPN_PRODUCT_CONNECTION_IDLE_TIMEOUT
            .try_into()
            .expect("fixed VPN connection idle timeout fits QUIC transport parameters"),
    ));
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
pub(crate) mod tests {
    use std::{
        os::fd::OwnedFd,
        os::unix::net::UnixDatagram as StdUnixDatagram,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use noq::Endpoint;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };
    use serde_json::json;

    use tokio::{net::UnixDatagram, time::timeout};

    use crate::{
        VPN_CAP_IPV4, VPN_CAP_IPV6, VpnPacketBridgeStopReason, vpn_certificate_fingerprint,
    };

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
        assert_eq!(
            client.config().expected_client_ipv4(),
            Some("10.77.0.2".parse().unwrap())
        );
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

        let server_transport = format!("{:?}", server.tls_config().transport);
        let mut client_transport = TransportConfig::default();
        configure_product_transport(&mut client_transport, 1, 0);
        let client_transport = format!("{client_transport:?}");
        assert!(server_transport.contains("max_idle_timeout: Some(10000)"));
        assert!(client_transport.contains("max_idle_timeout: Some(10000)"));

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

    #[test]
    fn server_identity_reload_accepts_policy_and_fingerprint_changes_but_rejects_network_drift() {
        let deployment = TestDeployment::new();
        let bootstrap = load_vpn_server_product_bootstrap(&deployment.server_config).unwrap();
        let identity_path = deployment.path.join("vpn-identities.json");
        let mut identity: serde_json::Value =
            serde_json::from_slice(&fs::read(&identity_path).unwrap()).unwrap();
        identity["identities"][0]["fingerprints"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::from("22".repeat(32)));
        identity["identities"][0]["allowed_destinations"] =
            serde_json::json!(["10.0.0.0/8", "::/0"]);
        write_json(&identity_path, &identity);

        let report = bootstrap.reload_identities().unwrap();
        assert_eq!(report.identities.previous_fingerprint_count, 1);
        assert_eq!(report.identities.fingerprint_count, 2);
        assert_eq!(report.sessions, crate::VpnSessionReconcileReport::default());

        identity["identities"][0]["client_ipv4"] = serde_json::Value::from("10.77.0.3");
        write_json(&identity_path, &identity);
        assert!(matches!(
            bootstrap.reload_identities(),
            Err(VpnServerIdentityReloadError::NetworkTopologyChanged)
        ));
        let current = bootstrap.coordinator().registry_snapshot();
        assert_eq!(
            current.identities()[0].client_ipv4(),
            Some("10.77.0.2".parse().unwrap())
        );
        assert_eq!(current.fingerprint_count(), 2);
    }

    #[test]
    fn server_identity_reload_reuses_initial_global_budget_validation() {
        let deployment = TestDeployment::new();
        let identity_path = deployment.path.join("vpn-identities.json");
        let mut identity: serde_json::Value =
            serde_json::from_slice(&fs::read(&identity_path).unwrap()).unwrap();
        identity["identities"][0]["limits"]["max_reassembly_bytes"] =
            serde_json::Value::from(1_048_576);
        write_json(&identity_path, &identity);
        let mut server: serde_json::Value =
            serde_json::from_slice(&fs::read(&deployment.server_config).unwrap()).unwrap();
        server["global_reassembly_bytes"] = serde_json::Value::from(1_048_576);
        write_json(&deployment.server_config, &server);
        let bootstrap = load_vpn_server_product_bootstrap(&deployment.server_config).unwrap();

        identity["identities"][0]["limits"]["max_reassembly_bytes"] =
            serde_json::Value::from(8_388_608);
        write_json(&identity_path, &identity);
        assert!(matches!(
            bootstrap.reload_identities(),
            Err(VpnServerIdentityReloadError::IdentityLimitExceedsGlobalBudget)
        ));
        assert_eq!(
            bootstrap.coordinator().registry_snapshot().identities()[0]
                .limits()
                .max_reassembly_bytes(),
            1_048_576
        );
    }

    #[test]
    fn server_identity_reload_rejects_enabled_set_drift_when_forwarding_is_configured() {
        let deployment = TestDeployment::new();
        let mut server: serde_json::Value =
            serde_json::from_slice(&fs::read(&deployment.server_config).unwrap()).unwrap();
        server["forwarding"] = serde_json::json!({
            "manage_sysctls": false,
            "ipv4_masquerade": true,
            "ipv6_masquerade": false
        });
        write_json(&deployment.server_config, &server);
        let bootstrap = load_vpn_server_product_bootstrap(&deployment.server_config).unwrap();
        let identity_path = deployment.path.join("vpn-identities.json");
        let mut identity: serde_json::Value =
            serde_json::from_slice(&fs::read(&identity_path).unwrap()).unwrap();
        identity["identities"][0]["enabled"] = serde_json::Value::Bool(false);
        write_json(&identity_path, &identity);

        assert!(matches!(
            bootstrap.reload_identities(),
            Err(VpnServerIdentityReloadError::ForwardingIdentitySetChanged)
        ));
        assert!(bootstrap.coordinator().registry_snapshot().identities()[0].enabled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn product_connection_runtime_bridges_both_directions_and_releases_session() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let deployment = TestDeployment::new();
        let server =
            Arc::new(load_vpn_server_product_bootstrap(&deployment.server_config).unwrap());
        let client = load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();

        let server_endpoint =
            Endpoint::server(server.tls_config().clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client.tls_config().clone());

        let (server_device, server_tun) = packet_device_pair();
        let (client_device, client_tun) = packet_device_pair();
        let accept_endpoint = server_endpoint.clone();
        let server_context = server.clone();
        let server_task = tokio::spawn(async move {
            let incoming = accept_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            connection.handshake_confirmed().await.unwrap();
            start_vpn_server_product_connection(
                &server_context,
                connection,
                &server_device,
                Duration::from_secs(2),
            )
            .await
            .unwrap()
        });

        let connection = client_endpoint
            .connect(server_addr, client.config().server_name())
            .unwrap()
            .await
            .unwrap();
        connection.handshake_confirmed().await.unwrap();
        let client_runtime = start_vpn_client_product_connection(
            &client,
            connection,
            &client_device,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let VpnServerProductConnectionOutcome::Active(server_runtime) = server_task.await.unwrap()
        else {
            panic!("registered client must be accepted");
        };

        assert_eq!(
            client_runtime.accept().client_ipv4,
            client.config().expected_client_ipv4()
        );
        let uplink = ipv4_packet(1280, "10.77.0.2", "198.51.100.8", 0x41);
        client_tun.send(&uplink).await.unwrap();
        let mut buffer = vec![0_u8; 1600];
        let received = timeout(Duration::from_secs(2), server_tun.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], uplink.as_slice());

        let downlink = ipv6_packet(1500, "2001:db8::8", "fd77::2", 0x52);
        server_tun.send(&downlink).await.unwrap();
        let received = timeout(Duration::from_secs(2), client_tun.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], downlink.as_slice());

        let (client_report, server_report) =
            tokio::join!(client_runtime.shutdown(), server_runtime.shutdown());
        assert_eq!(
            client_report.packet_bridge.stop_reason,
            VpnPacketBridgeStopReason::ShutdownRequested
        );
        assert_eq!(
            server_report.packet_bridge.stop_reason,
            VpnPacketBridgeStopReason::ShutdownRequested
        );
        assert!(server_report.session_released);
        assert!(server.coordinator().active_session("client-a").is_none());
        assert_eq!(client_report.packet_bridge.metrics.device_read_packets, 1);
        assert_eq!(server_report.packet_bridge.metrics.device_read_packets, 1);

        client_endpoint.close(0_u8.into(), b"test complete");
        server_endpoint.close(0_u8.into(), b"test complete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn assigned_address_drift_is_rejected_before_client_data_path_starts() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let deployment = TestDeployment::new();
        let mut client_config: serde_json::Value =
            serde_json::from_slice(&fs::read(&deployment.client_config).unwrap()).unwrap();
        client_config["expected_client_ipv4"] = serde_json::Value::from("10.77.0.9");
        write_json(&deployment.client_config, &client_config);

        let server =
            Arc::new(load_vpn_server_product_bootstrap(&deployment.server_config).unwrap());
        let client = load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        let server_endpoint =
            Endpoint::server(server.tls_config().clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client.tls_config().clone());
        let (server_device, _server_tun) = packet_device_pair();
        let (client_device, _client_tun) = packet_device_pair();

        let accept_endpoint = server_endpoint.clone();
        let server_context = server.clone();
        let server_task = tokio::spawn(async move {
            let incoming = accept_endpoint.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            connection.handshake_confirmed().await.unwrap();
            start_vpn_server_product_connection(
                &server_context,
                connection,
                &server_device,
                Duration::from_secs(2),
            )
            .await
            .unwrap()
        });

        let connection = client_endpoint
            .connect(server_addr, client.config().server_name())
            .unwrap()
            .await
            .unwrap();
        connection.handshake_confirmed().await.unwrap();
        assert!(matches!(
            start_vpn_client_product_connection(
                &client,
                connection,
                &client_device,
                Duration::from_secs(2),
            )
            .await,
            Err(VpnProductConnectionStartError::AssignedAddressMismatch)
        ));

        let VpnServerProductConnectionOutcome::Active(server_runtime) = server_task.await.unwrap()
        else {
            panic!("registered client must complete server authorization");
        };
        let report = timeout(Duration::from_secs(2), server_runtime.wait())
            .await
            .unwrap();
        assert!(report.session_released);
        assert!(server.coordinator().active_session("client-a").is_none());

        client_endpoint.close(0_u8.into(), b"test complete");
        server_endpoint.close(0_u8.into(), b"test complete");
    }

    #[test]
    fn product_runtime_lease_prevents_two_tun_readers() {
        let deployment = TestDeployment::new();
        let client = load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        let first = client.acquire_runtime().unwrap();
        let worker_guard = first.clone();
        assert!(client.acquire_runtime().is_none());
        drop(first);
        assert!(client.acquire_runtime().is_none());
        drop(worker_guard);
        assert!(client.acquire_runtime().is_some());
    }

    pub(crate) struct TestDeployment {
        pub(crate) path: PathBuf,
        pub(crate) server_config: PathBuf,
        pub(crate) client_config: PathBuf,
    }

    impl TestDeployment {
        pub(crate) fn new() -> Self {
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
                "expected_client_ipv4": "10.77.0.2",
                "expected_server_ipv4": "10.77.0.1",
                "expected_client_ipv6": "fd77::2",
                "expected_server_ipv6": "fd77::1",
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

    pub(crate) fn write_json(path: &Path, value: &serde_json::Value) {
        write_file(path, &serde_json::to_vec(value).unwrap(), 0o600);
    }

    fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    pub(crate) fn packet_device_pair() -> (VpnPacketDevice, UnixDatagram) {
        let (device, peer) = StdUnixDatagram::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let device = VpnPacketDevice::from_file(File::from(OwnedFd::from(device))).unwrap();
        let peer = UnixDatagram::from_std(peer).unwrap();
        (device, peer)
    }

    pub(crate) fn ipv4_packet(len: usize, source: &str, destination: &str, fill: u8) -> Vec<u8> {
        let source = source.parse::<std::net::Ipv4Addr>().unwrap().octets();
        let destination = destination.parse::<std::net::Ipv4Addr>().unwrap().octets();
        let mut packet = vec![fill; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    pub(crate) fn ipv6_packet(len: usize, source: &str, destination: &str, fill: u8) -> Vec<u8> {
        let source = source.parse::<std::net::Ipv6Addr>().unwrap().octets();
        let destination = destination.parse::<std::net::Ipv6Addr>().unwrap().octets();
        let mut packet = vec![fill; len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet
    }
}

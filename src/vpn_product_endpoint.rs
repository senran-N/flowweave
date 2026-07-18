use std::{
    collections::HashSet,
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use noq::{
    ClosePathError, ConnectError, Connection, ConnectionError, Endpoint, FourTuple, Path,
    PathError, PathEvent, PathId, PathStatus, TransportErrorCode,
};
use tokio::{
    net::lookup_host,
    sync::watch,
    task::JoinHandle,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_stream::StreamExt;

use crate::vpn_packet_bridge::VpnClientPacketPump;
use crate::vpn_product_runtime::start_vpn_client_product_connection_with_packet_pump;
use crate::{
    VPN_MAX_CONTROL_HANDSHAKE_TIMEOUT, VpnClientProductBootstrap, VpnClientProductConnectionReport,
    VpnClientProductConnectionRuntime, VpnPacketDevice, VpnProductConnectionStartError,
    VpnServerProductBootstrap, VpnServerProductConnectionOutcome, VpnServerProductConnectionReport,
    VpnServerProductConnectionRuntime, start_vpn_client_product_connection,
    start_vpn_server_product_connection,
};

pub const VPN_CLOSE_PRODUCT_ENDPOINT_START_FAILED: u32 = 0x109;
pub const VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED: u32 = 0x10a;

pub const VPN_PRODUCT_ENDPOINT_DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
pub const VPN_PRODUCT_ENDPOINT_DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
pub const VPN_PRODUCT_ENDPOINT_DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
pub const VPN_PRODUCT_ENDPOINT_DEFAULT_CONNECT_ATTEMPTS: usize = 4;

const VPN_PRODUCT_ENDPOINT_MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const VPN_PRODUCT_ENDPOINT_MAX_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const VPN_PRODUCT_ENDPOINT_MAX_CONNECT_ATTEMPTS: usize = 16;
const PATH_CID_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const ENDPOINT_START_FAILED_REASON: &[u8] = b"product_endpoint_start_failed";
const ENDPOINT_STOPPED_REASON: &[u8] = b"product_endpoint_stopped";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductEndpointLimitsError {
    InvalidOperationTimeout,
    InvalidControlTimeout,
    InvalidDrainTimeout,
    InvalidConnectAttempts,
}

impl fmt::Display for VpnProductEndpointLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperationTimeout => "vpn_product_endpoint_invalid_operation_timeout",
            Self::InvalidControlTimeout => "vpn_product_endpoint_invalid_control_timeout",
            Self::InvalidDrainTimeout => "vpn_product_endpoint_invalid_drain_timeout",
            Self::InvalidConnectAttempts => "vpn_product_endpoint_invalid_connect_attempts",
        })
    }
}

impl Error for VpnProductEndpointLimitsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnProductEndpointLimits {
    operation_timeout: Duration,
    control_timeout: Duration,
    drain_timeout: Duration,
    max_connect_attempts: usize,
}

impl VpnProductEndpointLimits {
    pub fn new(
        operation_timeout: Duration,
        control_timeout: Duration,
        drain_timeout: Duration,
        max_connect_attempts: usize,
    ) -> Result<Self, VpnProductEndpointLimitsError> {
        if operation_timeout.is_zero()
            || operation_timeout > VPN_PRODUCT_ENDPOINT_MAX_OPERATION_TIMEOUT
        {
            return Err(VpnProductEndpointLimitsError::InvalidOperationTimeout);
        }
        if control_timeout.is_zero() || control_timeout > VPN_MAX_CONTROL_HANDSHAKE_TIMEOUT {
            return Err(VpnProductEndpointLimitsError::InvalidControlTimeout);
        }
        if drain_timeout.is_zero() || drain_timeout > VPN_PRODUCT_ENDPOINT_MAX_DRAIN_TIMEOUT {
            return Err(VpnProductEndpointLimitsError::InvalidDrainTimeout);
        }
        if max_connect_attempts == 0
            || max_connect_attempts > VPN_PRODUCT_ENDPOINT_MAX_CONNECT_ATTEMPTS
        {
            return Err(VpnProductEndpointLimitsError::InvalidConnectAttempts);
        }
        Ok(Self {
            operation_timeout,
            control_timeout,
            drain_timeout,
            max_connect_attempts,
        })
    }

    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }

    pub const fn control_timeout(self) -> Duration {
        self.control_timeout
    }

    pub const fn drain_timeout(self) -> Duration {
        self.drain_timeout
    }

    pub const fn max_connect_attempts(self) -> usize {
        self.max_connect_attempts
    }
}

impl Default for VpnProductEndpointLimits {
    fn default() -> Self {
        Self {
            operation_timeout: VPN_PRODUCT_ENDPOINT_DEFAULT_OPERATION_TIMEOUT,
            control_timeout: VPN_PRODUCT_ENDPOINT_DEFAULT_CONTROL_TIMEOUT,
            drain_timeout: VPN_PRODUCT_ENDPOINT_DEFAULT_DRAIN_TIMEOUT,
            max_connect_attempts: VPN_PRODUCT_ENDPOINT_DEFAULT_CONNECT_ATTEMPTS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductConnectStartError {
    EndpointStopping,
    CidsExhausted,
    InvalidServerName,
    InvalidRemoteAddress,
    MissingClientConfig,
    UnsupportedVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductPathOpenError {
    MultipathNotNegotiated,
    ServerSideNotAllowed,
    MaxPathIdReached,
    RemoteCidsExhausted,
    ValidationFailed,
    InvalidRemoteAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductConnectFailure {
    VersionMismatch,
    TransportUnavailable,
    TransportProtocol,
    CryptoValidation,
    PeerClosed,
    Reset,
    TimedOut,
    LocallyClosed,
    CidsExhausted,
}

impl fmt::Display for VpnProductConnectFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VersionMismatch => "version_mismatch",
            Self::TransportUnavailable => "transport_unavailable",
            Self::TransportProtocol => "transport_protocol",
            Self::CryptoValidation => "crypto_validation",
            Self::PeerClosed => "peer_closed",
            Self::Reset => "reset",
            Self::TimedOut => "timed_out",
            Self::LocallyClosed => "locally_closed",
            Self::CidsExhausted => "cids_exhausted",
        })
    }
}

#[derive(Debug)]
pub enum VpnProductEndpointError {
    Limits(VpnProductEndpointLimitsError),
    ServerBind(io::ErrorKind),
    ClientBind(io::ErrorKind),
    LocalAddress(io::ErrorKind),
    DnsLookup(io::ErrorKind),
    DnsTimeout,
    NoCompatibleServerAddress,
    ConnectStart(VpnProductConnectStartError),
    ConnectFailed(VpnProductConnectFailure),
    ConnectTimeout,
    HandshakeConfirmationFailed,
    HandshakeConfirmationTimeout,
    MultipathNotNegotiated,
    PathOpen(VpnProductPathOpenError),
    PathOpenTimeout,
    BootstrapPathMissing,
    BootstrapPathClose,
    ProductConnection(VpnProductConnectionStartError),
    WorkerFailed,
}

impl fmt::Display for VpnProductEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(formatter, "vpn_product_endpoint_limits:{error}"),
            Self::ServerBind(kind) => {
                write!(formatter, "vpn_product_endpoint_server_bind:{kind:?}")
            }
            Self::ClientBind(kind) => {
                write!(formatter, "vpn_product_endpoint_client_bind:{kind:?}")
            }
            Self::LocalAddress(kind) => {
                write!(formatter, "vpn_product_endpoint_local_address:{kind:?}")
            }
            Self::DnsLookup(kind) => write!(formatter, "vpn_product_endpoint_dns:{kind:?}"),
            Self::ConnectStart(error) => {
                write!(formatter, "vpn_product_endpoint_connect_start:{error:?}")
            }
            Self::PathOpen(error) => {
                write!(formatter, "vpn_product_endpoint_path_open:{error:?}")
            }
            Self::ConnectFailed(error) => {
                write!(formatter, "vpn_product_endpoint_connect_failed:{error}")
            }
            Self::ProductConnection(error) => {
                write!(formatter, "vpn_product_endpoint_connection:{error}")
            }
            other => formatter.write_str(match other {
                Self::DnsTimeout => "vpn_product_endpoint_dns_timeout",
                Self::NoCompatibleServerAddress => {
                    "vpn_product_endpoint_no_compatible_server_address"
                }
                Self::ConnectTimeout => "vpn_product_endpoint_connect_timeout",
                Self::HandshakeConfirmationFailed => {
                    "vpn_product_endpoint_handshake_confirmation_failed"
                }
                Self::HandshakeConfirmationTimeout => {
                    "vpn_product_endpoint_handshake_confirmation_timeout"
                }
                Self::MultipathNotNegotiated => "vpn_product_endpoint_multipath_not_negotiated",
                Self::PathOpenTimeout => "vpn_product_endpoint_path_open_timeout",
                Self::BootstrapPathMissing => "vpn_product_endpoint_bootstrap_path_missing",
                Self::BootstrapPathClose => "vpn_product_endpoint_bootstrap_path_close",
                Self::WorkerFailed => "vpn_product_endpoint_worker_failed",
                Self::Limits(_)
                | Self::ServerBind(_)
                | Self::ClientBind(_)
                | Self::LocalAddress(_)
                | Self::DnsLookup(_)
                | Self::ConnectStart(_)
                | Self::ConnectFailed(_)
                | Self::PathOpen(_)
                | Self::ProductConnection(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnProductEndpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Limits(error) => Some(error),
            Self::ProductConnection(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VpnProductEndpointLimitsError> for VpnProductEndpointError {
    fn from(error: VpnProductEndpointLimitsError) -> Self {
        Self::Limits(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnServerProductEndpointStopReason {
    ShutdownRequested,
    EndpointStopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnServerProductEndpointReport {
    pub stop_reason: VpnServerProductEndpointStopReason,
    pub incoming_connections: u64,
    pub transport_connections: u64,
    pub transport_failures: u64,
    pub transport_timeouts: u64,
    pub confirmation_failures: u64,
    pub confirmation_timeouts: u64,
    pub busy_refusals: u64,
    pub session_rejections: u64,
    pub runtime_start_failures: u64,
    pub completed_sessions: u64,
    pub worker_failures: u64,
    pub forced_session_shutdowns: u64,
    pub last_connection: Option<VpnServerProductConnectionReport>,
    pub endpoint_drained: bool,
}

impl VpnServerProductEndpointReport {
    fn new(stop_reason: VpnServerProductEndpointStopReason) -> Self {
        Self {
            stop_reason,
            incoming_connections: 0,
            transport_connections: 0,
            transport_failures: 0,
            transport_timeouts: 0,
            confirmation_failures: 0,
            confirmation_timeouts: 0,
            busy_refusals: 0,
            session_rejections: 0,
            runtime_start_failures: 0,
            completed_sessions: 0,
            worker_failures: 0,
            forced_session_shutdowns: 0,
            last_connection: None,
            endpoint_drained: false,
        }
    }
}

pub struct VpnServerProductEndpointRuntime {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<VpnServerProductEndpointReport>>,
}

impl VpnServerProductEndpointRuntime {
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn request_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    pub async fn shutdown(
        mut self,
    ) -> Result<VpnServerProductEndpointReport, VpnProductEndpointError> {
        self.request_shutdown();
        self.join().await
    }

    pub async fn wait(mut self) -> Result<VpnServerProductEndpointReport, VpnProductEndpointError> {
        self.join().await
    }

    pub async fn join(
        &mut self,
    ) -> Result<VpnServerProductEndpointReport, VpnProductEndpointError> {
        let task = self
            .task
            .as_mut()
            .ok_or(VpnProductEndpointError::WorkerFailed)?;
        let report = task
            .await
            .map_err(|_| VpnProductEndpointError::WorkerFailed)?;
        self.task.take();
        Ok(report)
    }
}

impl fmt::Debug for VpnServerProductEndpointRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnServerProductEndpointRuntime")
            .field("local_addr", &"[redacted]")
            .field("task_running", &self.task.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for VpnServerProductEndpointRuntime {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

pub fn start_vpn_server_product_endpoint(
    bootstrap: Arc<VpnServerProductBootstrap>,
    device: &VpnPacketDevice,
    limits: VpnProductEndpointLimits,
) -> Result<VpnServerProductEndpointRuntime, VpnProductEndpointError> {
    validate_limits(limits)?;
    let endpoint = Endpoint::server(bootstrap.tls_config().clone(), bootstrap.config().listen())
        .map_err(|error| VpnProductEndpointError::ServerBind(error.kind()))?;
    let local_addr = endpoint
        .local_addr()
        .map_err(|error| VpnProductEndpointError::LocalAddress(error.kind()))?;
    let (shutdown, shutdown_receiver) = watch::channel(false);
    let device = device.clone();
    let task = tokio::spawn(run_vpn_server_product_endpoint(
        endpoint,
        bootstrap,
        device,
        limits,
        shutdown_receiver,
    ));
    Ok(VpnServerProductEndpointRuntime {
        local_addr,
        shutdown,
        task: Some(task),
    })
}

async fn run_vpn_server_product_endpoint(
    endpoint: Endpoint,
    bootstrap: Arc<VpnServerProductBootstrap>,
    device: VpnPacketDevice,
    limits: VpnProductEndpointLimits,
    mut shutdown: watch::Receiver<bool>,
) -> VpnServerProductEndpointReport {
    let mut report =
        VpnServerProductEndpointReport::new(VpnServerProductEndpointStopReason::EndpointStopped);

    'accept: loop {
        let incoming = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                report.stop_reason = VpnServerProductEndpointStopReason::ShutdownRequested;
                break;
            }
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            }
        };
        increment(&mut report.incoming_connections);

        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(_) => {
                increment(&mut report.transport_failures);
                continue;
            }
        };
        let connection = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                report.stop_reason = VpnServerProductEndpointStopReason::ShutdownRequested;
                break;
            }
            result = timeout(limits.operation_timeout, connecting) => match result {
                Ok(Ok(connection)) => connection,
                Ok(Err(_)) => {
                    increment(&mut report.transport_failures);
                    continue;
                }
                Err(_) => {
                    increment(&mut report.transport_timeouts);
                    continue;
                }
            }
        };
        increment(&mut report.transport_connections);

        let confirmed = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                connection.close(
                    VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED.into(),
                    ENDPOINT_STOPPED_REASON,
                );
                report.stop_reason = VpnServerProductEndpointStopReason::ShutdownRequested;
                break;
            }
            result = timeout(limits.operation_timeout, connection.handshake_confirmed()) => result,
        };
        match confirmed {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                increment(&mut report.confirmation_failures);
                continue;
            }
            Err(_) => {
                increment(&mut report.confirmation_timeouts);
                connection.close(
                    VPN_CLOSE_PRODUCT_ENDPOINT_START_FAILED.into(),
                    ENDPOINT_START_FAILED_REASON,
                );
                continue;
            }
        }

        let outcome = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                connection.close(
                    VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED.into(),
                    ENDPOINT_STOPPED_REASON,
                );
                report.stop_reason = VpnServerProductEndpointStopReason::ShutdownRequested;
                break;
            }
            result = start_vpn_server_product_connection(
                &bootstrap,
                connection.clone(),
                &device,
                limits.control_timeout,
            ) => result,
        };
        let runtime = match outcome {
            Ok(VpnServerProductConnectionOutcome::Rejected(_)) => {
                increment(&mut report.session_rejections);
                continue;
            }
            Ok(VpnServerProductConnectionOutcome::Active(runtime)) => runtime,
            Err(_) => {
                increment(&mut report.runtime_start_failures);
                continue;
            }
        };

        let mut runtime_task = tokio::spawn(wait_server_runtime(runtime));
        loop {
            tokio::select! {
                biased;
                joined = &mut runtime_task => {
                    match joined {
                        Ok(connection_report) => {
                            increment(&mut report.completed_sessions);
                            report.last_connection = Some(connection_report);
                        }
                        Err(_) => increment(&mut report.worker_failures),
                    }
                    break;
                }
                _ = wait_for_shutdown(&mut shutdown) => {
                    report.stop_reason = VpnServerProductEndpointStopReason::ShutdownRequested;
                    endpoint.set_server_config(None);
                    endpoint.close(
                        VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED.into(),
                        ENDPOINT_STOPPED_REASON,
                    );
                    match timeout(limits.drain_timeout, &mut runtime_task).await {
                        Ok(Ok(connection_report)) => {
                            increment(&mut report.completed_sessions);
                            report.last_connection = Some(connection_report);
                        }
                        Ok(Err(_)) => increment(&mut report.worker_failures),
                        Err(_) => {
                            runtime_task.abort();
                            let _ = runtime_task.await;
                            increment(&mut report.forced_session_shutdowns);
                        }
                    }
                    break 'accept;
                }
                incoming = endpoint.accept() => match incoming {
                    Some(incoming) => {
                        increment(&mut report.incoming_connections);
                        increment(&mut report.busy_refusals);
                        incoming.refuse();
                    }
                    None => {
                        endpoint.close(
                            VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED.into(),
                            ENDPOINT_STOPPED_REASON,
                        );
                        match timeout(limits.drain_timeout, &mut runtime_task).await {
                            Ok(Ok(connection_report)) => {
                                increment(&mut report.completed_sessions);
                                report.last_connection = Some(connection_report);
                            }
                            Ok(Err(_)) => increment(&mut report.worker_failures),
                            Err(_) => {
                                runtime_task.abort();
                                let _ = runtime_task.await;
                                increment(&mut report.forced_session_shutdowns);
                            }
                        }
                        break 'accept;
                    }
                }
            }
        }
    }

    endpoint.set_server_config(None);
    endpoint.close(
        VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED.into(),
        ENDPOINT_STOPPED_REASON,
    );
    report.endpoint_drained = timeout(limits.drain_timeout, endpoint.wait_all_draining())
        .await
        .is_ok();
    report
}

async fn wait_server_runtime(
    runtime: Box<VpnServerProductConnectionRuntime>,
) -> VpnServerProductConnectionReport {
    runtime.wait().await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnClientProductEndpointReport {
    pub established_path_count: usize,
    pub endpoint_drained: bool,
    pub connection: VpnClientProductConnectionReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnClientProductPathSnapshot {
    pub slot: usize,
    pub path_id: u32,
    pub active: bool,
    pub explicit_source_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnClientProductPathReplacement {
    pub slot: usize,
    pub old_path_id: u32,
    pub new_path_id: u32,
    pub old_path_abandoned: bool,
    pub explicit_source_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnClientProductPathRebindReport {
    pub connection_stable_id: usize,
    pub session_generation: u64,
    pub socket_generation: u64,
    pub implicit_path_pinged: bool,
    pub replacements: Vec<VpnClientProductPathReplacement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientProductPathRebindError {
    ConnectionUnavailable,
    SocketBind(io::ErrorKind),
    SocketConfigure(io::ErrorKind),
    SocketRebind(io::ErrorKind),
    LocalAddress(io::ErrorKind),
    ImplicitPathMissing,
    ImplicitPathPing,
    PathOpen {
        slot: usize,
        error: VpnProductPathOpenError,
    },
    PathOpenTimeout {
        slot: usize,
    },
    PathInspect,
    ExplicitSourceMismatch,
    PathClose,
    PathEventLagged,
    PathEventClosed,
    PathAbandonTimeout,
}

impl fmt::Display for VpnClientProductPathRebindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketBind(kind) => write!(formatter, "vpn_client_path_rebind_bind:{kind:?}"),
            Self::SocketConfigure(kind) => {
                write!(
                    formatter,
                    "vpn_client_path_rebind_socket_configure:{kind:?}"
                )
            }
            Self::SocketRebind(kind) => {
                write!(formatter, "vpn_client_path_rebind_socket:{kind:?}")
            }
            Self::LocalAddress(kind) => {
                write!(formatter, "vpn_client_path_rebind_local_address:{kind:?}")
            }
            Self::PathOpen { slot, error } => {
                write!(
                    formatter,
                    "vpn_client_path_rebind_path_open:{slot}:{error:?}"
                )
            }
            Self::PathOpenTimeout { slot } => {
                write!(formatter, "vpn_client_path_rebind_path_open_timeout:{slot}")
            }
            other => formatter.write_str(match other {
                Self::ConnectionUnavailable => "vpn_client_path_rebind_connection_unavailable",
                Self::ImplicitPathMissing => "vpn_client_path_rebind_implicit_path_missing",
                Self::ImplicitPathPing => "vpn_client_path_rebind_implicit_path_ping",
                Self::PathInspect => "vpn_client_path_rebind_path_inspect",
                Self::ExplicitSourceMismatch => "vpn_client_path_rebind_explicit_source_mismatch",
                Self::PathClose => "vpn_client_path_rebind_path_close",
                Self::PathEventLagged => "vpn_client_path_rebind_path_event_lagged",
                Self::PathEventClosed => "vpn_client_path_rebind_path_event_closed",
                Self::PathAbandonTimeout => "vpn_client_path_rebind_path_abandon_timeout",
                Self::SocketBind(_)
                | Self::SocketConfigure(_)
                | Self::SocketRebind(_)
                | Self::LocalAddress(_)
                | Self::PathOpen { .. }
                | Self::PathOpenTimeout { .. } => unreachable!(),
            }),
        }
    }
}

impl Error for VpnClientProductPathRebindError {}

#[derive(Debug, Clone, Copy)]
struct VpnClientConfiguredPath {
    local_ip: IpAddr,
    path_id: PathId,
}

pub struct VpnClientProductEndpointRuntime {
    endpoint: Endpoint,
    connection: Option<VpnClientProductConnectionRuntime>,
    connection_report: Option<VpnClientProductConnectionReport>,
    local_addr: SocketAddr,
    bind_ip: IpAddr,
    server_addr: SocketAddr,
    configured_paths: Vec<VpnClientConfiguredPath>,
    implicit_path: Option<PathId>,
    socket_generation: u64,
    established_path_count: usize,
    operation_timeout: Duration,
    drain_timeout: Duration,
}

impl VpnClientProductEndpointRuntime {
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub const fn established_path_count(&self) -> usize {
        self.established_path_count
    }

    pub fn connection_stable_id(&self) -> Option<usize> {
        self.connection
            .as_ref()
            .map(VpnClientProductConnectionRuntime::connection_stable_id)
    }

    pub fn session_generation(&self) -> Option<u64> {
        self.connection
            .as_ref()
            .map(|connection| connection.accept().session_generation)
    }

    pub const fn socket_generation(&self) -> u64 {
        self.socket_generation
    }

    pub fn configured_path_snapshots(&self) -> Vec<VpnClientProductPathSnapshot> {
        let Some(connection) = self.connection.as_ref() else {
            return Vec::new();
        };
        let connection = connection.transport_connection();
        self.configured_paths
            .iter()
            .enumerate()
            .map(|(slot, configured)| {
                let path = connection.path(configured.path_id);
                let explicit_source_verified = path.as_ref().is_some_and(|path| {
                    path.network_path()
                        .is_ok_and(|path| path.local_ip() == Some(configured.local_ip))
                }) || (configured.path_id == PathId::ZERO
                    && self.bind_ip == configured.local_ip
                    && self.local_addr.ip() == configured.local_ip);
                VpnClientProductPathSnapshot {
                    slot,
                    path_id: configured.path_id.as_u32(),
                    active: path.is_some(),
                    explicit_source_verified,
                }
            })
            .collect()
    }

    /// Rebind the endpoint socket and replace every configured explicit path in place.
    ///
    /// Each replacement is validated with its configured source IP before the old path is closed.
    /// The QUIC connection and FWC1 session remain unchanged throughout the operation.
    pub async fn rebind_network_paths(
        &mut self,
    ) -> Result<VpnClientProductPathRebindReport, VpnClientProductPathRebindError> {
        let connection_runtime = self
            .connection
            .as_ref()
            .ok_or(VpnClientProductPathRebindError::ConnectionUnavailable)?;
        let connection_stable_id = connection_runtime.connection_stable_id();
        let session_generation = connection_runtime.accept().session_generation;
        let connection = connection_runtime.transport_connection().clone();

        let socket = StdUdpSocket::bind(SocketAddr::new(self.bind_ip, 0))
            .map_err(|error| VpnClientProductPathRebindError::SocketBind(error.kind()))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| VpnClientProductPathRebindError::SocketConfigure(error.kind()))?;
        let rebind_result = if self.configured_paths.is_empty() {
            // With no explicit source contract, retain NoQ's standard network-change handling so
            // the operating system can select and migrate the implicit path.
            self.endpoint.rebind(socket)
        } else {
            self.endpoint.rebind_preserving_paths(socket)
        };
        rebind_result
            .map_err(|error| VpnClientProductPathRebindError::SocketRebind(error.kind()))?;
        self.local_addr = self
            .endpoint
            .local_addr()
            .map_err(|error| VpnClientProductPathRebindError::LocalAddress(error.kind()))?;
        self.socket_generation = self.socket_generation.saturating_add(1);

        let implicit_path_pinged = match self.implicit_path {
            Some(path_id) => {
                let path = connection
                    .path(path_id)
                    .ok_or(VpnClientProductPathRebindError::ImplicitPathMissing)?;
                path.ping()
                    .map_err(|_| VpnClientProductPathRebindError::ImplicitPathPing)?;
                true
            }
            None => false,
        };

        for configured in &self.configured_paths {
            if let Some(path) = connection.path(configured.path_id) {
                let _ = path.ping();
            }
        }

        let deadline = Instant::now() + self.operation_timeout;
        let mut replacements = Vec::with_capacity(self.configured_paths.len());
        for slot in 0..self.configured_paths.len() {
            let configured = self.configured_paths[slot];
            let new_path =
                open_configured_path(&connection, self.server_addr, configured.local_ip, deadline)
                    .await
                    .map_err(|error| map_path_rebind_open_error(slot, error))?;
            let new_path_id = new_path.id();
            let network_path = match new_path.network_path() {
                Ok(network_path) => network_path,
                Err(_) => {
                    let _ = new_path.close();
                    return Err(VpnClientProductPathRebindError::PathInspect);
                }
            };
            let explicit_source_verified = network_path.local_ip() == Some(configured.local_ip);
            if !explicit_source_verified {
                let _ = new_path.close();
                return Err(VpnClientProductPathRebindError::ExplicitSourceMismatch);
            }

            let mut path_events = connection.path_events();
            let old_path_abandoned = match connection.path(configured.path_id) {
                Some(old_path) => match old_path.close() {
                    Ok(()) => {
                        if let Err(error) =
                            wait_for_path_abandoned(&mut path_events, configured.path_id, deadline)
                                .await
                        {
                            let _ = new_path.close();
                            return Err(error);
                        }
                        true
                    }
                    Err(ClosePathError::ClosedPath) => true,
                    Err(ClosePathError::MultipathNotNegotiated | ClosePathError::LastOpenPath) => {
                        let _ = new_path.close();
                        return Err(VpnClientProductPathRebindError::PathClose);
                    }
                },
                None => true,
            };
            self.configured_paths[slot].path_id = new_path_id;
            replacements.push(VpnClientProductPathReplacement {
                slot,
                old_path_id: configured.path_id.as_u32(),
                new_path_id: new_path_id.as_u32(),
                old_path_abandoned,
                explicit_source_verified,
            });
        }

        if connection.stable_id() != connection_stable_id
            || self.session_generation() != Some(session_generation)
        {
            return Err(VpnClientProductPathRebindError::ConnectionUnavailable);
        }
        Ok(VpnClientProductPathRebindReport {
            connection_stable_id,
            session_generation,
            socket_generation: self.socket_generation,
            implicit_path_pinged,
            replacements,
        })
    }

    pub fn accept(&self) -> crate::VpnAccept {
        self.connection
            .as_ref()
            .expect("active endpoint runtime has a connection")
            .accept()
    }

    pub fn packet_bridge_metrics(&self) -> crate::VpnPacketBridgeMetricsSnapshot {
        self.connection
            .as_ref()
            .expect("active endpoint runtime has a connection")
            .packet_bridge_metrics()
    }

    pub fn request_shutdown(&self) {
        if let Some(connection) = self.connection.as_ref() {
            connection.request_shutdown();
        }
        self.endpoint.close(
            VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED.into(),
            ENDPOINT_STOPPED_REASON,
        );
    }

    pub async fn shutdown(mut self) -> VpnClientProductEndpointReport {
        self.request_shutdown();
        self.join().await
    }

    pub async fn wait(mut self) -> VpnClientProductEndpointReport {
        self.join().await
    }

    pub async fn join(&mut self) -> VpnClientProductEndpointReport {
        if self.connection_report.is_none() {
            let connection = self
                .connection
                .as_mut()
                .expect("active endpoint runtime has a connection")
                .join()
                .await;
            self.connection.take();
            self.connection_report = Some(connection);
            self.endpoint.close(
                VPN_CLOSE_PRODUCT_ENDPOINT_STOPPED.into(),
                ENDPOINT_STOPPED_REASON,
            );
        }

        let endpoint_drained = timeout(self.drain_timeout, self.endpoint.wait_all_draining())
            .await
            .is_ok();
        VpnClientProductEndpointReport {
            established_path_count: self.established_path_count,
            endpoint_drained,
            connection: self
                .connection_report
                .take()
                .expect("completed endpoint runtime has a connection report"),
        }
    }
}

impl fmt::Debug for VpnClientProductEndpointRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnClientProductEndpointRuntime")
            .field("local_addr", &"[redacted]")
            .field("socket_generation", &self.socket_generation)
            .field("established_path_count", &self.established_path_count)
            .field("configured_path_count", &self.configured_paths.len())
            .field("accept", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl Drop for VpnClientProductEndpointRuntime {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

struct VpnClientConnectedTransport {
    endpoint: Endpoint,
    connection: Connection,
    local_addr: SocketAddr,
    bind_ip: IpAddr,
    server_addr: SocketAddr,
    configured_paths: Vec<VpnClientConfiguredPath>,
    implicit_path: Option<PathId>,
    established_path_count: usize,
}

pub async fn connect_vpn_client_product_endpoint(
    bootstrap: &VpnClientProductBootstrap,
    device: &VpnPacketDevice,
    limits: VpnProductEndpointLimits,
) -> Result<VpnClientProductEndpointRuntime, VpnProductEndpointError> {
    connect_vpn_client_product_endpoint_inner(bootstrap, device, None, limits).await
}

pub(crate) async fn connect_vpn_client_product_endpoint_with_packet_pump(
    bootstrap: &VpnClientProductBootstrap,
    device: &VpnPacketDevice,
    packet_pump: &VpnClientPacketPump,
    limits: VpnProductEndpointLimits,
) -> Result<VpnClientProductEndpointRuntime, VpnProductEndpointError> {
    connect_vpn_client_product_endpoint_inner(bootstrap, device, Some(packet_pump), limits).await
}

async fn connect_vpn_client_product_endpoint_inner(
    bootstrap: &VpnClientProductBootstrap,
    device: &VpnPacketDevice,
    packet_pump: Option<&VpnClientPacketPump>,
    limits: VpnProductEndpointLimits,
) -> Result<VpnClientProductEndpointRuntime, VpnProductEndpointError> {
    validate_limits(limits)?;
    let addresses = resolve_server_addresses(bootstrap, limits).await?;
    let mut last_error = VpnProductEndpointError::NoCompatibleServerAddress;

    for server_addr in addresses {
        match connect_vpn_client_address(bootstrap, server_addr, limits).await {
            Ok(transport) => {
                let VpnClientConnectedTransport {
                    endpoint,
                    connection,
                    local_addr,
                    bind_ip,
                    server_addr,
                    configured_paths,
                    implicit_path,
                    established_path_count,
                } = transport;
                let start_result = match packet_pump {
                    Some(packet_pump) => {
                        start_vpn_client_product_connection_with_packet_pump(
                            bootstrap,
                            connection,
                            device,
                            limits.control_timeout,
                            packet_pump,
                        )
                        .await
                    }
                    None => {
                        start_vpn_client_product_connection(
                            bootstrap,
                            connection,
                            device,
                            limits.control_timeout,
                        )
                        .await
                    }
                };
                let runtime = match start_result {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        endpoint.close(
                            VPN_CLOSE_PRODUCT_ENDPOINT_START_FAILED.into(),
                            ENDPOINT_START_FAILED_REASON,
                        );
                        let _ = timeout(limits.drain_timeout, endpoint.wait_all_draining()).await;
                        return Err(VpnProductEndpointError::ProductConnection(error));
                    }
                };
                return Ok(VpnClientProductEndpointRuntime {
                    endpoint,
                    connection: Some(runtime),
                    connection_report: None,
                    local_addr,
                    bind_ip,
                    server_addr,
                    configured_paths,
                    implicit_path,
                    socket_generation: 0,
                    established_path_count,
                    operation_timeout: limits.operation_timeout,
                    drain_timeout: limits.drain_timeout,
                });
            }
            Err(error) => last_error = error,
        }
    }

    Err(last_error)
}

async fn resolve_server_addresses(
    bootstrap: &VpnClientProductBootstrap,
    limits: VpnProductEndpointLimits,
) -> Result<Vec<SocketAddr>, VpnProductEndpointError> {
    let lookup = timeout(
        limits.operation_timeout,
        lookup_host(bootstrap.config().server()),
    )
    .await
    .map_err(|_| VpnProductEndpointError::DnsTimeout)?
    .map_err(|error| VpnProductEndpointError::DnsLookup(error.kind()))?;
    let preferred_family = bootstrap
        .config()
        .primary_local_ip()
        .or_else(|| bootstrap.config().additional_local_ips().first().copied());
    let mut seen = HashSet::new();
    let addresses = lookup
        .filter(|address| valid_remote_socket(*address))
        .filter(|address| {
            preferred_family
                .map(|local| local.is_ipv4() == address.is_ipv4())
                .unwrap_or(true)
        })
        .filter(|address| seen.insert(*address))
        .take(limits.max_connect_attempts)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(VpnProductEndpointError::NoCompatibleServerAddress);
    }
    Ok(addresses)
}

async fn connect_vpn_client_address(
    bootstrap: &VpnClientProductBootstrap,
    server_addr: SocketAddr,
    limits: VpnProductEndpointLimits,
) -> Result<VpnClientConnectedTransport, VpnProductEndpointError> {
    let replace_bootstrap_path = bootstrap.config().primary_local_ip().is_some()
        && !bootstrap.config().additional_local_ips().is_empty();
    let bind_ip = if replace_bootstrap_path {
        unspecified_for(server_addr.ip())
    } else {
        bootstrap
            .config()
            .primary_local_ip()
            .unwrap_or_else(|| unspecified_for(server_addr.ip()))
    };
    let endpoint = Endpoint::client(SocketAddr::new(bind_ip, 0))
        .map_err(|error| VpnProductEndpointError::ClientBind(error.kind()))?;
    let local_addr = endpoint
        .local_addr()
        .map_err(|error| VpnProductEndpointError::LocalAddress(error.kind()))?;
    endpoint.set_default_client_config(bootstrap.tls_config().clone());

    let result = async {
        let deadline = Instant::now() + limits.operation_timeout;
        let connecting = endpoint
            .connect(server_addr, bootstrap.config().server_name())
            .map_err(|error| VpnProductEndpointError::ConnectStart(map_connect_error(error)))?;
        let connection = timeout_at(deadline, connecting)
            .await
            .map_err(|_| VpnProductEndpointError::ConnectTimeout)?
            .map_err(|error| VpnProductEndpointError::ConnectFailed(map_connection_error(error)))?;
        timeout_at(deadline, connection.handshake_confirmed())
            .await
            .map_err(|_| VpnProductEndpointError::HandshakeConfirmationTimeout)?
            .map_err(|_| VpnProductEndpointError::HandshakeConfirmationFailed)?;
        if !connection.is_multipath_enabled() {
            return Err(VpnProductEndpointError::MultipathNotNegotiated);
        }

        let explicit_local_ips = bootstrap
            .config()
            .primary_local_ip()
            .into_iter()
            .chain(bootstrap.config().additional_local_ips().iter().copied())
            .collect::<Vec<_>>();
        let mut configured_paths = Vec::with_capacity(explicit_local_ips.len());
        if let Some(primary) = bootstrap.config().primary_local_ip()
            && !replace_bootstrap_path
        {
            configured_paths.push(VpnClientConfiguredPath {
                local_ip: primary,
                path_id: PathId::ZERO,
            });
        }
        let paths_to_open = if replace_bootstrap_path {
            explicit_local_ips.as_slice()
        } else {
            bootstrap.config().additional_local_ips()
        };
        for local_ip in paths_to_open {
            let path = open_configured_path(&connection, server_addr, *local_ip, deadline).await?;
            configured_paths.push(VpnClientConfiguredPath {
                local_ip: *local_ip,
                path_id: path.id(),
            });
        }
        if replace_bootstrap_path {
            connection
                .path(PathId::ZERO)
                .ok_or(VpnProductEndpointError::BootstrapPathMissing)?
                .close()
                .map_err(|_| VpnProductEndpointError::BootstrapPathClose)?;
        }
        let implicit_path = bootstrap
            .config()
            .primary_local_ip()
            .is_none()
            .then_some(PathId::ZERO);
        let established_path_count = configured_paths.len() + usize::from(implicit_path.is_some());
        Ok((
            connection,
            configured_paths,
            implicit_path,
            established_path_count,
        ))
    }
    .await;

    match result {
        Ok((connection, configured_paths, implicit_path, established_path_count)) => {
            Ok(VpnClientConnectedTransport {
                endpoint,
                connection,
                local_addr,
                bind_ip,
                server_addr,
                configured_paths,
                implicit_path,
                established_path_count,
            })
        }
        Err(error) => {
            endpoint.close(
                VPN_CLOSE_PRODUCT_ENDPOINT_START_FAILED.into(),
                ENDPOINT_START_FAILED_REASON,
            );
            let _ = timeout(limits.drain_timeout, endpoint.wait_all_draining()).await;
            Err(error)
        }
    }
}

async fn open_configured_path(
    connection: &Connection,
    server_addr: SocketAddr,
    local_ip: IpAddr,
    deadline: Instant,
) -> Result<Path, VpnProductEndpointError> {
    loop {
        let open = connection.open_path(
            FourTuple::new(server_addr, Some(local_ip)),
            PathStatus::Available,
        );
        match timeout_at(deadline, open).await {
            Ok(Ok(path)) => return Ok(path),
            Ok(Err(PathError::RemoteCidsExhausted | PathError::MaxPathIdReached))
                if Instant::now() < deadline =>
            {
                sleep(PATH_CID_RETRY_INTERVAL).await;
            }
            Ok(Err(error)) => {
                return Err(VpnProductEndpointError::PathOpen(map_path_error(error)));
            }
            Err(_) => return Err(VpnProductEndpointError::PathOpenTimeout),
        }
    }
}

async fn wait_for_path_abandoned(
    events: &mut noq::PathEvents,
    expected: PathId,
    deadline: Instant,
) -> Result<(), VpnClientProductPathRebindError> {
    loop {
        match timeout_at(deadline, events.next()).await {
            Ok(Some(Ok(PathEvent::Abandoned { id, .. }))) if id == expected => return Ok(()),
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) => return Err(VpnClientProductPathRebindError::PathEventLagged),
            Ok(None) => return Err(VpnClientProductPathRebindError::PathEventClosed),
            Err(_) => return Err(VpnClientProductPathRebindError::PathAbandonTimeout),
        }
    }
}

fn map_path_rebind_open_error(
    slot: usize,
    error: VpnProductEndpointError,
) -> VpnClientProductPathRebindError {
    match error {
        VpnProductEndpointError::PathOpen(error) => {
            VpnClientProductPathRebindError::PathOpen { slot, error }
        }
        VpnProductEndpointError::PathOpenTimeout => {
            VpnClientProductPathRebindError::PathOpenTimeout { slot }
        }
        _ => unreachable!("configured path helper only returns path-open errors"),
    }
}

fn validate_limits(limits: VpnProductEndpointLimits) -> Result<(), VpnProductEndpointError> {
    VpnProductEndpointLimits::new(
        limits.operation_timeout,
        limits.control_timeout,
        limits.drain_timeout,
        limits.max_connect_attempts,
    )?;
    Ok(())
}

fn map_connect_error(error: ConnectError) -> VpnProductConnectStartError {
    match error {
        ConnectError::EndpointStopping => VpnProductConnectStartError::EndpointStopping,
        ConnectError::CidsExhausted => VpnProductConnectStartError::CidsExhausted,
        ConnectError::InvalidServerName(_) => VpnProductConnectStartError::InvalidServerName,
        ConnectError::InvalidRemoteAddress(_) => VpnProductConnectStartError::InvalidRemoteAddress,
        ConnectError::NoDefaultClientConfig => VpnProductConnectStartError::MissingClientConfig,
        ConnectError::UnsupportedVersion => VpnProductConnectStartError::UnsupportedVersion,
    }
}

fn map_connection_error(error: ConnectionError) -> VpnProductConnectFailure {
    match error {
        ConnectionError::VersionMismatch => VpnProductConnectFailure::VersionMismatch,
        ConnectionError::TransportError(error) => {
            let code = u64::from(error.code);
            if error.crypto.is_some() || (0x100..0x200).contains(&code) {
                VpnProductConnectFailure::CryptoValidation
            } else if error.code == TransportErrorCode::CONNECTION_REFUSED
                || error.code == TransportErrorCode::NO_VIABLE_PATH
            {
                VpnProductConnectFailure::TransportUnavailable
            } else {
                VpnProductConnectFailure::TransportProtocol
            }
        }
        ConnectionError::ConnectionClosed(_) | ConnectionError::ApplicationClosed(_) => {
            VpnProductConnectFailure::PeerClosed
        }
        ConnectionError::Reset => VpnProductConnectFailure::Reset,
        ConnectionError::TimedOut => VpnProductConnectFailure::TimedOut,
        ConnectionError::LocallyClosed => VpnProductConnectFailure::LocallyClosed,
        ConnectionError::CidsExhausted => VpnProductConnectFailure::CidsExhausted,
    }
}

fn map_path_error(error: PathError) -> VpnProductPathOpenError {
    match error {
        PathError::MultipathNotNegotiated => VpnProductPathOpenError::MultipathNotNegotiated,
        PathError::ServerSideNotAllowed => VpnProductPathOpenError::ServerSideNotAllowed,
        PathError::MaxPathIdReached => VpnProductPathOpenError::MaxPathIdReached,
        PathError::RemoteCidsExhausted => VpnProductPathOpenError::RemoteCidsExhausted,
        PathError::ValidationFailed => VpnProductPathOpenError::ValidationFailed,
        PathError::InvalidRemoteAddress(_) => VpnProductPathOpenError::InvalidRemoteAddress,
    }
}

fn valid_remote_socket(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address.ip(), IpAddr::V4(address) if address == Ipv4Addr::BROADCAST)
}

fn unspecified_for(address: IpAddr) -> IpAddr {
    if address.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn increment(value: &mut u64) {
    *value = value.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use std::{fs, net::UdpSocket as StdUdpSocket};

    use serde_json::Value;
    use tokio::time::timeout;

    use crate::{VpnSessionError, vpn_product_runtime::tests as runtime_tests};

    use super::*;

    fn test_limits(operation_timeout: Duration) -> VpnProductEndpointLimits {
        VpnProductEndpointLimits::new(
            operation_timeout,
            Duration::from_secs(2),
            Duration::from_secs(2),
            1,
        )
        .unwrap()
    }

    #[test]
    fn endpoint_limits_are_finite_and_bounded() {
        assert_eq!(
            VpnProductEndpointLimits::new(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1),
                1,
            ),
            Err(VpnProductEndpointLimitsError::InvalidOperationTimeout)
        );
        assert_eq!(
            VpnProductEndpointLimits::new(
                Duration::from_secs(1),
                VPN_MAX_CONTROL_HANDSHAKE_TIMEOUT + Duration::from_nanos(1),
                Duration::from_secs(1),
                1,
            ),
            Err(VpnProductEndpointLimitsError::InvalidControlTimeout)
        );
        assert_eq!(
            VpnProductEndpointLimits::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::ZERO,
                1,
            ),
            Err(VpnProductEndpointLimitsError::InvalidDrainTimeout)
        );
        assert_eq!(
            VpnProductEndpointLimits::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                0,
            ),
            Err(VpnProductEndpointLimitsError::InvalidConnectAttempts)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn endpoint_rejects_then_reuses_packet_devices_across_path_configurations() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let deployment = runtime_tests::TestDeployment::new();
        let server_addr = reserve_udp_address();
        configure_endpoint(
            &deployment,
            server_addr,
            &format!("localhost:{}", server_addr.port()),
            Some("127.0.0.1"),
            &["127.0.0.2"],
        );

        let server =
            Arc::new(crate::load_vpn_server_product_bootstrap(&deployment.server_config).unwrap());
        let client = crate::load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        set_identity_enabled(&deployment, false);
        server
            .coordinator()
            .reload_from_path(&deployment.path.join("vpn-identities.json"))
            .unwrap();

        let (server_device, server_tun) = runtime_tests::packet_device_pair();
        let (client_device, client_tun) = runtime_tests::packet_device_pair();
        let limits = test_limits(Duration::from_secs(2));
        let server_runtime =
            start_vpn_server_product_endpoint(server.clone(), &server_device, limits).unwrap();
        assert_eq!(server_runtime.local_addr(), server_addr);

        assert!(matches!(
            connect_vpn_client_product_endpoint(&client, &client_device, limits).await,
            Err(VpnProductEndpointError::ProductConnection(
                VpnProductConnectionStartError::ClientSession(VpnSessionError::Rejected(_))
            ))
        ));

        set_identity_enabled(&deployment, true);
        server
            .coordinator()
            .reload_from_path(&deployment.path.join("vpn-identities.json"))
            .unwrap();

        let mut first = connect_vpn_client_product_endpoint(&client, &client_device, limits)
            .await
            .unwrap();
        assert_eq!(first.established_path_count(), 2);
        let connection_stable_id = first.connection_stable_id().unwrap();
        let session_generation = first.session_generation().unwrap();
        let initial_paths = first.configured_path_snapshots();
        assert_eq!(initial_paths.len(), 2);
        assert!(
            initial_paths
                .iter()
                .all(|path| path.active && path.explicit_source_verified)
        );
        let uplink = runtime_tests::ipv4_packet(1280, "10.77.0.2", "198.51.100.8", 0x61);
        client_tun.send(&uplink).await.unwrap();
        let mut buffer = vec![0_u8; 1600];
        let received = timeout(Duration::from_secs(2), server_tun.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], uplink.as_slice());
        let rebind = first.rebind_network_paths().await.unwrap();
        assert_eq!(rebind.connection_stable_id, connection_stable_id);
        assert_eq!(rebind.session_generation, session_generation);
        assert_eq!(rebind.socket_generation, 1);
        assert!(!rebind.implicit_path_pinged);
        assert_eq!(rebind.replacements.len(), 2);
        assert!(rebind.replacements.iter().all(|replacement| {
            replacement.old_path_abandoned
                && replacement.explicit_source_verified
                && replacement.old_path_id != replacement.new_path_id
        }));
        let rebound_paths = first.configured_path_snapshots();
        assert_eq!(rebound_paths.len(), initial_paths.len());
        assert!(
            rebound_paths
                .iter()
                .all(|path| path.active && path.explicit_source_verified)
        );
        for (initial, rebound) in initial_paths.iter().zip(&rebound_paths) {
            assert_eq!(initial.slot, rebound.slot);
            assert_ne!(initial.path_id, rebound.path_id);
        }
        assert_eq!(first.connection_stable_id(), Some(connection_stable_id));
        assert_eq!(first.session_generation(), Some(session_generation));
        let rebound_uplink = runtime_tests::ipv4_packet(1280, "10.77.0.2", "198.51.100.9", 0x62);
        client_tun.send(&rebound_uplink).await.unwrap();
        let received = timeout(Duration::from_secs(2), server_tun.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], rebound_uplink.as_slice());
        let busy_error = connect_vpn_client_product_endpoint(&client, &client_device, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            busy_error,
            VpnProductEndpointError::ConnectFailed(VpnProductConnectFailure::PeerClosed)
        ));
        let first_report = first.shutdown().await;
        assert_eq!(first_report.established_path_count, 2);
        assert!(first_report.endpoint_drained);
        wait_for_session_release(&server).await;

        configure_endpoint(
            &deployment,
            server_addr,
            &format!("localhost:{}", server_addr.port()),
            Some("127.0.0.1"),
            &[],
        );
        let primary_only_client =
            crate::load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        let mut second =
            connect_vpn_client_product_endpoint(&primary_only_client, &client_device, limits)
                .await
                .unwrap();
        assert_eq!(second.established_path_count(), 1);
        let second_connection_stable_id = second.connection_stable_id().unwrap();
        let second_session_generation = second.session_generation().unwrap();
        let primary_path = second.configured_path_snapshots();
        assert_eq!(primary_path.len(), 1);
        assert_eq!(primary_path[0].path_id, PathId::ZERO.as_u32());
        assert!(primary_path[0].active && primary_path[0].explicit_source_verified);
        let primary_rebind = second.rebind_network_paths().await.unwrap();
        assert_eq!(
            primary_rebind.connection_stable_id,
            second_connection_stable_id
        );
        assert_eq!(primary_rebind.session_generation, second_session_generation);
        assert_eq!(primary_rebind.replacements.len(), 1);
        assert_eq!(
            primary_rebind.replacements[0].old_path_id,
            PathId::ZERO.as_u32()
        );
        assert!(
            primary_rebind.replacements[0].old_path_abandoned
                && primary_rebind.replacements[0].explicit_source_verified
        );
        assert_eq!(
            second.connection_stable_id(),
            Some(second_connection_stable_id)
        );
        assert_eq!(second.session_generation(), Some(second_session_generation));
        let downlink = runtime_tests::ipv6_packet(1500, "2001:db8::8", "fd77::2", 0x72);
        server_tun.send(&downlink).await.unwrap();
        let received = timeout(Duration::from_secs(2), client_tun.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], downlink.as_slice());
        let second_report = second.shutdown().await;
        assert!(second_report.endpoint_drained);
        wait_for_session_release(&server).await;

        configure_endpoint(
            &deployment,
            server_addr,
            &server_addr.to_string(),
            None,
            &[],
        );
        let implicit_client =
            crate::load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        let mut third =
            connect_vpn_client_product_endpoint(&implicit_client, &client_device, limits)
                .await
                .unwrap();
        assert_eq!(third.established_path_count(), 1);
        assert!(third.configured_path_snapshots().is_empty());
        let third_connection_stable_id = third.connection_stable_id().unwrap();
        let third_session_generation = third.session_generation().unwrap();
        let implicit_rebind = third.rebind_network_paths().await.unwrap();
        assert_eq!(
            implicit_rebind.connection_stable_id,
            third_connection_stable_id
        );
        assert_eq!(implicit_rebind.session_generation, third_session_generation);
        assert!(implicit_rebind.implicit_path_pinged);
        assert!(implicit_rebind.replacements.is_empty());
        let implicit_uplink = runtime_tests::ipv4_packet(1280, "10.77.0.2", "198.51.100.10", 0x63);
        client_tun.send(&implicit_uplink).await.unwrap();
        let received = timeout(Duration::from_secs(2), server_tun.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], implicit_uplink.as_slice());
        let third_report = third.shutdown().await;
        assert!(third_report.endpoint_drained);
        wait_for_session_release(&server).await;

        let server_report = server_runtime.shutdown().await.unwrap();
        assert_eq!(
            server_report.stop_reason,
            VpnServerProductEndpointStopReason::ShutdownRequested
        );
        assert_eq!(server_report.session_rejections, 1);
        assert_eq!(server_report.busy_refusals, 1);
        assert_eq!(server_report.completed_sessions, 3);
        assert_eq!(server_report.runtime_start_failures, 0);
        assert_eq!(server_report.worker_failures, 0);
        assert_eq!(server_report.forced_session_shutdowns, 0);
        assert!(server_report.endpoint_drained);
        assert!(
            server_report
                .last_connection
                .is_some_and(|report| report.session_released)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_endpoint_rejects_an_unconfigured_source_address_without_leaking_it() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let deployment = runtime_tests::TestDeployment::new();
        let server_addr = reserve_udp_address();
        configure_endpoint(
            &deployment,
            server_addr,
            &server_addr.to_string(),
            Some("192.0.2.44"),
            &[],
        );
        let client = crate::load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        let (client_device, _client_tun) = runtime_tests::packet_device_pair();

        let error = connect_vpn_client_product_endpoint(
            &client,
            &client_device,
            test_limits(Duration::from_millis(200)),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            VpnProductEndpointError::ClientBind(io::ErrorKind::AddrNotAvailable)
        ));
        let debug = format!("{error:?}");
        assert!(!debug.contains("192.0.2.44"));
        assert!(!debug.contains(&server_addr.to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_endpoint_has_a_hard_transport_handshake_deadline() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let deployment = runtime_tests::TestDeployment::new();
        let blackhole = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();
        configure_endpoint(
            &deployment,
            reserve_udp_address(),
            &blackhole_addr.to_string(),
            None,
            &[],
        );
        let client = crate::load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        let (client_device, _client_tun) = runtime_tests::packet_device_pair();

        let error = connect_vpn_client_product_endpoint(
            &client,
            &client_device,
            test_limits(Duration::from_millis(75)),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, VpnProductEndpointError::ConnectTimeout));
        assert!(!format!("{error:?}").contains(&blackhole_addr.to_string()));
        drop(blackhole);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn client_endpoint_keeps_standard_server_name_verification_enabled() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let deployment = runtime_tests::TestDeployment::new();
        let server_addr = reserve_udp_address();
        configure_endpoint(
            &deployment,
            server_addr,
            &server_addr.to_string(),
            None,
            &[],
        );
        let mut client_config: Value =
            serde_json::from_slice(&fs::read(&deployment.client_config).unwrap()).unwrap();
        client_config["server_name"] = Value::from("wrong.test");
        runtime_tests::write_json(&deployment.client_config, &client_config);

        let server =
            Arc::new(crate::load_vpn_server_product_bootstrap(&deployment.server_config).unwrap());
        let client = crate::load_vpn_client_product_bootstrap(&deployment.client_config).unwrap();
        let (server_device, _server_tun) = runtime_tests::packet_device_pair();
        let (client_device, _client_tun) = runtime_tests::packet_device_pair();
        let limits = test_limits(Duration::from_secs(1));
        let server_runtime =
            start_vpn_server_product_endpoint(server, &server_device, limits).unwrap();

        let error = connect_vpn_client_product_endpoint(&client, &client_device, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            VpnProductEndpointError::ConnectFailed(VpnProductConnectFailure::CryptoValidation)
        ));
        let report = server_runtime.shutdown().await.unwrap();
        assert_eq!(report.completed_sessions, 0);
        assert_eq!(report.runtime_start_failures, 0);
    }

    fn reserve_udp_address() -> SocketAddr {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    fn configure_endpoint(
        deployment: &runtime_tests::TestDeployment,
        listen: SocketAddr,
        server: &str,
        primary_local_ip: Option<&str>,
        additional_local_ips: &[&str],
    ) {
        let mut server_config: Value =
            serde_json::from_slice(&fs::read(&deployment.server_config).unwrap()).unwrap();
        server_config["listen"] = Value::from(listen.to_string());
        runtime_tests::write_json(&deployment.server_config, &server_config);

        let mut client_config: Value =
            serde_json::from_slice(&fs::read(&deployment.client_config).unwrap()).unwrap();
        client_config["server"] = Value::from(server);
        client_config["primary_local_ip"] = primary_local_ip.map_or(Value::Null, Value::from);
        client_config["additional_local_ips"] = Value::Array(
            additional_local_ips
                .iter()
                .map(|address| Value::from(*address))
                .collect(),
        );
        runtime_tests::write_json(&deployment.client_config, &client_config);
    }

    fn set_identity_enabled(deployment: &runtime_tests::TestDeployment, enabled: bool) {
        let path = deployment.path.join("vpn-identities.json");
        let mut identity: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        identity["identities"][0]["enabled"] = Value::from(enabled);
        runtime_tests::write_json(&path, &identity);
    }

    async fn wait_for_session_release(server: &VpnServerProductBootstrap) {
        timeout(Duration::from_secs(2), async {
            loop {
                if server.coordinator().active_session("client-a").is_none() {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}

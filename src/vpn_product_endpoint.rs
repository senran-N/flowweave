use std::{
    collections::HashSet,
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use noq::{
    ConnectError, Connection, ConnectionError, Endpoint, FourTuple, PathError, PathId, PathStatus,
    TransportErrorCode,
};
use tokio::{
    net::lookup_host,
    sync::watch,
    task::JoinHandle,
    time::{Instant, sleep, timeout, timeout_at},
};

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

pub struct VpnClientProductEndpointRuntime {
    endpoint: Endpoint,
    connection: Option<VpnClientProductConnectionRuntime>,
    connection_report: Option<VpnClientProductConnectionReport>,
    local_addr: SocketAddr,
    established_path_count: usize,
    drain_timeout: Duration,
}

impl VpnClientProductEndpointRuntime {
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub const fn established_path_count(&self) -> usize {
        self.established_path_count
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
            .field("established_path_count", &self.established_path_count)
            .field("accept", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl Drop for VpnClientProductEndpointRuntime {
    fn drop(&mut self) {
        self.request_shutdown();
    }
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
            Ok((endpoint, connection, local_addr, established_path_count)) => {
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
                    established_path_count,
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
) -> Result<(Endpoint, Connection, SocketAddr, usize), VpnProductEndpointError> {
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

        let configured_paths = bootstrap
            .config()
            .primary_local_ip()
            .filter(|_| replace_bootstrap_path)
            .into_iter()
            .chain(bootstrap.config().additional_local_ips().iter().copied())
            .collect::<Vec<_>>();
        for local_ip in &configured_paths {
            open_configured_path(&connection, server_addr, *local_ip, deadline).await?;
        }
        if replace_bootstrap_path {
            connection
                .path(PathId::ZERO)
                .ok_or(VpnProductEndpointError::BootstrapPathMissing)?
                .close()
                .map_err(|_| VpnProductEndpointError::BootstrapPathClose)?;
        }
        let established_path_count = if replace_bootstrap_path {
            configured_paths.len()
        } else {
            configured_paths.len().saturating_add(1)
        };
        Ok((connection, established_path_count))
    }
    .await;

    match result {
        Ok((connection, established_path_count)) => {
            Ok((endpoint, connection, local_addr, established_path_count))
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
) -> Result<(), VpnProductEndpointError> {
    loop {
        let open = connection.open_path(
            FourTuple::new(server_addr, Some(local_ip)),
            PathStatus::Available,
        );
        match timeout_at(deadline, open).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(PathError::RemoteCidsExhausted)) if Instant::now() < deadline => {
                sleep(PATH_CID_RETRY_INTERVAL).await;
            }
            Ok(Err(error)) => {
                return Err(VpnProductEndpointError::PathOpen(map_path_error(error)));
            }
            Err(_) => return Err(VpnProductEndpointError::PathOpenTimeout),
        }
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
    async fn endpoint_rejects_then_reuses_packet_devices_for_two_generations() {
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

        let first = connect_vpn_client_product_endpoint(&client, &client_device, limits)
            .await
            .unwrap();
        assert_eq!(first.established_path_count(), 2);
        let uplink = runtime_tests::ipv4_packet(1280, "10.77.0.2", "198.51.100.8", 0x61);
        client_tun.send(&uplink).await.unwrap();
        let mut buffer = vec![0_u8; 1600];
        let received = timeout(Duration::from_secs(2), server_tun.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], uplink.as_slice());
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

        let second = connect_vpn_client_product_endpoint(&client, &client_device, limits)
            .await
            .unwrap();
        assert_eq!(second.established_path_count(), 2);
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

        let server_report = server_runtime.shutdown().await.unwrap();
        assert_eq!(
            server_report.stop_reason,
            VpnServerProductEndpointStopReason::ShutdownRequested
        );
        assert_eq!(server_report.session_rejections, 1);
        assert_eq!(server_report.busy_refusals, 1);
        assert_eq!(server_report.completed_sessions, 2);
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

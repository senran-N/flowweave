use std::{
    env,
    error::Error,
    ffi::OsStr,
    fmt, fs,
    io::{self, Write},
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::UnixDatagram,
        },
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    signal::unix::{Signal, SignalKind, signal},
    time::timeout,
};

use crate::{
    VpnPacketBridgeStopReason, VpnProductBootstrapError, VpnProductEndpointError,
    VpnProductEndpointLimits, VpnServerProductBootstrap, VpnServerProductEndpointStopReason,
    VpnTunAttachError, attach_existing_vpn_tun, connect_vpn_client_product_endpoint,
    load_vpn_client_product_bootstrap, load_vpn_server_product_bootstrap,
    start_vpn_server_product_endpoint,
};

const READY_LINE: &str = "ready";
const STOPPED_LINE: &str = "stopped";
const SERVER_READY_NOTIFICATION: &str = "READY=1\nSTATUS=FlowWeave VPN server ready";
const CLIENT_READY_NOTIFICATION: &str = "READY=1\nSTATUS=FlowWeave VPN client ready";
const STOPPING_NOTIFICATION: &str = "STOPPING=1\nSTATUS=FlowWeave VPN stopping";
const SERVER_RELOAD_SOCKET_ENV: &str = "FLOWWEAVE_VPN_SERVER_RELOAD_SOCKET";
const SERVER_RELOAD_REQUEST: &[u8; 4] = b"FWR1";
const SERVER_RELOAD_RESPONSE_OK: u8 = 0;
const SERVER_RELOAD_RESPONSE_REJECTED: u8 = 1;
const SERVER_RELOAD_IO_TIMEOUT: Duration = Duration::from_secs(2);
const SERVER_RELOAD_SUCCEEDED_STATUS: &str = "STATUS=FlowWeave VPN identities reloaded";
const SERVER_RELOAD_FAILED_STATUS: &str = "STATUS=FlowWeave VPN identity reload rejected";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductProcessRole {
    Server,
    Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductProcessStopSignal {
    Terminate,
    Interrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnProductProcessReport {
    pub role: VpnProductProcessRole,
    pub stop_signal: VpnProductProcessStopSignal,
    pub endpoint_drained: bool,
    pub established_path_count: usize,
    pub completed_sessions: u64,
    pub packet_bridge_stop_reason: Option<VpnPacketBridgeStopReason>,
    pub identity_reloads: u64,
    pub identity_reload_failures: u64,
}

#[derive(Debug)]
pub enum VpnProductProcessError {
    Bootstrap(VpnProductBootstrapError),
    Tun(VpnTunAttachError),
    Endpoint(VpnProductEndpointError),
    Signal(io::ErrorKind),
    NotifySocketInvalid,
    Notify(io::ErrorKind),
    StatusOutput(io::ErrorKind),
    ReloadSocketInvalid,
    ReloadSocketDirectoryUnsafe,
    ReloadSocketBind(io::ErrorKind),
    ReloadSocketPermissions(io::ErrorKind),
    ReloadControl(io::ErrorKind),
    ReloadUnsupported,
    UnexpectedServerStop,
    UnexpectedClientStop,
    ServerShutdownIncomplete,
    ClientShutdownIncomplete,
}

impl fmt::Display for VpnProductProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bootstrap(error) => write!(formatter, "vpn_process_bootstrap:{error}"),
            Self::Tun(error) => write!(formatter, "vpn_process_tun:{error}"),
            Self::Endpoint(error) => write!(formatter, "vpn_process_endpoint:{error}"),
            Self::Signal(kind) => write!(formatter, "vpn_process_signal:{kind:?}"),
            Self::Notify(kind) => write!(formatter, "vpn_process_notify:{kind:?}"),
            Self::StatusOutput(kind) => write!(formatter, "vpn_process_status_output:{kind:?}"),
            Self::ReloadSocketBind(kind) => {
                write!(formatter, "vpn_process_reload_socket_bind:{kind:?}")
            }
            Self::ReloadSocketPermissions(kind) => {
                write!(formatter, "vpn_process_reload_socket_permissions:{kind:?}")
            }
            Self::ReloadControl(kind) => write!(formatter, "vpn_process_reload_control:{kind:?}"),
            other => formatter.write_str(match other {
                Self::NotifySocketInvalid => "vpn_process_notify_socket_invalid",
                Self::ReloadSocketInvalid => "vpn_process_reload_socket_invalid",
                Self::ReloadSocketDirectoryUnsafe => "vpn_process_reload_socket_directory_unsafe",
                Self::ReloadUnsupported => "vpn_process_reload_unsupported",
                Self::UnexpectedServerStop => "vpn_process_unexpected_server_stop",
                Self::UnexpectedClientStop => "vpn_process_unexpected_client_stop",
                Self::ServerShutdownIncomplete => "vpn_process_server_shutdown_incomplete",
                Self::ClientShutdownIncomplete => "vpn_process_client_shutdown_incomplete",
                Self::Bootstrap(_)
                | Self::Tun(_)
                | Self::Endpoint(_)
                | Self::Signal(_)
                | Self::Notify(_)
                | Self::StatusOutput(_)
                | Self::ReloadSocketBind(_)
                | Self::ReloadSocketPermissions(_)
                | Self::ReloadControl(_) => unreachable!(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnServerReloadRequestError {
    SocketInvalid,
    Connect(io::ErrorKind),
    Io(io::ErrorKind),
    Timeout,
    Rejected,
    InvalidResponse,
}

impl fmt::Display for VpnServerReloadRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(kind) => write!(formatter, "vpn_server_reload_connect:{kind:?}"),
            Self::Io(kind) => write!(formatter, "vpn_server_reload_io:{kind:?}"),
            other => formatter.write_str(match other {
                Self::SocketInvalid => "vpn_server_reload_socket_invalid",
                Self::Timeout => "vpn_server_reload_timeout",
                Self::Rejected => "vpn_server_reload_rejected",
                Self::InvalidResponse => "vpn_server_reload_invalid_response",
                Self::Connect(_) | Self::Io(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnServerReloadRequestError {}

impl Error for VpnProductProcessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bootstrap(error) => Some(error),
            Self::Tun(error) => Some(error),
            Self::Endpoint(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VpnProductBootstrapError> for VpnProductProcessError {
    fn from(value: VpnProductBootstrapError) -> Self {
        Self::Bootstrap(value)
    }
}

impl From<VpnTunAttachError> for VpnProductProcessError {
    fn from(value: VpnTunAttachError) -> Self {
        Self::Tun(value)
    }
}

impl From<VpnProductEndpointError> for VpnProductProcessError {
    fn from(value: VpnProductEndpointError) -> Self {
        Self::Endpoint(value)
    }
}

struct VpnServerReloadControl {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl VpnServerReloadControl {
    fn bind_from_environment() -> Result<Option<Self>, VpnProductProcessError> {
        let Some(path) = env::var_os(SERVER_RELOAD_SOCKET_ENV).map(PathBuf::from) else {
            return Ok(None);
        };
        Self::bind(&path).map(Some)
    }

    fn bind(path: &Path) -> Result<Self, VpnProductProcessError> {
        validate_reload_socket_path(path)
            .map_err(|()| VpnProductProcessError::ReloadSocketInvalid)?;
        let parent = path
            .parent()
            .ok_or(VpnProductProcessError::ReloadSocketInvalid)?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|error| VpnProductProcessError::ReloadSocketBind(error.kind()))?;
        // SAFETY: geteuid has no pointer arguments and only returns the current effective UID.
        let effective_uid = unsafe { libc::geteuid() };
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != effective_uid
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(VpnProductProcessError::ReloadSocketDirectoryUnsafe);
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| VpnProductProcessError::ReloadSocketBind(error.kind()))?;
        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(path);
            return Err(VpnProductProcessError::ReloadSocketPermissions(
                error.kind(),
            ));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| VpnProductProcessError::ReloadSocketPermissions(error.kind()))?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o177 != 0
        {
            let _ = fs::remove_file(path);
            return Err(VpnProductProcessError::ReloadSocketDirectoryUnsafe);
        }
        Ok(Self {
            listener,
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    async fn accept(&self) -> Result<UnixStream, VpnProductProcessError> {
        self.listener
            .accept()
            .await
            .map(|(stream, _)| stream)
            .map_err(|error| VpnProductProcessError::ReloadControl(error.kind()))
    }
}

impl Drop for VpnServerReloadControl {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_reload_socket_path(path: &Path) -> Result<(), ()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(());
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || !components.all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(());
    }
    Ok(())
}

pub async fn request_vpn_server_identity_reload(
    socket_path: impl AsRef<Path>,
) -> Result<(), VpnServerReloadRequestError> {
    let socket_path = socket_path.as_ref();
    validate_reload_socket_path(socket_path)
        .map_err(|()| VpnServerReloadRequestError::SocketInvalid)?;
    let mut stream = timeout(SERVER_RELOAD_IO_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .map_err(|_| VpnServerReloadRequestError::Timeout)?
        .map_err(|error| VpnServerReloadRequestError::Connect(error.kind()))?;
    let (response, trailing_response_bytes) = timeout(SERVER_RELOAD_IO_TIMEOUT, async {
        stream.write_all(SERVER_RELOAD_REQUEST).await?;
        stream.shutdown().await?;
        let mut response = [0_u8; 1];
        stream.read_exact(&mut response).await?;
        let mut trailing = [0_u8; 1];
        let trailing_response_bytes = stream.read(&mut trailing).await?;
        Ok::<(u8, usize), io::Error>((response[0], trailing_response_bytes))
    })
    .await
    .map_err(|_| VpnServerReloadRequestError::Timeout)?
    .map_err(|error| VpnServerReloadRequestError::Io(error.kind()))?;
    if trailing_response_bytes != 0 {
        return Err(VpnServerReloadRequestError::InvalidResponse);
    }
    match response {
        SERVER_RELOAD_RESPONSE_OK => Ok(()),
        SERVER_RELOAD_RESPONSE_REJECTED => Err(VpnServerReloadRequestError::Rejected),
        _ => Err(VpnServerReloadRequestError::InvalidResponse),
    }
}

async fn accept_reload_request(
    control: Option<&VpnServerReloadControl>,
) -> Result<UnixStream, VpnProductProcessError> {
    match control {
        Some(control) => control.accept().await,
        None => std::future::pending().await,
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct ServerReloadCounters {
    succeeded: u64,
    failed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerReloadOutcome {
    Succeeded,
    Rejected,
}

fn reload_server_identities(
    bootstrap: &VpnServerProductBootstrap,
    counters: &mut ServerReloadCounters,
) -> ServerReloadOutcome {
    match bootstrap.reload_identities() {
        Ok(_) => {
            counters.succeeded = counters.succeeded.saturating_add(1);
            let _ = notify_systemd(SERVER_RELOAD_SUCCEEDED_STATUS);
            eprintln!("vpn_server_identity_reloaded");
            ServerReloadOutcome::Succeeded
        }
        Err(error) => {
            counters.failed = counters.failed.saturating_add(1);
            let _ = notify_systemd(SERVER_RELOAD_FAILED_STATUS);
            eprintln!("vpn_server_identity_reload_failed:{error}");
            ServerReloadOutcome::Rejected
        }
    }
}

async fn handle_reload_request(
    mut stream: UnixStream,
    bootstrap: &VpnServerProductBootstrap,
    counters: &mut ServerReloadCounters,
) {
    let request = timeout(SERVER_RELOAD_IO_TIMEOUT, async {
        let mut request = [0_u8; SERVER_RELOAD_REQUEST.len()];
        stream.read_exact(&mut request).await?;
        let mut trailing = [0_u8; 1];
        let trailing_request_bytes = stream.read(&mut trailing).await?;
        Ok::<([u8; SERVER_RELOAD_REQUEST.len()], usize), io::Error>((
            request,
            trailing_request_bytes,
        ))
    })
    .await;
    let outcome = match request {
        Ok(Ok((request, 0))) if &request == SERVER_RELOAD_REQUEST => {
            reload_server_identities(bootstrap, counters)
        }
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => ServerReloadOutcome::Rejected,
    };
    let response = match outcome {
        ServerReloadOutcome::Succeeded => SERVER_RELOAD_RESPONSE_OK,
        ServerReloadOutcome::Rejected => SERVER_RELOAD_RESPONSE_REJECTED,
    };
    let _ = timeout(SERVER_RELOAD_IO_TIMEOUT, stream.write_all(&[response])).await;
}

pub async fn run_vpn_server_product_process(
    config_path: impl AsRef<Path>,
) -> Result<VpnProductProcessReport, VpnProductProcessError> {
    let mut signals = ProductSignals::new()?;
    let bootstrap = Arc::new(load_vpn_server_product_bootstrap(config_path.as_ref())?);
    let reload_control = VpnServerReloadControl::bind_from_environment()?;
    let mut reload_counters = ServerReloadCounters::default();
    let attached =
        attach_existing_vpn_tun(bootstrap.config().tun_name(), bootstrap.config().tun_mtu())?;
    let mut runtime = start_vpn_server_product_endpoint(
        bootstrap.clone(),
        attached.device(),
        VpnProductEndpointLimits::default(),
    )?;
    while let Some(signal) = signals.recv_pending().await? {
        match signal {
            ProductSignal::Hangup => {
                reload_server_identities(&bootstrap, &mut reload_counters);
            }
            ProductSignal::Terminate | ProductSignal::Interrupt => {
                let stopping = notify_systemd(STOPPING_NOTIFICATION);
                runtime.request_shutdown();
                let report = runtime.join().await?;
                drop(attached);
                stopping?;
                return finish_server_stop(signal, report, reload_counters);
            }
        }
    }
    if let Err(error) = emit_ready(VpnProductProcessRole::Server) {
        runtime.request_shutdown();
        let _ = runtime.join().await;
        return Err(error);
    }

    loop {
        tokio::select! {
            biased;
            signal = signals.recv() => {
                let signal = signal?;
                match signal {
                    ProductSignal::Hangup => {
                        reload_server_identities(&bootstrap, &mut reload_counters);
                    }
                    ProductSignal::Terminate | ProductSignal::Interrupt => {
                        let stopping = notify_systemd(STOPPING_NOTIFICATION);
                        runtime.request_shutdown();
                        let report = runtime.join().await?;
                        drop(attached);
                        stopping?;
                        return finish_server_stop(signal, report, reload_counters);
                    }
                }
            }
            request = accept_reload_request(reload_control.as_ref()) => {
                let request = request?;
                handle_reload_request(request, &bootstrap, &mut reload_counters).await;
            }
            result = runtime.join() => {
                let _ = result?;
                drop(attached);
                let _ = notify_systemd("STATUS=FlowWeave VPN server stopped unexpectedly");
                return Err(VpnProductProcessError::UnexpectedServerStop);
            }
        }
    }
}

pub async fn run_vpn_client_product_process(
    config_path: impl AsRef<Path>,
) -> Result<VpnProductProcessReport, VpnProductProcessError> {
    let mut signals = ProductSignals::new()?;
    let bootstrap = load_vpn_client_product_bootstrap(config_path.as_ref())?;
    let attached =
        attach_existing_vpn_tun(bootstrap.config().tun_name(), bootstrap.config().tun_mtu())?;
    let startup = tokio::select! {
        biased;
        signal = signals.recv() => Err(signal?),
        runtime = connect_vpn_client_product_endpoint(
            &bootstrap,
            attached.device(),
            VpnProductEndpointLimits::default(),
        ) => Ok(runtime),
    };
    let mut runtime = match startup {
        Ok(runtime) => runtime?,
        Err(signal) => {
            let stopping = notify_systemd(STOPPING_NOTIFICATION);
            drop(attached);
            stopping?;
            return finish_pre_ready_stop(VpnProductProcessRole::Client, signal);
        }
    };
    if let Some(signal) = signals.recv_pending().await? {
        let stopping = notify_systemd(STOPPING_NOTIFICATION);
        runtime.request_shutdown();
        let report = runtime.join().await;
        drop(attached);
        stopping?;
        return finish_client_stop(signal, report);
    }
    if let Err(error) = emit_ready(VpnProductProcessRole::Client) {
        runtime.request_shutdown();
        let _ = runtime.join().await;
        return Err(error);
    }

    tokio::select! {
        biased;
        signal = signals.recv() => {
            let signal = signal?;
            let stopping = notify_systemd(STOPPING_NOTIFICATION);
            runtime.request_shutdown();
            let report = runtime.join().await;
            drop(attached);
            stopping?;
            finish_client_stop(signal, report)
        }
        report = runtime.join() => {
            let _ = report;
            drop(attached);
            let _ = notify_systemd("STATUS=FlowWeave VPN client stopped unexpectedly");
            Err(VpnProductProcessError::UnexpectedClientStop)
        }
    }
}

fn finish_pre_ready_stop(
    role: VpnProductProcessRole,
    signal: ProductSignal,
) -> Result<VpnProductProcessReport, VpnProductProcessError> {
    finish_clean_stop(VpnProductProcessReport {
        role,
        stop_signal: map_stop_signal(signal)?,
        endpoint_drained: true,
        established_path_count: 0,
        completed_sessions: 0,
        packet_bridge_stop_reason: None,
        identity_reloads: 0,
        identity_reload_failures: 0,
    })
}

fn finish_server_stop(
    signal: ProductSignal,
    report: crate::VpnServerProductEndpointReport,
    reload_counters: ServerReloadCounters,
) -> Result<VpnProductProcessReport, VpnProductProcessError> {
    validate_server_shutdown(&report)?;
    finish_clean_stop(VpnProductProcessReport {
        role: VpnProductProcessRole::Server,
        stop_signal: map_stop_signal(signal)?,
        endpoint_drained: report.endpoint_drained,
        established_path_count: 0,
        completed_sessions: report.completed_sessions,
        packet_bridge_stop_reason: report
            .last_connection
            .map(|connection| connection.packet_bridge.stop_reason),
        identity_reloads: reload_counters.succeeded,
        identity_reload_failures: reload_counters.failed,
    })
}

fn finish_client_stop(
    signal: ProductSignal,
    report: crate::VpnClientProductEndpointReport,
) -> Result<VpnProductProcessReport, VpnProductProcessError> {
    if !report.endpoint_drained
        || report.connection.packet_bridge.stop_reason
            != VpnPacketBridgeStopReason::ShutdownRequested
    {
        return Err(VpnProductProcessError::ClientShutdownIncomplete);
    }
    finish_clean_stop(VpnProductProcessReport {
        role: VpnProductProcessRole::Client,
        stop_signal: map_stop_signal(signal)?,
        endpoint_drained: report.endpoint_drained,
        established_path_count: report.established_path_count,
        completed_sessions: 1,
        packet_bridge_stop_reason: Some(report.connection.packet_bridge.stop_reason),
        identity_reloads: 0,
        identity_reload_failures: 0,
    })
}

fn map_stop_signal(
    signal: ProductSignal,
) -> Result<VpnProductProcessStopSignal, VpnProductProcessError> {
    match signal {
        ProductSignal::Terminate => Ok(VpnProductProcessStopSignal::Terminate),
        ProductSignal::Interrupt => Ok(VpnProductProcessStopSignal::Interrupt),
        ProductSignal::Hangup => Err(VpnProductProcessError::ReloadUnsupported),
    }
}

fn validate_server_shutdown(
    report: &crate::VpnServerProductEndpointReport,
) -> Result<(), VpnProductProcessError> {
    if report.stop_reason != VpnServerProductEndpointStopReason::ShutdownRequested
        || !report.endpoint_drained
        || report.worker_failures != 0
        || report.forced_session_shutdowns != 0
    {
        return Err(VpnProductProcessError::ServerShutdownIncomplete);
    }
    Ok(())
}

fn emit_ready(role: VpnProductProcessRole) -> Result<(), VpnProductProcessError> {
    let notification = match role {
        VpnProductProcessRole::Server => SERVER_READY_NOTIFICATION,
        VpnProductProcessRole::Client => CLIENT_READY_NOTIFICATION,
    };
    notify_systemd(notification)?;
    write_status_line(READY_LINE)
}

fn finish_clean_stop(
    report: VpnProductProcessReport,
) -> Result<VpnProductProcessReport, VpnProductProcessError> {
    write_status_line(STOPPED_LINE)?;
    Ok(report)
}

fn write_status_line(line: &str) -> Result<(), VpnProductProcessError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{line}")
        .and_then(|()| output.flush())
        .map_err(|error| VpnProductProcessError::StatusOutput(error.kind()))
}

fn notify_systemd(message: &str) -> Result<(), VpnProductProcessError> {
    let Some(socket) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    send_notify(&socket, message.as_bytes())
}

fn send_notify(socket: &OsStr, message: &[u8]) -> Result<(), VpnProductProcessError> {
    let name = socket.as_bytes();
    if name.is_empty() || name.contains(&0) {
        return Err(VpnProductProcessError::NotifySocketInvalid);
    }
    let datagram =
        UnixDatagram::unbound().map_err(|error| VpnProductProcessError::Notify(error.kind()))?;
    if name[0] == b'@' {
        if name.len() == 1 {
            return Err(VpnProductProcessError::NotifySocketInvalid);
        }
        let address = std::os::unix::net::SocketAddr::from_abstract_name(&name[1..])
            .map_err(|_| VpnProductProcessError::NotifySocketInvalid)?;
        datagram
            .send_to_addr(message, &address)
            .map_err(|error| VpnProductProcessError::Notify(error.kind()))?;
    } else {
        if name[0] != b'/' {
            return Err(VpnProductProcessError::NotifySocketInvalid);
        }
        datagram
            .send_to(message, Path::new(socket))
            .map_err(|error| VpnProductProcessError::Notify(error.kind()))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductSignal {
    Terminate,
    Interrupt,
    Hangup,
}

struct ProductSignals {
    terminate: Signal,
    interrupt: Signal,
    hangup: Signal,
}

impl ProductSignals {
    fn new() -> Result<Self, VpnProductProcessError> {
        Ok(Self {
            terminate: signal(SignalKind::terminate())
                .map_err(|error| VpnProductProcessError::Signal(error.kind()))?,
            interrupt: signal(SignalKind::interrupt())
                .map_err(|error| VpnProductProcessError::Signal(error.kind()))?,
            hangup: signal(SignalKind::hangup())
                .map_err(|error| VpnProductProcessError::Signal(error.kind()))?,
        })
    }

    async fn recv(&mut self) -> Result<ProductSignal, VpnProductProcessError> {
        tokio::select! {
            received = self.terminate.recv() => received
                .map(|()| ProductSignal::Terminate)
                .ok_or(VpnProductProcessError::Signal(io::ErrorKind::BrokenPipe)),
            received = self.interrupt.recv() => received
                .map(|()| ProductSignal::Interrupt)
                .ok_or(VpnProductProcessError::Signal(io::ErrorKind::BrokenPipe)),
            received = self.hangup.recv() => received
                .map(|()| ProductSignal::Hangup)
                .ok_or(VpnProductProcessError::Signal(io::ErrorKind::BrokenPipe)),
        }
    }

    async fn recv_pending(&mut self) -> Result<Option<ProductSignal>, VpnProductProcessError> {
        tokio::select! {
            biased;
            signal = self.recv() => signal.map(Some),
            _ = std::future::ready(()) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{ffi::OsStrExt, net::UnixDatagram},
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn notify_messages_are_stable_and_contain_no_network_identity() {
        for message in [
            SERVER_READY_NOTIFICATION,
            CLIENT_READY_NOTIFICATION,
            STOPPING_NOTIFICATION,
            SERVER_RELOAD_SUCCEEDED_STATUS,
            SERVER_RELOAD_FAILED_STATUS,
        ] {
            assert!(!message.contains("10."));
            assert!(!message.contains("fd"));
            assert!(!message.contains("client_id"));
            assert!(!message.contains("certificate"));
        }
        assert_eq!(READY_LINE, "ready");
        assert_eq!(STOPPED_LINE, "stopped");
    }

    #[test]
    fn notify_supports_filesystem_and_abstract_unix_datagrams() {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "flowweave-vpn-notify-{}-{sequence}.sock",
            std::process::id()
        ));
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        send_notify(path.as_os_str(), b"READY=1").unwrap();
        let mut buffer = [0_u8; 64];
        let received = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..received], b"READY=1");
        drop(receiver);
        fs::remove_file(&path).unwrap();

        let abstract_name = format!("flowweave-vpn-notify-{}-{sequence}", std::process::id());
        let address =
            std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&address).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut notify_name = vec![b'@'];
        notify_name.extend_from_slice(abstract_name.as_bytes());
        send_notify(OsStr::from_bytes(&notify_name), b"STOPPING=1").unwrap();
        let received = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..received], b"STOPPING=1");
    }

    #[test]
    fn notify_rejects_relative_empty_and_nul_addresses() {
        for value in [
            b"".as_slice(),
            b"relative".as_slice(),
            b"@".as_slice(),
            b"/bad\0path",
        ] {
            assert_eq!(
                send_notify(OsStr::from_bytes(value), b"READY=1")
                    .unwrap_err()
                    .to_string(),
                "vpn_process_notify_socket_invalid"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn synchronous_reload_control_reports_commit_and_rejection_without_losing_old_state() {
        use std::os::unix::fs::PermissionsExt;

        let deployment = crate::vpn_product_runtime::tests::TestDeployment::new();
        fs::set_permissions(&deployment.path, fs::Permissions::from_mode(0o700)).unwrap();
        let identity_path = deployment.path.join("vpn-identities.json");
        let socket_path = deployment.path.join("reload.sock");
        let bootstrap =
            Arc::new(crate::load_vpn_server_product_bootstrap(&deployment.server_config).unwrap());
        let control = VpnServerReloadControl::bind(&socket_path).unwrap();
        assert_eq!(
            fs::symlink_metadata(&socket_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let server_bootstrap = bootstrap.clone();
        let server = tokio::spawn(async move {
            let mut counters = ServerReloadCounters::default();
            for _ in 0..3 {
                let stream = control.accept().await.unwrap();
                handle_reload_request(stream, &server_bootstrap, &mut counters).await;
            }
            counters
        });

        let mut identity: serde_json::Value =
            serde_json::from_slice(&fs::read(&identity_path).unwrap()).unwrap();
        identity["identities"][0]["fingerprints"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::from("22".repeat(32)));
        crate::vpn_product_runtime::tests::write_json(&identity_path, &identity);
        request_vpn_server_identity_reload(&socket_path)
            .await
            .unwrap();
        assert_eq!(
            bootstrap
                .coordinator()
                .registry_snapshot()
                .fingerprint_count(),
            2
        );

        let mut malformed = UnixStream::connect(&socket_path).await.unwrap();
        malformed.write_all(b"FWR1x").await.unwrap();
        malformed.shutdown().await.unwrap();
        let mut malformed_response = [0_u8; 1];
        malformed.read_exact(&mut malformed_response).await.unwrap();
        assert_eq!(malformed_response[0], SERVER_RELOAD_RESPONSE_REJECTED);
        assert_eq!(
            bootstrap
                .coordinator()
                .registry_snapshot()
                .fingerprint_count(),
            2
        );

        fs::write(&identity_path, b"{invalid-json").unwrap();
        assert_eq!(
            request_vpn_server_identity_reload(&socket_path)
                .await
                .unwrap_err(),
            VpnServerReloadRequestError::Rejected
        );
        let counters = server.await.unwrap();
        assert_eq!(counters.succeeded, 1);
        assert_eq!(counters.failed, 1);
        assert_eq!(
            bootstrap
                .coordinator()
                .registry_snapshot()
                .fingerprint_count(),
            2
        );
        assert!(!socket_path.exists());

        let invalid_response_listener = UnixListener::bind(&socket_path).unwrap();
        let invalid_response_server = tokio::spawn(async move {
            let (mut stream, _) = invalid_response_listener.accept().await.unwrap();
            let mut request = [0_u8; SERVER_RELOAD_REQUEST.len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, SERVER_RELOAD_REQUEST);
            let mut trailing = [0_u8; 1];
            assert_eq!(stream.read(&mut trailing).await.unwrap(), 0);
            stream
                .write_all(&[SERVER_RELOAD_RESPONSE_OK, 0xff])
                .await
                .unwrap();
        });
        assert_eq!(
            request_vpn_server_identity_reload(&socket_path)
                .await
                .unwrap_err(),
            VpnServerReloadRequestError::InvalidResponse
        );
        invalid_response_server.await.unwrap();
        fs::remove_file(&socket_path).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_control_rejects_relative_paths_and_shared_directories() {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            validate_reload_socket_path(Path::new("relative.sock")),
            Err(())
        );
        let deployment = crate::vpn_product_runtime::tests::TestDeployment::new();
        fs::set_permissions(&deployment.path, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            VpnServerReloadControl::bind(&deployment.path.join("reload.sock")),
            Err(VpnProductProcessError::ReloadSocketDirectoryUnsafe)
        ));

        fs::set_permissions(&deployment.path, fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = deployment.path.join("reload.sock");
        let moved_socket_path = deployment.path.join("moved.sock");
        let control = VpnServerReloadControl::bind(&socket_path).unwrap();
        fs::rename(&socket_path, &moved_socket_path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        drop(control);
        assert!(socket_path.exists());
        drop(replacement);
        fs::remove_file(socket_path).unwrap();
        fs::remove_file(moved_socket_path).unwrap();
    }

    #[test]
    fn vpn_systemd_units_bind_privilege_to_short_network_transactions() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for (unit_name, role) in [
            ("flowweave-vpn-client.service", "client"),
            ("flowweave-vpn-server.service", "server"),
        ] {
            let unit = fs::read_to_string(root.join("deploy").join(unit_name)).unwrap();
            let lines = unit.lines().collect::<Vec<_>>();
            assert!(lines.contains(&"Type=notify"));
            assert!(lines.contains(&"NotifyAccess=main"));
            assert!(lines.contains(&"User=flowweave"));
            assert!(lines.contains(&"Group=flowweave"));
            assert!(lines.iter().any(|line| {
                line.starts_with(&format!(
                    "ExecStartPre=+/usr/local/bin/flowweave-vpn-net prepare-{role} "
                )) && line.ends_with(" @flowweave")
            }));
            let exec_start = format!(
                "ExecStart=/usr/local/bin/flowweave-vpn {role} /etc/flowweave/vpn-{role}.json"
            );
            assert!(lines.contains(&exec_start.as_str()));
            if role == "server" {
                assert!(lines.contains(&"RuntimeDirectory=flowweave-vpn-server"));
                assert!(lines.contains(&"RuntimeDirectoryMode=0700"));
                assert!(lines.contains(
                    &"Environment=FLOWWEAVE_VPN_SERVER_RELOAD_SOCKET=/run/flowweave-vpn-server/reload.sock"
                ));
                assert!(lines.contains(
                    &"ExecReload=/usr/local/bin/flowweave-vpn reload-server /run/flowweave-vpn-server/reload.sock"
                ));
            } else {
                assert!(!lines.iter().any(|line| line.starts_with("ExecReload=")));
            }
            assert!(lines.iter().any(|line| {
                line.starts_with(&format!(
                    "ExecStartPost=+/usr/local/bin/flowweave-vpn-net activate-{role} "
                ))
            }));
            let stop_post = lines
                .iter()
                .filter(|line| line.starts_with("ExecStopPost="))
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(stop_post.len(), 2);
            assert!(stop_post[0].contains(&format!("deactivate-{role}")));
            assert!(stop_post[1].contains(" cleanup "));
            assert!(!lines.iter().any(|line| line.starts_with("ExecStop=")));
            for required in [
                "Restart=on-failure",
                "TimeoutStartSec=90s",
                "TimeoutStopSec=30s",
                "CapabilityBoundingSet=",
                "AmbientCapabilities=",
                "NoNewPrivileges=true",
                "DevicePolicy=closed",
                "DeviceAllow=/dev/net/tun rw",
                "ProtectKernelTunables=true",
                "ProtectProc=invisible",
                "ProtectSystem=strict",
                "ProcSubset=pid",
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
                "RestrictNamespaces=true",
                "MemoryDenyWriteExecute=true",
            ] {
                assert!(
                    lines.contains(&required),
                    "{unit_name} 缺少 systemd 合同 {required}"
                );
            }
        }
    }
}

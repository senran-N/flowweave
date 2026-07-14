use std::{
    env,
    error::Error,
    ffi::OsStr,
    fmt,
    io::{self, Write},
    os::{
        linux::net::SocketAddrExt,
        unix::{ffi::OsStrExt, net::UnixDatagram},
    },
    path::Path,
    sync::Arc,
};

use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::{
    VpnPacketBridgeStopReason, VpnProductBootstrapError, VpnProductEndpointError,
    VpnProductEndpointLimits, VpnServerProductEndpointStopReason, VpnTunAttachError,
    attach_existing_vpn_tun, connect_vpn_client_product_endpoint,
    load_vpn_client_product_bootstrap, load_vpn_server_product_bootstrap,
    start_vpn_server_product_endpoint,
};

const READY_LINE: &str = "ready";
const STOPPED_LINE: &str = "stopped";
const SERVER_READY_NOTIFICATION: &str = "READY=1\nSTATUS=FlowWeave VPN server ready";
const CLIENT_READY_NOTIFICATION: &str = "READY=1\nSTATUS=FlowWeave VPN client ready";
const STOPPING_NOTIFICATION: &str = "STOPPING=1\nSTATUS=FlowWeave VPN stopping";

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
            other => formatter.write_str(match other {
                Self::NotifySocketInvalid => "vpn_process_notify_socket_invalid",
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
                | Self::StatusOutput(_) => unreachable!(),
            }),
        }
    }
}

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

pub async fn run_vpn_server_product_process(
    config_path: impl AsRef<Path>,
) -> Result<VpnProductProcessReport, VpnProductProcessError> {
    let mut signals = ProductSignals::new()?;
    let bootstrap = Arc::new(load_vpn_server_product_bootstrap(config_path.as_ref())?);
    let attached =
        attach_existing_vpn_tun(bootstrap.config().tun_name(), bootstrap.config().tun_mtu())?;
    let mut runtime = start_vpn_server_product_endpoint(
        bootstrap,
        attached.device(),
        VpnProductEndpointLimits::default(),
    )?;
    if let Some(signal) = signals.recv_pending().await? {
        let stopping = notify_systemd(STOPPING_NOTIFICATION);
        runtime.request_shutdown();
        let report = runtime.join().await?;
        drop(attached);
        stopping?;
        return finish_server_stop(signal, report);
    }
    if let Err(error) = emit_ready(VpnProductProcessRole::Server) {
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
            let report = runtime.join().await?;
            drop(attached);
            stopping?;
            finish_server_stop(signal, report)
        }
        result = runtime.join() => {
            let _ = result?;
            drop(attached);
            let _ = notify_systemd("STATUS=FlowWeave VPN server stopped unexpectedly");
            Err(VpnProductProcessError::UnexpectedServerStop)
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
    })
}

fn finish_server_stop(
    signal: ProductSignal,
    report: crate::VpnServerProductEndpointReport,
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

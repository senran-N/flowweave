use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::{
    VPN_MAX_IP_PACKET_LEN, VPN_MIN_IP_PACKET_LEN, VpnDatagramRuntime, VpnDatagramRuntimeReport,
    VpnDatagramRuntimeStopReason, VpnPacketQueueError, VpnPacketSender,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPacketBridgeConfigError {
    InvalidPacketLength,
}

impl fmt::Display for VpnPacketBridgeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("vpn_packet_bridge_invalid_packet_length")
    }
}

impl Error for VpnPacketBridgeConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnPacketBridgeConfig {
    max_packet_len: usize,
}

impl VpnPacketBridgeConfig {
    pub fn new(max_packet_len: usize) -> Result<Self, VpnPacketBridgeConfigError> {
        if !(VPN_MIN_IP_PACKET_LEN..=VPN_MAX_IP_PACKET_LEN).contains(&max_packet_len) {
            return Err(VpnPacketBridgeConfigError::InvalidPacketLength);
        }
        Ok(Self { max_packet_len })
    }

    pub const fn max_packet_len(self) -> usize {
        self.max_packet_len
    }
}

#[derive(Clone)]
pub struct VpnPacketDevice {
    io: Arc<AsyncFd<File>>,
}

impl VpnPacketDevice {
    pub fn from_file(file: File) -> io::Result<Self> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("vpn packet device requires a Tokio runtime"))?;
        set_nonblocking(file.as_raw_fd())?;
        Ok(Self {
            io: Arc::new(AsyncFd::new(file)?),
        })
    }

    pub async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vpn packet read buffer is empty",
            ));
        }
        loop {
            let mut readiness = self.io.readable().await?;
            match readiness.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(buffer)
            }) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > VPN_MAX_IP_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vpn packet write length is invalid",
            ));
        }
        loop {
            let mut readiness = self.io.writable().await?;
            match readiness.try_io(|inner| {
                let mut file = inner.get_ref();
                file.write(packet)
            }) {
                Ok(Ok(written)) if written == packet.len() => return Ok(()),
                Ok(Ok(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vpn packet device returned a partial write",
                    ));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }
}

impl fmt::Debug for VpnPacketDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnPacketDevice")
            .finish_non_exhaustive()
    }
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: fcntl only reads flags for the live descriptor borrowed from File.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK == 0 {
        // SAFETY: fcntl updates only the status flags of the same live descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnPacketBridgeMetricsSnapshot {
    pub device_read_packets: u64,
    pub device_read_bytes: u64,
    pub device_written_packets: u64,
    pub device_written_bytes: u64,
    pub oversized_device_packets: u64,
    pub oversized_device_observed_bytes: u64,
    pub outbound_queue_dropped_packets: u64,
    pub outbound_queue_dropped_bytes: u64,
    pub offline_dropped_packets: u64,
    pub offline_dropped_bytes: u64,
}

#[derive(Clone, Default)]
pub struct VpnPacketBridgeMetrics {
    inner: Arc<VpnPacketBridgeMetricCounters>,
}

impl VpnPacketBridgeMetrics {
    pub fn snapshot(&self) -> VpnPacketBridgeMetricsSnapshot {
        VpnPacketBridgeMetricsSnapshot {
            device_read_packets: self.inner.device_read_packets.load(Ordering::Relaxed),
            device_read_bytes: self.inner.device_read_bytes.load(Ordering::Relaxed),
            device_written_packets: self.inner.device_written_packets.load(Ordering::Relaxed),
            device_written_bytes: self.inner.device_written_bytes.load(Ordering::Relaxed),
            oversized_device_packets: self.inner.oversized_device_packets.load(Ordering::Relaxed),
            oversized_device_observed_bytes: self
                .inner
                .oversized_device_observed_bytes
                .load(Ordering::Relaxed),
            outbound_queue_dropped_packets: self
                .inner
                .outbound_queue_dropped_packets
                .load(Ordering::Relaxed),
            outbound_queue_dropped_bytes: self
                .inner
                .outbound_queue_dropped_bytes
                .load(Ordering::Relaxed),
            offline_dropped_packets: self.inner.offline_dropped_packets.load(Ordering::Relaxed),
            offline_dropped_bytes: self.inner.offline_dropped_bytes.load(Ordering::Relaxed),
        }
    }

    fn record_read(&self, bytes: usize) {
        increment(&self.inner.device_read_packets);
        add_usize(&self.inner.device_read_bytes, bytes);
    }

    fn record_written(&self, bytes: usize) {
        increment(&self.inner.device_written_packets);
        add_usize(&self.inner.device_written_bytes, bytes);
    }

    fn record_oversized(&self, bytes: usize) {
        increment(&self.inner.oversized_device_packets);
        add_usize(&self.inner.oversized_device_observed_bytes, bytes);
    }

    fn record_queue_drop(&self, bytes: usize) {
        increment(&self.inner.outbound_queue_dropped_packets);
        add_usize(&self.inner.outbound_queue_dropped_bytes, bytes);
    }

    fn record_offline_drop(&self, bytes: usize) {
        increment(&self.inner.offline_dropped_packets);
        add_usize(&self.inner.offline_dropped_bytes, bytes);
    }
}

impl fmt::Debug for VpnPacketBridgeMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(formatter)
    }
}

#[derive(Default)]
struct VpnPacketBridgeMetricCounters {
    device_read_packets: AtomicU64,
    device_read_bytes: AtomicU64,
    device_written_packets: AtomicU64,
    device_written_bytes: AtomicU64,
    oversized_device_packets: AtomicU64,
    oversized_device_observed_bytes: AtomicU64,
    outbound_queue_dropped_packets: AtomicU64,
    outbound_queue_dropped_bytes: AtomicU64,
    offline_dropped_packets: AtomicU64,
    offline_dropped_bytes: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientPacketPumpStartError {
    InvalidConfig(VpnPacketBridgeConfigError),
    RuntimeUnavailable,
}

impl fmt::Display for VpnClientPacketPumpStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => {
                write!(formatter, "vpn_client_packet_pump_config:{error}")
            }
            Self::RuntimeUnavailable => formatter.write_str("vpn_client_packet_pump_no_tokio"),
        }
    }
}

impl Error for VpnClientPacketPumpStartError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientPacketPumpAttachError {
    InvalidPacketLength,
    AlreadyAttached,
    GenerationExhausted,
    ControlPoisoned,
}

impl fmt::Display for VpnClientPacketPumpAttachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPacketLength => "vpn_client_packet_pump_invalid_packet_length",
            Self::AlreadyAttached => "vpn_client_packet_pump_already_attached",
            Self::GenerationExhausted => "vpn_client_packet_pump_generation_exhausted",
            Self::ControlPoisoned => "vpn_client_packet_pump_control_poisoned",
        })
    }
}

impl Error for VpnClientPacketPumpAttachError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientPacketPumpStopReason {
    ShutdownRequested,
    DeviceClosed,
    DeviceReadFailed(io::ErrorKind),
    WorkerFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnClientPacketPumpReport {
    pub stop_reason: VpnClientPacketPumpStopReason,
    pub metrics: VpnPacketBridgeMetricsSnapshot,
}

pub struct VpnClientPacketPump {
    control: VpnClientPacketPumpControl,
    task: Option<JoinHandle<VpnClientPacketPumpReport>>,
    metrics: VpnPacketBridgeMetrics,
}

impl VpnClientPacketPump {
    pub fn metrics_snapshot(&self) -> VpnPacketBridgeMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn request_shutdown(&self) {
        self.control.request_shutdown();
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn shutdown(mut self) -> VpnClientPacketPumpReport {
        self.request_shutdown();
        self.join().await
    }

    pub async fn join(&mut self) -> VpnClientPacketPumpReport {
        let task = self
            .task
            .as_mut()
            .expect("client packet pump task is present");
        let report = match task.await {
            Ok(report) => report,
            Err(_) => VpnClientPacketPumpReport {
                stop_reason: VpnClientPacketPumpStopReason::WorkerFailed,
                metrics: self.metrics.snapshot(),
            },
        };
        self.task.take();
        report
    }

    pub(crate) fn attach(
        &self,
        outbound: VpnPacketSender,
        max_packet_len: usize,
    ) -> Result<VpnClientPacketPumpAttachment, VpnClientPacketPumpAttachError> {
        self.control.attach(outbound, max_packet_len)
    }

    pub(crate) fn metrics(&self) -> VpnPacketBridgeMetrics {
        self.metrics.clone()
    }
}

impl fmt::Debug for VpnClientPacketPump {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnClientPacketPump")
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

impl Drop for VpnClientPacketPump {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

#[derive(Clone)]
struct VpnClientPacketPumpTarget {
    max_packet_len: usize,
    outbound: VpnPacketSender,
}

#[derive(Clone)]
struct VpnClientPacketPumpControl {
    inner: Arc<VpnClientPacketPumpControlInner>,
}

struct VpnClientPacketPumpControlInner {
    max_packet_len: usize,
    target: watch::Sender<Option<VpnClientPacketPumpTarget>>,
    shutdown: watch::Sender<bool>,
    attachment: Mutex<VpnClientPacketPumpAttachmentState>,
}

struct VpnClientPacketPumpAttachmentState {
    next_generation: u64,
    active_generation: Option<u64>,
}

impl VpnClientPacketPumpControl {
    fn new(max_packet_len: usize) -> Self {
        let (target, _) = watch::channel(None);
        let (shutdown, _) = watch::channel(false);
        Self {
            inner: Arc::new(VpnClientPacketPumpControlInner {
                max_packet_len,
                target,
                shutdown,
                attachment: Mutex::new(VpnClientPacketPumpAttachmentState {
                    next_generation: 1,
                    active_generation: None,
                }),
            }),
        }
    }

    fn target_receiver(&self) -> watch::Receiver<Option<VpnClientPacketPumpTarget>> {
        self.inner.target.subscribe()
    }

    fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.inner.shutdown.subscribe()
    }

    fn request_shutdown(&self) {
        self.inner.shutdown.send_replace(true);
    }

    fn attach(
        &self,
        outbound: VpnPacketSender,
        max_packet_len: usize,
    ) -> Result<VpnClientPacketPumpAttachment, VpnClientPacketPumpAttachError> {
        if !(VPN_MIN_IP_PACKET_LEN..=self.inner.max_packet_len).contains(&max_packet_len) {
            return Err(VpnClientPacketPumpAttachError::InvalidPacketLength);
        }
        let mut state = self
            .inner
            .attachment
            .lock()
            .map_err(|_| VpnClientPacketPumpAttachError::ControlPoisoned)?;
        if state.active_generation.is_some() {
            return Err(VpnClientPacketPumpAttachError::AlreadyAttached);
        }
        let generation = state.next_generation;
        state.next_generation = generation
            .checked_add(1)
            .ok_or(VpnClientPacketPumpAttachError::GenerationExhausted)?;
        state.active_generation = Some(generation);
        self.inner
            .target
            .send_replace(Some(VpnClientPacketPumpTarget {
                max_packet_len,
                outbound,
            }));
        Ok(VpnClientPacketPumpAttachment {
            control: self.clone(),
            generation,
            attached: true,
        })
    }

    fn detach(&self, generation: u64) {
        let mut state = match self.inner.attachment.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.active_generation == Some(generation) {
            state.active_generation = None;
            self.inner.target.send_replace(None);
        }
    }
}

pub(crate) struct VpnClientPacketPumpAttachment {
    control: VpnClientPacketPumpControl,
    generation: u64,
    attached: bool,
}

impl VpnClientPacketPumpAttachment {
    fn detach(&mut self) {
        if self.attached {
            self.attached = false;
            self.control.detach(self.generation);
        }
    }
}

impl Drop for VpnClientPacketPumpAttachment {
    fn drop(&mut self) {
        self.detach();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPacketBridgeStopReason {
    ShutdownRequested,
    DatagramRuntime(VpnDatagramRuntimeStopReason),
    DeviceClosed,
    DeviceReadFailed(io::ErrorKind),
    DeviceWriteFailed(io::ErrorKind),
    WorkerFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnPacketBridgeReport {
    pub stop_reason: VpnPacketBridgeStopReason,
    pub metrics: VpnPacketBridgeMetricsSnapshot,
    pub datagram_runtime: Option<VpnDatagramRuntimeReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPacketBridgeStartError {
    InvalidConfig(VpnPacketBridgeConfigError),
    ClientPump(VpnClientPacketPumpAttachError),
    RuntimeUnavailable,
}

impl fmt::Display for VpnPacketBridgeStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "vpn_packet_bridge_config:{error}"),
            Self::ClientPump(error) => write!(formatter, "vpn_packet_bridge_client_pump:{error}"),
            Self::RuntimeUnavailable => formatter.write_str("vpn_packet_bridge_no_tokio"),
        }
    }
}

impl Error for VpnPacketBridgeStartError {}

pub struct VpnPacketBridge {
    control: VpnPacketBridgeControl,
    task: Option<JoinHandle<VpnPacketBridgeReport>>,
    metrics: VpnPacketBridgeMetrics,
}

impl VpnPacketBridge {
    pub fn metrics_snapshot(&self) -> VpnPacketBridgeMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn request_shutdown(&self) {
        self.control.request_shutdown();
    }

    pub async fn shutdown(mut self) -> VpnPacketBridgeReport {
        self.request_shutdown();
        self.join().await
    }

    pub async fn wait(mut self) -> VpnPacketBridgeReport {
        self.join().await
    }

    pub async fn join(&mut self) -> VpnPacketBridgeReport {
        let task = self.task.as_mut().expect("packet bridge task is present");
        let report = match task.await {
            Ok(report) => report,
            Err(_) => VpnPacketBridgeReport {
                stop_reason: VpnPacketBridgeStopReason::WorkerFailed,
                metrics: self.metrics.snapshot(),
                datagram_runtime: None,
            },
        };
        self.task.take();
        report
    }
}

impl fmt::Debug for VpnPacketBridge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnPacketBridge")
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

impl Drop for VpnPacketBridge {
    fn drop(&mut self) {
        self.control.request_shutdown();
    }
}

pub fn start_vpn_client_packet_pump(
    device: VpnPacketDevice,
    config: VpnPacketBridgeConfig,
) -> Result<VpnClientPacketPump, VpnClientPacketPumpStartError> {
    VpnPacketBridgeConfig::new(config.max_packet_len)
        .map_err(VpnClientPacketPumpStartError::InvalidConfig)?;
    tokio::runtime::Handle::try_current()
        .map_err(|_| VpnClientPacketPumpStartError::RuntimeUnavailable)?;
    let control = VpnClientPacketPumpControl::new(config.max_packet_len);
    let metrics = VpnPacketBridgeMetrics::default();
    let task_control = control.clone();
    let task_metrics = metrics.clone();
    let task = tokio::spawn(async move {
        run_vpn_client_packet_pump(device, config, task_control, task_metrics).await
    });
    Ok(VpnClientPacketPump {
        control,
        task: Some(task),
        metrics,
    })
}

pub fn start_vpn_packet_bridge(
    device: VpnPacketDevice,
    runtime: VpnDatagramRuntime,
    config: VpnPacketBridgeConfig,
) -> Result<VpnPacketBridge, VpnPacketBridgeStartError> {
    start_vpn_packet_bridge_with_completion_guard(device, runtime, config, ())
}

pub(crate) fn start_vpn_packet_bridge_with_completion_guard<G>(
    device: VpnPacketDevice,
    runtime: VpnDatagramRuntime,
    config: VpnPacketBridgeConfig,
    completion_guard: G,
) -> Result<VpnPacketBridge, VpnPacketBridgeStartError>
where
    G: Send + 'static,
{
    VpnPacketBridgeConfig::new(config.max_packet_len)
        .map_err(VpnPacketBridgeStartError::InvalidConfig)?;
    tokio::runtime::Handle::try_current()
        .map_err(|_| VpnPacketBridgeStartError::RuntimeUnavailable)?;
    let control = VpnPacketBridgeControl::new();
    let metrics = VpnPacketBridgeMetrics::default();
    let task_control = control.clone();
    let task_metrics = metrics.clone();
    let task = tokio::spawn(async move {
        let report =
            run_vpn_packet_bridge(device, runtime, config, task_control, task_metrics).await;
        drop(completion_guard);
        report
    });
    Ok(VpnPacketBridge {
        control,
        task: Some(task),
        metrics,
    })
}

pub(crate) fn start_vpn_packet_bridge_with_client_pump<G>(
    device: VpnPacketDevice,
    runtime: VpnDatagramRuntime,
    config: VpnPacketBridgeConfig,
    pump: &VpnClientPacketPump,
    completion_guard: G,
) -> Result<VpnPacketBridge, VpnPacketBridgeStartError>
where
    G: Send + 'static,
{
    VpnPacketBridgeConfig::new(config.max_packet_len)
        .map_err(VpnPacketBridgeStartError::InvalidConfig)?;
    tokio::runtime::Handle::try_current()
        .map_err(|_| VpnPacketBridgeStartError::RuntimeUnavailable)?;
    let attachment = pump
        .attach(runtime.outbound_sender(), config.max_packet_len)
        .map_err(VpnPacketBridgeStartError::ClientPump)?;
    let control = VpnPacketBridgeControl::new();
    let metrics = pump.metrics();
    let task_control = control.clone();
    let task_metrics = metrics.clone();
    let task = tokio::spawn(async move {
        let report = run_vpn_packet_bridge_with_client_pump(
            device,
            runtime,
            task_control,
            task_metrics,
            attachment,
        )
        .await;
        drop(completion_guard);
        report
    });
    Ok(VpnPacketBridge {
        control,
        task: Some(task),
        metrics,
    })
}

#[derive(Clone)]
struct VpnPacketBridgeControl {
    shutdown: watch::Sender<bool>,
}

impl VpnPacketBridgeControl {
    fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self { shutdown }
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    fn request_shutdown(&self) {
        self.shutdown.send_replace(true);
    }
}

#[derive(Debug)]
pub(crate) enum VpnPacketReaderExit {
    Shutdown,
    DeviceClosed,
    DeviceReadFailed(io::ErrorKind),
    OutboundClosed,
}

enum VpnPacketBridgeTrigger {
    Shutdown,
    DatagramRuntimeStopped,
    Reader(VpnPacketReaderExit),
    DeviceWriteFailed(io::ErrorKind),
    WorkerFailed,
}

async fn run_vpn_client_packet_pump(
    device: VpnPacketDevice,
    config: VpnPacketBridgeConfig,
    control: VpnClientPacketPumpControl,
    metrics: VpnPacketBridgeMetrics,
) -> VpnClientPacketPumpReport {
    let target = control.target_receiver();
    let mut shutdown = control.shutdown_receiver();
    let mut buffer = vec![0_u8; config.max_packet_len.saturating_add(1)];
    let stop_reason = loop {
        let read_result = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                break VpnClientPacketPumpStopReason::ShutdownRequested;
            }
            result = device.read_packet(&mut buffer) => result,
        };
        let bytes = match read_result {
            Ok(0) => break VpnClientPacketPumpStopReason::DeviceClosed,
            Ok(bytes) => bytes,
            Err(error) => {
                break VpnClientPacketPumpStopReason::DeviceReadFailed(error.kind());
            }
        };
        metrics.record_read(bytes);
        let Some(target) = target.borrow().clone() else {
            metrics.record_offline_drop(bytes);
            continue;
        };
        if bytes > target.max_packet_len {
            metrics.record_oversized(bytes);
            continue;
        }
        if target.outbound.try_send(buffer[..bytes].to_vec()).is_err() {
            metrics.record_queue_drop(bytes);
        }
    };
    VpnClientPacketPumpReport {
        stop_reason,
        metrics: metrics.snapshot(),
    }
}

async fn run_vpn_packet_bridge(
    device: VpnPacketDevice,
    mut runtime: VpnDatagramRuntime,
    config: VpnPacketBridgeConfig,
    control: VpnPacketBridgeControl,
    metrics: VpnPacketBridgeMetrics,
) -> VpnPacketBridgeReport {
    let (reader_exit_sender, mut reader_exit_receiver) = mpsc::unbounded_channel();
    let reader_device = device.clone();
    let reader_metrics = metrics.clone();
    let reader_outbound = runtime.outbound_sender();
    let reader_shutdown = control.subscribe();
    let reader = tokio::spawn(async move {
        let exit = run_packet_reader(
            reader_device,
            reader_outbound,
            config,
            reader_shutdown,
            reader_metrics,
        )
        .await;
        let _ = reader_exit_sender.send(exit);
    });
    let mut shutdown = control.subscribe();

    let trigger = 'supervisor: loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                break VpnPacketBridgeTrigger::Shutdown;
            }
            reader_exit = reader_exit_receiver.recv() => {
                break match reader_exit {
                    Some(VpnPacketReaderExit::Shutdown) => VpnPacketBridgeTrigger::Shutdown,
                    Some(exit) => VpnPacketBridgeTrigger::Reader(exit),
                    None => VpnPacketBridgeTrigger::WorkerFailed,
                };
            }
            packet = runtime.recv_packet() => {
                let Some(packet) = packet else {
                    break VpnPacketBridgeTrigger::DatagramRuntimeStopped;
                };
                let bytes = packet.packet().as_bytes();
                let write_result = tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut shutdown) => {
                        break 'supervisor VpnPacketBridgeTrigger::Shutdown;
                    }
                    reader_exit = reader_exit_receiver.recv() => {
                        break 'supervisor match reader_exit {
                            Some(VpnPacketReaderExit::Shutdown) => VpnPacketBridgeTrigger::Shutdown,
                            Some(exit) => VpnPacketBridgeTrigger::Reader(exit),
                            None => VpnPacketBridgeTrigger::WorkerFailed,
                        };
                    }
                    result = device.write_packet(bytes) => result,
                };
                match write_result {
                    Ok(()) => metrics.record_written(bytes.len()),
                    Err(error) => {
                        break VpnPacketBridgeTrigger::DeviceWriteFailed(error.kind());
                    }
                }
            }
        }
    };

    control.request_shutdown();
    finish_vpn_packet_bridge(trigger, runtime, Some(reader), metrics).await
}

async fn run_vpn_packet_bridge_with_client_pump(
    device: VpnPacketDevice,
    mut runtime: VpnDatagramRuntime,
    control: VpnPacketBridgeControl,
    metrics: VpnPacketBridgeMetrics,
    mut attachment: VpnClientPacketPumpAttachment,
) -> VpnPacketBridgeReport {
    let mut shutdown = control.subscribe();
    let trigger = loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                break VpnPacketBridgeTrigger::Shutdown;
            }
            packet = runtime.recv_packet() => {
                let Some(packet) = packet else {
                    break VpnPacketBridgeTrigger::DatagramRuntimeStopped;
                };
                let bytes = packet.packet().as_bytes();
                let write_result = tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut shutdown) => {
                        break VpnPacketBridgeTrigger::Shutdown;
                    }
                    result = device.write_packet(bytes) => result,
                };
                match write_result {
                    Ok(()) => metrics.record_written(bytes.len()),
                    Err(error) => {
                        break VpnPacketBridgeTrigger::DeviceWriteFailed(error.kind());
                    }
                }
            }
        }
    };

    attachment.detach();
    control.request_shutdown();
    finish_vpn_packet_bridge(trigger, runtime, None, metrics).await
}

async fn finish_vpn_packet_bridge(
    trigger: VpnPacketBridgeTrigger,
    runtime: VpnDatagramRuntime,
    reader: Option<JoinHandle<()>>,
    metrics: VpnPacketBridgeMetrics,
) -> VpnPacketBridgeReport {
    let (mut stop_reason, datagram_runtime) = match trigger {
        VpnPacketBridgeTrigger::Shutdown => (
            VpnPacketBridgeStopReason::ShutdownRequested,
            Some(runtime.shutdown().await),
        ),
        VpnPacketBridgeTrigger::DatagramRuntimeStopped
        | VpnPacketBridgeTrigger::Reader(VpnPacketReaderExit::OutboundClosed) => {
            let report = runtime.wait().await;
            (
                VpnPacketBridgeStopReason::DatagramRuntime(report.stop_reason),
                Some(report),
            )
        }
        VpnPacketBridgeTrigger::Reader(VpnPacketReaderExit::DeviceClosed) => (
            VpnPacketBridgeStopReason::DeviceClosed,
            Some(runtime.shutdown().await),
        ),
        VpnPacketBridgeTrigger::Reader(VpnPacketReaderExit::DeviceReadFailed(kind)) => (
            VpnPacketBridgeStopReason::DeviceReadFailed(kind),
            Some(runtime.shutdown().await),
        ),
        VpnPacketBridgeTrigger::DeviceWriteFailed(kind) => (
            VpnPacketBridgeStopReason::DeviceWriteFailed(kind),
            Some(runtime.shutdown().await),
        ),
        VpnPacketBridgeTrigger::WorkerFailed => (
            VpnPacketBridgeStopReason::WorkerFailed,
            Some(runtime.shutdown().await),
        ),
        VpnPacketBridgeTrigger::Reader(VpnPacketReaderExit::Shutdown) => {
            unreachable!("reader shutdown is converted to a bridge shutdown trigger")
        }
    };
    if let Some(reader) = reader
        && reader.await.is_err()
    {
        stop_reason = VpnPacketBridgeStopReason::WorkerFailed;
    }
    VpnPacketBridgeReport {
        stop_reason,
        metrics: metrics.snapshot(),
        datagram_runtime,
    }
}

pub(crate) async fn run_packet_reader(
    device: VpnPacketDevice,
    outbound: VpnPacketSender,
    config: VpnPacketBridgeConfig,
    mut shutdown: watch::Receiver<bool>,
    metrics: VpnPacketBridgeMetrics,
) -> VpnPacketReaderExit {
    let mut buffer = vec![0_u8; config.max_packet_len.saturating_add(1)];
    loop {
        let read_result = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => return VpnPacketReaderExit::Shutdown,
            result = device.read_packet(&mut buffer) => result,
        };
        let bytes = match read_result {
            Ok(0) => return VpnPacketReaderExit::DeviceClosed,
            Ok(bytes) => bytes,
            Err(error) => return VpnPacketReaderExit::DeviceReadFailed(error.kind()),
        };
        metrics.record_read(bytes);
        if bytes > config.max_packet_len {
            metrics.record_oversized(bytes);
            continue;
        }
        match outbound.try_send(buffer[..bytes].to_vec()) {
            Ok(()) => {}
            Err(VpnPacketQueueError::Closed) => return VpnPacketReaderExit::OutboundClosed,
            Err(
                VpnPacketQueueError::InvalidPacketSize
                | VpnPacketQueueError::PacketLimit
                | VpnPacketQueueError::ByteLimit,
            ) => metrics.record_queue_drop(bytes),
        }
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

fn increment(counter: &AtomicU64) {
    add(counter, 1);
}

fn add_usize(counter: &AtomicU64, amount: usize) {
    add(counter, u64::try_from(amount).unwrap_or(u64::MAX));
}

fn add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

#[cfg(test)]
mod tests {
    use std::{os::fd::OwnedFd, os::unix::net::UnixDatagram as StdUnixDatagram, time::Duration};

    use tokio::{net::UnixDatagram, time::timeout};

    use super::*;

    #[test]
    fn config_rejects_lengths_outside_the_negotiated_ip_range() {
        assert_eq!(
            VpnPacketBridgeConfig::new(VPN_MIN_IP_PACKET_LEN - 1).unwrap_err(),
            VpnPacketBridgeConfigError::InvalidPacketLength
        );
        assert_eq!(
            VpnPacketBridgeConfig::new(VPN_MAX_IP_PACKET_LEN + 1).unwrap_err(),
            VpnPacketBridgeConfigError::InvalidPacketLength
        );
    }

    #[test]
    fn packet_device_without_tokio_runtime_returns_an_error_instead_of_panicking() {
        let (device, _peer) = StdUnixDatagram::pair().unwrap();
        let error = VpnPacketDevice::from_file(File::from(OwnedFd::from(device))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn packet_file_preserves_boundaries_in_both_directions() {
        let (device, peer) = packet_device_pair();
        peer.send(b"first-packet").await.unwrap();
        peer.send(b"second").await.unwrap();

        let mut buffer = [0_u8; 64];
        let first = timeout(Duration::from_secs(1), device.read_packet(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..first], b"first-packet");
        let second = timeout(Duration::from_secs(1), device.read_packet(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..second], b"second");

        device.write_packet(b"return-packet").await.unwrap();
        let received = timeout(Duration::from_secs(1), peer.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..received], b"return-packet");
    }

    #[tokio::test]
    async fn client_packet_pump_drops_every_offline_packet_without_replay_queue() {
        let (device, peer) = packet_device_pair();
        let config = VpnPacketBridgeConfig::new(VPN_MIN_IP_PACKET_LEN).unwrap();
        let mut pump = start_vpn_client_packet_pump(device, config).unwrap();

        peer.send(b"offline-one").await.unwrap();
        peer.send(b"offline-two-longer").await.unwrap();
        timeout(Duration::from_secs(1), async {
            loop {
                if pump.metrics_snapshot().offline_dropped_packets == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let snapshot = pump.metrics_snapshot();
        assert_eq!(snapshot.device_read_packets, 2);
        assert_eq!(snapshot.offline_dropped_packets, 2);
        assert_eq!(
            snapshot.offline_dropped_bytes,
            u64::try_from(b"offline-one".len() + b"offline-two-longer".len()).unwrap()
        );
        pump.request_shutdown();
        let report = pump.join().await;
        assert_eq!(
            report.stop_reason,
            VpnClientPacketPumpStopReason::ShutdownRequested
        );
        assert_eq!(report.metrics, snapshot);
    }

    fn packet_device_pair() -> (VpnPacketDevice, UnixDatagram) {
        let (device, peer) = StdUnixDatagram::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let device = VpnPacketDevice::from_file(File::from(OwnedFd::from(device))).unwrap();
        let peer = UnixDatagram::from_std(peer).unwrap();
        (device, peer)
    }
}

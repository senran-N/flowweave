use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use noq::{Connection, ConnectionError, SendDatagramError};
use tokio::{
    sync::{Notify, mpsc},
    task::{JoinError, JoinHandle},
    time::{MissedTickBehavior, interval},
};

use crate::{
    VPN_MAX_IP_PACKET_LEN, VPN_MIN_QUIC_DATAGRAM_LEN, VpnAccept, VpnDataPacket, VpnDataPathError,
    VpnDataPathHandle, VpnPacketDirection,
};

pub const VPN_DEFAULT_PACKET_QUEUE_PACKETS: usize = 1024;
pub const VPN_DEFAULT_PACKET_QUEUE_BYTES: usize = 8 * 1024 * 1024;
pub const VPN_MAX_PACKET_QUEUE_PACKETS: usize = 65_536;
pub const VPN_MAX_PACKET_QUEUE_BYTES: usize = 1024 * 1024 * 1024;
pub const VPN_DEFAULT_REASSEMBLY_TICK: Duration = Duration::from_millis(250);
pub const VPN_MAX_REASSEMBLY_TICK: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnDatagramRole {
    Server,
    Client,
}

impl VpnDatagramRole {
    const fn directions(self) -> (VpnPacketDirection, VpnPacketDirection) {
        match self {
            Self::Server => (VpnPacketDirection::Uplink, VpnPacketDirection::Downlink),
            Self::Client => (VpnPacketDirection::Downlink, VpnPacketDirection::Uplink),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnDatagramRuntimeConfigError {
    InvalidDatagramLength,
    InvalidQueuePacketLimit,
    InvalidQueueByteLimit,
    InvalidReassemblyTick,
}

impl fmt::Display for VpnDatagramRuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDatagramLength => "vpn_datagram_runtime_invalid_datagram_length",
            Self::InvalidQueuePacketLimit => "vpn_datagram_runtime_invalid_queue_packet_limit",
            Self::InvalidQueueByteLimit => "vpn_datagram_runtime_invalid_queue_byte_limit",
            Self::InvalidReassemblyTick => "vpn_datagram_runtime_invalid_reassembly_tick",
        })
    }
}

impl Error for VpnDatagramRuntimeConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnDatagramRuntimeConfig {
    role: VpnDatagramRole,
    max_datagram_len: usize,
    inbound_queue_packets: usize,
    inbound_queue_bytes: usize,
    outbound_queue_packets: usize,
    outbound_queue_bytes: usize,
    reassembly_tick: Duration,
}

impl VpnDatagramRuntimeConfig {
    pub fn new(
        role: VpnDatagramRole,
        max_datagram_len: usize,
    ) -> Result<Self, VpnDatagramRuntimeConfigError> {
        let config = Self {
            role,
            max_datagram_len,
            inbound_queue_packets: VPN_DEFAULT_PACKET_QUEUE_PACKETS,
            inbound_queue_bytes: VPN_DEFAULT_PACKET_QUEUE_BYTES,
            outbound_queue_packets: VPN_DEFAULT_PACKET_QUEUE_PACKETS,
            outbound_queue_bytes: VPN_DEFAULT_PACKET_QUEUE_BYTES,
            reassembly_tick: VPN_DEFAULT_REASSEMBLY_TICK,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn from_accept(
        role: VpnDatagramRole,
        accept: VpnAccept,
    ) -> Result<Self, VpnDatagramRuntimeConfigError> {
        Self::new(role, usize::from(accept.max_datagram_len))
    }

    pub fn with_queue_limits(
        mut self,
        inbound_packets: usize,
        inbound_bytes: usize,
        outbound_packets: usize,
        outbound_bytes: usize,
    ) -> Result<Self, VpnDatagramRuntimeConfigError> {
        self.inbound_queue_packets = inbound_packets;
        self.inbound_queue_bytes = inbound_bytes;
        self.outbound_queue_packets = outbound_packets;
        self.outbound_queue_bytes = outbound_bytes;
        self.validate()?;
        Ok(self)
    }

    pub fn with_reassembly_tick(
        mut self,
        reassembly_tick: Duration,
    ) -> Result<Self, VpnDatagramRuntimeConfigError> {
        self.reassembly_tick = reassembly_tick;
        self.validate()?;
        Ok(self)
    }

    pub const fn role(self) -> VpnDatagramRole {
        self.role
    }

    pub const fn max_datagram_len(self) -> usize {
        self.max_datagram_len
    }

    fn validate(self) -> Result<(), VpnDatagramRuntimeConfigError> {
        if !(VPN_MIN_QUIC_DATAGRAM_LEN..=u16::MAX as usize).contains(&self.max_datagram_len) {
            return Err(VpnDatagramRuntimeConfigError::InvalidDatagramLength);
        }
        if self.inbound_queue_packets == 0
            || self.inbound_queue_packets > VPN_MAX_PACKET_QUEUE_PACKETS
            || self.outbound_queue_packets == 0
            || self.outbound_queue_packets > VPN_MAX_PACKET_QUEUE_PACKETS
        {
            return Err(VpnDatagramRuntimeConfigError::InvalidQueuePacketLimit);
        }
        if !(VPN_MAX_IP_PACKET_LEN..=VPN_MAX_PACKET_QUEUE_BYTES).contains(&self.inbound_queue_bytes)
            || !(VPN_MAX_IP_PACKET_LEN..=VPN_MAX_PACKET_QUEUE_BYTES)
                .contains(&self.outbound_queue_bytes)
        {
            return Err(VpnDatagramRuntimeConfigError::InvalidQueueByteLimit);
        }
        if self.reassembly_tick.is_zero() || self.reassembly_tick > VPN_MAX_REASSEMBLY_TICK {
            return Err(VpnDatagramRuntimeConfigError::InvalidReassemblyTick);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnDatagramRuntimeStartError {
    InvalidConfig(VpnDatagramRuntimeConfigError),
    RuntimeUnavailable,
    InactiveDataPath,
    DataPathAlreadyBound,
    DatagramUnavailable,
    DatagramCapacityTooSmall,
}

impl fmt::Display for VpnDatagramRuntimeStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "vpn_datagram_runtime_config:{error}"),
            Self::RuntimeUnavailable => formatter.write_str("vpn_datagram_runtime_no_tokio"),
            Self::InactiveDataPath => formatter.write_str("vpn_datagram_runtime_inactive_path"),
            Self::DataPathAlreadyBound => {
                formatter.write_str("vpn_datagram_runtime_path_already_bound")
            }
            Self::DatagramUnavailable => {
                formatter.write_str("vpn_datagram_runtime_datagram_unavailable")
            }
            Self::DatagramCapacityTooSmall => {
                formatter.write_str("vpn_datagram_runtime_datagram_too_small")
            }
        }
    }
}

impl Error for VpnDatagramRuntimeStartError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPacketQueueError {
    InvalidPacketSize,
    PacketLimit,
    ByteLimit,
    Closed,
}

impl fmt::Display for VpnPacketQueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPacketSize => "vpn_packet_queue_invalid_packet_size",
            Self::PacketLimit => "vpn_packet_queue_packet_limit",
            Self::ByteLimit => "vpn_packet_queue_byte_limit",
            Self::Closed => "vpn_packet_queue_closed",
        })
    }
}

impl Error for VpnPacketQueueError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnDatagramRuntimeStopReason {
    ShutdownRequested,
    ConnectionClosed,
    ConnectionFailed,
    DataPathStale,
    ResourceInvariant,
    DatagramSendFailed,
    PacketIdExhausted,
    InboundConsumerClosed,
    WorkerFailed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnDatagramRuntimeMetricsSnapshot {
    pub received_datagrams: u64,
    pub received_datagram_bytes: u64,
    pub rejected_datagrams: u64,
    pub completed_inbound_packets: u64,
    pub completed_inbound_bytes: u64,
    pub inbound_queue_dropped_packets: u64,
    pub inbound_queue_dropped_bytes: u64,
    pub outbound_queue_accepted_packets: u64,
    pub outbound_queue_accepted_bytes: u64,
    pub outbound_queue_dropped_packets: u64,
    pub outbound_queue_dropped_bytes: u64,
    pub outbound_packets_encoded: u64,
    pub outbound_packets_sent: u64,
    pub outbound_packets_rejected: u64,
    pub outbound_fragments_sent: u64,
    pub outbound_fragment_bytes: u64,
    pub outbound_packets_partially_sent: u64,
    pub reassembly_packets_expired: u64,
    pub inbound_queue_current_packets: usize,
    pub inbound_queue_current_bytes: usize,
    pub inbound_queue_peak_packets: usize,
    pub inbound_queue_peak_bytes: usize,
    pub outbound_queue_current_packets: usize,
    pub outbound_queue_current_bytes: usize,
    pub outbound_queue_peak_packets: usize,
    pub outbound_queue_peak_bytes: usize,
}

#[derive(Clone)]
pub struct VpnDatagramRuntimeMetrics {
    inner: Arc<VpnDatagramRuntimeMetricCounters>,
    inbound_budget: VpnPacketQueueBudget,
    outbound_budget: VpnPacketQueueBudget,
}

impl VpnDatagramRuntimeMetrics {
    pub fn snapshot(&self) -> VpnDatagramRuntimeMetricsSnapshot {
        let inbound = self.inbound_budget.snapshot();
        let outbound = self.outbound_budget.snapshot();
        VpnDatagramRuntimeMetricsSnapshot {
            received_datagrams: self.inner.received_datagrams.load(Ordering::Relaxed),
            received_datagram_bytes: self.inner.received_datagram_bytes.load(Ordering::Relaxed),
            rejected_datagrams: self.inner.rejected_datagrams.load(Ordering::Relaxed),
            completed_inbound_packets: self.inner.completed_inbound_packets.load(Ordering::Relaxed),
            completed_inbound_bytes: self.inner.completed_inbound_bytes.load(Ordering::Relaxed),
            inbound_queue_dropped_packets: self
                .inner
                .inbound_queue_dropped_packets
                .load(Ordering::Relaxed),
            inbound_queue_dropped_bytes: self
                .inner
                .inbound_queue_dropped_bytes
                .load(Ordering::Relaxed),
            outbound_queue_accepted_packets: self
                .inner
                .outbound_queue_accepted_packets
                .load(Ordering::Relaxed),
            outbound_queue_accepted_bytes: self
                .inner
                .outbound_queue_accepted_bytes
                .load(Ordering::Relaxed),
            outbound_queue_dropped_packets: self
                .inner
                .outbound_queue_dropped_packets
                .load(Ordering::Relaxed),
            outbound_queue_dropped_bytes: self
                .inner
                .outbound_queue_dropped_bytes
                .load(Ordering::Relaxed),
            outbound_packets_encoded: self.inner.outbound_packets_encoded.load(Ordering::Relaxed),
            outbound_packets_sent: self.inner.outbound_packets_sent.load(Ordering::Relaxed),
            outbound_packets_rejected: self.inner.outbound_packets_rejected.load(Ordering::Relaxed),
            outbound_fragments_sent: self.inner.outbound_fragments_sent.load(Ordering::Relaxed),
            outbound_fragment_bytes: self.inner.outbound_fragment_bytes.load(Ordering::Relaxed),
            outbound_packets_partially_sent: self
                .inner
                .outbound_packets_partially_sent
                .load(Ordering::Relaxed),
            reassembly_packets_expired: self
                .inner
                .reassembly_packets_expired
                .load(Ordering::Relaxed),
            inbound_queue_current_packets: inbound.current_packets,
            inbound_queue_current_bytes: inbound.current_bytes,
            inbound_queue_peak_packets: inbound.peak_packets,
            inbound_queue_peak_bytes: inbound.peak_bytes,
            outbound_queue_current_packets: outbound.current_packets,
            outbound_queue_current_bytes: outbound.current_bytes,
            outbound_queue_peak_packets: outbound.peak_packets,
            outbound_queue_peak_bytes: outbound.peak_bytes,
        }
    }

    fn new(inbound_budget: VpnPacketQueueBudget, outbound_budget: VpnPacketQueueBudget) -> Self {
        Self {
            inner: Arc::new(VpnDatagramRuntimeMetricCounters::default()),
            inbound_budget,
            outbound_budget,
        }
    }

    fn record_received_datagram(&self, bytes: usize) {
        increment(&self.inner.received_datagrams);
        add_usize(&self.inner.received_datagram_bytes, bytes);
    }

    fn record_rejected_datagram(&self) {
        increment(&self.inner.rejected_datagrams);
    }

    fn record_completed_inbound(&self, bytes: usize) {
        increment(&self.inner.completed_inbound_packets);
        add_usize(&self.inner.completed_inbound_bytes, bytes);
    }

    fn record_inbound_queue_drop(&self, bytes: usize) {
        increment(&self.inner.inbound_queue_dropped_packets);
        add_usize(&self.inner.inbound_queue_dropped_bytes, bytes);
    }

    fn record_outbound_queue_accept(&self, bytes: usize) {
        increment(&self.inner.outbound_queue_accepted_packets);
        add_usize(&self.inner.outbound_queue_accepted_bytes, bytes);
    }

    fn record_outbound_queue_drop(&self, bytes: usize) {
        increment(&self.inner.outbound_queue_dropped_packets);
        add_usize(&self.inner.outbound_queue_dropped_bytes, bytes);
    }

    fn record_outbound_encoded(&self) {
        increment(&self.inner.outbound_packets_encoded);
    }

    fn record_outbound_sent(&self) {
        increment(&self.inner.outbound_packets_sent);
    }

    fn record_outbound_rejected(&self) {
        increment(&self.inner.outbound_packets_rejected);
    }

    fn record_fragment_sent(&self, bytes: usize) {
        increment(&self.inner.outbound_fragments_sent);
        add_usize(&self.inner.outbound_fragment_bytes, bytes);
    }

    fn record_partial_send(&self) {
        increment(&self.inner.outbound_packets_partially_sent);
    }

    fn record_expired(&self, packets: usize) {
        add_usize(&self.inner.reassembly_packets_expired, packets);
    }
}

impl fmt::Debug for VpnDatagramRuntimeMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(formatter)
    }
}

#[derive(Default)]
struct VpnDatagramRuntimeMetricCounters {
    received_datagrams: AtomicU64,
    received_datagram_bytes: AtomicU64,
    rejected_datagrams: AtomicU64,
    completed_inbound_packets: AtomicU64,
    completed_inbound_bytes: AtomicU64,
    inbound_queue_dropped_packets: AtomicU64,
    inbound_queue_dropped_bytes: AtomicU64,
    outbound_queue_accepted_packets: AtomicU64,
    outbound_queue_accepted_bytes: AtomicU64,
    outbound_queue_dropped_packets: AtomicU64,
    outbound_queue_dropped_bytes: AtomicU64,
    outbound_packets_encoded: AtomicU64,
    outbound_packets_sent: AtomicU64,
    outbound_packets_rejected: AtomicU64,
    outbound_fragments_sent: AtomicU64,
    outbound_fragment_bytes: AtomicU64,
    outbound_packets_partially_sent: AtomicU64,
    reassembly_packets_expired: AtomicU64,
}

pub struct VpnQueuedPacket {
    packet: VpnDataPacket,
    _lease: VpnPacketQueueLease,
}

impl VpnQueuedPacket {
    pub fn packet(&self) -> &VpnDataPacket {
        &self.packet
    }
}

impl fmt::Debug for VpnQueuedPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnQueuedPacket")
            .field("packet", self.packet())
            .finish()
    }
}

#[derive(Clone)]
pub struct VpnPacketSender {
    sender: mpsc::Sender<VpnOutboundQueueEntry>,
    budget: VpnPacketQueueBudget,
    metrics: VpnDatagramRuntimeMetrics,
}

impl VpnPacketSender {
    pub fn try_send(&self, packet: Vec<u8>) -> Result<(), VpnPacketQueueError> {
        let bytes = packet.len();
        if bytes == 0 || bytes > VPN_MAX_IP_PACKET_LEN {
            self.metrics.record_outbound_queue_drop(bytes);
            return Err(VpnPacketQueueError::InvalidPacketSize);
        }
        let lease = self.budget.try_reserve(bytes).inspect_err(|_| {
            self.metrics.record_outbound_queue_drop(bytes);
        })?;
        let entry = VpnOutboundQueueEntry {
            packet: Some(packet),
            _lease: lease,
        };
        match self.sender.try_send(entry) {
            Ok(()) => {
                self.metrics.record_outbound_queue_accept(bytes);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.record_outbound_queue_drop(bytes);
                Err(VpnPacketQueueError::PacketLimit)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics.record_outbound_queue_drop(bytes);
                Err(VpnPacketQueueError::Closed)
            }
        }
    }
}

impl fmt::Debug for VpnPacketSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnPacketSender")
            .field("queue", &self.budget.snapshot())
            .finish()
    }
}

pub struct VpnDatagramRuntime {
    outbound: VpnPacketSender,
    inbound: Option<mpsc::Receiver<VpnQueuedPacket>>,
    control: Arc<VpnRuntimeControl>,
    task: Option<JoinHandle<VpnDatagramRuntimeReport>>,
    metrics: VpnDatagramRuntimeMetrics,
}

impl VpnDatagramRuntime {
    pub fn outbound(&self) -> &VpnPacketSender {
        &self.outbound
    }

    pub fn outbound_sender(&self) -> VpnPacketSender {
        self.outbound.clone()
    }

    pub async fn recv_packet(&mut self) -> Option<VpnQueuedPacket> {
        self.inbound
            .as_mut()
            .expect("runtime inbound queue is present")
            .recv()
            .await
    }

    pub fn metrics_snapshot(&self) -> VpnDatagramRuntimeMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub async fn shutdown(mut self) -> VpnDatagramRuntimeReport {
        self.control.request_shutdown();
        self.inbound.take();
        self.await_report().await
    }

    pub async fn wait(mut self) -> VpnDatagramRuntimeReport {
        self.await_report().await
    }

    async fn await_report(&mut self) -> VpnDatagramRuntimeReport {
        let task = self.task.take().expect("runtime task is present");
        match task.await {
            Ok(report) => report,
            Err(_) => VpnDatagramRuntimeReport {
                stop_reason: VpnDatagramRuntimeStopReason::WorkerFailed,
                metrics: self.metrics.snapshot(),
            },
        }
    }
}

impl fmt::Debug for VpnDatagramRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnDatagramRuntime")
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

impl Drop for VpnDatagramRuntime {
    fn drop(&mut self) {
        self.control.request_shutdown();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnDatagramRuntimeReport {
    pub stop_reason: VpnDatagramRuntimeStopReason,
    pub metrics: VpnDatagramRuntimeMetricsSnapshot,
}

pub fn start_vpn_datagram_runtime(
    connection: Connection,
    data_path: VpnDataPathHandle,
    config: VpnDatagramRuntimeConfig,
) -> Result<VpnDatagramRuntime, VpnDatagramRuntimeStartError> {
    config
        .validate()
        .map_err(VpnDatagramRuntimeStartError::InvalidConfig)?;
    tokio::runtime::Handle::try_current()
        .map_err(|_| VpnDatagramRuntimeStartError::RuntimeUnavailable)?;
    if !data_path.snapshot().active {
        return Err(VpnDatagramRuntimeStartError::InactiveDataPath);
    }
    let connection_limit = connection
        .max_datagram_size()
        .ok_or(VpnDatagramRuntimeStartError::DatagramUnavailable)?;
    let max_datagram_len = config.max_datagram_len.min(connection_limit);
    if max_datagram_len < VPN_MIN_QUIC_DATAGRAM_LEN {
        return Err(VpnDatagramRuntimeStartError::DatagramCapacityTooSmall);
    }
    if !data_path.try_bind_runtime() {
        return Err(VpnDatagramRuntimeStartError::DataPathAlreadyBound);
    }
    if !data_path.snapshot().active {
        data_path.unbind_runtime();
        return Err(VpnDatagramRuntimeStartError::InactiveDataPath);
    }

    let inbound_budget =
        VpnPacketQueueBudget::new(config.inbound_queue_packets, config.inbound_queue_bytes);
    let outbound_budget =
        VpnPacketQueueBudget::new(config.outbound_queue_packets, config.outbound_queue_bytes);
    let metrics = VpnDatagramRuntimeMetrics::new(inbound_budget.clone(), outbound_budget.clone());
    let (inbound_sender, inbound_receiver) = mpsc::channel(config.inbound_queue_packets);
    let (outbound_sender, outbound_receiver) = mpsc::channel(config.outbound_queue_packets);
    let outbound = VpnPacketSender {
        sender: outbound_sender,
        budget: outbound_budget,
        metrics: metrics.clone(),
    };
    let control = Arc::new(VpnRuntimeControl::default());
    let (inbound_direction, outbound_direction) = config.role.directions();

    let inbound_task = tokio::spawn(run_inbound_loop(VpnInboundLoop {
        connection: connection.clone(),
        data_path: data_path.clone(),
        direction: inbound_direction,
        sender: inbound_sender,
        budget: inbound_budget,
        control: control.clone(),
        metrics: metrics.clone(),
        reassembly_tick: config.reassembly_tick,
    }));
    let outbound_task = tokio::spawn(run_outbound_loop(
        connection,
        data_path.clone(),
        outbound_direction,
        outbound_receiver,
        control.clone(),
        metrics.clone(),
        max_datagram_len,
    ));
    let supervisor_control = control.clone();
    let supervisor_metrics = metrics.clone();
    let task = tokio::spawn(async move {
        supervise_runtime(
            inbound_task,
            outbound_task,
            data_path,
            supervisor_control,
            supervisor_metrics,
        )
        .await
    });

    Ok(VpnDatagramRuntime {
        outbound,
        inbound: Some(inbound_receiver),
        control,
        task: Some(task),
        metrics,
    })
}

struct VpnInboundLoop {
    connection: Connection,
    data_path: VpnDataPathHandle,
    direction: VpnPacketDirection,
    sender: mpsc::Sender<VpnQueuedPacket>,
    budget: VpnPacketQueueBudget,
    control: Arc<VpnRuntimeControl>,
    metrics: VpnDatagramRuntimeMetrics,
    reassembly_tick: Duration,
}

async fn run_inbound_loop(task: VpnInboundLoop) -> VpnRuntimeTaskExit {
    let VpnInboundLoop {
        connection,
        data_path,
        direction,
        sender,
        budget,
        control,
        metrics,
        reassembly_tick,
    } = task;
    let mut expiry = interval(reassembly_tick);
    expiry.set_missed_tick_behavior(MissedTickBehavior::Skip);
    expiry.tick().await;
    loop {
        tokio::select! {
            biased;
            () = control.cancelled() => return VpnRuntimeTaskExit::Stopped,
            _ = expiry.tick() => {
                if !data_path.snapshot().active {
                    return VpnRuntimeTaskExit::DataPathStale;
                }
                metrics.record_expired(data_path.expire_reassembly(Instant::now()));
            }
            result = connection.read_datagram() => {
                let datagram = match result {
                    Ok(datagram) => datagram,
                    Err(ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed) => {
                        return VpnRuntimeTaskExit::ConnectionClosed;
                    }
                    Err(_) => return VpnRuntimeTaskExit::ConnectionFailed,
                };
                metrics.record_received_datagram(datagram.len());
                match data_path.ingest_datagram(direction, &datagram, Instant::now()) {
                    Ok(Some(packet)) => {
                        let bytes = packet.as_bytes().len();
                        metrics.record_completed_inbound(bytes);
                        let lease = match budget.try_reserve(bytes) {
                            Ok(lease) => lease,
                            Err(_) => {
                                metrics.record_inbound_queue_drop(bytes);
                                continue;
                            }
                        };
                        let queued = VpnQueuedPacket {
                            packet,
                            _lease: lease,
                        };
                        match sender.try_send(queued) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                metrics.record_inbound_queue_drop(bytes);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                metrics.record_inbound_queue_drop(bytes);
                                return VpnRuntimeTaskExit::InboundConsumerClosed;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(VpnDataPathError::StaleGeneration) => {
                        return VpnRuntimeTaskExit::DataPathStale;
                    }
                    Err(VpnDataPathError::ResourceAccountingInvariant) => {
                        return VpnRuntimeTaskExit::ResourceInvariant;
                    }
                    Err(VpnDataPathError::Quota(_)
                        | VpnDataPathError::Fragment(_)
                        | VpnDataPathError::Policy(_)) => {
                        metrics.record_rejected_datagram();
                    }
                }
            }
        }
    }
}

async fn run_outbound_loop(
    connection: Connection,
    data_path: VpnDataPathHandle,
    direction: VpnPacketDirection,
    mut receiver: mpsc::Receiver<VpnOutboundQueueEntry>,
    control: Arc<VpnRuntimeControl>,
    metrics: VpnDatagramRuntimeMetrics,
    max_datagram_len: usize,
) -> VpnRuntimeTaskExit {
    let packet_ids = AtomicU32::new(1);
    loop {
        let entry = tokio::select! {
            biased;
            () = control.cancelled() => return VpnRuntimeTaskExit::Stopped,
            entry = receiver.recv() => match entry {
                Some(entry) => entry,
                None => {
                    control.cancelled().await;
                    return VpnRuntimeTaskExit::Stopped;
                }
            }
        };
        let packet = entry.into_packet();
        let Some(packet_id) = allocate_packet_id(&packet_ids) else {
            return VpnRuntimeTaskExit::PacketIdExhausted;
        };
        let fragments = match data_path.encode_ip_packet(
            direction,
            packet_id,
            &packet,
            max_datagram_len,
            Instant::now(),
        ) {
            Ok(fragments) => fragments,
            Err(VpnDataPathError::StaleGeneration) => {
                return VpnRuntimeTaskExit::DataPathStale;
            }
            Err(VpnDataPathError::ResourceAccountingInvariant) => {
                return VpnRuntimeTaskExit::ResourceInvariant;
            }
            Err(
                VpnDataPathError::Quota(_)
                | VpnDataPathError::Fragment(_)
                | VpnDataPathError::Policy(_),
            ) => {
                metrics.record_outbound_rejected();
                continue;
            }
        };
        metrics.record_outbound_encoded();
        let fragment_count = fragments.len();
        let mut sent = 0_usize;
        for fragment in fragments {
            let bytes = fragment.len();
            let result = tokio::select! {
                biased;
                () = control.cancelled() => {
                    if sent > 0 && sent < fragment_count {
                        metrics.record_partial_send();
                    }
                    return VpnRuntimeTaskExit::Stopped;
                }
                result = connection.send_datagram_wait(fragment.into()) => result,
            };
            match result {
                Ok(()) => {
                    sent += 1;
                    metrics.record_fragment_sent(bytes);
                }
                Err(SendDatagramError::ConnectionLost(
                    ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed,
                )) => {
                    if sent > 0 {
                        metrics.record_partial_send();
                    }
                    return VpnRuntimeTaskExit::ConnectionClosed;
                }
                Err(SendDatagramError::ConnectionLost(_)) => {
                    if sent > 0 {
                        metrics.record_partial_send();
                    }
                    return VpnRuntimeTaskExit::ConnectionFailed;
                }
                Err(
                    SendDatagramError::UnsupportedByPeer
                    | SendDatagramError::Disabled
                    | SendDatagramError::TooLarge,
                ) => {
                    if sent > 0 {
                        metrics.record_partial_send();
                    }
                    return VpnRuntimeTaskExit::DatagramSendFailed;
                }
            }
        }
        metrics.record_outbound_sent();
    }
}

async fn supervise_runtime(
    mut inbound: JoinHandle<VpnRuntimeTaskExit>,
    mut outbound: JoinHandle<VpnRuntimeTaskExit>,
    data_path: VpnDataPathHandle,
    control: Arc<VpnRuntimeControl>,
    metrics: VpnDatagramRuntimeMetrics,
) -> VpnDatagramRuntimeReport {
    let (first, inbound_finished) = tokio::select! {
        result = &mut inbound => (join_task(result), true),
        result = &mut outbound => (join_task(result), false),
    };
    control.stop();
    let second = if inbound_finished {
        join_task(outbound.await)
    } else {
        join_task(inbound.await)
    };
    data_path.unbind_runtime();
    data_path.deactivate();
    let stop_reason = if control.shutdown_requested.load(Ordering::Acquire) {
        VpnDatagramRuntimeStopReason::ShutdownRequested
    } else {
        combine_task_exits(first, second).stop_reason()
    };
    VpnDatagramRuntimeReport {
        stop_reason,
        metrics: metrics.snapshot(),
    }
}

fn join_task(result: Result<VpnRuntimeTaskExit, JoinError>) -> VpnRuntimeTaskExit {
    result.unwrap_or(VpnRuntimeTaskExit::WorkerFailed)
}

fn combine_task_exits(first: VpnRuntimeTaskExit, second: VpnRuntimeTaskExit) -> VpnRuntimeTaskExit {
    if first == VpnRuntimeTaskExit::WorkerFailed || second == VpnRuntimeTaskExit::WorkerFailed {
        VpnRuntimeTaskExit::WorkerFailed
    } else if first == VpnRuntimeTaskExit::Stopped {
        second
    } else {
        first
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VpnRuntimeTaskExit {
    Stopped,
    ConnectionClosed,
    ConnectionFailed,
    DataPathStale,
    ResourceInvariant,
    DatagramSendFailed,
    PacketIdExhausted,
    InboundConsumerClosed,
    WorkerFailed,
}

impl VpnRuntimeTaskExit {
    const fn stop_reason(self) -> VpnDatagramRuntimeStopReason {
        match self {
            Self::Stopped => VpnDatagramRuntimeStopReason::ShutdownRequested,
            Self::ConnectionClosed => VpnDatagramRuntimeStopReason::ConnectionClosed,
            Self::ConnectionFailed => VpnDatagramRuntimeStopReason::ConnectionFailed,
            Self::DataPathStale => VpnDatagramRuntimeStopReason::DataPathStale,
            Self::ResourceInvariant => VpnDatagramRuntimeStopReason::ResourceInvariant,
            Self::DatagramSendFailed => VpnDatagramRuntimeStopReason::DatagramSendFailed,
            Self::PacketIdExhausted => VpnDatagramRuntimeStopReason::PacketIdExhausted,
            Self::InboundConsumerClosed => VpnDatagramRuntimeStopReason::InboundConsumerClosed,
            Self::WorkerFailed => VpnDatagramRuntimeStopReason::WorkerFailed,
        }
    }
}

#[derive(Default)]
struct VpnRuntimeControl {
    stopping: AtomicBool,
    shutdown_requested: AtomicBool,
    notify: Notify,
}

impl VpnRuntimeControl {
    fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
        self.stop();
    }

    fn stop(&self) {
        if !self.stopping.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.stopping.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct VpnOutboundQueueEntry {
    packet: Option<Vec<u8>>,
    _lease: VpnPacketQueueLease,
}

impl VpnOutboundQueueEntry {
    fn into_packet(mut self) -> Vec<u8> {
        self.packet.take().expect("outbound packet is present")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VpnPacketQueueBudgetSnapshot {
    current_packets: usize,
    current_bytes: usize,
    peak_packets: usize,
    peak_bytes: usize,
}

#[derive(Clone)]
struct VpnPacketQueueBudget {
    inner: Arc<VpnPacketQueueBudgetInner>,
}

impl VpnPacketQueueBudget {
    fn new(packet_limit: usize, byte_limit: usize) -> Self {
        Self {
            inner: Arc::new(VpnPacketQueueBudgetInner {
                packet_limit,
                byte_limit,
                current_packets: AtomicUsize::new(0),
                current_bytes: AtomicUsize::new(0),
                peak_packets: AtomicUsize::new(0),
                peak_bytes: AtomicUsize::new(0),
            }),
        }
    }

    fn try_reserve(&self, bytes: usize) -> Result<VpnPacketQueueLease, VpnPacketQueueError> {
        let Some(current_bytes) =
            try_add_bounded(&self.inner.current_bytes, bytes, self.inner.byte_limit)
        else {
            return Err(VpnPacketQueueError::ByteLimit);
        };
        let Some(current_packets) =
            try_add_bounded(&self.inner.current_packets, 1, self.inner.packet_limit)
        else {
            subtract(&self.inner.current_bytes, bytes);
            return Err(VpnPacketQueueError::PacketLimit);
        };
        self.inner
            .peak_bytes
            .fetch_max(current_bytes, Ordering::Relaxed);
        self.inner
            .peak_packets
            .fetch_max(current_packets, Ordering::Relaxed);
        Ok(VpnPacketQueueLease {
            budget: self.clone(),
            bytes,
        })
    }

    fn release(&self, bytes: usize) {
        subtract(&self.inner.current_bytes, bytes);
        subtract(&self.inner.current_packets, 1);
    }

    fn snapshot(&self) -> VpnPacketQueueBudgetSnapshot {
        VpnPacketQueueBudgetSnapshot {
            current_packets: self.inner.current_packets.load(Ordering::Relaxed),
            current_bytes: self.inner.current_bytes.load(Ordering::Relaxed),
            peak_packets: self.inner.peak_packets.load(Ordering::Relaxed),
            peak_bytes: self.inner.peak_bytes.load(Ordering::Relaxed),
        }
    }
}

struct VpnPacketQueueBudgetInner {
    packet_limit: usize,
    byte_limit: usize,
    current_packets: AtomicUsize,
    current_bytes: AtomicUsize,
    peak_packets: AtomicUsize,
    peak_bytes: AtomicUsize,
}

struct VpnPacketQueueLease {
    budget: VpnPacketQueueBudget,
    bytes: usize,
}

impl Drop for VpnPacketQueueLease {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

fn allocate_packet_id(next: &AtomicU32) -> Option<u32> {
    next.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        (current != 0).then_some(current.wrapping_add(1))
    })
    .ok()
}

fn try_add_bounded(counter: &AtomicUsize, amount: usize, limit: usize) -> Option<usize> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(amount).filter(|next| *next <= limit)
        })
        .ok()
        .and_then(|previous| previous.checked_add(amount))
}

fn subtract(counter: &AtomicUsize, amount: usize) {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_sub(amount)
        })
        .expect("VPN packet queue accounting cannot underflow");
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
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use noq::Endpoint;
    use tokio::time::timeout;

    use crate::{
        MultipathScheduler, PtoRecovery, QuicCongestion, VpnCertificateFingerprint, VpnIdentity,
        VpnIdentityLimits, VpnIpNetwork,
        vpn_data_policy::VpnDataPolicyMetrics,
        vpn_quota::{VpnGlobalReassemblyBudget, VpnIdentityRateLimiter, VpnQuotaMetrics},
    };

    use super::*;

    #[test]
    fn config_rejects_unbounded_or_unusable_values() {
        assert_eq!(
            VpnDatagramRuntimeConfig::new(VpnDatagramRole::Server, VPN_MIN_QUIC_DATAGRAM_LEN - 1,)
                .unwrap_err(),
            VpnDatagramRuntimeConfigError::InvalidDatagramLength
        );
        let config = VpnDatagramRuntimeConfig::new(VpnDatagramRole::Server, 1200).unwrap();
        assert_eq!(
            config
                .with_queue_limits(0, VPN_MAX_IP_PACKET_LEN, 1, VPN_MAX_IP_PACKET_LEN)
                .unwrap_err(),
            VpnDatagramRuntimeConfigError::InvalidQueuePacketLimit
        );
        assert_eq!(
            config
                .with_queue_limits(1, VPN_MAX_IP_PACKET_LEN - 1, 1, VPN_MAX_IP_PACKET_LEN)
                .unwrap_err(),
            VpnDatagramRuntimeConfigError::InvalidQueueByteLimit
        );
        assert_eq!(
            config.with_reassembly_tick(Duration::ZERO).unwrap_err(),
            VpnDatagramRuntimeConfigError::InvalidReassemblyTick
        );
    }

    #[test]
    fn queue_budget_is_dual_bounded_and_drop_safe() {
        let budget = VpnPacketQueueBudget::new(1, 100);
        let lease = budget.try_reserve(60).unwrap();
        assert!(matches!(
            budget.try_reserve(1),
            Err(VpnPacketQueueError::PacketLimit)
        ));
        assert!(matches!(
            budget.try_reserve(50),
            Err(VpnPacketQueueError::ByteLimit)
        ));
        assert_eq!(budget.snapshot().current_bytes, 60);
        drop(lease);
        assert_eq!(budget.snapshot().current_packets, 0);
        assert_eq!(budget.snapshot().current_bytes, 0);
        assert_eq!(budget.snapshot().peak_packets, 1);
        assert_eq!(budget.snapshot().peak_bytes, 60);
    }

    #[test]
    fn packet_id_allocator_uses_max_once_then_exhausts() {
        let next = AtomicU32::new(u32::MAX);
        assert_eq!(allocate_packet_id(&next), Some(u32::MAX));
        assert_eq!(allocate_packet_id(&next), None);
    }

    #[test]
    fn supervisor_preserves_real_failure_and_worker_panic() {
        assert_eq!(
            combine_task_exits(
                VpnRuntimeTaskExit::Stopped,
                VpnRuntimeTaskExit::ConnectionFailed,
            ),
            VpnRuntimeTaskExit::ConnectionFailed
        );
        assert_eq!(
            combine_task_exits(
                VpnRuntimeTaskExit::ConnectionClosed,
                VpnRuntimeTaskExit::WorkerFailed,
            ),
            VpnRuntimeTaskExit::WorkerFailed
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_noq_datagram_runtime_transfers_fragmented_ipv4_and_ipv6_both_ways() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let (server_endpoint, client_endpoint, server_connection, client_connection) =
            connection_pair().await;
        let server_path = active_data_path(1);
        let client_path = active_data_path(1);
        let server_config = VpnDatagramRuntimeConfig::new(VpnDatagramRole::Server, 1200).unwrap();
        let client_config = VpnDatagramRuntimeConfig::new(VpnDatagramRole::Client, 1200).unwrap();
        let mut server = start_vpn_datagram_runtime(
            server_connection.clone(),
            server_path.clone(),
            server_config,
        )
        .unwrap();
        assert!(matches!(
            start_vpn_datagram_runtime(server_connection.clone(), server_path, server_config,),
            Err(VpnDatagramRuntimeStartError::DataPathAlreadyBound)
        ));
        let mut client =
            start_vpn_datagram_runtime(client_connection.clone(), client_path, client_config)
                .unwrap();

        let uplink = ipv4_packet(3000, "10.77.0.2", "198.51.100.8", 0x71);
        client.outbound().try_send(uplink.clone()).unwrap();
        let received = timeout(Duration::from_secs(3), server.recv_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.packet().as_bytes(), uplink);
        drop(received);

        let downlink = ipv6_packet(1280, "2001:db8::8", "fd77::2", 0x72);
        server.outbound().try_send(downlink.clone()).unwrap();
        let received = timeout(Duration::from_secs(3), client.recv_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.packet().as_bytes(), downlink);
        drop(received);

        let client_metrics = client.metrics_snapshot();
        let server_metrics = server.metrics_snapshot();
        assert!(client_metrics.outbound_fragments_sent >= 3);
        assert_eq!(client_metrics.outbound_packets_sent, 1);
        assert_eq!(server_metrics.outbound_packets_sent, 1);
        assert!(server_metrics.received_datagrams >= 3);
        assert_eq!(server_metrics.completed_inbound_packets, 1);
        assert_eq!(client_metrics.completed_inbound_packets, 1);

        assert_eq!(
            client.shutdown().await.stop_reason,
            VpnDatagramRuntimeStopReason::ShutdownRequested
        );
        assert_eq!(
            server.shutdown().await.stop_reason,
            VpnDatagramRuntimeStopReason::ShutdownRequested
        );
        client_connection.close(0_u8.into(), b"test complete");
        server_connection.close(0_u8.into(), b"test complete");
        client_endpoint.close(0_u8.into(), b"test complete");
        server_endpoint.close(0_u8.into(), b"test complete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stale_data_path_stops_real_datagram_runtime() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let (server_endpoint, client_endpoint, server_connection, client_connection) =
            connection_pair().await;
        let server_path = active_data_path(1);
        let client_path = active_data_path(1);
        let server_config = VpnDatagramRuntimeConfig::new(VpnDatagramRole::Server, 1200)
            .unwrap()
            .with_reassembly_tick(Duration::from_millis(10))
            .unwrap();
        let server = start_vpn_datagram_runtime(
            server_connection.clone(),
            server_path.clone(),
            server_config,
        )
        .unwrap();
        let client = start_vpn_datagram_runtime(
            client_connection.clone(),
            client_path,
            VpnDatagramRuntimeConfig::new(VpnDatagramRole::Client, 1200).unwrap(),
        )
        .unwrap();

        server_path.deactivate();
        let report = timeout(Duration::from_secs(3), server.wait())
            .await
            .unwrap();
        assert_eq!(
            report.stop_reason,
            VpnDatagramRuntimeStopReason::DataPathStale
        );
        assert_eq!(
            client.shutdown().await.stop_reason,
            VpnDatagramRuntimeStopReason::ShutdownRequested
        );
        client_connection.close(0_u8.into(), b"test complete");
        server_connection.close(0_u8.into(), b"test complete");
        client_endpoint.close(0_u8.into(), b"test complete");
        server_endpoint.close(0_u8.into(), b"test complete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_inbound_queue_drops_new_packet_at_packet_cap_without_blocking_quic() {
        let _network_test_guard = crate::LOCAL_NETWORK_TEST_LOCK.lock().await;
        let (server_endpoint, client_endpoint, server_connection, client_connection) =
            connection_pair().await;
        let server_config = VpnDatagramRuntimeConfig::new(VpnDatagramRole::Server, 1200)
            .unwrap()
            .with_queue_limits(
                1,
                VPN_MAX_IP_PACKET_LEN,
                VPN_DEFAULT_PACKET_QUEUE_PACKETS,
                VPN_DEFAULT_PACKET_QUEUE_BYTES,
            )
            .unwrap();
        let mut server = start_vpn_datagram_runtime(
            server_connection.clone(),
            active_data_path(1),
            server_config,
        )
        .unwrap();
        let client = start_vpn_datagram_runtime(
            client_connection.clone(),
            active_data_path(1),
            VpnDatagramRuntimeConfig::new(VpnDatagramRole::Client, 1200).unwrap(),
        )
        .unwrap();

        client
            .outbound()
            .try_send(ipv4_packet(20, "10.77.0.2", "198.51.100.8", 0x81))
            .unwrap();
        client
            .outbound()
            .try_send(ipv4_packet(20, "10.77.0.2", "198.51.100.9", 0x82))
            .unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                if server.metrics_snapshot().completed_inbound_packets >= 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let metrics = server.metrics_snapshot();
        assert_eq!(metrics.completed_inbound_packets, 2);
        assert_eq!(metrics.inbound_queue_dropped_packets, 1);
        assert_eq!(metrics.inbound_queue_current_packets, 1);
        drop(server.recv_packet().await.unwrap());
        assert_eq!(server.metrics_snapshot().inbound_queue_current_packets, 0);

        assert_eq!(
            client.shutdown().await.stop_reason,
            VpnDatagramRuntimeStopReason::ShutdownRequested
        );
        assert_eq!(
            server.shutdown().await.stop_reason,
            VpnDatagramRuntimeStopReason::ShutdownRequested
        );
        client_connection.close(0_u8.into(), b"test complete");
        server_connection.close(0_u8.into(), b"test complete");
        client_endpoint.close(0_u8.into(), b"test complete");
        server_endpoint.close(0_u8.into(), b"test complete");
    }

    async fn connection_pair() -> (Endpoint, Endpoint, Connection, Connection) {
        let (server_config, client_config) = crate::make_configs(
            None,
            PtoRecovery::Disabled,
            MultipathScheduler::NoqDefault,
            QuicCongestion::Cubic,
            false,
            None,
        )
        .unwrap();
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let server_connection = async {
            let incoming = server_endpoint.accept().await.unwrap();
            incoming.await.unwrap()
        };
        let (server_connection, client_connection) =
            tokio::join!(server_connection, async { connecting.await.unwrap() });
        server_connection.handshake_confirmed().await.unwrap();
        client_connection.handshake_confirmed().await.unwrap();
        assert!(server_connection.max_datagram_size().unwrap() >= VPN_MIN_QUIC_DATAGRAM_LEN);
        assert!(client_connection.max_datagram_size().unwrap() >= VPN_MIN_QUIC_DATAGRAM_LEN);
        (
            server_endpoint,
            client_endpoint,
            server_connection,
            client_connection,
        )
    }

    fn active_data_path(generation: u64) -> VpnDataPathHandle {
        let identity = VpnIdentity::new(
            "client-a",
            vec![VpnCertificateFingerprint::from_sha256([1; 32])],
            true,
            Some("10.77.0.2".parse().unwrap()),
            Some("fd77::2".parse().unwrap()),
            vec![
                VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
            ],
            VpnIdentityLimits::default(),
        )
        .unwrap();
        let quota_metrics = VpnQuotaMetrics::default();
        let policy_metrics = VpnDataPolicyMetrics::default();
        let budget = VpnGlobalReassemblyBudget::new(
            crate::VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES,
            crate::VPN_DEFAULT_GLOBAL_INFLIGHT_PACKETS,
            quota_metrics.clone(),
        )
        .unwrap();
        let rate_limiter = Arc::new(VpnIdentityRateLimiter::new(
            identity.limits(),
            Instant::now(),
            quota_metrics.clone(),
        ));
        let path = VpnDataPathHandle::new_inactive(
            identity,
            generation,
            rate_limiter,
            budget,
            quota_metrics,
            policy_metrics,
        )
        .unwrap();
        path.activate();
        path
    }

    fn ipv4_packet(len: usize, source: &str, destination: &str, fill: u8) -> Vec<u8> {
        let source = source.parse::<Ipv4Addr>().unwrap().octets();
        let destination = destination.parse::<Ipv4Addr>().unwrap().octets();
        let mut packet = vec![fill; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv6_packet(len: usize, source: &str, destination: &str, fill: u8) -> Vec<u8> {
        let source = source.parse::<Ipv6Addr>().unwrap().octets();
        let destination = destination.parse::<Ipv6Addr>().unwrap().octets();
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

use std::{
    error::Error,
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use noq::{
    ClientConfig, Connection, ConnectionError, Endpoint, FourTuple, Path, PathError, PathId,
    PathStats, PathStatus, ServerConfig, StreamId, TransportConfig,
    congestion::{Bbr3Config, CubicConfig},
    rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};

mod b_ingress;
mod hysteria;
mod proxy;
mod proxy_observe;
mod proxy_soak;
mod realtime;
mod realtime_controller;
mod realtime_v3;
mod scheduler;
mod vpn;
mod vpn_active_session;
mod vpn_control;
mod vpn_data_path;
mod vpn_data_policy;
mod vpn_datagram_runtime;
mod vpn_identity;
mod vpn_identity_config;
mod vpn_quota;
mod vpn_session;
mod vpn_tls;
pub use b_ingress::{
    BIngressSmokeReport, run_b_ingress_observability_controller,
    run_b_ingress_observability_receiver, run_b_ingress_shaper_calibration,
};
pub use hysteria::{
    HysteriaCongestion, HysteriaFailoverConfig, HysteriaFailoverReport, HysteriaLine,
    HysteriaRealtimeConfig, HysteriaRealtimeReport, HysteriaThroughputConfig,
    HysteriaThroughputReport, run_hysteria_failover, run_hysteria_realtime,
    run_hysteria_throughput, verify_hysteria_binary,
};
pub use proxy::{
    PROXY_EVENT_SCHEMA, ProxyClientConfig, ProxyMetricsSnapshot, ProxyRuntime, ProxyServerConfig,
    run_proxy_client, run_proxy_server, start_proxy_client, start_proxy_server,
};
pub use proxy_observe::{
    MAX_PROXY_EVENT_LINE_BYTES, PROXY_OBSERVATION_SCHEMA, ProxyHealthPolicy, ProxyHealthReport,
    ProxyObservation, ProxyRoleObservation, analyze_proxy_jsonl,
};
pub use proxy_soak::{
    PROXY_PUBLIC_SOAK_REPORT_SCHEMA, PROXY_SOAK_REPORT_SCHEMA, ProxyPublicSoakConfig,
    ProxyPublicSoakReport, ProxyPublicSoakStopReason, ProxySoakConfig, ProxySoakReport,
    run_proxy_public_soak, run_proxy_public_soak_with_checkpoints,
    run_proxy_public_soak_with_shutdown, run_proxy_soak, run_proxy_soak_echo_server,
};
pub use realtime::{
    RealtimeDatagramConfig, RealtimeDatagramReport, run_batched_duplication_realtime,
};
pub use realtime_controller::{
    RealtimeControllerGateConfig, RealtimeControllerGateReport, run_realtime_controller_gate,
};
pub use realtime_v3::{
    RealtimeV3WireConfig, RealtimeV3WireReport, RealtimeV4Config, RealtimeV4Report,
    RealtimeV12Config, RealtimeV12Report, run_v3_wire_latency_probe, run_v4_bbr3_coding_realtime,
    run_v12_bbr3_two_of_three_realtime,
};
pub use scheduler::MultipathScheduler;
pub use vpn::{
    VPN_DEFAULT_FRAGMENT_TIMEOUT, VPN_DEFAULT_MAX_INFLIGHT_PACKETS,
    VPN_DEFAULT_MAX_REASSEMBLY_BYTES, VPN_IP_DATAGRAM_HEADER_LEN, VPN_IP_DATAGRAM_MAGIC,
    VPN_MAX_FRAGMENTS_PER_PACKET, VPN_MAX_IP_DATAGRAM_LEN, VPN_MAX_IP_PACKET_LEN,
    VPN_MIN_QUIC_DATAGRAM_LEN, VpnFragment, VpnIpPacketMeta, VpnPacketError, VpnReassembler,
    VpnReassemblyLimits, VpnReassemblyStats, decode_vpn_ip_fragment, encode_vpn_ip_fragments,
    inspect_vpn_ip_packet,
};
pub use vpn_active_session::{
    VPN_CLOSE_COMMIT_REJECTED, VPN_CLOSE_IDENTITY_REVOKED, VPN_CLOSE_POLICY_CHANGED,
    VPN_CLOSE_SERVER_SHUTDOWN, VPN_CLOSE_SESSION_REPLACED, VpnActiveSessionSnapshot,
    VpnCommittedSession, VpnCoordinatorReloadReport, VpnManagedActiveSession,
    VpnManagedServerOutcome, VpnManagedSessionError, VpnSessionCommitError, VpnSessionCommitReport,
    VpnSessionCoordinator, VpnSessionCoordinatorMetrics, VpnSessionReconcileReport,
    vpn_server_managed_control_handshake,
};
pub use vpn_control::{
    VPN_ALPN, VPN_CAP_FRAGMENTATION, VPN_CAP_IPV4, VPN_CAP_IPV6, VPN_CAP_MULTIPATH_REQUIRED,
    VPN_CONTROL_FORMAT_VERSION, VPN_CONTROL_HEADER_LEN, VPN_CONTROL_MAGIC,
    VPN_CONTROL_MAX_MESSAGE_LEN, VPN_KNOWN_CAPABILITIES, VPN_REQUIRED_CAPABILITIES,
    VPN_WIRE_VERSION_V1, VpnAccept, VpnControlError, VpnControlMessage, VpnHello, VpnReject,
    VpnRejectReason, decode_vpn_control_message, encode_vpn_control_message,
    select_vpn_wire_version,
};
#[cfg(feature = "fuzzing")]
pub use vpn_data_path::fuzz_vpn_data_path;
pub use vpn_data_path::{VpnDataPacket, VpnDataPathError, VpnDataPathHandle, VpnDataPathSnapshot};
pub use vpn_data_policy::{
    VpnDataPolicyError, VpnDataPolicyMetricsSnapshot, validate_vpn_ip_packet_policy,
};
pub use vpn_datagram_runtime::{
    VPN_DEFAULT_PACKET_QUEUE_BYTES, VPN_DEFAULT_PACKET_QUEUE_PACKETS, VPN_DEFAULT_REASSEMBLY_TICK,
    VPN_MAX_PACKET_QUEUE_BYTES, VPN_MAX_PACKET_QUEUE_PACKETS, VPN_MAX_REASSEMBLY_TICK,
    VpnDatagramRole, VpnDatagramRuntime, VpnDatagramRuntimeConfig, VpnDatagramRuntimeConfigError,
    VpnDatagramRuntimeMetrics, VpnDatagramRuntimeMetricsSnapshot, VpnDatagramRuntimeReport,
    VpnDatagramRuntimeStartError, VpnDatagramRuntimeStopReason, VpnPacketQueueError,
    VpnPacketSender, VpnQueuedPacket, start_vpn_datagram_runtime,
};
pub use vpn_identity::{
    VPN_MAX_BYTES_PER_SECOND, VPN_MAX_CLIENT_ID_LEN, VPN_MAX_CONNECTIONS_PER_IDENTITY,
    VPN_MAX_DESTINATION_NETWORKS_PER_IDENTITY, VPN_MAX_FINGERPRINTS_PER_IDENTITY,
    VPN_MAX_IDENTITIES, VPN_MAX_PACKETS_PER_SECOND, VPN_SHA256_FINGERPRINT_LEN,
    VpnCertificateFingerprint, VpnIdentity, VpnIdentityAuthorizationError, VpnIdentityError,
    VpnIdentityLimits, VpnIdentityRegistry, VpnIpNetwork,
};
pub use vpn_identity_config::{
    SharedVpnIdentityRegistry, VPN_IDENTITY_CONFIG_MAX_BYTES, VPN_IDENTITY_CONFIG_VERSION,
    VpnIdentityConfigError, VpnIdentityReloadReport, load_vpn_identity_registry,
    parse_vpn_identity_registry_json,
};
pub use vpn_quota::{
    VPN_DEFAULT_GLOBAL_INFLIGHT_PACKETS, VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES,
    VPN_MAX_GLOBAL_INFLIGHT_PACKETS, VPN_MAX_GLOBAL_REASSEMBLY_BYTES, VpnPacketDirection,
    VpnQuotaMetricsSnapshot, VpnQuotaRejection,
};
pub use vpn_session::{
    VPN_CLOSE_CONTROL_FAILED, VPN_CLOSE_CONTROL_REJECTED, VPN_DEFAULT_CONTROL_HANDSHAKE_TIMEOUT,
    VPN_MAX_CONTROL_HANDSHAKE_TIMEOUT, VpnNegotiatedSession, VpnServerControlOutcome,
    VpnServerNegotiationConfig, VpnSessionError, VpnSessionGeneration, negotiate_vpn_hello,
    vpn_client_control_handshake, vpn_server_control_handshake,
};
pub use vpn_tls::{
    build_vpn_client_tls_config, build_vpn_server_tls_config, verify_vpn_alpn,
    vpn_certificate_fingerprint, vpn_certificate_sha256, vpn_peer_certificate_fingerprint,
    vpn_peer_certificate_sha256,
};

pub type LabError = Box<dyn Error + Send + Sync + 'static>;
pub type LabResult<T> = Result<T, LabError>;

// Real local MPQUIC tests share loopback sockets, timers, and several Tokio runtimes. Running
// them concurrently can stall a 10 ms realtime generator beyond its deliberately narrow wire
// timestamp range, which tests host scheduling rather than transport behavior.
#[cfg(test)]
pub(crate) static LOCAL_NETWORK_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicCongestion {
    Cubic,
    Bbr3,
}

impl QuicCongestion {
    pub const ALL: [Self; 2] = [Self::Cubic, Self::Bbr3];

    pub const fn description(self) -> &'static str {
        match self {
            Self::Cubic => "Cubic",
            Self::Bbr3 => "BBR3",
        }
    }
}

const MAGIC: &[u8; 4] = b"FWL1";
const FAILOVER_MAGIC: &[u8; 4] = b"FWP1";
const FAILOVER_PROGRESS: &[u8; 4] = b"FWP+";
const SUSTAINED_FAILOVER_MAGIC: &[u8; 4] = b"FWA1";
const SUSTAINED_FAILOVER_READY: &[u8; 4] = b"FWA+";
const SUSTAINED_FAILOVER_OK: &[u8; 4] = b"FWA=";
const SUSTAINED_FAILOVER_GO: u8 = 1;
const SUSTAINED_FAILOVER_HEADER_SIZE: usize = 20;
const SUSTAINED_RECORD_HEADER_SIZE: usize = 16;
const SUSTAINED_RECORD_END: u64 = u64::MAX;
const DATAGRAM_MAGIC: &[u8; 4] = b"FWDG";
const DATAGRAM_PROBE_SIZE: usize = 8;
const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;
const MAX_FRAME_SIZE: usize = MAX_PAYLOAD_SIZE + 8;
const MAX_DATAGRAM_PROBES: usize = 2_000;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const FAILOVER_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(8);
const SUSTAINED_FAILOVER_GRACE: Duration = Duration::from_secs(60);
const NETWORK_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
const DATAGRAM_SEND_INTERVAL: Duration = Duration::from_millis(5);
const DATAGRAM_RECEIVE_GRACE: Duration = Duration::from_millis(1_500);
const MAX_SUSTAINED_WARMUP: Duration = Duration::from_secs(30);
const MAX_SUSTAINED_MEASUREMENT: Duration = Duration::from_secs(120);
const DECLARED_EPOCH_COHORT_DURATION: Duration = Duration::from_millis(250);
const DECLARED_EPOCH_SETTLE_WAIT: Duration = Duration::from_millis(1_500);
const LINE_ONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LINE_TWO_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

#[derive(Debug)]
pub struct BasicLabReport {
    pub multipath_negotiated: bool,
    pub primary_carried_data: bool,
    pub primary_bytes_sent: u64,
    pub secondary_carried_data: bool,
    pub secondary_bytes_sent: u64,
    pub failover_transfer_ok: bool,
    pub datagram_echoes: usize,
    pub datagram_p95: Duration,
    pub path_limit_rejected: bool,
    pub malformed_frame_rejected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    LineOneOnly,
    LineTwoOnly,
    MultipathAvailable,
}

impl PathMode {
    pub fn description(self) -> &'static str {
        match self {
            Self::LineOneOnly => "仅线路一",
            Self::LineTwoOnly => "仅线路二",
            Self::MultipathAvailable => "MPQUIC 双路径",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PtoRecovery {
    #[default]
    Disabled,
    CrossPathHedge,
    CrossPathHedgeAndAbandon,
    CrossPathRecovery,
    CrossPathRecoveryWithAckEscape,
    CrossPathRecoveryWithFeedbackHandoff,
    CrossPathRecoveryWithFeedbackSnapshot,
    CrossPathRecoveryWithFeedbackProbe,
    CrossPathRecoveryWithFeedbackEvidence,
    CrossPathRecoveryWithFeedbackEvidenceAndGapRescue,
    CrossPathRecoveryWithFeedbackEvidenceAndGapWatch,
    CrossPathRecoveryWithApplicationProgressWatch,
    CrossPathRecoveryWithApplicationProgressDeadline,
    CrossPathRecoveryWithVersionAwareDeadline,
    CrossPathRecoveryWithStreamProgress,
    CrossPathRecoveryWithMultiFlightBudget,
    CrossPathRecoveryWithStableMultiFlightBudget,
    CrossPathRecoveryWithDeliveryGapWatch,
    CrossPathRecoveryWithAlternativeStability,
    CrossPathRecoveryWithStreamProgressSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FailoverDirection {
    ClientToServer = 0,
    ServerToClient = 1,
}

impl FailoverDirection {
    pub const ALL: [Self; 2] = [Self::ClientToServer, Self::ServerToClient];

    pub fn description(self) -> &'static str {
        match self {
            Self::ClientToServer => "正向（客户端到服务端）",
            Self::ServerToClient => "反向（服务端到客户端）",
        }
    }
}

impl TryFrom<u8> for FailoverDirection {
    type Error = LabError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ClientToServer),
            1 => Ok(Self::ServerToClient),
            _ => Err(other_error("持续换网实验的传输方向不合法")),
        }
    }
}

impl PtoRecovery {
    pub const CANDIDATES: [Self; 2] = [Self::Disabled, Self::CrossPathHedge];

    pub fn description(self) -> &'static str {
        match self {
            Self::Disabled => "NoQ 默认恢复",
            Self::CrossPathHedge => "FlowWeave PTO 跨路径对冲",
            Self::CrossPathHedgeAndAbandon => "FlowWeave PTO + abandoned 即时对冲",
            Self::CrossPathRecovery => "FlowWeave PTO + abandoned + ACK 进展跨路径恢复",
            Self::CrossPathRecoveryWithAckEscape => "FlowWeave ACK 进展恢复 + 有界跨路径 ACK 逃生",
            Self::CrossPathRecoveryWithFeedbackHandoff => "FlowWeave ACK 逃生 + 关键反馈路径交接",
            Self::CrossPathRecoveryWithFeedbackSnapshot => "FlowWeave 反馈交接 + 在途流控快照",
            Self::CrossPathRecoveryWithFeedbackProbe => {
                "FlowWeave 在途流控快照 + 预恢复单帧反馈探针"
            }
            Self::CrossPathRecoveryWithFeedbackEvidence => {
                "FlowWeave 反馈探针 + 证据驱动选择性恢复"
            }
            Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue => {
                "FlowWeave 证据恢复 + 有界关键缺口探针"
            }
            Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch => {
                "FlowWeave 证据恢复 + 稳定缺口计时救援"
            }
            Self::CrossPathRecoveryWithApplicationProgressWatch => {
                "FlowWeave 应用义务时钟 + 阻塞信用逃生"
            }
            Self::CrossPathRecoveryWithApplicationProgressDeadline => {
                "FlowWeave 应用义务时钟 + 服务截止预算"
            }
            Self::CrossPathRecoveryWithVersionAwareDeadline => {
                "FlowWeave 应用义务时钟 + 版本感知服务预算"
            }
            Self::CrossPathRecoveryWithStreamProgress => {
                "FlowWeave 版本感知服务预算 + 数据级流进度"
            }
            Self::CrossPathRecoveryWithMultiFlightBudget => {
                "FlowWeave 数据级流进度 + 三航次服务预算"
            }
            Self::CrossPathRecoveryWithStableMultiFlightBudget => {
                "FlowWeave 三航次服务预算 + 认证反馈稳定门控"
            }
            Self::CrossPathRecoveryWithDeliveryGapWatch => {
                "FlowWeave 认证反馈稳定门控 + 重传交付缺口监视"
            }
            Self::CrossPathRecoveryWithAlternativeStability => {
                "FlowWeave 重传交付缺口监视 + 替代目标持续领先门控"
            }
            Self::CrossPathRecoveryWithStreamProgressSnapshot => {
                "FlowWeave 替代目标持续领先门控 + 在途流进度快照"
            }
        }
    }

    fn pto_reinjection_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathHedge
                | Self::CrossPathHedgeAndAbandon
                | Self::CrossPathRecovery
                | Self::CrossPathRecoveryWithAckEscape
                | Self::CrossPathRecoveryWithFeedbackHandoff
                | Self::CrossPathRecoveryWithFeedbackSnapshot
                | Self::CrossPathRecoveryWithFeedbackProbe
                | Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn abandon_reinjection_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathHedgeAndAbandon
                | Self::CrossPathRecovery
                | Self::CrossPathRecoveryWithAckEscape
                | Self::CrossPathRecoveryWithFeedbackHandoff
                | Self::CrossPathRecoveryWithFeedbackSnapshot
                | Self::CrossPathRecoveryWithFeedbackProbe
                | Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn ack_progress_reinjection_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecovery
                | Self::CrossPathRecoveryWithAckEscape
                | Self::CrossPathRecoveryWithFeedbackHandoff
                | Self::CrossPathRecoveryWithFeedbackSnapshot
                | Self::CrossPathRecoveryWithFeedbackProbe
                | Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn ack_escape_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithAckEscape
                | Self::CrossPathRecoveryWithFeedbackHandoff
                | Self::CrossPathRecoveryWithFeedbackSnapshot
                | Self::CrossPathRecoveryWithFeedbackProbe
                | Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn feedback_handoff_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithFeedbackHandoff
                | Self::CrossPathRecoveryWithFeedbackSnapshot
                | Self::CrossPathRecoveryWithFeedbackProbe
                | Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn feedback_credit_snapshot_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithFeedbackSnapshot
                | Self::CrossPathRecoveryWithFeedbackProbe
                | Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn feedback_probe_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithFeedbackProbe
                | Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn feedback_evidence_reinjection_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithFeedbackEvidence
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                | Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn stream_gap_rescue_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
        )
    }

    fn stream_gap_watch_rescue_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch
                | Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn ack_progress_stream_obligation_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn blocked_credit_handoff_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithApplicationProgressWatch
                | Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn ack_progress_service_deadline(self) -> Option<Duration> {
        matches!(
            self,
            Self::CrossPathRecoveryWithApplicationProgressDeadline
                | Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
        .then_some(Duration::from_millis(1_000))
    }

    fn ack_progress_fresh_alternative_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithVersionAwareDeadline
                | Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn stream_progress_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithStreamProgress
                | Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn ack_progress_service_recovery_flights(self) -> u32 {
        if matches!(
            self,
            Self::CrossPathRecoveryWithMultiFlightBudget
                | Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        ) {
            3
        } else {
            1
        }
    }

    fn ack_progress_feedback_stability_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithStableMultiFlightBudget
                | Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn stream_gap_delivery_watch_rescue_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithDeliveryGapWatch
                | Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn ack_progress_alternative_stability_enabled(self) -> bool {
        matches!(
            self,
            Self::CrossPathRecoveryWithAlternativeStability
                | Self::CrossPathRecoveryWithStreamProgressSnapshot
        )
    }

    fn feedback_stream_progress_snapshot_enabled(self) -> bool {
        matches!(self, Self::CrossPathRecoveryWithStreamProgressSnapshot)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkBenchmarkConfig {
    pub mode: PathMode,
    pub scheduler: MultipathScheduler,
    pub congestion: QuicCongestion,
    pub pto_recovery: PtoRecovery,
    pub transfer_size: usize,
    pub datagram_count: usize,
}

impl NetworkBenchmarkConfig {
    pub fn new(
        mode: PathMode,
        scheduler: MultipathScheduler,
        transfer_size: usize,
        datagram_count: usize,
    ) -> Self {
        Self {
            mode,
            scheduler,
            congestion: QuicCongestion::Cubic,
            pto_recovery: PtoRecovery::Disabled,
            transfer_size,
            datagram_count,
        }
    }

    pub fn with_pto_recovery(mut self, pto_recovery: PtoRecovery) -> Self {
        self.pto_recovery = pto_recovery;
        self
    }

    pub fn with_congestion(mut self, congestion: QuicCongestion) -> Self {
        self.congestion = congestion;
        self
    }

    fn validate(self) -> LabResult<()> {
        if self.transfer_size == 0 {
            return Err(other_error("网络实验的传输大小不能为 0"));
        }
        if self.transfer_size > MAX_PAYLOAD_SIZE {
            return Err(other_error(format!(
                "网络实验的传输大小不能超过 {MAX_PAYLOAD_SIZE} 字节"
            )));
        }
        if self.datagram_count > MAX_DATAGRAM_PROBES {
            return Err(other_error(format!(
                "Datagram 探针数量不能超过 {MAX_DATAGRAM_PROBES}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SustainedBenchmarkConfig {
    pub mode: PathMode,
    pub scheduler: MultipathScheduler,
    pub congestion: QuicCongestion,
    pub pto_recovery: PtoRecovery,
    pub warmup_duration: Duration,
    pub measurement_duration: Duration,
    pub chunk_size: usize,
}

impl SustainedBenchmarkConfig {
    pub fn new(
        mode: PathMode,
        scheduler: MultipathScheduler,
        warmup_duration: Duration,
        measurement_duration: Duration,
        chunk_size: usize,
    ) -> Self {
        Self {
            mode,
            scheduler,
            congestion: QuicCongestion::Cubic,
            pto_recovery: PtoRecovery::Disabled,
            warmup_duration,
            measurement_duration,
            chunk_size,
        }
    }

    pub fn with_pto_recovery(mut self, pto_recovery: PtoRecovery) -> Self {
        self.pto_recovery = pto_recovery;
        self
    }

    pub fn with_congestion(mut self, congestion: QuicCongestion) -> Self {
        self.congestion = congestion;
        self
    }

    fn validate(self) -> LabResult<()> {
        if self.warmup_duration.is_zero() || self.warmup_duration > MAX_SUSTAINED_WARMUP {
            return Err(other_error(format!(
                "持续实验预热时间必须大于 0 且不超过 {} 秒",
                MAX_SUSTAINED_WARMUP.as_secs()
            )));
        }
        if self.measurement_duration.is_zero()
            || self.measurement_duration > MAX_SUSTAINED_MEASUREMENT
        {
            return Err(other_error(format!(
                "持续实验计时时间必须大于 0 且不超过 {} 秒",
                MAX_SUSTAINED_MEASUREMENT.as_secs()
            )));
        }
        if self.chunk_size == 0 || self.chunk_size > MAX_PAYLOAD_SIZE {
            return Err(other_error(format!(
                "持续实验单块大小必须大于 0 且不超过 {MAX_PAYLOAD_SIZE} 字节"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ContinuousBenchmarkConfig {
    pub mode: PathMode,
    pub scheduler: MultipathScheduler,
    pub congestion: QuicCongestion,
    pub pto_recovery: PtoRecovery,
    pub warmup_duration: Duration,
    pub measurement_duration: Duration,
    pub chunk_size: usize,
}

impl ContinuousBenchmarkConfig {
    pub fn new(
        mode: PathMode,
        scheduler: MultipathScheduler,
        warmup_duration: Duration,
        measurement_duration: Duration,
        chunk_size: usize,
    ) -> Self {
        Self {
            mode,
            scheduler,
            congestion: QuicCongestion::Cubic,
            pto_recovery: PtoRecovery::Disabled,
            warmup_duration,
            measurement_duration,
            chunk_size,
        }
    }

    pub fn with_pto_recovery(mut self, pto_recovery: PtoRecovery) -> Self {
        self.pto_recovery = pto_recovery;
        self
    }

    pub fn with_congestion(mut self, congestion: QuicCongestion) -> Self {
        self.congestion = congestion;
        self
    }

    fn validate(self) -> LabResult<()> {
        SustainedBenchmarkConfig::new(
            self.mode,
            self.scheduler,
            self.warmup_duration,
            self.measurement_duration,
            self.chunk_size,
        )
        .with_congestion(self.congestion)
        .with_pto_recovery(self.pto_recovery)
        .validate()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DeclaredBackloggedEpochConfig {
    pub mode: PathMode,
    pub warmup_duration: Duration,
    pub measurement_duration: Duration,
    pub chunk_size: usize,
}

impl DeclaredBackloggedEpochConfig {
    pub fn new(
        mode: PathMode,
        warmup_duration: Duration,
        measurement_duration: Duration,
        chunk_size: usize,
    ) -> Self {
        Self {
            mode,
            warmup_duration,
            measurement_duration,
            chunk_size,
        }
    }

    fn validate(self) -> LabResult<()> {
        if self.mode == PathMode::MultipathAvailable {
            return Err(other_error(
                "declared backlogged epoch 门控只允许独立测量一条线路",
            ));
        }
        SustainedBenchmarkConfig::new(
            self.mode,
            MultipathScheduler::NoqDefault,
            self.warmup_duration,
            self.measurement_duration,
            self.chunk_size,
        )
        .validate()?;
        if !self
            .measurement_duration
            .as_nanos()
            .is_multiple_of(DECLARED_EPOCH_COHORT_DURATION.as_nanos())
        {
            return Err(other_error(
                "declared backlogged epoch 时长必须是 250 ms 的整数倍",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SustainedFailoverConfig {
    pub scheduler: MultipathScheduler,
    pub pto_recovery: PtoRecovery,
    pub direction: FailoverDirection,
    pub total_duration: Duration,
    pub failure_after: Duration,
    pub chunk_size: usize,
    pub seed: u8,
    pub collect_stream_state_diagnostics: bool,
    pub receiver_anchored_response_timeout: bool,
}

impl SustainedFailoverConfig {
    pub fn new(
        scheduler: MultipathScheduler,
        pto_recovery: PtoRecovery,
        direction: FailoverDirection,
        total_duration: Duration,
        failure_after: Duration,
        chunk_size: usize,
        seed: u8,
    ) -> Self {
        Self {
            scheduler,
            pto_recovery,
            direction,
            total_duration,
            failure_after,
            chunk_size,
            seed,
            collect_stream_state_diagnostics: false,
            receiver_anchored_response_timeout: false,
        }
    }

    pub fn with_stream_state_diagnostics(mut self) -> Self {
        self.collect_stream_state_diagnostics = true;
        self
    }

    /// Starts the final-response timeout only after the receiver reports that all forward data
    /// has arrived, so forward drain time cannot consume the reverse-path PTO budget.
    pub fn with_receiver_anchored_response_timeout(mut self) -> Self {
        self.receiver_anchored_response_timeout = true;
        self
    }

    fn validate(self) -> LabResult<()> {
        if self.total_duration.is_zero() || self.total_duration > MAX_SUSTAINED_MEASUREMENT {
            return Err(other_error(format!(
                "正式换网实验总时长必须在 0 到 {} 秒之间",
                MAX_SUSTAINED_MEASUREMENT.as_secs()
            )));
        }
        if self.failure_after.is_zero() || self.failure_after >= self.total_duration {
            return Err(other_error("黑洞时刻必须晚于开始且早于实验结束"));
        }
        if self.chunk_size < SUSTAINED_RECORD_HEADER_SIZE || self.chunk_size > MAX_PAYLOAD_SIZE {
            return Err(other_error(format!(
                "正式换网实验记录载荷必须在 {SUSTAINED_RECORD_HEADER_SIZE} 到 {MAX_PAYLOAD_SIZE} 字节之间"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum BenchmarkWorkload {
    Fixed {
        transfer_size: usize,
        datagram_count: usize,
    },
    Sustained {
        warmup_duration: Duration,
        measurement_duration: Duration,
        chunk_size: usize,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PathMeasurement {
    pub udp_bytes_sent: u64,
    pub udp_datagrams_sent: u64,
    pub fresh_stream_bytes_sent: u64,
    pub retransmitted_stream_bytes_sent: u64,
    pub declared_epoch_cohorts: u64,
    pub declared_epoch_settled_cohorts: u64,
    pub declared_epoch_empty_cohorts: u64,
    pub declared_epoch_fresh_bytes: u64,
    pub declared_epoch_acked_bytes: u64,
    pub declared_epoch_late_acked_bytes: u64,
    pub declared_epoch_bytes_missing_at_drain: u64,
    pub declared_epoch_pending_cohorts: u64,
    pub declared_epoch_pending_origin_bytes: u64,
    pub declared_epoch_tracked_origin_bytes: u64,
    pub path_acks_same_path: u64,
    pub path_acks_cross_path: u64,
    pub path_ack_escape_requests: u64,
    pub path_ack_escape_acks: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub loss_detection_timeouts: u64,
    pub pto_timeouts: u64,
    pub pto_recovery_attempts: u64,
    pub pto_recovery_empty_attempts: u64,
    pub last_pto_recovery_unacked_bytes: u64,
    pub last_pto_recovery_stream_frames: u64,
    pub pto_hedges: u64,
    pub pto_hedge_bytes: u64,
    pub path_abandon_recovery_attempts: u64,
    pub path_abandon_recovery_empty_attempts: u64,
    pub path_abandon_reinjections: u64,
    pub path_abandon_reinjected_bytes: u64,
    pub ack_progress_recovery_timeouts: u64,
    pub ack_progress_recovery_attempts: u64,
    pub ack_progress_recovery_empty_attempts: u64,
    pub ack_progress_reinjections: u64,
    pub ack_progress_reinjected_bytes: u64,
    pub ack_progress_feedback_probe_timeouts: u64,
    pub ack_progress_feedback_probes: u64,
    pub ack_progress_feedback_probe_bytes: u64,
    pub stream_progress_updates: u64,
    pub stream_progress_acked_bytes: u64,
    pub blocked_credit_handoffs: u64,
    pub blocked_credit_max_data_requeues: u64,
    pub blocked_credit_max_stream_data_requeues: u64,
    pub stream_gap_rescue_probes: u64,
    pub stream_gap_rescue_bytes: u64,
    pub ack_eliciting_packet_number_advance: u64,
    pub final_rtt: Duration,
    pub final_pto: Duration,
    pub final_cwnd: u64,
    pub final_bytes_in_flight: u64,
    pub final_ack_eliciting_packets_in_flight: u64,
    pub final_tracked_sent_packets: u64,
    pub final_tracked_ack_eliciting_packets: u64,
    pub final_loss_detection_timer_armed: bool,
    pub final_ack_progress_recovery_timer_armed: bool,
}

impl PathMeasurement {
    pub fn declared_epoch_service_rate_mbps(&self) -> f64 {
        if self.declared_epoch_cohorts == 0 {
            return 0.0;
        }
        let observed = DECLARED_EPOCH_COHORT_DURATION
            .saturating_mul(u32::try_from(self.declared_epoch_cohorts).unwrap_or(u32::MAX))
            .as_secs_f64();
        self.declared_epoch_acked_bytes as f64 * 8.0 / observed / 1_000_000.0
    }

    pub fn declared_epoch_ack_coverage_ratio(&self) -> f64 {
        if self.declared_epoch_fresh_bytes == 0 {
            return 0.0;
        }
        self.declared_epoch_acked_bytes as f64 / self.declared_epoch_fresh_bytes as f64
    }

    pub fn declared_epoch_late_ack_ratio(&self) -> f64 {
        if self.declared_epoch_fresh_bytes == 0 {
            return 0.0;
        }
        self.declared_epoch_late_acked_bytes as f64 / self.declared_epoch_fresh_bytes as f64
    }
}

#[derive(Debug, Clone)]
pub struct DeclaredBackloggedEpochReport {
    pub mode: PathMode,
    pub multipath_negotiated: bool,
    pub data_intact: bool,
    pub writer_alive_at_epoch_start: bool,
    pub writer_alive_at_epoch_end: bool,
    pub transfer_size: usize,
    pub transfer_duration: Duration,
    pub throughput_mbps: f64,
    pub path: PathMeasurement,
    pub total_udp_bytes_sent: u64,
    pub cpu_time: Duration,
    pub cpu_utilization_percent: f64,
    pub peak_rss_kib: u64,
    pub path_open: bool,
}

#[derive(Debug, Clone)]
pub struct DatagramMeasurement {
    pub sent: usize,
    pub echoed: usize,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub p99: Option<Duration>,
}

impl DatagramMeasurement {
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        ((self.sent - self.echoed) as f64 / self.sent as f64) * 100.0
    }
}

#[derive(Debug, Clone)]
pub struct NetworkBenchmarkReport {
    pub mode: PathMode,
    pub scheduler: MultipathScheduler,
    pub congestion: QuicCongestion,
    pub pto_recovery: PtoRecovery,
    pub multipath_negotiated: bool,
    pub transfer_size: usize,
    pub transfer_duration: Duration,
    pub throughput_mbps: f64,
    pub datagrams: DatagramMeasurement,
    pub line_one: PathMeasurement,
    pub line_two: PathMeasurement,
    pub total_udp_bytes_sent: u64,
    pub extra_udp_bytes_sent: u64,
    pub cpu_time: Duration,
    pub cpu_utilization_percent: f64,
    pub peak_rss_kib: u64,
    pub all_configured_paths_open: bool,
    pub any_configured_path_open: bool,
}

#[derive(Debug, Clone)]
pub struct ContinuousBenchmarkReport {
    pub mode: PathMode,
    pub scheduler: MultipathScheduler,
    pub congestion: QuicCongestion,
    pub pto_recovery: PtoRecovery,
    pub multipath_negotiated: bool,
    pub data_intact: bool,
    pub writer_alive_at_measurement_start: bool,
    pub writer_alive_at_measurement_end: bool,
    pub transfer_size: usize,
    pub transfer_duration: Duration,
    pub throughput_mbps: f64,
    pub records_received_in_window: u64,
    pub total_records_received: u64,
    pub total_application_bytes_received: u64,
    pub line_one: PathMeasurement,
    pub line_two: PathMeasurement,
    pub total_udp_bytes_sent: u64,
    pub extra_udp_bytes_sent: u64,
    pub cpu_time: Duration,
    pub cpu_utilization_percent: f64,
    pub peak_rss_kib: u64,
    pub all_configured_paths_open: bool,
    pub any_configured_path_open: bool,
}

impl ContinuousBenchmarkReport {
    pub fn both_paths_carried_minimum_effective_share(&self) -> bool {
        if self.mode != PathMode::MultipathAvailable {
            return false;
        }
        let total = self
            .line_one
            .fresh_stream_bytes_sent
            .saturating_add(self.line_two.fresh_stream_bytes_sent);
        total != 0
            && self.line_one.fresh_stream_bytes_sent.saturating_mul(10) >= total
            && self.line_two.fresh_stream_bytes_sent.saturating_mul(10) >= total
    }
}

impl NetworkBenchmarkReport {
    pub fn both_paths_carried_minimum_effective_share(&self) -> bool {
        if self.mode != PathMode::MultipathAvailable {
            return false;
        }
        let total = self
            .line_one
            .fresh_stream_bytes_sent
            .saturating_add(self.line_two.fresh_stream_bytes_sent);
        total != 0
            && self.line_one.fresh_stream_bytes_sent.saturating_mul(10) >= total
            && self.line_two.fresh_stream_bytes_sent.saturating_mul(10) >= total
    }
}

#[derive(Debug, Clone)]
pub struct FailoverReport {
    pub scheduler: MultipathScheduler,
    pub pto_recovery: PtoRecovery,
    pub recovered: bool,
    pub recovery_time: Option<Duration>,
    pub completion_time: Option<Duration>,
    pub failure_reason: Option<String>,
    pub configured_path_idle_timeout: Duration,
    pub primary_bytes_after_blackhole: u64,
    pub secondary_bytes_after_blackhole: u64,
    pub primary_lost_packets: u64,
    pub secondary_lost_packets: u64,
    pub primary_pto_hedges: u64,
    pub secondary_pto_hedges: u64,
    pub primary_pto_hedge_bytes: u64,
    pub secondary_pto_hedge_bytes: u64,
    pub primary_path_open: bool,
    pub secondary_path_open: bool,
}

#[derive(Debug, Clone)]
pub struct SustainedFailoverTimeline {
    pub primary_open_at_fault: bool,
    pub secondary_open_at_fault: bool,
    pub primary_rtt_at_fault: Duration,
    pub primary_pto_at_fault: Duration,
    pub primary_cwnd_at_fault: u64,
    pub primary_bytes_in_flight_at_fault: u64,
    pub primary_ack_eliciting_packets_in_flight_at_fault: u64,
    pub primary_tracked_sent_packets_at_fault: u64,
    pub primary_tracked_ack_eliciting_packets_at_fault: u64,
    pub primary_latest_ack_eliciting_packet_number_at_fault: u64,
    pub primary_pto_count_at_fault: u32,
    pub primary_loss_detection_timer_armed_at_fault: bool,
    pub first_primary_loss_timeout: Option<Duration>,
    pub first_primary_pto: Option<Duration>,
    pub first_primary_recovery_attempt: Option<Duration>,
    pub first_primary_hedge: Option<Duration>,
    pub first_primary_ack_progress_timeout: Option<Duration>,
    pub first_primary_ack_progress_reinjection: Option<Duration>,
    pub first_primary_ack_progress_feedback_probe: Option<Duration>,
    pub first_primary_ack_eliciting_send: Option<Duration>,
    pub last_primary_ack_eliciting_send: Option<Duration>,
    pub first_primary_udp_receive: Option<Duration>,
    pub last_primary_udp_receive: Option<Duration>,
    pub first_primary_loss_timer_unarmed: Option<Duration>,
    pub first_primary_ack_eliciting_in_flight_zero: Option<Duration>,
    pub first_primary_tracked_ack_eliciting_zero: Option<Duration>,
    pub max_primary_bytes_in_flight: u64,
    pub max_primary_ack_eliciting_packets_in_flight: u64,
    pub max_primary_tracked_sent_packets: u64,
    pub max_primary_tracked_ack_eliciting_packets: u64,
    pub first_secondary_udp_send: Option<Duration>,
    pub first_secondary_stream_retransmit: Option<Duration>,
    pub first_secondary_fresh_stream: Option<Duration>,
    pub first_receiver_primary_cross_path_ack: Option<Duration>,
    pub first_receiver_secondary_same_path_ack: Option<Duration>,
    pub first_receiver_secondary_cross_path_ack: Option<Duration>,
    pub primary_closed: Option<Duration>,
    pub secondary_closed: Option<Duration>,
    observed_primary_latest_ack_eliciting_packet_number: u64,
    observed_primary_udp_rx_datagrams: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamStateSample {
    pub elapsed_after_fault: Duration,
    pub stream_id: StreamId,
    pub sender_fully_acked_offset: Option<u64>,
    pub sender_unacknowledged_bytes: Option<u64>,
    pub sender_lowest_retransmit_offset: Option<u64>,
    pub sender_retransmit_bytes: Option<u64>,
    pub sender_offset: Option<u64>,
    pub sender_max_stream_data: Option<u64>,
    pub sender_stream_flow_control_blocked: Option<bool>,
    pub sender_connection_flow_control_blocked: Option<bool>,
    pub sender_connection_data: u64,
    pub sender_max_data: u64,
    pub sender_max_data_blocked: bool,
    pub receiver_contiguous_offset: Option<u64>,
    pub receiver_highest_offset: Option<u64>,
    pub receiver_sent_max_stream_data: Option<u64>,
    pub receiver_current_max_stream_data: Option<u64>,
    pub receiver_max_stream_data_pending: bool,
    pub receiver_max_stream_data_in_flight_packets: u64,
    pub receiver_data: u64,
    pub receiver_max_data: u64,
    pub receiver_sent_max_data: u64,
    pub receiver_max_data_pending: bool,
    pub receiver_max_data_in_flight_packets: u64,
    pub response_sender_fully_acked_offset: Option<u64>,
    pub response_sender_unacknowledged_bytes: Option<u64>,
    pub response_sender_lowest_retransmit_offset: Option<u64>,
    pub response_sender_retransmit_bytes: Option<u64>,
    pub response_sender_offset: Option<u64>,
    pub response_sender_max_stream_data: Option<u64>,
    pub response_sender_flow_control_blocked: Option<bool>,
    pub response_sender_connection_blocked: Option<bool>,
    pub response_receiver_contiguous_offset: Option<u64>,
    pub response_receiver_highest_offset: Option<u64>,
    pub primary_ack_progress_obligation_stream_id: Option<StreamId>,
    pub primary_ack_progress_obligation_offset: Option<u64>,
    pub primary_ack_progress_obligation_age: Option<Duration>,
    pub primary_ack_progress_deadline_remaining: Option<Duration>,
    pub primary_ack_progress_full_recovery_deadline_remaining: Option<Duration>,
    pub primary_ack_progress_service_deadline: Option<Duration>,
    pub primary_ack_progress_alternative_recovery_budget: Option<Duration>,
    pub primary_ack_progress_feedback_probe_staged: bool,
    pub primary_ack_progress_timer_armed: bool,
    pub primary_ack_progress_stream_frames_in_flight: u64,
    pub primary_ack_progress_has_cross_path_alternative: bool,
    pub primary_ack_progress_pto_recovery_probe_active: bool,
    pub primary_authenticated_feedback_age: Option<Duration>,
    pub secondary_authenticated_feedback_age: Option<Duration>,
    pub primary_stream_progress_updates: u64,
    pub primary_stream_progress_acked_bytes: u64,
    pub secondary_stream_progress_updates: u64,
    pub secondary_stream_progress_acked_bytes: u64,
    pub secondary_ack_progress_has_cross_path_alternative: bool,
    pub secondary_lost_packets: u64,
    pub secondary_stream_retransmit_bytes: u64,
    pub secondary_pto_timeouts: u64,
    pub secondary_stream_gap_rescue_probes: u64,
    pub secondary_stream_gap_rescue_bytes: u64,
    pub secondary_rtt: Duration,
    pub secondary_pto: Duration,
    pub secondary_cwnd: u64,
    pub secondary_bytes_in_flight: u64,
    pub secondary_ack_eliciting_packets_in_flight: u64,
    pub secondary_tracked_sent_packets: u64,
    pub secondary_tracked_ack_eliciting_packets: u64,
    pub secondary_latest_ack_eliciting_packet_number: u64,
    pub secondary_pto_count: u32,
    pub secondary_loss_detection_timer_armed: bool,
    pub receiver_primary_tracked_max_data_packets: u64,
    pub receiver_primary_tracked_max_stream_data_packets: u64,
    pub receiver_primary_pto_count: u32,
    pub receiver_primary_loss_detection_timer_armed: bool,
    pub receiver_primary_stream_fresh_bytes: u64,
    pub receiver_secondary_tracked_max_data_packets: u64,
    pub receiver_secondary_tracked_max_stream_data_packets: u64,
    pub receiver_secondary_pto_count: u32,
    pub receiver_secondary_loss_detection_timer_armed: bool,
    pub receiver_secondary_stream_fresh_bytes: u64,
    pub receiver_secondary_stream_retransmit_bytes: u64,
    pub receiver_secondary_lost_packets: u64,
    pub receiver_secondary_pto_timeouts: u64,
    pub receiver_secondary_bytes_in_flight: u64,
    pub receiver_secondary_ack_eliciting_packets_in_flight: u64,
    pub receiver_secondary_tracked_sent_packets: u64,
    pub receiver_secondary_tracked_ack_eliciting_packets: u64,
}

impl SustainedFailoverTimeline {
    fn new(
        primary_open_at_fault: bool,
        secondary_open_at_fault: bool,
        primary_at_fault: PathStats,
    ) -> Self {
        Self {
            primary_open_at_fault,
            secondary_open_at_fault,
            primary_rtt_at_fault: primary_at_fault.rtt,
            primary_pto_at_fault: primary_at_fault.pto,
            primary_cwnd_at_fault: primary_at_fault.cwnd,
            primary_bytes_in_flight_at_fault: primary_at_fault.bytes_in_flight,
            primary_ack_eliciting_packets_in_flight_at_fault: primary_at_fault
                .ack_eliciting_packets_in_flight,
            primary_tracked_sent_packets_at_fault: primary_at_fault.tracked_sent_packets,
            primary_tracked_ack_eliciting_packets_at_fault: primary_at_fault
                .tracked_ack_eliciting_packets,
            primary_latest_ack_eliciting_packet_number_at_fault: primary_at_fault
                .latest_ack_eliciting_packet_number,
            primary_pto_count_at_fault: primary_at_fault.pto_count,
            primary_loss_detection_timer_armed_at_fault: primary_at_fault
                .loss_detection_timer_armed,
            first_primary_loss_timeout: None,
            first_primary_pto: None,
            first_primary_recovery_attempt: None,
            first_primary_hedge: None,
            first_primary_ack_progress_timeout: None,
            first_primary_ack_progress_reinjection: None,
            first_primary_ack_progress_feedback_probe: None,
            first_primary_ack_eliciting_send: None,
            last_primary_ack_eliciting_send: None,
            first_primary_udp_receive: None,
            last_primary_udp_receive: None,
            first_primary_loss_timer_unarmed: (!primary_at_fault.loss_detection_timer_armed)
                .then_some(Duration::ZERO),
            first_primary_ack_eliciting_in_flight_zero: (primary_at_fault
                .ack_eliciting_packets_in_flight
                == 0)
                .then_some(Duration::ZERO),
            first_primary_tracked_ack_eliciting_zero: (primary_at_fault
                .tracked_ack_eliciting_packets
                == 0)
                .then_some(Duration::ZERO),
            max_primary_bytes_in_flight: primary_at_fault.bytes_in_flight,
            max_primary_ack_eliciting_packets_in_flight: primary_at_fault
                .ack_eliciting_packets_in_flight,
            max_primary_tracked_sent_packets: primary_at_fault.tracked_sent_packets,
            max_primary_tracked_ack_eliciting_packets: primary_at_fault
                .tracked_ack_eliciting_packets,
            first_secondary_udp_send: None,
            first_secondary_stream_retransmit: None,
            first_secondary_fresh_stream: None,
            first_receiver_primary_cross_path_ack: None,
            first_receiver_secondary_same_path_ack: None,
            first_receiver_secondary_cross_path_ack: None,
            primary_closed: (!primary_open_at_fault).then_some(Duration::ZERO),
            secondary_closed: (!secondary_open_at_fault).then_some(Duration::ZERO),
            observed_primary_latest_ack_eliciting_packet_number: primary_at_fault
                .latest_ack_eliciting_packet_number,
            observed_primary_udp_rx_datagrams: primary_at_fault.udp_rx.datagrams,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SustainedFailoverReport {
    pub scheduler: MultipathScheduler,
    pub pto_recovery: PtoRecovery,
    pub direction: FailoverDirection,
    pub recovered: bool,
    pub data_intact: bool,
    pub exchange_complete: bool,
    pub recovery_gap: Option<Duration>,
    pub transfer_duration: Option<Duration>,
    pub records_received: u64,
    pub application_bytes_received: u64,
    pub failure_reason: Option<String>,
    pub sender_primary_before_blackhole: PathMeasurement,
    pub sender_secondary_before_blackhole: PathMeasurement,
    pub sender_primary_after_blackhole: PathMeasurement,
    pub sender_secondary_after_blackhole: PathMeasurement,
    pub receiver_primary_after_blackhole: PathMeasurement,
    pub receiver_secondary_after_blackhole: PathMeasurement,
    pub timeline: SustainedFailoverTimeline,
    pub recovery_gap_started_after_fault: Option<Duration>,
    pub recovery_gap_ended_after_fault: Option<Duration>,
    pub recovery_gap_next_sequence: Option<u64>,
    pub primary_path_open: bool,
    pub secondary_path_open: bool,
    pub stream_state_samples: Vec<StreamStateSample>,
}

#[derive(Debug)]
enum SustainedServerEvent {
    Record { sequence: u64, received_at: Instant },
    Finished { records: u64, bytes: u64 },
    Failed(String),
}

#[derive(Debug)]
struct SustainedEventTrace {
    received_at: Vec<Instant>,
    records: u64,
    bytes: u64,
}

async fn collect_sustained_server_events(
    mut events: mpsc::UnboundedReceiver<SustainedServerEvent>,
    chunk_size: usize,
) -> LabResult<SustainedEventTrace> {
    let mut received_at = Vec::new();
    let mut expected_sequence = 0_u64;

    while let Some(event) = events.recv().await {
        match event {
            SustainedServerEvent::Record {
                sequence,
                received_at: at,
            } => {
                if sequence != expected_sequence {
                    return Err(other_error(format!(
                        "持续 writer 接收事件序号错误：期望 {expected_sequence}，实际 {sequence}",
                    )));
                }
                received_at.push(at);
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or_else(|| other_error("持续 writer 接收事件序号溢出"))?;
            }
            SustainedServerEvent::Finished { records, bytes } => {
                let expected_bytes = records
                    .checked_mul(chunk_size as u64)
                    .ok_or_else(|| other_error("持续 writer 接收事件业务字节数溢出"))?;
                if records != expected_sequence || bytes != expected_bytes {
                    return Err(other_error(
                        "持续 writer 接收事件的最终记录数或业务字节数不一致",
                    ));
                }
                return Ok(SustainedEventTrace {
                    received_at,
                    records,
                    bytes,
                });
            }
            SustainedServerEvent::Failed(reason) => {
                return Err(other_error(format!("持续 writer 服务端失败：{reason}")));
            }
        }
    }

    Err(other_error("持续 writer 接收事件通道提前关闭"))
}

fn count_received_records_in_window(
    received_at: &[Instant],
    started: Instant,
    ended: Instant,
) -> LabResult<u64> {
    if ended < started {
        return Err(other_error("持续 writer 测量窗口结束早于开始"));
    }
    u64::try_from(
        received_at
            .iter()
            .filter(|received_at| **received_at >= started && **received_at < ended)
            .count(),
    )
    .map_err(|_| other_error("持续 writer 测量窗口记录数超出 u64"))
}

#[derive(Debug)]
struct SustainedReceiveTrace {
    received_at: Vec<Instant>,
    records: u64,
    bytes: u64,
    elapsed: Duration,
}

struct SustainedFlowOutcome {
    trace: SustainedReceiveTrace,
    exchange_failure: Option<String>,
}

struct RunningLab {
    server_task: JoinHandle<LabResult<()>>,
    server_connection: Connection,
    client_endpoint: Endpoint,
    connection: Connection,
    server_addr: SocketAddr,
    primary: Path,
}

#[derive(Default)]
struct LabInstrumentation {
    declared_backlogged_epoch_sensor: bool,
    segmentation_offload: Option<bool>,
    sustained_events: Option<mpsc::UnboundedSender<SustainedServerEvent>>,
    realtime_datagram_events: Option<mpsc::UnboundedSender<realtime::RealtimeDatagramEvent>>,
}

#[derive(Debug, Clone, Copy)]
struct ResourceMeasurement {
    cpu_time: Duration,
    cpu_utilization_percent: f64,
    peak_rss_kib: u64,
}

struct ResourceMonitor {
    cpu_ticks_before: u64,
    stop: Arc<AtomicBool>,
    peak_rss_kib: Arc<AtomicU64>,
    task: Option<JoinHandle<()>>,
}

impl ResourceMonitor {
    fn start() -> LabResult<Self> {
        let cpu_ticks_before = read_process_cpu_ticks()?;
        let initial_rss = read_process_rss_kib()?;
        let stop = Arc::new(AtomicBool::new(false));
        let peak_rss_kib = Arc::new(AtomicU64::new(initial_rss));
        let monitor_stop = stop.clone();
        let monitor_peak = peak_rss_kib.clone();
        let task = tokio::spawn(async move {
            while !monitor_stop.load(Ordering::Relaxed) {
                if let Ok(rss_kib) = read_process_rss_kib() {
                    monitor_peak.fetch_max(rss_kib, Ordering::Relaxed);
                }
                sleep(Duration::from_millis(50)).await;
            }
        });

        Ok(Self {
            cpu_ticks_before,
            stop,
            peak_rss_kib,
            task: Some(task),
        })
    }

    async fn finish(mut self, elapsed: Duration) -> LabResult<ResourceMeasurement> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|error| other_error(format!("资源监控任务异常退出：{error}")))?;
        }
        let final_rss = read_process_rss_kib()?;
        self.peak_rss_kib.fetch_max(final_rss, Ordering::Relaxed);

        let cpu_ticks = read_process_cpu_ticks()?.saturating_sub(self.cpu_ticks_before);
        let ticks_per_second = process_clock_ticks_per_second()?;
        let cpu_time = Duration::from_secs_f64(cpu_ticks as f64 / ticks_per_second as f64);
        let cpu_utilization_percent = if elapsed.is_zero() {
            0.0
        } else {
            cpu_time.as_secs_f64() / elapsed.as_secs_f64() * 100.0
        };

        Ok(ResourceMeasurement {
            cpu_time,
            cpu_utilization_percent,
            peak_rss_kib: self.peak_rss_kib.load(Ordering::Relaxed),
        })
    }
}

impl Drop for ResourceMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl RunningLab {
    async fn open_second_path(&self, status: PathStatus) -> LabResult<Path> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(other_error("等待新路径所需的连接标识超时"));
            }

            match timeout(
                remaining,
                self.connection.open_path(
                    FourTuple::new(self.server_addr, Some(IpAddr::V4(LINE_TWO_IP))),
                    status,
                ),
            )
            .await
            {
                Ok(Ok(path)) => return Ok(path),
                Ok(Err(PathError::RemoteCidsExhausted)) => {
                    sleep(Duration::from_millis(50).min(remaining)).await;
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => return Err(other_error("建立第二条 MPQUIC 路径超时")),
            }
        }
    }

    async fn shutdown(self) -> LabResult<()> {
        self.connection.close(0_u8.into(), b"lab complete");
        self.client_endpoint.wait_all_draining().await;

        match timeout(OPERATION_TIMEOUT, self.server_task).await {
            Ok(joined) => {
                joined.map_err(|error| other_error(format!("服务端任务异常退出：{error}")))??;
                Ok(())
            }
            Err(_) => Err(other_error("服务端没有在连接关闭后及时退出")),
        }
    }
}

pub async fn run_basic_lab() -> LabResult<BasicLabReport> {
    let lab = start_connection(Ipv4Addr::UNSPECIFIED, None, PtoRecovery::Disabled).await?;

    let report_result: LabResult<BasicLabReport> = async {
        let connection = &lab.connection;
        let primary = lab.primary.clone();
        let multipath_negotiated = connection.is_multipath_enabled();

        let primary_before = primary.stats().udp_tx.bytes;
        transfer_and_verify(connection, 256 * 1024, 11).await?;
        let primary_bytes_sent = primary.stats().udp_tx.bytes.saturating_sub(primary_before);
        let primary_carried_data = primary_bytes_sent >= 256 * 1024;

        let secondary = lab.open_second_path(PathStatus::Available).await?;

        let path_limit_rejected = matches!(
            timeout(
                OPERATION_TIMEOUT,
                connection.open_path(
                    FourTuple::new(
                        lab.server_addr,
                        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))),
                    ),
                    PathStatus::Available,
                ),
            )
            .await
            .map_err(|_| other_error("路径上限测试超时"))?,
            Err(PathError::MaxPathIdReached)
        );

        primary.set_status(PathStatus::Backup)?;
        secondary.set_status(PathStatus::Available)?;
        sleep(Duration::from_millis(100)).await;

        let secondary_before = secondary.stats().udp_tx.bytes;
        transfer_and_verify(connection, 512 * 1024, 29).await?;
        let secondary_bytes_sent = secondary
            .stats()
            .udp_tx
            .bytes
            .saturating_sub(secondary_before);
        let secondary_carried_data = secondary_bytes_sent >= 512 * 1024;

        let malformed_frame_rejected = send_malformed_frame(connection).await?;

        primary.close()?;
        sleep(Duration::from_millis(100)).await;
        transfer_and_verify(connection, 256 * 1024, 47).await?;

        let datagram_latencies = datagram_echo_test(connection, 24).await?;

        Ok(BasicLabReport {
            multipath_negotiated,
            primary_carried_data,
            primary_bytes_sent,
            secondary_carried_data,
            secondary_bytes_sent,
            failover_transfer_ok: true,
            datagram_echoes: datagram_latencies.len(),
            datagram_p95: percentile(&datagram_latencies, 95).expect("基础实验固定发送了 Datagram"),
            path_limit_rejected,
            malformed_frame_rejected,
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = report_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_network_benchmark(
    config: NetworkBenchmarkConfig,
) -> LabResult<NetworkBenchmarkReport> {
    config.validate()?;

    run_network_workload(
        config.mode,
        config.scheduler,
        config.congestion,
        config.pto_recovery,
        BenchmarkWorkload::Fixed {
            transfer_size: config.transfer_size,
            datagram_count: config.datagram_count,
        },
    )
    .await
}

pub async fn run_sustained_network_benchmark(
    config: SustainedBenchmarkConfig,
) -> LabResult<NetworkBenchmarkReport> {
    config.validate()?;

    run_network_workload(
        config.mode,
        config.scheduler,
        config.congestion,
        config.pto_recovery,
        BenchmarkWorkload::Sustained {
            warmup_duration: config.warmup_duration,
            measurement_duration: config.measurement_duration,
            chunk_size: config.chunk_size,
        },
    )
    .await
}

pub async fn run_continuous_network_benchmark(
    config: ContinuousBenchmarkConfig,
) -> LabResult<ContinuousBenchmarkReport> {
    config.validate()?;

    let client_ip = match config.mode {
        PathMode::LineOneOnly => LINE_ONE_IP,
        PathMode::LineTwoOnly => LINE_TWO_IP,
        PathMode::MultipathAvailable => Ipv4Addr::UNSPECIFIED,
    };
    let (sustained_events_tx, sustained_events_rx) = mpsc::unbounded_channel();
    let lab = start_connection_internal(
        client_ip,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        config.pto_recovery,
        config.scheduler,
        config.congestion,
        LabInstrumentation {
            sustained_events: Some(sustained_events_tx),
            ..LabInstrumentation::default()
        },
    )
    .await?;
    let secondary = if config.mode == PathMode::MultipathAvailable {
        Some(lab.open_second_path(PathStatus::Available).await?)
    } else {
        None
    };
    sleep(Duration::from_millis(150)).await;

    let operation_result: LabResult<ContinuousBenchmarkReport> = async {
        let event_collector = tokio::spawn(collect_sustained_server_events(
            sustained_events_rx,
            config.chunk_size,
        ));
        let (writer, stop_writer, completed_bytes) =
            start_continuous_writer(&lab.connection, config.chunk_size, 197).await?;

        sleep(config.warmup_duration).await;
        let writer_alive_at_measurement_start = !writer.is_finished();
        if !writer_alive_at_measurement_start {
            let result = writer
                .await
                .map_err(|error| other_error(format!("持续 writer task 提前退出：{error}")))?;
            result?;
            return Err(other_error("持续 writer task 在测量前意外完成"));
        }

        let primary_before = lab.primary.stats();
        let secondary_before = secondary.as_ref().map(Path::stats);
        let resources = ResourceMonitor::start()?;
        let measurement_started = Instant::now();

        sleep(config.measurement_duration).await;
        let measurement_ended = Instant::now();
        let transfer_duration = measurement_ended.saturating_duration_since(measurement_started);
        let writer_alive_at_measurement_end = !writer.is_finished();
        let primary_after = lab.primary.stats();
        let secondary_after = secondary.as_ref().map(Path::stats);
        let _ = stop_writer.send(());
        let resources = resources.finish(transfer_duration).await?;

        let (sent_records, sent_bytes) = timeout(SUSTAINED_FAILOVER_GRACE, writer)
            .await
            .map_err(|_| other_error("等待持续 writer task 完整收尾超时"))?
            .map_err(|error| other_error(format!("持续 writer task 异常退出：{error}")))??;
        if sent_bytes != completed_bytes.load(Ordering::Relaxed) {
            return Err(other_error("持续 writer task 的累计业务字节统计不一致"));
        }

        let received = timeout(SUSTAINED_FAILOVER_GRACE, event_collector)
            .await
            .map_err(|_| other_error("等待持续 writer 接收事件收尾超时"))?
            .map_err(|error| other_error(format!("持续 writer 接收事件任务异常退出：{error}")))??;
        if (sent_records, sent_bytes) != (received.records, received.bytes) {
            return Err(other_error(
                "持续 writer 最终发送与接收记录数或业务字节数不一致",
            ));
        }

        let records_received_in_window = count_received_records_in_window(
            &received.received_at,
            measurement_started,
            measurement_ended,
        )?;
        let transfer_bytes = records_received_in_window
            .checked_mul(config.chunk_size as u64)
            .ok_or_else(|| other_error("持续 writer 测量窗口业务字节数溢出"))?;
        let transfer_size = usize::try_from(transfer_bytes)
            .map_err(|_| other_error("持续 writer 测量窗口业务字节数超出平台范围"))?;

        let primary_measurement = path_delta(primary_before, primary_after);
        let secondary_measurement = match (secondary_before, secondary_after) {
            (Some(before), Some(after)) => path_delta(before, after),
            _ => PathMeasurement::default(),
        };
        let (line_one, line_two) = match config.mode {
            PathMode::LineOneOnly => (primary_measurement, PathMeasurement::default()),
            PathMode::LineTwoOnly => (PathMeasurement::default(), primary_measurement),
            PathMode::MultipathAvailable => (primary_measurement, secondary_measurement),
        };
        let total_udp_bytes_sent = line_one
            .udp_bytes_sent
            .saturating_add(line_two.udp_bytes_sent);
        let all_configured_paths_open = lab.primary.status().is_ok()
            && secondary.as_ref().is_none_or(|path| path.status().is_ok());
        let any_configured_path_open = lab.primary.status().is_ok()
            || secondary.as_ref().is_some_and(|path| path.status().is_ok());

        Ok(ContinuousBenchmarkReport {
            mode: config.mode,
            scheduler: config.scheduler,
            congestion: config.congestion,
            pto_recovery: config.pto_recovery,
            multipath_negotiated: lab.connection.is_multipath_enabled(),
            data_intact: true,
            writer_alive_at_measurement_start,
            writer_alive_at_measurement_end,
            transfer_size,
            transfer_duration,
            throughput_mbps: throughput_mbps(transfer_size, transfer_duration),
            records_received_in_window,
            total_records_received: received.records,
            total_application_bytes_received: received.bytes,
            line_one,
            line_two,
            total_udp_bytes_sent,
            extra_udp_bytes_sent: total_udp_bytes_sent.saturating_sub(transfer_bytes),
            cpu_time: resources.cpu_time,
            cpu_utilization_percent: resources.cpu_utilization_percent,
            peak_rss_kib: resources.peak_rss_kib,
            all_configured_paths_open,
            any_configured_path_open,
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_declared_backlogged_epoch_probe(
    config: DeclaredBackloggedEpochConfig,
) -> LabResult<DeclaredBackloggedEpochReport> {
    config.validate()?;
    let client_ip = match config.mode {
        PathMode::LineOneOnly => LINE_ONE_IP,
        PathMode::LineTwoOnly => LINE_TWO_IP,
        PathMode::MultipathAvailable => unreachable!("validated as single-path only"),
    };
    let lab = start_connection_internal(
        client_ip,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        PtoRecovery::Disabled,
        MultipathScheduler::NoqDefault,
        QuicCongestion::Cubic,
        LabInstrumentation {
            declared_backlogged_epoch_sensor: true,
            ..LabInstrumentation::default()
        },
    )
    .await?;

    let operation_result: LabResult<DeclaredBackloggedEpochReport> = async {
        let (writer, stop_writer, completed_bytes) =
            start_continuous_writer(&lab.connection, config.chunk_size, 197).await?;

        sleep(config.warmup_duration).await;
        let writer_alive_at_epoch_start = !writer.is_finished();
        if !writer_alive_at_epoch_start {
            let result = writer
                .await
                .map_err(|error| other_error(format!("持续 writer task 提前退出：{error}")))?;
            result?;
            return Err(other_error("持续 writer task 在 epoch 前意外完成"));
        }

        let before = lab.primary.stats();
        let resources = ResourceMonitor::start()?;
        let epoch_started = Instant::now();
        lab.connection
            .begin_declared_backlogged_epoch(config.measurement_duration)?;
        let bytes_before = completed_bytes.load(Ordering::Relaxed);

        sleep(config.measurement_duration).await;
        let transfer_duration = epoch_started.elapsed();
        let bytes_after = completed_bytes.load(Ordering::Relaxed);
        let writer_alive_at_epoch_end = !writer.is_finished();
        let _ = stop_writer.send(());
        let resources = resources.finish(transfer_duration).await?;

        let (_records, total_bytes) = timeout(SUSTAINED_FAILOVER_GRACE, writer)
            .await
            .map_err(|_| other_error("等待持续 writer task 完整收尾超时"))?
            .map_err(|error| other_error(format!("持续 writer task 异常退出：{error}")))??;
        if total_bytes != completed_bytes.load(Ordering::Relaxed) {
            return Err(other_error("持续 writer task 的累计业务字节统计不一致"));
        }

        sleep(DECLARED_EPOCH_SETTLE_WAIT).await;
        let after = lab.primary.stats();
        let path = path_delta(before, after);
        let transfer_bytes = bytes_after.saturating_sub(bytes_before);
        let transfer_size = usize::try_from(transfer_bytes)
            .map_err(|_| other_error("declared epoch 业务字节数超出平台范围"))?;

        Ok(DeclaredBackloggedEpochReport {
            mode: config.mode,
            multipath_negotiated: lab.connection.is_multipath_enabled(),
            data_intact: true,
            writer_alive_at_epoch_start,
            writer_alive_at_epoch_end,
            transfer_size,
            transfer_duration,
            throughput_mbps: throughput_mbps(transfer_size, transfer_duration),
            total_udp_bytes_sent: path.udp_bytes_sent,
            path,
            cpu_time: resources.cpu_time,
            cpu_utilization_percent: resources.cpu_utilization_percent,
            peak_rss_kib: resources.peak_rss_kib,
            path_open: lab.primary.status().is_ok(),
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

async fn run_network_workload(
    mode: PathMode,
    scheduler: MultipathScheduler,
    congestion: QuicCongestion,
    pto_recovery: PtoRecovery,
    workload: BenchmarkWorkload,
) -> LabResult<NetworkBenchmarkReport> {
    let datagram_count = match workload {
        BenchmarkWorkload::Fixed { datagram_count, .. } => datagram_count,
        BenchmarkWorkload::Sustained { .. } => 0,
    };

    let client_ip = match mode {
        PathMode::LineOneOnly => LINE_ONE_IP,
        PathMode::LineTwoOnly => LINE_TWO_IP,
        PathMode::MultipathAvailable => Ipv4Addr::UNSPECIFIED,
    };
    let lab = start_connection_with_scheduler_and_congestion(
        client_ip,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        pto_recovery,
        scheduler,
        congestion,
    )
    .await?;

    let secondary = if mode == PathMode::MultipathAvailable {
        Some(lab.open_second_path(PathStatus::Available).await?)
    } else {
        None
    };
    sleep(Duration::from_millis(150)).await;

    let operation_result: LabResult<NetworkBenchmarkReport> = async {
        if let BenchmarkWorkload::Sustained {
            warmup_duration,
            chunk_size,
            ..
        } = workload
        {
            let _ =
                transfer_for_duration(&lab.connection, warmup_duration, chunk_size, 131).await?;
        }

        let primary_before = lab.primary.stats();
        let secondary_before = secondary.as_ref().map(Path::stats);
        let resource_monitor = ResourceMonitor::start()?;

        let (transfer_size, transfer_duration) = match workload {
            BenchmarkWorkload::Fixed { transfer_size, .. } => {
                let transfer_started = Instant::now();
                transfer_and_verify(&lab.connection, transfer_size, 83).await?;
                (transfer_size, transfer_started.elapsed())
            }
            BenchmarkWorkload::Sustained {
                measurement_duration,
                chunk_size,
                ..
            } => {
                transfer_for_duration(&lab.connection, measurement_duration, chunk_size, 197)
                    .await?
            }
        };
        let resources = resource_monitor.finish(transfer_duration).await?;

        let datagrams = datagram_echo_probe(&lab.connection, datagram_count).await?;

        let primary_after = lab.primary.stats();
        let secondary_after = secondary.as_ref().map(Path::stats);
        let primary_measurement = path_delta(primary_before, primary_after);
        let secondary_measurement = match (secondary_before, secondary_after) {
            (Some(before), Some(after)) => path_delta(before, after),
            _ => PathMeasurement::default(),
        };

        let (line_one, line_two) = match mode {
            PathMode::LineOneOnly => (primary_measurement, PathMeasurement::default()),
            PathMode::LineTwoOnly => (PathMeasurement::default(), primary_measurement),
            PathMode::MultipathAvailable => (primary_measurement, secondary_measurement),
        };
        let total_udp_bytes_sent = line_one
            .udp_bytes_sent
            .saturating_add(line_two.udp_bytes_sent);
        let application_bytes_sent = (transfer_size as u64)
            .saturating_add((datagram_count as u64).saturating_mul(DATAGRAM_PROBE_SIZE as u64));

        let all_configured_paths_open = lab.primary.status().is_ok()
            && secondary.as_ref().is_none_or(|path| path.status().is_ok());
        let any_configured_path_open = lab.primary.status().is_ok()
            || secondary.as_ref().is_some_and(|path| path.status().is_ok());

        Ok(NetworkBenchmarkReport {
            mode,
            scheduler,
            congestion,
            pto_recovery,
            multipath_negotiated: lab.connection.is_multipath_enabled(),
            transfer_size,
            transfer_duration,
            throughput_mbps: throughput_mbps(transfer_size, transfer_duration),
            datagrams,
            line_one,
            line_two,
            total_udp_bytes_sent,
            extra_udp_bytes_sent: total_udp_bytes_sent.saturating_sub(application_bytes_sent),
            cpu_time: resources.cpu_time,
            cpu_utilization_percent: resources.cpu_utilization_percent,
            peak_rss_kib: resources.peak_rss_kib,
            all_configured_paths_open,
            any_configured_path_open,
        })
    }
    .await;

    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_blackhole_failover<Activate, Restore>(
    scheduler: MultipathScheduler,
    pto_recovery: PtoRecovery,
    activate_blackhole: Activate,
    restore_network: Restore,
) -> LabResult<FailoverReport>
where
    Activate: FnOnce() -> LabResult<()>,
    Restore: FnOnce() -> LabResult<()>,
{
    let lab = start_connection_with_scheduler(
        Ipv4Addr::UNSPECIFIED,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        pto_recovery,
        scheduler,
    )
    .await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;

    let operation_result: LabResult<FailoverReport> = async {
        transfer_and_verify(&lab.connection, 128 * 1024, 101).await?;

        let primary_before = lab.primary.stats();
        let secondary_before = secondary.stats();
        activate_blackhole()?;

        let failure_started = Instant::now();
        let transfer_result = timeout(
            FAILOVER_OBSERVATION_TIMEOUT,
            transfer_and_verify_with_progress(&lab.connection, 256 * 1024, 113, failure_started),
        )
        .await;

        let (recovered, recovery_time, completion_time, failure_reason) = match transfer_result {
            Ok(Ok(timing)) => (
                true,
                Some(timing.recovery_time),
                Some(timing.completion_time),
                None,
            ),
            Ok(Err(error)) => (false, None, None, Some(error.to_string())),
            Err(_) => (
                false,
                None,
                None,
                Some(format!(
                    "{} 秒观察窗口内没有恢复传输",
                    FAILOVER_OBSERVATION_TIMEOUT.as_secs()
                )),
            ),
        };

        let primary_after = lab.primary.stats();
        let secondary_after = secondary.stats();
        let primary_delta = path_delta(primary_before, primary_after);
        let secondary_delta = path_delta(secondary_before, secondary_after);

        Ok(FailoverReport {
            scheduler,
            pto_recovery,
            recovered,
            recovery_time,
            completion_time,
            failure_reason,
            configured_path_idle_timeout: NETWORK_PATH_IDLE_TIMEOUT,
            primary_bytes_after_blackhole: primary_delta.udp_bytes_sent,
            secondary_bytes_after_blackhole: secondary_delta.udp_bytes_sent,
            primary_lost_packets: primary_delta.lost_packets,
            secondary_lost_packets: secondary_delta.lost_packets,
            primary_pto_hedges: primary_delta.pto_hedges,
            secondary_pto_hedges: secondary_delta.pto_hedges,
            primary_pto_hedge_bytes: primary_delta.pto_hedge_bytes,
            secondary_pto_hedge_bytes: secondary_delta.pto_hedge_bytes,
            primary_path_open: lab.primary.status().is_ok(),
            secondary_path_open: secondary.status().is_ok(),
        })
    }
    .await;

    let restore_result = restore_network();
    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    restore_result?;
    shutdown_result?;
    Ok(report)
}

pub async fn run_sustained_blackhole_failover<Activate, Restore>(
    config: SustainedFailoverConfig,
    activate_blackhole: Activate,
    restore_network: Restore,
) -> LabResult<SustainedFailoverReport>
where
    Activate: FnOnce() -> LabResult<()>,
    Restore: FnOnce() -> LabResult<()>,
{
    config.validate()?;
    let (lab, server_events) = start_connection_with_sustained_observer(
        Ipv4Addr::UNSPECIFIED,
        Some(NETWORK_PATH_IDLE_TIMEOUT),
        config.pto_recovery,
        config.scheduler,
    )
    .await?;
    let secondary = lab.open_second_path(PathStatus::Backup).await?;
    sleep(Duration::from_millis(250)).await;
    let server_primary = lab
        .server_connection
        .path(PathId::ZERO)
        .ok_or_else(|| other_error("服务端找不到正式实验的主路径"))?;
    let server_secondary = lab
        .server_connection
        .path(secondary.id())
        .ok_or_else(|| other_error("服务端找不到正式实验的备用路径"))?;
    let (sender_primary, sender_secondary, receiver_primary, receiver_secondary) =
        match config.direction {
            FailoverDirection::ClientToServer => (
                lab.primary.clone(),
                secondary.clone(),
                server_primary,
                server_secondary,
            ),
            FailoverDirection::ServerToClient => (
                server_primary,
                server_secondary,
                lab.primary.clone(),
                secondary.clone(),
            ),
        };
    let (sender_connection, receiver_connection) = match config.direction {
        FailoverDirection::ClientToServer => {
            (lab.connection.clone(), lab.server_connection.clone())
        }
        FailoverDirection::ServerToClient => {
            (lab.server_connection.clone(), lab.connection.clone())
        }
    };

    let operation_result: LabResult<SustainedFailoverReport> = async {
        let primary_before = sender_primary.stats();
        let secondary_before = sender_secondary.stats();
        let (started_tx, started_rx) = oneshot::channel();
        let flow_connection = lab.connection.clone();
        let mut flow_task = tokio::spawn(run_sustained_failover_flow(
            flow_connection,
            config,
            server_events,
            started_tx,
        ));

        let (started_at, stream_id) = match timeout(OPERATION_TIMEOUT, started_rx).await {
            Ok(Ok(started)) => started,
            Ok(Err(_)) => {
                let result = flow_task
                    .await
                    .map_err(|error| other_error(format!("持续换网任务异常退出：{error}")))?;
                return Err(result
                    .err()
                    .unwrap_or_else(|| other_error("持续换网任务没有报告开始时刻")));
            }
            Err(_) => {
                flow_task.abort();
                let _ = flow_task.await;
                return Err(other_error("等待持续换网业务开始超时"));
            }
        };

        tokio::select! {
            result = &mut flow_task => {
                let result = result
                    .map_err(|error| other_error(format!("持续换网任务异常退出：{error}")))?;
                return Err(result
                    .err()
                    .unwrap_or_else(|| other_error("持续换网业务在制造黑洞前提前结束")));
            }
            () = sleep(config.failure_after) => {}
        }

        let primary_at_blackhole = sender_primary.stats();
        let secondary_at_blackhole = sender_secondary.stats();
        let receiver_primary_at_blackhole = receiver_primary.stats();
        let receiver_secondary_at_blackhole = receiver_secondary.stats();
        if let Err(error) = activate_blackhole() {
            flow_task.abort();
            let _ = flow_task.await;
            return Err(error);
        }
        let failure_started = Instant::now();
        let mut timeline = SustainedFailoverTimeline::new(
            sender_primary.status().is_ok(),
            sender_secondary.status().is_ok(),
            primary_at_blackhole,
        );
        observe_sustained_failover_timeline(
            &mut timeline,
            failure_started,
            &sender_primary,
            &sender_secondary,
            &receiver_primary,
            &receiver_secondary,
            primary_at_blackhole,
            secondary_at_blackhole,
            receiver_primary_at_blackhole,
            receiver_secondary_at_blackhole,
        );
        let mut stream_state_samples = Vec::new();
        if config.collect_stream_state_diagnostics {
            observe_sustained_stream_state(
                &mut stream_state_samples,
                failure_started,
                stream_id,
                &sender_connection,
                &receiver_connection,
                &sender_primary,
                &sender_secondary,
                &receiver_primary,
                &receiver_secondary,
                primary_at_blackhole,
                secondary_at_blackhole,
                receiver_primary_at_blackhole,
                receiver_secondary_at_blackhole,
            );
        }

        let remaining = config
            .total_duration
            .saturating_add(SUSTAINED_FAILOVER_GRACE)
            .saturating_sub(started_at.elapsed());
        let monitored_flow = async {
            loop {
                tokio::select! {
                    result = &mut flow_task => break result,
                    () = sleep(Duration::from_millis(5)) => {
                        observe_sustained_failover_timeline(
                            &mut timeline,
                            failure_started,
                            &sender_primary,
                            &sender_secondary,
                            &receiver_primary,
                            &receiver_secondary,
                            primary_at_blackhole,
                            secondary_at_blackhole,
                            receiver_primary_at_blackhole,
                            receiver_secondary_at_blackhole,
                        );
                        if config.collect_stream_state_diagnostics {
                            observe_sustained_stream_state(
                                &mut stream_state_samples,
                                failure_started,
                                stream_id,
                                &sender_connection,
                                &receiver_connection,
                                &sender_primary,
                                &sender_secondary,
                                &receiver_primary,
                                &receiver_secondary,
                                primary_at_blackhole,
                                secondary_at_blackhole,
                                receiver_primary_at_blackhole,
                                receiver_secondary_at_blackhole,
                            );
                        }
                    }
                }
            }
        };
        let flow_result = match timeout(remaining, monitored_flow).await {
            Ok(result) => Some(
                result.map_err(|error| other_error(format!("持续换网任务异常退出：{error}")))?,
            ),
            Err(_) => {
                flow_task.abort();
                let _ = flow_task.await;
                None
            }
        };

        let primary_after = sender_primary.stats();
        let secondary_after = sender_secondary.stats();
        let receiver_primary_after = receiver_primary.stats();
        let receiver_secondary_after = receiver_secondary.stats();
        observe_sustained_failover_timeline(
            &mut timeline,
            failure_started,
            &sender_primary,
            &sender_secondary,
            &receiver_primary,
            &receiver_secondary,
            primary_at_blackhole,
            secondary_at_blackhole,
            receiver_primary_at_blackhole,
            receiver_secondary_at_blackhole,
        );
        if config.collect_stream_state_diagnostics {
            observe_sustained_stream_state(
                &mut stream_state_samples,
                failure_started,
                stream_id,
                &sender_connection,
                &receiver_connection,
                &sender_primary,
                &sender_secondary,
                &receiver_primary,
                &receiver_secondary,
                primary_at_blackhole,
                secondary_at_blackhole,
                receiver_primary_at_blackhole,
                receiver_secondary_at_blackhole,
            );
        }
        let primary_before_delta = path_delta(primary_before, primary_at_blackhole);
        let secondary_before_delta = path_delta(secondary_before, secondary_at_blackhole);
        let primary_after_delta = path_delta(primary_at_blackhole, primary_after);
        let secondary_after_delta = path_delta(secondary_at_blackhole, secondary_after);
        let receiver_primary_after_delta =
            path_delta(receiver_primary_at_blackhole, receiver_primary_after);
        let receiver_secondary_after_delta =
            path_delta(receiver_secondary_at_blackhole, receiver_secondary_after);

        let (trace, flow_failure) = match flow_result {
            Some(Ok(outcome)) => (Some(outcome.trace), outcome.exchange_failure),
            Some(Err(error)) => (None, Some(error.to_string())),
            None => (
                None,
                Some(format!(
                    "业务开始后 {} 秒内没有完成持续传输",
                    (config.total_duration + SUSTAINED_FAILOVER_GRACE).as_secs()
                )),
            ),
        };
        let recovery_gap_trace = trace
            .as_ref()
            .and_then(|trace| recovery_gap_trace_after_fault(&trace.received_at, failure_started));
        let recovery_gap = recovery_gap_trace.map(|gap| gap.duration);
        let data_intact = trace.is_some();
        let exchange_complete = data_intact && flow_failure.is_none();
        let recovered = data_intact && recovery_gap.is_some();
        let failure_reason = flow_failure
            .or_else(|| (!recovered).then(|| "没有找到同时覆盖故障前后数据的恢复间隔".to_owned()));

        Ok(SustainedFailoverReport {
            scheduler: config.scheduler,
            pto_recovery: config.pto_recovery,
            direction: config.direction,
            recovered,
            data_intact,
            exchange_complete,
            recovery_gap,
            transfer_duration: trace.as_ref().map(|trace| trace.elapsed),
            records_received: trace.as_ref().map_or(0, |trace| trace.records),
            application_bytes_received: trace.as_ref().map_or(0, |trace| trace.bytes),
            failure_reason,
            sender_primary_before_blackhole: primary_before_delta,
            sender_secondary_before_blackhole: secondary_before_delta,
            sender_primary_after_blackhole: primary_after_delta,
            sender_secondary_after_blackhole: secondary_after_delta,
            receiver_primary_after_blackhole: receiver_primary_after_delta,
            receiver_secondary_after_blackhole: receiver_secondary_after_delta,
            timeline,
            recovery_gap_started_after_fault: recovery_gap_trace.map(|gap| gap.started_after_fault),
            recovery_gap_ended_after_fault: recovery_gap_trace.map(|gap| gap.ended_after_fault),
            recovery_gap_next_sequence: recovery_gap_trace.map(|gap| gap.next_sequence),
            primary_path_open: sender_primary.status().is_ok(),
            secondary_path_open: sender_secondary.status().is_ok(),
            stream_state_samples,
        })
    }
    .await;

    let restore_result = restore_network();
    let shutdown_result = lab.shutdown().await;
    let report = operation_result?;
    restore_result?;
    shutdown_result?;
    Ok(report)
}

async fn run_sustained_failover_flow(
    connection: Connection,
    config: SustainedFailoverConfig,
    mut server_events: mpsc::UnboundedReceiver<SustainedServerEvent>,
    started_tx: oneshot::Sender<(Instant, StreamId)>,
) -> LabResult<SustainedFlowOutcome> {
    let (mut send, mut receive) = timeout(OPERATION_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| other_error("打开正式换网业务流超时"))??;
    let request = make_sustained_stream_request(config)?;
    timeout(OPERATION_TIMEOUT, send.write_all(&request))
        .await
        .map_err(|_| other_error("发送正式换网请求超时"))??;

    let mut ready = [0_u8; SUSTAINED_FAILOVER_READY.len()];
    timeout(OPERATION_TIMEOUT, receive.read_exact(&mut ready))
        .await
        .map_err(|_| other_error("等待正式换网服务端就绪超时"))??;
    if &ready != SUSTAINED_FAILOVER_READY {
        return Err(other_error("服务端没有返回正式换网就绪标记"));
    }
    timeout(OPERATION_TIMEOUT, send.write_all(&[SUSTAINED_FAILOVER_GO]))
        .await
        .map_err(|_| other_error("发送正式换网开始标记超时"))??;
    let started_at = Instant::now();
    started_tx
        .send((started_at, send.id()))
        .map_err(|_| other_error("正式换网启动时刻无人接收"))?;

    match config.direction {
        FailoverDirection::ClientToServer => {
            let (receiver_complete_tx, receiver_complete_rx) = oneshot::channel();
            let network = async {
                let (sent_records, sent_bytes, _) = write_sustained_records(
                    &mut send,
                    config.total_duration,
                    config.chunk_size,
                    config.seed,
                )
                .await?;
                if config.receiver_anchored_response_timeout {
                    timeout(SUSTAINED_FAILOVER_GRACE, receiver_complete_rx)
                        .await
                        .map_err(|_| other_error("等待正式换网服务端完整接收事件超时"))?
                        .map_err(|_| other_error("正式换网服务端完整接收事件通道提前关闭"))?;
                }
                let response = timeout(OPERATION_TIMEOUT, receive.read_to_end(64))
                    .await
                    .map_err(|_| other_error("等待正式换网服务端校验结果超时"))??;
                let (received_records, received_bytes) =
                    parse_sustained_success_response(&response)?;
                if (sent_records, sent_bytes) != (received_records, received_bytes) {
                    return Err(other_error("正式换网收发记录总数或字节数不一致"));
                }
                Ok::<(u64, u64), LabError>((sent_records, sent_bytes))
            };
            let events = async {
                let trace = collect_sustained_server_trace(&mut server_events).await?;
                let _ = receiver_complete_tx.send(());
                Ok::<SustainedReceiveTrace, LabError>(trace)
            };
            let (network, trace) = tokio::join!(network, events);
            let (mut trace, exchange_failure) = match (network, trace) {
                (Ok((sent_records, sent_bytes)), Ok(trace)) => {
                    if (trace.records, trace.bytes) != (sent_records, sent_bytes) {
                        return Err(other_error("正式换网服务端事件统计与线上的校验结果不一致"));
                    }
                    (trace, None)
                }
                (Err(network_error), Ok(trace)) => {
                    let failure = format!(
                        "客户端未收到最终校验响应：{network_error}；服务端已完整校验 {} 条记录 / {} 字节",
                        trace.records, trace.bytes
                    );
                    (trace, Some(failure))
                }
                (Err(network_error), Err(trace_error)) => {
                    return Err(other_error(format!(
                        "正式换网双端同时失败：客户端：{network_error}；服务端：{trace_error}"
                    )));
                }
                (Ok(_), Err(error)) => return Err(error),
            };
            trace.elapsed = started_at.elapsed();
            Ok(SustainedFlowOutcome {
                trace,
                exchange_failure,
            })
        }
        FailoverDirection::ServerToClient => {
            send.finish()?;
            let mut trace =
                receive_sustained_records(&mut receive, config.chunk_size, config.seed, None)
                    .await?;
            trace.elapsed = started_at.elapsed();
            Ok(SustainedFlowOutcome {
                trace,
                exchange_failure: None,
            })
        }
    }
}

async fn collect_sustained_server_trace(
    events: &mut mpsc::UnboundedReceiver<SustainedServerEvent>,
) -> LabResult<SustainedReceiveTrace> {
    let started = Instant::now();
    let mut expected_sequence = 0_u64;
    let mut received_at = Vec::new();
    loop {
        match events.recv().await {
            Some(SustainedServerEvent::Record {
                sequence,
                received_at: timestamp,
            }) => {
                if sequence != expected_sequence {
                    return Err(other_error(format!(
                        "服务端事件记录编号错误：期望 {expected_sequence}，实际 {sequence}"
                    )));
                }
                expected_sequence += 1;
                received_at.push(timestamp);
            }
            Some(SustainedServerEvent::Finished { records, bytes }) => {
                if records != expected_sequence {
                    return Err(other_error("服务端完成事件的记录总数不正确"));
                }
                return Ok(SustainedReceiveTrace {
                    received_at,
                    records,
                    bytes,
                    elapsed: started.elapsed(),
                });
            }
            Some(SustainedServerEvent::Failed(reason)) => {
                return Err(other_error(format!(
                    "{reason}；失败前已完整收到 {expected_sequence} 条记录"
                )));
            }
            None => return Err(other_error("持续换网服务端事件通道提前关闭")),
        }
    }
}

#[cfg(test)]
fn recovery_gap_after_fault(received_at: &[Instant], failure_started: Instant) -> Option<Duration> {
    recovery_gap_trace_after_fault(received_at, failure_started).map(|gap| gap.duration)
}

#[derive(Debug, Clone, Copy)]
struct RecoveryGapTrace {
    duration: Duration,
    started_after_fault: Duration,
    ended_after_fault: Duration,
    next_sequence: u64,
}

fn recovery_gap_trace_after_fault(
    received_at: &[Instant],
    failure_started: Instant,
) -> Option<RecoveryGapTrace> {
    let has_before = received_at
        .iter()
        .any(|timestamp| *timestamp < failure_started);
    let has_after = received_at
        .iter()
        .any(|timestamp| *timestamp >= failure_started);
    if !has_before || !has_after {
        return None;
    }

    received_at
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[1] >= failure_started)
        .map(|(index, pair)| RecoveryGapTrace {
            duration: pair[1].saturating_duration_since(pair[0]),
            started_after_fault: pair[0].saturating_duration_since(failure_started),
            ended_after_fault: pair[1].saturating_duration_since(failure_started),
            next_sequence: (index + 1) as u64,
        })
        .max_by_key(|gap| gap.duration)
}

#[allow(clippy::too_many_arguments)]
fn observe_sustained_failover_timeline(
    timeline: &mut SustainedFailoverTimeline,
    failure_started: Instant,
    sender_primary: &Path,
    sender_secondary: &Path,
    receiver_primary: &Path,
    receiver_secondary: &Path,
    primary_at_blackhole: PathStats,
    secondary_at_blackhole: PathStats,
    receiver_primary_at_blackhole: PathStats,
    receiver_secondary_at_blackhole: PathStats,
) {
    let elapsed = failure_started.elapsed();
    let primary = sender_primary.stats();
    let secondary = sender_secondary.stats();
    let receiver_primary = receiver_primary.stats();
    let receiver_secondary = receiver_secondary.stats();

    record_first_timeline_event(
        &mut timeline.first_primary_loss_timeout,
        primary.loss_detection_timeouts > primary_at_blackhole.loss_detection_timeouts,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_pto,
        primary.pto_timeouts > primary_at_blackhole.pto_timeouts,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_recovery_attempt,
        primary.pto_recovery_attempts > primary_at_blackhole.pto_recovery_attempts,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_hedge,
        primary.pto_hedges > primary_at_blackhole.pto_hedges,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_ack_progress_timeout,
        primary.ack_progress_recovery_timeouts
            > primary_at_blackhole.ack_progress_recovery_timeouts,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_ack_progress_reinjection,
        primary.ack_progress_reinjections > primary_at_blackhole.ack_progress_reinjections,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_ack_progress_feedback_probe,
        primary.ack_progress_feedback_probes > primary_at_blackhole.ack_progress_feedback_probes,
        elapsed,
    );
    if primary.latest_ack_eliciting_packet_number
        > timeline.observed_primary_latest_ack_eliciting_packet_number
    {
        record_first_timeline_event(
            &mut timeline.first_primary_ack_eliciting_send,
            true,
            elapsed,
        );
        timeline.last_primary_ack_eliciting_send = Some(elapsed);
        timeline.observed_primary_latest_ack_eliciting_packet_number =
            primary.latest_ack_eliciting_packet_number;
    }
    if primary.udp_rx.datagrams > timeline.observed_primary_udp_rx_datagrams {
        record_first_timeline_event(&mut timeline.first_primary_udp_receive, true, elapsed);
        timeline.last_primary_udp_receive = Some(elapsed);
        timeline.observed_primary_udp_rx_datagrams = primary.udp_rx.datagrams;
    }
    record_first_timeline_event(
        &mut timeline.first_primary_loss_timer_unarmed,
        !primary.loss_detection_timer_armed,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_ack_eliciting_in_flight_zero,
        primary.ack_eliciting_packets_in_flight == 0,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_primary_tracked_ack_eliciting_zero,
        primary.tracked_ack_eliciting_packets == 0,
        elapsed,
    );
    timeline.max_primary_bytes_in_flight = timeline
        .max_primary_bytes_in_flight
        .max(primary.bytes_in_flight);
    timeline.max_primary_ack_eliciting_packets_in_flight = timeline
        .max_primary_ack_eliciting_packets_in_flight
        .max(primary.ack_eliciting_packets_in_flight);
    timeline.max_primary_tracked_sent_packets = timeline
        .max_primary_tracked_sent_packets
        .max(primary.tracked_sent_packets);
    timeline.max_primary_tracked_ack_eliciting_packets = timeline
        .max_primary_tracked_ack_eliciting_packets
        .max(primary.tracked_ack_eliciting_packets);
    record_first_timeline_event(
        &mut timeline.first_secondary_udp_send,
        secondary.udp_tx.bytes > secondary_at_blackhole.udp_tx.bytes,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_secondary_stream_retransmit,
        secondary.frame_tx.stream_retransmit_bytes
            > secondary_at_blackhole.frame_tx.stream_retransmit_bytes,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_secondary_fresh_stream,
        secondary.frame_tx.stream_fresh_bytes > secondary_at_blackhole.frame_tx.stream_fresh_bytes,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_receiver_primary_cross_path_ack,
        receiver_primary.frame_tx.path_acks_cross_path
            > receiver_primary_at_blackhole.frame_tx.path_acks_cross_path,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_receiver_secondary_same_path_ack,
        receiver_secondary.frame_tx.path_acks_same_path
            > receiver_secondary_at_blackhole.frame_tx.path_acks_same_path,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.first_receiver_secondary_cross_path_ack,
        receiver_secondary.frame_tx.path_acks_cross_path
            > receiver_secondary_at_blackhole
                .frame_tx
                .path_acks_cross_path,
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.primary_closed,
        sender_primary.status().is_err(),
        elapsed,
    );
    record_first_timeline_event(
        &mut timeline.secondary_closed,
        sender_secondary.status().is_err(),
        elapsed,
    );
}

// This diagnostic sampler deliberately receives both endpoint snapshots and their fault-time
// baselines together so every derived counter is taken at one instant.
#[allow(clippy::too_many_arguments)]
fn observe_sustained_stream_state(
    samples: &mut Vec<StreamStateSample>,
    failure_started: Instant,
    stream_id: StreamId,
    sender_connection: &Connection,
    receiver_connection: &Connection,
    sender_primary: &Path,
    sender_secondary: &Path,
    receiver_primary: &Path,
    receiver_secondary: &Path,
    primary_at_blackhole: PathStats,
    secondary_at_blackhole: PathStats,
    receiver_primary_at_blackhole: PathStats,
    receiver_secondary_at_blackhole: PathStats,
) {
    let sender = sender_connection.stats();
    let receiver = receiver_connection.stats();
    let sender_stream = sender.streams.iter().find(|stream| stream.id == stream_id);
    let receiver_stream = receiver
        .streams
        .iter()
        .find(|stream| stream.id == stream_id);
    let sampled_at = Instant::now();
    let primary = sender_primary.stats();
    let secondary = sender_secondary.stats();
    let receiver_primary = receiver_primary.stats();
    let receiver_secondary = receiver_secondary.stats();

    samples.push(StreamStateSample {
        elapsed_after_fault: failure_started.elapsed(),
        stream_id,
        sender_fully_acked_offset: sender_stream.and_then(|stream| stream.send_fully_acked_offset),
        sender_unacknowledged_bytes: sender_stream
            .and_then(|stream| stream.send_unacknowledged_bytes),
        sender_lowest_retransmit_offset: sender_stream
            .and_then(|stream| stream.send_lowest_retransmit_offset),
        sender_retransmit_bytes: sender_stream.and_then(|stream| stream.send_retransmit_bytes),
        sender_offset: sender_stream.and_then(|stream| stream.send_offset),
        sender_max_stream_data: sender_stream.and_then(|stream| stream.send_max_data),
        sender_stream_flow_control_blocked: sender_stream
            .and_then(|stream| stream.send_flow_control_blocked),
        sender_connection_flow_control_blocked: sender_stream
            .and_then(|stream| stream.send_connection_blocked),
        sender_connection_data: sender.flow_control.send_data,
        sender_max_data: sender.flow_control.send_max_data,
        sender_max_data_blocked: sender.flow_control.send_blocked,
        receiver_contiguous_offset: receiver_stream
            .and_then(|stream| stream.receive_contiguous_offset),
        receiver_highest_offset: receiver_stream.and_then(|stream| stream.receive_highest_offset),
        receiver_sent_max_stream_data: receiver_stream
            .and_then(|stream| stream.receive_sent_max_stream_data),
        receiver_current_max_stream_data: receiver_stream
            .and_then(|stream| stream.receive_current_max_stream_data),
        receiver_max_stream_data_pending: receiver_stream
            .is_some_and(|stream| stream.receive_max_stream_data_pending),
        receiver_max_stream_data_in_flight_packets: receiver_stream
            .map_or(0, |stream| stream.receive_max_stream_data_in_flight_packets),
        receiver_data: receiver.flow_control.receive_data,
        receiver_max_data: receiver.flow_control.receive_max_data,
        receiver_sent_max_data: receiver.flow_control.receive_sent_max_data,
        receiver_max_data_pending: receiver.flow_control.receive_max_data_pending,
        receiver_max_data_in_flight_packets: receiver
            .flow_control
            .receive_max_data_in_flight_packets,
        response_sender_fully_acked_offset: receiver_stream
            .and_then(|stream| stream.send_fully_acked_offset),
        response_sender_unacknowledged_bytes: receiver_stream
            .and_then(|stream| stream.send_unacknowledged_bytes),
        response_sender_lowest_retransmit_offset: receiver_stream
            .and_then(|stream| stream.send_lowest_retransmit_offset),
        response_sender_retransmit_bytes: receiver_stream
            .and_then(|stream| stream.send_retransmit_bytes),
        response_sender_offset: receiver_stream.and_then(|stream| stream.send_offset),
        response_sender_max_stream_data: receiver_stream.and_then(|stream| stream.send_max_data),
        response_sender_flow_control_blocked: receiver_stream
            .and_then(|stream| stream.send_flow_control_blocked),
        response_sender_connection_blocked: receiver_stream
            .and_then(|stream| stream.send_connection_blocked),
        response_receiver_contiguous_offset: sender_stream
            .and_then(|stream| stream.receive_contiguous_offset),
        response_receiver_highest_offset: sender_stream
            .and_then(|stream| stream.receive_highest_offset),
        primary_ack_progress_obligation_stream_id: primary
            .ack_progress_stream_obligation
            .map(|(id, _)| id),
        primary_ack_progress_obligation_offset: primary
            .ack_progress_stream_obligation
            .map(|(_, offset)| offset),
        primary_ack_progress_obligation_age: primary
            .ack_progress_start
            .map(|start| sampled_at.saturating_duration_since(start)),
        primary_ack_progress_deadline_remaining: primary
            .ack_progress_recovery_deadline
            .map(|deadline| deadline.saturating_duration_since(sampled_at)),
        primary_ack_progress_full_recovery_deadline_remaining: primary
            .ack_progress_full_recovery_deadline
            .map(|deadline| deadline.saturating_duration_since(sampled_at)),
        primary_ack_progress_service_deadline: primary.ack_progress_service_deadline,
        primary_ack_progress_alternative_recovery_budget: primary
            .ack_progress_alternative_recovery_budget,
        primary_ack_progress_feedback_probe_staged: primary.ack_progress_feedback_probe_staged,
        primary_ack_progress_timer_armed: primary.ack_progress_recovery_timer_armed,
        primary_ack_progress_stream_frames_in_flight: primary.ack_progress_stream_frames_in_flight,
        primary_ack_progress_has_cross_path_alternative: primary
            .ack_progress_has_cross_path_alternative,
        primary_ack_progress_pto_recovery_probe_active: primary
            .ack_progress_pto_recovery_probe_active,
        primary_authenticated_feedback_age: primary
            .last_authenticated_at
            .map(|last| sampled_at.saturating_duration_since(last)),
        secondary_authenticated_feedback_age: secondary
            .last_authenticated_at
            .map(|last| sampled_at.saturating_duration_since(last)),
        primary_stream_progress_updates: primary
            .stream_progress_updates
            .saturating_sub(primary_at_blackhole.stream_progress_updates),
        primary_stream_progress_acked_bytes: primary
            .stream_progress_acked_bytes
            .saturating_sub(primary_at_blackhole.stream_progress_acked_bytes),
        secondary_stream_progress_updates: secondary
            .stream_progress_updates
            .saturating_sub(secondary_at_blackhole.stream_progress_updates),
        secondary_stream_progress_acked_bytes: secondary
            .stream_progress_acked_bytes
            .saturating_sub(secondary_at_blackhole.stream_progress_acked_bytes),
        secondary_ack_progress_has_cross_path_alternative: secondary
            .ack_progress_has_cross_path_alternative,
        secondary_lost_packets: secondary
            .lost_packets
            .saturating_sub(secondary_at_blackhole.lost_packets),
        secondary_stream_retransmit_bytes: secondary
            .frame_tx
            .stream_retransmit_bytes
            .saturating_sub(secondary_at_blackhole.frame_tx.stream_retransmit_bytes),
        secondary_pto_timeouts: secondary
            .pto_timeouts
            .saturating_sub(secondary_at_blackhole.pto_timeouts),
        secondary_stream_gap_rescue_probes: secondary
            .stream_gap_rescue_probes
            .saturating_sub(secondary_at_blackhole.stream_gap_rescue_probes),
        secondary_stream_gap_rescue_bytes: secondary
            .stream_gap_rescue_bytes
            .saturating_sub(secondary_at_blackhole.stream_gap_rescue_bytes),
        secondary_rtt: secondary.rtt,
        secondary_pto: secondary.pto,
        secondary_cwnd: secondary.cwnd,
        secondary_bytes_in_flight: secondary.bytes_in_flight,
        secondary_ack_eliciting_packets_in_flight: secondary.ack_eliciting_packets_in_flight,
        secondary_tracked_sent_packets: secondary.tracked_sent_packets,
        secondary_tracked_ack_eliciting_packets: secondary.tracked_ack_eliciting_packets,
        secondary_latest_ack_eliciting_packet_number: secondary.latest_ack_eliciting_packet_number,
        secondary_pto_count: secondary.pto_count,
        secondary_loss_detection_timer_armed: secondary.loss_detection_timer_armed,
        receiver_primary_tracked_max_data_packets: receiver_primary.tracked_max_data_packets,
        receiver_primary_tracked_max_stream_data_packets: receiver_primary
            .tracked_max_stream_data_packets,
        receiver_primary_pto_count: receiver_primary.pto_count,
        receiver_primary_loss_detection_timer_armed: receiver_primary.loss_detection_timer_armed,
        receiver_primary_stream_fresh_bytes: receiver_primary
            .frame_tx
            .stream_fresh_bytes
            .saturating_sub(receiver_primary_at_blackhole.frame_tx.stream_fresh_bytes),
        receiver_secondary_tracked_max_data_packets: receiver_secondary.tracked_max_data_packets,
        receiver_secondary_tracked_max_stream_data_packets: receiver_secondary
            .tracked_max_stream_data_packets,
        receiver_secondary_pto_count: receiver_secondary.pto_count,
        receiver_secondary_loss_detection_timer_armed: receiver_secondary
            .loss_detection_timer_armed,
        receiver_secondary_stream_fresh_bytes: receiver_secondary
            .frame_tx
            .stream_fresh_bytes
            .saturating_sub(receiver_secondary_at_blackhole.frame_tx.stream_fresh_bytes),
        receiver_secondary_stream_retransmit_bytes: receiver_secondary
            .frame_tx
            .stream_retransmit_bytes
            .saturating_sub(
                receiver_secondary_at_blackhole
                    .frame_tx
                    .stream_retransmit_bytes,
            ),
        receiver_secondary_lost_packets: receiver_secondary
            .lost_packets
            .saturating_sub(receiver_secondary_at_blackhole.lost_packets),
        receiver_secondary_pto_timeouts: receiver_secondary
            .pto_timeouts
            .saturating_sub(receiver_secondary_at_blackhole.pto_timeouts),
        receiver_secondary_bytes_in_flight: receiver_secondary.bytes_in_flight,
        receiver_secondary_ack_eliciting_packets_in_flight: receiver_secondary
            .ack_eliciting_packets_in_flight,
        receiver_secondary_tracked_sent_packets: receiver_secondary.tracked_sent_packets,
        receiver_secondary_tracked_ack_eliciting_packets: receiver_secondary
            .tracked_ack_eliciting_packets,
    });
}

fn record_first_timeline_event(slot: &mut Option<Duration>, happened: bool, elapsed: Duration) {
    if slot.is_none() && happened {
        *slot = Some(elapsed);
    }
}

async fn start_connection(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
) -> LabResult<RunningLab> {
    start_connection_with_scheduler(
        client_ip,
        path_idle_timeout,
        pto_recovery,
        MultipathScheduler::NoqDefault,
    )
    .await
}

async fn start_connection_with_scheduler(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
) -> LabResult<RunningLab> {
    start_connection_with_scheduler_and_congestion(
        client_ip,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        QuicCongestion::Cubic,
    )
    .await
}

async fn start_connection_with_scheduler_and_congestion(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
    congestion: QuicCongestion,
) -> LabResult<RunningLab> {
    start_connection_internal(
        client_ip,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        congestion,
        LabInstrumentation::default(),
    )
    .await
}

async fn start_connection_with_sustained_observer(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
) -> LabResult<(RunningLab, mpsc::UnboundedReceiver<SustainedServerEvent>)> {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let lab = start_connection_internal(
        client_ip,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        QuicCongestion::Cubic,
        LabInstrumentation {
            sustained_events: Some(events_tx),
            ..LabInstrumentation::default()
        },
    )
    .await?;
    Ok((lab, events_rx))
}

async fn start_connection_with_realtime_datagram_observer(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
) -> LabResult<(
    RunningLab,
    mpsc::UnboundedReceiver<realtime::RealtimeDatagramEvent>,
)> {
    start_connection_with_realtime_datagram_observer_and_congestion(
        client_ip,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        QuicCongestion::Cubic,
    )
    .await
}

async fn start_connection_with_realtime_datagram_observer_and_congestion(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
    congestion: QuicCongestion,
) -> LabResult<(
    RunningLab,
    mpsc::UnboundedReceiver<realtime::RealtimeDatagramEvent>,
)> {
    start_connection_with_realtime_datagram_observer_and_transport(
        client_ip,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        congestion,
        None,
    )
    .await
}

async fn start_connection_with_realtime_datagram_observer_and_transport(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
    congestion: QuicCongestion,
    segmentation_offload: Option<bool>,
) -> LabResult<(
    RunningLab,
    mpsc::UnboundedReceiver<realtime::RealtimeDatagramEvent>,
)> {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let lab = start_connection_internal(
        client_ip,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        congestion,
        LabInstrumentation {
            segmentation_offload,
            realtime_datagram_events: Some(events_tx),
            ..LabInstrumentation::default()
        },
    )
    .await?;
    Ok((lab, events_rx))
}

async fn start_connection_internal(
    client_ip: Ipv4Addr,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
    congestion: QuicCongestion,
    instrumentation: LabInstrumentation,
) -> LabResult<RunningLab> {
    let LabInstrumentation {
        declared_backlogged_epoch_sensor,
        segmentation_offload,
        sustained_events,
        realtime_datagram_events,
    } = instrumentation;
    let (server_config, client_config) = make_configs(
        path_idle_timeout,
        pto_recovery,
        scheduler,
        congestion,
        declared_backlogged_epoch_sensor,
        segmentation_offload,
    )?;
    let server_endpoint =
        Endpoint::server(server_config, SocketAddr::new(IpAddr::V4(LINE_ONE_IP), 0))?;
    let server_addr = server_endpoint.local_addr()?;
    let (server_connection_tx, server_connection_rx) = oneshot::channel();

    let server_task = tokio::spawn(async move {
        let incoming = timeout(OPERATION_TIMEOUT, server_endpoint.accept())
            .await
            .map_err(|_| other_error("服务端等待连接超时"))?
            .ok_or_else(|| other_error("服务端提前停止监听"))?;
        let connection = timeout(OPERATION_TIMEOUT, incoming)
            .await
            .map_err(|_| other_error("服务端握手超时"))??;
        server_connection_tx
            .send(connection.clone())
            .map_err(|_| other_error("实验控制器没有接收服务端连接"))?;
        serve_connection(connection, sustained_events, realtime_datagram_events).await
    });

    let client_endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(client_ip), 0))?;
    client_endpoint.set_default_client_config(client_config);

    let connection = timeout(
        OPERATION_TIMEOUT,
        client_endpoint
            .connect(server_addr, "localhost")
            .map_err(|error| other_error(format!("客户端无法开始连接：{error}")))?,
    )
    .await
    .map_err(|_| other_error("客户端握手超时"))??;
    let server_connection = timeout(OPERATION_TIMEOUT, server_connection_rx)
        .await
        .map_err(|_| other_error("等待服务端连接句柄超时"))?
        .map_err(|_| other_error("服务端没有返回连接句柄"))?;

    if !connection.is_multipath_enabled() {
        connection.close(0_u8.into(), b"multipath negotiation failed");
        return Err(other_error("客户端和服务端没有协商成功 MPQUIC"));
    }

    let primary = connection
        .path(PathId::ZERO)
        .ok_or_else(|| other_error("连接成功后找不到主路径"))?;

    Ok(RunningLab {
        server_task,
        server_connection,
        client_endpoint,
        connection,
        server_addr,
        primary,
    })
}

fn make_configs(
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    scheduler: MultipathScheduler,
    congestion: QuicCongestion,
    declared_backlogged_epoch_sensor: bool,
    segmentation_offload: Option<bool>,
) -> LabResult<(ServerConfig, ClientConfig)> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = CertificateDer::from(generated.cert);
    let private_key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())?;
    let server_transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| other_error("无法配置服务端传输参数"))?;
    configure_transport(
        server_transport,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        congestion,
        declared_backlogged_epoch_sensor,
    );
    if let Some(enabled) = segmentation_offload {
        server_transport.enable_segmentation_offload(enabled);
    }

    let mut roots = noq::rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;
    let mut client_transport = TransportConfig::default();
    configure_transport(
        &mut client_transport,
        path_idle_timeout,
        pto_recovery,
        scheduler,
        congestion,
        declared_backlogged_epoch_sensor,
    );
    if let Some(enabled) = segmentation_offload {
        client_transport.enable_segmentation_offload(enabled);
    }
    client_config.transport_config(Arc::new(client_transport));

    Ok((server_config, client_config))
}

fn configure_transport(
    transport: &mut TransportConfig,
    path_idle_timeout: Option<Duration>,
    pto_recovery: PtoRecovery,
    _scheduler: MultipathScheduler,
    congestion: QuicCongestion,
    declared_backlogged_epoch_sensor: bool,
) {
    match congestion {
        QuicCongestion::Cubic => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        QuicCongestion::Bbr3 => {
            transport.congestion_controller_factory(Arc::new(Bbr3Config::default()));
        }
    }
    transport
        .max_concurrent_multipath_paths(2)
        .cross_path_pto_reinjection(pto_recovery.pto_reinjection_enabled())
        .cross_path_abandon_reinjection(pto_recovery.abandon_reinjection_enabled())
        .cross_path_ack_progress_reinjection(pto_recovery.ack_progress_reinjection_enabled())
        .cross_path_ack_progress_stream_obligation(
            pto_recovery.ack_progress_stream_obligation_enabled(),
        )
        .cross_path_ack_progress_service_deadline(pto_recovery.ack_progress_service_deadline())
        .cross_path_ack_progress_service_recovery_flights(
            pto_recovery.ack_progress_service_recovery_flights(),
        )
        .cross_path_ack_progress_fresh_alternative(
            pto_recovery.ack_progress_fresh_alternative_enabled(),
        )
        .cross_path_ack_progress_feedback_stability(
            pto_recovery.ack_progress_feedback_stability_enabled(),
        )
        .cross_path_ack_progress_alternative_stability(
            pto_recovery.ack_progress_alternative_stability_enabled(),
        )
        .cross_path_ack_progress_feedback_probe(pto_recovery.feedback_probe_enabled())
        .cross_path_ack_progress_feedback_evidence_reinjection(
            pto_recovery.feedback_evidence_reinjection_enabled(),
        )
        .stream_gap_rescue(pto_recovery.stream_gap_rescue_enabled())
        .stream_gap_watch_rescue(pto_recovery.stream_gap_watch_rescue_enabled())
        .stream_gap_delivery_watch_rescue(pto_recovery.stream_gap_delivery_watch_rescue_enabled())
        .cross_path_ack_escape(pto_recovery.ack_escape_enabled())
        .cross_path_feedback_handoff(pto_recovery.feedback_handoff_enabled())
        .cross_path_feedback_credit_snapshot(pto_recovery.feedback_credit_snapshot_enabled())
        .cross_path_feedback_stream_progress_snapshot(
            pto_recovery.feedback_stream_progress_snapshot_enabled(),
        )
        .cross_path_blocked_credit_handoff(pto_recovery.blocked_credit_handoff_enabled())
        .cross_path_stream_progress(pto_recovery.stream_progress_enabled())
        .declared_backlogged_epoch_sensor(declared_backlogged_epoch_sensor)
        .default_path_max_idle_timeout(path_idle_timeout)
        .default_path_keep_alive_interval(Some(Duration::from_millis(200)))
        .datagram_receive_buffer_size(Some(1024 * 1024))
        .datagram_send_buffer_size(1024 * 1024);
}

async fn serve_connection(
    connection: Connection,
    sustained_events: Option<mpsc::UnboundedSender<SustainedServerEvent>>,
    realtime_datagram_events: Option<mpsc::UnboundedSender<realtime::RealtimeDatagramEvent>>,
) -> LabResult<()> {
    let datagram_connection = connection.clone();
    let datagram_task = tokio::spawn(async move {
        loop {
            let data = match datagram_connection.read_datagram().await {
                Ok(data) => data,
                Err(ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed) => {
                    return Ok::<(), LabError>(());
                }
                Err(error) => return Err(error.into()),
            };

            if let Some(events) = realtime_datagram_events.as_ref() {
                if events
                    .send(realtime::RealtimeDatagramEvent {
                        data: data.to_vec(),
                        received_at: Instant::now(),
                    })
                    .is_err()
                {
                    return Ok::<(), LabError>(());
                }
                continue;
            }

            datagram_connection
                .send_datagram_wait(data)
                .await
                .map_err(|error| other_error(format!("服务端回显 Datagram 失败：{error}")))?;
        }
    });

    loop {
        let (send, receive) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed) => break,
            Err(error) => return Err(error.into()),
        };

        let stream_events = sustained_events.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_stream(send, receive, stream_events).await {
                eprintln!("服务端处理数据流失败：{error}");
            }
        });
    }

    match datagram_task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(other_error(format!("Datagram 回显任务异常退出：{error}"))),
    }
}

async fn handle_stream(
    mut send: noq::SendStream,
    mut receive: noq::RecvStream,
    sustained_events: Option<mpsc::UnboundedSender<SustainedServerEvent>>,
) -> LabResult<()> {
    let mut header = [0_u8; 8];
    receive.read_exact(&mut header).await?;

    if &header[..4] == FAILOVER_MAGIC {
        return handle_progress_stream(send, receive, header).await;
    }

    if &header[..4] == SUSTAINED_FAILOVER_MAGIC {
        return handle_sustained_failover_stream(send, receive, header, sustained_events).await;
    }

    let remaining = receive.read_to_end(MAX_FRAME_SIZE - header.len()).await?;
    let mut request = Vec::with_capacity(header.len() + remaining.len());
    request.extend_from_slice(&header);
    request.extend_from_slice(&remaining);
    let response = match parse_frame(&request) {
        Ok(payload) => make_success_response(payload),
        Err(reason) => make_error_response(reason),
    };

    send.write_all(&response).await?;
    send.finish()?;
    Ok(())
}

async fn handle_progress_stream(
    mut send: noq::SendStream,
    mut receive: noq::RecvStream,
    header: [u8; 8],
) -> LabResult<()> {
    let declared =
        u32::from_be_bytes(header[4..8].try_into().expect("长度字段固定为 4 字节")) as usize;
    if declared == 0 || declared > MAX_PAYLOAD_SIZE {
        send.write_all(&make_error_response("进度传输长度不合法"))
            .await?;
        send.finish()?;
        return Ok(());
    }

    let mut first_byte = [0_u8; 1];
    receive.read_exact(&mut first_byte).await?;
    send.write_all(FAILOVER_PROGRESS).await?;

    let remaining = receive.read_to_end(declared - 1).await?;
    if remaining.len() != declared - 1 {
        send.write_all(&make_error_response("进度传输提前结束"))
            .await?;
        send.finish()?;
        return Ok(());
    }

    let mut payload = Vec::with_capacity(declared);
    payload.push(first_byte[0]);
    payload.extend_from_slice(&remaining);
    send.write_all(&make_success_response(&payload)).await?;
    send.finish()?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct SustainedStreamRequest {
    direction: FailoverDirection,
    duration: Duration,
    chunk_size: usize,
    seed: u8,
}

async fn handle_sustained_failover_stream(
    mut send: noq::SendStream,
    mut receive: noq::RecvStream,
    first: [u8; 8],
    sustained_events: Option<mpsc::UnboundedSender<SustainedServerEvent>>,
) -> LabResult<()> {
    let result = async {
        let request = read_sustained_stream_request(&mut receive, first).await?;
        send.write_all(SUSTAINED_FAILOVER_READY).await?;

        let mut go = [0_u8; 1];
        receive.read_exact(&mut go).await?;
        if go[0] != SUSTAINED_FAILOVER_GO {
            return Err(other_error("持续换网实验缺少开始标记"));
        }

        match request.direction {
            FailoverDirection::ClientToServer => {
                let trace = receive_sustained_records(
                    &mut receive,
                    request.chunk_size,
                    request.seed,
                    sustained_events.as_ref(),
                )
                .await?;
                let response = make_sustained_success_response(trace.records, trace.bytes);
                send.write_all(&response).await?;
                send.finish()?;
            }
            FailoverDirection::ServerToClient => {
                let trailing = receive.read_to_end(1).await?;
                if !trailing.is_empty() {
                    return Err(other_error("反向持续换网请求包含多余数据"));
                }
                write_sustained_records(
                    &mut send,
                    request.duration,
                    request.chunk_size,
                    request.seed,
                )
                .await?;
            }
        }
        Ok(())
    }
    .await;

    if let Err(error) = &result
        && let Some(events) = sustained_events
    {
        let _ = events.send(SustainedServerEvent::Failed(error.to_string()));
    }
    result
}

async fn read_sustained_stream_request(
    receive: &mut noq::RecvStream,
    first: [u8; 8],
) -> LabResult<SustainedStreamRequest> {
    let mut header = [0_u8; SUSTAINED_FAILOVER_HEADER_SIZE];
    header[..first.len()].copy_from_slice(&first);
    receive.read_exact(&mut header[first.len()..]).await?;

    if &header[..4] != SUSTAINED_FAILOVER_MAGIC
        || header[5..8] != [0; 3]
        || header[17..20] != [0; 3]
    {
        return Err(other_error("持续换网实验请求头格式不正确"));
    }

    let direction = FailoverDirection::try_from(header[4])?;
    let duration_millis = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .expect("持续换网实验时长固定为 4 字节"),
    );
    let chunk_size = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .expect("持续换网实验记录大小固定为 4 字节"),
    ) as usize;
    let duration = Duration::from_millis(duration_millis.into());
    if duration.is_zero() || duration > MAX_SUSTAINED_MEASUREMENT {
        return Err(other_error("持续换网实验请求的时长不合法"));
    }
    if !(SUSTAINED_RECORD_HEADER_SIZE..=MAX_PAYLOAD_SIZE).contains(&chunk_size) {
        return Err(other_error("持续换网实验请求的记录大小不合法"));
    }

    Ok(SustainedStreamRequest {
        direction,
        duration,
        chunk_size,
        seed: header[16],
    })
}

fn make_sustained_stream_request(config: SustainedFailoverConfig) -> LabResult<[u8; 20]> {
    let duration_millis = u32::try_from(config.total_duration.as_millis())
        .map_err(|_| other_error("持续换网实验时长无法写入请求头"))?;
    let chunk_size = u32::try_from(config.chunk_size)
        .map_err(|_| other_error("持续换网实验记录大小无法写入请求头"))?;
    let mut header = [0_u8; SUSTAINED_FAILOVER_HEADER_SIZE];
    header[..4].copy_from_slice(SUSTAINED_FAILOVER_MAGIC);
    header[4] = config.direction as u8;
    header[8..12].copy_from_slice(&duration_millis.to_be_bytes());
    header[12..16].copy_from_slice(&chunk_size.to_be_bytes());
    header[16] = config.seed;
    Ok(header)
}

fn make_sustained_success_response(records: u64, bytes: u64) -> [u8; 20] {
    let mut response = [0_u8; 20];
    response[..4].copy_from_slice(SUSTAINED_FAILOVER_OK);
    response[4..12].copy_from_slice(&records.to_be_bytes());
    response[12..20].copy_from_slice(&bytes.to_be_bytes());
    response
}

fn parse_sustained_success_response(response: &[u8]) -> LabResult<(u64, u64)> {
    if response.len() != 20 || &response[..4] != SUSTAINED_FAILOVER_OK {
        return Err(other_error("服务端没有返回有效的持续换网校验结果"));
    }
    let records = u64::from_be_bytes(
        response[4..12]
            .try_into()
            .expect("持续换网记录数固定为 8 字节"),
    );
    let bytes = u64::from_be_bytes(
        response[12..20]
            .try_into()
            .expect("持续换网字节数固定为 8 字节"),
    );
    Ok((records, bytes))
}

async fn start_continuous_writer(
    connection: &Connection,
    chunk_size: usize,
    seed: u8,
) -> LabResult<(
    JoinHandle<LabResult<(u64, u64)>>,
    oneshot::Sender<()>,
    Arc<AtomicU64>,
)> {
    let request_config = SustainedFailoverConfig::new(
        MultipathScheduler::NoqDefault,
        PtoRecovery::Disabled,
        FailoverDirection::ClientToServer,
        Duration::from_secs(1),
        Duration::from_millis(500),
        chunk_size,
        seed,
    );
    let (mut send, mut receive) = timeout(OPERATION_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| other_error("打开持续 writer 上传流超时"))??;
    let request = make_sustained_stream_request(request_config)?;
    timeout(OPERATION_TIMEOUT, send.write_all(&request))
        .await
        .map_err(|_| other_error("发送持续 writer 上传请求超时"))??;

    let mut ready = [0_u8; SUSTAINED_FAILOVER_READY.len()];
    timeout(OPERATION_TIMEOUT, receive.read_exact(&mut ready))
        .await
        .map_err(|_| other_error("等待持续 writer 服务端就绪超时"))??;
    if &ready != SUSTAINED_FAILOVER_READY {
        return Err(other_error("持续 writer 服务端没有返回就绪标记"));
    }
    timeout(OPERATION_TIMEOUT, send.write_all(&[SUSTAINED_FAILOVER_GO]))
        .await
        .map_err(|_| other_error("发送持续 writer 开始标记超时"))??;

    let (stop_tx, stop_rx) = oneshot::channel();
    let completed_bytes = Arc::new(AtomicU64::new(0));
    let writer_completed_bytes = Arc::clone(&completed_bytes);
    let task = tokio::spawn(async move {
        run_declared_backlogged_writer(
            &mut send,
            &mut receive,
            stop_rx,
            writer_completed_bytes,
            chunk_size,
            seed,
        )
        .await
    });
    Ok((task, stop_tx, completed_bytes))
}

async fn run_declared_backlogged_writer(
    send: &mut noq::SendStream,
    receive: &mut noq::RecvStream,
    mut stop: oneshot::Receiver<()>,
    completed_bytes: Arc<AtomicU64>,
    chunk_size: usize,
    seed: u8,
) -> LabResult<(u64, u64)> {
    let mut sequence = 0_u64;
    let mut bytes = 0_u64;
    let mut payload = vec![0_u8; chunk_size];

    loop {
        match stop.try_recv() {
            Ok(()) | Err(oneshot::error::TryRecvError::Closed) => break,
            Err(oneshot::error::TryRecvError::Empty) => {}
        }

        fill_sustained_payload(&mut payload, seed, sequence);
        let mut header = [0_u8; SUSTAINED_RECORD_HEADER_SIZE];
        header[..8].copy_from_slice(&sequence.to_be_bytes());
        header[8..].copy_from_slice(&digest(&payload).to_be_bytes());
        timeout(OPERATION_TIMEOUT, async {
            send.write_all(&header).await?;
            send.write_all(&payload).await?;
            Ok::<(), LabError>(())
        })
        .await
        .map_err(|_| other_error("持续 writer 记录发送超时"))??;

        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| other_error("持续 writer 记录编号溢出"))?;
        bytes = bytes
            .checked_add(chunk_size as u64)
            .ok_or_else(|| other_error("持续 writer 累计字节数溢出"))?;
        completed_bytes.store(bytes, Ordering::Relaxed);
    }

    let mut end = [0_u8; SUSTAINED_RECORD_HEADER_SIZE];
    end[..8].copy_from_slice(&SUSTAINED_RECORD_END.to_be_bytes());
    end[8..].copy_from_slice(&sequence.to_be_bytes());
    timeout(OPERATION_TIMEOUT, send.write_all(&end))
        .await
        .map_err(|_| other_error("持续 writer 结束标记发送超时"))??;
    send.finish()?;

    let response = timeout(OPERATION_TIMEOUT, receive.read_to_end(64))
        .await
        .map_err(|_| other_error("等待持续 writer 完整性响应超时"))??;
    let (received_records, received_bytes) = parse_sustained_success_response(&response)?;
    if (sequence, bytes) != (received_records, received_bytes) {
        return Err(other_error("持续 writer 上传的记录数或业务字节数不一致"));
    }
    Ok((sequence, bytes))
}

async fn write_sustained_records(
    send: &mut noq::SendStream,
    duration: Duration,
    chunk_size: usize,
    seed: u8,
) -> LabResult<(u64, u64, Duration)> {
    let started = Instant::now();
    let mut sequence = 0_u64;
    let mut bytes = 0_u64;
    let mut payload = vec![0_u8; chunk_size];

    while started.elapsed() < duration {
        fill_sustained_payload(&mut payload, seed, sequence);
        let mut header = [0_u8; SUSTAINED_RECORD_HEADER_SIZE];
        header[..8].copy_from_slice(&sequence.to_be_bytes());
        header[8..].copy_from_slice(&digest(&payload).to_be_bytes());
        timeout(OPERATION_TIMEOUT, async {
            send.write_all(&header).await?;
            send.write_all(&payload).await?;
            Ok::<(), LabError>(())
        })
        .await
        .map_err(|_| other_error("持续换网数据记录发送超时"))??;

        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| other_error("持续换网记录编号溢出"))?;
        bytes = bytes
            .checked_add(chunk_size as u64)
            .ok_or_else(|| other_error("持续换网累计字节数溢出"))?;
    }

    let mut end = [0_u8; SUSTAINED_RECORD_HEADER_SIZE];
    end[..8].copy_from_slice(&SUSTAINED_RECORD_END.to_be_bytes());
    end[8..].copy_from_slice(&sequence.to_be_bytes());
    timeout(OPERATION_TIMEOUT, send.write_all(&end))
        .await
        .map_err(|_| other_error("持续换网结束标记发送超时"))??;
    send.finish()?;
    Ok((sequence, bytes, started.elapsed()))
}

async fn receive_sustained_records(
    receive: &mut noq::RecvStream,
    chunk_size: usize,
    seed: u8,
    sustained_events: Option<&mpsc::UnboundedSender<SustainedServerEvent>>,
) -> LabResult<SustainedReceiveTrace> {
    let started = Instant::now();
    let mut expected_sequence = 0_u64;
    let mut bytes = 0_u64;
    let mut payload = vec![0_u8; chunk_size];
    let mut received_at = Vec::new();

    loop {
        let mut header = [0_u8; SUSTAINED_RECORD_HEADER_SIZE];
        timeout(OPERATION_TIMEOUT, receive.read_exact(&mut header))
            .await
            .map_err(|_| other_error("等待持续换网数据记录超时"))??;
        let sequence = u64::from_be_bytes(
            header[..8]
                .try_into()
                .expect("持续换网记录编号固定为 8 字节"),
        );
        let expected_digest =
            u64::from_be_bytes(header[8..].try_into().expect("持续换网摘要固定为 8 字节"));

        if sequence == SUSTAINED_RECORD_END {
            if expected_digest != expected_sequence {
                return Err(other_error("持续换网结束标记的记录总数不正确"));
            }
            let trailing = receive.read_to_end(1).await?;
            if !trailing.is_empty() {
                return Err(other_error("持续换网结束标记后仍有多余数据"));
            }
            if let Some(events) = sustained_events {
                events
                    .send(SustainedServerEvent::Finished {
                        records: expected_sequence,
                        bytes,
                    })
                    .map_err(|_| other_error("持续换网服务端事件接收端已关闭"))?;
            }
            return Ok(SustainedReceiveTrace {
                received_at,
                records: expected_sequence,
                bytes,
                elapsed: started.elapsed(),
            });
        }

        if sequence != expected_sequence {
            return Err(other_error(format!(
                "持续换网记录编号错误：期望 {expected_sequence}，实际 {sequence}"
            )));
        }
        timeout(OPERATION_TIMEOUT, receive.read_exact(&mut payload))
            .await
            .map_err(|_| other_error(format!("等待持续换网记录 {sequence} 载荷超时")))??;
        if !sustained_payload_is_valid(&payload, seed, sequence)
            || digest(&payload) != expected_digest
        {
            return Err(other_error(format!(
                "持续换网记录 {sequence} 的内容摘要不正确"
            )));
        }

        let now = Instant::now();
        received_at.push(now);
        if let Some(events) = sustained_events {
            events
                .send(SustainedServerEvent::Record {
                    sequence,
                    received_at: now,
                })
                .map_err(|_| other_error("持续换网服务端事件接收端已关闭"))?;
        }
        expected_sequence += 1;
        bytes = bytes
            .checked_add(chunk_size as u64)
            .ok_or_else(|| other_error("持续换网接收字节数溢出"))?;
    }
}

fn fill_sustained_payload(payload: &mut [u8], seed: u8, sequence: u64) {
    let sequence = sequence as u8;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add(sequence)
            .wrapping_add((index as u8).wrapping_mul(31));
    }
}

fn sustained_payload_is_valid(payload: &[u8], seed: u8, sequence: u64) -> bool {
    let sequence = sequence as u8;
    payload.iter().enumerate().all(|(index, byte)| {
        *byte
            == seed
                .wrapping_add(sequence)
                .wrapping_add((index as u8).wrapping_mul(31))
    })
}

struct PreparedTransfer {
    request: Vec<u8>,
    payload_size: usize,
    expected_digest: u64,
}

impl PreparedTransfer {
    fn new(size: usize, seed: u8) -> Self {
        let payload = make_payload(size, seed);
        Self {
            request: make_frame(&payload),
            payload_size: size,
            expected_digest: digest(&payload),
        }
    }
}

async fn transfer_and_verify(connection: &Connection, size: usize, seed: u8) -> LabResult<()> {
    let transfer = PreparedTransfer::new(size, seed);
    transfer_prepared_and_verify(connection, &transfer).await
}

struct FailoverTransferTiming {
    recovery_time: Duration,
    completion_time: Duration,
}

async fn transfer_and_verify_with_progress(
    connection: &Connection,
    size: usize,
    seed: u8,
    failure_started: Instant,
) -> LabResult<FailoverTransferTiming> {
    let payload = make_payload(size, seed);
    let expected_digest = digest(&payload);
    let mut request = Vec::with_capacity(payload.len() + 8);
    request.extend_from_slice(FAILOVER_MAGIC);
    request.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    request.extend_from_slice(&payload);

    let (mut send, mut receive) = connection.open_bi().await?;
    let sender = async {
        send.write_all(&request).await?;
        send.finish()?;
        Ok::<(), LabError>(())
    };
    let receiver = async {
        let mut progress = [0_u8; FAILOVER_PROGRESS.len()];
        receive.read_exact(&mut progress).await?;
        if &progress != FAILOVER_PROGRESS {
            return Err(other_error("服务端没有返回有效的恢复进度标记"));
        }
        let recovery_time = failure_started.elapsed();

        let response = receive.read_to_end(64).await?;
        verify_success_response(&response, size, expected_digest)?;
        Ok(FailoverTransferTiming {
            recovery_time,
            completion_time: failure_started.elapsed(),
        })
    };
    let (sender, receiver) = tokio::join!(sender, receiver);

    sender?;
    receiver
}

async fn transfer_for_duration(
    connection: &Connection,
    duration: Duration,
    chunk_size: usize,
    seed: u8,
) -> LabResult<(usize, Duration)> {
    let transfer = PreparedTransfer::new(chunk_size, seed);
    let started = Instant::now();
    let mut transferred = 0usize;

    while started.elapsed() < duration {
        transfer_prepared_and_verify(connection, &transfer).await?;
        transferred = transferred
            .checked_add(chunk_size)
            .ok_or_else(|| other_error("持续实验累计字节数溢出"))?;
    }

    Ok((transferred, started.elapsed()))
}

async fn transfer_prepared_and_verify(
    connection: &Connection,
    transfer: &PreparedTransfer,
) -> LabResult<()> {
    let (mut send, mut receive) = timeout(OPERATION_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| other_error("打开数据流超时"))??;
    timeout(OPERATION_TIMEOUT, send.write_all(&transfer.request))
        .await
        .map_err(|_| other_error("发送测试数据超时"))??;
    send.finish()?;

    let response = timeout(OPERATION_TIMEOUT, receive.read_to_end(64))
        .await
        .map_err(|_| other_error("等待服务端校验结果超时"))??;
    verify_success_response(&response, transfer.payload_size, transfer.expected_digest)
}

async fn send_malformed_frame(connection: &Connection) -> LabResult<bool> {
    let (mut send, mut receive) = timeout(OPERATION_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| other_error("打开错误输入测试流超时"))??;
    send.write_all(b"this is not a FlowWeave frame").await?;
    send.finish()?;

    let response = timeout(OPERATION_TIMEOUT, receive.read_to_end(256))
        .await
        .map_err(|_| other_error("等待错误输入响应超时"))??;
    Ok(response.starts_with(b"ER:"))
}

async fn datagram_echo_test(connection: &Connection, count: usize) -> LabResult<Vec<Duration>> {
    let mut latencies = Vec::with_capacity(count);

    for sequence in 0..count {
        let payload = format!("FW-DATAGRAM-{sequence:04}").into_bytes();
        let started = Instant::now();
        timeout(
            OPERATION_TIMEOUT,
            connection.send_datagram_wait(payload.clone().into()),
        )
        .await
        .map_err(|_| other_error("发送 Datagram 超时"))??;

        let echoed = timeout(OPERATION_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| other_error("等待 Datagram 回显超时"))??;
        if echoed.as_ref() != payload {
            return Err(other_error("Datagram 回显内容与发送内容不一致"));
        }
        latencies.push(started.elapsed());
    }

    Ok(latencies)
}

async fn datagram_echo_probe(
    connection: &Connection,
    count: usize,
) -> LabResult<DatagramMeasurement> {
    if count == 0 {
        return Ok(DatagramMeasurement {
            sent: 0,
            echoed: 0,
            p50: None,
            p95: None,
            p99: None,
        });
    }

    let read_connection = connection.clone();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        loop {
            let data = match read_connection.read_datagram().await {
                Ok(data) => data,
                Err(error) => {
                    let _ = event_sender
                        .send(Err(other_error(format!("读取 Datagram 探针失败：{error}"))));
                    break;
                }
            };

            let event = parse_datagram_probe(&data).map(|sequence| (sequence, Instant::now()));
            if event_sender.send(event).is_err() {
                break;
            }
        }
    });

    let probe_result: LabResult<DatagramMeasurement> = async {
        let mut sent_at = Vec::with_capacity(count);
        for sequence in 0..count {
            let mut payload = Vec::with_capacity(DATAGRAM_PROBE_SIZE);
            payload.extend_from_slice(DATAGRAM_MAGIC);
            payload.extend_from_slice(&(sequence as u32).to_be_bytes());

            sent_at.push(Instant::now());
            timeout(
                OPERATION_TIMEOUT,
                connection.send_datagram_wait(payload.into()),
            )
            .await
            .map_err(|_| other_error("发送 Datagram 探针超时"))??;
            sleep(DATAGRAM_SEND_INTERVAL).await;
        }

        let deadline = Instant::now() + DATAGRAM_RECEIVE_GRACE;
        let mut received = vec![false; count];
        let mut latencies = Vec::with_capacity(count);

        while latencies.len() < count {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            let event = match timeout(remaining, events.recv()).await {
                Ok(Some(event)) => event?,
                Ok(None) => return Err(other_error("Datagram 探针读取任务提前退出")),
                Err(_) => break,
            };
            let (sequence, received_at) = event;
            if sequence >= count {
                return Err(other_error("收到超出范围的 Datagram 探针编号"));
            }
            if !received[sequence] {
                received[sequence] = true;
                latencies.push(received_at.saturating_duration_since(sent_at[sequence]));
            }
        }

        Ok(DatagramMeasurement {
            sent: count,
            echoed: latencies.len(),
            p50: percentile(&latencies, 50),
            p95: percentile(&latencies, 95),
            p99: percentile(&latencies, 99),
        })
    }
    .await;

    reader.abort();
    let _ = reader.await;
    probe_result
}

fn parse_datagram_probe(data: &[u8]) -> LabResult<usize> {
    if data.len() != DATAGRAM_PROBE_SIZE || &data[..4] != DATAGRAM_MAGIC {
        return Err(other_error("Datagram 探针格式不正确"));
    }
    Ok(u32::from_be_bytes(
        data[4..8]
            .try_into()
            .expect("Datagram 探针编号固定为 4 字节"),
    ) as usize)
}

fn make_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn parse_frame(frame: &[u8]) -> Result<&[u8], &'static str> {
    if frame.len() < 8 {
        return Err("数据太短");
    }
    if &frame[..4] != MAGIC {
        return Err("标识不正确");
    }

    let declared =
        u32::from_be_bytes(frame[4..8].try_into().expect("长度字段固定为 4 字节")) as usize;
    if declared > MAX_PAYLOAD_SIZE {
        return Err("数据超过实验上限");
    }
    if frame.len() != declared + 8 {
        return Err("声明长度与实际长度不一致");
    }
    Ok(&frame[8..])
}

fn make_success_response(payload: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(18);
    response.extend_from_slice(b"OK");
    response.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    response.extend_from_slice(&digest(payload).to_be_bytes());
    response
}

fn make_error_response(reason: &str) -> Vec<u8> {
    format!("ER:{reason}").into_bytes()
}

fn verify_success_response(
    response: &[u8],
    expected_size: usize,
    expected_digest: u64,
) -> LabResult<()> {
    if response.len() != 18 || &response[..2] != b"OK" {
        return Err(other_error("服务端没有返回有效的成功响应"));
    }

    let received_size = u64::from_be_bytes(
        response[2..10]
            .try_into()
            .expect("成功响应中的长度字段固定为 8 字节"),
    ) as usize;
    let received_digest = u64::from_be_bytes(
        response[10..18]
            .try_into()
            .expect("成功响应中的摘要字段固定为 8 字节"),
    );

    if received_size != expected_size || received_digest != expected_digest {
        return Err(other_error("服务端收到的数据与客户端发送的数据不一致"));
    }
    Ok(())
}

fn make_payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|index| seed.wrapping_add((index as u8).wrapping_mul(31)))
        .collect()
}

fn digest(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        hash.wrapping_mul(0x100000001b3) ^ u64::from(*byte)
    })
}

fn percentile(samples: &[Duration], percentage: usize) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() * percentage).div_ceil(100)).saturating_sub(1);
    sorted.get(index).copied()
}

fn path_delta(before: PathStats, after: PathStats) -> PathMeasurement {
    PathMeasurement {
        udp_bytes_sent: after.udp_tx.bytes.saturating_sub(before.udp_tx.bytes),
        udp_datagrams_sent: after
            .udp_tx
            .datagrams
            .saturating_sub(before.udp_tx.datagrams),
        fresh_stream_bytes_sent: after
            .frame_tx
            .stream_fresh_bytes
            .saturating_sub(before.frame_tx.stream_fresh_bytes),
        retransmitted_stream_bytes_sent: after
            .frame_tx
            .stream_retransmit_bytes
            .saturating_sub(before.frame_tx.stream_retransmit_bytes),
        declared_epoch_cohorts: after
            .declared_epoch_cohorts
            .saturating_sub(before.declared_epoch_cohorts),
        declared_epoch_settled_cohorts: after
            .declared_epoch_settled_cohorts
            .saturating_sub(before.declared_epoch_settled_cohorts),
        declared_epoch_empty_cohorts: after
            .declared_epoch_empty_cohorts
            .saturating_sub(before.declared_epoch_empty_cohorts),
        declared_epoch_fresh_bytes: after
            .declared_epoch_fresh_bytes
            .saturating_sub(before.declared_epoch_fresh_bytes),
        declared_epoch_acked_bytes: after
            .declared_epoch_acked_bytes
            .saturating_sub(before.declared_epoch_acked_bytes),
        declared_epoch_late_acked_bytes: after
            .declared_epoch_late_acked_bytes
            .saturating_sub(before.declared_epoch_late_acked_bytes),
        declared_epoch_bytes_missing_at_drain: after
            .declared_epoch_bytes_missing_at_drain
            .saturating_sub(before.declared_epoch_bytes_missing_at_drain),
        declared_epoch_pending_cohorts: after.declared_epoch_pending_cohorts,
        declared_epoch_pending_origin_bytes: after.declared_epoch_pending_origin_bytes,
        declared_epoch_tracked_origin_bytes: after.declared_epoch_tracked_origin_bytes,
        path_acks_same_path: after
            .frame_tx
            .path_acks_same_path
            .saturating_sub(before.frame_tx.path_acks_same_path),
        path_acks_cross_path: after
            .frame_tx
            .path_acks_cross_path
            .saturating_sub(before.frame_tx.path_acks_cross_path),
        path_ack_escape_requests: after
            .frame_tx
            .path_ack_escape_requests
            .saturating_sub(before.frame_tx.path_ack_escape_requests),
        path_ack_escape_acks: after
            .frame_tx
            .path_ack_escape_acks
            .saturating_sub(before.frame_tx.path_ack_escape_acks),
        lost_packets: after.lost_packets.saturating_sub(before.lost_packets),
        lost_bytes: after.lost_bytes.saturating_sub(before.lost_bytes),
        loss_detection_timeouts: after
            .loss_detection_timeouts
            .saturating_sub(before.loss_detection_timeouts),
        pto_timeouts: after.pto_timeouts.saturating_sub(before.pto_timeouts),
        pto_recovery_attempts: after
            .pto_recovery_attempts
            .saturating_sub(before.pto_recovery_attempts),
        pto_recovery_empty_attempts: after
            .pto_recovery_empty_attempts
            .saturating_sub(before.pto_recovery_empty_attempts),
        last_pto_recovery_unacked_bytes: if after.pto_recovery_attempts
            > before.pto_recovery_attempts
        {
            after.last_pto_recovery_unacked_bytes
        } else {
            0
        },
        last_pto_recovery_stream_frames: if after.pto_recovery_attempts
            > before.pto_recovery_attempts
        {
            after.last_pto_recovery_stream_frames
        } else {
            0
        },
        pto_hedges: after.pto_hedges.saturating_sub(before.pto_hedges),
        pto_hedge_bytes: after.pto_hedge_bytes.saturating_sub(before.pto_hedge_bytes),
        path_abandon_recovery_attempts: after
            .path_abandon_recovery_attempts
            .saturating_sub(before.path_abandon_recovery_attempts),
        path_abandon_recovery_empty_attempts: after
            .path_abandon_recovery_empty_attempts
            .saturating_sub(before.path_abandon_recovery_empty_attempts),
        path_abandon_reinjections: after
            .path_abandon_reinjections
            .saturating_sub(before.path_abandon_reinjections),
        path_abandon_reinjected_bytes: after
            .path_abandon_reinjected_bytes
            .saturating_sub(before.path_abandon_reinjected_bytes),
        ack_progress_recovery_timeouts: after
            .ack_progress_recovery_timeouts
            .saturating_sub(before.ack_progress_recovery_timeouts),
        ack_progress_recovery_attempts: after
            .ack_progress_recovery_attempts
            .saturating_sub(before.ack_progress_recovery_attempts),
        ack_progress_recovery_empty_attempts: after
            .ack_progress_recovery_empty_attempts
            .saturating_sub(before.ack_progress_recovery_empty_attempts),
        ack_progress_reinjections: after
            .ack_progress_reinjections
            .saturating_sub(before.ack_progress_reinjections),
        ack_progress_reinjected_bytes: after
            .ack_progress_reinjected_bytes
            .saturating_sub(before.ack_progress_reinjected_bytes),
        ack_progress_feedback_probe_timeouts: after
            .ack_progress_feedback_probe_timeouts
            .saturating_sub(before.ack_progress_feedback_probe_timeouts),
        ack_progress_feedback_probes: after
            .ack_progress_feedback_probes
            .saturating_sub(before.ack_progress_feedback_probes),
        ack_progress_feedback_probe_bytes: after
            .ack_progress_feedback_probe_bytes
            .saturating_sub(before.ack_progress_feedback_probe_bytes),
        stream_progress_updates: after
            .stream_progress_updates
            .saturating_sub(before.stream_progress_updates),
        stream_progress_acked_bytes: after
            .stream_progress_acked_bytes
            .saturating_sub(before.stream_progress_acked_bytes),
        blocked_credit_handoffs: after
            .blocked_credit_handoffs
            .saturating_sub(before.blocked_credit_handoffs),
        blocked_credit_max_data_requeues: after
            .blocked_credit_max_data_requeues
            .saturating_sub(before.blocked_credit_max_data_requeues),
        blocked_credit_max_stream_data_requeues: after
            .blocked_credit_max_stream_data_requeues
            .saturating_sub(before.blocked_credit_max_stream_data_requeues),
        stream_gap_rescue_probes: after
            .stream_gap_rescue_probes
            .saturating_sub(before.stream_gap_rescue_probes),
        stream_gap_rescue_bytes: after
            .stream_gap_rescue_bytes
            .saturating_sub(before.stream_gap_rescue_bytes),
        ack_eliciting_packet_number_advance: after
            .latest_ack_eliciting_packet_number
            .saturating_sub(before.latest_ack_eliciting_packet_number),
        final_rtt: after.rtt,
        final_pto: after.pto,
        final_cwnd: after.cwnd,
        final_bytes_in_flight: after.bytes_in_flight,
        final_ack_eliciting_packets_in_flight: after.ack_eliciting_packets_in_flight,
        final_tracked_sent_packets: after.tracked_sent_packets,
        final_tracked_ack_eliciting_packets: after.tracked_ack_eliciting_packets,
        final_loss_detection_timer_armed: after.loss_detection_timer_armed,
        final_ack_progress_recovery_timer_armed: after.ack_progress_recovery_timer_armed,
    }
}

fn throughput_mbps(bytes: usize, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        return 0.0;
    }
    (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0
}

fn read_process_cpu_ticks() -> LabResult<u64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let fields = stat
        .rfind(") ")
        .map(|index| &stat[index + 2..])
        .ok_or_else(|| other_error("无法解析 /proc/self/stat 中的进程名称"))?;
    let mut fields = fields.split_whitespace();
    let user_ticks = fields
        .nth(11)
        .ok_or_else(|| other_error("/proc/self/stat 缺少用户 CPU 时间"))?
        .parse::<u64>()?;
    let system_ticks = fields
        .next()
        .ok_or_else(|| other_error("/proc/self/stat 缺少系统 CPU 时间"))?
        .parse::<u64>()?;
    Ok(user_ticks.saturating_add(system_ticks))
}

fn read_process_rss_kib() -> LabResult<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .ok_or_else(|| other_error("/proc/self/status 缺少 VmRSS"))?;
    Ok(value.parse()?)
}

fn process_clock_ticks_per_second() -> LabResult<u64> {
    static TICKS_PER_SECOND: AtomicU64 = AtomicU64::new(0);
    let cached = TICKS_PER_SECOND.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(cached);
    }

    let output = Command::new("getconf").arg("CLK_TCK").output()?;
    if !output.status.success() {
        return Err(other_error(format!(
            "getconf CLK_TCK 失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let ticks = String::from_utf8(output.stdout)?.trim().parse::<u64>()?;
    if ticks == 0 {
        return Err(other_error("getconf CLK_TCK 返回了 0"));
    }
    TICKS_PER_SECOND.store(ticks, Ordering::Relaxed);
    Ok(ticks)
}

pub fn verify_basic_report(report: &BasicLabReport) -> LabResult<()> {
    if !report.multipath_negotiated {
        return Err(other_error("MPQUIC 没有协商成功"));
    }
    if !report.primary_carried_data || !report.secondary_carried_data {
        return Err(other_error("两条路径没有分别承载实际数据"));
    }
    if !report.failover_transfer_ok {
        return Err(other_error("关闭主路径后无法继续传输"));
    }
    if report.datagram_echoes != 24 {
        return Err(other_error("Datagram 回显数量不正确"));
    }
    if !report.path_limit_rejected {
        return Err(other_error("超过路径数量上限时没有被正确拒绝"));
    }
    if !report.malformed_frame_rejected {
        return Err(other_error("格式错误的数据没有被明确拒绝"));
    }
    Ok(())
}

pub fn print_basic_report(report: &BasicLabReport) {
    println!("FlowWeave / 织流 第一阶段实验通过");
    println!("- MPQUIC 协商：{}", pass(report.multipath_negotiated));
    println!(
        "- 主路径承载数据：{}（发送 {} 字节）",
        pass(report.primary_carried_data),
        report.primary_bytes_sent
    );
    println!(
        "- 第二路径承载数据：{}（发送 {} 字节）",
        pass(report.secondary_carried_data),
        report.secondary_bytes_sent
    );
    println!(
        "- 主路径关闭后继续传输：{}",
        pass(report.failover_transfer_ok)
    );
    println!("- Datagram 回显：{} 个", report.datagram_echoes);
    println!("- Datagram 往返延迟 P95：{:?}", report.datagram_p95);
    println!("- 超过路径上限被拒绝：{}", pass(report.path_limit_rejected));
    println!(
        "- 错误格式数据被拒绝：{}",
        pass(report.malformed_frame_rejected)
    );
    println!("注意：本命令只展示基础 MPQUIC 功能；A/B/C 正式门控和代理入口见项目文档。");
}

fn pass(value: bool) -> &'static str {
    if value { "通过" } else { "失败" }
}

fn other_error(message: impl Into<String>) -> LabError {
    io::Error::other(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn true_mpquic_two_path_lab_passes() {
        let _network_test_guard = LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = run_basic_lab().await.expect("MPQUIC 双路径实验应成功运行");
        verify_basic_report(&report).expect("实验报告中的全部基础条件都应通过");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sustained_mpquic_workload_runs_past_requested_duration() {
        let _network_test_guard = LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = run_sustained_network_benchmark(SustainedBenchmarkConfig::new(
            PathMode::MultipathAvailable,
            MultipathScheduler::NoqDefault,
            Duration::from_millis(50),
            Duration::from_millis(100),
            64 * 1024,
        ))
        .await
        .expect("持续 MPQUIC 实验应成功运行");

        assert!(report.multipath_negotiated);
        assert!(report.transfer_duration >= Duration::from_millis(100));
        assert!(report.transfer_size >= 64 * 1024);
        assert!(report.peak_rss_kib > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn continuous_writer_spans_warmup_measurement_and_integrity_close() {
        let _network_test_guard = LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = run_continuous_network_benchmark(ContinuousBenchmarkConfig::new(
            PathMode::MultipathAvailable,
            MultipathScheduler::NoqDefault,
            Duration::from_millis(50),
            Duration::from_millis(150),
            16 * 1024,
        ))
        .await
        .expect("持续单流 MPQUIC 实验应成功运行");

        assert!(report.multipath_negotiated);
        assert!(report.data_intact);
        assert!(report.writer_alive_at_measurement_start);
        assert!(report.writer_alive_at_measurement_end);
        assert!(report.transfer_duration >= Duration::from_millis(150));
        assert!(report.records_received_in_window > 0);
        assert_eq!(
            report.transfer_size as u64,
            report.records_received_in_window * 16 * 1024
        );
        assert!(report.total_records_received >= report.records_received_in_window);
        assert!(report.total_application_bytes_received >= report.transfer_size as u64);
        // This short loopback integrity test may spend longer than PathIdle draining the
        // unbounded writer after measurement, while NoQ default legitimately leaves the
        // unused secondary path idle. Formal B tests separately require both shaped paths open.
        assert!(report.any_configured_path_open);
        assert!(report.peak_rss_kib > 0);
    }

    #[test]
    fn continuous_writer_window_counts_only_completed_records_in_half_open_interval() {
        let started = Instant::now();
        let ended = started + Duration::from_millis(100);
        let received_at = [
            started - Duration::from_nanos(1),
            started,
            started + Duration::from_millis(50),
            ended - Duration::from_nanos(1),
            ended,
        ];

        assert_eq!(
            count_received_records_in_window(&received_at, started, ended)
                .expect("合法半开窗口应能计数"),
            3
        );
        assert!(count_received_records_in_window(&received_at, ended, started).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn declared_backlogged_epoch_keeps_all_cohorts_and_stream_integrity() {
        let _network_test_guard = LOCAL_NETWORK_TEST_LOCK.lock().await;
        let report = run_declared_backlogged_epoch_probe(DeclaredBackloggedEpochConfig::new(
            PathMode::LineOneOnly,
            Duration::from_millis(50),
            Duration::from_millis(500),
            16 * 1024,
        ))
        .await
        .expect("declared backlogged epoch 本地探针应完整运行");

        assert!(report.multipath_negotiated);
        assert!(report.data_intact);
        assert!(report.writer_alive_at_epoch_start);
        assert!(report.writer_alive_at_epoch_end);
        assert!(report.transfer_size > 0);
        assert!(report.path_open);
        assert_eq!(report.path.declared_epoch_cohorts, 2);
        assert_eq!(report.path.declared_epoch_settled_cohorts, 2);
        assert_eq!(report.path.declared_epoch_pending_cohorts, 0);
        assert_eq!(report.path.declared_epoch_pending_origin_bytes, 0);
        assert_eq!(report.path.declared_epoch_tracked_origin_bytes, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failover_progress_is_reported_before_full_integrity_check() {
        let _network_test_guard = LOCAL_NETWORK_TEST_LOCK.lock().await;
        let lab = start_connection(Ipv4Addr::UNSPECIFIED, None, PtoRecovery::Disabled)
            .await
            .expect("进度测量实验应建立连接");
        let started = Instant::now();
        let timing = transfer_and_verify_with_progress(&lab.connection, 64 * 1024, 17, started)
            .await
            .expect("进度传输应完整校验");

        assert!(timing.recovery_time <= timing.completion_time);
        lab.shutdown().await.expect("进度实验应正常关闭");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sustained_failover_protocol_preserves_both_directions() {
        let _network_test_guard = LOCAL_NETWORK_TEST_LOCK.lock().await;
        for direction in FailoverDirection::ALL {
            let (lab, events) = start_connection_with_sustained_observer(
                Ipv4Addr::UNSPECIFIED,
                None,
                PtoRecovery::Disabled,
                MultipathScheduler::NoqDefault,
            )
            .await
            .expect("正式换网协议实验应建立连接");
            let config = SustainedFailoverConfig::new(
                MultipathScheduler::NoqDefault,
                PtoRecovery::Disabled,
                direction,
                Duration::from_millis(100),
                Duration::from_millis(50),
                4 * 1024,
                31,
            );
            let (started_tx, started_rx) = oneshot::channel();
            let task = tokio::spawn(run_sustained_failover_flow(
                lab.connection.clone(),
                config,
                events,
                started_tx,
            ));
            let _ = timeout(OPERATION_TIMEOUT, started_rx)
                .await
                .expect("正式换网协议应报告开始")
                .expect("正式换网协议开始通道不应关闭");
            let outcome = timeout(OPERATION_TIMEOUT, task)
                .await
                .expect("正式换网协议不应超时")
                .expect("正式换网协议任务不应崩溃")
                .expect("正式换网协议应完整校验");
            assert!(outcome.exchange_failure.is_none());
            let trace = outcome.trace;

            assert!(trace.records > 0);
            assert_eq!(trace.bytes, trace.records * config.chunk_size as u64);
            assert_eq!(trace.received_at.len() as u64, trace.records);
            lab.shutdown().await.expect("正式换网协议实验应正常关闭");
        }
    }

    #[test]
    fn recovery_gap_keeps_stale_post_fault_delivery_from_hiding_outage() {
        let base = Instant::now();
        let received = [
            base,
            base + Duration::from_millis(10),
            base + Duration::from_millis(12),
            base + Duration::from_millis(412),
            base + Duration::from_millis(420),
        ];
        let gap = recovery_gap_after_fault(&received, base + Duration::from_millis(11))
            .expect("故障前后都有数据，应找到恢复间隔");
        assert_eq!(gap, Duration::from_millis(400));
    }

    #[test]
    fn ack_progress_diagnostic_variant_enables_all_recovery_primitives() {
        let recovery = PtoRecovery::CrossPathRecovery;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn ack_escape_diagnostic_variant_is_isolated_from_history_and_candidates() {
        let recovery = PtoRecovery::CrossPathRecoveryWithAckEscape;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(!PtoRecovery::CrossPathRecovery.ack_escape_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn feedback_handoff_variant_preserves_historical_ack_escape() {
        let recovery = PtoRecovery::CrossPathRecoveryWithFeedbackHandoff;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(!recovery.feedback_credit_snapshot_enabled());
        assert!(!PtoRecovery::CrossPathRecoveryWithAckEscape.feedback_handoff_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn feedback_snapshot_variant_is_separate_and_default_off() {
        let recovery = PtoRecovery::CrossPathRecoveryWithFeedbackSnapshot;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(!recovery.feedback_probe_enabled());
        assert!(
            !PtoRecovery::CrossPathRecoveryWithFeedbackHandoff.feedback_credit_snapshot_enabled()
        );
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn feedback_probe_variant_composes_without_changing_snapshot_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithFeedbackProbe;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(!recovery.feedback_evidence_reinjection_enabled());
        assert!(!PtoRecovery::CrossPathRecoveryWithFeedbackSnapshot.feedback_probe_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn feedback_evidence_variant_composes_without_changing_probe_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithFeedbackEvidence;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(!recovery.stream_gap_rescue_enabled());
        assert!(
            !PtoRecovery::CrossPathRecoveryWithFeedbackProbe
                .feedback_evidence_reinjection_enabled()
        );
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn gap_rescue_variant_is_separate_from_evidence_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_rescue_enabled());
        assert!(!recovery.stream_gap_watch_rescue_enabled());
        assert!(!PtoRecovery::CrossPathRecoveryWithFeedbackEvidence.stream_gap_rescue_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn gap_watch_variant_is_separate_from_immediate_rescue_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(!recovery.stream_gap_rescue_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(
            !PtoRecovery::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue
                .stream_gap_watch_rescue_enabled()
        );
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn application_progress_variant_composes_without_changing_gap_watch_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithApplicationProgressWatch;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(!recovery.stream_gap_rescue_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert_eq!(recovery.ack_progress_service_deadline(), None);

        let historical = PtoRecovery::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch;
        assert!(!historical.ack_progress_stream_obligation_enabled());
        assert!(!historical.blocked_credit_handoff_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn service_deadline_variant_is_separate_from_application_progress_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithApplicationProgressDeadline;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(!recovery.stream_gap_rescue_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert!(!recovery.ack_progress_fresh_alternative_enabled());

        let historical = PtoRecovery::CrossPathRecoveryWithApplicationProgressWatch;
        assert_eq!(historical.ack_progress_service_deadline(), None);
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn version_aware_deadline_variant_is_separate_from_v6_2_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithVersionAwareDeadline;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert!(recovery.ack_progress_fresh_alternative_enabled());

        let historical = PtoRecovery::CrossPathRecoveryWithApplicationProgressDeadline;
        assert!(!historical.ack_progress_fresh_alternative_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn stream_progress_variant_inherits_v6_3_and_stays_isolated() {
        let recovery = PtoRecovery::CrossPathRecoveryWithStreamProgress;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert!(recovery.ack_progress_fresh_alternative_enabled());
        assert!(recovery.stream_progress_enabled());
        assert_eq!(recovery.ack_progress_service_recovery_flights(), 1);

        let historical = PtoRecovery::CrossPathRecoveryWithVersionAwareDeadline;
        assert!(!historical.stream_progress_enabled());
        assert!(!PtoRecovery::Disabled.stream_progress_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn multi_flight_budget_variant_inherits_v6_4_and_stays_isolated() {
        let recovery = PtoRecovery::CrossPathRecoveryWithMultiFlightBudget;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert!(recovery.ack_progress_fresh_alternative_enabled());
        assert!(recovery.stream_progress_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert_eq!(recovery.ack_progress_service_recovery_flights(), 3);
        assert!(!recovery.ack_progress_feedback_stability_enabled());

        let historical = PtoRecovery::CrossPathRecoveryWithStreamProgress;
        assert_eq!(historical.ack_progress_service_recovery_flights(), 1);
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn stable_multi_flight_variant_inherits_v6_5_without_changing_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithStableMultiFlightBudget;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert!(recovery.ack_progress_fresh_alternative_enabled());
        assert!(recovery.stream_progress_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert_eq!(recovery.ack_progress_service_recovery_flights(), 3);
        assert!(recovery.ack_progress_feedback_stability_enabled());
        assert!(!recovery.stream_gap_delivery_watch_rescue_enabled());

        let historical = PtoRecovery::CrossPathRecoveryWithMultiFlightBudget;
        assert!(!historical.ack_progress_feedback_stability_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn delivery_gap_watch_variant_inherits_v6_6_without_changing_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithDeliveryGapWatch;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(!recovery.stream_gap_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert!(recovery.ack_progress_fresh_alternative_enabled());
        assert!(recovery.stream_progress_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert_eq!(recovery.ack_progress_service_recovery_flights(), 3);
        assert!(recovery.ack_progress_feedback_stability_enabled());
        assert!(recovery.stream_gap_delivery_watch_rescue_enabled());

        let historical = PtoRecovery::CrossPathRecoveryWithStableMultiFlightBudget;
        assert!(!historical.stream_gap_delivery_watch_rescue_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn alternative_stability_variant_inherits_v6_7_without_changing_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithAlternativeStability;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(!recovery.stream_gap_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert!(recovery.ack_progress_fresh_alternative_enabled());
        assert!(recovery.stream_progress_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert_eq!(recovery.ack_progress_service_recovery_flights(), 3);
        assert!(recovery.ack_progress_feedback_stability_enabled());
        assert!(recovery.stream_gap_delivery_watch_rescue_enabled());
        assert!(recovery.ack_progress_alternative_stability_enabled());

        let historical = PtoRecovery::CrossPathRecoveryWithDeliveryGapWatch;
        assert!(!historical.ack_progress_alternative_stability_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn stream_progress_snapshot_variant_inherits_v6_8_without_changing_history() {
        let recovery = PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot;
        assert!(recovery.pto_reinjection_enabled());
        assert!(recovery.abandon_reinjection_enabled());
        assert!(recovery.ack_progress_reinjection_enabled());
        assert!(recovery.ack_escape_enabled());
        assert!(recovery.feedback_handoff_enabled());
        assert!(recovery.feedback_credit_snapshot_enabled());
        assert!(recovery.feedback_probe_enabled());
        assert!(recovery.feedback_evidence_reinjection_enabled());
        assert!(recovery.stream_gap_watch_rescue_enabled());
        assert!(recovery.ack_progress_stream_obligation_enabled());
        assert!(recovery.blocked_credit_handoff_enabled());
        assert!(recovery.ack_progress_fresh_alternative_enabled());
        assert!(recovery.stream_progress_enabled());
        assert_eq!(
            recovery.ack_progress_service_deadline(),
            Some(Duration::from_millis(1_000))
        );
        assert_eq!(recovery.ack_progress_service_recovery_flights(), 3);
        assert!(recovery.ack_progress_feedback_stability_enabled());
        assert!(recovery.stream_gap_delivery_watch_rescue_enabled());
        assert!(recovery.ack_progress_alternative_stability_enabled());
        assert!(recovery.feedback_stream_progress_snapshot_enabled());

        let historical = PtoRecovery::CrossPathRecoveryWithAlternativeStability;
        assert!(!historical.feedback_stream_progress_snapshot_enabled());
        assert!(!PtoRecovery::CANDIDATES.contains(&recovery));
    }

    #[test]
    fn stream_state_sampling_is_diagnostic_only() {
        let config = SustainedFailoverConfig::new(
            MultipathScheduler::NoqDefault,
            PtoRecovery::CrossPathRecoveryWithAckEscape,
            FailoverDirection::ClientToServer,
            Duration::from_secs(30),
            Duration::from_secs(10),
            16 * 1024,
            1,
        );
        assert!(!config.collect_stream_state_diagnostics);
        assert!(!config.receiver_anchored_response_timeout);
        assert!(
            config
                .with_stream_state_diagnostics()
                .collect_stream_state_diagnostics
        );
        assert!(
            config
                .with_receiver_anchored_response_timeout()
                .receiver_anchored_response_timeout
        );
    }

    #[test]
    fn sustained_payload_validation_detects_corruption() {
        let mut payload = vec![0_u8; 1024];
        fill_sustained_payload(&mut payload, 7, 19);
        assert!(sustained_payload_is_valid(&payload, 7, 19));
        payload[511] ^= 0x80;
        assert!(!sustained_payload_is_valid(&payload, 7, 19));
    }

    #[test]
    fn malformed_application_frame_is_rejected() {
        assert_eq!(parse_frame(b"bad"), Err("数据太短"));

        let mut wrong_length = make_frame(b"hello");
        wrong_length[7] = 9;
        assert_eq!(parse_frame(&wrong_length), Err("声明长度与实际长度不一致"));
    }

    #[test]
    fn unsafe_network_benchmark_sizes_are_rejected() {
        let empty = NetworkBenchmarkConfig::new(
            PathMode::LineOneOnly,
            MultipathScheduler::NoqDefault,
            0,
            1,
        );
        assert!(empty.validate().is_err());

        let oversized = NetworkBenchmarkConfig::new(
            PathMode::LineOneOnly,
            MultipathScheduler::NoqDefault,
            MAX_PAYLOAD_SIZE + 1,
            1,
        );
        assert!(oversized.validate().is_err());

        let too_many_probes = NetworkBenchmarkConfig::new(
            PathMode::LineOneOnly,
            MultipathScheduler::NoqDefault,
            1024,
            MAX_DATAGRAM_PROBES + 1,
        );
        assert!(too_many_probes.validate().is_err());

        let no_warmup = SustainedBenchmarkConfig::new(
            PathMode::MultipathAvailable,
            MultipathScheduler::NoqDefault,
            Duration::ZERO,
            Duration::from_secs(20),
            512 * 1024,
        );
        assert!(no_warmup.validate().is_err());

        let too_long = SustainedBenchmarkConfig::new(
            PathMode::MultipathAvailable,
            MultipathScheduler::NoqDefault,
            Duration::from_secs(2),
            MAX_SUSTAINED_MEASUREMENT + Duration::from_secs(1),
            512 * 1024,
        );
        assert!(too_long.validate().is_err());

        let oversized_chunk = SustainedBenchmarkConfig::new(
            PathMode::MultipathAvailable,
            MultipathScheduler::NoqDefault,
            Duration::from_secs(2),
            Duration::from_secs(20),
            MAX_PAYLOAD_SIZE + 1,
        );
        assert!(oversized_chunk.validate().is_err());

        let no_continuous_measurement = ContinuousBenchmarkConfig::new(
            PathMode::MultipathAvailable,
            MultipathScheduler::NoqDefault,
            Duration::from_secs(2),
            Duration::ZERO,
            16 * 1024,
        );
        assert!(no_continuous_measurement.validate().is_err());

        let oversized_continuous_chunk = ContinuousBenchmarkConfig::new(
            PathMode::MultipathAvailable,
            MultipathScheduler::NoqDefault,
            Duration::from_secs(2),
            Duration::from_secs(20),
            MAX_PAYLOAD_SIZE + 1,
        );
        assert!(oversized_continuous_chunk.validate().is_err());

        let fault_after_end = SustainedFailoverConfig::new(
            MultipathScheduler::NoqDefault,
            PtoRecovery::Disabled,
            FailoverDirection::ClientToServer,
            Duration::from_secs(30),
            Duration::from_secs(30),
            16 * 1024,
            1,
        );
        assert!(fault_after_end.validate().is_err());

        let tiny_failover_chunk = SustainedFailoverConfig::new(
            MultipathScheduler::NoqDefault,
            PtoRecovery::Disabled,
            FailoverDirection::ServerToClient,
            Duration::from_secs(30),
            Duration::from_secs(10),
            SUSTAINED_RECORD_HEADER_SIZE - 1,
            1,
        );
        assert!(tiny_failover_chunk.validate().is_err());
    }
}

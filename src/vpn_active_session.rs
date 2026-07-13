use std::{
    collections::HashMap,
    error::Error,
    fmt,
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use noq::Connection;
use tokio::time::timeout;

use crate::vpn_quota::VpnQuotaBook;
use crate::{
    VPN_CLOSE_CONTROL_REJECTED, VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES,
    VPN_DEFAULT_GLOBAL_REASSEMBLY_RESERVATIONS, VpnCertificateFingerprint, VpnDataPolicyError,
    VpnDataPolicyMetricsSnapshot, VpnIdentityAuthorizationError, VpnIdentityConfigError,
    VpnIdentityRegistry, VpnIdentityReloadReport, VpnIpPacketMeta, VpnNegotiatedSession,
    VpnPacketDirection, VpnQuotaMetricsSnapshot, VpnQuotaRejection, VpnReject,
    VpnServerControlOutcome, VpnServerNegotiationConfig, VpnSessionError, VpnSessionGeneration,
    load_vpn_identity_registry, validate_vpn_ip_packet_policy, vpn_server_control_handshake,
};

pub const VPN_CLOSE_SESSION_REPLACED: u32 = 0x100;
pub const VPN_CLOSE_IDENTITY_REVOKED: u32 = 0x101;
pub const VPN_CLOSE_POLICY_CHANGED: u32 = 0x102;
pub const VPN_CLOSE_COMMIT_REJECTED: u32 = 0x103;
pub const VPN_CLOSE_SERVER_SHUTDOWN: u32 = 0x104;

const SESSION_REPLACED_REASON: &[u8] = b"session_replaced";
const IDENTITY_REVOKED_REASON: &[u8] = b"identity_revoked";
const POLICY_CHANGED_REASON: &[u8] = b"policy_changed";
const COMMIT_REJECTED_REASON: &[u8] = b"session_commit_rejected";
const SERVER_SHUTDOWN_REASON: &[u8] = b"server_shutdown";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnSessionCommitError {
    IdentityRevoked,
    PolicyChanged,
}

impl fmt::Display for VpnSessionCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityRevoked => "vpn_session_commit_identity_revoked",
            Self::PolicyChanged => "vpn_session_commit_policy_changed",
        })
    }
}

impl Error for VpnSessionCommitError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnManagedSessionError {
    GenerationExhausted,
    InvalidResourceLimits,
    Control(VpnSessionError),
    Commit(VpnSessionCommitError),
}

impl fmt::Display for VpnManagedSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationExhausted => formatter.write_str("vpn_session_generation_exhausted"),
            Self::InvalidResourceLimits => {
                formatter.write_str("vpn_session_invalid_resource_limits")
            }
            Self::Control(error) => write!(formatter, "vpn_managed_session_control:{error}"),
            Self::Commit(error) => write!(formatter, "vpn_managed_session_commit:{error}"),
        }
    }
}

impl Error for VpnManagedSessionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnSessionCommitReport {
    pub session_generation: u64,
    pub replaced_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnSessionReconcileReport {
    pub kept: usize,
    pub identity_revoked: usize,
    pub policy_changed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnCoordinatorReloadReport {
    pub identities: VpnIdentityReloadReport,
    pub sessions: VpnSessionReconcileReport,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnSessionCoordinatorMetrics {
    pub active_sessions: usize,
    pub total_committed: u64,
    pub replacements: u64,
    pub commit_rejections: u64,
    pub identity_revocations: u64,
    pub policy_change_closes: u64,
    pub normal_releases: u64,
    pub shutdown_closes: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VpnActiveSessionSnapshot {
    client_id: String,
    fingerprint: VpnCertificateFingerprint,
    session_generation: u64,
    connection_stable_id: usize,
}

impl VpnActiveSessionSnapshot {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub const fn fingerprint(&self) -> VpnCertificateFingerprint {
        self.fingerprint
    }

    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }

    pub const fn connection_stable_id(&self) -> usize {
        self.connection_stable_id
    }
}

impl fmt::Debug for VpnActiveSessionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnActiveSessionSnapshot")
            .field("client_id", &"[redacted]")
            .field("fingerprint", &self.fingerprint)
            .field("session_generation", &self.session_generation)
            .field("connection_stable_id", &self.connection_stable_id)
            .finish()
    }
}

pub struct VpnReassemblyReservation {
    state: Weak<Mutex<CoordinatorState>>,
    reservation_id: u64,
    bytes: usize,
}

impl VpnReassemblyReservation {
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn release(self) {
        drop(self);
    }
}

impl fmt::Debug for VpnReassemblyReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnReassemblyReservation")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for VpnReassemblyReservation {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .quotas
            .release_reassembly(self.reservation_id);
    }
}

#[derive(Clone)]
pub struct VpnSessionCoordinator {
    state: Arc<Mutex<CoordinatorState>>,
    next_generation: Arc<AtomicU64>,
}

impl VpnSessionCoordinator {
    pub fn new(registry: VpnIdentityRegistry) -> Self {
        Self::with_resource_limits(
            registry,
            1,
            VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES,
            VPN_DEFAULT_GLOBAL_REASSEMBLY_RESERVATIONS,
        )
        .expect("the fixed VPN coordinator limits are valid")
    }

    pub fn with_initial_generation(
        registry: VpnIdentityRegistry,
        initial_generation: u64,
    ) -> Result<Self, VpnManagedSessionError> {
        Self::with_resource_limits(
            registry,
            initial_generation,
            VPN_DEFAULT_GLOBAL_REASSEMBLY_BYTES,
            VPN_DEFAULT_GLOBAL_REASSEMBLY_RESERVATIONS,
        )
    }

    pub fn with_resource_limits(
        registry: VpnIdentityRegistry,
        initial_generation: u64,
        global_reassembly_limit: usize,
        global_reservation_limit: usize,
    ) -> Result<Self, VpnManagedSessionError> {
        if initial_generation == 0 {
            return Err(VpnManagedSessionError::GenerationExhausted);
        }
        let quotas = VpnQuotaBook::new(global_reassembly_limit, global_reservation_limit)
            .ok_or(VpnManagedSessionError::InvalidResourceLimits)?;
        Ok(Self {
            state: Arc::new(Mutex::new(CoordinatorState {
                registry: Arc::new(registry),
                active: HashMap::new(),
                metrics: VpnSessionCoordinatorMetrics::default(),
                data_metrics: VpnDataPolicyMetricsSnapshot::default(),
                quotas,
            })),
            next_generation: Arc::new(AtomicU64::new(initial_generation)),
        })
    }

    pub fn registry_snapshot(&self) -> Arc<VpnIdentityRegistry> {
        self.lock_state().registry.clone()
    }

    pub fn allocate_generation(&self) -> Result<VpnSessionGeneration, VpnManagedSessionError> {
        let generation = self
            .next_generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current != 0).then_some(current.wrapping_add(1))
            })
            .map_err(|_| VpnManagedSessionError::GenerationExhausted)?;
        VpnSessionGeneration::new(generation).ok_or(VpnManagedSessionError::GenerationExhausted)
    }

    pub fn commit(
        &self,
        session: VpnNegotiatedSession,
        connection: Connection,
    ) -> Result<VpnSessionCommitReport, VpnSessionCommitError> {
        self.commit_with_handle_at(
            session,
            Arc::new(NoqConnectionHandle(connection)),
            Instant::now(),
        )
    }

    pub fn active_session(&self, client_id: &str) -> Option<VpnActiveSessionSnapshot> {
        self.lock_state()
            .active
            .get(client_id)
            .map(ActiveVpnSession::snapshot)
    }

    pub fn is_current(&self, client_id: &str, session_generation: u64) -> bool {
        self.lock_state()
            .active
            .get(client_id)
            .is_some_and(|active| active.session.accept().session_generation == session_generation)
    }

    pub fn release_if_current(&self, client_id: &str, session_generation: u64) -> bool {
        let mut state = self.lock_state();
        let is_current = state
            .active
            .get(client_id)
            .is_some_and(|active| active.session.accept().session_generation == session_generation);
        if !is_current {
            return false;
        }
        state.active.remove(client_id);
        state.quotas.deactivate(client_id, session_generation);
        state.metrics.normal_releases = state.metrics.normal_releases.saturating_add(1);
        state.metrics.active_sessions = state.active.len();
        true
    }

    pub fn metrics_snapshot(&self) -> VpnSessionCoordinatorMetrics {
        self.lock_state().metrics
    }

    pub fn quota_metrics_snapshot(&self) -> VpnQuotaMetricsSnapshot {
        self.lock_state().quotas.metrics()
    }

    pub fn data_policy_metrics_snapshot(&self) -> VpnDataPolicyMetricsSnapshot {
        self.lock_state().data_metrics
    }

    pub fn authorize_ip_packet(
        &self,
        client_id: &str,
        session_generation: u64,
        direction: VpnPacketDirection,
        packet: &[u8],
        now: Instant,
    ) -> Result<VpnIpPacketMeta, VpnDataPolicyError> {
        let mut state = self.lock_state();
        let is_current = state
            .active
            .get(client_id)
            .is_some_and(|active| active.session.accept().session_generation == session_generation);
        if !is_current {
            state.quotas.record_stale_generation();
            return Err(VpnDataPolicyError::StaleGeneration);
        }
        state
            .quotas
            .admit_packet(client_id, session_generation, direction, packet.len(), now)
            .map_err(VpnDataPolicyError::Quota)?;
        let result = validate_vpn_ip_packet_policy(
            state
                .active
                .get(client_id)
                .expect("current generation requires an active session")
                .session
                .identity(),
            direction,
            packet,
        );
        let bytes = u64::try_from(packet.len()).unwrap_or(u64::MAX);
        match result {
            Ok(_) => match direction {
                VpnPacketDirection::Uplink => {
                    state.data_metrics.forwarded_uplink_packets = state
                        .data_metrics
                        .forwarded_uplink_packets
                        .saturating_add(1);
                    state.data_metrics.forwarded_uplink_bytes = state
                        .data_metrics
                        .forwarded_uplink_bytes
                        .saturating_add(bytes);
                }
                VpnPacketDirection::Downlink => {
                    state.data_metrics.forwarded_downlink_packets = state
                        .data_metrics
                        .forwarded_downlink_packets
                        .saturating_add(1);
                    state.data_metrics.forwarded_downlink_bytes = state
                        .data_metrics
                        .forwarded_downlink_bytes
                        .saturating_add(bytes);
                }
            },
            Err(VpnDataPolicyError::Packet(_)) => {
                state.data_metrics.malformed_packet_rejections = state
                    .data_metrics
                    .malformed_packet_rejections
                    .saturating_add(1);
            }
            Err(VpnDataPolicyError::UplinkSourceSpoofed) => {
                state.data_metrics.uplink_source_spoof_rejections = state
                    .data_metrics
                    .uplink_source_spoof_rejections
                    .saturating_add(1);
            }
            Err(VpnDataPolicyError::DestinationPolicyRejected) => {
                state.data_metrics.destination_policy_rejections = state
                    .data_metrics
                    .destination_policy_rejections
                    .saturating_add(1);
            }
            Err(VpnDataPolicyError::DownlinkDestinationMismatch) => {
                state.data_metrics.downlink_destination_rejections = state
                    .data_metrics
                    .downlink_destination_rejections
                    .saturating_add(1);
            }
            Err(VpnDataPolicyError::StaleGeneration | VpnDataPolicyError::Quota(_)) => {}
        }
        result
    }

    pub fn admit_packet(
        &self,
        client_id: &str,
        session_generation: u64,
        direction: VpnPacketDirection,
        packet_len: usize,
        now: Instant,
    ) -> Result<(), VpnQuotaRejection> {
        self.lock_state().quotas.admit_packet(
            client_id,
            session_generation,
            direction,
            packet_len,
            now,
        )
    }

    pub fn reserve_reassembly(
        &self,
        client_id: &str,
        session_generation: u64,
        bytes: usize,
    ) -> Result<VpnReassemblyReservation, VpnQuotaRejection> {
        let reservation_id =
            self.lock_state()
                .quotas
                .reserve_reassembly(client_id, session_generation, bytes)?;
        Ok(VpnReassemblyReservation {
            state: Arc::downgrade(&self.state),
            reservation_id,
            bytes,
        })
    }

    pub fn reload_from_path(
        &self,
        path: &Path,
    ) -> Result<VpnCoordinatorReloadReport, VpnIdentityConfigError> {
        let candidate = load_vpn_identity_registry(path)?;
        Ok(self.replace_registry(candidate))
    }

    pub fn replace_registry(&self, registry: VpnIdentityRegistry) -> VpnCoordinatorReloadReport {
        let mut state = self.lock_state();
        let identities = VpnIdentityReloadReport {
            previous_identity_count: state.registry.identities().len(),
            identity_count: registry.identities().len(),
            previous_fingerprint_count: state.registry.fingerprint_count(),
            fingerprint_count: registry.fingerprint_count(),
        };
        state.registry = Arc::new(registry);

        let decisions = state
            .active
            .iter()
            .map(|(client_id, active)| {
                let decision = match state.registry.authorize(active.session.fingerprint()) {
                    Ok(identity)
                        if identity.client_id() == client_id
                            && active.session.identity().has_same_session_policy(identity) =>
                    {
                        ReconcileDecision::Keep
                    }
                    Ok(identity) if identity.client_id() == client_id => {
                        ReconcileDecision::PolicyChanged
                    }
                    Ok(_) | Err(_) => ReconcileDecision::IdentityRevoked,
                };
                (client_id.clone(), decision)
            })
            .collect::<Vec<_>>();

        let mut sessions = VpnSessionReconcileReport::default();
        let mut closed = Vec::new();
        for (client_id, decision) in decisions {
            match decision {
                ReconcileDecision::Keep => sessions.kept += 1,
                ReconcileDecision::IdentityRevoked => {
                    let active = state
                        .active
                        .remove(&client_id)
                        .expect("reconcile decision references an active session");
                    closed.push((active.connection, CloseReason::IdentityRevoked));
                    sessions.identity_revoked += 1;
                    state.metrics.identity_revocations =
                        state.metrics.identity_revocations.saturating_add(1);
                }
                ReconcileDecision::PolicyChanged => {
                    let active = state
                        .active
                        .remove(&client_id)
                        .expect("reconcile decision references an active session");
                    closed.push((active.connection, CloseReason::PolicyChanged));
                    sessions.policy_changed += 1;
                    state.metrics.policy_change_closes =
                        state.metrics.policy_change_closes.saturating_add(1);
                }
            }
        }
        state.metrics.active_sessions = state.active.len();
        let active_generations = state
            .active
            .iter()
            .map(|(client_id, active)| {
                (
                    client_id.clone(),
                    active.session.accept().session_generation,
                )
            })
            .collect::<HashMap<_, _>>();
        let registry = state.registry.clone();
        state
            .quotas
            .reconcile(&registry, &active_generations, Instant::now());
        drop(state);
        for (connection, reason) in closed {
            connection.close(reason.code(), reason.message());
        }

        VpnCoordinatorReloadReport {
            identities,
            sessions,
        }
    }

    pub fn close_all(&self) -> usize {
        let mut state = self.lock_state();
        let active = state
            .active
            .drain()
            .map(|(_, active)| active)
            .collect::<Vec<_>>();
        state.metrics.shutdown_closes = state
            .metrics
            .shutdown_closes
            .saturating_add(u64::try_from(active.len()).unwrap_or(u64::MAX));
        state.metrics.active_sessions = 0;
        let registry = state.registry.clone();
        state
            .quotas
            .reconcile(&registry, &HashMap::new(), Instant::now());
        drop(state);
        for session in &active {
            session
                .connection
                .close(VPN_CLOSE_SERVER_SHUTDOWN, SERVER_SHUTDOWN_REASON);
        }
        active.len()
    }

    #[cfg(test)]
    fn commit_with_handle(
        &self,
        session: VpnNegotiatedSession,
        connection: Arc<dyn VpnSessionConnection>,
    ) -> Result<VpnSessionCommitReport, VpnSessionCommitError> {
        self.commit_with_handle_at(session, connection, Instant::now())
    }

    fn commit_with_handle_at(
        &self,
        session: VpnNegotiatedSession,
        connection: Arc<dyn VpnSessionConnection>,
        now: Instant,
    ) -> Result<VpnSessionCommitReport, VpnSessionCommitError> {
        let client_id = session.identity().client_id().to_owned();
        let session_generation = session.accept().session_generation;
        let limits = session.identity().limits();
        let validation = {
            let mut state = self.lock_state();
            let validation = match state.registry.authorize(session.fingerprint()) {
                Ok(identity)
                    if identity.client_id() == client_id
                        && session.identity().has_same_session_policy(identity) =>
                {
                    Ok(())
                }
                Ok(identity) if identity.client_id() == client_id => {
                    Err(VpnSessionCommitError::PolicyChanged)
                }
                Ok(_)
                | Err(VpnIdentityAuthorizationError::UnknownFingerprint)
                | Err(VpnIdentityAuthorizationError::IdentityDisabled) => {
                    Err(VpnSessionCommitError::IdentityRevoked)
                }
            };
            if let Err(error) = validation {
                state.metrics.commit_rejections = state.metrics.commit_rejections.saturating_add(1);
                Err(error)
            } else {
                state
                    .quotas
                    .activate(&client_id, session_generation, limits, now);
                let replaced = state.active.insert(
                    client_id,
                    ActiveVpnSession {
                        session,
                        connection: connection.clone(),
                    },
                );
                state.metrics.total_committed = state.metrics.total_committed.saturating_add(1);
                if replaced.is_some() {
                    state.metrics.replacements = state.metrics.replacements.saturating_add(1);
                }
                state.metrics.active_sessions = state.active.len();
                let report = VpnSessionCommitReport {
                    session_generation,
                    replaced_generation: replaced
                        .as_ref()
                        .map(|active| active.session.accept().session_generation),
                };
                Ok((report, replaced))
            }
        };

        match validation {
            Ok((report, replaced)) => {
                if let Some(replaced) = replaced {
                    replaced
                        .connection
                        .close(VPN_CLOSE_SESSION_REPLACED, SESSION_REPLACED_REASON);
                }
                Ok(report)
            }
            Err(error) => {
                connection.close(VPN_CLOSE_COMMIT_REJECTED, COMMIT_REJECTED_REASON);
                Err(error)
            }
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, CoordinatorState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for VpnSessionCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock_state();
        formatter
            .debug_struct("VpnSessionCoordinator")
            .field("identity_count", &state.registry.identities().len())
            .field("active_session_count", &state.active.len())
            .field("metrics", &state.metrics)
            .finish()
    }
}

pub struct VpnManagedActiveSession {
    session: Box<VpnNegotiatedSession>,
    commit: VpnSessionCommitReport,
}

impl VpnManagedActiveSession {
    pub fn session(&self) -> &VpnNegotiatedSession {
        &self.session
    }

    pub const fn commit_report(&self) -> VpnSessionCommitReport {
        self.commit
    }
}

impl fmt::Debug for VpnManagedActiveSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnManagedActiveSession")
            .field("session", &self.session)
            .field("commit", &self.commit)
            .finish()
    }
}

#[derive(Debug)]
pub enum VpnManagedServerOutcome {
    Active(Box<VpnManagedActiveSession>),
    Rejected(VpnReject),
}

pub async fn vpn_server_managed_control_handshake(
    connection: &Connection,
    coordinator: &VpnSessionCoordinator,
    config: VpnServerNegotiationConfig,
    handshake_timeout: Duration,
) -> Result<VpnManagedServerOutcome, VpnManagedSessionError> {
    let generation = coordinator.allocate_generation()?;
    let registry = coordinator.registry_snapshot();
    match vpn_server_control_handshake(connection, &registry, config, generation, handshake_timeout)
        .await
        .map_err(VpnManagedSessionError::Control)?
    {
        VpnServerControlOutcome::Accepted(session) => {
            let commit = coordinator
                .commit(session.as_ref().clone(), connection.clone())
                .map_err(VpnManagedSessionError::Commit)?;
            Ok(VpnManagedServerOutcome::Active(Box::new(
                VpnManagedActiveSession { session, commit },
            )))
        }
        VpnServerControlOutcome::Rejected(reject) => {
            let drain_timeout = handshake_timeout.min(Duration::from_secs(1));
            if timeout(drain_timeout, connection.closed()).await.is_err() {
                connection.close(VPN_CLOSE_CONTROL_REJECTED.into(), b"control_rejected");
            }
            Ok(VpnManagedServerOutcome::Rejected(reject))
        }
    }
}

struct CoordinatorState {
    registry: Arc<VpnIdentityRegistry>,
    active: HashMap<String, ActiveVpnSession>,
    metrics: VpnSessionCoordinatorMetrics,
    data_metrics: VpnDataPolicyMetricsSnapshot,
    quotas: VpnQuotaBook,
}

struct ActiveVpnSession {
    session: VpnNegotiatedSession,
    connection: Arc<dyn VpnSessionConnection>,
}

impl ActiveVpnSession {
    fn snapshot(&self) -> VpnActiveSessionSnapshot {
        VpnActiveSessionSnapshot {
            client_id: self.session.identity().client_id().to_owned(),
            fingerprint: self.session.fingerprint(),
            session_generation: self.session.accept().session_generation,
            connection_stable_id: self.connection.stable_id(),
        }
    }
}

trait VpnSessionConnection: Send + Sync {
    fn stable_id(&self) -> usize;
    fn close(&self, code: u32, reason: &[u8]);
}

struct NoqConnectionHandle(Connection);

impl VpnSessionConnection for NoqConnectionHandle {
    fn stable_id(&self) -> usize {
        self.0.stable_id()
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.0.close(code.into(), reason);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileDecision {
    Keep,
    IdentityRevoked,
    PolicyChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    IdentityRevoked,
    PolicyChanged,
}

impl CloseReason {
    const fn code(self) -> u32 {
        match self {
            Self::IdentityRevoked => VPN_CLOSE_IDENTITY_REVOKED,
            Self::PolicyChanged => VPN_CLOSE_POLICY_CHANGED,
        }
    }

    const fn message(self) -> &'static [u8] {
        match self {
            Self::IdentityRevoked => IDENTITY_REVOKED_REASON,
            Self::PolicyChanged => POLICY_CHANGED_REASON,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{Ipv4Addr, Ipv6Addr},
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use crate::{
        VPN_CAP_IPV4, VPN_CAP_IPV6, VPN_MAX_IP_PACKET_LEN, VPN_REQUIRED_CAPABILITIES,
        VPN_WIRE_VERSION_V1, VpnHello, VpnIdentity, VpnIdentityLimits, VpnIpNetwork,
        VpnServerNegotiationConfig, negotiate_vpn_hello,
    };

    use super::*;

    #[test]
    fn successful_commit_replaces_old_and_stale_release_cannot_remove_new() {
        let old_fingerprint = fingerprint(1);
        let new_fingerprint = fingerprint(2);
        let registry = registry(vec![old_fingerprint, new_fingerprint], true, "0.0.0.0/0");
        let coordinator = VpnSessionCoordinator::new(registry.clone());
        let old_connection = Arc::new(FakeConnection::new());
        let old_session = session(&registry, old_fingerprint, 1);
        assert_eq!(
            coordinator
                .commit_with_handle(old_session, old_connection.clone())
                .unwrap(),
            VpnSessionCommitReport {
                session_generation: 1,
                replaced_generation: None,
            }
        );

        let new_connection = Arc::new(FakeConnection::new());
        let new_session = session(&registry, new_fingerprint, 2);
        assert_eq!(
            coordinator
                .commit_with_handle(new_session, new_connection.clone())
                .unwrap(),
            VpnSessionCommitReport {
                session_generation: 2,
                replaced_generation: Some(1),
            }
        );
        assert_eq!(
            old_connection.closes(),
            vec![(VPN_CLOSE_SESSION_REPLACED, SESSION_REPLACED_REASON.to_vec())]
        );
        assert!(new_connection.closes().is_empty());
        assert!(!coordinator.is_current("client-a", 1));
        assert!(coordinator.is_current("client-a", 2));
        assert!(!coordinator.release_if_current("client-a", 1));
        assert!(coordinator.is_current("client-a", 2));
        assert!(coordinator.release_if_current("client-a", 2));
        assert!(coordinator.active_session("client-a").is_none());
    }

    #[test]
    fn failed_candidate_commit_closes_new_and_preserves_healthy_old() {
        let old_fingerprint = fingerprint(1);
        let candidate_fingerprint = fingerprint(2);
        let overlap = registry(
            vec![old_fingerprint, candidate_fingerprint],
            true,
            "0.0.0.0/0",
        );
        let coordinator = VpnSessionCoordinator::new(overlap.clone());
        let old_connection = Arc::new(FakeConnection::new());
        coordinator
            .commit_with_handle(
                session(&overlap, old_fingerprint, 1),
                old_connection.clone(),
            )
            .unwrap();
        let candidate = session(&overlap, candidate_fingerprint, 2);

        let report =
            coordinator.replace_registry(registry(vec![old_fingerprint], true, "0.0.0.0/0"));
        assert_eq!(report.sessions.kept, 1);
        let candidate_connection = Arc::new(FakeConnection::new());
        assert_eq!(
            coordinator
                .commit_with_handle(candidate, candidate_connection.clone())
                .unwrap_err(),
            VpnSessionCommitError::IdentityRevoked
        );
        assert!(old_connection.closes().is_empty());
        assert!(coordinator.is_current("client-a", 1));
        assert_eq!(
            candidate_connection.closes(),
            vec![(VPN_CLOSE_COMMIT_REJECTED, COMMIT_REJECTED_REASON.to_vec())]
        );
    }

    #[test]
    fn reload_keeps_overlap_but_revokes_removed_fingerprint_and_changed_policy() {
        let old_fingerprint = fingerprint(1);
        let new_fingerprint = fingerprint(2);
        let original = registry(vec![old_fingerprint], true, "0.0.0.0/0");
        let coordinator = VpnSessionCoordinator::new(original.clone());
        let old_connection = Arc::new(FakeConnection::new());
        coordinator
            .commit_with_handle(
                session(&original, old_fingerprint, 1),
                old_connection.clone(),
            )
            .unwrap();

        let overlap = registry(vec![old_fingerprint, new_fingerprint], true, "0.0.0.0/0");
        let report = coordinator.replace_registry(overlap);
        assert_eq!(
            report.sessions,
            VpnSessionReconcileReport {
                kept: 1,
                identity_revoked: 0,
                policy_changed: 0,
            }
        );
        assert!(old_connection.closes().is_empty());

        let report =
            coordinator.replace_registry(registry(vec![new_fingerprint], true, "0.0.0.0/0"));
        assert_eq!(report.sessions.identity_revoked, 1);
        assert_eq!(
            old_connection.closes(),
            vec![(VPN_CLOSE_IDENTITY_REVOKED, IDENTITY_REVOKED_REASON.to_vec())]
        );

        let current = registry(vec![new_fingerprint], true, "0.0.0.0/0");
        let policy_connection = Arc::new(FakeConnection::new());
        coordinator
            .commit_with_handle(
                session(&current, new_fingerprint, 2),
                policy_connection.clone(),
            )
            .unwrap();
        let report =
            coordinator.replace_registry(registry(vec![new_fingerprint], true, "10.0.0.0/8"));
        assert_eq!(report.sessions.policy_changed, 1);
        assert_eq!(
            policy_connection.closes(),
            vec![(VPN_CLOSE_POLICY_CHANGED, POLICY_CHANGED_REASON.to_vec())]
        );
    }

    #[test]
    fn disabling_identity_and_shutdown_close_every_current_session_once() {
        let fingerprint = fingerprint(1);
        let original = registry(vec![fingerprint], true, "0.0.0.0/0");
        let coordinator = VpnSessionCoordinator::new(original.clone());
        let first = Arc::new(FakeConnection::new());
        coordinator
            .commit_with_handle(session(&original, fingerprint, 1), first.clone())
            .unwrap();
        let report = coordinator.replace_registry(registry(vec![fingerprint], false, "0.0.0.0/0"));
        assert_eq!(report.sessions.identity_revoked, 1);
        assert_eq!(first.closes().len(), 1);

        let enabled = registry(vec![fingerprint], true, "0.0.0.0/0");
        coordinator.replace_registry(enabled.clone());
        let second = Arc::new(FakeConnection::new());
        coordinator
            .commit_with_handle(session(&enabled, fingerprint, 2), second.clone())
            .unwrap();
        assert_eq!(coordinator.close_all(), 1);
        assert_eq!(coordinator.close_all(), 0);
        assert_eq!(
            second.closes(),
            vec![(VPN_CLOSE_SERVER_SHUTDOWN, SERVER_SHUTDOWN_REASON.to_vec())]
        );
        assert_eq!(coordinator.metrics_snapshot().active_sessions, 0);
    }

    #[test]
    fn generation_allocator_uses_max_once_then_fails_closed() {
        let coordinator = VpnSessionCoordinator::with_initial_generation(
            registry(vec![fingerprint(1)], true, "0.0.0.0/0"),
            u64::MAX,
        )
        .unwrap();
        assert_eq!(coordinator.allocate_generation().unwrap().get(), u64::MAX);
        assert_eq!(
            coordinator.allocate_generation().unwrap_err(),
            VpnManagedSessionError::GenerationExhausted
        );
    }

    #[test]
    fn replacement_and_fast_reconnect_do_not_reset_shared_rate_tokens() {
        let started = Instant::now();
        let old_fingerprint = fingerprint(1);
        let new_fingerprint = fingerprint(2);
        let limits = VpnIdentityLimits::new(1, 1, 65_535, VPN_MAX_IP_PACKET_LEN).unwrap();
        let registry = registry_with_limits(
            vec![old_fingerprint, new_fingerprint],
            true,
            "0.0.0.0/0",
            limits,
        );
        let coordinator = VpnSessionCoordinator::new(registry.clone());
        coordinator
            .commit_with_handle_at(
                session(&registry, old_fingerprint, 1),
                Arc::new(FakeConnection::new()),
                started,
            )
            .unwrap();
        coordinator
            .admit_packet("client-a", 1, VpnPacketDirection::Uplink, 1, started)
            .unwrap();
        assert_eq!(
            coordinator.admit_packet("client-a", 1, VpnPacketDirection::Downlink, 1, started,),
            Err(VpnQuotaRejection::PacketRateExceeded)
        );

        coordinator
            .commit_with_handle_at(
                session(&registry, new_fingerprint, 2),
                Arc::new(FakeConnection::new()),
                started,
            )
            .unwrap();
        assert_eq!(
            coordinator.admit_packet("client-a", 1, VpnPacketDirection::Uplink, 1, started,),
            Err(VpnQuotaRejection::StaleGeneration)
        );
        assert_eq!(
            coordinator.admit_packet("client-a", 2, VpnPacketDirection::Uplink, 1, started,),
            Err(VpnQuotaRejection::PacketRateExceeded)
        );

        let refilled = started + Duration::from_secs(1);
        coordinator
            .admit_packet("client-a", 2, VpnPacketDirection::Uplink, 1, refilled)
            .unwrap();
        assert!(coordinator.release_if_current("client-a", 2));
        coordinator
            .commit_with_handle_at(
                session(&registry, new_fingerprint, 3),
                Arc::new(FakeConnection::new()),
                refilled,
            )
            .unwrap();
        assert_eq!(
            coordinator.admit_packet("client-a", 3, VpnPacketDirection::Uplink, 1, refilled,),
            Err(VpnQuotaRejection::PacketRateExceeded)
        );
        let metrics = coordinator.quota_metrics_snapshot();
        assert_eq!(metrics.admitted_uplink_packets, 2);
        assert_eq!(metrics.packet_rate_rejections, 3);
        assert_eq!(metrics.stale_generation_rejections, 1);
    }

    #[test]
    fn reassembly_reservation_survives_replacement_and_releases_on_drop() {
        let started = Instant::now();
        let fingerprint = fingerprint(1);
        let limits = VpnIdentityLimits::new(1, 100, 100_000, 100_000).unwrap();
        let registry = registry_with_limits(vec![fingerprint], true, "0.0.0.0/0", limits);
        let coordinator =
            VpnSessionCoordinator::with_resource_limits(registry.clone(), 1, 80_000, 2).unwrap();
        coordinator
            .commit_with_handle_at(
                session(&registry, fingerprint, 1),
                Arc::new(FakeConnection::new()),
                started,
            )
            .unwrap();
        let old_reservation = coordinator
            .reserve_reassembly("client-a", 1, 60_000)
            .unwrap();
        assert_eq!(old_reservation.bytes(), 60_000);
        assert_eq!(
            coordinator
                .reserve_reassembly("client-a", 1, 30_000)
                .unwrap_err(),
            VpnQuotaRejection::GlobalReassemblyLimit
        );

        coordinator
            .commit_with_handle_at(
                session(&registry, fingerprint, 2),
                Arc::new(FakeConnection::new()),
                started,
            )
            .unwrap();
        assert_eq!(
            coordinator
                .reserve_reassembly("client-a", 1, 1)
                .unwrap_err(),
            VpnQuotaRejection::StaleGeneration
        );
        assert_eq!(
            coordinator
                .reserve_reassembly("client-a", 2, 30_000)
                .unwrap_err(),
            VpnQuotaRejection::GlobalReassemblyLimit
        );
        old_reservation.release();
        let current = coordinator
            .reserve_reassembly("client-a", 2, 30_000)
            .unwrap();
        assert_eq!(
            coordinator
                .quota_metrics_snapshot()
                .current_reassembly_bytes,
            30_000
        );
        drop(current);
        let metrics = coordinator.quota_metrics_snapshot();
        assert_eq!(metrics.current_reassembly_bytes, 0);
        assert_eq!(metrics.active_reassembly_reservations, 0);
        assert_eq!(metrics.peak_reassembly_bytes, 60_000);
    }

    #[test]
    fn coordinator_applies_rate_limit_before_source_and_destination_policy() {
        let started = Instant::now();
        let fingerprint = fingerprint(1);
        let registry = registry(vec![fingerprint], true, "198.51.100.0/24");
        let coordinator = VpnSessionCoordinator::new(registry.clone());
        coordinator
            .commit_with_handle_at(
                session(&registry, fingerprint, 1),
                Arc::new(FakeConnection::new()),
                started,
            )
            .unwrap();

        coordinator
            .authorize_ip_packet(
                "client-a",
                1,
                VpnPacketDirection::Uplink,
                &ipv4_packet("10.77.0.2", "198.51.100.8"),
                started,
            )
            .unwrap();
        assert_eq!(
            coordinator
                .authorize_ip_packet(
                    "client-a",
                    1,
                    VpnPacketDirection::Uplink,
                    &ipv4_packet("10.77.0.9", "198.51.100.8"),
                    started,
                )
                .unwrap_err(),
            VpnDataPolicyError::UplinkSourceSpoofed
        );
        assert_eq!(
            coordinator
                .authorize_ip_packet(
                    "client-a",
                    1,
                    VpnPacketDirection::Uplink,
                    &ipv4_packet("10.77.0.2", "203.0.113.8"),
                    started,
                )
                .unwrap_err(),
            VpnDataPolicyError::DestinationPolicyRejected
        );
        coordinator
            .authorize_ip_packet(
                "client-a",
                1,
                VpnPacketDirection::Downlink,
                &ipv4_packet("198.51.100.8", "10.77.0.2"),
                started,
            )
            .unwrap();
        assert_eq!(
            coordinator
                .authorize_ip_packet(
                    "client-a",
                    1,
                    VpnPacketDirection::Downlink,
                    &ipv4_packet("198.51.100.8", "10.77.0.9"),
                    started,
                )
                .unwrap_err(),
            VpnDataPolicyError::DownlinkDestinationMismatch
        );
        assert_eq!(
            coordinator
                .authorize_ip_packet("client-a", 1, VpnPacketDirection::Uplink, &[0x40], started,)
                .unwrap_err(),
            VpnDataPolicyError::Packet(crate::VpnPacketError::InvalidIpv4Header)
        );
        assert_eq!(
            coordinator
                .authorize_ip_packet(
                    "client-a",
                    2,
                    VpnPacketDirection::Uplink,
                    &ipv4_packet("10.77.0.2", "198.51.100.8"),
                    started,
                )
                .unwrap_err(),
            VpnDataPolicyError::StaleGeneration
        );

        let data = coordinator.data_policy_metrics_snapshot();
        assert_eq!(data.forwarded_uplink_packets, 1);
        assert_eq!(data.forwarded_downlink_packets, 1);
        assert_eq!(data.uplink_source_spoof_rejections, 1);
        assert_eq!(data.destination_policy_rejections, 1);
        assert_eq!(data.downlink_destination_rejections, 1);
        assert_eq!(data.malformed_packet_rejections, 1);
        let quota = coordinator.quota_metrics_snapshot();
        assert_eq!(quota.admitted_uplink_packets, 4);
        assert_eq!(quota.admitted_downlink_packets, 2);
        assert_eq!(quota.stale_generation_rejections, 1);
    }

    #[test]
    fn concurrent_packet_admission_cannot_oversubscribe_one_identity_bucket() {
        let started = Instant::now();
        let fingerprint = fingerprint(1);
        let limits = VpnIdentityLimits::new(1, 10, 1_000_000, VPN_MAX_IP_PACKET_LEN).unwrap();
        let registry = registry_with_limits(vec![fingerprint], true, "0.0.0.0/0", limits);
        let coordinator = VpnSessionCoordinator::new(registry.clone());
        coordinator
            .commit_with_handle_at(
                session(&registry, fingerprint, 1),
                Arc::new(FakeConnection::new()),
                started,
            )
            .unwrap();

        let workers = (0..32)
            .map(|_| {
                let coordinator = coordinator.clone();
                std::thread::spawn(move || {
                    coordinator
                        .admit_packet("client-a", 1, VpnPacketDirection::Uplink, 1, started)
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        let accepted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, 10);
        let metrics = coordinator.quota_metrics_snapshot();
        assert_eq!(metrics.admitted_uplink_packets, 10);
        assert_eq!(metrics.packet_rate_rejections, 22);
    }

    #[test]
    fn failed_identity_file_reload_keeps_active_then_disabled_reload_closes_it() {
        let fingerprint = fingerprint(1);
        let registry = registry(vec![fingerprint], true, "0.0.0.0/0");
        let coordinator = VpnSessionCoordinator::new(registry.clone());
        let connection = Arc::new(FakeConnection::new());
        coordinator
            .commit_with_handle(session(&registry, fingerprint, 1), connection.clone())
            .unwrap();

        let path = std::env::temp_dir().join(format!(
            "flowweave-vpn-coordinator-{}-{}.json",
            std::process::id(),
            connection.stable_id()
        ));
        write_private_identity_config(&path, b"{not-json");
        assert!(coordinator.reload_from_path(&path).is_err());
        assert!(coordinator.is_current("client-a", 1));
        assert!(connection.closes().is_empty());

        let disabled = format!(
            r#"{{
                "config_version":1,
                "server_ipv4":"10.77.0.1",
                "server_ipv6":"fd77::1",
                "identities":[{{
                    "client_id":"client-a",
                    "fingerprints":["{}"],
                    "enabled":false,
                    "client_ipv4":"10.77.0.2",
                    "client_ipv6":"fd77::2",
                    "allowed_destinations":["0.0.0.0/0","::/0"],
                    "limits":{{
                        "max_connections":1,
                        "max_packets_per_second":100000,
                        "max_bytes_per_second":134217728,
                        "max_reassembly_bytes":8388608
                    }}
                }}]
            }}"#,
            fingerprint.to_hex()
        );
        write_private_identity_config(&path, disabled.as_bytes());
        let report = coordinator.reload_from_path(&path).unwrap();
        assert_eq!(report.sessions.identity_revoked, 1);
        assert!(!coordinator.is_current("client-a", 1));
        assert_eq!(
            connection.closes(),
            vec![(VPN_CLOSE_IDENTITY_REVOKED, IDENTITY_REVOKED_REASON.to_vec())]
        );
        let _ = fs::remove_file(path);
    }

    fn fingerprint(value: u8) -> VpnCertificateFingerprint {
        VpnCertificateFingerprint::from_sha256([value; 32])
    }

    fn registry(
        fingerprints: Vec<VpnCertificateFingerprint>,
        enabled: bool,
        ipv4_policy: &str,
    ) -> VpnIdentityRegistry {
        registry_with_limits(
            fingerprints,
            enabled,
            ipv4_policy,
            VpnIdentityLimits::default(),
        )
    }

    fn registry_with_limits(
        fingerprints: Vec<VpnCertificateFingerprint>,
        enabled: bool,
        ipv4_policy: &str,
        limits: VpnIdentityLimits,
    ) -> VpnIdentityRegistry {
        let (network, prefix) = ipv4_policy.split_once('/').unwrap();
        let identity = VpnIdentity::new(
            "client-a",
            fingerprints,
            enabled,
            Some("10.77.0.2".parse().unwrap()),
            Some("fd77::2".parse::<Ipv6Addr>().unwrap()),
            vec![
                VpnIpNetwork::v4(
                    network.parse::<Ipv4Addr>().unwrap(),
                    prefix.parse().unwrap(),
                )
                .unwrap(),
                VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
            ],
            limits,
        )
        .unwrap();
        VpnIdentityRegistry::new(
            Some("10.77.0.1".parse().unwrap()),
            Some("fd77::1".parse().unwrap()),
            vec![identity],
        )
        .unwrap()
    }

    fn session(
        registry: &VpnIdentityRegistry,
        fingerprint: VpnCertificateFingerprint,
        generation: u64,
    ) -> VpnNegotiatedSession {
        negotiate_vpn_hello(
            registry,
            fingerprint,
            VpnHello {
                min_wire_version: VPN_WIRE_VERSION_V1,
                max_wire_version: VPN_WIRE_VERSION_V1,
                capabilities: VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4 | VPN_CAP_IPV6,
                max_ip_packet_len: u16::MAX,
                max_datagram_len: 1200,
            },
            VpnServerNegotiationConfig::default(),
            VpnSessionGeneration::new(generation).unwrap(),
        )
        .unwrap()
    }

    fn ipv4_packet(source: &str, destination: &str) -> Vec<u8> {
        let source = source.parse::<Ipv4Addr>().unwrap().octets();
        let destination = destination.parse::<Ipv4Addr>().unwrap().octets();
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn write_private_identity_config(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
        set_private_permissions(path);
    }

    #[cfg(unix)]
    fn set_private_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_private_permissions(_path: &Path) {}

    struct FakeConnection {
        stable_id: usize,
        closes: Mutex<Vec<(u32, Vec<u8>)>>,
    }

    impl FakeConnection {
        fn new() -> Self {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
            Self {
                stable_id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                closes: Mutex::new(Vec::new()),
            }
        }

        fn closes(&self) -> Vec<(u32, Vec<u8>)> {
            self.closes.lock().unwrap().clone()
        }
    }

    impl VpnSessionConnection for FakeConnection {
        fn stable_id(&self) -> usize {
            self.stable_id
        }

        fn close(&self, code: u32, reason: &[u8]) {
            self.closes.lock().unwrap().push((code, reason.to_vec()));
        }
    }
}

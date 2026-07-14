use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    VPN_PRODUCT_CONFIG_MAX_BYTES, VpnClientProductConfig, VpnIpNetwork,
    parse_vpn_client_product_config_json,
};

use super::{
    IpCommand, PLAN_FINGERPRINT_BYTES, STATE_TEMP_SEQUENCE, VpnNetworkError, VpnNetworkIoStage,
    VpnNetworkIpOperation, VpnNetworkRole, VpnNetworkState, VpnNetworkStateLock,
    VpnNetworkStatePhase, client_network_plan, config_base, ensure_privileged_network_helper,
    hex_encode, io_error, read_owned_private_file, sync_directory, valid_lower_hex,
    validate_prepared_state, validate_root_private_regular_file,
};

pub const VPN_CLIENT_ROUTE_STATE_VERSION: u16 = 1;
pub const VPN_CLIENT_ROUTE_STATE_MAX_BYTES: usize = 64 * 1024;
const CLIENT_ROUTE_STATE_SUFFIX: &str = ".routes";
const CLIENT_ROUTE_PLAN_FINGERPRINT_BYTES: usize = 32;
const CLIENT_ROUTE_STATE_FINGERPRINT_BYTES: usize = 32;
const ROUTE_PROTOCOL_MIN: u32 = 200;
const ROUTE_PROTOCOL_MAX: u32 = 252;
const ROUTE_TABLE_MIN: u32 = 10_000;
const ROUTE_TABLE_MAX: u32 = 59_999;
const ROUTE_PRIORITY_MIN: u32 = 10_000;
const ROUTE_PRIORITY_MAX: u32 = 29_999;
const ROUTE_METRIC_MIN: u32 = 40_000;
const ROUTE_METRIC_MAX: u32 = 59_999;
const ROUTE_SLOT_ATTEMPTS: usize = 64;
const MAIN_ROUTE_TABLE: u32 = 254;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientRouteActivationOutcome {
    Activated,
    AlreadyActive,
    RecoveredAndActivated,
}

impl VpnClientRouteActivationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activated => "activated",
            Self::AlreadyActive => "already_active",
            Self::RecoveredAndActivated => "recovered_and_activated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnClientRouteDeactivationOutcome {
    Deactivated,
    AlreadyInactive,
    RecoveredInterruptedActivation,
}

impl VpnClientRouteDeactivationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deactivated => "deactivated",
            Self::AlreadyInactive => "already_inactive",
            Self::RecoveredInterruptedActivation => "recovered_interrupted_activation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    const ALL: [Self; 2] = [Self::Ipv4, Self::Ipv6];

    const fn ip_flag(self) -> &'static str {
        match self {
            Self::Ipv4 => "-4",
            Self::Ipv6 => "-6",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct VpnClientRoutePlan {
    network_plan_fingerprint: String,
    tun_name: String,
    interface_index: u32,
    owner_uid: u32,
    destination_networks: Vec<String>,
    fingerprint: String,
}

impl VpnClientRoutePlan {
    fn new(
        network_state: &VpnNetworkState,
        config: &VpnClientProductConfig,
    ) -> Result<Self, VpnNetworkError> {
        let interface_index = network_state
            .interface_index
            .filter(|index| *index != 0)
            .ok_or(VpnNetworkError::ClientRouteStateInvalid)?;
        let mut destination_networks = config
            .allowed_destinations()
            .iter()
            .copied()
            .map(network_prefix)
            .collect::<Vec<_>>();
        destination_networks.sort();
        destination_networks.dedup();
        if destination_networks.is_empty() {
            return Err(VpnNetworkError::InvalidPlan);
        }
        let mut plan = Self {
            network_plan_fingerprint: network_state.plan_fingerprint.clone(),
            tun_name: network_state.tun_name.clone(),
            interface_index,
            owner_uid: network_state.owner_uid,
            destination_networks,
            fingerprint: String::new(),
        };
        plan.fingerprint = plan.compute_fingerprint()?;
        Ok(plan)
    }

    fn compute_fingerprint(&self) -> Result<String, VpnNetworkError> {
        #[derive(Serialize)]
        struct CanonicalRoutePlan<'a> {
            plan_version: u16,
            network_plan_fingerprint: &'a str,
            tun_name: &'a str,
            interface_index: u32,
            owner_uid: u32,
            destination_networks: &'a [String],
        }

        let bytes = serde_json::to_vec(&CanonicalRoutePlan {
            plan_version: 1,
            network_plan_fingerprint: &self.network_plan_fingerprint,
            tun_name: &self.tun_name,
            interface_index: self.interface_index,
            owner_uid: self.owner_uid,
            destination_networks: &self.destination_networks,
        })
        .map_err(|_| VpnNetworkError::InvalidPlan)?;
        Ok(hex_encode(digest(&SHA256, &bytes).as_ref()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VpnClientRouteStatePhase {
    Activating,
    Active,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VpnClientRouteState {
    state_version: u16,
    phase: VpnClientRouteStatePhase,
    route_plan_fingerprint: String,
    state_fingerprint: String,
    network_plan_fingerprint: String,
    tun_name: String,
    interface_index: u32,
    owner_uid: u32,
    route_protocol: u8,
    route_table: u32,
    uid_rule_priority: u32,
    tunnel_rule_priority: u32,
    route_metric: u32,
    destination_networks: Vec<String>,
}

impl VpnClientRouteState {
    fn new_activating(plan: &VpnClientRoutePlan, slot: RouteSlot) -> Result<Self, VpnNetworkError> {
        let mut state = Self {
            state_version: VPN_CLIENT_ROUTE_STATE_VERSION,
            phase: VpnClientRouteStatePhase::Activating,
            route_plan_fingerprint: plan.fingerprint.clone(),
            state_fingerprint: String::new(),
            network_plan_fingerprint: plan.network_plan_fingerprint.clone(),
            tun_name: plan.tun_name.clone(),
            interface_index: plan.interface_index,
            owner_uid: plan.owner_uid,
            route_protocol: slot.protocol,
            route_table: slot.table,
            uid_rule_priority: slot.uid_priority,
            tunnel_rule_priority: slot.tunnel_priority,
            route_metric: slot.metric,
            destination_networks: plan.destination_networks.clone(),
        };
        state.state_fingerprint = state.compute_state_fingerprint()?;
        state.validate_shape()?;
        Ok(state)
    }

    fn validate_shape(&self) -> Result<(), VpnNetworkError> {
        if self.state_version != VPN_CLIENT_ROUTE_STATE_VERSION {
            return Err(VpnNetworkError::ClientRouteStateUnsupportedVersion);
        }
        super::validate_vpn_tun_name(&self.tun_name)
            .map_err(|_| VpnNetworkError::ClientRouteStateInvalid)?;
        if self.interface_index == 0
            || self.owner_uid == 0
            || !valid_lower_hex(
                &self.route_plan_fingerprint,
                CLIENT_ROUTE_PLAN_FINGERPRINT_BYTES,
            )
            || !valid_lower_hex(&self.network_plan_fingerprint, PLAN_FINGERPRINT_BYTES)
            || !valid_lower_hex(
                &self.state_fingerprint,
                CLIENT_ROUTE_STATE_FINGERPRINT_BYTES,
            )
            || !(ROUTE_PROTOCOL_MIN..=ROUTE_PROTOCOL_MAX).contains(&u32::from(self.route_protocol))
            || !(ROUTE_TABLE_MIN..=ROUTE_TABLE_MAX).contains(&self.route_table)
            || !(ROUTE_PRIORITY_MIN..=ROUTE_PRIORITY_MAX).contains(&self.uid_rule_priority)
            || self.tunnel_rule_priority != self.uid_rule_priority + 1
            || self.tunnel_rule_priority > ROUTE_PRIORITY_MAX + 1
            || !(ROUTE_METRIC_MIN..=ROUTE_METRIC_MAX).contains(&self.route_metric)
            || self.destination_networks.is_empty()
        {
            return Err(VpnNetworkError::ClientRouteStateInvalid);
        }
        let parsed = self
            .destination_networks
            .iter()
            .map(|network| parse_network_prefix(network))
            .collect::<Result<Vec<_>, _>>()?;
        let mut canonical = parsed
            .iter()
            .copied()
            .map(network_prefix)
            .collect::<Vec<_>>();
        canonical.sort();
        canonical.dedup();
        if canonical != self.destination_networks
            || self.compute_state_fingerprint()? != self.state_fingerprint
        {
            return Err(VpnNetworkError::ClientRouteStateInvalid);
        }
        Ok(())
    }

    fn compute_state_fingerprint(&self) -> Result<String, VpnNetworkError> {
        #[derive(Serialize)]
        struct CanonicalRouteState<'a> {
            state_version: u16,
            route_plan_fingerprint: &'a str,
            network_plan_fingerprint: &'a str,
            tun_name: &'a str,
            interface_index: u32,
            owner_uid: u32,
            route_protocol: u8,
            route_table: u32,
            uid_rule_priority: u32,
            tunnel_rule_priority: u32,
            route_metric: u32,
            destination_networks: &'a [String],
        }

        let bytes = serde_json::to_vec(&CanonicalRouteState {
            state_version: self.state_version,
            route_plan_fingerprint: &self.route_plan_fingerprint,
            network_plan_fingerprint: &self.network_plan_fingerprint,
            tun_name: &self.tun_name,
            interface_index: self.interface_index,
            owner_uid: self.owner_uid,
            route_protocol: self.route_protocol,
            route_table: self.route_table,
            uid_rule_priority: self.uid_rule_priority,
            tunnel_rule_priority: self.tunnel_rule_priority,
            route_metric: self.route_metric,
            destination_networks: &self.destination_networks,
        })
        .map_err(|_| VpnNetworkError::ClientRouteStateInvalid)?;
        Ok(hex_encode(digest(&SHA256, &bytes).as_ref()))
    }

    fn families(&self) -> HashSet<AddressFamily> {
        self.destination_networks
            .iter()
            .filter_map(|network| parse_network_prefix(network).ok())
            .map(network_family)
            .collect()
    }
}

impl std::fmt::Debug for VpnClientRouteState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VpnClientRouteState")
            .field("state_version", &self.state_version)
            .field("phase", &self.phase)
            .field("tun_name", &self.tun_name)
            .field("interface_index", &self.interface_index)
            .field("owner_uid", &self.owner_uid)
            .field("route_protocol", &self.route_protocol)
            .field("route_table", &self.route_table)
            .field("uid_rule_priority", &self.uid_rule_priority)
            .field("tunnel_rule_priority", &self.tunnel_rule_priority)
            .field("route_metric", &self.route_metric)
            .field(
                "destination_network_count",
                &self.destination_networks.len(),
            )
            .field("route_plan_fingerprint", &"[redacted]")
            .field("state_fingerprint", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct RouteSlot {
    protocol: u8,
    table: u32,
    uid_priority: u32,
    tunnel_priority: u32,
    metric: u32,
}

pub fn activate_vpn_client_routes(
    config_path: &Path,
    state_path: &Path,
) -> Result<VpnClientRouteActivationOutcome, VpnNetworkError> {
    ensure_privileged_network_helper()?;
    let state_lock = VpnNetworkStateLock::acquire(state_path)?;
    let network_state = state_lock.read()?.ok_or(VpnNetworkError::StateConflict)?;
    let network_plan = network_state.plan()?;
    if network_state.role != VpnNetworkRole::Client
        || network_state.phase != VpnNetworkStatePhase::Prepared
    {
        return Err(VpnNetworkError::StateConflict);
    }
    let ip = IpCommand::discover()?;
    validate_prepared_state(&ip, &network_state, &network_plan)?;

    let config_file = read_owned_private_file(
        config_path,
        VPN_PRODUCT_CONFIG_MAX_BYTES,
        VpnNetworkIoStage::ConfigOpen,
        VpnNetworkIoStage::ConfigInspect,
        VpnNetworkIoStage::ConfigRead,
    )?;
    let config =
        parse_vpn_client_product_config_json(&config_file.bytes, config_base(config_path))?;
    let current_network_plan =
        client_network_plan(&config, network_state.owner_uid, config_file.gid)?;
    if current_network_plan.fingerprint != network_plan.fingerprint {
        return Err(VpnNetworkError::StateConflict);
    }
    let route_plan = VpnClientRoutePlan::new(&network_state, &config)?;

    let mut recovered = false;
    if let Some(existing) = state_lock.read_client_routes()? {
        existing.validate_shape()?;
        match existing.phase {
            VpnClientRouteStatePhase::Active => {
                if existing.network_plan_fingerprint != route_plan.network_plan_fingerprint
                    || existing.route_plan_fingerprint != route_plan.fingerprint
                {
                    return Err(VpnNetworkError::ClientRouteStateConflict);
                }
                validate_active_routes(&ip, &existing)?;
                return Ok(VpnClientRouteActivationOutcome::AlreadyActive);
            }
            VpnClientRouteStatePhase::Activating => {
                rollback_client_routes(&ip, &existing)?;
                state_lock.remove_client_routes()?;
                recovered = true;
            }
        }
    }

    let slot = choose_route_slot(&ip)?;
    let mut route_state = VpnClientRouteState::new_activating(&route_plan, slot)?;
    state_lock.write_client_routes(&route_state)?;
    let result = (|| {
        install_client_routes(&ip, &route_state)?;
        validate_active_routes(&ip, &route_state)?;
        route_state.phase = VpnClientRouteStatePhase::Active;
        state_lock.write_client_routes(&route_state)
    })();
    if let Err(error) = result {
        if rollback_client_routes(&ip, &route_state).is_err()
            || state_lock.remove_client_routes().is_err()
        {
            return Err(VpnNetworkError::RollbackFailed);
        }
        return Err(error);
    }

    Ok(if recovered {
        VpnClientRouteActivationOutcome::RecoveredAndActivated
    } else {
        VpnClientRouteActivationOutcome::Activated
    })
}

pub fn deactivate_vpn_client_routes(
    state_path: &Path,
) -> Result<VpnClientRouteDeactivationOutcome, VpnNetworkError> {
    ensure_privileged_network_helper()?;
    let state_lock = VpnNetworkStateLock::acquire(state_path)?;
    deactivate_vpn_client_routes_locked(&state_lock)
}

pub(super) fn deactivate_vpn_client_routes_locked(
    state_lock: &VpnNetworkStateLock,
) -> Result<VpnClientRouteDeactivationOutcome, VpnNetworkError> {
    let Some(state) = state_lock.read_client_routes()? else {
        return Ok(VpnClientRouteDeactivationOutcome::AlreadyInactive);
    };
    state.validate_shape()?;
    let ip = IpCommand::discover()?;
    let interrupted = state.phase == VpnClientRouteStatePhase::Activating;
    rollback_client_routes(&ip, &state)?;
    state_lock.remove_client_routes()?;
    Ok(if interrupted {
        VpnClientRouteDeactivationOutcome::RecoveredInterruptedActivation
    } else {
        VpnClientRouteDeactivationOutcome::Deactivated
    })
}

impl VpnNetworkStateLock {
    fn client_route_state_path(&self) -> Result<PathBuf, VpnNetworkError> {
        let mut name = self
            .state_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(VpnNetworkError::InvalidStatePath)?
            .to_os_string();
        name.push(CLIENT_ROUTE_STATE_SUFFIX);
        Ok(self.state_directory.join(name))
    }

    fn read_client_routes(&self) -> Result<Option<VpnClientRouteState>, VpnNetworkError> {
        let path = self.client_route_state_path()?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(VpnNetworkIoStage::ClientRouteStateOpen, error)),
        };
        let metadata = validate_root_private_regular_file(
            &file,
            VpnNetworkIoStage::ClientRouteStateInspect,
            true,
        )?;
        if metadata.len() > VPN_CLIENT_ROUTE_STATE_MAX_BYTES as u64 {
            return Err(VpnNetworkError::ClientRouteStateTooLarge);
        }
        let mut limited = file.take((VPN_CLIENT_ROUTE_STATE_MAX_BYTES + 1) as u64);
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(VPN_CLIENT_ROUTE_STATE_MAX_BYTES)
                .min(VPN_CLIENT_ROUTE_STATE_MAX_BYTES),
        );
        limited
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(VpnNetworkIoStage::ClientRouteStateRead, error))?;
        if bytes.len() > VPN_CLIENT_ROUTE_STATE_MAX_BYTES {
            return Err(VpnNetworkError::ClientRouteStateTooLarge);
        }
        let state: VpnClientRouteState = serde_json::from_slice(&bytes).map_err(|error| {
            VpnNetworkError::ClientRouteStateInvalidJson {
                line: error.line(),
                column: error.column(),
            }
        })?;
        state.validate_shape()?;
        Ok(Some(state))
    }

    fn write_client_routes(&self, state: &VpnClientRouteState) -> Result<(), VpnNetworkError> {
        state.validate_shape()?;
        let path = self.client_route_state_path()?;
        let mut bytes = serde_json::to_vec_pretty(state)
            .map_err(|_| VpnNetworkError::ClientRouteStateInvalid)?;
        bytes.push(b'\n');
        if bytes.len() > VPN_CLIENT_ROUTE_STATE_MAX_BYTES {
            return Err(VpnNetworkError::ClientRouteStateTooLarge);
        }
        let file_name = path.file_name().ok_or(VpnNetworkError::InvalidStatePath)?;
        let sequence = STATE_TEMP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".tmp.{}.{}", std::process::id(), sequence));
        let temporary_path = self.state_directory.join(temporary_name);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary_path)
                .map_err(|error| io_error(VpnNetworkIoStage::ClientRouteStateWrite, error))?;
            file.write_all(&bytes)
                .map_err(|error| io_error(VpnNetworkIoStage::ClientRouteStateWrite, error))?;
            file.sync_all()
                .map_err(|error| io_error(VpnNetworkIoStage::ClientRouteStateSync, error))?;
            fs::rename(&temporary_path, &path)
                .map_err(|error| io_error(VpnNetworkIoStage::ClientRouteStateRename, error))?;
            sync_directory(&self.state_directory)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn remove_client_routes(&self) -> Result<(), VpnNetworkError> {
        let path = self.client_route_state_path()?;
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&self.state_directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(VpnNetworkIoStage::ClientRouteStateRemove, error)),
        }
    }
}

fn choose_route_slot(ip: &IpCommand) -> Result<RouteSlot, VpnNetworkError> {
    let ipv4_rules = inspect_policy_rules(ip, AddressFamily::Ipv4)?;
    let ipv6_rules = inspect_policy_rules(ip, AddressFamily::Ipv6)?;
    for _ in 0..ROUTE_SLOT_ATTEMPTS {
        let uid_priority = random_range(ROUTE_PRIORITY_MIN, ROUTE_PRIORITY_MAX)?;
        let slot = RouteSlot {
            protocol: u8::try_from(random_range(ROUTE_PROTOCOL_MIN, ROUTE_PROTOCOL_MAX)?)
                .map_err(|_| VpnNetworkError::RandomUnavailable)?,
            table: random_range(ROUTE_TABLE_MIN, ROUTE_TABLE_MAX)?,
            uid_priority,
            tunnel_priority: uid_priority + 1,
            metric: random_range(ROUTE_METRIC_MIN, ROUTE_METRIC_MAX)?,
        };
        if rules_reserve_slot(&ipv4_rules, slot) || rules_reserve_slot(&ipv6_rules, slot) {
            continue;
        }
        if !inspect_policy_routes(ip, AddressFamily::Ipv4, slot.table)?.is_empty()
            || !inspect_policy_routes(ip, AddressFamily::Ipv6, slot.table)?.is_empty()
        {
            continue;
        }
        return Ok(slot);
    }
    Err(VpnNetworkError::ClientRouteSlotUnavailable)
}

fn random_range(minimum: u32, maximum: u32) -> Result<u32, VpnNetworkError> {
    let mut bytes = [0_u8; 4];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| VpnNetworkError::RandomUnavailable)?;
    let span = maximum
        .checked_sub(minimum)
        .and_then(|value| value.checked_add(1))
        .ok_or(VpnNetworkError::RandomUnavailable)?;
    Ok(minimum + u32::from_le_bytes(bytes) % span)
}

#[derive(Deserialize)]
struct RawPolicyRule {
    priority: u32,
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    uid_start: Option<u32>,
    #[serde(default)]
    uid_end: Option<u32>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

fn inspect_policy_rules(
    ip: &IpCommand,
    family: AddressFamily,
) -> Result<Vec<RawPolicyRule>, VpnNetworkError> {
    ip.json(
        VpnNetworkIpOperation::InspectPolicyRule,
        &[family.ip_flag(), "-N", "-j", "rule", "show"],
    )
}

fn rules_reserve_slot(rules: &[RawPolicyRule], slot: RouteSlot) -> bool {
    rules.iter().any(|rule| {
        rule.priority == slot.uid_priority
            || rule.priority == slot.tunnel_priority
            || parse_numeric(&rule.table) == Some(slot.table)
    })
}

#[derive(Deserialize)]
struct RawPolicyRoute {
    dst: String,
    #[serde(default)]
    dev: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
    #[serde(default)]
    pref: Option<String>,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

fn inspect_policy_routes(
    ip: &IpCommand,
    family: AddressFamily,
    table: u32,
) -> Result<Vec<RawPolicyRoute>, VpnNetworkError> {
    let table = table.to_string();
    let output = ip
        .command(&[
            family.ip_flag(),
            "-N",
            "-j",
            "route",
            "show",
            "table",
            &table,
        ])?
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| VpnNetworkError::Io {
            stage: VpnNetworkIoStage::IpSpawn,
            kind: error.kind(),
        })?;
    let routes: Vec<RawPolicyRoute> = serde_json::from_slice(&output.stdout)
        .map_err(|_| VpnNetworkError::IpOutputInvalid(VpnNetworkIpOperation::InspectPolicyRoute))?;
    if output.status.success() || output.status.code() == Some(2) && routes.is_empty() {
        Ok(routes)
    } else {
        Err(VpnNetworkError::IpCommandFailed {
            operation: VpnNetworkIpOperation::InspectPolicyRoute,
            status: output.status.code(),
        })
    }
}

fn install_client_routes(
    ip: &IpCommand,
    state: &VpnClientRouteState,
) -> Result<(), VpnNetworkError> {
    for family in state.families() {
        add_uid_escape_rule(ip, state, family)?;
    }
    for network in &state.destination_networks {
        add_policy_route(ip, state, network)?;
    }
    for family in state.families() {
        add_tunnel_rule(ip, state, family)?;
    }
    Ok(())
}

fn add_uid_escape_rule(
    ip: &IpCommand,
    state: &VpnClientRouteState,
    family: AddressFamily,
) -> Result<(), VpnNetworkError> {
    let priority = state.uid_rule_priority.to_string();
    let uidrange = format!("{}-{}", state.owner_uid, state.owner_uid);
    let protocol = state.route_protocol.to_string();
    ip.status(
        VpnNetworkIpOperation::AddUidEscapeRule,
        &[
            family.ip_flag(),
            "rule",
            "add",
            "priority",
            &priority,
            "uidrange",
            &uidrange,
            "lookup",
            "main",
            "protocol",
            &protocol,
        ],
    )
}

fn add_tunnel_rule(
    ip: &IpCommand,
    state: &VpnClientRouteState,
    family: AddressFamily,
) -> Result<(), VpnNetworkError> {
    let priority = state.tunnel_rule_priority.to_string();
    let table = state.route_table.to_string();
    let protocol = state.route_protocol.to_string();
    ip.status(
        VpnNetworkIpOperation::AddTunnelRule,
        &[
            family.ip_flag(),
            "rule",
            "add",
            "priority",
            &priority,
            "lookup",
            &table,
            "protocol",
            &protocol,
        ],
    )
}

fn add_policy_route(
    ip: &IpCommand,
    state: &VpnClientRouteState,
    network: &str,
) -> Result<(), VpnNetworkError> {
    let family = network_family(parse_network_prefix(network)?);
    let table = state.route_table.to_string();
    let protocol = state.route_protocol.to_string();
    let metric = state.route_metric.to_string();
    ip.status(
        VpnNetworkIpOperation::AddPolicyRoute,
        &[
            family.ip_flag(),
            "route",
            "add",
            network,
            "dev",
            &state.tun_name,
            "table",
            &table,
            "proto",
            &protocol,
            "metric",
            &metric,
        ],
    )
}

fn validate_active_routes(
    ip: &IpCommand,
    state: &VpnClientRouteState,
) -> Result<(), VpnNetworkError> {
    let snapshot = inspect_route_objects(ip, state)?;
    let expected_families = state.families();
    let expected_routes = state
        .destination_networks
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    if snapshot.uid_rules != expected_families
        || snapshot.tunnel_rules != expected_families
        || snapshot.routes != expected_routes
    {
        return Err(VpnNetworkError::ClientRouteStateDrift);
    }
    Ok(())
}

fn rollback_client_routes(
    ip: &IpCommand,
    state: &VpnClientRouteState,
) -> Result<(), VpnNetworkError> {
    let snapshot = inspect_route_objects(ip, state)?;
    for family in AddressFamily::ALL {
        if snapshot.tunnel_rules.contains(&family) {
            delete_tunnel_rule(ip, state, family)?;
        }
    }
    for network in &state.destination_networks {
        if snapshot.routes.contains(network) {
            delete_policy_route(ip, state, network)?;
        }
    }
    for family in AddressFamily::ALL {
        if snapshot.uid_rules.contains(&family) {
            delete_uid_escape_rule(ip, state, family)?;
        }
    }
    let remaining = inspect_route_objects(ip, state)?;
    if !remaining.uid_rules.is_empty()
        || !remaining.tunnel_rules.is_empty()
        || !remaining.routes.is_empty()
    {
        return Err(VpnNetworkError::ClientRouteStateDrift);
    }
    Ok(())
}

#[derive(Default)]
struct RouteObjectSnapshot {
    uid_rules: HashSet<AddressFamily>,
    tunnel_rules: HashSet<AddressFamily>,
    routes: HashSet<String>,
}

fn inspect_route_objects(
    ip: &IpCommand,
    state: &VpnClientRouteState,
) -> Result<RouteObjectSnapshot, VpnNetworkError> {
    state.validate_shape()?;
    let expected_families = state.families();
    let expected_routes = state
        .destination_networks
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    let mut snapshot = RouteObjectSnapshot::default();
    for family in AddressFamily::ALL {
        for rule in inspect_policy_rules(ip, family)? {
            let table = parse_numeric(&rule.table);
            let touches_state = rule.priority == state.uid_rule_priority
                || rule.priority == state.tunnel_rule_priority
                || table == Some(state.route_table);
            if !touches_state {
                continue;
            }
            if expected_families.contains(&family)
                && exact_uid_rule(&rule, state)
                && snapshot.uid_rules.insert(family)
            {
                continue;
            }
            if expected_families.contains(&family)
                && exact_tunnel_rule(&rule, state)
                && snapshot.tunnel_rules.insert(family)
            {
                continue;
            }
            return Err(VpnNetworkError::ClientRouteStateDrift);
        }

        for route in inspect_policy_routes(ip, family, state.route_table)? {
            let network = normalize_route_destination(&route.dst, family)?;
            if !expected_routes.contains(&network)
                || !exact_policy_route(&route, state, family)
                || !snapshot.routes.insert(network)
            {
                return Err(VpnNetworkError::ClientRouteStateDrift);
            }
        }
    }
    Ok(snapshot)
}

fn exact_uid_rule(rule: &RawPolicyRule, state: &VpnClientRouteState) -> bool {
    rule.priority == state.uid_rule_priority
        && rule.src.as_deref() == Some("all")
        && rule.uid_start == Some(state.owner_uid)
        && rule.uid_end == Some(state.owner_uid)
        && parse_numeric(&rule.table) == Some(MAIN_ROUTE_TABLE)
        && parse_numeric(&rule.protocol) == Some(u32::from(state.route_protocol))
        && rule.extra.is_empty()
}

fn exact_tunnel_rule(rule: &RawPolicyRule, state: &VpnClientRouteState) -> bool {
    rule.priority == state.tunnel_rule_priority
        && rule.src.as_deref() == Some("all")
        && rule.uid_start.is_none()
        && rule.uid_end.is_none()
        && parse_numeric(&rule.table) == Some(state.route_table)
        && parse_numeric(&rule.protocol) == Some(u32::from(state.route_protocol))
        && rule.extra.is_empty()
}

fn exact_policy_route(
    route: &RawPolicyRoute,
    state: &VpnClientRouteState,
    family: AddressFamily,
) -> bool {
    route.dev.as_deref() == Some(state.tun_name.as_str())
        && parse_numeric(&route.protocol) == Some(u32::from(state.route_protocol))
        && route.metric == Some(state.route_metric)
        && match family {
            AddressFamily::Ipv4 => route.scope.as_deref() == Some("253") && route.pref.is_none(),
            AddressFamily::Ipv6 => {
                route.scope.is_none() && matches!(route.pref.as_deref(), None | Some("medium"))
            }
        }
        && route.flags.iter().all(|flag| flag == "linkdown")
        && route.extra.is_empty()
}

fn delete_uid_escape_rule(
    ip: &IpCommand,
    state: &VpnClientRouteState,
    family: AddressFamily,
) -> Result<(), VpnNetworkError> {
    let priority = state.uid_rule_priority.to_string();
    let uidrange = format!("{}-{}", state.owner_uid, state.owner_uid);
    let protocol = state.route_protocol.to_string();
    ip.status(
        VpnNetworkIpOperation::DeleteUidEscapeRule,
        &[
            family.ip_flag(),
            "rule",
            "del",
            "priority",
            &priority,
            "uidrange",
            &uidrange,
            "lookup",
            "main",
            "protocol",
            &protocol,
        ],
    )
}

fn delete_tunnel_rule(
    ip: &IpCommand,
    state: &VpnClientRouteState,
    family: AddressFamily,
) -> Result<(), VpnNetworkError> {
    let priority = state.tunnel_rule_priority.to_string();
    let table = state.route_table.to_string();
    let protocol = state.route_protocol.to_string();
    ip.status(
        VpnNetworkIpOperation::DeleteTunnelRule,
        &[
            family.ip_flag(),
            "rule",
            "del",
            "priority",
            &priority,
            "lookup",
            &table,
            "protocol",
            &protocol,
        ],
    )
}

fn delete_policy_route(
    ip: &IpCommand,
    state: &VpnClientRouteState,
    network: &str,
) -> Result<(), VpnNetworkError> {
    let family = network_family(parse_network_prefix(network)?);
    let table = state.route_table.to_string();
    let protocol = state.route_protocol.to_string();
    let metric = state.route_metric.to_string();
    ip.status(
        VpnNetworkIpOperation::DeletePolicyRoute,
        &[
            family.ip_flag(),
            "route",
            "del",
            network,
            "dev",
            &state.tun_name,
            "table",
            &table,
            "proto",
            &protocol,
            "metric",
            &metric,
        ],
    )
}

fn parse_numeric(value: &Option<String>) -> Option<u32> {
    value.as_deref()?.parse().ok()
}

fn network_prefix(network: VpnIpNetwork) -> String {
    match network {
        VpnIpNetwork::V4 {
            network,
            prefix_len,
        } => format!("{network}/{prefix_len}"),
        VpnIpNetwork::V6 {
            network,
            prefix_len,
        } => format!("{network}/{prefix_len}"),
    }
}

fn parse_network_prefix(value: &str) -> Result<VpnIpNetwork, VpnNetworkError> {
    let (address, prefix) = value
        .split_once('/')
        .filter(|(_, prefix)| !prefix.contains('/'))
        .ok_or(VpnNetworkError::ClientRouteStateInvalid)?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| VpnNetworkError::ClientRouteStateInvalid)?;
    if let Ok(address) = address.parse::<Ipv4Addr>() {
        let network = VpnIpNetwork::v4(address, prefix)
            .map_err(|_| VpnNetworkError::ClientRouteStateInvalid)?;
        return (network_prefix(network) == value)
            .then_some(network)
            .ok_or(VpnNetworkError::ClientRouteStateInvalid);
    }
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| VpnNetworkError::ClientRouteStateInvalid)?;
    let network =
        VpnIpNetwork::v6(address, prefix).map_err(|_| VpnNetworkError::ClientRouteStateInvalid)?;
    (network_prefix(network) == value)
        .then_some(network)
        .ok_or(VpnNetworkError::ClientRouteStateInvalid)
}

const fn network_family(network: VpnIpNetwork) -> AddressFamily {
    match network {
        VpnIpNetwork::V4 { .. } => AddressFamily::Ipv4,
        VpnIpNetwork::V6 { .. } => AddressFamily::Ipv6,
    }
}

fn normalize_route_destination(
    destination: &str,
    family: AddressFamily,
) -> Result<String, VpnNetworkError> {
    if destination == "default" {
        return Ok(match family {
            AddressFamily::Ipv4 => "0.0.0.0/0".to_owned(),
            AddressFamily::Ipv6 => "::/0".to_owned(),
        });
    }
    let network = parse_network_prefix(destination)?;
    if network_family(network) != family {
        return Err(VpnNetworkError::ClientRouteStateDrift);
    }
    Ok(network_prefix(network))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_networks_are_canonical_and_default_is_normalized() {
        assert_eq!(
            network_prefix(parse_network_prefix("0.0.0.0/0").unwrap()),
            "0.0.0.0/0"
        );
        assert_eq!(
            network_prefix(parse_network_prefix("2001:db8::/32").unwrap()),
            "2001:db8::/32"
        );
        assert!(parse_network_prefix("10.0.0.1/8").is_err());
        assert_eq!(
            normalize_route_destination("default", AddressFamily::Ipv4).unwrap(),
            "0.0.0.0/0"
        );
        assert_eq!(
            normalize_route_destination("default", AddressFamily::Ipv6).unwrap(),
            "::/0"
        );
    }

    #[test]
    fn route_state_fingerprint_covers_every_ownership_field() {
        let plan = VpnClientRoutePlan {
            network_plan_fingerprint: "11".repeat(PLAN_FINGERPRINT_BYTES),
            tun_name: "fwvpn0".to_owned(),
            interface_index: 7,
            owner_uid: 1000,
            destination_networks: vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()],
            fingerprint: "22".repeat(CLIENT_ROUTE_PLAN_FINGERPRINT_BYTES),
        };
        let state = VpnClientRouteState::new_activating(
            &plan,
            RouteSlot {
                protocol: 222,
                table: 41_001,
                uid_priority: 12_000,
                tunnel_priority: 12_001,
                metric: 42_760,
            },
        )
        .unwrap();
        state.validate_shape().unwrap();
        let mut changed = state.clone();
        changed.route_table += 1;
        assert_eq!(
            changed.validate_shape().unwrap_err(),
            VpnNetworkError::ClientRouteStateInvalid
        );
    }
}

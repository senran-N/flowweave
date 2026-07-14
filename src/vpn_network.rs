use std::{
    collections::HashSet,
    error::Error,
    ffi::{CString, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    mem,
    net::IpAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

use crate::{
    VPN_IDENTITY_CONFIG_MAX_BYTES, VPN_PRODUCT_CONFIG_MAX_BYTES, VpnClientProductConfig,
    VpnIdentityConfigError, VpnIdentityRegistry, VpnProductConfigError, VpnServerProductConfig,
    parse_vpn_client_product_config_json, parse_vpn_identity_registry_json,
    parse_vpn_server_product_config_json,
    vpn_product_config::{validate_vpn_tun_mtu, validate_vpn_tun_name},
};

pub const VPN_NETWORK_STATE_VERSION: u16 = 1;
pub const VPN_NETWORK_STATE_MAX_BYTES: usize = 64 * 1024;

const TUN_DEVICE_PATH: &str = "/dev/net/tun";
const TUN_DEVICE_MAJOR: u32 = 10;
const TUN_DEVICE_MINOR: u32 = 200;
const CAP_NET_ADMIN_NUMBER: u32 = 12;
const PLAN_FINGERPRINT_BYTES: usize = 32;
const OWNERSHIP_TOKEN_BYTES: usize = 16;
const TEMPORARY_TUN_PREFIX: &str = "fwv";
const OWNERSHIP_ALIAS_PREFIX: &str = "flowweave-vpn-net:v1:";

static STATE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnNetworkRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnNetworkStatePhase {
    Preparing,
    Prepared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnNetworkPrepareOutcome {
    Prepared,
    AlreadyPrepared,
    RecoveredAndPrepared,
}

impl VpnNetworkPrepareOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::AlreadyPrepared => "already_prepared",
            Self::RecoveredAndPrepared => "recovered_and_prepared",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnNetworkCleanupOutcome {
    Cleaned,
    AlreadyClean,
    RecoveredInterruptedPrepare,
}

impl VpnNetworkCleanupOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cleaned => "cleaned",
            Self::AlreadyClean => "already_clean",
            Self::RecoveredInterruptedPrepare => "recovered_interrupted_prepare",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnNetworkIoStage {
    ProcessStatus,
    ConfigOpen,
    ConfigInspect,
    ConfigRead,
    IdentityOpen,
    IdentityInspect,
    IdentityRead,
    StateDirectoryInspect,
    StateLockOpen,
    StateLockInspect,
    StateLock,
    StateOpen,
    StateInspect,
    StateRead,
    StateWrite,
    StateSync,
    StateRename,
    StateRemove,
    StateDirectorySync,
    IpInspect,
    IpSpawn,
    TunDeviceOpen,
    TunDeviceInspect,
    TunCreate,
    TunOwner,
    TunGroup,
    TunPersist,
    TunDeleteAttach,
    TunDeletePersist,
    InterfaceInspect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnNetworkIpOperation {
    InspectLink,
    InspectAddresses,
    InspectRoute,
    SetAlias,
    SetMtu,
    SetUp,
    AddAddress,
    AddRoute,
    Rename,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnNetworkError {
    NotRoot,
    ProcessStatusInvalid,
    NetAdminCapabilityMissing,
    Io {
        stage: VpnNetworkIoStage,
        kind: io::ErrorKind,
    },
    ConfigSymlink,
    ConfigNotRegular,
    ConfigUnsafePermissions,
    ConfigOwnershipInvalid,
    ConfigOwnerMismatch,
    ProductConfig(VpnProductConfigError),
    IdentityConfig(VpnIdentityConfigError),
    InvalidPlan,
    RandomUnavailable,
    InvalidStatePath,
    UnsafeStateDirectory,
    UnsafeStateFile,
    StateBusy,
    StateTooLarge,
    StateInvalidJson {
        line: usize,
        column: usize,
    },
    StateUnsupportedVersion,
    StateInvalid,
    StateConflict,
    StateDrift,
    IpBinaryUnavailable,
    IpBinaryUnsafe,
    IpCommandFailed {
        operation: VpnNetworkIpOperation,
        status: Option<i32>,
    },
    IpOutputInvalid(VpnNetworkIpOperation),
    InterfaceExists,
    InterfaceMissing,
    InterfaceOwnershipMismatch,
    InterfaceBusy,
    InvalidTunCharacterDevice,
    RollbackFailed,
}

impl fmt::Display for VpnNetworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { stage, kind } => write!(formatter, "vpn_network_io:{stage:?}:{kind:?}"),
            Self::ProductConfig(error) => write!(formatter, "vpn_network_product_config:{error}"),
            Self::IdentityConfig(error) => {
                write!(formatter, "vpn_network_identity_config:{error}")
            }
            Self::StateInvalidJson { line, column } => {
                write!(formatter, "vpn_network_state_invalid_json:{line}:{column}")
            }
            Self::IpCommandFailed { operation, status } => {
                write!(
                    formatter,
                    "vpn_network_ip_command:{operation:?}:{}",
                    status
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "signal".to_owned())
                )
            }
            Self::IpOutputInvalid(operation) => {
                write!(formatter, "vpn_network_ip_output:{operation:?}")
            }
            other => formatter.write_str(match other {
                Self::NotRoot => "vpn_network_not_root",
                Self::ProcessStatusInvalid => "vpn_network_process_status_invalid",
                Self::NetAdminCapabilityMissing => "vpn_network_net_admin_capability_missing",
                Self::ConfigSymlink => "vpn_network_config_symlink",
                Self::ConfigNotRegular => "vpn_network_config_not_regular",
                Self::ConfigUnsafePermissions => "vpn_network_config_unsafe_permissions",
                Self::ConfigOwnershipInvalid => "vpn_network_config_ownership_invalid",
                Self::ConfigOwnerMismatch => "vpn_network_config_owner_mismatch",
                Self::InvalidPlan => "vpn_network_invalid_plan",
                Self::RandomUnavailable => "vpn_network_random_unavailable",
                Self::InvalidStatePath => "vpn_network_invalid_state_path",
                Self::UnsafeStateDirectory => "vpn_network_unsafe_state_directory",
                Self::UnsafeStateFile => "vpn_network_unsafe_state_file",
                Self::StateBusy => "vpn_network_state_busy",
                Self::StateTooLarge => "vpn_network_state_too_large",
                Self::StateUnsupportedVersion => "vpn_network_state_unsupported_version",
                Self::StateInvalid => "vpn_network_state_invalid",
                Self::StateConflict => "vpn_network_state_conflict",
                Self::StateDrift => "vpn_network_state_drift",
                Self::IpBinaryUnavailable => "vpn_network_ip_binary_unavailable",
                Self::IpBinaryUnsafe => "vpn_network_ip_binary_unsafe",
                Self::InterfaceExists => "vpn_network_interface_exists",
                Self::InterfaceMissing => "vpn_network_interface_missing",
                Self::InterfaceOwnershipMismatch => "vpn_network_interface_ownership_mismatch",
                Self::InterfaceBusy => "vpn_network_interface_busy",
                Self::InvalidTunCharacterDevice => "vpn_network_invalid_tun_character_device",
                Self::RollbackFailed => "vpn_network_rollback_failed",
                Self::Io { .. }
                | Self::ProductConfig(_)
                | Self::IdentityConfig(_)
                | Self::StateInvalidJson { .. }
                | Self::IpCommandFailed { .. }
                | Self::IpOutputInvalid(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnNetworkError {}

impl From<VpnProductConfigError> for VpnNetworkError {
    fn from(value: VpnProductConfigError) -> Self {
        Self::ProductConfig(value)
    }
}

impl From<VpnIdentityConfigError> for VpnNetworkError {
    fn from(value: VpnIdentityConfigError) -> Self {
        Self::IdentityConfig(value)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VpnNetworkPlan {
    role: VpnNetworkRole,
    tun_name: String,
    tun_mtu: u16,
    owner_uid: u32,
    owner_gid: u32,
    addresses: Vec<IpAddr>,
    routes: Vec<IpAddr>,
    fingerprint: [u8; PLAN_FINGERPRINT_BYTES],
}

impl VpnNetworkPlan {
    pub const fn role(&self) -> VpnNetworkRole {
        self.role
    }

    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    pub const fn tun_mtu(&self) -> u16 {
        self.tun_mtu
    }

    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub const fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    pub fn routes(&self) -> &[IpAddr] {
        &self.routes
    }

    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint)
    }

    fn new(
        role: VpnNetworkRole,
        tun_name: String,
        tun_mtu: u16,
        owner_uid: u32,
        owner_gid: u32,
        mut addresses: Vec<IpAddr>,
        mut routes: Vec<IpAddr>,
    ) -> Result<Self, VpnNetworkError> {
        validate_vpn_tun_name(&tun_name).map_err(VpnNetworkError::ProductConfig)?;
        validate_vpn_tun_mtu(tun_mtu).map_err(VpnNetworkError::ProductConfig)?;
        if owner_uid == 0 || owner_gid == 0 || addresses.is_empty() {
            return Err(VpnNetworkError::InvalidPlan);
        }
        addresses.sort_unstable();
        addresses.dedup();
        routes.sort_unstable();
        routes.dedup();
        if addresses.iter().any(|address| routes.contains(address)) {
            return Err(VpnNetworkError::InvalidPlan);
        }
        let mut plan = Self {
            role,
            tun_name,
            tun_mtu,
            owner_uid,
            owner_gid,
            addresses,
            routes,
            fingerprint: [0; PLAN_FINGERPRINT_BYTES],
        };
        plan.fingerprint = plan.compute_fingerprint()?;
        Ok(plan)
    }

    fn compute_fingerprint(&self) -> Result<[u8; PLAN_FINGERPRINT_BYTES], VpnNetworkError> {
        let canonical = CanonicalPlan {
            plan_version: 1,
            role: self.role,
            tun_name: &self.tun_name,
            tun_mtu: self.tun_mtu,
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            addresses: self.addresses.iter().map(host_prefix).collect(),
            routes: self.routes.iter().map(host_prefix).collect(),
        };
        let bytes = serde_json::to_vec(&canonical).map_err(|_| VpnNetworkError::InvalidPlan)?;
        let value = digest(&SHA256, &bytes);
        let mut fingerprint = [0; PLAN_FINGERPRINT_BYTES];
        fingerprint.copy_from_slice(value.as_ref());
        Ok(fingerprint)
    }
}

impl fmt::Debug for VpnNetworkPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnNetworkPlan")
            .field("role", &self.role)
            .field("tun_name", &self.tun_name)
            .field("tun_mtu", &self.tun_mtu)
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .field("address_count", &self.addresses.len())
            .field("route_count", &self.routes.len())
            .field("fingerprint", &"[redacted]")
            .finish()
    }
}

#[derive(Serialize)]
struct CanonicalPlan<'a> {
    plan_version: u16,
    role: VpnNetworkRole,
    tun_name: &'a str,
    tun_mtu: u16,
    owner_uid: u32,
    owner_gid: u32,
    addresses: Vec<String>,
    routes: Vec<String>,
}

struct OwnedPrivateFile {
    bytes: Vec<u8>,
    uid: u32,
    gid: u32,
}

pub fn load_vpn_client_network_plan(
    path: &Path,
    owner_uid: u32,
) -> Result<VpnNetworkPlan, VpnNetworkError> {
    let file = read_owned_private_file(
        path,
        VPN_PRODUCT_CONFIG_MAX_BYTES,
        VpnNetworkIoStage::ConfigOpen,
        VpnNetworkIoStage::ConfigInspect,
        VpnNetworkIoStage::ConfigRead,
    )?;
    let config = parse_vpn_client_product_config_json(&file.bytes, config_base(path))?;
    client_network_plan(&config, owner_uid, file.gid)
}

fn client_network_plan(
    config: &VpnClientProductConfig,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<VpnNetworkPlan, VpnNetworkError> {
    let mut addresses = Vec::with_capacity(2);
    let mut routes = Vec::with_capacity(2);
    addresses.extend(config.expected_client_ipv4().map(IpAddr::V4));
    addresses.extend(config.expected_client_ipv6().map(IpAddr::V6));
    routes.extend(config.expected_server_ipv4().map(IpAddr::V4));
    routes.extend(config.expected_server_ipv6().map(IpAddr::V6));
    VpnNetworkPlan::new(
        VpnNetworkRole::Client,
        config.tun_name().to_owned(),
        config.tun_mtu(),
        owner_uid,
        owner_gid,
        addresses,
        routes,
    )
}

pub fn load_vpn_server_network_plan(
    path: &Path,
    owner_uid: u32,
) -> Result<VpnNetworkPlan, VpnNetworkError> {
    let file = read_owned_private_file(
        path,
        VPN_PRODUCT_CONFIG_MAX_BYTES,
        VpnNetworkIoStage::ConfigOpen,
        VpnNetworkIoStage::ConfigInspect,
        VpnNetworkIoStage::ConfigRead,
    )?;
    let config = parse_vpn_server_product_config_json(&file.bytes, config_base(path))?;
    let identity = read_owned_private_file(
        config.identity_file(),
        VPN_IDENTITY_CONFIG_MAX_BYTES,
        VpnNetworkIoStage::IdentityOpen,
        VpnNetworkIoStage::IdentityInspect,
        VpnNetworkIoStage::IdentityRead,
    )?;
    if (identity.uid, identity.gid) != (file.uid, file.gid) {
        return Err(VpnNetworkError::ConfigOwnerMismatch);
    }
    let registry = parse_vpn_identity_registry_json(&identity.bytes)?;
    server_network_plan(&config, &registry, owner_uid, file.gid)
}

fn server_network_plan(
    config: &VpnServerProductConfig,
    registry: &VpnIdentityRegistry,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<VpnNetworkPlan, VpnNetworkError> {
    let mut addresses = Vec::with_capacity(2);
    addresses.extend(registry.server_ipv4().map(IpAddr::V4));
    addresses.extend(registry.server_ipv6().map(IpAddr::V6));
    let mut routes = Vec::with_capacity(registry.identities().len() * 2);
    for identity in registry.identities() {
        routes.extend(identity.client_ipv4().map(IpAddr::V4));
        routes.extend(identity.client_ipv6().map(IpAddr::V6));
    }
    VpnNetworkPlan::new(
        VpnNetworkRole::Server,
        config.tun_name().to_owned(),
        config.tun_mtu(),
        owner_uid,
        owner_gid,
        addresses,
        routes,
    )
}

fn read_owned_private_file(
    path: &Path,
    max_bytes: usize,
    open_stage: VpnNetworkIoStage,
    inspect_stage: VpnNetworkIoStage,
    read_stage: VpnNetworkIoStage,
) -> Result<OwnedPrivateFile, VpnNetworkError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                VpnNetworkError::ConfigSymlink
            } else {
                io_error(open_stage, error)
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error(inspect_stage, error))?;
    if !metadata.is_file() {
        return Err(VpnNetworkError::ConfigNotRegular);
    }
    let mode = metadata.permissions().mode();
    if mode & 0o440 != 0o440 || mode & 0o7137 != 0 {
        return Err(VpnNetworkError::ConfigUnsafePermissions);
    }
    if metadata.uid() != 0 || metadata.gid() == 0 {
        return Err(VpnNetworkError::ConfigOwnershipInvalid);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(match open_stage {
            VpnNetworkIoStage::IdentityOpen => {
                VpnNetworkError::IdentityConfig(VpnIdentityConfigError::FileTooLarge)
            }
            _ => VpnNetworkError::ProductConfig(VpnProductConfigError::FileTooLarge),
        });
    }
    let mut limited = file.take((max_bytes + 1) as u64);
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(max_bytes)
            .min(max_bytes),
    );
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(read_stage, error))?;
    if bytes.len() > max_bytes {
        return Err(match open_stage {
            VpnNetworkIoStage::IdentityOpen => {
                VpnNetworkError::IdentityConfig(VpnIdentityConfigError::FileTooLarge)
            }
            _ => VpnNetworkError::ProductConfig(VpnProductConfigError::FileTooLarge),
        });
    }
    Ok(OwnedPrivateFile {
        bytes,
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

fn config_base(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VpnNetworkState {
    state_version: u16,
    phase: VpnNetworkStatePhase,
    plan_fingerprint: String,
    role: VpnNetworkRole,
    tun_name: String,
    temporary_tun_name: String,
    ownership_token: String,
    interface_index: Option<u32>,
    tun_mtu: u16,
    owner_uid: u32,
    owner_gid: u32,
    addresses: Vec<String>,
    routes: Vec<String>,
}

impl VpnNetworkState {
    fn new_preparing(plan: &VpnNetworkPlan) -> Result<Self, VpnNetworkError> {
        let mut token = [0_u8; OWNERSHIP_TOKEN_BYTES];
        SystemRandom::new()
            .fill(&mut token)
            .map_err(|_| VpnNetworkError::RandomUnavailable)?;
        let ownership_token = hex_encode(&token);
        Ok(Self {
            state_version: VPN_NETWORK_STATE_VERSION,
            phase: VpnNetworkStatePhase::Preparing,
            plan_fingerprint: plan.fingerprint_hex(),
            role: plan.role,
            tun_name: plan.tun_name.clone(),
            temporary_tun_name: temporary_tun_name(&ownership_token),
            ownership_token,
            interface_index: None,
            tun_mtu: plan.tun_mtu,
            owner_uid: plan.owner_uid,
            owner_gid: plan.owner_gid,
            addresses: plan.addresses.iter().map(host_prefix).collect(),
            routes: plan.routes.iter().map(host_prefix).collect(),
        })
    }

    fn plan(&self) -> Result<VpnNetworkPlan, VpnNetworkError> {
        self.validate_shape()?;
        let addresses = self
            .addresses
            .iter()
            .map(|value| parse_host_prefix(value))
            .collect::<Result<Vec<_>, _>>()?;
        let routes = self
            .routes
            .iter()
            .map(|value| parse_host_prefix(value))
            .collect::<Result<Vec<_>, _>>()?;
        let plan = VpnNetworkPlan::new(
            self.role,
            self.tun_name.clone(),
            self.tun_mtu,
            self.owner_uid,
            self.owner_gid,
            addresses,
            routes,
        )?;
        let canonical_addresses = plan.addresses.iter().map(host_prefix).collect::<Vec<_>>();
        let canonical_routes = plan.routes.iter().map(host_prefix).collect::<Vec<_>>();
        if canonical_addresses != self.addresses
            || canonical_routes != self.routes
            || plan.fingerprint_hex() != self.plan_fingerprint
        {
            return Err(VpnNetworkError::StateInvalid);
        }
        Ok(plan)
    }

    fn ownership_alias(&self) -> String {
        format!("{OWNERSHIP_ALIAS_PREFIX}{}", self.ownership_token)
    }

    fn validate_shape(&self) -> Result<(), VpnNetworkError> {
        if self.state_version != VPN_NETWORK_STATE_VERSION {
            return Err(VpnNetworkError::StateUnsupportedVersion);
        }
        validate_vpn_tun_name(&self.tun_name).map_err(|_| VpnNetworkError::StateInvalid)?;
        validate_vpn_tun_name(&self.temporary_tun_name)
            .map_err(|_| VpnNetworkError::StateInvalid)?;
        validate_vpn_tun_mtu(self.tun_mtu).map_err(|_| VpnNetworkError::StateInvalid)?;
        if self.tun_name == self.temporary_tun_name
            || self.owner_uid == 0
            || self.owner_gid == 0
            || !valid_lower_hex(&self.plan_fingerprint, PLAN_FINGERPRINT_BYTES)
            || !valid_lower_hex(&self.ownership_token, OWNERSHIP_TOKEN_BYTES)
            || self.temporary_tun_name != temporary_tun_name(&self.ownership_token)
            || self.phase == VpnNetworkStatePhase::Prepared && self.interface_index.is_none()
            || self.interface_index == Some(0)
        {
            return Err(VpnNetworkError::StateInvalid);
        }
        Ok(())
    }
}

impl fmt::Debug for VpnNetworkState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnNetworkState")
            .field("state_version", &self.state_version)
            .field("phase", &self.phase)
            .field("role", &self.role)
            .field("tun_name", &self.tun_name)
            .field("temporary_tun_name", &self.temporary_tun_name)
            .field("interface_index", &self.interface_index)
            .field("tun_mtu", &self.tun_mtu)
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .field("address_count", &self.addresses.len())
            .field("route_count", &self.routes.len())
            .field("plan_fingerprint", &"[redacted]")
            .field("ownership_token", &"[redacted]")
            .finish()
    }
}

fn parse_vpn_network_state(bytes: &[u8]) -> Result<VpnNetworkState, VpnNetworkError> {
    let state: VpnNetworkState =
        serde_json::from_slice(bytes).map_err(|error| VpnNetworkError::StateInvalidJson {
            line: error.line(),
            column: error.column(),
        })?;
    state.plan()?;
    Ok(state)
}

fn host_prefix(address: &IpAddr) -> String {
    match address {
        IpAddr::V4(address) => format!("{address}/32"),
        IpAddr::V6(address) => format!("{address}/128"),
    }
}

fn parse_host_prefix(value: &str) -> Result<IpAddr, VpnNetworkError> {
    let (address, prefix) = value.split_once('/').ok_or(VpnNetworkError::StateInvalid)?;
    if prefix.contains('/') {
        return Err(VpnNetworkError::StateInvalid);
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| VpnNetworkError::StateInvalid)?;
    let expected = match address {
        IpAddr::V4(_) => "32",
        IpAddr::V6(_) => "128",
    };
    if prefix != expected || host_prefix(&address) != value {
        return Err(VpnNetworkError::StateInvalid);
    }
    Ok(address)
}

fn temporary_tun_name(token: &str) -> String {
    format!("{TEMPORARY_TUN_PREFIX}{}", &token[..12])
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn io_error(stage: VpnNetworkIoStage, error: io::Error) -> VpnNetworkError {
    VpnNetworkError::Io {
        stage,
        kind: error.kind(),
    }
}

struct VpnNetworkStateLock {
    _file: File,
    state_path: PathBuf,
    state_directory: PathBuf,
}

impl VpnNetworkStateLock {
    fn acquire(state_path: &Path) -> Result<Self, VpnNetworkError> {
        let (state_directory, file_name) = validate_state_path(state_path)?;
        let mut lock_name = file_name;
        lock_name.push(".lock");
        let lock_path = state_directory.join(lock_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|error| io_error(VpnNetworkIoStage::StateLockOpen, error))?;
        validate_root_private_regular_file(&file, VpnNetworkIoStage::StateLockInspect, true)?;
        // SAFETY: file is a live regular-file descriptor and LOCK_NB does not retain pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(VpnNetworkError::StateBusy);
            }
            return Err(io_error(VpnNetworkIoStage::StateLock, error));
        }
        Ok(Self {
            _file: file,
            state_path: state_path.to_owned(),
            state_directory,
        })
    }

    fn read(&self) -> Result<Option<VpnNetworkState>, VpnNetworkError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.state_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(VpnNetworkIoStage::StateOpen, error)),
        };
        let metadata =
            validate_root_private_regular_file(&file, VpnNetworkIoStage::StateInspect, true)?;
        if metadata.len() > VPN_NETWORK_STATE_MAX_BYTES as u64 {
            return Err(VpnNetworkError::StateTooLarge);
        }
        let mut limited = file.take((VPN_NETWORK_STATE_MAX_BYTES + 1) as u64);
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(VPN_NETWORK_STATE_MAX_BYTES)
                .min(VPN_NETWORK_STATE_MAX_BYTES),
        );
        limited
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(VpnNetworkIoStage::StateRead, error))?;
        if bytes.len() > VPN_NETWORK_STATE_MAX_BYTES {
            return Err(VpnNetworkError::StateTooLarge);
        }
        parse_vpn_network_state(&bytes).map(Some)
    }

    fn write(&self, state: &VpnNetworkState) -> Result<(), VpnNetworkError> {
        state.plan()?;
        let mut bytes =
            serde_json::to_vec_pretty(state).map_err(|_| VpnNetworkError::StateInvalid)?;
        bytes.push(b'\n');
        if bytes.len() > VPN_NETWORK_STATE_MAX_BYTES {
            return Err(VpnNetworkError::StateTooLarge);
        }
        let file_name = self
            .state_path
            .file_name()
            .ok_or(VpnNetworkError::InvalidStatePath)?;
        let sequence = STATE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
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
                .map_err(|error| io_error(VpnNetworkIoStage::StateWrite, error))?;
            file.write_all(&bytes)
                .map_err(|error| io_error(VpnNetworkIoStage::StateWrite, error))?;
            file.sync_all()
                .map_err(|error| io_error(VpnNetworkIoStage::StateSync, error))?;
            fs::rename(&temporary_path, &self.state_path)
                .map_err(|error| io_error(VpnNetworkIoStage::StateRename, error))?;
            sync_directory(&self.state_directory)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn remove(&self) -> Result<(), VpnNetworkError> {
        match fs::remove_file(&self.state_path) {
            Ok(()) => sync_directory(&self.state_directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(VpnNetworkIoStage::StateRemove, error)),
        }
    }
}

fn validate_state_path(state_path: &Path) -> Result<(PathBuf, OsString), VpnNetworkError> {
    if state_path.components().any(|component| {
        !matches!(
            component,
            Component::RootDir | Component::Prefix(_) | Component::Normal(_)
        )
    }) {
        return Err(VpnNetworkError::InvalidStatePath);
    }
    let file_name = state_path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(VpnNetworkError::InvalidStatePath)?
        .to_os_string();
    let directory = state_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let symlink_metadata = fs::symlink_metadata(directory)
        .map_err(|error| io_error(VpnNetworkIoStage::StateDirectoryInspect, error))?;
    if symlink_metadata.file_type().is_symlink()
        || !symlink_metadata.is_dir()
        || symlink_metadata.uid() != 0
        || symlink_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(VpnNetworkError::UnsafeStateDirectory);
    }
    Ok((directory.to_owned(), file_name))
}

fn validate_root_private_regular_file(
    file: &File,
    stage: VpnNetworkIoStage,
    require_private: bool,
) -> Result<fs::Metadata, VpnNetworkError> {
    let metadata = file.metadata().map_err(|error| io_error(stage, error))?;
    let forbidden_permissions = if require_private { 0o077 } else { 0o022 };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & forbidden_permissions != 0
    {
        return Err(VpnNetworkError::UnsafeStateFile);
    }
    Ok(metadata)
}

fn sync_directory(path: &Path) -> Result<(), VpnNetworkError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(VpnNetworkIoStage::StateDirectorySync, error))
}

struct IpCommand {
    path: PathBuf,
}

impl IpCommand {
    fn discover() -> Result<Self, VpnNetworkError> {
        for candidate in ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"] {
            let path = Path::new(candidate);
            let canonical = match fs::canonicalize(path) {
                Ok(path) => path,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(VpnNetworkIoStage::IpInspect, error)),
            };
            let metadata = fs::metadata(&canonical)
                .map_err(|error| io_error(VpnNetworkIoStage::IpInspect, error))?;
            if !metadata.is_file()
                || !trusted_system_binary_owner(metadata.uid())?
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(VpnNetworkError::IpBinaryUnsafe);
            }
            return Ok(Self { path: canonical });
        }
        Err(VpnNetworkError::IpBinaryUnavailable)
    }

    fn status(
        &self,
        operation: VpnNetworkIpOperation,
        arguments: &[&str],
    ) -> Result<(), VpnNetworkError> {
        let output = self
            .command(arguments)?
            .output()
            .map_err(|error| VpnNetworkError::Io {
                stage: VpnNetworkIoStage::IpSpawn,
                kind: error.kind(),
            })?;
        if !output.status.success() {
            return Err(VpnNetworkError::IpCommandFailed {
                operation,
                status: output.status.code(),
            });
        }
        Ok(())
    }

    fn json<T: for<'de> Deserialize<'de>>(
        &self,
        operation: VpnNetworkIpOperation,
        arguments: &[&str],
    ) -> Result<T, VpnNetworkError> {
        let output = self
            .command(arguments)?
            .output()
            .map_err(|error| VpnNetworkError::Io {
                stage: VpnNetworkIoStage::IpSpawn,
                kind: error.kind(),
            })?;
        if !output.status.success() {
            return Err(VpnNetworkError::IpCommandFailed {
                operation,
                status: output.status.code(),
            });
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| VpnNetworkError::IpOutputInvalid(operation))
    }

    fn command(&self, arguments: &[&str]) -> Result<Command, VpnNetworkError> {
        let mut command = Command::new(&self.path);
        command
            .args(arguments)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(command)
    }
}

fn trusted_system_binary_owner(uid: u32) -> Result<bool, VpnNetworkError> {
    if uid == 0 {
        return Ok(true);
    }
    let mapping = fs::read_to_string("/proc/self/uid_map")
        .map_err(|error| io_error(VpnNetworkIoStage::ProcessStatus, error))?;
    let mut fields = mapping
        .lines()
        .next()
        .ok_or(VpnNetworkError::ProcessStatusInvalid)?
        .split_whitespace();
    let inside = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(VpnNetworkError::ProcessStatusInvalid)?;
    let outside = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(VpnNetworkError::ProcessStatusInvalid)?;
    Ok(inside == 0 && outside != 0 && uid == 65_534)
}

#[derive(Deserialize)]
struct RawLink {
    ifindex: u32,
    ifname: String,
    flags: Vec<String>,
    mtu: u32,
    ifalias: Option<String>,
    linkinfo: Option<RawLinkInfo>,
}

#[derive(Deserialize)]
struct RawLinkInfo {
    info_kind: String,
    info_data: RawTunInfo,
}

#[derive(Deserialize)]
struct RawTunInfo {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    pi: bool,
    #[serde(default)]
    vnet_hdr: bool,
    #[serde(default)]
    multi_queue: bool,
    #[serde(default)]
    persist: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinkSnapshot {
    index: u32,
    name: String,
    up: bool,
    mtu: u32,
    alias: Option<String>,
    tun: bool,
    pi: bool,
    vnet_hdr: bool,
    multi_queue: bool,
    persist: bool,
    owner_uid: u32,
    owner_gid: u32,
}

#[derive(Deserialize)]
struct RawAddressLink {
    addr_info: Vec<RawAddress>,
}

#[derive(Deserialize)]
struct RawAddress {
    family: String,
    local: String,
    prefixlen: u8,
    scope: String,
}

#[derive(Deserialize)]
struct RawRoute {
    dst: Option<String>,
    protocol: Option<String>,
}

fn inspect_link(ip: &IpCommand, name: &str) -> Result<Option<LinkSnapshot>, VpnNetworkError> {
    if interface_index(name)?.is_none() {
        return Ok(None);
    }
    let links: Vec<RawLink> = ip.json(
        VpnNetworkIpOperation::InspectLink,
        &["-N", "-j", "-details", "link", "show", "dev", name],
    )?;
    let link = links
        .into_iter()
        .next()
        .ok_or(VpnNetworkError::IpOutputInvalid(
            VpnNetworkIpOperation::InspectLink,
        ))?;
    let info = link.linkinfo.ok_or(VpnNetworkError::IpOutputInvalid(
        VpnNetworkIpOperation::InspectLink,
    ))?;
    let tun = info.info_kind == "tun" && info.info_data.kind == "tun";
    let (owner_uid, owner_gid) = if tun {
        (
            read_tun_identity(name, "owner")?,
            read_tun_identity(name, "group")?,
        )
    } else {
        (0, 0)
    };
    Ok(Some(LinkSnapshot {
        index: link.ifindex,
        name: link.ifname,
        up: link.flags.iter().any(|flag| flag == "UP"),
        mtu: link.mtu,
        alias: link.ifalias,
        tun,
        pi: info.info_data.pi,
        vnet_hdr: info.info_data.vnet_hdr,
        multi_queue: info.info_data.multi_queue,
        persist: info.info_data.persist,
        owner_uid,
        owner_gid,
    }))
}

fn inspect_addresses(ip: &IpCommand, name: &str) -> Result<HashSet<IpAddr>, VpnNetworkError> {
    let links: Vec<RawAddressLink> = ip.json(
        VpnNetworkIpOperation::InspectAddresses,
        &["-j", "address", "show", "dev", name],
    )?;
    let link = links
        .into_iter()
        .next()
        .ok_or(VpnNetworkError::IpOutputInvalid(
            VpnNetworkIpOperation::InspectAddresses,
        ))?;
    let mut addresses = HashSet::new();
    for address in link.addr_info {
        let parsed = address.local.parse::<IpAddr>().map_err(|_| {
            VpnNetworkError::IpOutputInvalid(VpnNetworkIpOperation::InspectAddresses)
        })?;
        if matches!(parsed, IpAddr::V6(address) if address.is_unicast_link_local())
            && address.scope == "link"
        {
            continue;
        }
        let host_prefix = match parsed {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let expected_family = match parsed {
            IpAddr::V4(_) => "inet",
            IpAddr::V6(_) => "inet6",
        };
        if address.family != expected_family || address.prefixlen != host_prefix {
            return Err(VpnNetworkError::StateDrift);
        }
        addresses.insert(parsed);
    }
    Ok(addresses)
}

fn inspect_routes(ip: &IpCommand, name: &str) -> Result<HashSet<IpAddr>, VpnNetworkError> {
    let mut destinations = HashSet::new();
    for family in ["-4", "-6"] {
        let routes: Vec<RawRoute> = ip.json(
            VpnNetworkIpOperation::InspectRoute,
            &[family, "-j", "route", "show", "dev", name],
        )?;
        for route in routes {
            if route.protocol.as_deref() == Some("kernel") {
                continue;
            }
            let destination = route.dst.ok_or(VpnNetworkError::StateDrift)?;
            let address = if let Some((address, prefix)) = destination.split_once('/') {
                if prefix.contains('/') {
                    return Err(VpnNetworkError::StateDrift);
                }
                let address = address
                    .parse::<IpAddr>()
                    .map_err(|_| VpnNetworkError::StateDrift)?;
                let expected_prefix = match address {
                    IpAddr::V4(_) => "32",
                    IpAddr::V6(_) => "128",
                };
                if prefix != expected_prefix {
                    return Err(VpnNetworkError::StateDrift);
                }
                address
            } else {
                destination
                    .parse::<IpAddr>()
                    .map_err(|_| VpnNetworkError::StateDrift)?
            };
            if (family == "-4") != address.is_ipv4() {
                return Err(VpnNetworkError::StateDrift);
            }
            destinations.insert(address);
        }
    }
    Ok(destinations)
}

fn read_tun_identity(name: &str, field: &str) -> Result<u32, VpnNetworkError> {
    let value = fs::read_to_string(Path::new("/sys/class/net").join(name).join(field))
        .map_err(|error| io_error(VpnNetworkIoStage::InterfaceInspect, error))?;
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| VpnNetworkError::IpOutputInvalid(VpnNetworkIpOperation::InspectLink))
}

pub fn prepare_vpn_client_network(
    config_path: &Path,
    state_path: &Path,
    owner_uid: u32,
) -> Result<VpnNetworkPrepareOutcome, VpnNetworkError> {
    ensure_privileged_network_helper()?;
    let plan = load_vpn_client_network_plan(config_path, owner_uid)?;
    prepare_vpn_network(plan, state_path)
}

pub fn prepare_vpn_server_network(
    config_path: &Path,
    state_path: &Path,
    owner_uid: u32,
) -> Result<VpnNetworkPrepareOutcome, VpnNetworkError> {
    ensure_privileged_network_helper()?;
    let plan = load_vpn_server_network_plan(config_path, owner_uid)?;
    prepare_vpn_network(plan, state_path)
}

pub fn cleanup_vpn_network(state_path: &Path) -> Result<VpnNetworkCleanupOutcome, VpnNetworkError> {
    ensure_privileged_network_helper()?;
    let state_lock = VpnNetworkStateLock::acquire(state_path)?;
    let Some(state) = state_lock.read()? else {
        return Ok(VpnNetworkCleanupOutcome::AlreadyClean);
    };
    state.plan()?;
    let ip = IpCommand::discover()?;
    match state.phase {
        VpnNetworkStatePhase::Preparing => {
            rollback_preparing_state(&ip, &state)?;
            state_lock.remove()?;
            Ok(VpnNetworkCleanupOutcome::RecoveredInterruptedPrepare)
        }
        VpnNetworkStatePhase::Prepared => {
            let Some(link) = inspect_link(&ip, &state.tun_name)? else {
                state_lock.remove()?;
                return Ok(VpnNetworkCleanupOutcome::AlreadyClean);
            };
            validate_owned_link(&link, &state, &state.tun_name, false)?;
            delete_persistent_tun(&state.tun_name)?;
            if interface_index(&state.tun_name)?.is_some() {
                return Err(VpnNetworkError::InterfaceBusy);
            }
            state_lock.remove()?;
            Ok(VpnNetworkCleanupOutcome::Cleaned)
        }
    }
}

fn prepare_vpn_network(
    plan: VpnNetworkPlan,
    state_path: &Path,
) -> Result<VpnNetworkPrepareOutcome, VpnNetworkError> {
    let state_lock = VpnNetworkStateLock::acquire(state_path)?;
    let ip = IpCommand::discover()?;
    let mut recovered = false;
    if let Some(state) = state_lock.read()? {
        let state_plan = state.plan()?;
        match state.phase {
            VpnNetworkStatePhase::Prepared => {
                if state_plan.fingerprint != plan.fingerprint {
                    return Err(VpnNetworkError::StateConflict);
                }
                validate_prepared_state(&ip, &state, &plan)?;
                return Ok(VpnNetworkPrepareOutcome::AlreadyPrepared);
            }
            VpnNetworkStatePhase::Preparing => {
                rollback_preparing_state(&ip, &state)?;
                state_lock.remove()?;
                recovered = true;
            }
        }
    }

    if interface_index(&plan.tun_name)?.is_some() {
        return Err(VpnNetworkError::InterfaceExists);
    }
    let mut state = VpnNetworkState::new_preparing(&plan)?;
    if interface_index(&state.temporary_tun_name)?.is_some() {
        return Err(VpnNetworkError::InterfaceExists);
    }
    state_lock.write(&state)?;

    let result = (|| {
        let index =
            create_persistent_tun(&state.temporary_tun_name, state.owner_uid, state.owner_gid)?;
        state.interface_index = Some(index);
        state_lock.write(&state)?;
        configure_tun(&ip, &state, &plan)?;
        state.phase = VpnNetworkStatePhase::Prepared;
        state_lock.write(&state)?;
        Ok(())
    })();

    if let Err(error) = result {
        if rollback_preparing_state(&ip, &state).is_err() || state_lock.remove().is_err() {
            return Err(VpnNetworkError::RollbackFailed);
        }
        return Err(error);
    }

    Ok(if recovered {
        VpnNetworkPrepareOutcome::RecoveredAndPrepared
    } else {
        VpnNetworkPrepareOutcome::Prepared
    })
}

fn configure_tun(
    ip: &IpCommand,
    state: &VpnNetworkState,
    plan: &VpnNetworkPlan,
) -> Result<(), VpnNetworkError> {
    let alias = state.ownership_alias();
    ip.status(
        VpnNetworkIpOperation::SetAlias,
        &[
            "link",
            "set",
            "dev",
            &state.temporary_tun_name,
            "alias",
            &alias,
        ],
    )?;
    let mtu = state.tun_mtu.to_string();
    ip.status(
        VpnNetworkIpOperation::SetMtu,
        &["link", "set", "dev", &state.temporary_tun_name, "mtu", &mtu],
    )?;
    ip.status(
        VpnNetworkIpOperation::SetUp,
        &["link", "set", "dev", &state.temporary_tun_name, "up"],
    )?;
    for address in &plan.addresses {
        add_address(ip, &state.temporary_tun_name, *address)?;
    }
    for route in &plan.routes {
        add_route(ip, &state.temporary_tun_name, *route)?;
    }
    ip.status(
        VpnNetworkIpOperation::Rename,
        &[
            "link",
            "set",
            "dev",
            &state.temporary_tun_name,
            "name",
            &state.tun_name,
        ],
    )?;
    validate_prepared_state(ip, state, plan)
}

fn add_address(ip: &IpCommand, name: &str, address: IpAddr) -> Result<(), VpnNetworkError> {
    let family = match address {
        IpAddr::V4(_) => "-4",
        IpAddr::V6(_) => "-6",
    };
    let prefix = host_prefix(&address);
    let mut arguments = vec![family, "address", "add", &prefix, "dev", name];
    if address.is_ipv6() {
        arguments.push("nodad");
    }
    ip.status(VpnNetworkIpOperation::AddAddress, &arguments)
}

fn add_route(ip: &IpCommand, name: &str, destination: IpAddr) -> Result<(), VpnNetworkError> {
    let family = match destination {
        IpAddr::V4(_) => "-4",
        IpAddr::V6(_) => "-6",
    };
    let prefix = host_prefix(&destination);
    ip.status(
        VpnNetworkIpOperation::AddRoute,
        &[family, "route", "add", &prefix, "dev", name],
    )
}

fn validate_prepared_state(
    ip: &IpCommand,
    state: &VpnNetworkState,
    plan: &VpnNetworkPlan,
) -> Result<(), VpnNetworkError> {
    let link = inspect_link(ip, &state.tun_name)?.ok_or(VpnNetworkError::StateDrift)?;
    validate_owned_link(&link, state, &state.tun_name, true)
        .map_err(|_| VpnNetworkError::StateDrift)?;
    let addresses = inspect_addresses(ip, &state.tun_name)?;
    let expected_addresses = plan.addresses.iter().copied().collect::<HashSet<_>>();
    if addresses != expected_addresses {
        return Err(VpnNetworkError::StateDrift);
    }
    let routes = inspect_routes(ip, &state.tun_name)?;
    let expected_routes = plan.routes.iter().copied().collect::<HashSet<_>>();
    if routes != expected_routes {
        return Err(VpnNetworkError::StateDrift);
    }
    Ok(())
}

fn validate_owned_link(
    link: &LinkSnapshot,
    state: &VpnNetworkState,
    expected_name: &str,
    require_prepared: bool,
) -> Result<(), VpnNetworkError> {
    let expected_index = state
        .interface_index
        .ok_or(VpnNetworkError::InterfaceOwnershipMismatch)?;
    if link.index != expected_index
        || link.name != expected_name
        || !link.tun
        || link.pi
        || link.vnet_hdr
        || link.multi_queue
        || !link.persist
        || link.alias.as_deref() != Some(state.ownership_alias().as_str())
        || link.owner_uid != state.owner_uid
        || link.owner_gid != state.owner_gid
        || require_prepared && (link.mtu != u32::from(state.tun_mtu) || !link.up)
    {
        return Err(VpnNetworkError::InterfaceOwnershipMismatch);
    }
    Ok(())
}

fn rollback_preparing_state(
    ip: &IpCommand,
    state: &VpnNetworkState,
) -> Result<(), VpnNetworkError> {
    state.plan()?;
    let mut owned_name = None;
    for candidate in [&state.temporary_tun_name, &state.tun_name] {
        let Some(link) = inspect_link(ip, candidate)? else {
            continue;
        };
        let owned = match state.interface_index {
            Some(index) => {
                link.index == index
                    && link.tun
                    && !link.pi
                    && !link.vnet_hdr
                    && !link.multi_queue
                    && link.persist
                    && link.owner_uid == state.owner_uid
                    && link.owner_gid == state.owner_gid
                    && (link.alias.as_deref() == Some(state.ownership_alias().as_str())
                        || candidate == &state.temporary_tun_name && link.alias.is_none())
            }
            None => {
                candidate == &state.temporary_tun_name
                    && link.tun
                    && !link.pi
                    && !link.vnet_hdr
                    && !link.multi_queue
                    && link.persist
                    && link.owner_uid == state.owner_uid
                    && link.owner_gid == state.owner_gid
                    && (link.alias.is_none()
                        || link.alias.as_deref() == Some(state.ownership_alias().as_str()))
            }
        };
        if !owned || owned_name.is_some() {
            return Err(VpnNetworkError::InterfaceOwnershipMismatch);
        }
        owned_name = Some(candidate.as_str());
    }
    if let Some(name) = owned_name {
        delete_persistent_tun(name)?;
        if interface_index(name)?.is_some() {
            return Err(VpnNetworkError::InterfaceBusy);
        }
    }
    Ok(())
}

fn ensure_privileged_network_helper() -> Result<(), VpnNetworkError> {
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    // SAFETY: all three pointers reference writable uid_t values owned by this stack frame.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } < 0 {
        return Err(io_error(
            VpnNetworkIoStage::ProcessStatus,
            io::Error::last_os_error(),
        ));
    }
    if [real_uid, effective_uid, saved_uid] != [0, 0, 0] {
        return Err(VpnNetworkError::NotRoot);
    }
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| io_error(VpnNetworkIoStage::ProcessStatus, error))?;
    let capabilities =
        parse_status_u64(&status, "CapEff:", 16).ok_or(VpnNetworkError::ProcessStatusInvalid)?;
    if capabilities & (1_u64 << CAP_NET_ADMIN_NUMBER) == 0 {
        return Err(VpnNetworkError::NetAdminCapabilityMissing);
    }
    Ok(())
}

fn parse_status_u64(status: &str, field: &str, radix: u32) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))?
        .trim();
    u64::from_str_radix(value, radix).ok()
}

fn create_persistent_tun(name: &str, uid: u32, gid: u32) -> Result<u32, VpnNetworkError> {
    let file = open_tun_device()?;
    let mut request = make_ifreq(
        name.as_bytes(),
        (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as i16,
    );
    // SAFETY: request points to a fully initialized ifreq and file is an open /dev/net/tun fd.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &mut request) } < 0 {
        return Err(io_error(
            VpnNetworkIoStage::TunCreate,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: TUNSETOWNER consumes the scalar uid value and file is an attached TUN descriptor.
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            libc::TUNSETOWNER as _,
            uid as libc::c_ulong,
        )
    } < 0
    {
        return Err(io_error(
            VpnNetworkIoStage::TunOwner,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: TUNSETGROUP consumes the scalar gid value and file is an attached TUN descriptor.
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            libc::TUNSETGROUP as _,
            gid as libc::c_ulong,
        )
    } < 0
    {
        return Err(io_error(
            VpnNetworkIoStage::TunGroup,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: TUNSETPERSIST consumes a scalar boolean and file is an attached TUN descriptor.
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            libc::TUNSETPERSIST as _,
            1 as libc::c_ulong,
        )
    } < 0
    {
        return Err(io_error(
            VpnNetworkIoStage::TunPersist,
            io::Error::last_os_error(),
        ));
    }
    drop(file);
    interface_index(name)?.ok_or(VpnNetworkError::InterfaceMissing)
}

fn delete_persistent_tun(name: &str) -> Result<(), VpnNetworkError> {
    let file = open_tun_device()?;
    let mut request = make_ifreq(name.as_bytes(), (libc::IFF_TUN | libc::IFF_NO_PI) as i16);
    // SAFETY: request points to a fully initialized ifreq and file is an open /dev/net/tun fd.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &mut request) } < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBUSY) {
            return Err(VpnNetworkError::InterfaceBusy);
        }
        return Err(io_error(VpnNetworkIoStage::TunDeleteAttach, error));
    }
    // SAFETY: TUNSETPERSIST consumes a scalar boolean and file is an attached TUN descriptor.
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            libc::TUNSETPERSIST as _,
            0 as libc::c_ulong,
        )
    } < 0
    {
        return Err(io_error(
            VpnNetworkIoStage::TunDeletePersist,
            io::Error::last_os_error(),
        ));
    }
    drop(file);
    Ok(())
}

fn open_tun_device() -> Result<File, VpnNetworkError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(TUN_DEVICE_PATH)
        .map_err(|error| io_error(VpnNetworkIoStage::TunDeviceOpen, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error(VpnNetworkIoStage::TunDeviceInspect, error))?;
    let device = metadata.rdev();
    if !metadata.file_type().is_char_device()
        || libc::major(device) != TUN_DEVICE_MAJOR
        || libc::minor(device) != TUN_DEVICE_MINOR
    {
        return Err(VpnNetworkError::InvalidTunCharacterDevice);
    }
    Ok(file)
}

fn make_ifreq(name: &[u8], flags: i16) -> libc::ifreq {
    // SAFETY: all-zero is a valid initial representation for ifreq before populating its fields.
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    for (output, input) in request.ifr_name.iter_mut().zip(name.iter().copied()) {
        *output = input as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = flags;
    request
}

fn interface_index(name: &str) -> Result<Option<u32>, VpnNetworkError> {
    let name = CString::new(name).map_err(|_| VpnNetworkError::InvalidPlan)?;
    // SAFETY: name is a live NUL-terminated interface name.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error().is_none()
            || matches!(error.raw_os_error(), Some(libc::ENODEV) | Some(libc::ENXIO))
        {
            return Ok(None);
        }
        return Err(io_error(VpnNetworkIoStage::InterfaceInspect, error));
    }
    Ok(Some(index))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::{Value, json};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn client_and_server_configs_derive_one_canonical_network_truth() {
        let client_config = parse_vpn_client_product_config_json(
            serde_json::to_vec(&client_config_json())
                .unwrap()
                .as_slice(),
            Path::new("/test"),
        )
        .unwrap();
        let client = client_network_plan(&client_config, 1000, 1000).unwrap();
        assert_eq!(client.role(), VpnNetworkRole::Client);
        assert_eq!(client.tun_name(), "fwvpn0");
        assert_eq!(client.tun_mtu(), 1500);
        assert_eq!(client.owner_uid(), 1000);
        assert_eq!(client.owner_gid(), 1000);
        assert_eq!(
            client.addresses(),
            &[
                IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
                IpAddr::V6("fd77::2".parse::<Ipv6Addr>().unwrap()),
            ]
        );
        assert_eq!(
            client.routes(),
            &[
                IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
                IpAddr::V6("fd77::1".parse::<Ipv6Addr>().unwrap()),
            ]
        );

        let server_config = parse_vpn_server_product_config_json(
            serde_json::to_vec(&server_config_json())
                .unwrap()
                .as_slice(),
            Path::new("/test"),
        )
        .unwrap();
        let registry = parse_vpn_identity_registry_json(
            serde_json::to_vec(&identity_config_json())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let server = server_network_plan(&server_config, &registry, 1000, 1000).unwrap();
        assert_eq!(server.role(), VpnNetworkRole::Server);
        assert_eq!(server.addresses(), client.routes());
        assert_eq!(server.routes(), client.addresses());

        let client_debug = format!("{client:?}");
        assert!(!client_debug.contains("10.77.0.2"));
        assert!(!client_debug.contains("fd77::2"));
        assert!(!client_debug.contains(&client.fingerprint_hex()));
    }

    #[test]
    fn plan_fingerprint_is_semantic_sorted_and_owner_bound() {
        let first = VpnNetworkPlan::new(
            VpnNetworkRole::Server,
            "fwvpn0".to_owned(),
            1500,
            1000,
            1000,
            vec!["fd77::1".parse().unwrap(), "10.77.0.1".parse().unwrap()],
            vec!["fd77::2".parse().unwrap(), "10.77.0.2".parse().unwrap()],
        )
        .unwrap();
        let reordered = VpnNetworkPlan::new(
            VpnNetworkRole::Server,
            "fwvpn0".to_owned(),
            1500,
            1000,
            1000,
            vec!["10.77.0.1".parse().unwrap(), "fd77::1".parse().unwrap()],
            vec!["10.77.0.2".parse().unwrap(), "fd77::2".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(first.fingerprint, reordered.fingerprint);

        let different_owner = VpnNetworkPlan::new(
            VpnNetworkRole::Server,
            "fwvpn0".to_owned(),
            1500,
            1001,
            1000,
            first.addresses.clone(),
            first.routes.clone(),
        )
        .unwrap();
        assert_ne!(first.fingerprint, different_owner.fingerprint);
        assert_eq!(
            VpnNetworkPlan::new(
                VpnNetworkRole::Client,
                "fwvpn0".to_owned(),
                1500,
                0,
                1000,
                vec!["10.77.0.2".parse().unwrap()],
                vec!["10.77.0.1".parse().unwrap()],
            )
            .unwrap_err(),
            VpnNetworkError::InvalidPlan
        );
    }

    #[test]
    fn versioned_state_rejects_noncanonical_or_unowned_content() {
        let plan = VpnNetworkPlan::new(
            VpnNetworkRole::Client,
            "fwvpn0".to_owned(),
            1500,
            1000,
            1000,
            vec!["10.77.0.2".parse().unwrap(), "fd77::2".parse().unwrap()],
            vec!["10.77.0.1".parse().unwrap(), "fd77::1".parse().unwrap()],
        )
        .unwrap();
        let mut state = VpnNetworkState::new_preparing(&plan).unwrap();
        state.interface_index = Some(7);
        state.phase = VpnNetworkStatePhase::Prepared;
        let encoded = serde_json::to_vec(&state).unwrap();
        assert_eq!(parse_vpn_network_state(&encoded).unwrap(), state);

        let mut unknown = serde_json::to_value(&state).unwrap();
        unknown["unknown"] = Value::Bool(true);
        assert!(matches!(
            parse_vpn_network_state(&serde_json::to_vec(&unknown).unwrap()),
            Err(VpnNetworkError::StateInvalidJson { .. })
        ));

        let mut unsupported = serde_json::to_value(&state).unwrap();
        unsupported["state_version"] = Value::from(2);
        assert_eq!(
            parse_vpn_network_state(&serde_json::to_vec(&unsupported).unwrap()).unwrap_err(),
            VpnNetworkError::StateUnsupportedVersion
        );

        let mut duplicate = serde_json::to_value(&state).unwrap();
        duplicate["addresses"] = json!(["10.77.0.2/32", "10.77.0.2/32", "fd77::2/128"]);
        assert_eq!(
            parse_vpn_network_state(&serde_json::to_vec(&duplicate).unwrap()).unwrap_err(),
            VpnNetworkError::StateInvalid
        );

        let mut uppercase_token = serde_json::to_value(&state).unwrap();
        uppercase_token["ownership_token"] =
            Value::from(state.ownership_token.to_ascii_uppercase());
        assert_eq!(
            parse_vpn_network_state(&serde_json::to_vec(&uppercase_token).unwrap()).unwrap_err(),
            VpnNetworkError::StateInvalid
        );

        let mut no_index = serde_json::to_value(&state).unwrap();
        no_index["interface_index"] = Value::Null;
        assert_eq!(
            parse_vpn_network_state(&serde_json::to_vec(&no_index).unwrap()).unwrap_err(),
            VpnNetworkError::StateInvalid
        );
    }

    #[test]
    fn root_helper_config_loader_rejects_unsafe_ownership_permissions_and_symlinks() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let directory = TestDirectory::new();
        let config = directory.path.join("vpn-client.json");
        write_json(&config, &client_config_json());
        fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_vpn_client_network_plan(&config, 1000).unwrap_err(),
            VpnNetworkError::ConfigOwnershipInvalid
        );
        fs::set_permissions(&config, fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(
            load_vpn_client_network_plan(&config, 1000).unwrap_err(),
            VpnNetworkError::ConfigUnsafePermissions
        );

        let link = directory.path.join("vpn-client-link.json");
        symlink(&config, &link).unwrap();
        assert_eq!(
            load_vpn_client_network_plan(&link, 1000).unwrap_err(),
            VpnNetworkError::ConfigSymlink
        );
    }

    #[test]
    fn state_path_rejects_parent_traversal_before_filesystem_access() {
        assert_eq!(
            validate_state_path(Path::new("safe/../state.json")).unwrap_err(),
            VpnNetworkError::InvalidStatePath
        );
        assert_eq!(
            validate_state_path(Path::new("./state.json")).unwrap_err(),
            VpnNetworkError::InvalidStatePath
        );
    }

    fn client_config_json() -> Value {
        json!({
            "config_version": 1,
            "server": "192.0.2.1:4433",
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
            "primary_local_ip": "192.0.2.2",
            "additional_local_ips": []
        })
    }

    fn server_config_json() -> Value {
        json!({
            "config_version": 1,
            "listen": "192.0.2.1:4433",
            "certificate_der": "server.cert.der",
            "private_key_der": "server.key.der",
            "client_ca_der": "client-ca.cert.der",
            "identity_file": "vpn-identities.json",
            "tun_name": "fwvpn0",
            "tun_mtu": 1500,
            "max_datagram_len": 1200,
            "global_reassembly_bytes": 67108864,
            "global_inflight_packets": 8192
        })
    }

    fn identity_config_json() -> Value {
        json!({
            "config_version": 1,
            "server_ipv4": "10.77.0.1",
            "server_ipv6": "fd77::1",
            "identities": [{
                "client_id": "client-a",
                "fingerprints": ["11".repeat(32)],
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
        })
    }

    fn write_json(path: &Path, value: &Value) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        serde_json::to_writer(&mut file, value).unwrap();
        file.write_all(b"\n").unwrap();
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "flowweave-vpn-network-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    VPN_IDENTITY_CONFIG_MAX_BYTES, VPN_PRODUCT_CONFIG_MAX_BYTES, VpnIdentityRegistry,
    VpnServerForwardingConfig, VpnServerProductConfig, parse_vpn_identity_registry_json,
    parse_vpn_server_product_config_json,
};

use super::{
    IpCommand, OWNERSHIP_TOKEN_BYTES, PLAN_FINGERPRINT_BYTES, STATE_TEMP_SEQUENCE, VpnNetworkError,
    VpnNetworkIoStage, VpnNetworkNftOperation, VpnNetworkRole, VpnNetworkState,
    VpnNetworkStateLock, VpnNetworkStatePhase, config_base, ensure_privileged_network_helper,
    hex_encode, io_error, read_owned_private_file, server_network_plan, sync_directory,
    trusted_system_binary_owner, valid_lower_hex, validate_prepared_state,
    validate_root_private_regular_file, validate_vpn_tun_name,
};

pub const VPN_SERVER_FORWARDING_STATE_VERSION: u16 = 1;
pub const VPN_SERVER_FORWARDING_STATE_MAX_BYTES: usize = 1024 * 1024;

const SERVER_FORWARDING_STATE_SUFFIX: &str = ".forwarding";
const SERVER_FORWARDING_PLAN_FINGERPRINT_BYTES: usize = 32;
const SERVER_FORWARDING_STATE_FINGERPRINT_BYTES: usize = 32;
const NFT_TABLE_FINGERPRINT_BYTES: usize = 32;
const NFT_TABLE_FAMILY: &str = "inet";
const NFT_TABLE_NAME: &str = "flowweave_vpn";
const NFT_OWNERSHIP_PREFIX: &str = "flowweave-vpn-forwarding:v1:";
const SERVER_FORWARDING_LOCK_DIRECTORY: &str = "/run";
const SERVER_FORWARDING_LOCK_PATH: &str = "/run/flowweave-vpn-forwarding.lock";
const IPV4_FORWARDING_PATH: &str = "/proc/sys/net/ipv4/ip_forward";
const IPV6_FORWARDING_PATH: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnServerForwardingActivationOutcome {
    Disabled,
    RecoveredAndDisabled,
    Activated,
    AlreadyActive,
    RecoveredAndActivated,
}

impl VpnServerForwardingActivationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::RecoveredAndDisabled => "recovered_and_disabled",
            Self::Activated => "activated",
            Self::AlreadyActive => "already_active",
            Self::RecoveredAndActivated => "recovered_and_activated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnServerForwardingDeactivationOutcome {
    Deactivated,
    AlreadyInactive,
    RecoveredInterruptedActivation,
    RecoveredInterruptedDeactivation,
}

impl VpnServerForwardingDeactivationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deactivated => "deactivated",
            Self::AlreadyInactive => "already_inactive",
            Self::RecoveredInterruptedActivation => "recovered_interrupted_activation",
            Self::RecoveredInterruptedDeactivation => "recovered_interrupted_deactivation",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct VpnServerForwardingPlan {
    network_plan_fingerprint: String,
    tun_name: String,
    interface_index: u32,
    manage_sysctls: bool,
    ipv4_masquerade: bool,
    ipv6_masquerade: bool,
    client_ipv4: Vec<String>,
    client_ipv6: Vec<String>,
    fingerprint: String,
}

impl VpnServerForwardingPlan {
    fn new(
        network_state: &VpnNetworkState,
        config: VpnServerForwardingConfig,
        registry: &VpnIdentityRegistry,
    ) -> Result<Self, VpnNetworkError> {
        let interface_index = network_state
            .interface_index
            .filter(|index| *index != 0)
            .ok_or(VpnNetworkError::ServerForwardingStateInvalid)?;
        let mut client_ipv4 = registry
            .identities()
            .iter()
            .filter(|identity| identity.enabled())
            .filter_map(|identity| identity.client_ipv4())
            .collect::<Vec<_>>();
        client_ipv4.sort_unstable();
        client_ipv4.dedup();
        let mut client_ipv6 = registry
            .identities()
            .iter()
            .filter(|identity| identity.enabled())
            .filter_map(|identity| identity.client_ipv6())
            .collect::<Vec<_>>();
        client_ipv6.sort_unstable();
        client_ipv6.dedup();
        if config.ipv4_masquerade() && client_ipv4.is_empty()
            || config.ipv6_masquerade() && client_ipv6.is_empty()
        {
            return Err(VpnNetworkError::ServerForwardingFamilyUnavailable);
        }
        let mut plan = Self {
            network_plan_fingerprint: network_state.plan_fingerprint.clone(),
            tun_name: network_state.tun_name.clone(),
            interface_index,
            manage_sysctls: config.manage_sysctls(),
            ipv4_masquerade: config.ipv4_masquerade(),
            ipv6_masquerade: config.ipv6_masquerade(),
            client_ipv4: client_ipv4
                .into_iter()
                .map(|address| address.to_string())
                .collect(),
            client_ipv6: client_ipv6
                .into_iter()
                .map(|address| address.to_string())
                .collect(),
            fingerprint: String::new(),
        };
        plan.fingerprint = plan.compute_fingerprint()?;
        Ok(plan)
    }

    fn compute_fingerprint(&self) -> Result<String, VpnNetworkError> {
        compute_forwarding_plan_fingerprint(ForwardingPlanFingerprintInput {
            network_plan_fingerprint: &self.network_plan_fingerprint,
            tun_name: &self.tun_name,
            interface_index: self.interface_index,
            manage_sysctls: self.manage_sysctls,
            ipv4_masquerade: self.ipv4_masquerade,
            ipv6_masquerade: self.ipv6_masquerade,
            client_ipv4: &self.client_ipv4,
            client_ipv6: &self.client_ipv6,
        })
    }
}

struct ForwardingPlanFingerprintInput<'a> {
    network_plan_fingerprint: &'a str,
    tun_name: &'a str,
    interface_index: u32,
    manage_sysctls: bool,
    ipv4_masquerade: bool,
    ipv6_masquerade: bool,
    client_ipv4: &'a [String],
    client_ipv6: &'a [String],
}

fn compute_forwarding_plan_fingerprint(
    input: ForwardingPlanFingerprintInput<'_>,
) -> Result<String, VpnNetworkError> {
    #[derive(Serialize)]
    struct CanonicalForwardingPlan<'a> {
        plan_version: u16,
        network_plan_fingerprint: &'a str,
        tun_name: &'a str,
        interface_index: u32,
        manage_sysctls: bool,
        ipv4_masquerade: bool,
        ipv6_masquerade: bool,
        client_ipv4: &'a [String],
        client_ipv6: &'a [String],
    }

    let bytes = serde_json::to_vec(&CanonicalForwardingPlan {
        plan_version: 1,
        network_plan_fingerprint: input.network_plan_fingerprint,
        tun_name: input.tun_name,
        interface_index: input.interface_index,
        manage_sysctls: input.manage_sysctls,
        ipv4_masquerade: input.ipv4_masquerade,
        ipv6_masquerade: input.ipv6_masquerade,
        client_ipv4: input.client_ipv4,
        client_ipv6: input.client_ipv6,
    })
    .map_err(|_| VpnNetworkError::ServerForwardingStateInvalid)?;
    Ok(hex_encode(digest(&SHA256, &bytes).as_ref()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VpnServerForwardingStatePhase {
    Activating,
    Active,
    Deactivating,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VpnServerForwardingState {
    state_version: u16,
    phase: VpnServerForwardingStatePhase,
    forwarding_plan_fingerprint: String,
    state_fingerprint: String,
    network_plan_fingerprint: String,
    tun_name: String,
    interface_index: u32,
    ownership_token: String,
    manage_sysctls: bool,
    ipv4_masquerade: bool,
    ipv6_masquerade: bool,
    original_ipv4_forwarding: Option<u8>,
    original_ipv6_forwarding: Option<u8>,
    client_ipv4: Vec<String>,
    client_ipv6: Vec<String>,
    nft_table_fingerprint: Option<String>,
}

impl VpnServerForwardingState {
    fn new_activating(
        plan: &VpnServerForwardingPlan,
        originals: SysctlOriginals,
    ) -> Result<Self, VpnNetworkError> {
        let mut token = [0_u8; OWNERSHIP_TOKEN_BYTES];
        SystemRandom::new()
            .fill(&mut token)
            .map_err(|_| VpnNetworkError::RandomUnavailable)?;
        let mut state = Self {
            state_version: VPN_SERVER_FORWARDING_STATE_VERSION,
            phase: VpnServerForwardingStatePhase::Activating,
            forwarding_plan_fingerprint: plan.fingerprint.clone(),
            state_fingerprint: String::new(),
            network_plan_fingerprint: plan.network_plan_fingerprint.clone(),
            tun_name: plan.tun_name.clone(),
            interface_index: plan.interface_index,
            ownership_token: hex_encode(&token),
            manage_sysctls: plan.manage_sysctls,
            ipv4_masquerade: plan.ipv4_masquerade,
            ipv6_masquerade: plan.ipv6_masquerade,
            original_ipv4_forwarding: originals.ipv4,
            original_ipv6_forwarding: originals.ipv6,
            client_ipv4: plan.client_ipv4.clone(),
            client_ipv6: plan.client_ipv6.clone(),
            nft_table_fingerprint: None,
        };
        state.refresh_state_fingerprint()?;
        state.validate_shape()?;
        Ok(state)
    }

    fn set_phase(&mut self, phase: VpnServerForwardingStatePhase) -> Result<(), VpnNetworkError> {
        self.phase = phase;
        self.refresh_state_fingerprint()?;
        self.validate_shape()
    }

    fn set_active(&mut self, nft_table_fingerprint: String) -> Result<(), VpnNetworkError> {
        self.nft_table_fingerprint = Some(nft_table_fingerprint);
        self.set_phase(VpnServerForwardingStatePhase::Active)
    }

    fn required_ipv4(&self) -> bool {
        !self.client_ipv4.is_empty()
    }

    fn required_ipv6(&self) -> bool {
        !self.client_ipv6.is_empty()
    }

    fn ownership_comment(&self) -> String {
        format!("{NFT_OWNERSHIP_PREFIX}{}", self.ownership_token)
    }

    fn object_comment(&self, object: &str) -> String {
        format!("{}:{object}", self.ownership_comment())
    }

    fn validate_shape(&self) -> Result<(), VpnNetworkError> {
        if self.state_version != VPN_SERVER_FORWARDING_STATE_VERSION {
            return Err(VpnNetworkError::ServerForwardingStateUnsupportedVersion);
        }
        validate_vpn_tun_name(&self.tun_name)
            .map_err(|_| VpnNetworkError::ServerForwardingStateInvalid)?;
        if self.interface_index == 0
            || !valid_lower_hex(&self.network_plan_fingerprint, PLAN_FINGERPRINT_BYTES)
            || !valid_lower_hex(
                &self.forwarding_plan_fingerprint,
                SERVER_FORWARDING_PLAN_FINGERPRINT_BYTES,
            )
            || !valid_lower_hex(
                &self.state_fingerprint,
                SERVER_FORWARDING_STATE_FINGERPRINT_BYTES,
            )
            || !valid_lower_hex(&self.ownership_token, OWNERSHIP_TOKEN_BYTES)
            || self.ipv4_masquerade && self.client_ipv4.is_empty()
            || self.ipv6_masquerade && self.client_ipv6.is_empty()
            || self
                .nft_table_fingerprint
                .as_deref()
                .is_some_and(|fingerprint| {
                    !valid_lower_hex(fingerprint, NFT_TABLE_FINGERPRINT_BYTES)
                })
            || self.phase == VpnServerForwardingStatePhase::Activating
                && self.nft_table_fingerprint.is_some()
            || self.phase == VpnServerForwardingStatePhase::Active
                && self.nft_table_fingerprint.is_none()
        {
            return Err(VpnNetworkError::ServerForwardingStateInvalid);
        }
        validate_canonical_ipv4(&self.client_ipv4)?;
        validate_canonical_ipv6(&self.client_ipv6)?;
        let originals_valid = if self.manage_sysctls {
            self.original_ipv4_forwarding.is_some() == self.required_ipv4()
                && self.original_ipv6_forwarding.is_some() == self.required_ipv6()
                && self.original_ipv4_forwarding.is_none_or(|value| value <= 1)
                && self.original_ipv6_forwarding.is_none_or(|value| value <= 1)
        } else {
            self.original_ipv4_forwarding.is_none() && self.original_ipv6_forwarding.is_none()
        };
        if !originals_valid
            || compute_forwarding_plan_fingerprint(ForwardingPlanFingerprintInput {
                network_plan_fingerprint: &self.network_plan_fingerprint,
                tun_name: &self.tun_name,
                interface_index: self.interface_index,
                manage_sysctls: self.manage_sysctls,
                ipv4_masquerade: self.ipv4_masquerade,
                ipv6_masquerade: self.ipv6_masquerade,
                client_ipv4: &self.client_ipv4,
                client_ipv6: &self.client_ipv6,
            })? != self.forwarding_plan_fingerprint
            || self.compute_state_fingerprint()? != self.state_fingerprint
        {
            return Err(VpnNetworkError::ServerForwardingStateInvalid);
        }
        Ok(())
    }

    fn refresh_state_fingerprint(&mut self) -> Result<(), VpnNetworkError> {
        self.state_fingerprint = self.compute_state_fingerprint()?;
        Ok(())
    }

    fn compute_state_fingerprint(&self) -> Result<String, VpnNetworkError> {
        #[derive(Serialize)]
        struct CanonicalForwardingState<'a> {
            state_version: u16,
            forwarding_plan_fingerprint: &'a str,
            network_plan_fingerprint: &'a str,
            tun_name: &'a str,
            interface_index: u32,
            ownership_token: &'a str,
            manage_sysctls: bool,
            ipv4_masquerade: bool,
            ipv6_masquerade: bool,
            original_ipv4_forwarding: Option<u8>,
            original_ipv6_forwarding: Option<u8>,
            client_ipv4: &'a [String],
            client_ipv6: &'a [String],
        }

        let bytes = serde_json::to_vec(&CanonicalForwardingState {
            state_version: self.state_version,
            forwarding_plan_fingerprint: &self.forwarding_plan_fingerprint,
            network_plan_fingerprint: &self.network_plan_fingerprint,
            tun_name: &self.tun_name,
            interface_index: self.interface_index,
            ownership_token: &self.ownership_token,
            manage_sysctls: self.manage_sysctls,
            ipv4_masquerade: self.ipv4_masquerade,
            ipv6_masquerade: self.ipv6_masquerade,
            original_ipv4_forwarding: self.original_ipv4_forwarding,
            original_ipv6_forwarding: self.original_ipv6_forwarding,
            client_ipv4: &self.client_ipv4,
            client_ipv6: &self.client_ipv6,
        })
        .map_err(|_| VpnNetworkError::ServerForwardingStateInvalid)?;
        Ok(hex_encode(digest(&SHA256, &bytes).as_ref()))
    }
}

impl std::fmt::Debug for VpnServerForwardingState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VpnServerForwardingState")
            .field("state_version", &self.state_version)
            .field("phase", &self.phase)
            .field("tun_name", &self.tun_name)
            .field("interface_index", &self.interface_index)
            .field("manage_sysctls", &self.manage_sysctls)
            .field("ipv4_masquerade", &self.ipv4_masquerade)
            .field("ipv6_masquerade", &self.ipv6_masquerade)
            .field("ipv4_client_count", &self.client_ipv4.len())
            .field("ipv6_client_count", &self.client_ipv6.len())
            .field("forwarding_plan_fingerprint", &"[redacted]")
            .field("state_fingerprint", &"[redacted]")
            .field("ownership_token", &"[redacted]")
            .field("nft_table_fingerprint", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct SysctlOriginals {
    ipv4: Option<u8>,
    ipv6: Option<u8>,
}

pub fn activate_vpn_server_forwarding(
    config_path: &Path,
    state_path: &Path,
) -> Result<VpnServerForwardingActivationOutcome, VpnNetworkError> {
    ensure_privileged_network_helper()?;
    let state_lock = VpnNetworkStateLock::acquire(state_path)?;
    let network_state = state_lock.read()?.ok_or(VpnNetworkError::StateConflict)?;
    let network_plan = network_state.plan()?;
    if network_state.role != VpnNetworkRole::Server
        || network_state.phase != VpnNetworkStatePhase::Prepared
    {
        return Err(VpnNetworkError::StateConflict);
    }
    let ip = IpCommand::discover()?;
    validate_prepared_state(&ip, &network_state, &network_plan)?;

    let (config, registry, config_gid) = load_server_config_and_registry(config_path)?;
    let current_network_plan =
        server_network_plan(&config, &registry, network_state.owner_uid, config_gid)?;
    if current_network_plan.fingerprint != network_plan.fingerprint {
        return Err(VpnNetworkError::StateConflict);
    }
    let forwarding_plan = config
        .forwarding()
        .map(|forwarding| VpnServerForwardingPlan::new(&network_state, forwarding, &registry))
        .transpose()?;

    let existing = state_lock.read_server_forwarding()?;
    if forwarding_plan.is_none() && existing.is_none() {
        return Ok(VpnServerForwardingActivationOutcome::Disabled);
    }

    let _global_lock = VpnServerForwardingGlobalLock::acquire()?;
    let nft = NftCommand::discover()?;
    let mut recovered = false;
    if let Some(mut state) = existing {
        state.validate_shape()?;
        match state.phase {
            VpnServerForwardingStatePhase::Active => {
                let plan = forwarding_plan
                    .as_ref()
                    .ok_or(VpnNetworkError::ServerForwardingStateConflict)?;
                if state.network_plan_fingerprint != plan.network_plan_fingerprint
                    || state.forwarding_plan_fingerprint != plan.fingerprint
                {
                    return Err(VpnNetworkError::ServerForwardingStateConflict);
                }
                validate_active_sysctls(&state)?;
                let snapshot = inspect_owned_table(&nft, &state)?
                    .ok_or(VpnNetworkError::ServerForwardingStateDrift)?;
                if state.nft_table_fingerprint.as_deref() != Some(snapshot.fingerprint.as_str()) {
                    return Err(VpnNetworkError::ServerForwardingStateDrift);
                }
                return Ok(VpnServerForwardingActivationOutcome::AlreadyActive);
            }
            VpnServerForwardingStatePhase::Activating
            | VpnServerForwardingStatePhase::Deactivating => {
                state.set_phase(VpnServerForwardingStatePhase::Deactivating)?;
                state_lock.write_server_forwarding(&state)?;
                rollback_server_forwarding(&nft, &state)?;
                state_lock.remove_server_forwarding()?;
                recovered = true;
            }
        }
    }

    let Some(plan) = forwarding_plan else {
        return Ok(if recovered {
            VpnServerForwardingActivationOutcome::RecoveredAndDisabled
        } else {
            VpnServerForwardingActivationOutcome::Disabled
        });
    };
    if nft.table_exists()? {
        return Err(VpnNetworkError::ServerForwardingTableConflict);
    }
    let originals = capture_sysctl_originals(&plan)?;
    let mut state = VpnServerForwardingState::new_activating(&plan, originals)?;
    state_lock.write_server_forwarding(&state)?;

    let result = (|| {
        nft.apply_table(&nft_batch(&state))?;
        if state.manage_sysctls {
            enable_managed_sysctls(&state)?;
        } else {
            require_forwarding_enabled(state.required_ipv4(), state.required_ipv6())?;
        }
        let snapshot = inspect_owned_table(&nft, &state)?
            .ok_or(VpnNetworkError::ServerForwardingStateDrift)?;
        state.set_active(snapshot.fingerprint)?;
        state_lock.write_server_forwarding(&state)
    })();
    if let Err(error) = result {
        if rollback_server_forwarding(&nft, &state).is_err()
            || state_lock.remove_server_forwarding().is_err()
        {
            return Err(VpnNetworkError::RollbackFailed);
        }
        return Err(error);
    }

    Ok(if recovered {
        VpnServerForwardingActivationOutcome::RecoveredAndActivated
    } else {
        VpnServerForwardingActivationOutcome::Activated
    })
}

pub fn deactivate_vpn_server_forwarding(
    state_path: &Path,
) -> Result<VpnServerForwardingDeactivationOutcome, VpnNetworkError> {
    ensure_privileged_network_helper()?;
    let state_lock = VpnNetworkStateLock::acquire(state_path)?;
    deactivate_vpn_server_forwarding_locked(&state_lock)
}

pub(super) fn deactivate_vpn_server_forwarding_locked(
    state_lock: &VpnNetworkStateLock,
) -> Result<VpnServerForwardingDeactivationOutcome, VpnNetworkError> {
    let Some(mut state) = state_lock.read_server_forwarding()? else {
        return Ok(VpnServerForwardingDeactivationOutcome::AlreadyInactive);
    };
    state.validate_shape()?;
    let original_phase = state.phase;
    let _global_lock = VpnServerForwardingGlobalLock::acquire()?;
    let nft = NftCommand::discover()?;
    state.set_phase(VpnServerForwardingStatePhase::Deactivating)?;
    state_lock.write_server_forwarding(&state)?;
    rollback_server_forwarding(&nft, &state)?;
    state_lock.remove_server_forwarding()?;
    Ok(match original_phase {
        VpnServerForwardingStatePhase::Active => {
            VpnServerForwardingDeactivationOutcome::Deactivated
        }
        VpnServerForwardingStatePhase::Activating => {
            VpnServerForwardingDeactivationOutcome::RecoveredInterruptedActivation
        }
        VpnServerForwardingStatePhase::Deactivating => {
            VpnServerForwardingDeactivationOutcome::RecoveredInterruptedDeactivation
        }
    })
}

fn load_server_config_and_registry(
    config_path: &Path,
) -> Result<(VpnServerProductConfig, VpnIdentityRegistry, u32), VpnNetworkError> {
    let config_file = read_owned_private_file(
        config_path,
        VPN_PRODUCT_CONFIG_MAX_BYTES,
        VpnNetworkIoStage::ConfigOpen,
        VpnNetworkIoStage::ConfigInspect,
        VpnNetworkIoStage::ConfigRead,
    )?;
    let config =
        parse_vpn_server_product_config_json(&config_file.bytes, config_base(config_path))?;
    let identity_file = read_owned_private_file(
        config.identity_file(),
        VPN_IDENTITY_CONFIG_MAX_BYTES,
        VpnNetworkIoStage::IdentityOpen,
        VpnNetworkIoStage::IdentityInspect,
        VpnNetworkIoStage::IdentityRead,
    )?;
    if (identity_file.uid, identity_file.gid) != (config_file.uid, config_file.gid) {
        return Err(VpnNetworkError::ConfigOwnerMismatch);
    }
    let registry = parse_vpn_identity_registry_json(&identity_file.bytes)?;
    Ok((config, registry, config_file.gid))
}

impl VpnNetworkStateLock {
    fn server_forwarding_state_path(&self) -> Result<PathBuf, VpnNetworkError> {
        let mut name = self
            .state_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(VpnNetworkError::InvalidStatePath)?
            .to_os_string();
        name.push(SERVER_FORWARDING_STATE_SUFFIX);
        Ok(self.state_directory.join(name))
    }

    fn read_server_forwarding(&self) -> Result<Option<VpnServerForwardingState>, VpnNetworkError> {
        let path = self.server_forwarding_state_path()?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(io_error(
                    VpnNetworkIoStage::ServerForwardingStateOpen,
                    error,
                ));
            }
        };
        let metadata = validate_root_private_regular_file(
            &file,
            VpnNetworkIoStage::ServerForwardingStateInspect,
            true,
        )?;
        if metadata.len() > VPN_SERVER_FORWARDING_STATE_MAX_BYTES as u64 {
            return Err(VpnNetworkError::ServerForwardingStateTooLarge);
        }
        let mut limited = file.take((VPN_SERVER_FORWARDING_STATE_MAX_BYTES + 1) as u64);
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(VPN_SERVER_FORWARDING_STATE_MAX_BYTES)
                .min(VPN_SERVER_FORWARDING_STATE_MAX_BYTES),
        );
        limited
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(VpnNetworkIoStage::ServerForwardingStateRead, error))?;
        if bytes.len() > VPN_SERVER_FORWARDING_STATE_MAX_BYTES {
            return Err(VpnNetworkError::ServerForwardingStateTooLarge);
        }
        let state: VpnServerForwardingState = serde_json::from_slice(&bytes).map_err(|error| {
            VpnNetworkError::ServerForwardingStateInvalidJson {
                line: error.line(),
                column: error.column(),
            }
        })?;
        state.validate_shape()?;
        Ok(Some(state))
    }

    fn write_server_forwarding(
        &self,
        state: &VpnServerForwardingState,
    ) -> Result<(), VpnNetworkError> {
        state.validate_shape()?;
        let path = self.server_forwarding_state_path()?;
        let mut bytes = serde_json::to_vec_pretty(state)
            .map_err(|_| VpnNetworkError::ServerForwardingStateInvalid)?;
        bytes.push(b'\n');
        if bytes.len() > VPN_SERVER_FORWARDING_STATE_MAX_BYTES {
            return Err(VpnNetworkError::ServerForwardingStateTooLarge);
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
                .map_err(|error| io_error(VpnNetworkIoStage::ServerForwardingStateWrite, error))?;
            file.write_all(&bytes)
                .map_err(|error| io_error(VpnNetworkIoStage::ServerForwardingStateWrite, error))?;
            file.sync_all()
                .map_err(|error| io_error(VpnNetworkIoStage::ServerForwardingStateSync, error))?;
            fs::rename(&temporary_path, &path)
                .map_err(|error| io_error(VpnNetworkIoStage::ServerForwardingStateRename, error))?;
            sync_directory(&self.state_directory)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn remove_server_forwarding(&self) -> Result<(), VpnNetworkError> {
        let path = self.server_forwarding_state_path()?;
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&self.state_directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(
                VpnNetworkIoStage::ServerForwardingStateRemove,
                error,
            )),
        }
    }
}

struct VpnServerForwardingGlobalLock {
    _file: File,
}

impl VpnServerForwardingGlobalLock {
    fn acquire() -> Result<Self, VpnNetworkError> {
        let directory = fs::symlink_metadata(SERVER_FORWARDING_LOCK_DIRECTORY)
            .map_err(|error| io_error(VpnNetworkIoStage::ServerForwardingLockInspect, error))?;
        if directory.file_type().is_symlink()
            || !directory.is_dir()
            || directory.uid() != 0
            || directory.permissions().mode() & 0o022 != 0
        {
            return Err(VpnNetworkError::UnsafeStateDirectory);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(SERVER_FORWARDING_LOCK_PATH)
            .map_err(|error| io_error(VpnNetworkIoStage::ServerForwardingLockOpen, error))?;
        validate_root_private_regular_file(
            &file,
            VpnNetworkIoStage::ServerForwardingLockInspect,
            true,
        )?;
        // SAFETY: file is a live regular-file descriptor and LOCK_NB retains no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(VpnNetworkError::ServerForwardingBusy);
            }
            return Err(io_error(VpnNetworkIoStage::ServerForwardingLock, error));
        }
        Ok(Self { _file: file })
    }
}

struct NftCommand {
    path: PathBuf,
}

impl NftCommand {
    fn discover() -> Result<Self, VpnNetworkError> {
        for candidate in ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"] {
            let path = Path::new(candidate);
            let canonical = match fs::canonicalize(path) {
                Ok(path) => path,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(VpnNetworkIoStage::NftInspect, error)),
            };
            let metadata = fs::metadata(&canonical)
                .map_err(|error| io_error(VpnNetworkIoStage::NftInspect, error))?;
            if !metadata.is_file()
                || !trusted_system_binary_owner(metadata.uid())?
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(VpnNetworkError::NftBinaryUnsafe);
            }
            return Ok(Self { path: canonical });
        }
        Err(VpnNetworkError::NftBinaryUnavailable)
    }

    fn table_exists(&self) -> Result<bool, VpnNetworkError> {
        let value = self.json(
            VpnNetworkNftOperation::InspectTables,
            &["-j", "list", "tables"],
        )?;
        let entries = value
            .as_object()
            .filter(|object| object.len() == 1)
            .and_then(|object| object.get("nftables"))
            .and_then(Value::as_array)
            .ok_or(VpnNetworkError::NftOutputInvalid(
                VpnNetworkNftOperation::InspectTables,
            ))?;
        let mut matches = 0;
        for entry in entries {
            if entry
                .as_object()
                .is_some_and(|object| object.len() == 1 && object.contains_key("metainfo"))
            {
                continue;
            }
            let Some(table) = entry
                .as_object()
                .filter(|object| object.len() == 1)
                .and_then(|object| object.get("table"))
                .and_then(Value::as_object)
            else {
                return Err(VpnNetworkError::NftOutputInvalid(
                    VpnNetworkNftOperation::InspectTables,
                ));
            };
            if table.get("family").and_then(Value::as_str) == Some(NFT_TABLE_FAMILY)
                && table.get("name").and_then(Value::as_str) == Some(NFT_TABLE_NAME)
            {
                matches += 1;
            }
        }
        if matches > 1 {
            return Err(VpnNetworkError::NftOutputInvalid(
                VpnNetworkNftOperation::InspectTables,
            ));
        }
        Ok(matches == 1)
    }

    fn inspect_table(&self) -> Result<Option<Value>, VpnNetworkError> {
        if !self.table_exists()? {
            return Ok(None);
        }
        self.json(
            VpnNetworkNftOperation::InspectTable,
            &["-j", "list", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME],
        )
        .map(Some)
    }

    fn apply_table(&self, batch: &str) -> Result<(), VpnNetworkError> {
        let mut child = self
            .command(&["-f", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|error| io_error(VpnNetworkIoStage::NftSpawn, error))?;
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.wait_with_output();
            return Err(VpnNetworkError::NftCommandFailed {
                operation: VpnNetworkNftOperation::ApplyTable,
                status: None,
            });
        };
        let write_result = stdin.write_all(batch.as_bytes());
        drop(stdin);
        if let Err(error) = write_result {
            let _ = child.wait_with_output();
            return Err(io_error(VpnNetworkIoStage::NftSpawn, error));
        }
        let output = child
            .wait_with_output()
            .map_err(|error| io_error(VpnNetworkIoStage::NftSpawn, error))?;
        if !output.status.success() {
            return Err(VpnNetworkError::NftCommandFailed {
                operation: VpnNetworkNftOperation::ApplyTable,
                status: output.status.code(),
            });
        }
        Ok(())
    }

    fn delete_table(&self) -> Result<(), VpnNetworkError> {
        let output = self
            .command(&["delete", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME])
            .output()
            .map_err(|error| io_error(VpnNetworkIoStage::NftSpawn, error))?;
        if !output.status.success() {
            return Err(VpnNetworkError::NftCommandFailed {
                operation: VpnNetworkNftOperation::DeleteTable,
                status: output.status.code(),
            });
        }
        Ok(())
    }

    fn json(
        &self,
        operation: VpnNetworkNftOperation,
        arguments: &[&str],
    ) -> Result<Value, VpnNetworkError> {
        let output = self
            .command(arguments)
            .output()
            .map_err(|error| io_error(VpnNetworkIoStage::NftSpawn, error))?;
        if !output.status.success() {
            return Err(VpnNetworkError::NftCommandFailed {
                operation,
                status: output.status.code(),
            });
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| VpnNetworkError::NftOutputInvalid(operation))
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.path);
        command
            .args(arguments)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

struct NftTableSnapshot {
    fingerprint: String,
}

fn inspect_owned_table(
    nft: &NftCommand,
    state: &VpnServerForwardingState,
) -> Result<Option<NftTableSnapshot>, VpnNetworkError> {
    let Some(value) = nft.inspect_table()? else {
        return Ok(None);
    };
    let normalized = normalize_nft_json(value)?;
    validate_normalized_nft_table(&normalized, state)?;
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|_| VpnNetworkError::NftOutputInvalid(VpnNetworkNftOperation::InspectTable))?;
    Ok(Some(NftTableSnapshot {
        fingerprint: hex_encode(digest(&SHA256, &bytes).as_ref()),
    }))
}

fn normalize_nft_json(mut value: Value) -> Result<Value, VpnNetworkError> {
    let entries = value
        .as_object_mut()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get_mut("nftables"))
        .and_then(Value::as_array_mut)
        .ok_or(VpnNetworkError::NftOutputInvalid(
            VpnNetworkNftOperation::InspectTable,
        ))?;
    entries.retain(|entry| {
        !entry
            .as_object()
            .is_some_and(|object| object.len() == 1 && object.contains_key("metainfo"))
    });
    remove_volatile_nft_fields(&mut value);
    Ok(value)
}

fn remove_volatile_nft_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("handle");
            for value in object.values_mut() {
                remove_volatile_nft_fields(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_volatile_nft_fields(value);
            }
        }
        _ => {}
    }
}

fn validate_normalized_nft_table(
    value: &Value,
    state: &VpnServerForwardingState,
) -> Result<(), VpnNetworkError> {
    let entries = value
        .as_object()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("nftables"))
        .and_then(Value::as_array)
        .ok_or(VpnNetworkError::ServerForwardingStateDrift)?;
    let expected_table = expected_table(state);
    let mut expected_chains = expected_chains(state);
    let mut expected_rules = expected_rules(state);
    let mut table_seen = false;
    for entry in entries {
        let object = entry
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or(VpnNetworkError::ServerForwardingStateDrift)?;
        if let Some(table) = object.get("table") {
            if table_seen || table != &expected_table {
                return Err(VpnNetworkError::ServerForwardingStateDrift);
            }
            table_seen = true;
            continue;
        }
        if let Some(chain) = object.get("chain") {
            let name = chain
                .get("name")
                .and_then(Value::as_str)
                .ok_or(VpnNetworkError::ServerForwardingStateDrift)?;
            if expected_chains.remove(name).as_ref() != Some(chain) {
                return Err(VpnNetworkError::ServerForwardingStateDrift);
            }
            continue;
        }
        if let Some(rule) = object.get("rule") {
            let comment = rule
                .get("comment")
                .and_then(Value::as_str)
                .ok_or(VpnNetworkError::ServerForwardingStateDrift)?;
            if expected_rules.remove(comment).as_ref() != Some(rule) {
                return Err(VpnNetworkError::ServerForwardingStateDrift);
            }
            continue;
        }
        return Err(VpnNetworkError::ServerForwardingStateDrift);
    }
    if !table_seen || !expected_chains.is_empty() || !expected_rules.is_empty() {
        return Err(VpnNetworkError::ServerForwardingStateDrift);
    }
    Ok(())
}

fn expected_table(state: &VpnServerForwardingState) -> Value {
    json!({
        "family": NFT_TABLE_FAMILY,
        "name": NFT_TABLE_NAME,
        "comment": state.ownership_comment()
    })
}

fn expected_chains(state: &VpnServerForwardingState) -> HashMap<String, Value> {
    HashMap::from([
        (
            "forward".to_owned(),
            json!({
                "family": NFT_TABLE_FAMILY,
                "table": NFT_TABLE_NAME,
                "name": "forward",
                "comment": state.object_comment("chain:forward"),
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "accept"
            }),
        ),
        (
            "postrouting".to_owned(),
            json!({
                "family": NFT_TABLE_FAMILY,
                "table": NFT_TABLE_NAME,
                "name": "postrouting",
                "comment": state.object_comment("chain:postrouting"),
                "type": "nat",
                "hook": "postrouting",
                "prio": 100,
                "policy": "accept"
            }),
        ),
    ])
}

fn expected_rules(state: &VpnServerForwardingState) -> HashMap<String, Value> {
    let mut rules = HashMap::new();
    if !state.client_ipv4.is_empty() {
        insert_forward_rules(&mut rules, state, "ip", &state.client_ipv4, "v4");
    }
    if !state.client_ipv6.is_empty() {
        insert_forward_rules(&mut rules, state, "ip6", &state.client_ipv6, "v6");
    }
    insert_rule(
        &mut rules,
        state,
        "rule:drop-from-tun",
        "forward",
        json!([
            meta_match("iifname", "==", &state.tun_name),
            json!({"drop": null})
        ]),
    );
    insert_rule(
        &mut rules,
        state,
        "rule:drop-to-tun",
        "forward",
        json!([
            meta_match("oifname", "==", &state.tun_name),
            json!({"drop": null})
        ]),
    );
    if state.ipv4_masquerade {
        insert_masquerade_rule(&mut rules, state, "ip", &state.client_ipv4, "v4");
    }
    if state.ipv6_masquerade {
        insert_masquerade_rule(&mut rules, state, "ip6", &state.client_ipv6, "v6");
    }
    rules
}

fn insert_forward_rules(
    rules: &mut HashMap<String, Value>,
    state: &VpnServerForwardingState,
    protocol: &str,
    addresses: &[String],
    family_suffix: &str,
) {
    insert_rule(
        rules,
        state,
        &format!("rule:forward-{family_suffix}-out"),
        "forward",
        json!([
            meta_match("iifname", "==", &state.tun_name),
            meta_match("oifname", "!=", &state.tun_name),
            payload_match(protocol, "saddr", address_operand(addresses)),
            ct_state_match(&["established", "related", "new"]),
            json!({"accept": null})
        ]),
    );
    insert_rule(
        rules,
        state,
        &format!("rule:forward-{family_suffix}-in"),
        "forward",
        json!([
            meta_match("iifname", "!=", &state.tun_name),
            meta_match("oifname", "==", &state.tun_name),
            payload_match(protocol, "daddr", address_operand(addresses)),
            ct_state_match(&["established", "related"]),
            json!({"accept": null})
        ]),
    );
}

fn insert_masquerade_rule(
    rules: &mut HashMap<String, Value>,
    state: &VpnServerForwardingState,
    protocol: &str,
    addresses: &[String],
    family_suffix: &str,
) {
    insert_rule(
        rules,
        state,
        &format!("rule:masquerade-{family_suffix}"),
        "postrouting",
        json!([
            payload_match(protocol, "saddr", address_operand(addresses)),
            json!({"masquerade": null})
        ]),
    );
}

fn insert_rule(
    rules: &mut HashMap<String, Value>,
    state: &VpnServerForwardingState,
    comment_suffix: &str,
    chain: &str,
    expressions: Value,
) {
    let comment = state.object_comment(comment_suffix);
    let previous = rules.insert(
        comment.clone(),
        json!({
            "family": NFT_TABLE_FAMILY,
            "table": NFT_TABLE_NAME,
            "chain": chain,
            "comment": comment,
            "expr": expressions
        }),
    );
    debug_assert!(previous.is_none());
}

fn meta_match(key: &str, operation: &str, right: &str) -> Value {
    json!({
        "match": {
            "op": operation,
            "left": {"meta": {"key": key}},
            "right": right
        }
    })
}

fn payload_match(protocol: &str, field: &str, right: Value) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": protocol, "field": field}},
            "right": right
        }
    })
}

fn ct_state_match(states: &[&str]) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"ct": {"key": "state"}},
            "right": {"set": states}
        }
    })
}

fn address_operand(addresses: &[String]) -> Value {
    if addresses.len() == 1 {
        Value::String(addresses[0].clone())
    } else {
        json!({"set": addresses})
    }
}

fn nft_batch(state: &VpnServerForwardingState) -> String {
    let mut batch = String::new();
    append_nft_line(
        &mut batch,
        &format!(
            "add table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {{ comment \"{}\"; }}",
            state.ownership_comment()
        ),
    );
    append_nft_line(
        &mut batch,
        &format!(
            "add chain {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} forward {{ type filter hook forward priority filter; policy accept; comment \"{}\"; }}",
            state.object_comment("chain:forward")
        ),
    );
    append_nft_line(
        &mut batch,
        &format!(
            "add chain {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} postrouting {{ type nat hook postrouting priority srcnat; policy accept; comment \"{}\"; }}",
            state.object_comment("chain:postrouting")
        ),
    );
    if !state.client_ipv4.is_empty() {
        append_nft_forward_rules(&mut batch, state, "ip", &state.client_ipv4, "v4");
    }
    if !state.client_ipv6.is_empty() {
        append_nft_forward_rules(&mut batch, state, "ip6", &state.client_ipv6, "v6");
    }
    append_nft_line(
        &mut batch,
        &format!(
            "add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} forward iifname \"{}\" drop comment \"{}\"",
            state.tun_name,
            state.object_comment("rule:drop-from-tun")
        ),
    );
    append_nft_line(
        &mut batch,
        &format!(
            "add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} forward oifname \"{}\" drop comment \"{}\"",
            state.tun_name,
            state.object_comment("rule:drop-to-tun")
        ),
    );
    if state.ipv4_masquerade {
        append_nft_masquerade_rule(&mut batch, state, "ip", &state.client_ipv4, "v4");
    }
    if state.ipv6_masquerade {
        append_nft_masquerade_rule(&mut batch, state, "ip6", &state.client_ipv6, "v6");
    }
    batch
}

fn append_nft_forward_rules(
    batch: &mut String,
    state: &VpnServerForwardingState,
    protocol: &str,
    addresses: &[String],
    family_suffix: &str,
) {
    let addresses = nft_address_set(addresses);
    append_nft_line(
        batch,
        &format!(
            "add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} forward iifname \"{}\" oifname != \"{}\" {protocol} saddr {addresses} ct state {{ new, established, related }} accept comment \"{}\"",
            state.tun_name,
            state.tun_name,
            state.object_comment(&format!("rule:forward-{family_suffix}-out"))
        ),
    );
    append_nft_line(
        batch,
        &format!(
            "add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} forward iifname != \"{}\" oifname \"{}\" {protocol} daddr {addresses} ct state {{ established, related }} accept comment \"{}\"",
            state.tun_name,
            state.tun_name,
            state.object_comment(&format!("rule:forward-{family_suffix}-in"))
        ),
    );
}

fn append_nft_masquerade_rule(
    batch: &mut String,
    state: &VpnServerForwardingState,
    protocol: &str,
    addresses: &[String],
    family_suffix: &str,
) {
    append_nft_line(
        batch,
        &format!(
            "add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} postrouting {protocol} saddr {} masquerade comment \"{}\"",
            nft_address_set(addresses),
            state.object_comment(&format!("rule:masquerade-{family_suffix}"))
        ),
    );
}

fn append_nft_line(batch: &mut String, line: &str) {
    batch.push_str(line);
    batch.push('\n');
}

fn nft_address_set(addresses: &[String]) -> String {
    format!("{{ {} }}", addresses.join(", "))
}

fn rollback_server_forwarding(
    nft: &NftCommand,
    state: &VpnServerForwardingState,
) -> Result<(), VpnNetworkError> {
    restore_managed_sysctls(state)?;
    if let Some(snapshot) = inspect_owned_table(nft, state)? {
        if state
            .nft_table_fingerprint
            .as_deref()
            .is_some_and(|expected| expected != snapshot.fingerprint)
        {
            return Err(VpnNetworkError::ServerForwardingStateDrift);
        }
        nft.delete_table()?;
    }
    if nft.table_exists()? {
        return Err(VpnNetworkError::ServerForwardingStateDrift);
    }
    Ok(())
}

fn capture_sysctl_originals(
    plan: &VpnServerForwardingPlan,
) -> Result<SysctlOriginals, VpnNetworkError> {
    let required_ipv4 = !plan.client_ipv4.is_empty();
    let required_ipv6 = !plan.client_ipv6.is_empty();
    if !plan.manage_sysctls {
        require_forwarding_enabled(required_ipv4, required_ipv6)?;
        return Ok(SysctlOriginals {
            ipv4: None,
            ipv6: None,
        });
    }
    Ok(SysctlOriginals {
        ipv4: required_ipv4.then(read_ipv4_forwarding).transpose()?,
        ipv6: required_ipv6.then(read_ipv6_forwarding).transpose()?,
    })
}

fn require_forwarding_enabled(
    required_ipv4: bool,
    required_ipv6: bool,
) -> Result<(), VpnNetworkError> {
    if required_ipv4 && read_ipv4_forwarding()? != 1 {
        return Err(VpnNetworkError::Ipv4ForwardingDisabled);
    }
    if required_ipv6 && read_ipv6_forwarding()? != 1 {
        return Err(VpnNetworkError::Ipv6ForwardingDisabled);
    }
    Ok(())
}

fn validate_active_sysctls(state: &VpnServerForwardingState) -> Result<(), VpnNetworkError> {
    if state.required_ipv4() && read_ipv4_forwarding()? != 1
        || state.required_ipv6() && read_ipv6_forwarding()? != 1
    {
        return Err(VpnNetworkError::ServerForwardingStateDrift);
    }
    Ok(())
}

fn enable_managed_sysctls(state: &VpnServerForwardingState) -> Result<(), VpnNetworkError> {
    if state.original_ipv4_forwarding == Some(0) {
        write_ipv4_forwarding(1)?;
    }
    if state.original_ipv6_forwarding == Some(0) {
        write_ipv6_forwarding(1)?;
    }
    validate_active_sysctls(state)
}

fn restore_managed_sysctls(state: &VpnServerForwardingState) -> Result<(), VpnNetworkError> {
    if !state.manage_sysctls {
        return Ok(());
    }
    if let Some(original) = state.original_ipv4_forwarding {
        restore_sysctl(original, read_ipv4_forwarding, write_ipv4_forwarding)?;
    }
    if let Some(original) = state.original_ipv6_forwarding {
        restore_sysctl(original, read_ipv6_forwarding, write_ipv6_forwarding)?;
    }
    Ok(())
}

fn restore_sysctl(
    original: u8,
    read: fn() -> Result<u8, VpnNetworkError>,
    write: fn(u8) -> Result<(), VpnNetworkError>,
) -> Result<(), VpnNetworkError> {
    let current = read()?;
    if current == original {
        return Ok(());
    }
    if original == 0 && current == 1 {
        write(0)?;
        return Ok(());
    }
    Err(VpnNetworkError::ServerForwardingStateDrift)
}

fn read_ipv4_forwarding() -> Result<u8, VpnNetworkError> {
    read_sysctl(IPV4_FORWARDING_PATH, VpnNetworkIoStage::Ipv4ForwardingRead)
}

fn read_ipv6_forwarding() -> Result<u8, VpnNetworkError> {
    read_sysctl(IPV6_FORWARDING_PATH, VpnNetworkIoStage::Ipv6ForwardingRead)
}

fn write_ipv4_forwarding(value: u8) -> Result<(), VpnNetworkError> {
    write_sysctl(
        IPV4_FORWARDING_PATH,
        VpnNetworkIoStage::Ipv4ForwardingWrite,
        read_ipv4_forwarding,
        value,
    )
}

fn write_ipv6_forwarding(value: u8) -> Result<(), VpnNetworkError> {
    write_sysctl(
        IPV6_FORWARDING_PATH,
        VpnNetworkIoStage::Ipv6ForwardingWrite,
        read_ipv6_forwarding,
        value,
    )
}

fn read_sysctl(path: &str, stage: VpnNetworkIoStage) -> Result<u8, VpnNetworkError> {
    let value = fs::read_to_string(path).map_err(|error| io_error(stage, error))?;
    match value.trim() {
        "0" => Ok(0),
        "1" => Ok(1),
        _ => Err(VpnNetworkError::ServerForwardingStateDrift),
    }
}

fn write_sysctl(
    path: &str,
    stage: VpnNetworkIoStage,
    read: fn() -> Result<u8, VpnNetworkError>,
    value: u8,
) -> Result<(), VpnNetworkError> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| io_error(stage, error))?;
    writeln!(file, "{value}").map_err(|error| io_error(stage, error))?;
    if read()? != value {
        return Err(VpnNetworkError::ServerForwardingStateDrift);
    }
    Ok(())
}

fn validate_canonical_ipv4(addresses: &[String]) -> Result<(), VpnNetworkError> {
    let parsed = addresses
        .iter()
        .map(|address| {
            address
                .parse::<Ipv4Addr>()
                .map_err(|_| VpnNetworkError::ServerForwardingStateInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut canonical = parsed;
    canonical.sort_unstable();
    canonical.dedup();
    if canonical
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        != addresses
    {
        return Err(VpnNetworkError::ServerForwardingStateInvalid);
    }
    Ok(())
}

fn validate_canonical_ipv6(addresses: &[String]) -> Result<(), VpnNetworkError> {
    let parsed = addresses
        .iter()
        .map(|address| {
            address
                .parse::<Ipv6Addr>()
                .map_err(|_| VpnNetworkError::ServerForwardingStateInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut canonical = parsed;
    canonical.sort_unstable();
    canonical.dedup();
    if canonical
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        != addresses
    {
        return Err(VpnNetworkError::ServerForwardingStateInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn test_plan() -> VpnServerForwardingPlan {
        let mut plan = VpnServerForwardingPlan {
            network_plan_fingerprint: "11".repeat(PLAN_FINGERPRINT_BYTES),
            tun_name: "fwvpn0".to_owned(),
            interface_index: 7,
            manage_sysctls: true,
            ipv4_masquerade: true,
            ipv6_masquerade: false,
            client_ipv4: vec!["10.77.0.2".to_owned()],
            client_ipv6: vec!["fd77::2".to_owned()],
            fingerprint: String::new(),
        };
        plan.fingerprint = plan.compute_fingerprint().unwrap();
        plan
    }

    #[test]
    fn forwarding_state_fingerprint_covers_ownership_and_sysctls() {
        let state = VpnServerForwardingState::new_activating(
            &test_plan(),
            SysctlOriginals {
                ipv4: Some(0),
                ipv6: Some(1),
            },
        )
        .unwrap();
        state.validate_shape().unwrap();
        let mut changed = state.clone();
        changed.original_ipv4_forwarding = Some(1);
        assert_eq!(
            changed.validate_shape().unwrap_err(),
            VpnNetworkError::ServerForwardingStateInvalid
        );
    }

    #[test]
    fn nft_normalization_removes_only_volatile_metadata() {
        let value = json!({
            "nftables": [
                {"metainfo": {"version": "1.0"}},
                {"table": {
                    "family": "inet",
                    "name": "flowweave_vpn",
                    "handle": 9,
                    "comment": "owned"
                }}
            ]
        });
        let normalized = normalize_nft_json(value).unwrap();
        assert_eq!(
            normalized,
            json!({"nftables": [{"table": {
                "family": "inet",
                "name": "flowweave_vpn",
                "comment": "owned"
            }}]})
        );
    }

    #[test]
    fn inline_address_operand_accepts_nft_singleton_optimization() {
        assert_eq!(
            address_operand(&["10.77.0.2".to_owned()]),
            Value::String("10.77.0.2".to_owned())
        );
        assert_eq!(
            address_operand(&["10.77.0.2".to_owned(), "10.77.0.3".to_owned()]),
            json!({"set": ["10.77.0.2", "10.77.0.3"]})
        );
    }

    #[test]
    fn masquerade_requires_an_enabled_identity_in_that_family() {
        let config = parse_vpn_server_product_config_json(
            br#"{
                "config_version": 1,
                "listen": "0.0.0.0:4433",
                "certificate_der": "server.cert.der",
                "private_key_der": "server.key.der",
                "client_ca_der": "client-ca.cert.der",
                "identity_file": "identities.json",
                "tun_name": "fwvpn0",
                "tun_mtu": 1500,
                "max_datagram_len": 1200,
                "global_reassembly_bytes": 67108864,
                "global_inflight_packets": 8192,
                "forwarding": {
                    "manage_sysctls": false,
                    "ipv4_masquerade": false,
                    "ipv6_masquerade": true
                }
            }"#,
            Path::new("/etc/flowweave"),
        )
        .unwrap();
        let registry = parse_vpn_identity_registry_json(
            br#"{
                "config_version": 1,
                "server_ipv4": "10.77.0.1",
                "server_ipv6": null,
                "identities": [{
                    "client_id": "disabled-v4",
                    "fingerprints": [
                        "1111111111111111111111111111111111111111111111111111111111111111"
                    ],
                    "enabled": false,
                    "client_ipv4": "10.77.0.2",
                    "client_ipv6": null,
                    "allowed_destinations": ["0.0.0.0/0"],
                    "limits": {
                        "max_connections": 1,
                        "max_packets_per_second": 100000,
                        "max_bytes_per_second": 134217728,
                        "max_reassembly_bytes": 8388608
                    }
                }]
            }"#,
        )
        .unwrap();
        let network_state = VpnNetworkState {
            state_version: super::super::VPN_NETWORK_STATE_VERSION,
            phase: VpnNetworkStatePhase::Prepared,
            plan_fingerprint: "11".repeat(PLAN_FINGERPRINT_BYTES),
            role: VpnNetworkRole::Server,
            tun_name: "fwvpn0".to_owned(),
            temporary_tun_name: "fwv001122334455".to_owned(),
            ownership_token: "00".repeat(OWNERSHIP_TOKEN_BYTES),
            interface_index: Some(7),
            tun_mtu: 1500,
            owner_uid: 1000,
            owner_gid: 1000,
            addresses: vec!["10.77.0.1/32".to_owned()],
            routes: vec!["10.77.0.2/32".to_owned()],
        };
        assert!(matches!(
            VpnServerForwardingPlan::new(&network_state, config.forwarding().unwrap(), &registry,),
            Err(VpnNetworkError::ServerForwardingFamilyUnavailable)
        ));
    }
}

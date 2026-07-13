use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{Arc, RwLock},
};

use serde::Deserialize;

use crate::{
    VpnCertificateFingerprint, VpnIdentity, VpnIdentityError, VpnIdentityLimits,
    VpnIdentityRegistry, VpnIpNetwork,
};

pub const VPN_IDENTITY_CONFIG_VERSION: u16 = 1;
pub const VPN_IDENTITY_CONFIG_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnIdentityConfigError {
    Io(io::ErrorKind),
    NotRegularFile,
    UnsafePermissions,
    FileTooLarge,
    InvalidJson { line: usize, column: usize },
    UnsupportedConfigVersion,
    InvalidIpv4Address,
    InvalidIpv6Address,
    InvalidDestinationNetwork,
    Registry(VpnIdentityError),
    RegistryLockPoisoned,
}

impl fmt::Display for VpnIdentityConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(formatter, "vpn_identity_config_io:{kind:?}"),
            Self::InvalidJson { line, column } => {
                write!(
                    formatter,
                    "vpn_identity_config_invalid_json:{line}:{column}"
                )
            }
            Self::Registry(error) => write!(formatter, "vpn_identity_config_registry:{error}"),
            other => formatter.write_str(match other {
                Self::NotRegularFile => "vpn_identity_config_not_regular_file",
                Self::UnsafePermissions => "vpn_identity_config_unsafe_permissions",
                Self::FileTooLarge => "vpn_identity_config_file_too_large",
                Self::UnsupportedConfigVersion => "vpn_identity_config_unsupported_config_version",
                Self::InvalidIpv4Address => "vpn_identity_config_invalid_ipv4_address",
                Self::InvalidIpv6Address => "vpn_identity_config_invalid_ipv6_address",
                Self::InvalidDestinationNetwork => {
                    "vpn_identity_config_invalid_destination_network"
                }
                Self::RegistryLockPoisoned => "vpn_identity_config_registry_lock_poisoned",
                Self::Io(_) | Self::InvalidJson { .. } | Self::Registry(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnIdentityConfigError {}

impl From<VpnIdentityError> for VpnIdentityConfigError {
    fn from(value: VpnIdentityError) -> Self {
        Self::Registry(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnIdentityReloadReport {
    pub previous_identity_count: usize,
    pub identity_count: usize,
    pub previous_fingerprint_count: usize,
    pub fingerprint_count: usize,
}

#[derive(Clone)]
pub struct SharedVpnIdentityRegistry {
    inner: Arc<RwLock<Arc<VpnIdentityRegistry>>>,
}

impl SharedVpnIdentityRegistry {
    pub fn new(registry: VpnIdentityRegistry) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(registry))),
        }
    }

    pub fn snapshot(&self) -> Result<Arc<VpnIdentityRegistry>, VpnIdentityConfigError> {
        self.inner
            .read()
            .map(|registry| registry.clone())
            .map_err(|_| VpnIdentityConfigError::RegistryLockPoisoned)
    }

    pub fn replace(
        &self,
        registry: VpnIdentityRegistry,
    ) -> Result<VpnIdentityReloadReport, VpnIdentityConfigError> {
        let mut current = self
            .inner
            .write()
            .map_err(|_| VpnIdentityConfigError::RegistryLockPoisoned)?;
        let report = VpnIdentityReloadReport {
            previous_identity_count: current.identities().len(),
            identity_count: registry.identities().len(),
            previous_fingerprint_count: current.fingerprint_count(),
            fingerprint_count: registry.fingerprint_count(),
        };
        *current = Arc::new(registry);
        Ok(report)
    }

    pub fn reload_from_path(
        &self,
        path: &Path,
    ) -> Result<VpnIdentityReloadReport, VpnIdentityConfigError> {
        let candidate = load_vpn_identity_registry(path)?;
        self.replace(candidate)
    }
}

impl fmt::Debug for SharedVpnIdentityRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedVpnIdentityRegistry")
            .finish_non_exhaustive()
    }
}

pub fn load_vpn_identity_registry(
    path: &Path,
) -> Result<VpnIdentityRegistry, VpnIdentityConfigError> {
    let file = File::open(path).map_err(|error| VpnIdentityConfigError::Io(error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| VpnIdentityConfigError::Io(error.kind()))?;
    if !metadata.is_file() {
        return Err(VpnIdentityConfigError::NotRegularFile);
    }
    enforce_private_permissions(&metadata)?;
    if metadata.len() > VPN_IDENTITY_CONFIG_MAX_BYTES as u64 {
        return Err(VpnIdentityConfigError::FileTooLarge);
    }

    let mut limited = file.take((VPN_IDENTITY_CONFIG_MAX_BYTES + 1) as u64);
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(VPN_IDENTITY_CONFIG_MAX_BYTES)
            .min(VPN_IDENTITY_CONFIG_MAX_BYTES),
    );
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| VpnIdentityConfigError::Io(error.kind()))?;
    if bytes.len() > VPN_IDENTITY_CONFIG_MAX_BYTES {
        return Err(VpnIdentityConfigError::FileTooLarge);
    }
    parse_vpn_identity_registry_json(&bytes)
}

#[cfg(unix)]
fn enforce_private_permissions(metadata: &fs::Metadata) -> Result<(), VpnIdentityConfigError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(VpnIdentityConfigError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_permissions(_metadata: &fs::Metadata) -> Result<(), VpnIdentityConfigError> {
    Ok(())
}

pub fn parse_vpn_identity_registry_json(
    bytes: &[u8],
) -> Result<VpnIdentityRegistry, VpnIdentityConfigError> {
    let raw: RawRegistry =
        serde_json::from_slice(bytes).map_err(|error| VpnIdentityConfigError::InvalidJson {
            line: error.line(),
            column: error.column(),
        })?;
    if raw.config_version != VPN_IDENTITY_CONFIG_VERSION {
        return Err(VpnIdentityConfigError::UnsupportedConfigVersion);
    }

    let server_ipv4 = raw
        .server_ipv4
        .map(|value| {
            value
                .parse::<Ipv4Addr>()
                .map_err(|_| VpnIdentityConfigError::InvalidIpv4Address)
        })
        .transpose()?;
    let server_ipv6 = raw
        .server_ipv6
        .map(|value| {
            value
                .parse::<Ipv6Addr>()
                .map_err(|_| VpnIdentityConfigError::InvalidIpv6Address)
        })
        .transpose()?;
    let identities = raw
        .identities
        .into_iter()
        .map(parse_identity)
        .collect::<Result<Vec<_>, _>>()?;
    VpnIdentityRegistry::new(server_ipv4, server_ipv6, identities).map_err(Into::into)
}

fn parse_identity(raw: RawIdentity) -> Result<VpnIdentity, VpnIdentityConfigError> {
    let fingerprints = raw
        .fingerprints
        .into_iter()
        .map(|value| VpnCertificateFingerprint::parse_hex(&value).map_err(Into::into))
        .collect::<Result<Vec<_>, VpnIdentityConfigError>>()?;
    let client_ipv4 = raw
        .client_ipv4
        .map(|value| {
            value
                .parse::<Ipv4Addr>()
                .map_err(|_| VpnIdentityConfigError::InvalidIpv4Address)
        })
        .transpose()?;
    let client_ipv6 = raw
        .client_ipv6
        .map(|value| {
            value
                .parse::<Ipv6Addr>()
                .map_err(|_| VpnIdentityConfigError::InvalidIpv6Address)
        })
        .transpose()?;
    let allowed_destinations = raw
        .allowed_destinations
        .into_iter()
        .map(|value| parse_network(&value))
        .collect::<Result<Vec<_>, _>>()?;
    let limits = VpnIdentityLimits::new(
        raw.limits.max_connections,
        raw.limits.max_packets_per_second,
        raw.limits.max_bytes_per_second,
        raw.limits.max_reassembly_bytes,
    )?;
    VpnIdentity::new(
        raw.client_id,
        fingerprints,
        raw.enabled,
        client_ipv4,
        client_ipv6,
        allowed_destinations,
        limits,
    )
    .map_err(Into::into)
}

fn parse_network(value: &str) -> Result<VpnIpNetwork, VpnIdentityConfigError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or(VpnIdentityConfigError::InvalidDestinationNetwork)?;
    if prefix.contains('/') {
        return Err(VpnIdentityConfigError::InvalidDestinationNetwork);
    }
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| VpnIdentityConfigError::InvalidDestinationNetwork)?;
    if let Ok(address) = address.parse::<Ipv4Addr>() {
        return VpnIpNetwork::v4(address, prefix).map_err(Into::into);
    }
    if let Ok(address) = address.parse::<Ipv6Addr>() {
        return VpnIpNetwork::v6(address, prefix).map_err(Into::into);
    }
    Err(VpnIdentityConfigError::InvalidDestinationNetwork)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry {
    config_version: u16,
    server_ipv4: Option<String>,
    server_ipv6: Option<String>,
    identities: Vec<RawIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    client_id: String,
    fingerprints: Vec<String>,
    enabled: bool,
    client_ipv4: Option<String>,
    client_ipv6: Option<String>,
    allowed_destinations: Vec<String>,
    limits: RawLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_connections: u16,
    max_packets_per_second: u32,
    max_bytes_per_second: u64,
    max_reassembly_bytes: usize,
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::{Value, json};

    use crate::VpnIdentityAuthorizationError;

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn strict_json_builds_auditable_registry_and_limits() {
        let fingerprint = fingerprint_hex(0x11);
        let registry = parse_vpn_identity_registry_json(
            serde_json::to_string(&valid_config(&fingerprint, true))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let identity = registry
            .authorize(VpnCertificateFingerprint::parse_hex(&fingerprint).unwrap())
            .unwrap();
        assert_eq!(identity.client_id(), "client-a");
        assert_eq!(identity.limits().max_connections(), 1);
        assert_eq!(identity.limits().max_packets_per_second(), 50_000);
        assert_eq!(identity.limits().max_bytes_per_second(), 64 * 1024 * 1024);
        assert_eq!(identity.limits().max_reassembly_bytes(), 4 * 1024 * 1024);
        assert!(identity.allows_destination("198.51.100.7".parse().unwrap()));
        assert!(identity.allows_destination("fd00::7".parse().unwrap()));
    }

    #[test]
    fn deployment_identity_example_follows_the_strict_schema() {
        let registry = parse_vpn_identity_registry_json(include_bytes!(
            "../deploy/vpn-identities.json.example"
        ))
        .unwrap();
        assert_eq!(registry.identities().len(), 1);
        assert_eq!(registry.fingerprint_count(), 1);
    }

    #[test]
    fn unknown_duplicate_missing_and_version_fields_are_rejected() {
        let fingerprint = fingerprint_hex(0x11);
        let mut unknown = valid_config(&fingerprint, true);
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        assert!(matches!(
            parse_vpn_identity_registry_json(serde_json::to_string(&unknown).unwrap().as_bytes()),
            Err(VpnIdentityConfigError::InvalidJson { .. })
        ));

        let duplicate = br#"{
            "config_version":1,
            "config_version":1,
            "server_ipv4":"10.77.0.1",
            "server_ipv6":"fd77::1",
            "identities":[]
        }"#;
        assert!(matches!(
            parse_vpn_identity_registry_json(duplicate),
            Err(VpnIdentityConfigError::InvalidJson { .. })
        ));

        let mut unsupported = valid_config(&fingerprint, true);
        unsupported["config_version"] = Value::from(2);
        assert_eq!(
            parse_vpn_identity_registry_json(
                serde_json::to_string(&unsupported).unwrap().as_bytes()
            )
            .unwrap_err(),
            VpnIdentityConfigError::UnsupportedConfigVersion
        );

        let mut missing_limit = valid_config(&fingerprint, true);
        missing_limit["identities"][0]["limits"]
            .as_object_mut()
            .unwrap()
            .remove("max_connections");
        assert!(matches!(
            parse_vpn_identity_registry_json(
                serde_json::to_string(&missing_limit).unwrap().as_bytes()
            ),
            Err(VpnIdentityConfigError::InvalidJson { .. })
        ));
    }

    #[test]
    fn invalid_fingerprints_networks_and_address_families_fail_closed() {
        let mut invalid_fingerprint = valid_config("short", true);
        assert_eq!(
            parse_vpn_identity_registry_json(
                serde_json::to_string(&invalid_fingerprint)
                    .unwrap()
                    .as_bytes()
            )
            .unwrap_err(),
            VpnIdentityConfigError::Registry(VpnIdentityError::InvalidFingerprintHex)
        );

        invalid_fingerprint["identities"][0]["fingerprints"] = json!([fingerprint_hex(0x11)]);
        invalid_fingerprint["identities"][0]["allowed_destinations"] = json!(["10.0.0.1/8"]);
        assert_eq!(
            parse_vpn_identity_registry_json(
                serde_json::to_string(&invalid_fingerprint)
                    .unwrap()
                    .as_bytes()
            )
            .unwrap_err(),
            VpnIdentityConfigError::Registry(VpnIdentityError::NonCanonicalNetwork)
        );

        invalid_fingerprint["identities"][0]["allowed_destinations"] = json!(["0.0.0.0/0"]);
        invalid_fingerprint["server_ipv4"] = Value::Null;
        assert_eq!(
            parse_vpn_identity_registry_json(
                serde_json::to_string(&invalid_fingerprint)
                    .unwrap()
                    .as_bytes()
            )
            .unwrap_err(),
            VpnIdentityConfigError::Registry(VpnIdentityError::AddressFamilyUnavailable)
        );
    }

    #[test]
    fn failed_reload_preserves_old_registry_and_success_atomically_revokes_old() {
        let directory = TestDirectory::new();
        let path = directory.path().join("identities.json");
        let old = fingerprint_hex(0x11);
        let new = fingerprint_hex(0x22);
        write_private(
            &path,
            serde_json::to_string(&valid_config(&old, true))
                .unwrap()
                .as_bytes(),
        );
        let shared = SharedVpnIdentityRegistry::new(load_vpn_identity_registry(&path).unwrap());

        write_private(&path, b"{not-json");
        assert!(matches!(
            shared.reload_from_path(&path),
            Err(VpnIdentityConfigError::InvalidJson { .. })
        ));
        assert!(
            shared
                .snapshot()
                .unwrap()
                .authorize(VpnCertificateFingerprint::parse_hex(&old).unwrap())
                .is_ok()
        );

        write_private(
            &path,
            serde_json::to_string(&valid_config(&new, true))
                .unwrap()
                .as_bytes(),
        );
        let report = shared.reload_from_path(&path).unwrap();
        assert_eq!(
            report,
            VpnIdentityReloadReport {
                previous_identity_count: 1,
                identity_count: 1,
                previous_fingerprint_count: 1,
                fingerprint_count: 1,
            }
        );
        let snapshot = shared.snapshot().unwrap();
        assert_eq!(
            snapshot
                .authorize(VpnCertificateFingerprint::parse_hex(&old).unwrap())
                .unwrap_err(),
            VpnIdentityAuthorizationError::UnknownFingerprint
        );
        assert!(
            snapshot
                .authorize(VpnCertificateFingerprint::parse_hex(&new).unwrap())
                .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_rejects_group_or_other_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let path = directory.path().join("identities.json");
        write_private(
            &path,
            serde_json::to_string(&valid_config(&fingerprint_hex(0x11), true))
                .unwrap()
                .as_bytes(),
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_vpn_identity_registry(&path).unwrap_err(),
            VpnIdentityConfigError::UnsafePermissions
        );
    }

    fn valid_config(fingerprint: &str, enabled: bool) -> Value {
        json!({
            "config_version": VPN_IDENTITY_CONFIG_VERSION,
            "server_ipv4": "10.77.0.1",
            "server_ipv6": "fd77::1",
            "identities": [{
                "client_id": "client-a",
                "fingerprints": [fingerprint],
                "enabled": enabled,
                "client_ipv4": "10.77.0.2",
                "client_ipv6": "fd77::2",
                "allowed_destinations": ["0.0.0.0/0", "::/0"],
                "limits": {
                    "max_connections": 1,
                    "max_packets_per_second": 50_000,
                    "max_bytes_per_second": 64 * 1024 * 1024,
                    "max_reassembly_bytes": 4 * 1024 * 1024
                }
            }]
        })
    }

    fn fingerprint_hex(byte: u8) -> String {
        VpnCertificateFingerprint::from_sha256([byte; 32]).to_hex()
    }

    fn write_private(path: &Path, contents: &[u8]) {
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

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "flowweave-vpn-identity-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

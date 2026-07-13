use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{
    vpn::{VPN_DEFAULT_MAX_REASSEMBLY_BYTES, VPN_MAX_IP_PACKET_LEN},
    vpn_control::{valid_ipv4_tunnel_address, valid_ipv6_tunnel_address},
};

pub const VPN_SHA256_FINGERPRINT_LEN: usize = 32;
pub const VPN_MAX_IDENTITIES: usize = 4096;
pub const VPN_MAX_CLIENT_ID_LEN: usize = 64;
pub const VPN_MAX_FINGERPRINTS_PER_IDENTITY: usize = 2;
pub const VPN_MAX_DESTINATION_NETWORKS_PER_IDENTITY: usize = 256;
pub const VPN_MAX_CONNECTIONS_PER_IDENTITY: u16 = 1;
pub const VPN_MAX_PACKETS_PER_SECOND: u32 = 1_000_000;
pub const VPN_MAX_BYTES_PER_SECOND: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnIdentityError {
    InvalidFingerprintHex,
    InvalidClientId,
    MissingFingerprint,
    TooManyFingerprints,
    TooManyIdentities,
    TooManyDestinationNetworks,
    MissingClientAddress,
    InvalidClientAddress,
    MissingServerAddress,
    InvalidServerAddress,
    AddressFamilyUnavailable,
    ClientServerAddressConflict,
    DuplicateClientId,
    DuplicateFingerprint,
    DuplicateClientAddress,
    DuplicateDestinationNetwork,
    InvalidLimits,
    InvalidNetworkPrefix,
    NonCanonicalNetwork,
}

impl fmt::Display for VpnIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFingerprintHex => "vpn_identity_invalid_fingerprint_hex",
            Self::InvalidClientId => "vpn_identity_invalid_client_id",
            Self::MissingFingerprint => "vpn_identity_missing_fingerprint",
            Self::TooManyFingerprints => "vpn_identity_too_many_fingerprints",
            Self::TooManyIdentities => "vpn_identity_too_many_identities",
            Self::TooManyDestinationNetworks => "vpn_identity_too_many_destination_networks",
            Self::MissingClientAddress => "vpn_identity_missing_client_address",
            Self::InvalidClientAddress => "vpn_identity_invalid_client_address",
            Self::MissingServerAddress => "vpn_identity_missing_server_address",
            Self::InvalidServerAddress => "vpn_identity_invalid_server_address",
            Self::AddressFamilyUnavailable => "vpn_identity_address_family_unavailable",
            Self::ClientServerAddressConflict => "vpn_identity_client_server_address_conflict",
            Self::DuplicateClientId => "vpn_identity_duplicate_client_id",
            Self::DuplicateFingerprint => "vpn_identity_duplicate_fingerprint",
            Self::DuplicateClientAddress => "vpn_identity_duplicate_client_address",
            Self::DuplicateDestinationNetwork => "vpn_identity_duplicate_destination_network",
            Self::InvalidLimits => "vpn_identity_invalid_limits",
            Self::InvalidNetworkPrefix => "vpn_identity_invalid_network_prefix",
            Self::NonCanonicalNetwork => "vpn_identity_non_canonical_network",
        })
    }
}

impl Error for VpnIdentityError {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VpnCertificateFingerprint([u8; VPN_SHA256_FINGERPRINT_LEN]);

impl VpnCertificateFingerprint {
    pub const fn from_sha256(bytes: [u8; VPN_SHA256_FINGERPRINT_LEN]) -> Self {
        Self(bytes)
    }

    pub fn parse_hex(value: &str) -> Result<Self, VpnIdentityError> {
        if value.len() != VPN_SHA256_FINGERPRINT_LEN * 2 || !value.is_ascii() {
            return Err(VpnIdentityError::InvalidFingerprintHex);
        }
        let mut bytes = [0_u8; VPN_SHA256_FINGERPRINT_LEN];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            let high = decode_hex(value.as_bytes()[offset])?;
            let low = decode_hex(value.as_bytes()[offset + 1])?;
            *output = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; VPN_SHA256_FINGERPRINT_LEN] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(VPN_SHA256_FINGERPRINT_LEN * 2);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

impl fmt::Debug for VpnCertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VpnCertificateFingerprint([redacted])")
    }
}

fn decode_hex(value: u8) -> Result<u8, VpnIdentityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(VpnIdentityError::InvalidFingerprintHex),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VpnIpNetwork {
    V4 { network: Ipv4Addr, prefix_len: u8 },
    V6 { network: Ipv6Addr, prefix_len: u8 },
}

impl VpnIpNetwork {
    pub fn v4(network: Ipv4Addr, prefix_len: u8) -> Result<Self, VpnIdentityError> {
        if prefix_len > 32 {
            return Err(VpnIdentityError::InvalidNetworkPrefix);
        }
        let mask = prefix_mask_v4(prefix_len);
        if u32::from(network) & mask != u32::from(network) {
            return Err(VpnIdentityError::NonCanonicalNetwork);
        }
        Ok(Self::V4 {
            network,
            prefix_len,
        })
    }

    pub fn v6(network: Ipv6Addr, prefix_len: u8) -> Result<Self, VpnIdentityError> {
        if prefix_len > 128 {
            return Err(VpnIdentityError::InvalidNetworkPrefix);
        }
        let mask = prefix_mask_v6(prefix_len);
        if u128::from(network) & mask != u128::from(network) {
            return Err(VpnIdentityError::NonCanonicalNetwork);
        }
        Ok(Self::V6 {
            network,
            prefix_len,
        })
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (
                Self::V4 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(address),
            ) => {
                let mask = prefix_mask_v4(prefix_len);
                u32::from(address) & mask == u32::from(network)
            }
            (
                Self::V6 {
                    network,
                    prefix_len,
                },
                IpAddr::V6(address),
            ) => {
                let mask = prefix_mask_v6(prefix_len);
                u128::from(address) & mask == u128::from(network)
            }
            _ => false,
        }
    }
}

fn prefix_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn prefix_mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnIdentityLimits {
    max_connections: u16,
    max_packets_per_second: u32,
    max_bytes_per_second: u64,
    max_reassembly_bytes: usize,
}

impl VpnIdentityLimits {
    pub fn new(
        max_connections: u16,
        max_packets_per_second: u32,
        max_bytes_per_second: u64,
        max_reassembly_bytes: usize,
    ) -> Result<Self, VpnIdentityError> {
        let limits = Self {
            max_connections,
            max_packets_per_second,
            max_bytes_per_second,
            max_reassembly_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub const fn max_connections(self) -> u16 {
        self.max_connections
    }

    pub const fn max_packets_per_second(self) -> u32 {
        self.max_packets_per_second
    }

    pub const fn max_bytes_per_second(self) -> u64 {
        self.max_bytes_per_second
    }

    pub const fn max_reassembly_bytes(self) -> usize {
        self.max_reassembly_bytes
    }

    fn validate(self) -> Result<(), VpnIdentityError> {
        if self.max_connections == 0
            || self.max_connections > VPN_MAX_CONNECTIONS_PER_IDENTITY
            || self.max_packets_per_second == 0
            || self.max_packets_per_second > VPN_MAX_PACKETS_PER_SECOND
            || self.max_bytes_per_second == 0
            || self.max_bytes_per_second > VPN_MAX_BYTES_PER_SECOND
            || self.max_reassembly_bytes < VPN_MAX_IP_PACKET_LEN
            || self.max_reassembly_bytes > VPN_DEFAULT_MAX_REASSEMBLY_BYTES
        {
            return Err(VpnIdentityError::InvalidLimits);
        }
        Ok(())
    }
}

impl Default for VpnIdentityLimits {
    fn default() -> Self {
        Self {
            max_connections: 1,
            max_packets_per_second: 100_000,
            max_bytes_per_second: 128 * 1024 * 1024,
            max_reassembly_bytes: VPN_DEFAULT_MAX_REASSEMBLY_BYTES,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VpnIdentity {
    client_id: String,
    fingerprints: Vec<VpnCertificateFingerprint>,
    enabled: bool,
    client_ipv4: Option<Ipv4Addr>,
    client_ipv6: Option<Ipv6Addr>,
    allowed_destinations: Vec<VpnIpNetwork>,
    limits: VpnIdentityLimits,
}

impl VpnIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: impl Into<String>,
        fingerprints: Vec<VpnCertificateFingerprint>,
        enabled: bool,
        client_ipv4: Option<Ipv4Addr>,
        client_ipv6: Option<Ipv6Addr>,
        allowed_destinations: Vec<VpnIpNetwork>,
        limits: VpnIdentityLimits,
    ) -> Result<Self, VpnIdentityError> {
        let identity = Self {
            client_id: client_id.into(),
            fingerprints,
            enabled,
            client_ipv4,
            client_ipv6,
            allowed_destinations,
            limits,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn fingerprints(&self) -> &[VpnCertificateFingerprint] {
        &self.fingerprints
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn client_ipv4(&self) -> Option<Ipv4Addr> {
        self.client_ipv4
    }

    pub const fn client_ipv6(&self) -> Option<Ipv6Addr> {
        self.client_ipv6
    }

    pub fn allowed_destinations(&self) -> &[VpnIpNetwork] {
        &self.allowed_destinations
    }

    pub const fn limits(&self) -> VpnIdentityLimits {
        self.limits
    }

    pub fn permits_source(&self, source: IpAddr) -> bool {
        match source {
            IpAddr::V4(source) => self.client_ipv4 == Some(source),
            IpAddr::V6(source) => self.client_ipv6 == Some(source),
        }
    }

    pub fn allows_destination(&self, destination: IpAddr) -> bool {
        self.allowed_destinations
            .iter()
            .any(|network| network.contains(destination))
    }

    pub fn has_same_session_policy(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.enabled == other.enabled
            && self.client_ipv4 == other.client_ipv4
            && self.client_ipv6 == other.client_ipv6
            && self.allowed_destinations == other.allowed_destinations
            && self.limits == other.limits
    }

    fn validate(&self) -> Result<(), VpnIdentityError> {
        if self.client_id.is_empty()
            || self.client_id.len() > VPN_MAX_CLIENT_ID_LEN
            || !self
                .client_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(VpnIdentityError::InvalidClientId);
        }
        if self.fingerprints.is_empty() {
            return Err(VpnIdentityError::MissingFingerprint);
        }
        if self.fingerprints.len() > VPN_MAX_FINGERPRINTS_PER_IDENTITY {
            return Err(VpnIdentityError::TooManyFingerprints);
        }
        let mut fingerprints = HashSet::with_capacity(self.fingerprints.len());
        if !self
            .fingerprints
            .iter()
            .copied()
            .all(|fingerprint| fingerprints.insert(fingerprint))
        {
            return Err(VpnIdentityError::DuplicateFingerprint);
        }
        if self.client_ipv4.is_none() && self.client_ipv6.is_none() {
            return Err(VpnIdentityError::MissingClientAddress);
        }
        if self
            .client_ipv4
            .is_some_and(|address| !valid_ipv4_tunnel_address(address))
            || self
                .client_ipv6
                .is_some_and(|address| !valid_ipv6_tunnel_address(address))
        {
            return Err(VpnIdentityError::InvalidClientAddress);
        }
        if self.allowed_destinations.len() > VPN_MAX_DESTINATION_NETWORKS_PER_IDENTITY {
            return Err(VpnIdentityError::TooManyDestinationNetworks);
        }
        let mut destination_networks = HashSet::with_capacity(self.allowed_destinations.len());
        if !self
            .allowed_destinations
            .iter()
            .copied()
            .all(|network| destination_networks.insert(network))
        {
            return Err(VpnIdentityError::DuplicateDestinationNetwork);
        }
        if self
            .allowed_destinations
            .iter()
            .any(|network| match network {
                VpnIpNetwork::V4 { .. } => self.client_ipv4.is_none(),
                VpnIpNetwork::V6 { .. } => self.client_ipv6.is_none(),
            })
        {
            return Err(VpnIdentityError::AddressFamilyUnavailable);
        }
        self.limits.validate()
    }
}

impl fmt::Debug for VpnIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnIdentity")
            .field("client_id", &"[redacted]")
            .field("fingerprint_count", &self.fingerprints.len())
            .field("enabled", &self.enabled)
            .field("has_ipv4", &self.client_ipv4.is_some())
            .field("has_ipv6", &self.client_ipv6.is_some())
            .field(
                "destination_network_count",
                &self.allowed_destinations.len(),
            )
            .field("limits", &self.limits)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnIdentityAuthorizationError {
    UnknownFingerprint,
    IdentityDisabled,
}

impl fmt::Display for VpnIdentityAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownFingerprint => "vpn_identity_unknown_fingerprint",
            Self::IdentityDisabled => "vpn_identity_disabled",
        })
    }
}

impl Error for VpnIdentityAuthorizationError {}

#[derive(Clone)]
pub struct VpnIdentityRegistry {
    server_ipv4: Option<Ipv4Addr>,
    server_ipv6: Option<Ipv6Addr>,
    identities: Vec<VpnIdentity>,
    identity_by_client_id: HashMap<String, usize>,
    identity_by_fingerprint: HashMap<VpnCertificateFingerprint, usize>,
}

impl VpnIdentityRegistry {
    pub fn new(
        server_ipv4: Option<Ipv4Addr>,
        server_ipv6: Option<Ipv6Addr>,
        identities: Vec<VpnIdentity>,
    ) -> Result<Self, VpnIdentityError> {
        if server_ipv4.is_none() && server_ipv6.is_none() {
            return Err(VpnIdentityError::MissingServerAddress);
        }
        if server_ipv4.is_some_and(|address| !valid_ipv4_tunnel_address(address))
            || server_ipv6.is_some_and(|address| !valid_ipv6_tunnel_address(address))
        {
            return Err(VpnIdentityError::InvalidServerAddress);
        }
        if identities.len() > VPN_MAX_IDENTITIES {
            return Err(VpnIdentityError::TooManyIdentities);
        }

        let mut identity_by_client_id = HashMap::with_capacity(identities.len());
        let mut identity_by_fingerprint = HashMap::new();
        let mut ipv4_addresses = HashSet::new();
        let mut ipv6_addresses = HashSet::new();
        for (index, identity) in identities.iter().enumerate() {
            identity.validate()?;
            if identity.client_ipv4.is_some() && server_ipv4.is_none()
                || identity.client_ipv6.is_some() && server_ipv6.is_none()
            {
                return Err(VpnIdentityError::AddressFamilyUnavailable);
            }
            if identity
                .client_ipv4
                .zip(server_ipv4)
                .is_some_and(|(client, server)| client == server)
                || identity
                    .client_ipv6
                    .zip(server_ipv6)
                    .is_some_and(|(client, server)| client == server)
            {
                return Err(VpnIdentityError::ClientServerAddressConflict);
            }
            if identity_by_client_id
                .insert(identity.client_id.clone(), index)
                .is_some()
            {
                return Err(VpnIdentityError::DuplicateClientId);
            }
            for fingerprint in &identity.fingerprints {
                if identity_by_fingerprint
                    .insert(*fingerprint, index)
                    .is_some()
                {
                    return Err(VpnIdentityError::DuplicateFingerprint);
                }
            }
            if identity
                .client_ipv4
                .is_some_and(|address| !ipv4_addresses.insert(address))
                || identity
                    .client_ipv6
                    .is_some_and(|address| !ipv6_addresses.insert(address))
            {
                return Err(VpnIdentityError::DuplicateClientAddress);
            }
        }

        Ok(Self {
            server_ipv4,
            server_ipv6,
            identities,
            identity_by_client_id,
            identity_by_fingerprint,
        })
    }

    pub const fn server_ipv4(&self) -> Option<Ipv4Addr> {
        self.server_ipv4
    }

    pub const fn server_ipv6(&self) -> Option<Ipv6Addr> {
        self.server_ipv6
    }

    pub fn identities(&self) -> &[VpnIdentity] {
        &self.identities
    }

    pub fn fingerprint_count(&self) -> usize {
        self.identity_by_fingerprint.len()
    }

    pub fn identity_by_client_id(&self, client_id: &str) -> Option<&VpnIdentity> {
        self.identity_by_client_id
            .get(client_id)
            .map(|index| &self.identities[*index])
    }

    pub fn authorize(
        &self,
        fingerprint: VpnCertificateFingerprint,
    ) -> Result<&VpnIdentity, VpnIdentityAuthorizationError> {
        let index = self
            .identity_by_fingerprint
            .get(&fingerprint)
            .ok_or(VpnIdentityAuthorizationError::UnknownFingerprint)?;
        let identity = &self.identities[*index];
        if !identity.enabled {
            return Err(VpnIdentityAuthorizationError::IdentityDisabled);
        }
        Ok(identity)
    }
}

impl fmt::Debug for VpnIdentityRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnIdentityRegistry")
            .field("has_server_ipv4", &self.server_ipv4.is_some())
            .field("has_server_ipv6", &self.server_ipv6.is_some())
            .field("identity_count", &self.identities.len())
            .field("fingerprint_count", &self.identity_by_fingerprint.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hex_is_strict_and_debug_is_redacted() {
        let value = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";
        let fingerprint = VpnCertificateFingerprint::parse_hex(value).unwrap();
        assert_eq!(
            fingerprint.to_hex(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            format!("{fingerprint:?}"),
            "VpnCertificateFingerprint([redacted])"
        );
        assert_eq!(
            VpnCertificateFingerprint::parse_hex("ab").unwrap_err(),
            VpnIdentityError::InvalidFingerprintHex
        );
        assert_eq!(
            VpnCertificateFingerprint::parse_hex(
                "zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .unwrap_err(),
            VpnIdentityError::InvalidFingerprintHex
        );
    }

    #[test]
    fn networks_are_canonical_and_do_not_cross_address_families() {
        let ipv4 = VpnIpNetwork::v4("10.8.0.0".parse().unwrap(), 16).unwrap();
        assert!(ipv4.contains("10.8.9.7".parse().unwrap()));
        assert!(!ipv4.contains("10.9.0.1".parse().unwrap()));
        assert!(!ipv4.contains("fd00::1".parse().unwrap()));
        assert_eq!(
            VpnIpNetwork::v4("10.8.0.1".parse().unwrap(), 24).unwrap_err(),
            VpnIdentityError::NonCanonicalNetwork
        );

        let ipv6 = VpnIpNetwork::v6("fd77::".parse().unwrap(), 64).unwrap();
        assert!(ipv6.contains("fd77::1234".parse().unwrap()));
        assert!(!ipv6.contains("fd78::1".parse().unwrap()));
        assert_eq!(
            VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 129).unwrap_err(),
            VpnIdentityError::InvalidNetworkPrefix
        );
    }

    #[test]
    fn overlapping_fingerprints_authorize_one_identity_and_rotation_revokes_old() {
        let old = fingerprint(1);
        let new = fingerprint(2);
        let initial_registry = registry(vec![identity(
            "client-a",
            vec![old, new],
            true,
            "10.77.0.2",
            "fd77::2",
        )])
        .unwrap();
        assert_eq!(
            initial_registry.authorize(old).unwrap().client_id(),
            "client-a"
        );
        assert_eq!(
            initial_registry.authorize(new).unwrap().client_id(),
            "client-a"
        );
        assert!(
            initial_registry
                .authorize(old)
                .unwrap()
                .permits_source("10.77.0.2".parse().unwrap())
        );
        assert!(
            !initial_registry
                .authorize(old)
                .unwrap()
                .permits_source("10.77.0.3".parse().unwrap())
        );
        assert!(
            initial_registry
                .authorize(old)
                .unwrap()
                .allows_destination("192.0.2.8".parse().unwrap())
        );

        let rotated = registry(vec![identity(
            "client-a",
            vec![new],
            true,
            "10.77.0.2",
            "fd77::2",
        )])
        .unwrap();
        assert_eq!(
            rotated.authorize(old).unwrap_err(),
            VpnIdentityAuthorizationError::UnknownFingerprint
        );
        assert_eq!(rotated.authorize(new).unwrap().client_id(), "client-a");
    }

    #[test]
    fn disabled_identity_is_distinct_from_an_unknown_certificate() {
        let disabled = fingerprint(9);
        let registry = registry(vec![identity(
            "disabled-client",
            vec![disabled],
            false,
            "10.77.0.9",
            "fd77::9",
        )])
        .unwrap();
        assert_eq!(
            registry.authorize(disabled).unwrap_err(),
            VpnIdentityAuthorizationError::IdentityDisabled
        );
        assert_eq!(
            registry.authorize(fingerprint(10)).unwrap_err(),
            VpnIdentityAuthorizationError::UnknownFingerprint
        );
    }

    #[test]
    fn registry_rejects_duplicate_ids_fingerprints_and_addresses() {
        let first = identity(
            "client-a",
            vec![fingerprint(1)],
            true,
            "10.77.0.2",
            "fd77::2",
        );
        let same_id = identity(
            "client-a",
            vec![fingerprint(2)],
            true,
            "10.77.0.3",
            "fd77::3",
        );
        assert_eq!(
            registry(vec![first.clone(), same_id]).unwrap_err(),
            VpnIdentityError::DuplicateClientId
        );

        let same_fingerprint = identity(
            "client-b",
            vec![fingerprint(1)],
            true,
            "10.77.0.3",
            "fd77::3",
        );
        assert_eq!(
            registry(vec![first.clone(), same_fingerprint]).unwrap_err(),
            VpnIdentityError::DuplicateFingerprint
        );

        let same_address = identity(
            "client-b",
            vec![fingerprint(2)],
            true,
            "10.77.0.2",
            "fd77::3",
        );
        assert_eq!(
            registry(vec![first, same_address]).unwrap_err(),
            VpnIdentityError::DuplicateClientAddress
        );
    }

    #[test]
    fn local_identity_and_global_address_contracts_are_strict() {
        assert_eq!(
            VpnIdentity::new(
                "bad client",
                vec![fingerprint(1)],
                true,
                Some("10.77.0.2".parse().unwrap()),
                None,
                vec![],
                VpnIdentityLimits::default(),
            )
            .unwrap_err(),
            VpnIdentityError::InvalidClientId
        );
        assert_eq!(
            VpnIdentityLimits::new(0, 1, 1, VPN_MAX_IP_PACKET_LEN).unwrap_err(),
            VpnIdentityError::InvalidLimits
        );
        assert_eq!(
            VpnIdentityLimits::new(2, 1, 1, VPN_MAX_IP_PACKET_LEN).unwrap_err(),
            VpnIdentityError::InvalidLimits
        );
        assert_eq!(
            VpnIdentityRegistry::new(None, None, vec![]).unwrap_err(),
            VpnIdentityError::MissingServerAddress
        );

        let server_conflict = identity(
            "client-a",
            vec![fingerprint(1)],
            true,
            "10.77.0.1",
            "fd77::2",
        );
        assert_eq!(
            registry(vec![server_conflict]).unwrap_err(),
            VpnIdentityError::ClientServerAddressConflict
        );
    }

    fn fingerprint(byte: u8) -> VpnCertificateFingerprint {
        VpnCertificateFingerprint::from_sha256([byte; VPN_SHA256_FINGERPRINT_LEN])
    }

    fn identity(
        client_id: &str,
        fingerprints: Vec<VpnCertificateFingerprint>,
        enabled: bool,
        ipv4: &str,
        ipv6: &str,
    ) -> VpnIdentity {
        VpnIdentity::new(
            client_id,
            fingerprints,
            enabled,
            Some(ipv4.parse().unwrap()),
            Some(ipv6.parse().unwrap()),
            vec![
                VpnIpNetwork::v4("0.0.0.0".parse().unwrap(), 0).unwrap(),
                VpnIpNetwork::v6("::".parse().unwrap(), 0).unwrap(),
            ],
            VpnIdentityLimits::default(),
        )
        .unwrap()
    }

    fn registry(identities: Vec<VpnIdentity>) -> Result<VpnIdentityRegistry, VpnIdentityError> {
        VpnIdentityRegistry::new(
            Some("10.77.0.1".parse().unwrap()),
            Some("fd77::1".parse().unwrap()),
            identities,
        )
    }
}

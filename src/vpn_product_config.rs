use std::{
    collections::HashSet,
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Component, Path, PathBuf},
};

use noq::rustls::pki_types::ServerName;
use serde::Deserialize;

use crate::{
    VPN_MAX_DESTINATION_NETWORKS_PER_IDENTITY, VPN_MAX_GLOBAL_INFLIGHT_PACKETS,
    VPN_MAX_GLOBAL_REASSEMBLY_BYTES, VPN_MAX_IP_PACKET_LEN, VPN_MIN_IP_PACKET_LEN,
    VPN_MIN_QUIC_DATAGRAM_LEN, VpnIdentityError, VpnIdentityLimits, VpnIpNetwork,
};

pub const VPN_PRODUCT_CONFIG_VERSION: u16 = 1;
pub const VPN_PRODUCT_CONFIG_MAX_BYTES: usize = 1024 * 1024;
pub const VPN_PRODUCT_MAX_EXPLICIT_PATHS: usize = 8;
pub const VPN_TUN_NAME_MAX_BYTES: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnProductConfigError {
    Io(io::ErrorKind),
    NotRegularFile,
    UnsafePermissions,
    FileTooLarge,
    InvalidJson { line: usize, column: usize },
    UnsupportedConfigVersion,
    InvalidListen,
    InvalidServer,
    InvalidServerName,
    InvalidPath,
    InvalidTunName,
    InvalidTunMtu,
    InvalidDatagramLength,
    MissingAddressFamily,
    InvalidLocalIp,
    TooManyLocalIps,
    DuplicateLocalIp,
    MixedLocalIpFamily,
    InvalidDestinationNetwork,
    DestinationNetwork(VpnIdentityError),
    DuplicateDestinationNetwork,
    DestinationFamilyDisabled,
    Limits(VpnIdentityError),
    InvalidGlobalReassemblyBytes,
    InvalidGlobalInflightPackets,
    GlobalReassemblyBelowIdentityLimit,
}

impl fmt::Display for VpnProductConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(formatter, "vpn_product_config_io:{kind:?}"),
            Self::InvalidJson { line, column } => {
                write!(formatter, "vpn_product_config_invalid_json:{line}:{column}")
            }
            Self::DestinationNetwork(error) => {
                write!(formatter, "vpn_product_config_destination:{error}")
            }
            Self::Limits(error) => write!(formatter, "vpn_product_config_limits:{error}"),
            other => formatter.write_str(match other {
                Self::NotRegularFile => "vpn_product_config_not_regular_file",
                Self::UnsafePermissions => "vpn_product_config_unsafe_permissions",
                Self::FileTooLarge => "vpn_product_config_file_too_large",
                Self::UnsupportedConfigVersion => "vpn_product_config_unsupported_version",
                Self::InvalidListen => "vpn_product_config_invalid_listen",
                Self::InvalidServer => "vpn_product_config_invalid_server",
                Self::InvalidServerName => "vpn_product_config_invalid_server_name",
                Self::InvalidPath => "vpn_product_config_invalid_path",
                Self::InvalidTunName => "vpn_product_config_invalid_tun_name",
                Self::InvalidTunMtu => "vpn_product_config_invalid_tun_mtu",
                Self::InvalidDatagramLength => "vpn_product_config_invalid_datagram_length",
                Self::MissingAddressFamily => "vpn_product_config_missing_address_family",
                Self::InvalidLocalIp => "vpn_product_config_invalid_local_ip",
                Self::TooManyLocalIps => "vpn_product_config_too_many_local_ips",
                Self::DuplicateLocalIp => "vpn_product_config_duplicate_local_ip",
                Self::MixedLocalIpFamily => "vpn_product_config_mixed_local_ip_family",
                Self::InvalidDestinationNetwork => "vpn_product_config_invalid_destination_network",
                Self::DuplicateDestinationNetwork => {
                    "vpn_product_config_duplicate_destination_network"
                }
                Self::DestinationFamilyDisabled => "vpn_product_config_destination_family_disabled",
                Self::InvalidGlobalReassemblyBytes => {
                    "vpn_product_config_invalid_global_reassembly_bytes"
                }
                Self::InvalidGlobalInflightPackets => {
                    "vpn_product_config_invalid_global_inflight_packets"
                }
                Self::GlobalReassemblyBelowIdentityLimit => {
                    "vpn_product_config_global_reassembly_below_identity_limit"
                }
                Self::Io(_)
                | Self::InvalidJson { .. }
                | Self::DestinationNetwork(_)
                | Self::Limits(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnProductConfigError {}

#[derive(Clone, PartialEq, Eq)]
pub struct VpnServerProductConfig {
    listen: SocketAddr,
    certificate_der: PathBuf,
    private_key_der: PathBuf,
    client_ca_der: PathBuf,
    identity_file: PathBuf,
    tun_name: String,
    tun_mtu: u16,
    max_datagram_len: u16,
    global_reassembly_bytes: usize,
    global_inflight_packets: usize,
}

impl VpnServerProductConfig {
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub fn certificate_der(&self) -> &Path {
        &self.certificate_der
    }

    pub fn private_key_der(&self) -> &Path {
        &self.private_key_der
    }

    pub fn client_ca_der(&self) -> &Path {
        &self.client_ca_der
    }

    pub fn identity_file(&self) -> &Path {
        &self.identity_file
    }

    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    pub const fn tun_mtu(&self) -> u16 {
        self.tun_mtu
    }

    pub const fn max_datagram_len(&self) -> u16 {
        self.max_datagram_len
    }

    pub const fn global_reassembly_bytes(&self) -> usize {
        self.global_reassembly_bytes
    }

    pub const fn global_inflight_packets(&self) -> usize {
        self.global_inflight_packets
    }
}

impl fmt::Debug for VpnServerProductConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnServerProductConfig")
            .field("listen", &self.listen)
            .field("tun_name", &self.tun_name)
            .field("tun_mtu", &self.tun_mtu)
            .field("max_datagram_len", &self.max_datagram_len)
            .field("global_reassembly_bytes", &self.global_reassembly_bytes)
            .field("global_inflight_packets", &self.global_inflight_packets)
            .field("credential_paths", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VpnClientProductConfig {
    server: String,
    server_name: String,
    server_ca_der: PathBuf,
    certificate_der: PathBuf,
    private_key_der: PathBuf,
    tun_name: String,
    tun_mtu: u16,
    max_datagram_len: u16,
    request_ipv4: bool,
    request_ipv6: bool,
    allowed_destinations: Vec<VpnIpNetwork>,
    limits: VpnIdentityLimits,
    global_reassembly_bytes: usize,
    global_inflight_packets: usize,
    primary_local_ip: Option<IpAddr>,
    additional_local_ips: Vec<IpAddr>,
}

impl VpnClientProductConfig {
    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn server_ca_der(&self) -> &Path {
        &self.server_ca_der
    }

    pub fn certificate_der(&self) -> &Path {
        &self.certificate_der
    }

    pub fn private_key_der(&self) -> &Path {
        &self.private_key_der
    }

    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    pub const fn tun_mtu(&self) -> u16 {
        self.tun_mtu
    }

    pub const fn max_datagram_len(&self) -> u16 {
        self.max_datagram_len
    }

    pub const fn request_ipv4(&self) -> bool {
        self.request_ipv4
    }

    pub const fn request_ipv6(&self) -> bool {
        self.request_ipv6
    }

    pub fn allowed_destinations(&self) -> &[VpnIpNetwork] {
        &self.allowed_destinations
    }

    pub const fn limits(&self) -> VpnIdentityLimits {
        self.limits
    }

    pub const fn global_reassembly_bytes(&self) -> usize {
        self.global_reassembly_bytes
    }

    pub const fn global_inflight_packets(&self) -> usize {
        self.global_inflight_packets
    }

    pub const fn primary_local_ip(&self) -> Option<IpAddr> {
        self.primary_local_ip
    }

    pub fn additional_local_ips(&self) -> &[IpAddr] {
        &self.additional_local_ips
    }
}

impl fmt::Debug for VpnClientProductConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnClientProductConfig")
            .field("server", &"[redacted]")
            .field("server_name", &"[redacted]")
            .field("tun_name", &self.tun_name)
            .field("tun_mtu", &self.tun_mtu)
            .field("max_datagram_len", &self.max_datagram_len)
            .field("request_ipv4", &self.request_ipv4)
            .field("request_ipv6", &self.request_ipv6)
            .field(
                "destination_network_count",
                &self.allowed_destinations.len(),
            )
            .field(
                "explicit_local_path_count",
                &(self.additional_local_ips.len() + usize::from(self.primary_local_ip.is_some())),
            )
            .field("limits", &self.limits)
            .field("global_reassembly_bytes", &self.global_reassembly_bytes)
            .field("global_inflight_packets", &self.global_inflight_packets)
            .field("credential_paths", &"[redacted]")
            .finish()
    }
}

pub fn load_vpn_server_product_config(
    path: &Path,
) -> Result<VpnServerProductConfig, VpnProductConfigError> {
    let bytes = read_private_config(path)?;
    parse_vpn_server_product_config_json(&bytes, config_base(path))
}

pub fn load_vpn_client_product_config(
    path: &Path,
) -> Result<VpnClientProductConfig, VpnProductConfigError> {
    let bytes = read_private_config(path)?;
    parse_vpn_client_product_config_json(&bytes, config_base(path))
}

pub fn parse_vpn_server_product_config_json(
    bytes: &[u8],
    base: &Path,
) -> Result<VpnServerProductConfig, VpnProductConfigError> {
    let raw: RawServerConfig = parse_json(bytes)?;
    validate_version(raw.config_version)?;
    let listen = raw
        .listen
        .parse::<SocketAddr>()
        .ok()
        .filter(|address| address.port() != 0 && valid_listen_ip(address.ip()))
        .ok_or(VpnProductConfigError::InvalidListen)?;
    let tun_name = validate_vpn_tun_name(&raw.tun_name)?.to_owned();
    validate_packet_sizes(raw.tun_mtu, raw.max_datagram_len)?;
    validate_global_limits(raw.global_reassembly_bytes, raw.global_inflight_packets)?;
    Ok(VpnServerProductConfig {
        listen,
        certificate_der: resolve_config_path(base, &raw.certificate_der)?,
        private_key_der: resolve_config_path(base, &raw.private_key_der)?,
        client_ca_der: resolve_config_path(base, &raw.client_ca_der)?,
        identity_file: resolve_config_path(base, &raw.identity_file)?,
        tun_name,
        tun_mtu: raw.tun_mtu,
        max_datagram_len: raw.max_datagram_len,
        global_reassembly_bytes: raw.global_reassembly_bytes,
        global_inflight_packets: raw.global_inflight_packets,
    })
}

pub fn parse_vpn_client_product_config_json(
    bytes: &[u8],
    base: &Path,
) -> Result<VpnClientProductConfig, VpnProductConfigError> {
    let raw: RawClientConfig = parse_json(bytes)?;
    validate_version(raw.config_version)?;
    validate_server_endpoint(&raw.server)?;
    ServerName::try_from(raw.server_name.clone())
        .map_err(|_| VpnProductConfigError::InvalidServerName)?;
    if raw
        .server_name
        .parse::<IpAddr>()
        .is_ok_and(|address| !valid_remote_ip(address))
    {
        return Err(VpnProductConfigError::InvalidServerName);
    }
    if !raw.request_ipv4 && !raw.request_ipv6 {
        return Err(VpnProductConfigError::MissingAddressFamily);
    }
    let tun_name = validate_vpn_tun_name(&raw.tun_name)?.to_owned();
    validate_packet_sizes(raw.tun_mtu, raw.max_datagram_len)?;
    validate_global_limits(raw.global_reassembly_bytes, raw.global_inflight_packets)?;
    let allowed_destinations =
        parse_destination_networks(raw.allowed_destinations, raw.request_ipv4, raw.request_ipv6)?;
    let limits = VpnIdentityLimits::new(
        1,
        raw.limits.max_packets_per_second,
        raw.limits.max_bytes_per_second,
        raw.limits.max_reassembly_bytes,
    )
    .map_err(VpnProductConfigError::Limits)?;
    if raw.global_reassembly_bytes < limits.max_reassembly_bytes() {
        return Err(VpnProductConfigError::GlobalReassemblyBelowIdentityLimit);
    }
    let primary_local_ip = raw.primary_local_ip.map(parse_local_ip).transpose()?;
    let additional_local_ips = raw
        .additional_local_ips
        .into_iter()
        .map(parse_local_ip)
        .collect::<Result<Vec<_>, _>>()?;
    validate_local_ips(primary_local_ip, &additional_local_ips)?;
    Ok(VpnClientProductConfig {
        server: raw.server,
        server_name: raw.server_name,
        server_ca_der: resolve_config_path(base, &raw.server_ca_der)?,
        certificate_der: resolve_config_path(base, &raw.certificate_der)?,
        private_key_der: resolve_config_path(base, &raw.private_key_der)?,
        tun_name,
        tun_mtu: raw.tun_mtu,
        max_datagram_len: raw.max_datagram_len,
        request_ipv4: raw.request_ipv4,
        request_ipv6: raw.request_ipv6,
        allowed_destinations,
        limits,
        global_reassembly_bytes: raw.global_reassembly_bytes,
        global_inflight_packets: raw.global_inflight_packets,
        primary_local_ip,
        additional_local_ips,
    })
}

fn read_private_config(path: &Path) -> Result<Vec<u8>, VpnProductConfigError> {
    let file = File::open(path).map_err(|error| VpnProductConfigError::Io(error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| VpnProductConfigError::Io(error.kind()))?;
    if !metadata.is_file() {
        return Err(VpnProductConfigError::NotRegularFile);
    }
    enforce_private_permissions(&metadata)?;
    if metadata.len() > VPN_PRODUCT_CONFIG_MAX_BYTES as u64 {
        return Err(VpnProductConfigError::FileTooLarge);
    }
    let mut limited = file.take((VPN_PRODUCT_CONFIG_MAX_BYTES + 1) as u64);
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(VPN_PRODUCT_CONFIG_MAX_BYTES)
            .min(VPN_PRODUCT_CONFIG_MAX_BYTES),
    );
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| VpnProductConfigError::Io(error.kind()))?;
    if bytes.len() > VPN_PRODUCT_CONFIG_MAX_BYTES {
        return Err(VpnProductConfigError::FileTooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn enforce_private_permissions(metadata: &fs::Metadata) -> Result<(), VpnProductConfigError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(VpnProductConfigError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_permissions(_metadata: &fs::Metadata) -> Result<(), VpnProductConfigError> {
    Ok(())
}

fn parse_json<'a, T>(bytes: &'a [u8]) -> Result<T, VpnProductConfigError>
where
    T: Deserialize<'a>,
{
    serde_json::from_slice(bytes).map_err(|error| VpnProductConfigError::InvalidJson {
        line: error.line(),
        column: error.column(),
    })
}

fn validate_version(version: u16) -> Result<(), VpnProductConfigError> {
    if version != VPN_PRODUCT_CONFIG_VERSION {
        return Err(VpnProductConfigError::UnsupportedConfigVersion);
    }
    Ok(())
}

fn validate_packet_sizes(tun_mtu: u16, max_datagram_len: u16) -> Result<(), VpnProductConfigError> {
    validate_vpn_tun_mtu(tun_mtu)?;
    if usize::from(max_datagram_len) < VPN_MIN_QUIC_DATAGRAM_LEN {
        return Err(VpnProductConfigError::InvalidDatagramLength);
    }
    Ok(())
}

fn validate_global_limits(bytes: usize, packets: usize) -> Result<(), VpnProductConfigError> {
    if !(VPN_MAX_IP_PACKET_LEN..=VPN_MAX_GLOBAL_REASSEMBLY_BYTES).contains(&bytes) {
        return Err(VpnProductConfigError::InvalidGlobalReassemblyBytes);
    }
    if packets == 0 || packets > VPN_MAX_GLOBAL_INFLIGHT_PACKETS {
        return Err(VpnProductConfigError::InvalidGlobalInflightPackets);
    }
    Ok(())
}

pub(crate) fn validate_vpn_tun_name(name: &str) -> Result<&str, VpnProductConfigError> {
    if name.is_empty()
        || name.len() > VPN_TUN_NAME_MAX_BYTES
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(VpnProductConfigError::InvalidTunName);
    }
    Ok(name)
}

pub(crate) fn validate_vpn_tun_mtu(mtu: u16) -> Result<u16, VpnProductConfigError> {
    if !(VPN_MIN_IP_PACKET_LEN..=VPN_MAX_IP_PACKET_LEN).contains(&usize::from(mtu)) {
        return Err(VpnProductConfigError::InvalidTunMtu);
    }
    Ok(mtu)
}

fn validate_server_endpoint(value: &str) -> Result<(), VpnProductConfigError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(VpnProductConfigError::InvalidServer);
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return if address.port() != 0 && valid_remote_ip(address.ip()) {
            Ok(())
        } else {
            Err(VpnProductConfigError::InvalidServer)
        };
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(VpnProductConfigError::InvalidServer);
    };
    if host.is_empty()
        || host.contains(':')
        || !host.is_ascii()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        || ServerName::try_from(host.to_owned()).is_err()
        || port.parse::<u16>().ok().is_none_or(|port| port == 0)
    {
        return Err(VpnProductConfigError::InvalidServer);
    }
    Ok(())
}

fn valid_listen_ip(address: IpAddr) -> bool {
    !address.is_multicast()
        && !matches!(address, IpAddr::V4(address) if address == Ipv4Addr::BROADCAST)
}

fn valid_remote_ip(address: IpAddr) -> bool {
    !address.is_unspecified() && valid_listen_ip(address)
}

fn resolve_config_path(base: &Path, value: &str) -> Result<PathBuf, VpnProductConfigError> {
    if value.is_empty() || value.trim() != value || value.contains('\0') {
        return Err(VpnProductConfigError::InvalidPath);
    }
    let path = Path::new(value);
    if path.file_name().is_none()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(VpnProductConfigError::InvalidPath);
    }
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    })
}

fn config_base(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn parse_destination_networks(
    values: Vec<String>,
    request_ipv4: bool,
    request_ipv6: bool,
) -> Result<Vec<VpnIpNetwork>, VpnProductConfigError> {
    if values.len() > VPN_MAX_DESTINATION_NETWORKS_PER_IDENTITY {
        return Err(VpnProductConfigError::DestinationNetwork(
            VpnIdentityError::TooManyDestinationNetworks,
        ));
    }
    let mut unique = HashSet::with_capacity(values.len());
    let mut networks = Vec::with_capacity(values.len());
    for value in values {
        let network = parse_destination_network(&value)?;
        if !unique.insert(network) {
            return Err(VpnProductConfigError::DuplicateDestinationNetwork);
        }
        if matches!(network, VpnIpNetwork::V4 { .. }) && !request_ipv4
            || matches!(network, VpnIpNetwork::V6 { .. }) && !request_ipv6
        {
            return Err(VpnProductConfigError::DestinationFamilyDisabled);
        }
        networks.push(network);
    }
    Ok(networks)
}

fn parse_destination_network(value: &str) -> Result<VpnIpNetwork, VpnProductConfigError> {
    let (address, prefix) = value
        .split_once('/')
        .filter(|(_, prefix)| !prefix.contains('/'))
        .ok_or(VpnProductConfigError::InvalidDestinationNetwork)?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| VpnProductConfigError::InvalidDestinationNetwork)?;
    if let Ok(address) = address.parse::<Ipv4Addr>() {
        return VpnIpNetwork::v4(address, prefix)
            .map_err(VpnProductConfigError::DestinationNetwork);
    }
    if let Ok(address) = address.parse::<Ipv6Addr>() {
        return VpnIpNetwork::v6(address, prefix)
            .map_err(VpnProductConfigError::DestinationNetwork);
    }
    Err(VpnProductConfigError::InvalidDestinationNetwork)
}

fn parse_local_ip(value: String) -> Result<IpAddr, VpnProductConfigError> {
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| VpnProductConfigError::InvalidLocalIp)?;
    let invalid = match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_multicast()
                || address.is_link_local()
                || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            address.is_unspecified() || address.is_multicast() || address.is_unicast_link_local()
        }
    };
    if invalid {
        return Err(VpnProductConfigError::InvalidLocalIp);
    }
    Ok(address)
}

fn validate_local_ips(
    primary: Option<IpAddr>,
    additional: &[IpAddr],
) -> Result<(), VpnProductConfigError> {
    let explicit_count = additional.len() + usize::from(primary.is_some());
    if explicit_count > VPN_PRODUCT_MAX_EXPLICIT_PATHS {
        return Err(VpnProductConfigError::TooManyLocalIps);
    }
    let mut unique = HashSet::with_capacity(explicit_count);
    if let Some(primary) = primary {
        unique.insert(primary);
    }
    let family = primary.or_else(|| additional.first().copied());
    for address in additional {
        if !unique.insert(*address) {
            return Err(VpnProductConfigError::DuplicateLocalIp);
        }
        if family.is_some_and(|family| family.is_ipv4() != address.is_ipv4()) {
            return Err(VpnProductConfigError::MixedLocalIpFamily);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerConfig {
    config_version: u16,
    listen: String,
    certificate_der: String,
    private_key_der: String,
    client_ca_der: String,
    identity_file: String,
    tun_name: String,
    tun_mtu: u16,
    max_datagram_len: u16,
    global_reassembly_bytes: usize,
    global_inflight_packets: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientConfig {
    config_version: u16,
    server: String,
    server_name: String,
    server_ca_der: String,
    certificate_der: String,
    private_key_der: String,
    tun_name: String,
    tun_mtu: u16,
    max_datagram_len: u16,
    request_ipv4: bool,
    request_ipv6: bool,
    allowed_destinations: Vec<String>,
    limits: RawClientLimits,
    global_reassembly_bytes: usize,
    global_inflight_packets: usize,
    primary_local_ip: Option<String>,
    additional_local_ips: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientLimits {
    max_packets_per_second: u32,
    max_bytes_per_second: u64,
    max_reassembly_bytes: usize,
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::{Value, json};

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn deployment_examples_follow_strict_server_and_client_contracts() {
        let base = Path::new("/etc/flowweave");
        let server = parse_vpn_server_product_config_json(
            include_bytes!("../deploy/vpn-server.json.example"),
            base,
        )
        .unwrap();
        assert_eq!(server.listen(), "0.0.0.0:4433".parse().unwrap());
        assert_eq!(server.tun_name(), "fwvpn0");
        assert_eq!(server.tun_mtu(), 1500);
        assert_eq!(server.private_key_der(), base.join("vpn-server.key.der"));

        let client = parse_vpn_client_product_config_json(
            include_bytes!("../deploy/vpn-client.json.example"),
            base,
        )
        .unwrap();
        assert_eq!(client.server(), "vpn.example.com:4433");
        assert_eq!(client.tun_name(), "fwvpn0");
        assert!(client.request_ipv4());
        assert!(client.request_ipv6());
        assert_eq!(client.allowed_destinations().len(), 2);
        assert_eq!(client.additional_local_ips().len(), 0);
        assert_eq!(client.limits().max_connections(), 1);
    }

    #[test]
    fn unknown_duplicate_missing_version_and_unsafe_paths_are_rejected() {
        let mut unknown = valid_server();
        unknown["unknown"] = Value::Bool(true);
        assert!(matches!(
            parse_server_value(unknown),
            Err(VpnProductConfigError::InvalidJson { .. })
        ));
        let duplicate = br#"{
            "config_version":1,
            "config_version":1,
            "listen":"0.0.0.0:4433",
            "certificate_der":"a",
            "private_key_der":"b",
            "client_ca_der":"c",
            "identity_file":"d",
            "tun_name":"fwvpn0",
            "tun_mtu":1500,
            "max_datagram_len":1200,
            "global_reassembly_bytes":67108864,
            "global_inflight_packets":8192
        }"#;
        assert!(matches!(
            parse_vpn_server_product_config_json(duplicate, Path::new("/tmp")),
            Err(VpnProductConfigError::InvalidJson { .. })
        ));
        let mut missing = valid_server();
        missing.as_object_mut().unwrap().remove("listen");
        assert!(matches!(
            parse_server_value(missing),
            Err(VpnProductConfigError::InvalidJson { .. })
        ));
        let mut unsupported = valid_server();
        unsupported["config_version"] = Value::from(2);
        assert_eq!(
            parse_server_value(unsupported).unwrap_err(),
            VpnProductConfigError::UnsupportedConfigVersion
        );
        let mut parent = valid_server();
        parent["private_key_der"] = Value::from("../secret.key");
        assert_eq!(
            parse_server_value(parent).unwrap_err(),
            VpnProductConfigError::InvalidPath
        );
        let mut absolute_parent = valid_server();
        absolute_parent["private_key_der"] = Value::from("/etc/flowweave/../secret.key");
        assert_eq!(
            parse_server_value(absolute_parent).unwrap_err(),
            VpnProductConfigError::InvalidPath
        );
    }

    #[test]
    fn packet_tun_global_and_endpoint_values_fail_closed() {
        for name in ["", "this-interface-name-is-too-long", "bad/name", ".."] {
            let mut value = valid_server();
            value["tun_name"] = Value::from(name);
            assert_eq!(
                parse_server_value(value).unwrap_err(),
                VpnProductConfigError::InvalidTunName
            );
        }
        let mut mtu = valid_server();
        mtu["tun_mtu"] = Value::from(1279);
        assert_eq!(
            parse_server_value(mtu).unwrap_err(),
            VpnProductConfigError::InvalidTunMtu
        );
        let mut datagram = valid_server();
        datagram["max_datagram_len"] = Value::from(VPN_MIN_QUIC_DATAGRAM_LEN - 1);
        assert_eq!(
            parse_server_value(datagram).unwrap_err(),
            VpnProductConfigError::InvalidDatagramLength
        );
        let mut global = valid_server();
        global["global_inflight_packets"] = Value::from(0);
        assert_eq!(
            parse_server_value(global).unwrap_err(),
            VpnProductConfigError::InvalidGlobalInflightPackets
        );
        let mut listen = valid_server();
        listen["listen"] = Value::from("224.0.0.1:4433");
        assert_eq!(
            parse_server_value(listen).unwrap_err(),
            VpnProductConfigError::InvalidListen
        );

        let mut server = valid_client();
        server["server"] = Value::from("not a host port");
        assert_eq!(
            parse_client_value(server).unwrap_err(),
            VpnProductConfigError::InvalidServer
        );
        for endpoint in ["0.0.0.0:4433", "224.0.0.1:4433", "-bad.example:4433"] {
            let mut server = valid_client();
            server["server"] = Value::from(endpoint);
            assert_eq!(
                parse_client_value(server).unwrap_err(),
                VpnProductConfigError::InvalidServer
            );
        }
        let mut server_name = valid_client();
        server_name["server_name"] = Value::from("bad name");
        assert_eq!(
            parse_client_value(server_name).unwrap_err(),
            VpnProductConfigError::InvalidServerName
        );
        let mut unspecified_server_name = valid_client();
        unspecified_server_name["server_name"] = Value::from("0.0.0.0");
        assert_eq!(
            parse_client_value(unspecified_server_name).unwrap_err(),
            VpnProductConfigError::InvalidServerName
        );
    }

    #[test]
    fn client_families_networks_limits_and_local_paths_are_cross_validated() {
        let mut no_family = valid_client();
        no_family["request_ipv4"] = Value::Bool(false);
        no_family["request_ipv6"] = Value::Bool(false);
        assert_eq!(
            parse_client_value(no_family).unwrap_err(),
            VpnProductConfigError::MissingAddressFamily
        );

        let mut disabled_family = valid_client();
        disabled_family["request_ipv6"] = Value::Bool(false);
        assert_eq!(
            parse_client_value(disabled_family).unwrap_err(),
            VpnProductConfigError::DestinationFamilyDisabled
        );
        let mut duplicate_network = valid_client();
        duplicate_network["allowed_destinations"] = json!(["0.0.0.0/0", "0.0.0.0/0"]);
        assert_eq!(
            parse_client_value(duplicate_network).unwrap_err(),
            VpnProductConfigError::DuplicateDestinationNetwork
        );
        let mut noncanonical = valid_client();
        noncanonical["allowed_destinations"] = json!(["10.0.0.1/8"]);
        assert_eq!(
            parse_client_value(noncanonical).unwrap_err(),
            VpnProductConfigError::DestinationNetwork(VpnIdentityError::NonCanonicalNetwork)
        );
        let mut limits = valid_client();
        limits["limits"]["max_packets_per_second"] = Value::from(0);
        assert_eq!(
            parse_client_value(limits).unwrap_err(),
            VpnProductConfigError::Limits(VpnIdentityError::InvalidLimits)
        );
        let mut global_below_identity = valid_client();
        global_below_identity["global_reassembly_bytes"] = Value::from(VPN_MAX_IP_PACKET_LEN);
        assert_eq!(
            parse_client_value(global_below_identity).unwrap_err(),
            VpnProductConfigError::GlobalReassemblyBelowIdentityLimit
        );
        let mut duplicate_ip = valid_client();
        duplicate_ip["primary_local_ip"] = Value::from("127.0.0.1");
        duplicate_ip["additional_local_ips"] = json!(["127.0.0.1"]);
        assert_eq!(
            parse_client_value(duplicate_ip).unwrap_err(),
            VpnProductConfigError::DuplicateLocalIp
        );
        let mut mixed = valid_client();
        mixed["primary_local_ip"] = Value::from("127.0.0.1");
        mixed["additional_local_ips"] = json!(["::1"]);
        assert_eq!(
            parse_client_value(mixed).unwrap_err(),
            VpnProductConfigError::MixedLocalIpFamily
        );
        let mut link_local = valid_client();
        link_local["primary_local_ip"] = Value::from("fe80::1");
        assert_eq!(
            parse_client_value(link_local).unwrap_err(),
            VpnProductConfigError::InvalidLocalIp
        );
        let mut too_many_paths = valid_client();
        too_many_paths["additional_local_ips"] = json!([
            "127.0.0.1",
            "127.0.0.2",
            "127.0.0.3",
            "127.0.0.4",
            "127.0.0.5",
            "127.0.0.6",
            "127.0.0.7",
            "127.0.0.8",
            "127.0.0.9"
        ]);
        assert_eq!(
            parse_client_value(too_many_paths).unwrap_err(),
            VpnProductConfigError::TooManyLocalIps
        );
    }

    #[cfg(unix)]
    #[test]
    fn product_config_file_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        assert_eq!(
            load_vpn_server_product_config(directory.path()).unwrap_err(),
            VpnProductConfigError::NotRegularFile
        );
        let path = directory.path().join("server.json");
        fs::write(&path, serde_json::to_vec(&valid_server()).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_vpn_server_product_config(&path).unwrap_err(),
            VpnProductConfigError::UnsafePermissions
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_vpn_server_product_config(&path).is_ok());

        let oversized = directory.path().join("oversized.json");
        fs::write(&oversized, vec![b' '; VPN_PRODUCT_CONFIG_MAX_BYTES + 1]).unwrap();
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_vpn_server_product_config(&oversized).unwrap_err(),
            VpnProductConfigError::FileTooLarge
        );
    }

    #[test]
    fn debug_output_redacts_servers_and_credential_paths() {
        let server = parse_server_value(valid_server()).unwrap();
        let client = parse_client_value(valid_client()).unwrap();
        let server_debug = format!("{server:?}");
        let client_debug = format!("{client:?}");
        assert!(!server_debug.contains("server.key"));
        assert!(!client_debug.contains("vpn.example.com"));
        assert!(!client_debug.contains("client.key"));
    }

    fn parse_server_value(value: Value) -> Result<VpnServerProductConfig, VpnProductConfigError> {
        parse_vpn_server_product_config_json(
            serde_json::to_string(&value).unwrap().as_bytes(),
            Path::new("/etc/flowweave"),
        )
    }

    fn parse_client_value(value: Value) -> Result<VpnClientProductConfig, VpnProductConfigError> {
        parse_vpn_client_product_config_json(
            serde_json::to_string(&value).unwrap().as_bytes(),
            Path::new("/etc/flowweave"),
        )
    }

    fn valid_server() -> Value {
        json!({
            "config_version": VPN_PRODUCT_CONFIG_VERSION,
            "listen": "0.0.0.0:4433",
            "certificate_der": "vpn-server.cert.der",
            "private_key_der": "vpn-server.key.der",
            "client_ca_der": "vpn-client-ca.cert.der",
            "identity_file": "vpn-identities.json",
            "tun_name": "fwvpn0",
            "tun_mtu": 1500,
            "max_datagram_len": 1200,
            "global_reassembly_bytes": 64 * 1024 * 1024,
            "global_inflight_packets": 8192
        })
    }

    fn valid_client() -> Value {
        json!({
            "config_version": VPN_PRODUCT_CONFIG_VERSION,
            "server": "vpn.example.com:4433",
            "server_name": "vpn.example.com",
            "server_ca_der": "vpn-server-ca.cert.der",
            "certificate_der": "vpn-client.cert.der",
            "private_key_der": "vpn-client.key.der",
            "tun_name": "fwvpn0",
            "tun_mtu": 1500,
            "max_datagram_len": 1200,
            "request_ipv4": true,
            "request_ipv6": true,
            "allowed_destinations": ["0.0.0.0/0", "::/0"],
            "limits": {
                "max_packets_per_second": 100000,
                "max_bytes_per_second": 134217728,
                "max_reassembly_bytes": 8388608
            },
            "global_reassembly_bytes": 67108864,
            "global_inflight_packets": 8192,
            "primary_local_ip": null,
            "additional_local_ips": []
        })
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "flowweave-vpn-product-config-{}-{sequence}",
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

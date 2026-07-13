use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{VPN_MAX_IP_PACKET_LEN, VPN_MIN_QUIC_DATAGRAM_LEN};

pub const VPN_ALPN: &[u8] = b"flowweave-vpn/1";
pub const VPN_CONTROL_MAGIC: &[u8; 4] = b"FWC1";
pub const VPN_CONTROL_FORMAT_VERSION: u8 = 1;
pub const VPN_CONTROL_HEADER_LEN: usize = 8;
pub const VPN_CONTROL_MAX_MESSAGE_LEN: usize = 256;
pub const VPN_WIRE_VERSION_V1: u16 = 1;

pub const VPN_CAP_IPV4: u32 = 1 << 0;
pub const VPN_CAP_IPV6: u32 = 1 << 1;
pub const VPN_CAP_FRAGMENTATION: u32 = 1 << 2;
pub const VPN_CAP_MULTIPATH_REQUIRED: u32 = 1 << 3;
pub const VPN_REQUIRED_CAPABILITIES: u32 = VPN_CAP_FRAGMENTATION | VPN_CAP_MULTIPATH_REQUIRED;
pub const VPN_KNOWN_CAPABILITIES: u32 =
    VPN_CAP_IPV4 | VPN_CAP_IPV6 | VPN_CAP_FRAGMENTATION | VPN_CAP_MULTIPATH_REQUIRED;

const VPN_CONTROL_HELLO: u8 = 1;
const VPN_CONTROL_ACCEPT: u8 = 2;
const VPN_CONTROL_REJECT: u8 = 3;
const VPN_HELLO_BODY_LEN: usize = 12;
const VPN_ACCEPT_BODY_LEN: usize = 60;
const VPN_REJECT_BODY_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnControlError {
    MessageTooShort,
    MessageTooLong,
    InvalidMagic,
    UnsupportedFormatVersion,
    UnknownMessageType,
    LengthMismatch,
    InvalidHello,
    InvalidAccept,
    InvalidReject,
    UnknownCapabilities,
    MissingRequiredCapabilities,
    InvalidAddress,
}

impl fmt::Display for VpnControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MessageTooShort => "vpn_control_message_too_short",
            Self::MessageTooLong => "vpn_control_message_too_long",
            Self::InvalidMagic => "vpn_control_invalid_magic",
            Self::UnsupportedFormatVersion => "vpn_control_unsupported_format_version",
            Self::UnknownMessageType => "vpn_control_unknown_message_type",
            Self::LengthMismatch => "vpn_control_length_mismatch",
            Self::InvalidHello => "vpn_control_invalid_hello",
            Self::InvalidAccept => "vpn_control_invalid_accept",
            Self::InvalidReject => "vpn_control_invalid_reject",
            Self::UnknownCapabilities => "vpn_control_unknown_capabilities",
            Self::MissingRequiredCapabilities => "vpn_control_missing_required_capabilities",
            Self::InvalidAddress => "vpn_control_invalid_address",
        })
    }
}

impl Error for VpnControlError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnHello {
    pub min_wire_version: u16,
    pub max_wire_version: u16,
    pub capabilities: u32,
    pub max_ip_packet_len: u16,
    pub max_datagram_len: u16,
}

impl VpnHello {
    pub fn validate(&self) -> Result<(), VpnControlError> {
        if self.min_wire_version == 0 || self.min_wire_version > self.max_wire_version {
            return Err(VpnControlError::InvalidHello);
        }
        validate_capabilities(self.capabilities)?;
        validate_sizes(self.max_ip_packet_len, self.max_datagram_len)
            .map_err(|_| VpnControlError::InvalidHello)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnAccept {
    pub selected_wire_version: u16,
    pub capabilities: u32,
    pub max_ip_packet_len: u16,
    pub max_datagram_len: u16,
    pub session_generation: u64,
    pub client_ipv4: Option<Ipv4Addr>,
    pub server_ipv4: Option<Ipv4Addr>,
    pub client_ipv6: Option<Ipv6Addr>,
    pub server_ipv6: Option<Ipv6Addr>,
}

impl VpnAccept {
    pub fn validate(&self) -> Result<(), VpnControlError> {
        if self.selected_wire_version == 0 || self.session_generation == 0 {
            return Err(VpnControlError::InvalidAccept);
        }
        validate_capabilities(self.capabilities)?;
        validate_sizes(self.max_ip_packet_len, self.max_datagram_len)
            .map_err(|_| VpnControlError::InvalidAccept)?;

        let has_ipv4 = self.capabilities & VPN_CAP_IPV4 != 0;
        let has_ipv6 = self.capabilities & VPN_CAP_IPV6 != 0;
        if has_ipv4 != (self.client_ipv4.is_some() && self.server_ipv4.is_some())
            || has_ipv6 != (self.client_ipv6.is_some() && self.server_ipv6.is_some())
            || self.client_ipv4.is_some() != self.server_ipv4.is_some()
            || self.client_ipv6.is_some() != self.server_ipv6.is_some()
        {
            return Err(VpnControlError::InvalidAccept);
        }
        if let (Some(client), Some(server)) = (self.client_ipv4, self.server_ipv4)
            && (client == server
                || !valid_ipv4_tunnel_address(client)
                || !valid_ipv4_tunnel_address(server))
        {
            return Err(VpnControlError::InvalidAddress);
        }
        if let (Some(client), Some(server)) = (self.client_ipv6, self.server_ipv6)
            && (client == server
                || !valid_ipv6_tunnel_address(client)
                || !valid_ipv6_tunnel_address(server))
        {
            return Err(VpnControlError::InvalidAddress);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VpnRejectReason {
    UnsupportedVersion = 1,
    Unauthorized = 2,
    IdentityDisabled = 3,
    AddressInUse = 4,
    ResourceLimit = 5,
    PolicyRejected = 6,
    ProtocolViolation = 7,
}

impl TryFrom<u16> for VpnRejectReason {
    type Error = VpnControlError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::IdentityDisabled),
            4 => Ok(Self::AddressInUse),
            5 => Ok(Self::ResourceLimit),
            6 => Ok(Self::PolicyRejected),
            7 => Ok(Self::ProtocolViolation),
            _ => Err(VpnControlError::InvalidReject),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnReject {
    pub reason: VpnRejectReason,
    pub retry_after_secs: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnControlMessage {
    Hello(VpnHello),
    Accept(VpnAccept),
    Reject(VpnReject),
}

pub fn select_vpn_wire_version(
    client_min: u16,
    client_max: u16,
    server_min: u16,
    server_max: u16,
) -> Option<u16> {
    if client_min == 0 || server_min == 0 || client_min > client_max || server_min > server_max {
        return None;
    }
    let lower = client_min.max(server_min);
    let upper = client_max.min(server_max);
    (lower <= upper).then_some(upper)
}

pub fn encode_vpn_control_message(message: VpnControlMessage) -> Result<Vec<u8>, VpnControlError> {
    let (message_type, body) = match message {
        VpnControlMessage::Hello(hello) => {
            hello.validate()?;
            let mut body = Vec::with_capacity(VPN_HELLO_BODY_LEN);
            body.extend_from_slice(&hello.min_wire_version.to_be_bytes());
            body.extend_from_slice(&hello.max_wire_version.to_be_bytes());
            body.extend_from_slice(&hello.capabilities.to_be_bytes());
            body.extend_from_slice(&hello.max_ip_packet_len.to_be_bytes());
            body.extend_from_slice(&hello.max_datagram_len.to_be_bytes());
            (VPN_CONTROL_HELLO, body)
        }
        VpnControlMessage::Accept(accept) => {
            accept.validate()?;
            let mut body = Vec::with_capacity(VPN_ACCEPT_BODY_LEN);
            body.extend_from_slice(&accept.selected_wire_version.to_be_bytes());
            body.extend_from_slice(&0_u16.to_be_bytes());
            body.extend_from_slice(&accept.capabilities.to_be_bytes());
            body.extend_from_slice(&accept.max_ip_packet_len.to_be_bytes());
            body.extend_from_slice(&accept.max_datagram_len.to_be_bytes());
            body.extend_from_slice(&accept.session_generation.to_be_bytes());
            body.extend_from_slice(&accept.client_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
            body.extend_from_slice(&accept.server_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
            body.extend_from_slice(&accept.client_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
            body.extend_from_slice(&accept.server_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
            (VPN_CONTROL_ACCEPT, body)
        }
        VpnControlMessage::Reject(reject) => {
            let mut body = Vec::with_capacity(VPN_REJECT_BODY_LEN);
            body.extend_from_slice(&(reject.reason as u16).to_be_bytes());
            body.extend_from_slice(&reject.retry_after_secs.to_be_bytes());
            (VPN_CONTROL_REJECT, body)
        }
    };

    let body_len = u16::try_from(body.len()).map_err(|_| VpnControlError::MessageTooLong)?;
    let mut encoded = Vec::with_capacity(VPN_CONTROL_HEADER_LEN + body.len());
    encoded.extend_from_slice(VPN_CONTROL_MAGIC);
    encoded.push(VPN_CONTROL_FORMAT_VERSION);
    encoded.push(message_type);
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

pub fn decode_vpn_control_message(encoded: &[u8]) -> Result<VpnControlMessage, VpnControlError> {
    if encoded.len() < VPN_CONTROL_HEADER_LEN {
        return Err(VpnControlError::MessageTooShort);
    }
    if encoded.len() > VPN_CONTROL_MAX_MESSAGE_LEN {
        return Err(VpnControlError::MessageTooLong);
    }
    if &encoded[..4] != VPN_CONTROL_MAGIC {
        return Err(VpnControlError::InvalidMagic);
    }
    if encoded[4] != VPN_CONTROL_FORMAT_VERSION {
        return Err(VpnControlError::UnsupportedFormatVersion);
    }
    let body_len = usize::from(u16::from_be_bytes([encoded[6], encoded[7]]));
    if VPN_CONTROL_HEADER_LEN + body_len != encoded.len() {
        return Err(VpnControlError::LengthMismatch);
    }
    let body = &encoded[VPN_CONTROL_HEADER_LEN..];
    match encoded[5] {
        VPN_CONTROL_HELLO => decode_hello(body).map(VpnControlMessage::Hello),
        VPN_CONTROL_ACCEPT => decode_accept(body).map(VpnControlMessage::Accept),
        VPN_CONTROL_REJECT => decode_reject(body).map(VpnControlMessage::Reject),
        _ => Err(VpnControlError::UnknownMessageType),
    }
}

fn decode_hello(body: &[u8]) -> Result<VpnHello, VpnControlError> {
    if body.len() != VPN_HELLO_BODY_LEN {
        return Err(VpnControlError::InvalidHello);
    }
    let hello = VpnHello {
        min_wire_version: u16::from_be_bytes([body[0], body[1]]),
        max_wire_version: u16::from_be_bytes([body[2], body[3]]),
        capabilities: u32::from_be_bytes(body[4..8].try_into().expect("fixed HELLO body")),
        max_ip_packet_len: u16::from_be_bytes([body[8], body[9]]),
        max_datagram_len: u16::from_be_bytes([body[10], body[11]]),
    };
    hello.validate()?;
    Ok(hello)
}

fn decode_accept(body: &[u8]) -> Result<VpnAccept, VpnControlError> {
    if body.len() != VPN_ACCEPT_BODY_LEN {
        return Err(VpnControlError::InvalidAccept);
    }
    if body[2..4] != [0, 0] {
        return Err(VpnControlError::InvalidAccept);
    }
    let capabilities = u32::from_be_bytes(body[4..8].try_into().expect("fixed ACCEPT body"));
    let client_ipv4 = Ipv4Addr::new(body[20], body[21], body[22], body[23]);
    let server_ipv4 = Ipv4Addr::new(body[24], body[25], body[26], body[27]);
    let mut client_ipv6 = [0_u8; 16];
    client_ipv6.copy_from_slice(&body[28..44]);
    let mut server_ipv6 = [0_u8; 16];
    server_ipv6.copy_from_slice(&body[44..60]);
    let accept = VpnAccept {
        selected_wire_version: u16::from_be_bytes([body[0], body[1]]),
        capabilities,
        max_ip_packet_len: u16::from_be_bytes([body[8], body[9]]),
        max_datagram_len: u16::from_be_bytes([body[10], body[11]]),
        session_generation: u64::from_be_bytes(body[12..20].try_into().expect("fixed ACCEPT body")),
        client_ipv4: (capabilities & VPN_CAP_IPV4 != 0).then_some(client_ipv4),
        server_ipv4: (capabilities & VPN_CAP_IPV4 != 0).then_some(server_ipv4),
        client_ipv6: (capabilities & VPN_CAP_IPV6 != 0).then_some(Ipv6Addr::from(client_ipv6)),
        server_ipv6: (capabilities & VPN_CAP_IPV6 != 0).then_some(Ipv6Addr::from(server_ipv6)),
    };
    if capabilities & VPN_CAP_IPV4 == 0
        && (client_ipv4 != Ipv4Addr::UNSPECIFIED || server_ipv4 != Ipv4Addr::UNSPECIFIED)
        || capabilities & VPN_CAP_IPV6 == 0
            && (client_ipv6 != Ipv6Addr::UNSPECIFIED.octets()
                || server_ipv6 != Ipv6Addr::UNSPECIFIED.octets())
    {
        return Err(VpnControlError::InvalidAccept);
    }
    accept.validate()?;
    Ok(accept)
}

fn decode_reject(body: &[u8]) -> Result<VpnReject, VpnControlError> {
    if body.len() != VPN_REJECT_BODY_LEN {
        return Err(VpnControlError::InvalidReject);
    }
    Ok(VpnReject {
        reason: VpnRejectReason::try_from(u16::from_be_bytes([body[0], body[1]]))?,
        retry_after_secs: u16::from_be_bytes([body[2], body[3]]),
    })
}

fn validate_capabilities(capabilities: u32) -> Result<(), VpnControlError> {
    if capabilities & !VPN_KNOWN_CAPABILITIES != 0 {
        return Err(VpnControlError::UnknownCapabilities);
    }
    if capabilities & VPN_REQUIRED_CAPABILITIES != VPN_REQUIRED_CAPABILITIES
        || capabilities & (VPN_CAP_IPV4 | VPN_CAP_IPV6) == 0
    {
        return Err(VpnControlError::MissingRequiredCapabilities);
    }
    Ok(())
}

fn validate_sizes(max_ip_packet_len: u16, max_datagram_len: u16) -> Result<(), ()> {
    if usize::from(max_ip_packet_len) < 1280
        || usize::from(max_ip_packet_len) > VPN_MAX_IP_PACKET_LEN
        || usize::from(max_datagram_len) < VPN_MIN_QUIC_DATAGRAM_LEN
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn valid_ipv4_tunnel_address(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}

pub(crate) fn valid_ipv6_tunnel_address(address: Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_unicast_link_local()
        && !address.is_multicast()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn hello_accept_and_reject_roundtrip_exactly() {
        let hello = VpnControlMessage::Hello(valid_hello());
        assert_eq!(
            decode_vpn_control_message(&encode_vpn_control_message(hello).unwrap()).unwrap(),
            hello
        );

        let accept = VpnControlMessage::Accept(valid_accept());
        let encoded = encode_vpn_control_message(accept).unwrap();
        assert_eq!(encoded.len(), VPN_CONTROL_HEADER_LEN + VPN_ACCEPT_BODY_LEN);
        assert_eq!(decode_vpn_control_message(&encoded).unwrap(), accept);

        let reject = VpnControlMessage::Reject(VpnReject {
            reason: VpnRejectReason::ResourceLimit,
            retry_after_secs: 30,
        });
        assert_eq!(
            decode_vpn_control_message(&encode_vpn_control_message(reject).unwrap()).unwrap(),
            reject
        );
    }

    #[test]
    fn highest_common_wire_version_is_selected_without_guessing() {
        assert_eq!(select_vpn_wire_version(1, 3, 2, 4), Some(3));
        assert_eq!(select_vpn_wire_version(1, 1, 2, 2), None);
        assert_eq!(select_vpn_wire_version(2, 1, 1, 2), None);
        assert_eq!(select_vpn_wire_version(0, 1, 1, 1), None);
    }

    #[test]
    fn control_header_rejects_foreign_versions_types_and_lengths() {
        let mut encoded =
            encode_vpn_control_message(VpnControlMessage::Hello(valid_hello())).unwrap();
        encoded[..4].copy_from_slice(b"FWC2");
        assert_eq!(
            decode_vpn_control_message(&encoded).unwrap_err(),
            VpnControlError::InvalidMagic
        );
        encoded[..4].copy_from_slice(VPN_CONTROL_MAGIC);
        encoded[4] = 2;
        assert_eq!(
            decode_vpn_control_message(&encoded).unwrap_err(),
            VpnControlError::UnsupportedFormatVersion
        );
        encoded[4] = VPN_CONTROL_FORMAT_VERSION;
        encoded[5] = 99;
        assert_eq!(
            decode_vpn_control_message(&encoded).unwrap_err(),
            VpnControlError::UnknownMessageType
        );
        encoded[5] = VPN_CONTROL_HELLO;
        encoded[7] = encoded[7].wrapping_add(1);
        assert_eq!(
            decode_vpn_control_message(&encoded).unwrap_err(),
            VpnControlError::LengthMismatch
        );
    }

    #[test]
    fn required_capabilities_sizes_and_addresses_are_strict() {
        let mut hello = valid_hello();
        hello.capabilities &= !VPN_CAP_FRAGMENTATION;
        assert_eq!(
            hello.validate().unwrap_err(),
            VpnControlError::MissingRequiredCapabilities
        );
        hello = valid_hello();
        hello.capabilities |= 1 << 31;
        assert_eq!(
            hello.validate().unwrap_err(),
            VpnControlError::UnknownCapabilities
        );
        hello = valid_hello();
        hello.max_datagram_len = u16::try_from(VPN_MIN_QUIC_DATAGRAM_LEN - 1).unwrap();
        assert_eq!(hello.validate().unwrap_err(), VpnControlError::InvalidHello);

        let mut accept = valid_accept();
        accept.client_ipv4 = Some(Ipv4Addr::LOCALHOST);
        assert_eq!(
            accept.validate().unwrap_err(),
            VpnControlError::InvalidAddress
        );
        accept = valid_accept();
        accept.server_ipv6 = None;
        assert_eq!(
            accept.validate().unwrap_err(),
            VpnControlError::InvalidAccept
        );
    }

    #[test]
    fn accept_reserved_and_absent_address_bytes_must_be_zero() {
        let accept = VpnAccept {
            capabilities: VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4,
            client_ipv6: None,
            server_ipv6: None,
            ..valid_accept()
        };
        let mut encoded = encode_vpn_control_message(VpnControlMessage::Accept(accept)).unwrap();
        encoded[VPN_CONTROL_HEADER_LEN + 2] = 1;
        assert_eq!(
            decode_vpn_control_message(&encoded).unwrap_err(),
            VpnControlError::InvalidAccept
        );

        encoded = encode_vpn_control_message(VpnControlMessage::Accept(accept)).unwrap();
        encoded[VPN_CONTROL_HEADER_LEN + 28] = 1;
        assert_eq!(
            decode_vpn_control_message(&encoded).unwrap_err(),
            VpnControlError::InvalidAccept
        );
    }

    fn valid_hello() -> VpnHello {
        VpnHello {
            min_wire_version: VPN_WIRE_VERSION_V1,
            max_wire_version: VPN_WIRE_VERSION_V1,
            capabilities: VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4 | VPN_CAP_IPV6,
            max_ip_packet_len: u16::MAX,
            max_datagram_len: 1200,
        }
    }

    fn valid_accept() -> VpnAccept {
        VpnAccept {
            selected_wire_version: VPN_WIRE_VERSION_V1,
            capabilities: VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4 | VPN_CAP_IPV6,
            max_ip_packet_len: u16::MAX,
            max_datagram_len: 1200,
            session_generation: 7,
            client_ipv4: Some("10.77.0.2".parse().unwrap()),
            server_ipv4: Some("10.77.0.1".parse().unwrap()),
            client_ipv6: Some("fd77::2".parse::<Ipv6Addr>().unwrap()),
            server_ipv6: Some("fd77::1".parse::<Ipv6Addr>().unwrap()),
        }
    }
}

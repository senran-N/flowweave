use std::{error::Error, fmt, num::NonZeroU64, time::Duration};

use noq::{Connection, RecvStream, SendStream};
use tokio::time::timeout;

use crate::{
    VPN_CAP_IPV4, VPN_CAP_IPV6, VPN_CONTROL_MAX_MESSAGE_LEN, VPN_MAX_IP_PACKET_LEN,
    VPN_MIN_QUIC_DATAGRAM_LEN, VPN_REQUIRED_CAPABILITIES, VPN_WIRE_VERSION_V1, VpnAccept,
    VpnCertificateFingerprint, VpnControlError, VpnControlMessage, VpnHello, VpnIdentity,
    VpnIdentityAuthorizationError, VpnIdentityRegistry, VpnReject, VpnRejectReason,
    decode_vpn_control_message, encode_vpn_control_message, select_vpn_wire_version,
    verify_vpn_alpn, vpn_peer_certificate_fingerprint,
};

pub const VPN_DEFAULT_CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const VPN_MAX_CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
pub const VPN_CLOSE_CONTROL_FAILED: u32 = 0x105;
pub const VPN_CLOSE_CONTROL_REJECTED: u32 = 0x106;

const CONTROL_FAILED_REASON: &[u8] = b"control_failed";
const CONTROL_REJECTED_REASON: &[u8] = b"control_rejected";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnSessionError {
    InvalidHandshakeTimeout,
    AlpnNotNegotiated,
    MultipathNotNegotiated,
    DatagramNotNegotiated,
    DatagramTooSmall,
    PeerIdentityUnavailable,
    StreamOpenFailed,
    StreamAcceptFailed,
    ControlReadFailed,
    ControlWriteFailed,
    ControlFinishFailed,
    ControlTimeout,
    InvalidControl(VpnControlError),
    UnexpectedControlMessage,
    InvalidServerResponse,
    Rejected(VpnReject),
}

impl fmt::Display for VpnSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidControl(error) => write!(formatter, "vpn_session_invalid_control:{error}"),
            Self::Rejected(reject) => write!(
                formatter,
                "vpn_session_rejected:{}:{}",
                reject.reason as u16, reject.retry_after_secs
            ),
            other => formatter.write_str(match other {
                Self::InvalidHandshakeTimeout => "vpn_session_invalid_handshake_timeout",
                Self::AlpnNotNegotiated => "vpn_session_alpn_not_negotiated",
                Self::MultipathNotNegotiated => "vpn_session_multipath_not_negotiated",
                Self::DatagramNotNegotiated => "vpn_session_datagram_not_negotiated",
                Self::DatagramTooSmall => "vpn_session_datagram_too_small",
                Self::PeerIdentityUnavailable => "vpn_session_peer_identity_unavailable",
                Self::StreamOpenFailed => "vpn_session_stream_open_failed",
                Self::StreamAcceptFailed => "vpn_session_stream_accept_failed",
                Self::ControlReadFailed => "vpn_session_control_read_failed",
                Self::ControlWriteFailed => "vpn_session_control_write_failed",
                Self::ControlFinishFailed => "vpn_session_control_finish_failed",
                Self::ControlTimeout => "vpn_session_control_timeout",
                Self::UnexpectedControlMessage => "vpn_session_unexpected_control_message",
                Self::InvalidServerResponse => "vpn_session_invalid_server_response",
                Self::InvalidControl(_) | Self::Rejected(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnSessionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnSessionGeneration(NonZeroU64);

impl VpnSessionGeneration {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnServerNegotiationConfig {
    min_wire_version: u16,
    max_wire_version: u16,
    max_ip_packet_len: u16,
    max_datagram_len: u16,
}

impl VpnServerNegotiationConfig {
    pub fn new(
        min_wire_version: u16,
        max_wire_version: u16,
        max_ip_packet_len: u16,
        max_datagram_len: u16,
    ) -> Result<Self, VpnControlError> {
        if min_wire_version == 0 || min_wire_version > max_wire_version {
            return Err(VpnControlError::InvalidAccept);
        }
        let validation = VpnHello {
            min_wire_version,
            max_wire_version,
            capabilities: VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4,
            max_ip_packet_len,
            max_datagram_len,
        };
        validation.validate()?;
        Ok(Self {
            min_wire_version,
            max_wire_version,
            max_ip_packet_len,
            max_datagram_len,
        })
    }

    pub const fn min_wire_version(self) -> u16 {
        self.min_wire_version
    }

    pub const fn max_wire_version(self) -> u16 {
        self.max_wire_version
    }

    pub const fn max_ip_packet_len(self) -> u16 {
        self.max_ip_packet_len
    }

    pub const fn max_datagram_len(self) -> u16 {
        self.max_datagram_len
    }
}

impl Default for VpnServerNegotiationConfig {
    fn default() -> Self {
        Self {
            min_wire_version: VPN_WIRE_VERSION_V1,
            max_wire_version: VPN_WIRE_VERSION_V1,
            max_ip_packet_len: u16::try_from(VPN_MAX_IP_PACKET_LEN)
                .expect("VPN IP packet limit fits u16"),
            max_datagram_len: 1200,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VpnNegotiatedSession {
    identity: VpnIdentity,
    fingerprint: VpnCertificateFingerprint,
    accept: VpnAccept,
}

impl VpnNegotiatedSession {
    pub fn identity(&self) -> &VpnIdentity {
        &self.identity
    }

    pub const fn fingerprint(&self) -> VpnCertificateFingerprint {
        self.fingerprint
    }

    pub const fn accept(&self) -> VpnAccept {
        self.accept
    }
}

impl fmt::Debug for VpnNegotiatedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnNegotiatedSession")
            .field("identity", &self.identity)
            .field("fingerprint", &self.fingerprint)
            .field("wire_version", &self.accept.selected_wire_version)
            .field("capabilities", &self.accept.capabilities)
            .field("session_generation", &self.accept.session_generation)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnServerControlOutcome {
    Accepted(Box<VpnNegotiatedSession>),
    Rejected(VpnReject),
}

pub fn negotiate_vpn_hello(
    registry: &VpnIdentityRegistry,
    fingerprint: VpnCertificateFingerprint,
    hello: VpnHello,
    config: VpnServerNegotiationConfig,
    generation: VpnSessionGeneration,
) -> Result<VpnNegotiatedSession, VpnReject> {
    if hello.validate().is_err() {
        return Err(reject(VpnRejectReason::ProtocolViolation));
    }
    let identity = match registry.authorize(fingerprint) {
        Ok(identity) => identity,
        Err(VpnIdentityAuthorizationError::UnknownFingerprint) => {
            return Err(reject(VpnRejectReason::Unauthorized));
        }
        Err(VpnIdentityAuthorizationError::IdentityDisabled) => {
            return Err(reject(VpnRejectReason::IdentityDisabled));
        }
    };
    let Some(selected_wire_version) = select_vpn_wire_version(
        hello.min_wire_version,
        hello.max_wire_version,
        config.min_wire_version,
        config.max_wire_version,
    ) else {
        return Err(reject(VpnRejectReason::UnsupportedVersion));
    };

    let mut capabilities = VPN_REQUIRED_CAPABILITIES;
    let ipv4_enabled = hello.capabilities & VPN_CAP_IPV4 != 0 && identity.client_ipv4().is_some();
    let ipv6_enabled = hello.capabilities & VPN_CAP_IPV6 != 0 && identity.client_ipv6().is_some();
    if ipv4_enabled {
        capabilities |= VPN_CAP_IPV4;
    }
    if ipv6_enabled {
        capabilities |= VPN_CAP_IPV6;
    }
    if !ipv4_enabled && !ipv6_enabled {
        return Err(reject(VpnRejectReason::PolicyRejected));
    }

    let accept = VpnAccept {
        selected_wire_version,
        capabilities,
        max_ip_packet_len: hello.max_ip_packet_len.min(config.max_ip_packet_len),
        max_datagram_len: hello.max_datagram_len.min(config.max_datagram_len),
        session_generation: generation.get(),
        client_ipv4: if ipv4_enabled {
            identity.client_ipv4()
        } else {
            None
        },
        server_ipv4: if ipv4_enabled {
            registry.server_ipv4()
        } else {
            None
        },
        client_ipv6: if ipv6_enabled {
            identity.client_ipv6()
        } else {
            None
        },
        server_ipv6: if ipv6_enabled {
            registry.server_ipv6()
        } else {
            None
        },
    };
    if accept.validate().is_err() {
        return Err(reject(VpnRejectReason::PolicyRejected));
    }
    Ok(VpnNegotiatedSession {
        identity: identity.clone(),
        fingerprint,
        accept,
    })
}

pub async fn vpn_client_control_handshake(
    connection: &Connection,
    hello: VpnHello,
    handshake_timeout: Duration,
) -> Result<VpnAccept, VpnSessionError> {
    validate_handshake_timeout(handshake_timeout)?;
    let mut hello = hello;
    hello.validate().map_err(VpnSessionError::InvalidControl)?;
    verify_vpn_alpn(connection).map_err(|_| VpnSessionError::AlpnNotNegotiated)?;
    validate_multipath(connection)?;
    hello.max_datagram_len = hello
        .max_datagram_len
        .min(connection_datagram_limit(connection)?);

    let result = timeout(handshake_timeout, async {
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|_| VpnSessionError::StreamOpenFailed)?;
        write_control_message(&mut send, VpnControlMessage::Hello(hello)).await?;
        match read_control_message(&mut receive).await? {
            VpnControlMessage::Accept(accept) => {
                validate_server_accept(hello, accept)?;
                Ok(accept)
            }
            VpnControlMessage::Reject(reject) => Err(VpnSessionError::Rejected(reject)),
            VpnControlMessage::Hello(_) => Err(VpnSessionError::UnexpectedControlMessage),
        }
    })
    .await
    .map_err(|_| VpnSessionError::ControlTimeout)?;
    match result {
        Ok(accept) => Ok(accept),
        Err(error @ VpnSessionError::Rejected(_)) => {
            connection.close(VPN_CLOSE_CONTROL_REJECTED.into(), CONTROL_REJECTED_REASON);
            Err(error)
        }
        Err(error) => {
            connection.close(VPN_CLOSE_CONTROL_FAILED.into(), CONTROL_FAILED_REASON);
            Err(error)
        }
    }
}

pub async fn vpn_server_control_handshake(
    connection: &Connection,
    registry: &VpnIdentityRegistry,
    config: VpnServerNegotiationConfig,
    generation: VpnSessionGeneration,
    handshake_timeout: Duration,
) -> Result<VpnServerControlOutcome, VpnSessionError> {
    validate_handshake_timeout(handshake_timeout)?;
    verify_vpn_alpn(connection).map_err(|_| VpnSessionError::AlpnNotNegotiated)?;
    validate_multipath(connection)?;
    let mut config = config;
    config.max_datagram_len = config
        .max_datagram_len
        .min(connection_datagram_limit(connection)?);
    let fingerprint = vpn_peer_certificate_fingerprint(connection)
        .map_err(|_| VpnSessionError::PeerIdentityUnavailable)?;

    timeout(handshake_timeout, async {
        let (mut send, mut receive) = connection
            .accept_bi()
            .await
            .map_err(|_| VpnSessionError::StreamAcceptFailed)?;
        let hello = match read_control_message(&mut receive).await {
            Ok(VpnControlMessage::Hello(hello)) => hello,
            Ok(VpnControlMessage::Accept(_) | VpnControlMessage::Reject(_))
            | Err(VpnSessionError::InvalidControl(_)) => {
                let rejection = reject(VpnRejectReason::ProtocolViolation);
                write_control_message(&mut send, VpnControlMessage::Reject(rejection)).await?;
                return Ok(VpnServerControlOutcome::Rejected(rejection));
            }
            Err(error) => return Err(error),
        };

        match negotiate_vpn_hello(registry, fingerprint, hello, config, generation) {
            Ok(session) => {
                write_control_message(&mut send, VpnControlMessage::Accept(session.accept()))
                    .await?;
                Ok(VpnServerControlOutcome::Accepted(Box::new(session)))
            }
            Err(rejection) => {
                write_control_message(&mut send, VpnControlMessage::Reject(rejection)).await?;
                Ok(VpnServerControlOutcome::Rejected(rejection))
            }
        }
    })
    .await
    .map_err(|_| VpnSessionError::ControlTimeout)?
}

async fn write_control_message(
    send: &mut SendStream,
    message: VpnControlMessage,
) -> Result<(), VpnSessionError> {
    let encoded = encode_vpn_control_message(message).map_err(VpnSessionError::InvalidControl)?;
    send.write_all(&encoded)
        .await
        .map_err(|_| VpnSessionError::ControlWriteFailed)?;
    send.finish()
        .map_err(|_| VpnSessionError::ControlFinishFailed)
}

async fn read_control_message(
    receive: &mut RecvStream,
) -> Result<VpnControlMessage, VpnSessionError> {
    let encoded = receive
        .read_to_end(VPN_CONTROL_MAX_MESSAGE_LEN + 1)
        .await
        .map_err(|_| VpnSessionError::ControlReadFailed)?;
    decode_vpn_control_message(&encoded).map_err(VpnSessionError::InvalidControl)
}

fn validate_server_accept(hello: VpnHello, accept: VpnAccept) -> Result<(), VpnSessionError> {
    accept
        .validate()
        .map_err(|_| VpnSessionError::InvalidServerResponse)?;
    if accept.selected_wire_version < hello.min_wire_version
        || accept.selected_wire_version > hello.max_wire_version
        || accept.capabilities & !hello.capabilities != 0
        || accept.max_ip_packet_len > hello.max_ip_packet_len
        || accept.max_datagram_len > hello.max_datagram_len
    {
        return Err(VpnSessionError::InvalidServerResponse);
    }
    Ok(())
}

fn validate_handshake_timeout(value: Duration) -> Result<(), VpnSessionError> {
    if value.is_zero() || value > VPN_MAX_CONTROL_HANDSHAKE_TIMEOUT {
        return Err(VpnSessionError::InvalidHandshakeTimeout);
    }
    Ok(())
}

fn validate_multipath(connection: &Connection) -> Result<(), VpnSessionError> {
    if !connection.is_multipath_enabled() {
        return Err(VpnSessionError::MultipathNotNegotiated);
    }
    Ok(())
}

fn connection_datagram_limit(connection: &Connection) -> Result<u16, VpnSessionError> {
    let size = connection
        .max_datagram_size()
        .ok_or(VpnSessionError::DatagramNotNegotiated)?;
    if size < VPN_MIN_QUIC_DATAGRAM_LEN {
        return Err(VpnSessionError::DatagramTooSmall);
    }
    Ok(u16::try_from(size).unwrap_or(u16::MAX))
}

const fn reject(reason: VpnRejectReason) -> VpnReject {
    VpnReject {
        reason,
        retry_after_secs: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{
        VPN_CAP_FRAGMENTATION, VPN_CAP_MULTIPATH_REQUIRED, VPN_WIRE_VERSION_V1, VpnIdentityLimits,
        VpnIpNetwork,
    };

    use super::*;

    #[test]
    fn negotiation_authorizes_identity_and_intersects_address_families() {
        let fingerprint = VpnCertificateFingerprint::from_sha256([7; 32]);
        let registry = registry(fingerprint, true, false);
        let session = negotiate_vpn_hello(
            &registry,
            fingerprint,
            hello(VPN_CAP_IPV4 | VPN_CAP_IPV6),
            VpnServerNegotiationConfig::default(),
            VpnSessionGeneration::new(9).unwrap(),
        )
        .unwrap();
        assert_eq!(session.identity().client_id(), "client-a");
        assert_eq!(session.accept().session_generation, 9);
        assert_eq!(
            session.accept().capabilities,
            VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4
        );
        assert_eq!(
            session.accept().client_ipv4,
            Some("10.77.0.2".parse().unwrap())
        );
        assert_eq!(session.accept().client_ipv6, None);
    }

    #[test]
    fn negotiation_distinguishes_unknown_disabled_version_and_policy_rejection() {
        let fingerprint = VpnCertificateFingerprint::from_sha256([7; 32]);
        let generation = VpnSessionGeneration::new(1).unwrap();
        let config = VpnServerNegotiationConfig::default();
        assert_eq!(
            negotiate_vpn_hello(
                &registry(fingerprint, true, false),
                VpnCertificateFingerprint::from_sha256([8; 32]),
                hello(VPN_CAP_IPV4),
                config,
                generation,
            )
            .unwrap_err(),
            reject(VpnRejectReason::Unauthorized)
        );
        assert_eq!(
            negotiate_vpn_hello(
                &registry(fingerprint, false, false),
                fingerprint,
                hello(VPN_CAP_IPV4),
                config,
                generation,
            )
            .unwrap_err(),
            reject(VpnRejectReason::IdentityDisabled)
        );

        let mut unsupported = hello(VPN_CAP_IPV4);
        unsupported.min_wire_version = 2;
        unsupported.max_wire_version = 2;
        assert_eq!(
            negotiate_vpn_hello(
                &registry(fingerprint, true, false),
                fingerprint,
                unsupported,
                config,
                generation,
            )
            .unwrap_err(),
            reject(VpnRejectReason::UnsupportedVersion)
        );
        assert_eq!(
            negotiate_vpn_hello(
                &registry(fingerprint, true, false),
                fingerprint,
                hello(VPN_CAP_IPV6),
                config,
                generation,
            )
            .unwrap_err(),
            reject(VpnRejectReason::PolicyRejected)
        );
    }

    #[test]
    fn generation_timeout_and_server_response_contracts_are_bounded() {
        assert!(VpnSessionGeneration::new(0).is_none());
        assert_eq!(
            validate_handshake_timeout(Duration::ZERO).unwrap_err(),
            VpnSessionError::InvalidHandshakeTimeout
        );
        assert_eq!(
            validate_handshake_timeout(VPN_MAX_CONTROL_HANDSHAKE_TIMEOUT + Duration::from_nanos(1))
                .unwrap_err(),
            VpnSessionError::InvalidHandshakeTimeout
        );

        let hello = hello(VPN_CAP_IPV4);
        let mut accept = VpnAccept {
            selected_wire_version: VPN_WIRE_VERSION_V1,
            capabilities: VPN_REQUIRED_CAPABILITIES | VPN_CAP_IPV4,
            max_ip_packet_len: hello.max_ip_packet_len,
            max_datagram_len: hello.max_datagram_len,
            session_generation: 1,
            client_ipv4: Some("10.77.0.2".parse().unwrap()),
            server_ipv4: Some("10.77.0.1".parse().unwrap()),
            client_ipv6: None,
            server_ipv6: None,
        };
        validate_server_accept(hello, accept).unwrap();
        accept.selected_wire_version = 2;
        assert_eq!(
            validate_server_accept(hello, accept).unwrap_err(),
            VpnSessionError::InvalidServerResponse
        );
    }

    fn hello(address_capabilities: u32) -> VpnHello {
        VpnHello {
            min_wire_version: VPN_WIRE_VERSION_V1,
            max_wire_version: VPN_WIRE_VERSION_V1,
            capabilities: VPN_CAP_FRAGMENTATION | VPN_CAP_MULTIPATH_REQUIRED | address_capabilities,
            max_ip_packet_len: u16::MAX,
            max_datagram_len: 1200,
        }
    }

    fn registry(
        fingerprint: VpnCertificateFingerprint,
        enabled: bool,
        ipv6: bool,
    ) -> VpnIdentityRegistry {
        let client_ipv6 = ipv6.then(|| "fd77::2".parse::<Ipv6Addr>().unwrap());
        let mut destinations = vec![VpnIpNetwork::v4(Ipv4Addr::UNSPECIFIED, 0).unwrap()];
        if ipv6 {
            destinations.push(VpnIpNetwork::v6(Ipv6Addr::UNSPECIFIED, 0).unwrap());
        }
        let identity = VpnIdentity::new(
            "client-a",
            vec![fingerprint],
            enabled,
            Some("10.77.0.2".parse().unwrap()),
            client_ipv6,
            destinations,
            VpnIdentityLimits::default(),
        )
        .unwrap();
        VpnIdentityRegistry::new(
            Some("10.77.0.1".parse().unwrap()),
            Some("fd77::1".parse().unwrap()),
            vec![identity],
        )
        .unwrap()
    }
}

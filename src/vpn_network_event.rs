use std::{
    fmt, io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use tokio::io::unix::AsyncFd;

const NETLINK_RECEIVE_BUFFER_BYTES: usize = 64 * 1024;
const NETLINK_MAX_DISCARD_DATAGRAMS: usize = 64;
const NETLINK_ALIGNMENT: usize = 4;
const NETLINK_HEADER_LEN: usize = size_of::<libc::nlmsghdr>();
const NETLINK_LINK_PAYLOAD_LEN: usize = size_of::<libc::ifinfomsg>();
// Linux UAPI include/uapi/linux/if_addr.h struct ifaddrmsg and
// include/uapi/linux/rtnetlink.h struct rtmsg. libc 0.2.186 does not export them.
const NETLINK_ADDRESS_PAYLOAD_LEN: usize = 8;
const NETLINK_ROUTE_PAYLOAD_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnNetworkRecoveryEvent {
    LinkAvailable,
    AddressAdded,
    RouteAdded,
    EventsLost,
}

impl fmt::Display for VpnNetworkRecoveryEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LinkAvailable => "link_available",
            Self::AddressAdded => "address_added",
            Self::RouteAdded => "route_added",
            Self::EventsLost => "events_lost",
        })
    }
}

pub(crate) struct VpnNetworkEventMonitor {
    socket: AsyncFd<OwnedFd>,
    buffer: Vec<u8>,
}

impl VpnNetworkEventMonitor {
    pub(crate) fn start() -> io::Result<Self> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("vpn network monitor requires a Tokio runtime"))?;
        // SAFETY: socket has no pointer arguments. On success the returned descriptor is
        // immediately owned by OwnedFd and is closed on every later error path.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw_fd was returned as a new owned descriptor by socket above.
        let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        // SAFETY: sockaddr_nl is a plain C address structure. Zero is a valid value for the
        // private padding and for nl_pid, which asks the kernel to allocate the port id.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        address.nl_groups = network_event_groups();
        // SAFETY: address points to an initialized sockaddr_nl of the supplied exact size, and
        // socket remains alive for the duration of bind.
        let bind_result = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            socket: AsyncFd::new(socket)?,
            buffer: vec![0_u8; NETLINK_RECEIVE_BUFFER_BYTES],
        })
    }

    pub(crate) async fn wait_for_recovery_event(&mut self) -> io::Result<VpnNetworkRecoveryEvent> {
        loop {
            let socket = &self.socket;
            let buffer = &mut self.buffer;
            let mut readiness = socket.readable().await?;
            match readiness.try_io(|inner| receive_datagram(inner.get_ref().as_raw_fd(), buffer)) {
                Ok(Ok(bytes)) => match parse_recovery_event(&buffer[..bytes]) {
                    Ok(Some(event)) => return Ok(event),
                    Ok(None) => continue,
                    Err(error) => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, error.as_str()));
                    }
                },
                Ok(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    return Ok(VpnNetworkRecoveryEvent::EventsLost);
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }

    pub(crate) fn discard_pending(&mut self) -> io::Result<()> {
        for _ in 0..NETLINK_MAX_DISCARD_DATAGRAMS {
            match receive_datagram(self.socket.get_ref().as_raw_fd(), &mut self.buffer) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl fmt::Debug for VpnNetworkEventMonitor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnNetworkEventMonitor")
            .finish_non_exhaustive()
    }
}

const fn network_event_groups() -> u32 {
    (libc::RTMGRP_LINK
        | libc::RTMGRP_IPV4_IFADDR
        | libc::RTMGRP_IPV6_IFADDR
        | libc::RTMGRP_IPV4_ROUTE
        | libc::RTMGRP_IPV6_ROUTE) as u32
}

fn receive_datagram(fd: i32, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buffer is writable for buffer.len() bytes and fd is a nonblocking netlink socket
    // owned by the caller. recv does not retain the pointer after returning.
    let received = unsafe {
        libc::recv(
            fd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = usize::try_from(received)
        .map_err(|_| io::Error::other("vpn network monitor returned an invalid length"))?;
    if received == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "vpn network monitor socket closed",
        ));
    }
    if received > buffer.len() {
        return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
    }
    Ok(received)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlinkParseError {
    TruncatedHeader,
    InvalidMessageLength,
    TruncatedPayload,
    LengthOverflow,
}

impl NetlinkParseError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TruncatedHeader => "vpn network event header is truncated",
            Self::InvalidMessageLength => "vpn network event length is invalid",
            Self::TruncatedPayload => "vpn network event payload is truncated",
            Self::LengthOverflow => "vpn network event length overflows",
        }
    }
}

fn parse_recovery_event(
    datagram: &[u8],
) -> Result<Option<VpnNetworkRecoveryEvent>, NetlinkParseError> {
    let mut offset = 0_usize;
    let mut recovery_event = None;
    while offset < datagram.len() {
        let remaining = &datagram[offset..];
        if remaining.len() < NETLINK_HEADER_LEN {
            return Err(NetlinkParseError::TruncatedHeader);
        }
        let message_len = read_u32(&remaining[..4]) as usize;
        if message_len < NETLINK_HEADER_LEN || message_len > remaining.len() {
            return Err(NetlinkParseError::InvalidMessageLength);
        }
        let message_type = read_u16(&remaining[4..6]);
        let payload = &remaining[NETLINK_HEADER_LEN..message_len];
        match message_type {
            libc::RTM_NEWLINK => {
                require_payload(payload, NETLINK_LINK_PAYLOAD_LEN)?;
                if link_is_available(payload) {
                    recovery_event.get_or_insert(VpnNetworkRecoveryEvent::LinkAvailable);
                }
            }
            libc::RTM_NEWADDR => {
                require_payload(payload, NETLINK_ADDRESS_PAYLOAD_LEN)?;
                recovery_event.get_or_insert(VpnNetworkRecoveryEvent::AddressAdded);
            }
            libc::RTM_NEWROUTE => {
                require_payload(payload, NETLINK_ROUTE_PAYLOAD_LEN)?;
                recovery_event.get_or_insert(VpnNetworkRecoveryEvent::RouteAdded);
            }
            message_type if message_type == libc::NLMSG_OVERRUN as u16 => {
                recovery_event.get_or_insert(VpnNetworkRecoveryEvent::EventsLost);
            }
            _ => {}
        }

        let aligned_len = message_len
            .checked_add(NETLINK_ALIGNMENT - 1)
            .ok_or(NetlinkParseError::LengthOverflow)?
            & !(NETLINK_ALIGNMENT - 1);
        if aligned_len > remaining.len() {
            if message_len == remaining.len() {
                offset = datagram.len();
            } else {
                return Err(NetlinkParseError::InvalidMessageLength);
            }
        } else {
            offset = offset
                .checked_add(aligned_len)
                .ok_or(NetlinkParseError::LengthOverflow)?;
        }
    }
    Ok(recovery_event)
}

fn require_payload(payload: &[u8], minimum: usize) -> Result<(), NetlinkParseError> {
    if payload.len() < minimum {
        Err(NetlinkParseError::TruncatedPayload)
    } else {
        Ok(())
    }
}

fn link_is_available(payload: &[u8]) -> bool {
    let flags_offset = 8;
    let flags = read_u32(&payload[flags_offset..flags_offset + size_of::<u32>()]);
    let is_up = flags & libc::IFF_UP as u32 != 0;
    let has_carrier = flags & (libc::IFF_RUNNING | libc::IFF_LOWER_UP) as u32 != 0;
    is_up && has_carrier
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes.try_into().expect("validated netlink u16 slice"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes.try_into().expect("validated netlink u32 slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netlink_parser_accepts_only_operational_link_updates() {
        let available = message(
            libc::RTM_NEWLINK,
            &link_payload((libc::IFF_UP | libc::IFF_RUNNING) as u32),
        );
        assert_eq!(
            parse_recovery_event(&available),
            Ok(Some(VpnNetworkRecoveryEvent::LinkAvailable))
        );

        let administrative_down = message(libc::RTM_NEWLINK, &link_payload(0));
        assert_eq!(parse_recovery_event(&administrative_down), Ok(None));
        let no_carrier = message(libc::RTM_NEWLINK, &link_payload(libc::IFF_UP as u32));
        assert_eq!(parse_recovery_event(&no_carrier), Ok(None));
        let deleted = message(libc::RTM_DELLINK, &link_payload(u32::MAX));
        assert_eq!(parse_recovery_event(&deleted), Ok(None));
    }

    #[test]
    fn netlink_parser_accepts_address_route_and_overrun_recovery_hints() {
        assert_eq!(
            parse_recovery_event(&message(
                libc::RTM_NEWADDR,
                &[0_u8; NETLINK_ADDRESS_PAYLOAD_LEN],
            )),
            Ok(Some(VpnNetworkRecoveryEvent::AddressAdded))
        );
        assert_eq!(
            parse_recovery_event(&message(
                libc::RTM_NEWROUTE,
                &[0_u8; NETLINK_ROUTE_PAYLOAD_LEN],
            )),
            Ok(Some(VpnNetworkRecoveryEvent::RouteAdded))
        );
        assert_eq!(
            parse_recovery_event(&message(libc::NLMSG_OVERRUN as u16, &[])),
            Ok(Some(VpnNetworkRecoveryEvent::EventsLost))
        );
    }

    #[test]
    fn netlink_parser_walks_aligned_multipart_datagrams() {
        let mut datagram = message(libc::RTM_DELLINK, &link_payload(0));
        datagram.extend(message(
            libc::RTM_NEWROUTE,
            &[0_u8; NETLINK_ROUTE_PAYLOAD_LEN],
        ));
        assert_eq!(
            parse_recovery_event(&datagram),
            Ok(Some(VpnNetworkRecoveryEvent::RouteAdded))
        );
    }

    #[test]
    fn netlink_parser_rejects_truncation_and_invalid_lengths() {
        assert_eq!(
            parse_recovery_event(&[0_u8; NETLINK_HEADER_LEN - 1]),
            Err(NetlinkParseError::TruncatedHeader)
        );
        let mut invalid = message(libc::RTM_NEWLINK, &link_payload(u32::MAX));
        invalid[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(
            parse_recovery_event(&invalid),
            Err(NetlinkParseError::InvalidMessageLength)
        );
        assert_eq!(
            parse_recovery_event(&message(libc::RTM_NEWLINK, &[])),
            Err(NetlinkParseError::TruncatedPayload)
        );
    }

    #[test]
    fn network_recovery_event_names_are_stable_and_redacted() {
        assert_eq!(
            VpnNetworkRecoveryEvent::LinkAvailable.to_string(),
            "link_available"
        );
        assert_eq!(
            VpnNetworkRecoveryEvent::AddressAdded.to_string(),
            "address_added"
        );
        assert_eq!(
            VpnNetworkRecoveryEvent::RouteAdded.to_string(),
            "route_added"
        );
        assert_eq!(
            VpnNetworkRecoveryEvent::EventsLost.to_string(),
            "events_lost"
        );
    }

    fn message(message_type: u16, payload: &[u8]) -> Vec<u8> {
        let message_len = NETLINK_HEADER_LEN + payload.len();
        let aligned_len = (message_len + NETLINK_ALIGNMENT - 1) & !(NETLINK_ALIGNMENT - 1);
        let mut bytes = Vec::with_capacity(aligned_len);
        bytes.extend((message_len as u32).to_ne_bytes());
        bytes.extend(message_type.to_ne_bytes());
        bytes.extend(0_u16.to_ne_bytes());
        bytes.extend(0_u32.to_ne_bytes());
        bytes.extend(0_u32.to_ne_bytes());
        bytes.extend(payload);
        bytes.resize(aligned_len, 0);
        bytes
    }

    fn link_payload(flags: u32) -> Vec<u8> {
        let mut payload = vec![0_u8; NETLINK_LINK_PAYLOAD_LEN];
        payload[8..12].copy_from_slice(&flags.to_ne_bytes());
        payload
    }
}

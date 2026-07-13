use std::{
    error::Error,
    ffi::CString,
    fmt,
    fs::{self, File, OpenOptions},
    io, mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::FileTypeExt, fs::MetadataExt, fs::OpenOptionsExt},
    },
    str,
};

use crate::{
    VpnPacketDevice, VpnProductConfigError,
    vpn_product_config::{validate_vpn_tun_mtu, validate_vpn_tun_name},
};

const TUN_DEVICE_PATH: &str = "/dev/net/tun";
const TUN_DEVICE_MAJOR: u32 = 10;
const TUN_DEVICE_MINOR: u32 = 200;
const CAP_NET_ADMIN_NUMBER: u32 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnTunAttachError {
    InvalidName,
    InvalidMtu,
    RunningAsRoot,
    UserIdentityInspect(io::ErrorKind),
    ProcessStatusIo(io::ErrorKind),
    ProcessStatusInvalid,
    NetAdminCapabilityPresent,
    NoNewPrivilegesDisabled,
    RuntimeUnavailable,
    InterfaceNotFound,
    InterfaceInspect(io::ErrorKind),
    InterfaceDown,
    InterfaceMtuInvalid,
    InterfaceMtuMismatch,
    TunDeviceOpen(io::ErrorKind),
    InvalidTunCharacterDevice,
    Attach(io::ErrorKind),
    Inspect(io::ErrorKind),
    NameMismatch,
    InvalidFlags,
    InterfaceIndexChanged,
    PacketDevice(io::ErrorKind),
}

impl fmt::Display for VpnTunAttachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserIdentityInspect(kind) => {
                write!(formatter, "vpn_tun_user_identity_inspect:{kind:?}")
            }
            Self::ProcessStatusIo(kind) => {
                write!(formatter, "vpn_tun_process_status_io:{kind:?}")
            }
            Self::InterfaceInspect(kind) => {
                write!(formatter, "vpn_tun_interface_inspect:{kind:?}")
            }
            Self::TunDeviceOpen(kind) => write!(formatter, "vpn_tun_device_open:{kind:?}"),
            Self::Attach(kind) => write!(formatter, "vpn_tun_attach:{kind:?}"),
            Self::Inspect(kind) => write!(formatter, "vpn_tun_inspect:{kind:?}"),
            Self::PacketDevice(kind) => write!(formatter, "vpn_tun_packet_device:{kind:?}"),
            other => formatter.write_str(match other {
                Self::InvalidName => "vpn_tun_invalid_name",
                Self::InvalidMtu => "vpn_tun_invalid_mtu",
                Self::RunningAsRoot => "vpn_tun_running_as_root",
                Self::ProcessStatusInvalid => "vpn_tun_process_status_invalid",
                Self::NetAdminCapabilityPresent => "vpn_tun_net_admin_capability_present",
                Self::NoNewPrivilegesDisabled => "vpn_tun_no_new_privileges_disabled",
                Self::RuntimeUnavailable => "vpn_tun_runtime_unavailable",
                Self::InterfaceNotFound => "vpn_tun_interface_not_found",
                Self::InterfaceDown => "vpn_tun_interface_down",
                Self::InterfaceMtuInvalid => "vpn_tun_interface_mtu_invalid",
                Self::InterfaceMtuMismatch => "vpn_tun_interface_mtu_mismatch",
                Self::InvalidTunCharacterDevice => "vpn_tun_invalid_character_device",
                Self::NameMismatch => "vpn_tun_name_mismatch",
                Self::InvalidFlags => "vpn_tun_invalid_flags",
                Self::InterfaceIndexChanged => "vpn_tun_interface_index_changed",
                Self::UserIdentityInspect(_)
                | Self::ProcessStatusIo(_)
                | Self::InterfaceInspect(_)
                | Self::TunDeviceOpen(_)
                | Self::Attach(_)
                | Self::Inspect(_)
                | Self::PacketDevice(_) => unreachable!(),
            }),
        }
    }
}

impl Error for VpnTunAttachError {}

pub struct VpnAttachedTun {
    name: String,
    interface_index: u32,
    mtu: u16,
    flags: i16,
    device: VpnPacketDevice,
}

impl VpnAttachedTun {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn interface_index(&self) -> u32 {
        self.interface_index
    }

    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    pub const fn flags(&self) -> i16 {
        self.flags
    }

    pub fn device(&self) -> &VpnPacketDevice {
        &self.device
    }

    pub fn into_device(self) -> VpnPacketDevice {
        self.device
    }
}

impl fmt::Debug for VpnAttachedTun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VpnAttachedTun")
            .field("name", &self.name)
            .field("interface_index", &self.interface_index)
            .field("mtu", &self.mtu)
            .field("flags", &format_args!("0x{:04x}", self.flags as u16))
            .finish_non_exhaustive()
    }
}

pub fn attach_existing_vpn_tun(
    name: &str,
    expected_mtu: u16,
) -> Result<VpnAttachedTun, VpnTunAttachError> {
    validate_vpn_tun_name(name).map_err(|error| match error {
        VpnProductConfigError::InvalidTunName => VpnTunAttachError::InvalidName,
        _ => unreachable!("TUN name validation only returns InvalidTunName"),
    })?;
    validate_vpn_tun_mtu(expected_mtu).map_err(|error| match error {
        VpnProductConfigError::InvalidTunMtu => VpnTunAttachError::InvalidMtu,
        _ => unreachable!("TUN MTU validation only returns InvalidTunMtu"),
    })?;
    ensure_unprivileged_process()?;
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(VpnTunAttachError::RuntimeUnavailable);
    }
    let name = CString::new(name).map_err(|_| VpnTunAttachError::InvalidName)?;
    let initial_interface_index = interface_index(&name)?;
    validate_interface_state(inspect_interface(name.to_bytes())?, expected_mtu)?;
    let file = open_tun_device()?;
    let requested_name = name.to_bytes();
    let mut request = make_ifreq(requested_name, (libc::IFF_TUN | libc::IFF_NO_PI) as i16);
    // SAFETY: request points to a fully initialized ifreq and file is an open /dev/net/tun fd.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &mut request) } < 0 {
        return Err(VpnTunAttachError::Attach(io::Error::last_os_error().kind()));
    }

    let mut actual = make_ifreq(&[], 0);
    // SAFETY: actual points to writable ifreq storage and file remains open and attached.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNGETIFF as _, &mut actual) } < 0 {
        return Err(VpnTunAttachError::Inspect(
            io::Error::last_os_error().kind(),
        ));
    }
    let actual_name = ifreq_name(&actual)?;
    if actual_name != requested_name {
        return Err(VpnTunAttachError::NameMismatch);
    }
    // SAFETY: TUNGETIFF initialized the ifru_flags member of this ifreq.
    let flags = unsafe { actual.ifr_ifru.ifru_flags };
    validate_tun_flags(flags)?;
    if interface_index(&name)? != initial_interface_index {
        return Err(VpnTunAttachError::InterfaceIndexChanged);
    }
    validate_interface_state(inspect_interface(requested_name)?, expected_mtu)?;
    let device = VpnPacketDevice::from_file(file)
        .map_err(|error| VpnTunAttachError::PacketDevice(error.kind()))?;
    Ok(VpnAttachedTun {
        name: str::from_utf8(requested_name)
            .expect("validated TUN names are ASCII")
            .to_owned(),
        interface_index: initial_interface_index,
        mtu: expected_mtu,
        flags,
        device,
    })
}

fn ensure_unprivileged_process() -> Result<(), VpnTunAttachError> {
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    // SAFETY: all three pointers reference writable uid_t values owned by this stack frame.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } < 0 {
        return Err(VpnTunAttachError::UserIdentityInspect(
            io::Error::last_os_error().kind(),
        ));
    }
    if [real_uid, effective_uid, saved_uid].contains(&0) {
        return Err(VpnTunAttachError::RunningAsRoot);
    }
    let privileges = process_privileges()?;
    if privileges.capabilities & (1_u64 << CAP_NET_ADMIN_NUMBER) != 0 {
        return Err(VpnTunAttachError::NetAdminCapabilityPresent);
    }
    if !privileges.no_new_privileges {
        return Err(VpnTunAttachError::NoNewPrivilegesDisabled);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessPrivileges {
    capabilities: u64,
    no_new_privileges: bool,
}

fn process_privileges() -> Result<ProcessPrivileges, VpnTunAttachError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| VpnTunAttachError::ProcessStatusIo(error.kind()))?;
    parse_process_privileges(&status).ok_or(VpnTunAttachError::ProcessStatusInvalid)
}

fn parse_process_privileges(status: &str) -> Option<ProcessPrivileges> {
    let capabilities = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
        .into_iter()
        .map(|field| parse_status_u64(status, field, 16))
        .try_fold(0_u64, |combined, value| Some(combined | value?))?;
    let no_new_privileges = match parse_status_u64(status, "NoNewPrivs:", 10)? {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some(ProcessPrivileges {
        capabilities,
        no_new_privileges,
    })
}

fn parse_status_u64(status: &str, field: &str, radix: u32) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))?
        .trim();
    u64::from_str_radix(value, radix).ok()
}

fn interface_index(name: &CString) -> Result<u32, VpnTunAttachError> {
    // SAFETY: name is a live NUL-terminated interface name.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(VpnTunAttachError::InterfaceNotFound);
    }
    Ok(index)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterfaceState {
    mtu: u16,
    flags: i16,
}

fn inspect_interface(name: &[u8]) -> Result<InterfaceState, VpnTunAttachError> {
    // SAFETY: socket has valid constants and returns a new descriptor or -1.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(VpnTunAttachError::InterfaceInspect(
            io::Error::last_os_error().kind(),
        ));
    }
    // SAFETY: socket is a newly owned descriptor and is transferred exactly once to OwnedFd.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };

    let mut mtu_request = make_ifreq(name, 0);
    // SAFETY: mtu_request is writable ifreq storage and socket is a live datagram socket.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU as _, &mut mtu_request) } < 0 {
        return Err(VpnTunAttachError::InterfaceInspect(
            io::Error::last_os_error().kind(),
        ));
    }
    // SAFETY: SIOCGIFMTU initialized the ifru_mtu member.
    let mtu = u16::try_from(unsafe { mtu_request.ifr_ifru.ifru_mtu })
        .map_err(|_| VpnTunAttachError::InterfaceMtuInvalid)?;

    let mut flags_request = make_ifreq(name, 0);
    // SAFETY: flags_request is writable ifreq storage and socket is a live datagram socket.
    if unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCGIFFLAGS as _,
            &mut flags_request,
        )
    } < 0
    {
        return Err(VpnTunAttachError::InterfaceInspect(
            io::Error::last_os_error().kind(),
        ));
    }
    // SAFETY: SIOCGIFFLAGS initialized the ifru_flags member.
    let flags = unsafe { flags_request.ifr_ifru.ifru_flags };
    Ok(InterfaceState { mtu, flags })
}

fn validate_interface_state(
    state: InterfaceState,
    expected_mtu: u16,
) -> Result<(), VpnTunAttachError> {
    if state.mtu != expected_mtu {
        return Err(VpnTunAttachError::InterfaceMtuMismatch);
    }
    if i32::from(state.flags) & libc::IFF_UP == 0 {
        return Err(VpnTunAttachError::InterfaceDown);
    }
    Ok(())
}

fn open_tun_device() -> Result<File, VpnTunAttachError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(TUN_DEVICE_PATH)
        .map_err(|error| VpnTunAttachError::TunDeviceOpen(error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| VpnTunAttachError::TunDeviceOpen(error.kind()))?;
    let device = metadata.rdev();
    if !metadata.file_type().is_char_device()
        || libc::major(device) != TUN_DEVICE_MAJOR
        || libc::minor(device) != TUN_DEVICE_MINOR
    {
        return Err(VpnTunAttachError::InvalidTunCharacterDevice);
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

fn ifreq_name(request: &libc::ifreq) -> Result<&[u8], VpnTunAttachError> {
    let end = request
        .ifr_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(request.ifr_name.len());
    let bytes = &request.ifr_name[..end];
    if !bytes.iter().all(|byte| (0..=0x7f).contains(byte)) {
        return Err(VpnTunAttachError::NameMismatch);
    }
    // c_char may be signed; validated ASCII bytes preserve their low 7 bits.
    Ok(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), bytes.len()) })
}

fn validate_tun_flags(flags: i16) -> Result<(), VpnTunAttachError> {
    let flags = i32::from(flags);
    let required = libc::IFF_TUN | libc::IFF_NO_PI;
    let forbidden = libc::IFF_TAP | libc::IFF_VNET_HDR | libc::IFF_MULTI_QUEUE;
    if flags & required != required || flags & forbidden != 0 {
        return Err(VpnTunAttachError::InvalidFlags);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_parser_and_security_contract_are_strict() {
        let safe = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
        assert_eq!(
            parse_process_privileges(safe),
            Some(ProcessPrivileges {
                capabilities: 0,
                no_new_privileges: true,
            })
        );
        for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let unsafe_status = safe.replacen(
                &format!("{field}:\t0000000000000000"),
                &format!("{field}:\t0000000000001000"),
                1,
            );
            assert_ne!(
                parse_process_privileges(&unsafe_status)
                    .unwrap()
                    .capabilities
                    & (1_u64 << CAP_NET_ADMIN_NUMBER),
                0
            );
        }
        assert_eq!(
            parse_process_privileges(&safe.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")),
            Some(ProcessPrivileges {
                capabilities: 0,
                no_new_privileges: false,
            })
        );
        assert_eq!(parse_process_privileges("CapEff:\tnot-hex\n"), None);
    }

    #[test]
    fn tun_flags_require_layer_three_packets_without_pi_or_offloads() {
        validate_tun_flags((libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_PERSIST) as i16).unwrap();
        for flags in [
            libc::IFF_TUN,
            libc::IFF_TAP | libc::IFF_NO_PI,
            libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR,
            libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE,
        ] {
            assert_eq!(
                validate_tun_flags(flags as i16).unwrap_err(),
                VpnTunAttachError::InvalidFlags
            );
        }
    }

    #[test]
    fn missing_interface_and_interface_state_validation_fail_closed() {
        let name = CString::new("fw-no-such-tun").unwrap();
        assert_eq!(
            interface_index(&name).unwrap_err(),
            VpnTunAttachError::InterfaceNotFound
        );
        assert_eq!(
            validate_interface_state(
                InterfaceState {
                    mtu: 1400,
                    flags: libc::IFF_UP as i16,
                },
                1500,
            )
            .unwrap_err(),
            VpnTunAttachError::InterfaceMtuMismatch
        );
        assert_eq!(
            validate_interface_state(
                InterfaceState {
                    mtu: 1500,
                    flags: 0,
                },
                1500,
            )
            .unwrap_err(),
            VpnTunAttachError::InterfaceDown
        );
    }
}

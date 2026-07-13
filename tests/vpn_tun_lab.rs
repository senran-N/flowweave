#![cfg(target_os = "linux")]

use std::{
    fs,
    path::{Path, PathBuf},
};

use flowweave_lab::{VpnTunAttachError, attach_existing_vpn_tun};

#[test]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
fn root_process_is_rejected_before_tun_access() {
    assert_isolated_lab();
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1500).unwrap_err(),
        VpnTunAttachError::RunningAsRoot
    );
}

#[test]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
fn process_without_no_new_privileges_is_rejected() {
    assert_isolated_lab();
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1500).unwrap_err(),
        VpnTunAttachError::NoNewPrivilegesDisabled
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
async fn down_tun_is_rejected_before_attach() {
    assert_isolated_lab();
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1500).unwrap_err(),
        VpnTunAttachError::InterfaceDown
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "必须通过 scripts/run_vpn_tun_lab.sh 在一次性 user+network namespace 中运行"]
async fn existing_tun_is_attached_only_by_unprivileged_owner() {
    assert_isolated_lab();
    assert_ne!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        attach_existing_vpn_tun("fwvpn0", 1400).unwrap_err(),
        VpnTunAttachError::InterfaceMtuMismatch
    );
    let attached = attach_existing_vpn_tun("fwvpn0", 1500).unwrap();
    assert_eq!(attached.name(), "fwvpn0");
    assert!(attached.interface_index() > 0);
    assert_eq!(attached.mtu(), 1500);
    assert_ne!(attached.flags() as i32 & libc::IFF_TUN, 0);
    assert_ne!(attached.flags() as i32 & libc::IFF_NO_PI, 0);
    assert_eq!(attached.flags() as i32 & libc::IFF_VNET_HDR, 0);
    assert!(Path::new("/dev/net/tun").exists());
    drop(attached);

    assert_eq!(
        attach_existing_vpn_tun("fw-missing0", 1500).unwrap_err(),
        VpnTunAttachError::InterfaceNotFound
    );
}

fn assert_isolated_lab() {
    assert_eq!(std::env::var("FLOWWEAVE_TUN_LAB").as_deref(), Ok("1"));
    let host_netns = PathBuf::from(std::env::var_os("FLOWWEAVE_HOST_NETNS").unwrap());
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        host_netns,
        "TUN attach lab refuses to run in the host network namespace"
    );
}

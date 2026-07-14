#![cfg(target_os = "linux")]

use std::{fs, future::pending, path::PathBuf};

use flowweave_lab::attach_existing_vpn_tun;

#[tokio::test(flavor = "current_thread")]
#[ignore = "必须通过 scripts/run_vpn_network_lab.sh 在一次性 user+network namespace 中运行"]
async fn attached_data_process_blocks_privileged_cleanup() {
    assert_isolated_lab();
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let marker = PathBuf::from(
        std::env::var_os("FLOWWEAVE_VPN_NETWORK_HOLD_MARKER")
            .expect("missing FLOWWEAVE_VPN_NETWORK_HOLD_MARKER"),
    );
    let attached = attach_existing_vpn_tun("fwvpn0", 1500).unwrap();
    fs::write(marker, b"ready").unwrap();
    let _held_attachment = attached;
    pending::<()>().await;
}

fn assert_isolated_lab() {
    assert_eq!(
        std::env::var("FLOWWEAVE_VPN_NETWORK_LAB").as_deref(),
        Ok("1")
    );
    let current = fs::read_link("/proc/self/ns/net").unwrap();
    let host = std::env::var("FLOWWEAVE_HOST_NETNS").unwrap();
    assert_ne!(current.to_string_lossy(), host);
}

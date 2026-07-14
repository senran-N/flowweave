#![cfg(target_os = "linux")]

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::linux::net::SocketAddrExt,
    os::unix::{ffi::OsStrExt, net::UnixDatagram},
    path::{Path, PathBuf},
    process,
    time::Duration,
};

use tokio::{signal::unix::SignalKind, time::sleep};

#[tokio::test(flavor = "current_thread")]
#[ignore = "必须通过 scripts/run_vpn_systemd_lab.sh 由真实 user systemd manager 运行"]
async fn vpn_systemd_lifecycle_role() {
    assert_eq!(env::var("FLOWWEAVE_VPN_SYSTEMD_LAB").as_deref(), Ok("1"));
    let stage = env::var("FLOWWEAVE_VPN_SYSTEMD_STAGE").unwrap();
    let scenario = env::var("FLOWWEAVE_VPN_SYSTEMD_SCENARIO").unwrap();
    let directory = lab_directory();
    match stage.as_str() {
        "prepare" | "activate" | "deactivate" | "cleanup" => {
            append_stage(&directory, &stage);
            if scenario == "prepare_failure" && stage == "prepare"
                || scenario == "activate_failure" && stage == "activate"
            {
                process::exit(42);
            }
        }
        "data" => run_data_role(&directory, &scenario).await,
        _ => panic!("invalid systemd lab stage"),
    }
}

async fn run_data_role(directory: &Path, scenario: &str) {
    append_stage(directory, "data_start");
    if scenario == "before_ready_failure" {
        append_stage(directory, "data_before_ready_failure");
        process::exit(43);
    }

    let mut terminate = tokio::signal::unix::signal(SignalKind::terminate()).unwrap();
    append_stage(directory, "data_ready");
    send_notify(b"READY=1\nSTATUS=FlowWeave VPN systemd lifecycle lab ready");
    if scenario == "unexpected_exit" {
        let trigger = directory.join("unexpected-exit.trigger");
        loop {
            if trigger.exists() {
                append_stage(directory, "data_unexpected_exit");
                process::exit(44);
            }
            tokio::select! {
                _ = terminate.recv() => {
                    append_stage(directory, "data_stopped");
                    send_notify(b"STOPPING=1");
                    return;
                }
                () = sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    terminate.recv().await;
    append_stage(directory, "data_stopped");
    send_notify(b"STOPPING=1");
}

fn append_stage(directory: &Path, stage: &str) {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let capabilities = status_field(&status, "CapEff:");
    let no_new_privileges = status_field(&status, "NoNewPrivs:");
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("lifecycle.log"))
        .unwrap();
    writeln!(
        log,
        "{stage} uid={} capabilities={capabilities} no_new_privileges={no_new_privileges}",
        // SAFETY: geteuid has no pointer arguments and only returns the current process identity.
        unsafe { libc::geteuid() }
    )
    .unwrap();
    log.sync_data().unwrap();
}

fn status_field<'a>(status: &'a str, field: &str) -> &'a str {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(str::trim)
        .unwrap()
}

fn send_notify(message: &[u8]) {
    let socket = env::var_os("NOTIFY_SOCKET").unwrap();
    let name = socket.as_bytes();
    assert!(!name.is_empty() && !name.contains(&0));
    let datagram = UnixDatagram::unbound().unwrap();
    if name[0] == b'@' {
        let address = std::os::unix::net::SocketAddr::from_abstract_name(&name[1..]).unwrap();
        datagram.send_to_addr(message, &address).unwrap();
    } else {
        datagram.send_to(message, Path::new(&socket)).unwrap();
    }
}

fn lab_directory() -> PathBuf {
    let path = PathBuf::from(env::var_os("FLOWWEAVE_VPN_SYSTEMD_DIR").unwrap());
    let runtime = PathBuf::from(env::var_os("XDG_RUNTIME_DIR").unwrap());
    assert!(path.starts_with(&runtime));
    assert!(
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("flowweave-vpn-systemd-state."))
    );
    path
}

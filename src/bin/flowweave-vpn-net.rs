#![cfg(target_os = "linux")]

use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use flowweave_lab::{cleanup_vpn_network, prepare_vpn_client_network, prepare_vpn_server_network};

fn main() -> ExitCode {
    match run() {
        Ok(outcome) => {
            println!("{outcome}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<&'static str, String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("flowweave-vpn-net"));
    let command = arguments.next();
    match command.as_deref().and_then(|value| value.to_str()) {
        Some("prepare-client") | Some("prepare-server") => {
            let config = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            let state = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            let owner_uid = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .and_then(|value| {
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|owner_uid| *owner_uid != 0 && owner_uid.to_string() == value)
                })
                .ok_or_else(|| "vpn_network_invalid_owner_uid".to_owned())?;
            if arguments.next().is_some() {
                return Err(usage(&program));
            }
            let outcome =
                if command.as_deref().and_then(|value| value.to_str()) == Some("prepare-client") {
                    prepare_vpn_client_network(&config, &state, owner_uid)
                } else {
                    prepare_vpn_server_network(&config, &state, owner_uid)
                }
                .map_err(|error| error.to_string())?;
            Ok(outcome.as_str())
        }
        Some("cleanup") => {
            let state = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            if arguments.next().is_some() {
                return Err(usage(&program));
            }
            cleanup_vpn_network(&state)
                .map(|outcome| outcome.as_str())
                .map_err(|error| error.to_string())
        }
        _ => Err(usage(&program)),
    }
}

fn usage(program: &OsString) -> String {
    format!(
        "用法：{} <prepare-client|prepare-server> <product-config> <state-path> <owner-uid> | cleanup <state-path>",
        PathBuf::from(program).display()
    )
}

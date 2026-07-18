#![cfg(target_os = "linux")]

use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use flowweave_lab::{
    request_vpn_client_credential_reload, request_vpn_server_identity_reload,
    run_vpn_client_product_process, run_vpn_server_product_process,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("flowweave-vpn"));
    let command = arguments.next();
    let path = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        return Err(usage(&program));
    }

    match (command.as_deref().and_then(|value| value.to_str()), path) {
        (Some("server"), Some(config)) => run_vpn_server_product_process(config)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string()),
        (Some("client"), Some(config)) => run_vpn_client_product_process(config)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string()),
        (Some("reload-server"), Some(socket)) => request_vpn_server_identity_reload(socket)
            .await
            .map_err(|error| error.to_string()),
        (Some("reload-client"), Some(socket)) => request_vpn_client_credential_reload(socket)
            .await
            .map_err(|error| error.to_string()),
        _ => Err(usage(&program)),
    }
}

fn usage(program: &OsString) -> String {
    format!(
        "用法：{} <server|client> <config-path> | reload-<server|client> <control-socket>",
        PathBuf::from(program).display()
    )
}

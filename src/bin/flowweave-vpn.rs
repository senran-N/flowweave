#![cfg(target_os = "linux")]

use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use flowweave_lab::{run_vpn_client_product_process, run_vpn_server_product_process};

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
    let role = arguments.next();
    let config = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| usage(&program))?;
    if arguments.next().is_some() {
        return Err(usage(&program));
    }

    match role.as_deref().and_then(|value| value.to_str()) {
        Some("server") => run_vpn_server_product_process(config)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string()),
        Some("client") => run_vpn_client_product_process(config)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string()),
        _ => Err(usage(&program)),
    }
}

fn usage(program: &OsString) -> String {
    format!(
        "用法：{} <server|client> <config-path>",
        PathBuf::from(program).display()
    )
}

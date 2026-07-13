use std::{env, ffi::OsString, io, path::PathBuf};

use flowweave_lab::{LabResult, run_proxy_client, run_proxy_server};

#[tokio::main]
async fn main() -> LabResult<()> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("flowweave-proxy"));
    let mode = arguments.next();
    let config = arguments.next();
    if arguments.next().is_some() {
        return Err(usage(&program));
    }
    let config = config.map(PathBuf::from).ok_or_else(|| usage(&program))?;
    match mode.as_deref().and_then(|mode| mode.to_str()) {
        Some("server") => run_proxy_server(config).await,
        Some("client") => run_proxy_client(config).await,
        _ => Err(usage(&program)),
    }
}

fn usage(program: &OsString) -> flowweave_lab::LabError {
    io::Error::other(format!(
        "用法：{} <server|client> <config-path>",
        PathBuf::from(program).display()
    ))
    .into()
}

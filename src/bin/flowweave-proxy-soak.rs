use std::{env, ffi::OsString, io, path::PathBuf, process::ExitCode, time::Duration};

use flowweave_lab::{LabResult, ProxySoakConfig, ProxySoakReport, run_proxy_soak};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(report) => {
            println!("{}", report.to_json());
            if report.stage_pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("flowweave-proxy-soak: {error}");
            ExitCode::from(2)
        }
    }
}

async fn run() -> LabResult<ProxySoakReport> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("flowweave-proxy-soak"));
    let mut config = ProxySoakConfig::default();
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--duration-secs") => {
                config.duration =
                    Duration::from_secs(parse_u64(arguments.next(), "--duration-secs")?)
            }
            Some("--workers") => config.workers = parse_usize(arguments.next(), "--workers")?,
            Some("--payload-bytes") => {
                config.payload_bytes = parse_usize(arguments.next(), "--payload-bytes")?
            }
            Some("--inter-flow-delay-ms") => {
                config.inter_flow_delay =
                    Duration::from_millis(parse_u64(arguments.next(), "--inter-flow-delay-ms")?)
            }
            Some("--single-path") => config.multipath = false,
            Some("--help" | "-h") => return Err(usage(&program)),
            _ => return Err(usage(&program)),
        }
    }
    run_proxy_soak(config).await
}

fn parse_u64(value: Option<OsString>, option: &str) -> LabResult<u64> {
    value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| io::Error::other(format!("{option} 缺少非负整数")))?
        .parse::<u64>()
        .map_err(|error| io::Error::other(format!("{option} 不是非负整数：{error}")).into())
}

fn parse_usize(value: Option<OsString>, option: &str) -> LabResult<usize> {
    let value = parse_u64(value, option)?;
    usize::try_from(value)
        .map_err(|_| io::Error::other(format!("{option} 超出平台整数范围")).into())
}

fn usage(program: &OsString) -> flowweave_lab::LabError {
    io::Error::other(format!(
        "用法：{} [--duration-secs N] [--workers N] [--payload-bytes N] [--inter-flow-delay-ms N] [--single-path]",
        PathBuf::from(program).display()
    ))
    .into()
}

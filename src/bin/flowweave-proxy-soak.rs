use std::{
    collections::VecDeque, env, ffi::OsString, io, net::SocketAddr, path::PathBuf,
    process::ExitCode, time::Duration,
};

use flowweave_lab::{
    LabResult, ProxyPublicSoakConfig, ProxyPublicSoakReport, ProxySoakConfig, ProxySoakReport,
    run_proxy_public_soak_with_shutdown, run_proxy_soak, run_proxy_soak_echo_server,
};
use tokio::sync::watch;

enum SoakCommand {
    Local(ProxySoakConfig),
    PublicWorkload(ProxyPublicSoakConfig),
    EchoServer(SocketAddr),
}

#[tokio::main]
async fn main() -> ExitCode {
    let command = match parse_command() {
        Ok(command) => command,
        Err(error) => {
            eprintln!("flowweave-proxy-soak: {error}");
            return ExitCode::from(2);
        }
    };
    match command {
        SoakCommand::Local(config) => match run_proxy_soak(config).await {
            Ok(report) => finish_local(report),
            Err(error) => fail_runtime(error),
        },
        SoakCommand::PublicWorkload(config) => match run_public_workload(config).await {
            Ok(report) => finish_public(report),
            Err(error) => fail_runtime(error),
        },
        SoakCommand::EchoServer(listen) => match run_proxy_soak_echo_server(listen).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail_runtime(error),
        },
    }
}

fn finish_local(report: ProxySoakReport) -> ExitCode {
    println!("{}", report.to_json());
    pass_exit_code(report.stage_pass)
}

fn finish_public(report: ProxyPublicSoakReport) -> ExitCode {
    println!("{}", report.to_json());
    pass_exit_code(report.stage_pass)
}

fn fail_runtime(error: flowweave_lab::LabError) -> ExitCode {
    eprintln!("flowweave-proxy-soak: {error}");
    ExitCode::from(2)
}

const fn pass_exit_code(stage_pass: bool) -> ExitCode {
    if stage_pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run_public_workload(config: ProxyPublicSoakConfig) -> LabResult<ProxyPublicSoakReport> {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let signal_task = tokio::spawn(async move {
        if wait_for_shutdown_signal().await.is_ok() {
            let _ = shutdown.send(true);
        }
    });
    let report = run_proxy_public_soak_with_shutdown(config, shutdown_rx, |checkpoint| {
        println!("{checkpoint}");
    })
    .await;
    signal_task.abort();
    let _ = signal_task.await;
    report
}

fn parse_command() -> LabResult<SoakCommand> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("flowweave-proxy-soak"));
    let mut arguments = arguments.collect::<VecDeque<_>>();
    match arguments.front().and_then(|argument| argument.to_str()) {
        Some("local") => {
            arguments.pop_front();
            parse_local(&program, arguments).map(SoakCommand::Local)
        }
        Some("public-workload") => {
            arguments.pop_front();
            parse_public_workload(&program, arguments).map(SoakCommand::PublicWorkload)
        }
        Some("echo-server") => {
            arguments.pop_front();
            parse_echo_server(&program, arguments).map(SoakCommand::EchoServer)
        }
        Some("--help" | "-h") => Err(usage(&program)),
        _ => parse_local(&program, arguments).map(SoakCommand::Local),
    }
}

fn parse_local(
    program: &OsString,
    mut arguments: VecDeque<OsString>,
) -> LabResult<ProxySoakConfig> {
    let mut config = ProxySoakConfig::default();
    while let Some(argument) = arguments.pop_front() {
        match argument.to_str() {
            Some("--duration-secs") => {
                config.duration =
                    Duration::from_secs(parse_u64(arguments.pop_front(), "--duration-secs")?)
            }
            Some("--workers") => config.workers = parse_usize(arguments.pop_front(), "--workers")?,
            Some("--payload-bytes") => {
                config.payload_bytes = parse_usize(arguments.pop_front(), "--payload-bytes")?
            }
            Some("--inter-flow-delay-ms") => {
                config.inter_flow_delay = Duration::from_millis(parse_u64(
                    arguments.pop_front(),
                    "--inter-flow-delay-ms",
                )?)
            }
            Some("--single-path") => config.multipath = false,
            Some("--help" | "-h") => return Err(usage(program)),
            _ => return Err(usage(program)),
        }
    }
    Ok(config)
}

fn parse_public_workload(
    program: &OsString,
    mut arguments: VecDeque<OsString>,
) -> LabResult<ProxyPublicSoakConfig> {
    let mut config = ProxyPublicSoakConfig::default();
    while let Some(argument) = arguments.pop_front() {
        match argument.to_str() {
            Some("--client-address") => {
                config.client_addr = parse_socket_addr(arguments.pop_front(), "--client-address")?
            }
            Some("--duration-secs") => {
                config.duration =
                    Duration::from_secs(parse_u64(arguments.pop_front(), "--duration-secs")?)
            }
            Some("--workers") => config.workers = parse_usize(arguments.pop_front(), "--workers")?,
            Some("--payload-bytes") => {
                config.payload_bytes = parse_usize(arguments.pop_front(), "--payload-bytes")?
            }
            Some("--upload-rate-kbps") => {
                let kilobits = parse_u64(arguments.pop_front(), "--upload-rate-kbps")?;
                config.upload_rate_bps = kilobits
                    .checked_mul(1_000)
                    .ok_or_else(|| io::Error::other("--upload-rate-kbps 换算为 bit/s 时溢出"))?;
            }
            Some("--upload-rate-bps") => {
                config.upload_rate_bps = parse_u64(arguments.pop_front(), "--upload-rate-bps")?
            }
            Some("--application-byte-budget") => {
                config.application_byte_budget =
                    parse_u64(arguments.pop_front(), "--application-byte-budget")?
            }
            Some("--checkpoint-secs") => {
                config.checkpoint_interval =
                    Duration::from_secs(parse_u64(arguments.pop_front(), "--checkpoint-secs")?)
            }
            Some("--help" | "-h") => return Err(usage(program)),
            _ => return Err(usage(program)),
        }
    }
    Ok(config)
}

fn parse_echo_server(
    program: &OsString,
    mut arguments: VecDeque<OsString>,
) -> LabResult<SocketAddr> {
    let mut listen = SocketAddr::from(([127, 0, 0, 1], 48080));
    while let Some(argument) = arguments.pop_front() {
        match argument.to_str() {
            Some("--listen") => {
                listen = parse_socket_addr(arguments.pop_front(), "--listen")?;
            }
            Some("--help" | "-h") => return Err(usage(program)),
            _ => return Err(usage(program)),
        }
    }
    Ok(listen)
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

fn parse_socket_addr(value: Option<OsString>, option: &str) -> LabResult<SocketAddr> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| io::Error::other(format!("{option} 缺少 IP:port")))?;
    value
        .parse::<SocketAddr>()
        .map_err(|error| io::Error::other(format!("{option} 不是合法 IP:port：{error}")).into())
}

fn usage(program: &OsString) -> flowweave_lab::LabError {
    io::Error::other(format!(
        "用法：\n  {} [local] [--duration-secs N] [--workers N] [--payload-bytes N] [--inter-flow-delay-ms N] [--single-path]\n  {} public-workload [--client-address IP:PORT] [--duration-secs N] [--workers N] [--payload-bytes N] [--upload-rate-kbps N] [--application-byte-budget N] [--checkpoint-secs N]\n  {} echo-server [--listen LOOPBACK_IP:PORT]",
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
    ))
    .into()
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> LabResult<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> LabResult<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

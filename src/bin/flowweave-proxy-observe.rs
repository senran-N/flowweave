use std::{
    env,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, BufReader},
    path::PathBuf,
    process::ExitCode,
};

use flowweave_lab::{LabResult, ProxyHealthPolicy, ProxyHealthReport, analyze_proxy_jsonl};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Verify,
    Summary,
}

fn main() -> ExitCode {
    match run() {
        Ok((command, report)) => {
            println!("{}", report.to_json());
            if command == Command::Verify && !report.healthy {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("flowweave-proxy-observe: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> LabResult<(Command, ProxyHealthReport)> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("flowweave-proxy-observe"));
    let command = match arguments.next().as_deref().and_then(OsStr::to_str) {
        Some("verify") => Command::Verify,
        Some("summary") => Command::Summary,
        _ => return Err(usage(&program)),
    };
    let input = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| usage(&program))?;
    let mut policy = ProxyHealthPolicy::strict_both();

    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--require-role") => {
                let value = arguments.next().ok_or_else(|| usage(&program))?;
                match value.to_str() {
                    Some("both") => {
                        policy.require_client = true;
                        policy.require_server = true;
                    }
                    Some("client") => {
                        policy.require_client = true;
                        policy.require_server = false;
                    }
                    Some("server") => {
                        policy.require_client = false;
                        policy.require_server = true;
                    }
                    Some("any") => {
                        policy.require_client = false;
                        policy.require_server = false;
                    }
                    _ => return Err(usage(&program)),
                }
            }
            Some("--allow-open-runtime") => {
                policy.require_clean_shutdown = false;
                policy.require_final_inactive = false;
                policy.require_closed_lifecycles = false;
            }
            Some("--max-rejections") => {
                policy.max_rejections = parse_u64(arguments.next(), "--max-rejections")?
            }
            Some("--max-timeouts") => {
                policy.max_timeouts = parse_u64(arguments.next(), "--max-timeouts")?
            }
            Some("--max-upstream-errors") => {
                policy.max_upstream_errors = parse_u64(arguments.next(), "--max-upstream-errors")?
            }
            Some("--max-forced-shutdowns") => {
                policy.max_forced_shutdowns = parse_u64(arguments.next(), "--max-forced-shutdowns")?
            }
            Some("--max-runtime-failures") => {
                policy.max_runtime_failures = parse_u64(arguments.next(), "--max-runtime-failures")?
            }
            _ => return Err(usage(&program)),
        }
    }

    let observation = if input.as_os_str() == "-" {
        analyze_proxy_jsonl(io::stdin().lock())?
    } else {
        analyze_proxy_jsonl(BufReader::new(File::open(input)?))?
    };
    Ok((command, observation.evaluate(policy)))
}

fn parse_u64(value: Option<OsString>, option: &str) -> LabResult<u64> {
    value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| io::Error::other(format!("{option} 缺少非负整数")))?
        .parse::<u64>()
        .map_err(|error| io::Error::other(format!("{option} 不是非负整数：{error}")).into())
}

fn usage(program: &OsString) -> flowweave_lab::LabError {
    io::Error::other(format!(
        "用法：{} <verify|summary> <jsonl-path|-> [--require-role both|client|server|any] [--allow-open-runtime] [--max-rejections N] [--max-timeouts N] [--max-upstream-errors N] [--max-forced-shutdowns N] [--max-runtime-failures N]",
        PathBuf::from(program).display()
    ))
    .into()
}

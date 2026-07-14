#![cfg(target_os = "linux")]

use std::{
    env,
    ffi::{CString, OsString},
    mem,
    path::PathBuf,
    process::ExitCode,
    ptr,
};

use flowweave_lab::{
    activate_vpn_client_routes, activate_vpn_server_forwarding, cleanup_vpn_network,
    deactivate_vpn_client_routes, deactivate_vpn_server_forwarding, prepare_vpn_client_network,
    prepare_vpn_server_network,
};

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
                .ok_or_else(|| "vpn_network_invalid_owner_uid".to_owned())
                .and_then(|value| parse_owner_uid(&value))?;
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
        Some("activate-client") => {
            let config = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            let state = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            if arguments.next().is_some() {
                return Err(usage(&program));
            }
            activate_vpn_client_routes(&config, &state)
                .map(|outcome| outcome.as_str())
                .map_err(|error| error.to_string())
        }
        Some("deactivate-client") => {
            let state = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            if arguments.next().is_some() {
                return Err(usage(&program));
            }
            deactivate_vpn_client_routes(&state)
                .map(|outcome| outcome.as_str())
                .map_err(|error| error.to_string())
        }
        Some("activate-server") => {
            let config = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            let state = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            if arguments.next().is_some() {
                return Err(usage(&program));
            }
            activate_vpn_server_forwarding(&config, &state)
                .map(|outcome| outcome.as_str())
                .map_err(|error| error.to_string())
        }
        Some("deactivate-server") => {
            let state = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| usage(&program))?;
            if arguments.next().is_some() {
                return Err(usage(&program));
            }
            deactivate_vpn_server_forwarding(&state)
                .map(|outcome| outcome.as_str())
                .map_err(|error| error.to_string())
        }
        _ => Err(usage(&program)),
    }
}

fn usage(program: &OsString) -> String {
    format!(
        "用法：{} <prepare-client|prepare-server> <product-config> <state-path> <owner-uid|@owner-user> | <activate-client|activate-server> <product-config> <state-path> | <deactivate-client|deactivate-server> <state-path> | cleanup <state-path>",
        PathBuf::from(program).display()
    )
}

fn parse_owner_uid(value: &str) -> Result<u32, String> {
    if let Ok(owner_uid) = value.parse::<u32>() {
        return (owner_uid != 0 && owner_uid.to_string() == value)
            .then_some(owner_uid)
            .ok_or_else(|| "vpn_network_invalid_owner_uid".to_owned());
    }
    let owner_user = value
        .strip_prefix('@')
        .filter(|name| valid_owner_user(name))
        .ok_or_else(|| "vpn_network_invalid_owner_uid".to_owned())?;
    resolve_owner_user(owner_user)
}

fn valid_owner_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn resolve_owner_user(value: &str) -> Result<u32, String> {
    let name = CString::new(value).map_err(|_| "vpn_network_invalid_owner_uid".to_owned())?;
    // SAFETY: sysconf has no pointer arguments and only reads the process NSS configuration.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_size = usize::try_from(suggested)
        .ok()
        .filter(|size| *size >= 1024)
        .unwrap_or(16 * 1024)
        .min(1024 * 1024);
    loop {
        // SAFETY: passwd is a plain C output structure initialized before getpwnam_r fills it.
        let mut entry: libc::passwd = unsafe { mem::zeroed() };
        let mut result = ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_size];
        // SAFETY: name is NUL-terminated, entry/result are writable, and buffer is live for the
        // duration of the lookup. getpwnam_r does not retain these pointers after returning.
        let status = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 {
            if result.is_null() {
                return Err("vpn_network_owner_user_not_found".to_owned());
            }
            return (entry.pw_uid != 0)
                .then_some(entry.pw_uid)
                .ok_or_else(|| "vpn_network_invalid_owner_uid".to_owned());
        }
        if status == libc::ERANGE && buffer_size < 1024 * 1024 {
            buffer_size = (buffer_size * 2).min(1024 * 1024);
            continue;
        }
        return Err("vpn_network_owner_user_lookup_failed".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_selector_preserves_canonical_uid_and_strict_user_syntax() {
        assert_eq!(parse_owner_uid("1000").unwrap(), 1000);
        for invalid in ["", "0", "01000", "@", "@-flowweave", "@bad/user"] {
            assert_eq!(
                parse_owner_uid(invalid).unwrap_err(),
                "vpn_network_invalid_owner_uid"
            );
        }
        assert_eq!(
            parse_owner_uid("@root").unwrap_err(),
            "vpn_network_invalid_owner_uid"
        );
        assert!(valid_owner_user("flowweave"));
        assert!(valid_owner_user("flowweave-vpn_1"));
    }
}

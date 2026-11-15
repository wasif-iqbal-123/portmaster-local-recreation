use crate::browser::{self, DohPolicy};
use crate::config::now_iso;
use crate::store::{load_json, save_json};
use crate::system::{self, DnsConfig};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub const HEARTBEAT_FILE_NAME: &str = "runtime_heartbeat.json";
pub const GUARD_LOG_FILE_NAME: &str = "guard.log";
const GUARD_POLL_SECS: u64 = 5;
const GUARD_FAILURE_RETRY_SECS: u64 = 30;

/// Written by the app every few seconds. If the app dies or is killed, the
/// guard sees a dead PID and restores the recorded DNS/browser state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub pid: u32,
    pub timestamp: u64,
    pub dns_running: bool,
}

#[cfg(windows)]
pub fn process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return false;
    }
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        let mut exit_code = 0u32;
        let read_ok = GetExitCodeProcess(handle, &mut exit_code).is_ok();
        let _ = CloseHandle(handle);
        // STILL_ACTIVE is 259; a dead process reports its exit code.
        read_ok && exit_code == 259
    }
}

#[cfg(not(windows))]
pub fn process_alive(_pid: u32) -> bool {
    false
}

fn append_log(data_dir: &Path, message: &str) {
    let path = data_dir.join(GUARD_LOG_FILE_NAME);
    let line = format!("{} {}\n", now_iso(), message);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

fn heartbeat_path(data_dir: &Path) -> PathBuf {
    data_dir.join(HEARTBEAT_FILE_NAME)
}

fn dns_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("system_dns.json")
}

fn doh_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("doh_policy.json")
}

fn restore_recorded_state(data_dir: &Path) -> bool {
    let mut restored = false;

    let dns: Option<DnsConfig> = load_json(&dns_state_path(data_dir));
    if let Some(config) = dns {
        match system::restore_system_dns(&config) {
            Ok(()) => {
                let _ = save_json(&dns_state_path(data_dir), &Option::<DnsConfig>::None);
                append_log(
                    data_dir,
                    &format!(
                        "restored system DNS on interface {} to {}",
                        config.interface,
                        config.ipv4.join(", ")
                    ),
                );
                restored = true;
            }
            Err(err) => {
                append_log(data_dir, &format!("could not restore system DNS: {err}"));
            }
        }
    }

    let doh: Option<DohPolicy> = load_json(&doh_state_path(data_dir));
    if let Some(policy) = doh {
        match browser::restore(&policy) {
            Ok(()) => {
                let _ = save_json(&doh_state_path(data_dir), &Option::<DohPolicy>::None);
                append_log(data_dir, "restored browser DoH policy");
                restored = true;
            }
            Err(err) => {
                append_log(data_dir, &format!("could not restore browser DoH policy: {err}"));
            }
        }
    }

    restored
}

/// Crash-safe guard process (`--dns-guard`). It is installed as an elevated
/// logon task and runs independently of the GUI. While the main app is alive it
/// does nothing; when the app is gone or its listener is not running it restores
/// the exact DNS servers and browser policy recorded before deployment.
pub fn run_guard(data_dir: PathBuf) -> ! {
    let _ = fs::create_dir_all(&data_dir);
    append_log(&data_dir, "DNS guard started");

    loop {
        let heartbeat: Option<Heartbeat> = load_json(&heartbeat_path(&data_dir));
        let alive = heartbeat
            .as_ref()
            .map(|beat| process_alive(beat.pid))
            .unwrap_or(false);

        // Only restore when the main process is actually gone. During startup the
        // listener may not yet be bound, and the deploy flow briefly points the OS
        // at the resolver before the heartbeat reports dns_running=true; treating
        // that as "unhealthy" caused a restore/deploy race.
        if !alive {
            if restore_recorded_state(&data_dir) {
                append_log(
                    &data_dir,
                    "application is stopped; internet DNS restored to the pre-deployment state",
                );
            }
            thread::sleep(Duration::from_secs(GUARD_FAILURE_RETRY_SECS));
        } else {
            thread::sleep(Duration::from_secs(GUARD_POLL_SECS));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_round_trips() {
        let heartbeat = Heartbeat {
            pid: 1234,
            timestamp: 1700000000,
            dns_running: true,
        };
        let text = serde_json::to_string(&heartbeat).unwrap();
        let parsed: Heartbeat = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, heartbeat);
    }

    #[test]
    fn zero_pid_is_never_alive() {
        assert!(!process_alive(0));
    }
}

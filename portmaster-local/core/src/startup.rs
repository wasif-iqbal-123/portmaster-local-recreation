use serde::{Deserialize, Serialize};

pub const TASK_NAME: &str = "Portmaster-Local System DNS";
pub const GUARD_TASK_NAME: &str = "Portmaster-Local DNS Guard";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutostartConfig {
    pub installed: bool,
}

pub fn supported() -> bool {
    cfg!(windows)
}

fn create_args_for(exe: &str, task_name: &str, flags: &str) -> Result<Vec<String>, String> {
    let exe = exe.trim();
    if exe.is_empty() {
        return Err("executable path is required".to_string());
    }
    Ok(vec![
        "/Create".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
        "/TR".to_string(),
        format!("\"{}\" {}", exe, flags),
        "/SC".to_string(),
        "ONLOGON".to_string(),
        "/RL".to_string(),
        "HIGHEST".to_string(),
        "/F".to_string(),
    ])
}

pub fn create_args(exe: &str) -> Result<Vec<String>, String> {
    create_args_for(exe, TASK_NAME, "--system-wide")
}

pub fn create_guard_args(exe: &str) -> Result<Vec<String>, String> {
    create_args_for(exe, GUARD_TASK_NAME, "--dns-guard")
}

pub fn query_args() -> [&'static str; 5] {
    ["/Query", "/TN", TASK_NAME, "/FO", "LIST"]
}

pub fn query_guard_args() -> [&'static str; 5] {
    ["/Query", "/TN", GUARD_TASK_NAME, "/FO", "LIST"]
}

pub fn delete_args() -> [&'static str; 4] {
    ["/Delete", "/TN", TASK_NAME, "/F"]
}

pub fn delete_guard_args() -> [&'static str; 4] {
    ["/Delete", "/TN", GUARD_TASK_NAME, "/F"]
}

#[cfg(windows)]
fn run_schtasks(args: &[String]) -> Result<String, String> {
    let mut process = std::process::Command::new("schtasks.exe");
    process.args(args);
    crate::system::hide_window(&mut process);
    let output = process
        .output()
        .map_err(|err| format!("could not launch schtasks: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            "no error output".to_string()
        } else {
            stderr
        };
        return Err(format!(
            "schtasks failed with {}: {detail}; administrator rights are required to change login autostart",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(not(windows))]
fn run_schtasks(_args: &[String]) -> Result<String, String> {
    Err("login autostart is implemented on Windows only".to_string())
}

fn install_task(exe: &str, task_name: &str, flags: &str) -> Result<(), String> {
    let args = create_args_for(exe, task_name, flags)?;
    run_schtasks(&args)?;
    Ok(())
}

fn remove_task(task_name: &str) -> Result<(), String> {
    let args = ["/Delete".to_string(), "/TN".to_string(), task_name.to_string(), "/F".to_string()];
    match run_schtasks(&args) {
        Ok(_) => Ok(()),
        Err(err) => {
            if err.contains("exit code 1") || err.contains("with 1") {
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

fn run_task(task_name: &str) -> Result<(), String> {
    let args = ["/Run".to_string(), "/TN".to_string(), task_name.to_string()];
    match run_schtasks(&args) {
        Ok(_) => Ok(()),
        Err(err) => {
            // An already-running task is not an installation failure.
            if err.contains("already running") || err.contains("exit code 1") || err.contains("with 1") {
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

fn end_task(task_name: &str) -> Result<(), String> {
    let args = ["/End".to_string(), "/TN".to_string(), task_name.to_string()];
    match run_schtasks(&args) {
        Ok(_) => Ok(()),
        Err(err) => {
            if err.contains("exit code 1") || err.contains("with 1") {
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

/// Install both the elevated DNS-owner task and the crash-safe guard task, and
/// start the guard immediately so a kill during this session is still covered.
pub fn install(exe: &str) -> Result<(), String> {
    install_task(exe, TASK_NAME, "--system-wide")?;
    install_task(exe, GUARD_TASK_NAME, "--dns-guard")?;
    run_task(GUARD_TASK_NAME)?;
    Ok(())
}

/// Start the guard immediately when the user installs autostart from the UI.
pub fn start_guard() -> Result<(), String> {
    run_task(GUARD_TASK_NAME)
}

pub fn install_guard(exe: &str) -> Result<(), String> {
    install_task(exe, GUARD_TASK_NAME, "--dns-guard")
}

pub fn remove() -> Result<(), String> {
    // Stop the guard process itself before deleting its task.
    end_task(GUARD_TASK_NAME)?;
    remove_task(TASK_NAME)?;
    remove_task(GUARD_TASK_NAME)?;
    Ok(())
}

pub fn remove_guard() -> Result<(), String> {
    remove_task(GUARD_TASK_NAME)
}

fn task_exists(args: &[&str]) -> Result<bool, String> {
    match run_schtasks(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>()) {
        Ok(_) => Ok(true),
        Err(err) => {
            if err.contains("exit code 1") || err.contains("with 1") {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }
}

pub fn installed() -> Result<bool, String> {
    task_exists(&query_args())
}

pub fn guard_installed() -> Result<bool, String> {
    task_exists(&query_guard_args())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_args_quote_the_executable_path_with_spaces() {
        let args = create_args("C:\\Program Files\\Portmaster-Local\\portmaster-local.exe").unwrap();
        assert!(args.contains(&"/SC".to_string()));
        assert!(args.contains(&"ONLOGON".to_string()));
        assert!(args.contains(&"HIGHEST".to_string()));
        assert!(args.contains(&"\"C:\\Program Files\\Portmaster-Local\\portmaster-local.exe\" --system-wide".to_string()));
    }

    #[test]
    fn guard_args_run_the_dns_guard_mode() {
        let args = create_guard_args("C:\\app.exe").unwrap();
        assert!(args.contains(&GUARD_TASK_NAME.to_string()));
        assert!(args.contains(&"\"C:\\app.exe\" --dns-guard".to_string()));
        assert!(create_guard_args("").is_err());
    }

    #[test]
    fn create_args_reject_an_empty_path() {
        assert!(create_args("").is_err());
        assert!(create_args("   ").is_err());
    }

    #[test]
    fn task_name_is_stable() {
        assert!(create_args("C:\\app.exe").unwrap().contains(&TASK_NAME.to_string()));
        assert!(query_args().contains(&TASK_NAME));
        assert!(delete_args().contains(&TASK_NAME));
    }

    #[test]
    fn guard_task_name_is_stable() {
        assert!(query_guard_args().contains(&GUARD_TASK_NAME));
        assert!(delete_guard_args().contains(&GUARD_TASK_NAME));
    }

    #[test]
    fn autostart_config_round_trips() {
        let config = AutostartConfig { installed: true };
        let text = serde_json::to_string(&config).unwrap();
        let parsed: AutostartConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, config);
    }
}

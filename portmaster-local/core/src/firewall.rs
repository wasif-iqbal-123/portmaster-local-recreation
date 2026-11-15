use crate::platform;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub program: Option<String>,
    pub direction: String,
    pub action: String,
}

pub fn supported() -> bool {
    platform::firewall_supported()
}

pub fn unsupported_reason() -> &'static str {
    "packet blocking is implemented with Windows Firewall rules and is available on Windows only"
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub fn app_rule_name(path: &str) -> String {
    format!("PortmasterLocal Block {:016x}", stable_hash(path))
}

pub fn build_app_rule_command(path: &str) -> String {
    let name = app_rule_name(path);
    format!(
        "New-NetFirewallRule -DisplayName {} -Direction Outbound -Program {} -Action Block -Profile Any -Enabled True",
        ps_quote(&name),
        ps_quote(path)
    )
}

pub fn build_all_outbound_command() -> String {
    format!(
        "New-NetFirewallRule -DisplayName {} -Direction Outbound -Action Block -Profile Any -Enabled True",
        ps_quote(ALL_OUTBOUND_NAME)
    )
}

pub fn build_inbound_command() -> String {
    format!(
        "New-NetFirewallRule -DisplayName {} -Direction Inbound -Action Block -Profile Any -Enabled True",
        ps_quote(ALL_INBOUND_NAME)
    )
}

#[cfg(windows)]
fn run_powershell(command: &str) -> Result<(), String> {
    let mut process = Command::new("powershell.exe");
    process.args(["-NoProfile", "-NonInteractive", "-Command", command]);
    crate::system::hide_window(&mut process);
    let status = process
        .status()
        .map_err(|err| format!("could not launch PowerShell: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "PowerShell command failed with {status}; administrator rights are required for firewall changes"
        ))
    }
}

#[cfg(not(windows))]
fn run_powershell(_command: &str) -> Result<(), String> {
    Err(unsupported_reason().to_string())
}

#[cfg(windows)]
fn run_powershell_capture(command: &str) -> Result<String, String> {
    let mut process = Command::new("powershell.exe");
    process.args(["-NoProfile", "-NonInteractive", "-Command", command]);
    crate::system::hide_window(&mut process);
    let output = process
        .output()
        .map_err(|err| format!("could not launch PowerShell: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell command failed with {}; administrator rights are required for firewall changes",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn exists_command(name: &str) -> String {
    format!(
        "if (Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue) {{ 'true' }} else {{ 'false' }}",
        ps_quote(name)
    )
}

fn rule_exists(name: &str) -> Result<bool, String> {
    #[cfg(windows)]
    {
        let output = run_powershell_capture(&exists_command(name))?;
        Ok(output.eq_ignore_ascii_case("true"))
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(unsupported_reason().to_string())
    }
}

const ALL_OUTBOUND_NAME: &str = "PortmasterLocal Block All Outbound";
const ALL_INBOUND_NAME: &str = "PortmasterLocal Block All Inbound";

pub fn apply_app_block(path: &str) -> Result<FirewallRule, String> {
    if path.trim().is_empty() {
        return Err("application path is empty".to_string());
    }
    let name = app_rule_name(path);
    if !rule_exists(&name)? {
        run_powershell(&build_app_rule_command(path))?;
    }
    Ok(FirewallRule {
        name,
        program: Some(path.to_string()),
        direction: "out".to_string(),
        action: "block".to_string(),
    })
}

pub fn apply_block_all_outbound() -> Result<FirewallRule, String> {
    if !rule_exists(ALL_OUTBOUND_NAME)? {
        run_powershell(&build_all_outbound_command())?;
    }
    Ok(FirewallRule {
        name: ALL_OUTBOUND_NAME.to_string(),
        program: None,
        direction: "out".to_string(),
        action: "block".to_string(),
    })
}

pub fn apply_block_all_inbound() -> Result<FirewallRule, String> {
    if !rule_exists(ALL_INBOUND_NAME)? {
        run_powershell(&build_inbound_command())?;
    }
    Ok(FirewallRule {
        name: ALL_INBOUND_NAME.to_string(),
        program: None,
        direction: "in".to_string(),
        action: "block".to_string(),
    })
}

pub fn remove_rule(name: &str) -> Result<(), String> {
    let command = format!(
        "Remove-NetFirewallRule -DisplayName {} -ErrorAction Stop",
        ps_quote(name)
    );
    run_powershell(&command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform;

    #[test]
    fn quotes_apostrophes() {
        assert_eq!(ps_quote("C:\\Bob's App\\app.exe"), "'C:\\Bob''s App\\app.exe'");
    }

    #[test]
    fn app_rule_name_is_stable_and_path_specific() {
        let first = app_rule_name("C:\\Program Files\\App\\app.exe");
        let second = app_rule_name("C:\\Program Files\\App\\app.exe");
        let third = app_rule_name("C:\\Program Files\\Other\\app.exe");
        assert_eq!(first, second);
        assert_ne!(first, third);
        assert!(first.starts_with("PortmasterLocal Block "));
    }

    #[test]
    fn command_contains_required_firewall_parameters() {
        let command = build_app_rule_command("C:\\Apps\\bad.exe");
        assert!(command.contains("-Direction Outbound"));
        assert!(command.contains("-Program 'C:\\Apps\\bad.exe'"));
        assert!(command.contains("-Action Block"));
    }

    #[test]
    fn preset_commands_use_the_names_checked_for_idempotency() {
        assert!(build_all_outbound_command().contains(ALL_OUTBOUND_NAME));
        assert!(build_inbound_command().contains(ALL_INBOUND_NAME));
        assert!(ALL_OUTBOUND_NAME.starts_with("PortmasterLocal Block"));
        assert!(ALL_INBOUND_NAME.starts_with("PortmasterLocal Block"));
    }

    #[test]
    fn existence_command_quotes_the_display_name() {
        let command = exists_command("PortmasterLocal Block Bob's rule");
        assert!(command.contains("Get-NetFirewallRule"));
        assert!(command.contains("'PortmasterLocal Block Bob''s rule'"));
        assert!(command.contains("'true'"));
        assert!(command.contains("'false'"));
    }

    #[test]
    fn supported_matches_platform() {
        assert_eq!(supported(), platform::firewall_supported());
    }

    #[test]
    fn rejects_empty_application_path() {
        assert!(apply_app_block("   ").is_err());
        assert!(apply_app_block("").is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_rule_actions_report_the_platform_limit() {
        assert!(!supported());
        assert!(apply_app_block("app.exe").is_err());
        assert!(apply_block_all_outbound().is_err());
        assert!(apply_block_all_inbound().is_err());
        assert!(remove_rule("PortmasterLocal Block test").is_err());
    }
}

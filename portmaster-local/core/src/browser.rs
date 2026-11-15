use serde::{Deserialize, Serialize};

/// Browser enterprise-policy keys that can turn off Chromium DNS-over-HTTPS.
pub const POLICY_KEYS: [&str; 3] = [
    r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave-Browser",
    r"HKLM:\SOFTWARE\Policies\Google\Chrome",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DohPolicyEntry {
    pub path: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DohPolicy {
    pub entries: Vec<DohPolicyEntry>,
}

#[derive(Deserialize)]
struct CaptureJson {
    entries: Vec<DohPolicyEntry>,
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn policy_list() -> String {
    POLICY_KEYS
        .iter()
        .map(|path| ps_quote(path))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn capture_command() -> String {
    format!(
        "$keys = @({policy_list}); \
         $result = foreach ($key in $keys) {{ \
             $value = $null; \
             if (Test-Path $key) {{ \
                 $value = (Get-ItemProperty -Path $key -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue).DnsOverHttpsMode; \
             }} \
             [pscustomobject]@{{ path = $key; value = $value }} \
         }}; \
         [pscustomobject]@{{ entries = @($result) }} | ConvertTo-Json -Compress",
        policy_list = policy_list()
    )
}

pub fn disable_command() -> String {
    format!(
        "$keys = @({policy_list}); \
         foreach ($key in $keys) {{ \
             New-Item -Path $key -Force | Out-Null; \
             Set-ItemProperty -Path $key -Name 'DnsOverHttpsMode' -Value 'off' -Type String; \
         }}",
        policy_list = policy_list()
    )
}

pub fn restore_command(policy: &DohPolicy) -> Result<String, String> {
    if policy.entries.is_empty() {
        return Err("no recorded browser DoH policy state".to_string());
    }
    let entries = policy
        .entries
        .iter()
        .map(|entry| {
            let value = match &entry.value {
                Some(value) => format!("{}", ps_quote(value)),
                None => "$null".to_string(),
            };
            format!(
                "[pscustomobject]@{{ path = {}; value = {} }}",
                ps_quote(&entry.path),
                value
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "$entries = @({entries}); \
         foreach ($entry in $entries) {{ \
             if ($null -eq $entry.value) {{ \
                 Remove-ItemProperty -Path $entry.path -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue; \
             }} else {{ \
                 New-Item -Path $entry.path -Force | Out-Null; \
                 Set-ItemProperty -Path $entry.path -Name 'DnsOverHttpsMode' -Value $entry.value -Type String; \
             }} \
         }}",
        entries = entries
    ))
}

#[cfg(windows)]
fn run_powershell(command: &str) -> Result<String, String> {
    let mut process = std::process::Command::new("powershell.exe");
    process.args(["-NoProfile", "-NonInteractive", "-Command", command]);
    crate::system::hide_window(&mut process);
    let output = process
        .output()
        .map_err(|err| format!("could not launch PowerShell: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell command failed with {}; administrator rights are required for browser policy changes",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(not(windows))]
fn run_powershell(_command: &str) -> Result<String, String> {
    Err("browser DoH policy is implemented on Windows only".to_string())
}

pub fn supported() -> bool {
    cfg!(windows)
}

pub fn capture() -> Result<DohPolicy, String> {
    let output = run_powershell(&capture_command())?;
    let parsed: CaptureJson = serde_json::from_str(&output)
        .map_err(|err| format!("could not parse browser policy report: {err}"))?;
    Ok(DohPolicy {
        entries: parsed.entries,
    })
}

/// Record the prior policy values, then disable Chromium DoH for Brave, Chrome,
/// and Edge. The returned state is persisted so the change can be reverted.
pub fn disable() -> Result<DohPolicy, String> {
    let prior = capture()?;
    run_powershell(&disable_command())?;
    Ok(prior)
}

pub fn restore(policy: &DohPolicy) -> Result<(), String> {
    run_powershell(&restore_command(policy)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_command_sets_the_policy_for_every_browser() {
        let command = disable_command();
        for key in POLICY_KEYS {
            assert!(command.contains(key));
        }
        assert_eq!(command.matches("Set-ItemProperty").count(), 1);
        assert_eq!(command.matches("DnsOverHttpsMode").count(), 1);
        assert!(command.contains("foreach ($key in $keys)"));
        assert!(command.contains("'off'"));
    }

    #[test]
    fn capture_command_reads_all_policy_keys() {
        let command = capture_command();
        for key in POLICY_KEYS {
            assert!(command.contains(key));
        }
        assert!(command.contains("ConvertTo-Json"));
    }

    #[test]
    fn restore_command_preserves_absent_and_present_values() {
        let policy = DohPolicy {
            entries: vec![
                DohPolicyEntry {
                    path: POLICY_KEYS[0].to_string(),
                    value: None,
                },
                DohPolicyEntry {
                    path: POLICY_KEYS[2].to_string(),
                    value: Some("automatic".to_string()),
                },
            ],
        };
        let command = restore_command(&policy).unwrap();
        assert!(command.contains("Remove-ItemProperty"));
        assert!(command.contains("'automatic'"));
        assert!(command.contains(POLICY_KEYS[2]));
        assert!(restore_command(&DohPolicy::default()).is_err());
    }

    #[test]
    fn policy_round_trips_through_json() {
        let policy = DohPolicy {
            entries: vec![DohPolicyEntry {
                path: POLICY_KEYS[1].to_string(),
                value: Some("off".to_string()),
            }],
        };
        let text = serde_json::to_string(&policy).unwrap();
        let parsed: DohPolicy = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, policy);
    }
}

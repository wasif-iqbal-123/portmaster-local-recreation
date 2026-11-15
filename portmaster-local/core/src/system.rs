use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::process::Command;

/// The DNS configuration of one interface. Windows uses an interface index and
/// Linux uses a link name; both are kept as strings so the same saved state can
/// be reported by the UI.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    pub interface: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

#[derive(Deserialize)]
struct DnsJson {
    #[serde(default)]
    ipv4: Vec<String>,
    #[serde(default)]
    ipv6: Vec<String>,
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Keep helper processes invisible. Without CREATE_NO_WINDOW, every DNS
/// supervisor check would flash a PowerShell console window.
#[cfg(windows)]
pub fn hide_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x08000000);
}

#[cfg(not(windows))]
pub fn hide_window(_command: &mut Command) {}

#[cfg(windows)]
fn run_powershell_capture(command: &str) -> Result<String, String> {
    let mut process = Command::new("powershell.exe");
    process.args(["-NoProfile", "-NonInteractive", "-Command", command]);
    hide_window(&mut process);
    let output = process
        .output()
        .map_err(|err| format!("could not launch PowerShell: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell command failed with {}; administrator rights may be required",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn run_resolvectl(args: &[&str]) -> Result<String, String> {
    let output = Command::new("resolvectl")
        .args(args)
        .output()
        .map_err(|err| format!("could not run resolvectl: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            "no error output".to_string()
        } else {
            stderr
        };
        return Err(format!("resolvectl {} failed: {detail}", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(windows)]
fn parse_index(interface: &str) -> Result<u32, String> {
    let index = interface
        .trim()
        .parse::<u32>()
        .map_err(|_| "interface index must be a number on Windows".to_string())?;
    if index == 0 {
        return Err("interface index must be a positive number".to_string());
    }
    Ok(index)
}

/// Parse the compact JSON produced by the Windows capture command.
fn parse_dns_json(output: &str) -> Result<DnsConfig, String> {
    let parsed: DnsJson = serde_json::from_str(output.trim())
        .map_err(|err| format!("could not parse DNS report: {err}"))?;
    Ok(DnsConfig {
        interface: String::new(),
        ipv4: parsed.ipv4,
        ipv6: parsed.ipv6,
    })
}

/// Extract the link name from one `ip route show default` line.
#[cfg(any(target_os = "linux", test))]
fn parse_default_interface(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let dev = tokens.iter().position(|token| *token == "dev")?;
    tokens.get(dev + 1).map(|value| (*value).to_string())
}

/// Find the interface Windows currently uses for its default route.
#[cfg(windows)]
pub fn active_interface() -> Result<String, String> {
    let output = run_powershell_capture(
        "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | \
         Sort-Object RouteMetric | Select-Object -First 1; \
         if ($null -eq $route) { throw 'no default route found' }; \
         [string]$route.InterfaceIndex",
    )?;
    let index = parse_index(&output)?;
    Ok(index.to_string())
}

/// Find the interface Linux currently uses for its default route.
#[cfg(target_os = "linux")]
pub fn active_interface() -> Result<String, String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|err| format!("could not run ip route: {err}"))?;
    if !output.status.success() {
        return Err(format!("ip route failed with {}", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("default"))
        .ok_or_else(|| "no default route found".to_string())?;
    parse_default_interface(line).ok_or_else(|| "default route has no dev field".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn active_interface() -> Result<String, String> {
    Err("active interface detection is not implemented on this platform".to_string())
}

#[cfg(target_os = "linux")]
fn parse_resolvectl_dns(interface: &str, output: &str) -> DnsConfig {
    let mut config = DnsConfig {
        interface: interface.trim().to_string(),
        ..DnsConfig::default()
    };
    let line = output
        .lines()
        .find(|line| line.contains(':'))
        .unwrap_or(output);
    let addresses = line.splitn(2, ':').nth(1).unwrap_or("");
    for token in addresses.split_whitespace() {
        if token.parse::<IpAddr>().is_err() {
            continue;
        }
        if token.contains(':') {
            config.ipv6.push(token.to_string());
        } else {
            config.ipv4.push(token.to_string());
        }
    }
    config
}

/// True when the captured interface configuration still points at this app.
pub fn points_to_local(config: &DnsConfig) -> bool {
    config
        .ipv4
        .iter()
        .chain(config.ipv6.iter())
        .any(|address| address.trim() == "127.0.0.1" || address.trim() == "::1")
}

fn build_windows_set_command(index: u32, addresses: &[String]) -> String {
    if addresses.is_empty() {
        format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses")
    } else {
        let list = addresses
            .iter()
            .map(|address| ps_quote(address))
            .collect::<Vec<_>>()
            .join(",");
        format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {list}")
    }
}

pub fn capture_system_dns(interface: &str) -> Result<DnsConfig, String> {
    let interface = interface.trim();
    if interface.is_empty() {
        return Err("interface is required".to_string());
    }

    #[cfg(windows)]
    {
        let index = parse_index(interface)?;
        let output = run_powershell_capture(&format!(
            "$v4 = @(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4 -ErrorAction Stop | Select-Object -ExpandProperty ServerAddresses); \
             $v6 = @(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv6 -ErrorAction Stop | Select-Object -ExpandProperty ServerAddresses); \
             [pscustomobject]@{{ ipv4 = $v4; ipv6 = $v6 }} | ConvertTo-Json -Compress"
        ))?;
        let mut config = parse_dns_json(&output)?;
        config.interface = interface.to_string();
        Ok(config)
    }

    #[cfg(target_os = "linux")]
    {
        let output = run_resolvectl(&["dns", interface])?;
        Ok(parse_resolvectl_dns(interface, &output))
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("system DNS configuration is not implemented on this platform".to_string())
    }
}

pub fn dns_report() -> Result<String, String> {
    #[cfg(windows)]
    {
        run_powershell_capture(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress",
        )
    }
    #[cfg(target_os = "linux")]
    {
        let report = run_resolvectl(&["status"])?;
        if report.is_empty() {
            return Err(
                "resolvectl returned no status; is systemd-resolved installed and running?".to_string(),
            );
        }
        Ok(report)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("system DNS configuration is not implemented on this platform".to_string())
    }
}

/// Record the current servers, then point the interface at the local resolver.
/// The returned `DnsConfig` is the prior state that must be persisted so the
/// reset action can restore the exact servers rather than falling back to DHCP.
pub fn apply_system_dns(interface: &str, port: u16) -> Result<DnsConfig, String> {
    if port != 53 {
        return Err("system DNS can only point at port 53; change the DNS port to 53 first".to_string());
    }
    let prior = capture_system_dns(interface)?;
    point_system_dns(interface)?;
    Ok(prior)
}

/// Point an interface at the local resolver without recapturing its prior state.
/// Used when reapplying DNS at login while the recorded prior state is already
/// available.
pub fn point_system_dns(interface: &str) -> Result<(), String> {
    let interface = interface.trim();
    if interface.is_empty() {
        return Err("interface is required".to_string());
    }

    #[cfg(windows)]
    {
        let index = parse_index(interface)?;
        run_powershell_capture(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {}",
            ps_quote("127.0.0.1")
        ))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        run_resolvectl(&["dns", interface, "127.0.0.1"]).map_err(|err| {
            format!("{err}; root rights are required to change link DNS settings")
        })?;
        Ok(())
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("system DNS configuration is not implemented on this platform".to_string())
    }
}

/// Restore the exact servers captured before `apply_system_dns`.
pub fn restore_system_dns(config: &DnsConfig) -> Result<(), String> {
    if config.interface.trim().is_empty() {
        return Err("recorded DNS state has no interface".to_string());
    }

    #[cfg(windows)]
    {
        let index = parse_index(&config.interface)?;
        let mut addresses = config.ipv4.clone();
        addresses.extend(config.ipv6.iter().cloned());
        run_powershell_capture(&build_windows_set_command(index, &addresses))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let interface = config.interface.trim();
        if config.ipv4.is_empty() && config.ipv6.is_empty() {
            run_resolvectl(&["revert", interface])
                .map_err(|err| format!("{err}; root rights are required to revert link DNS settings"))?;
            return Ok(());
        }
        let mut args = vec!["dns".to_string(), interface.to_string()];
        args.extend(config.ipv4.iter().cloned());
        args.extend(config.ipv6.iter().cloned());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_resolvectl(&refs)
            .map_err(|err| format!("{err}; root rights are required to change link DNS settings"))?;
        Ok(())
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("system DNS configuration is not implemented on this platform".to_string())
    }
}

/// Administrative fallback that resets the interface to DHCP-provided servers.
pub fn reset_system_dns(interface: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let index = parse_index(interface)?;
        run_powershell_capture(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"
        ))?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let interface = interface.trim();
        if interface.is_empty() {
            return Err("interface name is required on Linux".to_string());
        }
        run_resolvectl(&["revert", interface])
            .map_err(|err| format!("{err}; root rights are required to revert link DNS settings"))?;
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = interface;
        Err("system DNS configuration is not implemented on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_53_port() {
        assert!(apply_system_dns("1", 5333).is_err());
    }

    #[test]
    fn rejects_empty_interface_for_apply() {
        assert!(apply_system_dns("", 53).is_err());
        assert!(apply_system_dns("   ", 53).is_err());
    }

    #[test]
    fn rejects_empty_interface_for_reset() {
        assert!(reset_system_dns("").is_err());
        assert!(reset_system_dns("   ").is_err());
    }

    #[test]
    fn dns_config_round_trips_through_json() {
        let config = DnsConfig {
            interface: "12".to_string(),
            ipv4: vec!["192.168.1.1".to_string()],
            ipv6: vec!["2001:db8::1".to_string()],
        };
        let text = serde_json::to_string(&config).unwrap();
        let parsed: DnsConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn parses_windows_dns_json_and_rejects_garbage() {
        let config = parse_dns_json(r#"{"ipv4":["1.1.1.1"],"ipv6":["::1"]}"#).unwrap();
        assert_eq!(config.ipv4, vec!["1.1.1.1"]);
        assert_eq!(config.ipv6, vec!["::1"]);
        assert!(parse_dns_json("not json").is_err());
    }

    #[test]
    fn detects_whether_dns_points_at_the_local_resolver() {
        let local = DnsConfig {
            interface: "16".to_string(),
            ipv4: vec!["127.0.0.1".to_string()],
            ipv6: vec![],
        };
        assert!(points_to_local(&local));
        let routed = DnsConfig {
            interface: "16".to_string(),
            ipv4: vec!["192.168.1.1".to_string()],
            ipv6: vec![],
        };
        assert!(!points_to_local(&routed));
    }

    #[test]
    fn windows_restore_command_quotes_servers_and_resets_when_empty() {
        assert!(build_windows_set_command(12, &[]).contains("-ResetServerAddresses"));
        let command = build_windows_set_command(12, &["1.1.1.1".to_string(), "::1".to_string()]);
        assert!(command.contains("-InterfaceIndex 12"));
        assert!(command.contains("-ServerAddresses '1.1.1.1','::1'"));
    }

    #[test]
    fn parse_index_rejects_zero_and_text() {
        #[cfg(windows)]
        {
            assert!(parse_index("0").is_err());
            assert!(parse_index("not an index").is_err());
            assert_eq!(parse_index("12").unwrap(), 12);
        }
    }

    #[test]
    fn parses_default_route_interface() {
        assert_eq!(
            parse_default_interface("default via 192.168.1.1 dev eth0 proto dhcp metric 100"),
            Some("eth0".to_string())
        );
        assert_eq!(parse_default_interface("default via 10.0.0.1"), None);
        assert_eq!(parse_default_interface(""), None);
    }

    #[test]
    fn parses_resolvectl_dns_output() {
        #[cfg(target_os = "linux")]
        {
            let config = parse_resolvectl_dns("eth0", "Link 2 (eth0): 192.168.1.1 2001:db8::1");
            assert_eq!(config.interface, "eth0");
            assert_eq!(config.ipv4, vec!["192.168.1.1"]);
            assert_eq!(config.ipv6, vec!["2001:db8::1"]);
            let empty = parse_resolvectl_dns("eth0", "Link 2 (eth0):");
            assert!(empty.ipv4.is_empty());
            assert!(empty.ipv6.is_empty());
        }
    }
}

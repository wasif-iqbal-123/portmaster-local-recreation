//! Compile-time platform capability flags shared by the core engine and the UI.
//!
//! Keeping these checks in one module means the UI can disable controls that the
//! current build cannot implement instead of showing Windows-only affordances on
//! Linux or Android.

pub fn name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        "other"
    }
}

/// Packet-level blocking is implemented with Windows Firewall rules only.
pub fn firewall_supported() -> bool {
    cfg!(windows)
}

/// `resolvectl` on Linux and `Get-DnsClientServerAddress`/`Set-DnsClientServerAddress`
/// on Windows. Android has no equivalent system resolver integration here.
pub fn system_dns_supported() -> bool {
    cfg!(any(windows, target_os = "linux"))
}

/// The connection monitor reads Windows IP Helper tables or `/proc/net` on Linux.
pub fn connection_monitor_supported() -> bool {
    cfg!(any(windows, target_os = "linux"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_name_is_known() {
        assert!(matches!(name(), "windows" | "linux" | "android" | "other"));
    }

    #[test]
    fn capability_flags_match_the_compile_target() {
        assert_eq!(firewall_supported(), cfg!(windows));
        assert_eq!(system_dns_supported(), cfg!(any(windows, target_os = "linux")));
        assert_eq!(
            connection_monitor_supported(),
            cfg!(any(windows, target_os = "linux"))
        );
    }
}

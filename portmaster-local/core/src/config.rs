use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListFormat {
    Hosts,
    Adblock,
    Wildcard,
    Plain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
}

impl Action {
    pub fn parse(value: &str) -> Option<Action> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Action::Allow),
            "block" => Some(Action::Block),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    All,
    Internet,
    Lan,
    Localhost,
}

impl Scope {
    pub fn parse(value: &str) -> Option<Scope> {
        match value.trim().to_ascii_lowercase().as_str() {
            "all" => Some(Scope::All),
            "internet" => Some(Scope::Internet),
            "lan" => Some(Scope::Lan),
            "localhost" => Some(Scope::Localhost),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub bind_addr: String,
    pub dns_port: u16,
    pub fallback_port: u16,
    pub primary_doh_url: String,
    pub fallback_doh_url: String,
    pub auto_update: bool,
    pub update_interval_hours: u64,
    pub block_inbound: bool,
    pub block_all_internet: bool,
    pub default_action: Action,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(),
            dns_port: 53,
            fallback_port: 5333,
            primary_doh_url: "https://cloudflare-dns.com/dns-query".to_string(),
            fallback_doh_url: "https://dns.quad9.net/dns-query".to_string(),
            auto_update: true,
            update_interval_hours: 24,
            block_inbound: false,
            block_all_internet: false,
            default_action: Action::Allow,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: ListFormat,
    pub category: String,
    pub action: Action,
    pub enabled: bool,
    pub count: usize,
    pub last_updated: Option<String>,
    pub last_update_unix: Option<u64>,
    pub error: Option<String>,
}

impl Default for FilterSource {
    fn default() -> Self {
        Self::new("", "", "", ListFormat::Plain, "")
    }
}

impl FilterSource {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        url: impl Into<String>,
        format: ListFormat,
        category: impl Into<String>,
    ) -> Self {
        Self::new_with_action(id, name, url, format, category, Action::Block)
    }

    pub fn new_with_action(
        id: impl Into<String>,
        name: impl Into<String>,
        url: impl Into<String>,
        format: ListFormat,
        category: impl Into<String>,
        action: Action,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            url: url.into(),
            format,
            category: category.into(),
            action,
            enabled: true,
            count: 0,
            last_updated: None,
            last_update_unix: None,
            error: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FiltersConfig {
    pub sources: Vec<FilterSource>,
}

impl Default for FiltersConfig {
    fn default() -> Self {
        Self {
            sources: default_sources(),
        }
    }
}

pub fn default_sources() -> Vec<FilterSource> {
    // Portmaster's filter-list inventory, grouped into the same broad
    // categories used by the desktop client. Each entry is one downloadable
    // list; sources with multiple resource URLs are split by address family.
    let definitions: &[(&str, &str, &str, ListFormat, &str, Action)] = &[
        ("AA-AD", "AdAway Ads List", "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt", ListFormat::Hosts, "Ads & Trackers", Action::Block),
        ("SWC", "Dan Pollock's List of Bad Stuff - someonewhocares.org", "https://someonewhocares.org/hosts/zero/hosts", ListFormat::Hosts, "Mixed Ads/Trackers/Malware", Action::Block),
        ("DM-TR", "Disconnect.me Tracking Domains", "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt", ListFormat::Plain, "Ads & Trackers", Action::Block),
        ("DM-AD", "Disconnect.me Ad Domains", "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt", ListFormat::Plain, "Ads & Trackers", Action::Block),
        ("BD-AD", "hostsVN Ads List (Vietnam)", "https://raw.githubusercontent.com/bigdargon/hostsVN/master/option/hosts-VN", ListFormat::Hosts, "Ads & Trackers", Action::Block),
        ("PL-B", "Peter Lowe's Collection of Bad Domains", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&mimetype=plaintext", ListFormat::Plain, "Mixed Ads/Trackers/Malware", Action::Block),
        ("SFA-G", "Sinfonietta's Gambling List", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts", ListFormat::Hosts, "NSFW", Action::Block),
        ("SFA-V", "Sinfonietta's Gore List", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/snuff-hosts", ListFormat::Hosts, "NSFW", Action::Block),
        ("SFA-P", "Sinfonietta's Pornography List", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts", ListFormat::Hosts, "NSFW", Action::Block),
        ("SB-AM", "Steven Black's Ads and Malware Collection", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", ListFormat::Hosts, "Mixed Ads/Trackers/Malware", Action::Block),
        ("SB-AH", "Steven Black's Original Ad-Hoc List", "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts", ListFormat::Hosts, "Mixed Ads/Trackers/Malware", Action::Block),
        ("TX-AD", "Tiuxo's Ads List (Japan)", "https://raw.githubusercontent.com/tiuxo/hosts/master/ads", ListFormat::Hosts, "Ads & Trackers", Action::Block),
        ("TX-PRN", "Tiuxo's Pornography List (Japan)", "https://raw.githubusercontent.com/tiuxo/hosts/master/porn", ListFormat::Hosts, "NSFW", Action::Block),
        ("17-ADS", "Safing Ads List", "https://raw.githubusercontent.com/safing/intel-data/master/lists/ads.txt", ListFormat::Plain, "Ads & Trackers", Action::Block),
        ("17-ALYTC", "Safing Analytics List", "https://raw.githubusercontent.com/safing/intel-data/master/lists/analytics.txt", ListFormat::Plain, "Ads & Trackers", Action::Block),
        ("17-FRD", "Safing Fraud List", "https://raw.githubusercontent.com/safing/intel-data/master/lists/fraud.txt", ListFormat::Plain, "Deception", Action::Block),
        ("17-MAL", "Safing Malware List (Domains)", "https://raw.githubusercontent.com/safing/intel-data/master/lists/malware.txt", ListFormat::Plain, "Malware", Action::Block),
        ("17-MAL-IP4", "Safing Malware List (IPv4)", "https://raw.githubusercontent.com/safing/intel-data/master/lists/malware-ip4.txt", ListFormat::Plain, "Malware", Action::Block),
        ("17-MAL-IP6", "Safing Malware List (IPv6)", "https://raw.githubusercontent.com/safing/intel-data/master/lists/malware-ip6.txt", ListFormat::Plain, "Malware", Action::Block),
        ("17-PSH", "Safing Phishing List", "https://raw.githubusercontent.com/safing/intel-data/master/lists/phishing.txt", ListFormat::Plain, "Deception", Action::Block),
        ("17-TEL", "Safing Telemetry List", "https://raw.githubusercontent.com/safing/intel-data/master/lists/telemetry.txt", ListFormat::Plain, "Ads & Trackers", Action::Block),
        ("17-TRACO", "Safing Tracking List", "https://raw.githubusercontent.com/safing/intel-data/master/lists/tracking-other.txt", ListFormat::Plain, "Ads & Trackers", Action::Block),
        ("WSP", "Windows Spy Blocker", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", ListFormat::Hosts, "Experiments", Action::Block),
        ("AC-FE", "Abuse.ch FEODO Blocklist (IPv4)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", ListFormat::Plain, "Malware", Action::Block),
        ("17-UNBREAK", "Safing Unbreak List (Domains)", "https://raw.githubusercontent.com/safing/intel-data/master/lists/unbreak.txt", ListFormat::Plain, "Unbreak Popular Websites", Action::Allow),
        ("17-UNBREAK-IP4", "Safing Unbreak List (IPv4)", "https://raw.githubusercontent.com/safing/intel-data/master/lists/unbreak-ip4.txt", ListFormat::Plain, "Unbreak Popular Websites", Action::Allow),
        ("17-UNBREAK-IP6", "Safing Unbreak List (IPv6)", "https://raw.githubusercontent.com/safing/intel-data/master/lists/unbreak-ip6.txt", ListFormat::Plain, "Unbreak Popular Websites", Action::Allow),
        ("DCT", "Tracker List by Daniel Cuthbert", "https://raw.githubusercontent.com/danielcuthbert/trackers/master/trackers.txt", ListFormat::Plain, "Experiments", Action::Block),
        ("IPS", "IPsum Threat Intelligence Feed (IPv4)", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", ListFormat::Plain, "Malware", Action::Block),
        ("AGD", "AdGuardDNS List by ray", "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt", ListFormat::Hosts, "Mixed Ads/Trackers/Malware", Action::Block),
        ("OISD", "OISD.nl Blocklist", "https://dblw.oisd.nl/", ListFormat::Wildcard, "Mixed Ads/Trackers/Malware", Action::Block),
        ("OISD-NFSW", "OISD.nl NSFW Blocklist (small)", "https://nsfw-small.oisd.nl/domainswild", ListFormat::Wildcard, "NSFW", Action::Block),
        ("SH-CRL", "CRL endpoints by Scott Helme", "https://raw.githubusercontent.com/ScottHelme/revocation-endpoints/master/crl.txt", ListFormat::Hosts, "Experiments", Action::Block),
        ("SH-OCSP", "OCSP endpoints by Scott Helme", "https://raw.githubusercontent.com/ScottHelme/revocation-endpoints/master/ocsp.txt", ListFormat::Hosts, "Experiments", Action::Block),
        ("BT-META", "Facebook/Meta", "https://raw.githubusercontent.com/safing/intel-data/master/lists/big-tech/facebook-meta.txt", ListFormat::Plain, "Big Tech", Action::Block),
        ("BT-AMZN", "Amazon", "https://raw.githubusercontent.com/safing/intel-data/master/lists/big-tech/amazon.txt", ListFormat::Plain, "Big Tech", Action::Block),
        ("BT-GOOG", "Google", "https://raw.githubusercontent.com/safing/intel-data/master/lists/big-tech/google.txt", ListFormat::Plain, "Big Tech", Action::Block),
        ("BT-APPL", "Apple", "https://raw.githubusercontent.com/safing/intel-data/master/lists/big-tech/apple.txt", ListFormat::Plain, "Big Tech", Action::Block),
        ("BT-MSFT", "Microsoft", "https://raw.githubusercontent.com/safing/intel-data/master/lists/big-tech/microsoft.txt", ListFormat::Plain, "Big Tech", Action::Block),
    ];

    // Portmaster defaults: TRAC, MAL, BAD, and UNBREAK. The remaining broad
    // categories are available but disabled until the user opts in.
    const DEFAULT_ENABLED: &[&str] = &[
        "Ads & Trackers",
        "Malware",
        "Mixed Ads/Trackers/Malware",
        "Unbreak Popular Websites",
    ];

    definitions
        .iter()
        .map(|&(id, name, url, format, category, action)| {
            let mut source =
                FilterSource::new_with_action(id, name, url, format, category, action);
            source.enabled = DEFAULT_ENABLED.contains(&category);
            source
        })
        .collect()
}

/// Resolve the per-user data directory without third-party path crates.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("PORTMASTER_LOCAL_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return PathBuf::from(appdata).join("PortmasterLocal");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("portmaster-local");
    }
    PathBuf::from(".portmaster-local")
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn format_unix(unix: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(now_iso)
}

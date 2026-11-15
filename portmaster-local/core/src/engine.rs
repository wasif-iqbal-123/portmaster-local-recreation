use crate::browser::{self, DohPolicy};
use crate::config::{
    data_dir, format_unix, now_iso, now_unix, Action, FilterSource, FiltersConfig, ListFormat,
    Scope, Settings,
};
use crate::filter::{
    build_index, normalize_domain, parse_list, DomainIndex, DomainMatch, ParsedList,
};
use crate::firewall::{self, FirewallRule};
use crate::monitor::{self, Connection, ProcessInfo};
use crate::guard::{self, Heartbeat};
use crate::resolver::{
    answer_ips, blocked_response, build_query, doh_post_with_servers, http_get_with_servers,
    plain_dns_forward, parse_question, rewrite_id, HttpOptions,
};
use crate::platform;
use crate::rules::{evaluate, AppRule, Rules};
use crate::startup::{self, AutostartConfig};
use crate::system;
use crate::store::{atomic_write, load_json, save_json};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

const MAX_LOGS: usize = 200;
const MAX_LIST_BYTES: usize = 20 * 1024 * 1024;
const UPDATE_TIMEOUT_MS: u32 = 30_000;
const UPDATE_ATTEMPTS: u32 = 3;
const UPDATE_RETRY_BASE_MS: u64 = 1000;
const UPDATE_COOLDOWN_SECS: u64 = 900;

#[derive(Clone, Debug, Serialize, Default)]
pub struct Stats {
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub errors: u64,
    pub blocked_ips: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FirewallConfig {
    pub rules: Vec<FirewallRule>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PortConflict {
    pub port: u16,
    pub protocol: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub settings: Settings,
    pub sources: Vec<FilterSource>,
    pub rules: Rules,
    pub connections: Vec<Connection>,
    pub stats: Stats,
    pub logs: Vec<LogEntry>,
    pub firewall_rules: Vec<FirewallRule>,
    pub system_dns_state: Option<system::DnsConfig>,
    pub system_dns_error: Option<String>,
    pub doh_policy_state: Option<DohPolicy>,
    pub autostart_installed: bool,
    pub autostart_supported: bool,
    pub doh_supported: bool,
    pub dns_udp_port: u16,
    pub dns_tcp_port: u16,
    pub dns_running: bool,
    pub dns_error: Option<String>,
    pub port_conflicts: Vec<PortConflict>,
    pub update_running: bool,
    pub update_completed: usize,
    pub update_total: usize,
    pub update_current: String,
    pub domain_count: usize,
    pub ip_count: usize,
    pub data_dir: String,
    pub platform: String,
    pub firewall_supported: bool,
    pub system_dns_supported: bool,
    pub connection_monitor_supported: bool,
}

struct State {
    settings: Settings,
    sources: Vec<FilterSource>,
    rules: Rules,
    index: DomainIndex,
    connections: Vec<Connection>,
    stats: Stats,
    logs: VecDeque<LogEntry>,
    firewall_rules: Vec<FirewallRule>,
    system_dns_state: Option<system::DnsConfig>,
    system_dns_error: Option<String>,
    doh_policy_state: Option<DohPolicy>,
    autostart_installed: bool,
    dns_udp_port: u16,
    dns_tcp_port: u16,
    dns_running: bool,
    dns_error: Option<String>,
    port_conflicts: Vec<PortConflict>,
    update_running: bool,
    update_completed: usize,
    update_total: usize,
    update_current: String,
}

pub struct Engine {
    data_dir: PathBuf,
    state: RwLock<State>,
    started: AtomicBool,
    updating: AtomicBool,
    next_update_allowed: AtomicU64,
    system_wide: AtomicBool,
}

impl Engine {
    pub fn load() -> Arc<Engine> {
        Self::load_from(data_dir())
    }

    pub fn load_from(dir: PathBuf) -> Arc<Engine> {
        let settings: Settings = load_json(&dir.join("settings.json"));
        let filters: FiltersConfig = load_json(&dir.join("filters.json"));
        let rules: Rules = load_json(&dir.join("rules.json"));
        let firewall_config: FirewallConfig = load_json(&dir.join("firewall.json"));
        let system_dns_state: Option<system::DnsConfig> = load_json(&dir.join("system_dns.json"));
        let doh_policy_state: Option<DohPolicy> = load_json(&dir.join("doh_policy.json"));
        let autostart: AutostartConfig = load_json(&dir.join("autostart.json"));
        let sources = if filters.sources.is_empty() {
            FiltersConfig::default().sources
        } else {
            let mut merged = filters.sources;
            for default in FiltersConfig::default().sources {
                if !merged
                    .iter()
                    .any(|source| source.id == default.id || source.url == default.url)
                {
                    merged.push(default);
                }
            }
            merged
        };
        let engine = Arc::new(Engine {
            data_dir: dir,
            state: RwLock::new(State {
                settings,
                sources,
                rules,
                index: DomainIndex::default(),
                connections: Vec::new(),
                stats: Stats::default(),
                logs: VecDeque::new(),
                firewall_rules: firewall_config.rules,
                system_dns_state,
                system_dns_error: None,
                doh_policy_state,
                autostart_installed: autostart.installed,
                dns_udp_port: 0,
                dns_tcp_port: 0,
                dns_running: false,
                dns_error: None,
                port_conflicts: Vec::new(),
                update_running: false,
                update_completed: 0,
                update_total: 0,
                update_current: String::new(),
            }),
            started: AtomicBool::new(false),
            updating: AtomicBool::new(false),
            next_update_allowed: AtomicU64::new(0),
            system_wide: AtomicBool::new(false),
        });
        engine.rebuild_index();
        engine.log("info", "Portmaster-Local core loaded");
        engine.write_heartbeat();
        engine
    }

    pub fn set_system_wide(&self, value: bool) {
        self.system_wide.store(value, Ordering::SeqCst);
    }

    pub fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        self.spawn_monitor();
        self.spawn_dns();
        self.spawn_updater();
        self.spawn_heartbeat();
        self.spawn_dns_supervisor();
    }

    /// Keep a liveness marker for the crash-safe DNS guard. The guard restores
    /// the recorded system DNS as soon as this process is no longer alive.
    pub fn write_heartbeat(&self) {
        let dns_running = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .dns_running;
        let heartbeat = Heartbeat {
            pid: std::process::id(),
            timestamp: now_unix(),
            dns_running,
        };
        let _ = save_json(&self.heartbeat_path(), &heartbeat);
    }

    pub fn remove_heartbeat(&self) {
        let _ = fs::remove_file(self.heartbeat_path());
    }

    fn heartbeat_path(&self) -> PathBuf {
        self.data_dir.join(guard::HEARTBEAT_FILE_NAME)
    }

    fn spawn_heartbeat(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        thread::Builder::new()
            .name("heartbeat".to_string())
            .spawn(move || loop {
                engine.write_heartbeat();
                thread::sleep(Duration::from_secs(5));
            })
            .ok();
    }

    /// Supervise system DNS while the app runs. Windows/DHCP can reset DNS
    /// after a reconnect, and an unhealthy upstream must not leave the machine
    /// stuck on a dead resolver. Re-apply only after an upstream self-test; on
    /// upstream failure restore the recorded pre-deployment servers.
    fn spawn_dns_supervisor(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        thread::Builder::new()
            .name("dns-supervisor".to_string())
            .spawn(move || {
                thread::sleep(Duration::from_secs(10));
                let mut last_restore = 0u64;
                loop {
                    if engine.system_wide.load(Ordering::SeqCst) {
                        engine.supervise_system_dns(&mut last_restore);
                    }
                    thread::sleep(Duration::from_secs(20));
                }
            })
            .ok();
    }

    fn supervise_system_dns(&self, last_restore: &mut u64) {
        let (dns_running, dns_port, has_state) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            (
                state.dns_running,
                state.dns_udp_port,
                state.system_dns_state.is_some(),
            )
        };

        if !dns_running || dns_port != 53 {
            if has_state {
                if let Err(err) = self.restore_recorded_system_dns() {
                    self.log("error", format!("DNS listener lost; restore failed: {err}"));
                } else {
                    self.log(
                        "warning",
                        "DNS listener is unavailable; restored pre-deployment DNS to keep internet working",
                    );
                }
            }
            return;
        }

        let interface = match system::active_interface() {
            Ok(interface) => interface,
            Err(err) => {
                self.log("warning", format!("DNS supervisor could not detect interface: {err}"));
                return;
            }
        };
        let current = match system::capture_system_dns(&interface) {
            Ok(config) => config,
            Err(err) => {
                self.log("warning", format!("DNS supervisor could not read system DNS: {err}"));
                return;
            }
        };

        if system::points_to_local(&current) {
            match self.probe_upstream() {
                Ok(_) => {
                    *last_restore = 0;
                }
                Err(err) => {
                    let now = now_unix();
                    if *last_restore == 0 || now.saturating_sub(*last_restore) >= 60 {
                        match self.restore_recorded_system_dns() {
                            Ok(()) => {
                                *last_restore = now;
                                self.log(
                                    "warning",
                                    format!(
                                        "upstream unhealthy ({err}); restored pre-deployment DNS so internet is not left broken"
                                    ),
                                );
                            }
                            Err(restore_err) => {
                                self.log(
                                    "error",
                                    format!("upstream unhealthy and DNS restore failed: {restore_err}"),
                                );
                            }
                        }
                    }
                }
            }
            return;
        }

        // Windows/DHCP reset DNS away from this app. Re-apply only after the
        // upstream path proves healthy, otherwise leave normal internet alone.
        let now = now_unix();
        if now.saturating_sub(*last_restore) < 60 {
            return;
        }
        match self.probe_upstream() {
            Ok(_) => match self.apply_system_dns_auto() {
                Ok(config) => self.log(
                    "info",
                    format!(
                        "system DNS re-applied on interface {}; filtering restored",
                        config.interface
                    ),
                ),
                Err(err) => self.log("warning", format!("could not re-apply system DNS: {err}")),
            },
            Err(err) => self.log(
                "warning",
                format!("system DNS is not applied and upstream is unhealthy: {err}"),
            ),
        }
    }

    fn spawn_monitor(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        thread::Builder::new()
            .name("connection-monitor".to_string())
            .spawn(move || loop {
                let connections = monitor::snapshot();
                {
                    let mut state = engine.state.write().unwrap_or_else(|e| e.into_inner());
                    state.connections = connections;
                }
                thread::sleep(Duration::from_secs(3));
            })
            .ok();
    }

    fn spawn_dns(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        thread::Builder::new()
            .name("dns-bind".to_string())
            .spawn(move || {
                let settings = engine.state.read().unwrap_or_else(|e| e.into_inner()).settings.clone();
                let ip: IpAddr = match settings.bind_addr.parse() {
                    Ok(ip) => ip,
                    Err(_) => {
                        engine.log("error", "invalid bind address");
                        let mut state = engine.state.write().unwrap_or_else(|e| e.into_inner());
                        state.dns_error = Some("invalid bind address".to_string());
                        return;
                    }
                };
                let ports = candidate_ports(&settings);
                let (udp, listener, conflicts) = bind_listeners(ip, &ports);

                let udp_port = udp
                    .as_ref()
                    .and_then(|socket| socket.local_addr().ok())
                    .map(|addr| addr.port())
                    .unwrap_or(0);
                let tcp_port = listener
                    .as_ref()
                    .and_then(|listener| listener.local_addr().ok())
                    .map(|addr| addr.port())
                    .unwrap_or(0);
                let dns_error = if udp.is_none() && listener.is_none() {
                    let attempts = ports
                        .iter()
                        .map(|port| port.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    Some(format!(
                        "could not bind DNS server {ip} on configured port(s) {attempts}: {}",
                        conflicts
                            .iter()
                            .map(|conflict| format!("{}:{} {}", conflict.protocol, conflict.port, conflict.reason))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ))
                } else {
                    None
                };

                {
                    let mut state = engine.state.write().unwrap_or_else(|e| e.into_inner());
                    state.dns_udp_port = udp_port;
                    state.dns_tcp_port = tcp_port;
                    state.dns_running = udp_port != 0 || tcp_port != 0;
                    state.dns_error = dns_error.clone();
                    state.port_conflicts = conflicts.clone();
                }

                for conflict in &conflicts {
                    engine.log(
                        "warning",
                        format!(
                            "DNS {} port {} unavailable: {}",
                            conflict.protocol.to_uppercase(),
                            conflict.port,
                            conflict.reason
                        ),
                    );
                }

                if let Some(error) = dns_error {
                    engine.log("error", &error);
                    return;
                }

                let listener_text = if udp_port == tcp_port {
                    format!("{ip}:{udp_port}")
                } else {
                    format!("UDP {ip}:{udp_port}, TCP {ip}:{tcp_port}")
                };
                engine.log("info", format!("DNS server listening on {listener_text}"));

                if let Some(udp) = udp {
                    let engine_udp = Arc::clone(&engine);
                    let socket = Arc::new(udp);
                    thread::Builder::new()
                        .name("dns-udp".to_string())
                        .spawn(move || run_udp(engine_udp, socket))
                        .ok();
                }
                if let Some(listener) = listener {
                    let engine_tcp = Arc::clone(&engine);
                    thread::Builder::new()
                        .name("dns-tcp".to_string())
                        .spawn(move || run_tcp(engine_tcp, listener))
                        .ok();
                }
            })
            .ok();
    }

    fn spawn_updater(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        thread::Builder::new()
            .name("list-updater".to_string())
            .spawn(move || {
                thread::sleep(Duration::from_secs(15));
                // First run: fetch the complete inventory, including opt-in
                // categories, so every category can be enabled without waiting.
                if engine.missing_list_files() > 0 {
                    if let Err(err) = engine.download_all_filters() {
                        if !err.contains("already running") {
                            engine.log("error", err);
                        }
                    }
                }
                loop {
                    if engine.update_due() {
                        if let Err(err) = engine.update_filters(false) {
                            if !err.contains("already running") {
                                engine.log("error", err);
                            }
                        }
                    }
                    thread::sleep(Duration::from_secs(300));
                }
            })
            .ok();
    }

    pub fn log_event(&self, level: &str, message: impl Into<String>) {
        self.log(level, message);
    }

    fn log(&self, level: &str, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: now_iso(),
            level: level.to_string(),
            message: message.into(),
        };
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.logs.push_front(entry);
        while state.logs.len() > MAX_LOGS {
            state.logs.pop_back();
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            settings: state.settings.clone(),
            sources: state.sources.clone(),
            rules: state.rules.clone(),
            connections: state.connections.clone(),
            stats: state.stats.clone(),
            logs: state.logs.iter().cloned().collect(),
            firewall_rules: state.firewall_rules.clone(),
            system_dns_state: state.system_dns_state.clone(),
            system_dns_error: state.system_dns_error.clone(),
            doh_policy_state: state.doh_policy_state.clone(),
            autostart_installed: state.autostart_installed,
            autostart_supported: startup::supported(),
            doh_supported: browser::supported(),
            dns_udp_port: state.dns_udp_port,
            dns_tcp_port: state.dns_tcp_port,
            dns_running: state.dns_running,
            dns_error: state.dns_error.clone(),
            port_conflicts: state.port_conflicts.clone(),
            update_running: state.update_running,
            update_completed: state.update_completed,
            update_total: state.update_total,
            update_current: state.update_current.clone(),
            domain_count: state.index.block.len(),
            ip_count: state.index.ip_block.len(),
            data_dir: self.data_dir.display().to_string(),
            platform: platform::name().to_string(),
            firewall_supported: platform::firewall_supported(),
            system_dns_supported: platform::system_dns_supported(),
            connection_monitor_supported: platform::connection_monitor_supported(),
        }
    }

    fn rebuild_index(&self) {
        let (sources, rules) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            (state.sources.clone(), state.rules.clone())
        };
        let mut updated_sources = sources.clone();
        let mut lists = Vec::new();
        for source in &mut updated_sources {
            let path = self.list_path(&source.id);
            let text = fs::read_to_string(&path).unwrap_or_default();
            let parsed = parse_list(&text, source.format);
            source.count = parsed.domains.len() + parsed.ips.len();
            lists.push((source.enabled, source.action, parsed));
        }
        let index = build_index(&lists, &rules);
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.sources = updated_sources;
        state.index = index;
    }

    fn list_path(&self, id: &str) -> PathBuf {
        self.data_dir.join("lists").join(format!("{id}.txt"))
    }

    fn save_settings(&self) {
        let settings = self.state.read().unwrap_or_else(|e| e.into_inner()).settings.clone();
        let _ = save_json(&self.data_dir.join("settings.json"), &settings);
    }

    fn save_sources(&self) {
        let sources = self.state.read().unwrap_or_else(|e| e.into_inner()).sources.clone();
        let _ = save_json(
            &self.data_dir.join("filters.json"),
            &FiltersConfig { sources },
        );
    }

    fn save_rules(&self) {
        let rules = self.state.read().unwrap_or_else(|e| e.into_inner()).rules.clone();
        let _ = save_json(&self.data_dir.join("rules.json"), &rules);
    }

    fn save_firewall(&self) {
        let rules = self.state.read().unwrap_or_else(|e| e.into_inner()).firewall_rules.clone();
        let _ = save_json(&self.data_dir.join("firewall.json"), &FirewallConfig { rules });
    }

    fn save_system_dns(&self) {
        let config = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .system_dns_state
            .clone();
        let _ = save_json(&self.data_dir.join("system_dns.json"), &config);
    }

    fn save_doh_policy(&self) {
        let config = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .doh_policy_state
            .clone();
        let _ = save_json(&self.data_dir.join("doh_policy.json"), &config);
    }

    fn save_autostart(&self) {
        let config = AutostartConfig {
            installed: self
                .state
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .autostart_installed,
        };
        let _ = save_json(&self.data_dir.join("autostart.json"), &config);
    }

    pub fn set_settings(&self, settings: Settings) -> Result<(), String> {
        if settings.dns_port == 0 {
            return Err("DNS port must be between 1 and 65535".to_string());
        }
        if settings.fallback_port == 0 {
            return Err("fallback port must be between 1 and 65535".to_string());
        }
        if settings.bind_addr.parse::<IpAddr>().is_err() {
            return Err("bind address must be a valid IP address".to_string());
        }
        if settings.update_interval_hours == 0 {
            return Err("update interval must be at least one hour".to_string());
        }
        let (old_port, old_addr) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            (state.settings.dns_port, state.settings.bind_addr.clone())
        };
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.settings = settings.clone();
        }
        self.save_settings();
        if old_port != settings.dns_port || old_addr != settings.bind_addr {
            self.log(
                "info",
                "DNS bind settings changed; restart the app to rebind the server",
            );
        }
        Ok(())
    }

    pub fn set_default_action(&self, action: Action) -> Result<(), String> {
        let mut settings = self.state.read().unwrap_or_else(|e| e.into_inner()).settings.clone();
        settings.default_action = action;
        self.set_settings(settings)
    }

    pub fn add_source(
        &self,
        name: &str,
        url: &str,
        format: ListFormat,
        category: &str,
    ) -> Result<FilterSource, String> {
        let url = url.trim();
        if !url.starts_with("https://") {
            return Err("filter list URL must start with https://".to_string());
        }
        let name = name.trim();
        if name.is_empty() {
            return Err("filter source name is required".to_string());
        }
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let id = slug_id(name, &state.sources);
        let source = FilterSource::new(id, name, url, format, category.trim());
        state.sources.push(source.clone());
        drop(state);
        self.save_sources();
        self.rebuild_index();
        Ok(source)
    }

    pub fn remove_source(&self, id: &str) -> Result<(), String> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let before = state.sources.len();
        state.sources.retain(|source| source.id != id);
        if state.sources.len() == before {
            return Err("filter source not found".to_string());
        }
        drop(state);
        let _ = fs::remove_file(self.list_path(id));
        self.save_sources();
        self.rebuild_index();
        Ok(())
    }

    pub fn set_source_enabled(&self, id: &str, enabled: bool) -> Result<(), String> {
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            let source = state
                .sources
                .iter_mut()
                .find(|source| source.id == id)
                .ok_or_else(|| "filter source not found".to_string())?;
            source.enabled = enabled;
        }
        self.save_sources();
        self.rebuild_index();
        Ok(())
    }

    pub fn set_category_enabled(&self, category: &str, enabled: bool) -> Result<usize, String> {
        let changed = {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            let matching = state
                .sources
                .iter()
                .filter(|source| source.category == category)
                .count();
            if matching == 0 {
                return Err("filter category not found".to_string());
            }
            for source in state
                .sources
                .iter_mut()
                .filter(|source| source.category == category)
            {
                source.enabled = enabled;
            }
            matching
        };
        self.save_sources();
        self.rebuild_index();
        Ok(changed)
    }

    pub fn update_filters(self: &Arc<Self>, force: bool) -> Result<(), String> {
        self.start_update(force, false)
    }

    pub fn download_all_filters(self: &Arc<Self>) -> Result<(), String> {
        self.start_update(true, true)
    }

    /// True while any configured source has no list file on disk yet.
    pub fn missing_list_files(&self) -> usize {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state
            .sources
            .iter()
            .filter(|source| !self.list_path(&source.id).exists())
            .count()
    }

    fn start_update(self: &Arc<Self>, force: bool, include_disabled: bool) -> Result<(), String> {
        if self.updating.swap(true, Ordering::SeqCst) {
            return Err("an update is already running".to_string());
        }
        let total = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            let interval = state.settings.update_interval_hours.max(1) * 3600;
            let now = now_unix();
            state
                .sources
                .iter()
                .filter(|source| should_update(source, force, include_disabled, interval, now))
                .count()
        };
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.update_running = true;
            state.update_completed = 0;
            state.update_total = total;
            state.update_current = String::new();
        }
        let engine = Arc::clone(self);
        thread::Builder::new()
            .name("filter-download".to_string())
            .spawn(move || {
                engine.perform_update(force, include_disabled);
                let mut state = engine.state.write().unwrap_or_else(|e| e.into_inner());
                state.update_running = false;
                engine.updating.store(false, Ordering::SeqCst);
            })
            .map_err(|err| {
                self.updating.store(false, Ordering::SeqCst);
                let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                state.update_running = false;
                format!("could not start updater: {err}")
            })?;
        Ok(())
    }

    fn update_due(&self) -> bool {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        if !state.settings.auto_update {
            return false;
        }
        let now = now_unix();
        if now < self.next_update_allowed.load(Ordering::SeqCst) {
            return false;
        }
        let interval = state.settings.update_interval_hours.max(1) * 3600;
        state
            .sources
            .iter()
            .any(|source| should_update(source, false, false, interval, now))
    }

    fn perform_update(&self, force: bool, include_disabled: bool) {
        let (sources, auto_update, interval) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            (
                state.sources.clone(),
                state.settings.auto_update,
                state.settings.update_interval_hours.max(1) * 3600,
            )
        };
        if !auto_update && !force {
            return;
        }
        let now = now_unix();
        let mut success = 0usize;
        let mut failed = 0usize;
        let mut sources_now = sources.clone();
        for source in sources_now.iter_mut() {
            if !should_update(source, force, include_disabled, interval, now) {
                continue;
            }
            {
                let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                state.update_current = source.name.clone();
            }
            match self.download_source(source) {
                Ok(body) => match self.store_source(source, &body) {
                    Ok(()) => success += 1,
                    Err(err) => {
                        source.error = Some(err.clone());
                        failed += 1;
                        self.log("error", format!("filter source {} failed: {err}", source.name));
                    }
                },
                Err(err) => {
                    source.error = Some(err.clone());
                    failed += 1;
                    self.log("error", format!("filter source {} failed: {err}", source.name));
                }
            }
            {
                let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                state.update_completed = state.update_completed.saturating_add(1);
            }
        }
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.sources = sources_now;
            state.update_current = String::new();
            state.update_completed = state.update_total;
        }
        self.save_sources();
        self.rebuild_index();
        if failed > 0 {
            self.next_update_allowed
                .store(now_unix() + UPDATE_COOLDOWN_SECS, Ordering::SeqCst);
            self.log(
                "warning",
                format!(
                    "next automatic filter update attempt in {} minutes",
                    UPDATE_COOLDOWN_SECS / 60
                ),
            );
        } else {
            self.next_update_allowed.store(0, Ordering::SeqCst);
        }
        self.log(
            if failed > 0 { "error" } else { "info" },
            format!("filter update finished: {success} updated, {failed} failed"),
        );
    }

    fn download_source(&self, source: &FilterSource) -> Result<Vec<u8>, String> {
        let name = source.name.clone();
        let servers = self.bootstrap_servers();
        retry_fetch(
            &source.url,
            UPDATE_ATTEMPTS,
            Duration::from_millis(UPDATE_RETRY_BASE_MS),
            |url| {
                http_get_with_servers(
                    url,
                    HttpOptions::new(UPDATE_TIMEOUT_MS, MAX_LIST_BYTES),
                    &servers,
                )
            },
            |attempt, err| {
                self.log(
                    "warning",
                    format!(
                        "filter download attempt {attempt}/{UPDATE_ATTEMPTS} failed for {name}: {err}"
                    ),
                );
            },
        )
    }

    fn store_source(&self, source: &mut FilterSource, body: &[u8]) -> Result<(), String> {
        let parsed = parse_list_body(
            body,
            source.format,
            MAX_LIST_BYTES,
            source.action == Action::Allow,
        )?;
        atomic_write(&self.list_path(&source.id), body)?;
        source.count = parsed.domains.len() + parsed.ips.len();
        source.last_update_unix = Some(now_unix());
        source.last_updated = Some(format_unix(source.last_update_unix.unwrap_or(0)));
        source.error = None;
        self.log(
            "info",
            format!(
                "filter source {} updated: {} domains, {} IPs, {} bytes",
                source.name,
                parsed.domains.len(),
                parsed.ips.len(),
                body.len()
            ),
        );
        Ok(())
    }

    pub fn add_custom_domain(&self, action: Action, domain: &str) -> Result<(), String> {
        let domain = normalize_domain(domain).ok_or_else(|| "invalid domain name".to_string())?;
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        match action {
            Action::Allow => {
                if !state.rules.custom_allow.contains(&domain) {
                    state.rules.custom_allow.push(domain);
                }
            }
            Action::Block => {
                if !state.rules.custom_block.contains(&domain) {
                    state.rules.custom_block.push(domain);
                }
            }
        }
        drop(state);
        self.save_rules();
        self.rebuild_index();
        Ok(())
    }

    pub fn remove_custom_domain(&self, action: Action, domain: &str) -> Result<(), String> {
        let domain = normalize_domain(domain).ok_or_else(|| "invalid domain name".to_string())?;
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        match action {
            Action::Allow => state.rules.custom_allow.retain(|entry| entry != &domain),
            Action::Block => state.rules.custom_block.retain(|entry| entry != &domain),
        }
        drop(state);
        self.save_rules();
        self.rebuild_index();
        Ok(())
    }

    pub fn add_app_rule(
        &self,
        app_match: &str,
        action: Action,
        scope: Scope,
    ) -> Result<AppRule, String> {
        let app_match = app_match.trim();
        if app_match.is_empty() {
            return Err("application name or path is required".to_string());
        }
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        if state.rules.app_rules.iter().any(|rule| {
            rule.app_match.eq_ignore_ascii_case(app_match)
                && rule.action == action
                && rule.scope == scope
        }) {
            return Err("an identical app rule already exists".to_string());
        }
        let id = format!("app-{}", slug_hash(app_match, action, scope));
        let rule = AppRule {
            id,
            app_match: app_match.to_string(),
            action,
            scope,
        };
        state.rules.app_rules.push(rule.clone());
        drop(state);
        self.save_rules();
        Ok(rule)
    }

    pub fn remove_app_rule(&self, id: &str) -> Result<(), String> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let before = state.rules.app_rules.len();
        state.rules.app_rules.retain(|rule| rule.id != id);
        if state.rules.app_rules.len() == before {
            return Err("app rule not found".to_string());
        }
        drop(state);
        self.save_rules();
        Ok(())
    }

    pub fn apply_app_firewall(&self, path: &str) -> Result<FirewallRule, String> {
        let rule = firewall::apply_app_block(path)?;
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            if !state.firewall_rules.iter().any(|entry| entry.name == rule.name) {
                state.firewall_rules.push(rule.clone());
            }
        }
        self.save_firewall();
        self.log("info", format!("firewall block applied for {path}"));
        Ok(rule)
    }

    pub fn apply_firewall_preset(&self, preset: &str) -> Result<FirewallRule, String> {
        let rule = match preset {
            "outbound" => firewall::apply_block_all_outbound()?,
            "inbound" => firewall::apply_block_all_inbound()?,
            _ => return Err("unknown firewall preset".to_string()),
        };
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            if !state.firewall_rules.iter().any(|entry| entry.name == rule.name) {
                state.firewall_rules.push(rule.clone());
            }
        }
        self.save_firewall();
        self.log("info", format!("firewall preset {preset} applied"));
        Ok(rule)
    }

    pub fn remove_firewall_rule(&self, name: &str) -> Result<(), String> {
        firewall::remove_rule(name)?;
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.firewall_rules.retain(|entry| entry.name != name);
        }
        self.save_firewall();
        self.log("info", format!("firewall rule removed: {name}"));
        Ok(())
    }

    pub fn clear_firewall_rules(&self) -> Result<(), String> {
        let rules = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .firewall_rules
            .clone();
        let mut errors = Vec::new();
        for rule in rules {
            if let Err(err) = firewall::remove_rule(&rule.name) {
                errors.push(err);
            }
        }
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.firewall_rules.clear();
        }
        self.save_firewall();
        if errors.is_empty() {
            self.log("info", "all local firewall rules removed");
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn apply_system_dns(&self, interface: &str, port: u16) -> Result<system::DnsConfig, String> {
        let (dns_running, dns_udp_port) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            (state.dns_running, state.dns_udp_port)
        };
        if !dns_running || dns_udp_port != 53 {
            let message = "system-wide DNS requires this app to own UDP 53; restart with an elevated listener on port 53 first".to_string();
            {
                let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                state.system_dns_error = Some(message.clone());
            }
            return Err(message);
        }
        let prior = match system::apply_system_dns(interface, port) {
            Ok(prior) => prior,
            Err(err) => {
                let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                state.system_dns_error = Some(err.clone());
                return Err(err);
            }
        };
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.system_dns_state = Some(prior.clone());
            state.system_dns_error = None;
        }
        self.save_system_dns();
        self.log(
            "info",
            format!("system DNS set to 127.0.0.1 on interface {interface}; prior servers recorded"),
        );
        Ok(prior)
    }

    /// Resolve the current default-route interface and point it at this resolver.
    /// If a prior state is already recorded for that interface, keep it instead
    /// of recapturing 127.0.0.1 as the servers to restore.
    pub fn apply_system_dns_auto(&self) -> Result<system::DnsConfig, String> {
        let interface = system::active_interface()?;
        let existing = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .system_dns_state
            .clone();
        if let Some(config) = existing {
            if config.interface.eq_ignore_ascii_case(&interface) {
                if let Err(err) = system::point_system_dns(&interface) {
                    let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                    state.system_dns_error = Some(err.clone());
                    return Err(err);
                }
                self.log(
                    "info",
                    format!("system DNS reapplied on interface {interface}; prior servers retained"),
                );
                return Ok(config);
            }
        }
        self.apply_system_dns(&interface, 53)
    }

    pub fn reset_system_dns(&self, interface: &str) -> Result<(), String> {
        let saved = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .system_dns_state
            .clone();
        match saved {
            Some(config) => {
                if !config.interface.eq_ignore_ascii_case(interface.trim()) {
                    return Err(format!(
                        "recorded DNS state belongs to interface {}; pass that interface to restore it",
                        config.interface
                    ));
                }
                system::restore_system_dns(&config)?;
            }
            None => {
                return Err("no recorded DNS state; set system DNS first".to_string());
            }
        }
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.system_dns_state = None;
            state.system_dns_error = None;
        }
        self.save_system_dns();
        self.log("info", format!("system DNS restored on interface {interface}"));
        Ok(())
    }

    /// Restore any recorded DNS state. Used when the app exits so a stopped
    /// resolver does not leave the machine pointing at a dead 127.0.0.1.
    pub fn restore_recorded_system_dns(&self) -> Result<(), String> {
        let interface = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .system_dns_state
            .as_ref()
            .map(|config| config.interface.clone());
        match interface {
            Some(interface) => self.reset_system_dns(&interface),
            None => Ok(()),
        }
    }

    pub fn disable_browser_doh(&self) -> Result<DohPolicy, String> {
        let prior = browser::disable()?;
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.doh_policy_state = Some(prior.clone());
        }
        self.save_doh_policy();
        self.log(
            "info",
            "Chromium browser DoH disabled for Brave, Chrome, and Edge; prior policy recorded",
        );
        Ok(prior)
    }

    pub fn restore_browser_doh(&self) -> Result<(), String> {
        let saved = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .doh_policy_state
            .clone();
        match saved {
            Some(policy) => browser::restore(&policy)?,
            None => return Err("no recorded browser DoH policy state".to_string()),
        }
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.doh_policy_state = None;
        }
        self.save_doh_policy();
        self.log("info", "browser DoH policy restored");
        Ok(())
    }

    pub fn install_autostart(&self, exe: &str) -> Result<(), String> {
        startup::install(exe)?;
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.autostart_installed = true;
        }
        self.save_autostart();
        self.log(
            "info",
            format!(
                "login autostart installed for {exe}; --system-wide and --dns-guard tasks run elevated"
            ),
        );
        Ok(())
    }

    pub fn remove_autostart(&self) -> Result<(), String> {
        startup::remove()?;
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.autostart_installed = false;
        }
        self.save_autostart();
        self.log("info", "login autostart removed");
        Ok(())
    }

    pub fn refresh_autostart_state(&self) -> Result<bool, String> {
        let installed = startup::installed()? && startup::guard_installed()?;
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.autostart_installed = installed;
        }
        self.save_autostart();
        Ok(installed)
    }

    pub fn clear_logs(&self) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.logs.clear();
    }

    fn process_for(&self, source: SocketAddr, protocol: &str) -> Option<ProcessInfo> {
        if !source.ip().is_loopback() {
            return None;
        }
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state
            .connections
            .iter()
            .find(|connection| {
                connection.protocol == protocol && connection.local_port == source.port()
            })
            .map(|connection| ProcessInfo {
                pid: connection.pid,
                name: connection.process.clone(),
                path: connection.path.clone(),
            })
    }

    /// Upstream servers recorded before the OS DNS was pointed at this app.
    /// They are used to bootstrap DoH/filter hostnames without the OS resolver,
    /// which otherwise loops back into this listener.
    fn bootstrap_servers(&self) -> Vec<IpAddr> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let mut servers = Vec::new();
        if let Some(config) = &state.system_dns_state {
            for raw in config.ipv4.iter().chain(config.ipv6.iter()) {
                if let Ok(ip) = raw.parse::<IpAddr>() {
                    if !ip.is_loopback() && !ip.is_unspecified() && !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
        servers
    }

    /// Test that upstream resolution works before the OS DNS is changed. This
    /// is the deployment gate that prevents turning the machine's internet off.
    pub fn probe_upstream(&self) -> Result<String, String> {
        let query = build_query("example.com", 1, 0x706d)?;
        let response = self.forward(&query)?;
        let addresses = answer_ips(&response);
        if addresses.is_empty() {
            return Err("upstream resolver returned no addresses for example.com".to_string());
        }
        Ok(format!(
            "upstream resolver returned {} address(es) for example.com",
            addresses.len()
        ))
    }

    fn forward(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let settings = self.state.read().unwrap_or_else(|e| e.into_inner()).settings.clone();
        let servers = self.bootstrap_servers();
        let urls = doh_candidates(&settings);
        let mut last_error = String::new();

        // When deployment recorded the prior upstream servers, use plain DNS to
        // that upstream first. Windows DNS clients have short timeouts, and a
        // DoH TLS handshake can exceed them when Cloudflare/Quad9 is slow.
        if !servers.is_empty() {
            match plain_dns_forward(query, &servers, 3000) {
                Ok(response) => return Ok(response),
                Err(err) => last_error = format!("plain upstream failed: {err}"),
            }
        }

        for url in &urls {
            match doh_post_with_servers(url, query, &servers) {
                Ok(mut response) => {
                    rewrite_id(&mut response, query)?;
                    return Ok(response);
                }
                Err(err) => last_error = format!("{last_error}; {url}: {err}"),
            }
        }

        if last_error.is_empty() {
            last_error = "no DoH upstream configured and no recorded upstream DNS server".to_string();
        }
        Err(last_error)
    }

    fn handle_query(&self, query: &[u8], source: Option<SocketAddr>, protocol: &str) -> Vec<u8> {
        let Some(question) = parse_question(query) else {
            return servfail_response(query);
        };
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.stats.queries += 1;
        }
        let app = source.and_then(|addr| self.process_for(addr, protocol));
        let decision = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            evaluate(
                &state.index,
                &state.rules,
                state.settings.default_action,
                app.as_ref(),
                &question.name,
            )
        };
        if decision.action == Action::Block {
            self.note_block(&question.name, &decision.reason, app.as_ref());
            return blocked_response(query, question.end, 3);
        }
        match self.forward(query) {
            Ok(response) => {
                let blocked_ip = {
                    let state = self.state.read().unwrap_or_else(|e| e.into_inner());
                    answer_ips(&response)
                        .into_iter()
                        .any(|ip| state.index.ip_match(ip) == Some(DomainMatch::Block))
                };
                if blocked_ip {
                    self.note_block_ip(&question.name, app.as_ref());
                    return blocked_response(query, question.end, 3);
                }
                {
                    let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                    state.stats.forwarded += 1;
                }
                response
            }
            Err(err) => {
                {
                    let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
                    state.stats.errors += 1;
                }
                self.log("error", format!("DNS upstream failed for {}: {err}", question.name));
                servfail_response(query)
            }
        }
    }

    fn note_block(&self, domain: &str, reason: &str, app: Option<&ProcessInfo>) {
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.stats.blocked += 1;
        }
        let app_text = app
            .map(|process| format!(" [{}]", process.name))
            .unwrap_or_default();
        self.log("blocked", format!("{domain}{app_text}: {reason}"));
    }

    fn note_block_ip(&self, domain: &str, app: Option<&ProcessInfo>) {
        {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            state.stats.blocked += 1;
            state.stats.blocked_ips += 1;
        }
        let app_text = app
            .map(|process| format!(" [{}]", process.name))
            .unwrap_or_default();
        self.log("blocked", format!("{domain}{app_text}: blocked IP in answer"));
    }
}

fn candidate_ports(settings: &Settings) -> Vec<u16> {
    let mut ports = Vec::new();
    for port in [settings.dns_port, settings.fallback_port] {
        if port != 0 && !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports
}

/// Bind UDP and TCP independently so a failure on one protocol does not
/// discard a listener that succeeded on the other.
fn bind_listeners(
    ip: IpAddr,
    ports: &[u16],
) -> (Option<UdpSocket>, Option<TcpListener>, Vec<PortConflict>) {
    let mut udp = None;
    let mut tcp = None;
    let mut conflicts = Vec::new();
    for &port in ports {
        if udp.is_none() {
            match UdpSocket::bind((ip, port)) {
                Ok(socket) => udp = Some(socket),
                Err(err) => conflicts.push(PortConflict {
                    port,
                    protocol: "udp".to_string(),
                    reason: err.to_string(),
                }),
            }
        }
        if tcp.is_none() {
            match TcpListener::bind((ip, port)) {
                Ok(listener) => tcp = Some(listener),
                Err(err) => conflicts.push(PortConflict {
                    port,
                    protocol: "tcp".to_string(),
                    reason: err.to_string(),
                }),
            }
        }
        if udp.is_some() && tcp.is_some() {
            break;
        }
    }
    (udp, tcp, conflicts)
}

fn servfail_response(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut response = query[..12].to_vec();
    let mut flags = u16::from_be_bytes([query[2], query[3]]);
    flags |= 0x8000;
    flags = (flags & !0x000f) | 2;
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    for offset in [4usize, 6, 8, 10] {
        response[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes());
    }
    response
}

fn parse_list_body(
    body: &[u8],
    format: ListFormat,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<ParsedList, String> {
    if body.len() > max_bytes {
        return Err(format!(
            "downloaded list is {} bytes, over the {max_bytes} byte limit",
            body.len()
        ));
    }
    let parsed = parse_list(&String::from_utf8_lossy(body), format);
    let comment_only = !body.is_empty()
        && body.split(|byte| *byte == b'\n').all(|line| {
            let line = line.trim_ascii();
            line.is_empty() || line.starts_with(b"#") || line.starts_with(b"//")
        });
    if parsed.domains.is_empty() && parsed.ips.is_empty() && !allow_empty && !comment_only {
        return Err("downloaded list was empty or unparseable".to_string());
    }
    Ok(parsed)
}

fn retry_fetch<F, L>(
    url: &str,
    attempts: u32,
    base_backoff: Duration,
    mut fetch: F,
    mut on_failure: L,
) -> Result<Vec<u8>, String>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
    L: FnMut(u32, &str),
{
    let attempts = attempts.max(1);
    let mut last_error = String::new();
    for attempt in 1..=attempts {
        match fetch(url) {
            Ok(body) => return Ok(body),
            Err(err) => {
                last_error = err;
                on_failure(attempt, &last_error);
                if attempt < attempts {
                    let factor = 1u32 << (attempt - 1).min(30);
                    thread::sleep(base_backoff * factor);
                }
            }
        }
    }
    Err(format!("after {attempts} attempts: {last_error}"))
}

fn doh_candidates(settings: &Settings) -> Vec<String> {
    let mut urls = Vec::new();
    for raw in [&settings.primary_doh_url, &settings.fallback_doh_url] {
        let url = raw.trim();
        if url.is_empty() || !url.starts_with("https://") {
            continue;
        }
        let url = url.to_string();
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

fn run_udp(engine: Arc<Engine>, socket: Arc<UdpSocket>) {
    let mut buffer = [0u8; 8192];
    loop {
        let (length, source) = match socket.recv_from(&mut buffer) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if length == 0 {
            continue;
        }
        let query = buffer[..length].to_vec();
        let engine = Arc::clone(&engine);
        let socket = Arc::clone(&socket);
        thread::Builder::new()
            .name("dns-query".to_string())
            .spawn(move || {
                let response = engine.handle_query(&query, Some(source), "udp");
                if !response.is_empty() {
                    let _ = socket.send_to(&response, source);
                }
            })
            .ok();
    }
}

fn run_tcp(engine: Arc<Engine>, listener: TcpListener) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let engine = Arc::clone(&engine);
        thread::Builder::new()
            .name("dns-tcp-query".to_string())
            .spawn(move || handle_tcp(engine, stream))
            .ok();
    }
}

fn handle_tcp(engine: Arc<Engine>, mut stream: TcpStream) {
    let source = stream.peer_addr().ok();
    let mut length_bytes = [0u8; 2];
    if stream.read_exact(&mut length_bytes).is_err() {
        return;
    }
    let length = u16::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > 65535 {
        return;
    }
    let mut query = vec![0u8; length];
    if stream.read_exact(&mut query).is_err() {
        return;
    }
    let response = engine.handle_query(&query, source, "tcp");
    if response.is_empty() {
        return;
    }
    let mut framed = Vec::with_capacity(response.len() + 2);
    framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
    framed.extend_from_slice(&response);
    let _ = stream.write_all(&framed);
}

fn slug_id(name: &str, existing: &[FilterSource]) -> String {
    let base: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let base = base.trim_matches('-').to_string();
    let base = if base.is_empty() { "list".to_string() } else { base };
    let mut candidate = base.clone();
    let mut counter = 2;
    while existing.iter().any(|source| source.id == candidate) {
        candidate = format!("{base}-{counter}");
        counter += 1;
    }
    candidate
}

fn slug_hash(app_match: &str, action: Action, scope: Scope) -> String {
    let text = format!("{app_match}|{action:?}|{scope:?}");
    let mut hash = 0xcbf29ce484222325u64;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// A source is a candidate for an update when it is enabled (unless disabled
/// sources were explicitly requested) and its last update is older than the
/// configured interval. Forced updates ignore the interval.
fn should_update(
    source: &FilterSource,
    force: bool,
    include_disabled: bool,
    interval_secs: u64,
    now: u64,
) -> bool {
    if !include_disabled && !source.enabled {
        return false;
    }
    if force {
        return true;
    }
    match source.last_update_unix {
        Some(last) => now.saturating_sub(last) >= interval_secs,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform;

    #[test]
    fn snapshot_reports_platform_capabilities() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-platform-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.platform, platform::name());
        assert_eq!(snapshot.firewall_supported, platform::firewall_supported());
        assert_eq!(snapshot.system_dns_supported, platform::system_dns_supported());
        assert_eq!(snapshot.autostart_supported, startup::supported());
        assert_eq!(snapshot.doh_supported, browser::supported());
        assert_eq!(
            snapshot.connection_monitor_supported,
            platform::connection_monitor_supported()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_system_dns_state_round_trips_in_the_data_directory() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-dns-state-test");
        let _ = fs::remove_dir_all(&dir);
        let config = system::DnsConfig {
            interface: "12".to_string(),
            ipv4: vec!["192.168.1.1".to_string()],
            ipv6: vec!["2001:db8::1".to_string()],
        };
        save_json(&dir.join("system_dns.json"), &Some(config.clone())).unwrap();
        let engine = Engine::load_from(dir.clone());
        assert_eq!(engine.snapshot().system_dns_state, Some(config));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_without_recorded_state_returns_an_error() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-dns-reset-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        assert!(engine.reset_system_dns("12").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_system_dns_requires_an_owned_udp_53_listener() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-dns-apply-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        assert!(!engine.snapshot().dns_running);
        let error = engine.apply_system_dns("12", 53).unwrap_err();
        assert!(error.contains("own UDP 53"));
        assert_eq!(
            engine.snapshot().system_dns_error.as_deref(),
            Some(error.as_str())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_doh_and_autostart_state_round_trip() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-doh-autostart-test");
        let _ = fs::remove_dir_all(&dir);
        let policy = DohPolicy {
            entries: vec![browser::DohPolicyEntry {
                path: browser::POLICY_KEYS[2].to_string(),
                value: Some("automatic".to_string()),
            }],
        };
        save_json(&dir.join("doh_policy.json"), &Some(policy.clone())).unwrap();
        save_json(&dir.join("autostart.json"), &AutostartConfig { installed: true }).unwrap();
        let engine = Engine::load_from(dir.clone());
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.doh_policy_state, Some(policy));
        assert!(snapshot.autostart_installed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_reports_zero_update_progress_before_a_run() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-update-progress-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        let snapshot = engine.snapshot();
        assert!(!snapshot.update_running);
        assert_eq!(snapshot.update_completed, 0);
        assert_eq!(snapshot.update_total, 0);
        assert_eq!(snapshot.update_current, "");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_update_honors_interval_force_and_disabled_sources() {
        let mut source = FilterSource::new(
            "update-test",
            "update test",
            "https://example.invalid/list",
            ListFormat::Plain,
            "test",
        );
        let now = 10_000u64;
        source.last_update_unix = None;
        assert!(should_update(&source, false, false, 3600, now));
        assert!(should_update(&source, true, false, 3600, now));

        source.last_update_unix = Some(now - 1000);
        assert!(!should_update(&source, false, false, 3600, now));
        assert!(should_update(&source, true, false, 3600, now));

        source.last_update_unix = Some(now - 4000);
        assert!(should_update(&source, false, false, 3600, now));

        source.enabled = false;
        assert!(!should_update(&source, false, false, 3600, now));
        assert!(should_update(&source, true, true, 3600, now));
    }

    #[test]
    fn default_sources_use_portmaster_categories_and_defaults() {
        let sources = crate::config::default_sources();
        assert_eq!(sources.len(), 39);
        assert!(sources.iter().all(|source| !source.category.is_empty()));
        assert!(sources.iter().any(|source| source.category == "NSFW"));
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.category == "NSFW" && source.enabled)
                .count(),
            0
        );
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.category == "Unbreak Popular Websites")
                .count(),
            3
        );
        assert!(sources.iter().filter(|source| source.enabled).count() >= 10);
        assert!(sources
            .iter()
            .filter(|source| source.category == "Unbreak Popular Websites")
            .all(|source| source.action == Action::Allow));
        assert!(!sources
            .iter()
            .any(|source| source.category == "Social Media"));
    }

    #[test]
    fn category_toggle_updates_every_child_source() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-category-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        let changed = engine.set_category_enabled("NSFW", true).unwrap();
        assert_eq!(changed, 5);
        {
            let state = engine.state.read().unwrap_or_else(|e| e.into_inner());
            assert!(state
                .sources
                .iter()
                .filter(|source| source.category == "NSFW")
                .all(|source| source.enabled));
        }
        engine.set_category_enabled("NSFW", false).unwrap();
        assert!(engine.set_category_enabled("Missing", true).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn slug_ids_are_unique_and_safe() {
        let existing = vec![FilterSource::new("same-name", "x", "https://x", ListFormat::Plain, "x")];
        let id = slug_id("same name", &existing);
        assert_eq!(id, "same-name-2");
    }

    #[test]
    fn servfail_response_has_zero_counts() {
        let query = vec![0u8; 12];
        let response = servfail_response(&query);
        assert_eq!(response.len(), 12);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 2);
    }

    fn make_query(name: &str) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        query
    }

    #[test]
    fn blocked_query_is_answered_locally() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("engine-block-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        engine.add_custom_domain(Action::Block, "ads.example.com").unwrap();

        let response = engine.handle_query(&make_query("ads.example.com"), None, "udp");
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 3);
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.stats.queries, 1);
        assert_eq!(snapshot.stats.blocked, 1);
        assert_eq!(snapshot.stats.forwarded, 0);
        assert!(snapshot.logs.iter().any(|entry| entry.level == "blocked"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_body_validation_rejects_empty_and_oversized() {
        assert!(parse_list_body(b"", ListFormat::Plain, 1024, false).is_err());
        assert!(parse_list_body(b"", ListFormat::Plain, 1024, true).is_ok());
        assert!(
            parse_list_body(b"# header only\n\n", ListFormat::Plain, 1024, false).is_ok()
        );
        assert!(
            parse_list_body(b"too-big.example", ListFormat::Plain, 4, false).is_err()
        );
        assert!(
            parse_list_body(b"bad.example\n", ListFormat::Plain, 1024, false).is_ok()
        );
    }

    #[test]
    fn retry_fetch_recovers_from_transient_failures() {
        let mut calls = 0u32;
        let mut logged = Vec::new();
        let body = retry_fetch(
            "https://example.invalid/list",
            3,
            Duration::from_millis(0),
            |_url| {
                calls += 1;
                if calls < 3 {
                    Err(format!("attempt {calls} failed"))
                } else {
                    Ok(b"bad.example\n".to_vec())
                }
            },
            |attempt, err| logged.push((attempt, err.to_string())),
        )
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(body, b"bad.example\n".to_vec());
        assert_eq!(logged.len(), 2);
    }

    #[test]
    fn retry_fetch_reports_the_final_error() {
        let err = retry_fetch(
            "https://example.invalid/list",
            2,
            Duration::from_millis(0),
            |_url| Err("boom".to_string()),
            |_attempt, _err| {},
        )
        .unwrap_err();
        assert!(err.contains("after 2 attempts"));
        assert!(err.contains("boom"));
    }

    #[test]
    fn doh_candidates_follow_primary_then_fallback_and_deduplicate() {
        let settings = Settings {
            primary_doh_url: "https://a.example/dns-query".to_string(),
            fallback_doh_url: "https://a.example/dns-query".to_string(),
            ..Settings::default()
        };
        assert_eq!(doh_candidates(&settings), vec!["https://a.example/dns-query"]);

        let settings = Settings {
            primary_doh_url: "https://a.example/dns-query".to_string(),
            fallback_doh_url: "http://b.example/dns-query".to_string(),
            ..Settings::default()
        };
        assert_eq!(doh_candidates(&settings), vec!["https://a.example/dns-query"]);

        let settings = Settings {
            primary_doh_url: String::new(),
            fallback_doh_url: String::new(),
            ..Settings::default()
        };
        assert!(doh_candidates(&settings).is_empty());
    }

    #[test]
    fn store_source_persists_list_and_metadata() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-store-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        let mut source = FilterSource::new(
            "test-list",
            "test list",
            "https://example.invalid/list",
            ListFormat::Plain,
            "test",
        );
        let body = b"bad.example\n10.0.0.0/8\n";
        engine.store_source(&mut source, body).unwrap();
        assert_eq!(source.count, 2);
        assert!(source.last_update_unix.is_some());
        assert!(source.error.is_none());
        assert_eq!(fs::read(engine.list_path(&source.id)).unwrap(), body);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_update_cooldown_suppresses_automatic_updates() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-cooldown-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        assert!(engine.update_due());
        engine
            .next_update_allowed
            .store(now_unix() + UPDATE_COOLDOWN_SECS, Ordering::SeqCst);
        assert!(!engine.update_due());
        let _ = fs::remove_dir_all(&dir);
    }

    fn occupy_both(ip: IpAddr) -> (u16, UdpSocket, TcpListener) {
        for _ in 0..50 {
            let udp = UdpSocket::bind((ip, 0)).unwrap();
            let port = udp.local_addr().unwrap().port();
            if let Ok(tcp) = TcpListener::bind((ip, port)) {
                return (port, udp, tcp);
            }
        }
        panic!("could not find a free port for the test");
    }

    fn reserve_free_port(ip: IpAddr) -> u16 {
        for _ in 0..50 {
            let udp = UdpSocket::bind((ip, 0)).unwrap();
            let port = udp.local_addr().unwrap().port();
            if let Ok(tcp) = TcpListener::bind((ip, port)) {
                drop(tcp);
                drop(udp);
                return port;
            }
        }
        panic!("could not reserve a free port for the test");
    }

    #[test]
    fn candidate_ports_deduplicate_and_ignore_zero() {
        let settings = Settings {
            dns_port: 53,
            fallback_port: 5333,
            ..Settings::default()
        };
        assert_eq!(candidate_ports(&settings), vec![53, 5333]);

        let settings = Settings {
            dns_port: 53,
            fallback_port: 53,
            ..Settings::default()
        };
        assert_eq!(candidate_ports(&settings), vec![53]);

        let settings = Settings {
            dns_port: 53,
            fallback_port: 0,
            ..Settings::default()
        };
        assert_eq!(candidate_ports(&settings), vec![53]);
    }

    #[test]
    fn binds_udp_and_tcp_independently_when_udp_is_occupied() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let (held_port, held_udp, held_tcp) = occupy_both(ip);
        drop(held_tcp);
        let free_port = reserve_free_port(ip);

        let (udp, tcp, conflicts) = bind_listeners(ip, &[held_port, free_port]);
        assert_eq!(
            udp.expect("UDP should bind on the fallback port").local_addr().unwrap().port(),
            free_port
        );
        assert_eq!(
            tcp.expect("TCP should still bind on the requested port").local_addr().unwrap().port(),
            held_port
        );
        assert!(conflicts
            .iter()
            .any(|conflict| conflict.port == held_port && conflict.protocol == "udp"));
        drop(held_udp);
    }

    #[test]
    fn reports_conflicts_when_all_candidate_ports_are_occupied() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let (first, first_udp, first_tcp) = occupy_both(ip);
        let (second, second_udp, second_tcp) = occupy_both(ip);

        let (udp, tcp, conflicts) = bind_listeners(ip, &[first, second]);
        assert!(udp.is_none());
        assert!(tcp.is_none());
        assert_eq!(conflicts.len(), 4);
        for (port, protocol) in [(first, "udp"), (first, "tcp"), (second, "udp"), (second, "tcp")] {
            assert!(conflicts
                .iter()
                .any(|conflict| conflict.port == port && conflict.protocol == protocol));
        }

        drop(first_udp);
        drop(first_tcp);
        drop(second_udp);
        drop(second_tcp);
    }

    #[test]
    fn snapshot_reports_dns_status_with_no_listeners() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-dns-status-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.dns_udp_port, 0);
        assert_eq!(snapshot.dns_tcp_port, 0);
        assert!(!snapshot.dns_running);
        assert!(snapshot.dns_error.is_none());
        assert!(snapshot.port_conflicts.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_reject_zero_fallback_port() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-settings-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());
        let mut settings = engine.snapshot().settings;
        settings.fallback_port = 0;
        assert!(engine.set_settings(settings).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_round_trip_and_validation_guards() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-settings-round-trip-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());

        let mut invalid = engine.snapshot().settings;
        invalid.bind_addr = "not-an-ip".to_string();
        assert!(engine.set_settings(invalid.clone()).is_err());
        invalid = engine.snapshot().settings;
        invalid.dns_port = 0;
        assert!(engine.set_settings(invalid.clone()).is_err());
        invalid = engine.snapshot().settings;
        invalid.update_interval_hours = 0;
        assert!(engine.set_settings(invalid).is_err());

        let mut settings = engine.snapshot().settings;
        settings.bind_addr = "127.0.0.1".to_string();
        settings.dns_port = 5333;
        settings.fallback_port = 5334;
        settings.update_interval_hours = 6;
        settings.auto_update = false;
        engine.set_settings(settings.clone()).unwrap();

        let reloaded = Engine::load_from(dir.clone());
        let loaded = reloaded.snapshot().settings;
        assert_eq!(loaded.dns_port, 5333);
        assert_eq!(loaded.fallback_port, 5334);
        assert_eq!(loaded.update_interval_hours, 6);
        assert!(!loaded.auto_update);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn app_rules_are_added_deduplicated_persisted_and_removed() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("engine-app-rules-test");
        let _ = fs::remove_dir_all(&dir);
        let engine = Engine::load_from(dir.clone());

        let rule = engine
            .add_app_rule("chrome.exe", Action::Block, Scope::Internet)
            .unwrap();
        assert!(engine
            .add_app_rule("chrome.exe", Action::Block, Scope::Internet)
            .is_err());
        assert_eq!(engine.snapshot().rules.app_rules.len(), 1);

        let reloaded = Engine::load_from(dir.clone());
        assert_eq!(reloaded.snapshot().rules.app_rules.len(), 1);
        assert_eq!(reloaded.snapshot().rules.app_rules[0].id, rule.id);

        engine.remove_app_rule(&rule.id).unwrap();
        assert!(engine.remove_app_rule(&rule.id).is_err());
        assert!(engine.snapshot().rules.app_rules.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

}

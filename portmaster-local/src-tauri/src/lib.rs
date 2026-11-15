use portmaster_core::browser::DohPolicy;
use portmaster_core::config::{Action, ListFormat, Scope, Settings};
use portmaster_core::engine::{Engine, Snapshot};
use portmaster_core::firewall::FirewallRule;
use portmaster_core::rules::AppRule;
use portmaster_core::system;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::utils::config::AppDirectoriesOverride;
use tauri::{Manager, RunEvent, State, WindowEvent};

struct AppState {
    engine: Arc<Engine>,
}

#[tauri::command]
fn get_snapshot(state: State<'_, AppState>) -> Snapshot {
    state.engine.snapshot()
}

#[tauri::command]
fn update_filters(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.update_filters(true)
}

#[tauri::command]
fn download_all_filters(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.download_all_filters()
}

#[tauri::command]
fn set_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    state.engine.set_settings(settings)
}

#[tauri::command]
fn set_default_action(state: State<'_, AppState>, action: Action) -> Result<(), String> {
    state.engine.set_default_action(action)
}

#[tauri::command]
fn add_source(
    state: State<'_, AppState>,
    name: String,
    url: String,
    format: ListFormat,
    category: String,
) -> Result<(), String> {
    state
        .engine
        .add_source(&name, &url, format, &category)
        .map(|_| ())
}

#[tauri::command]
fn remove_source(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state.engine.remove_source(&id)
}

#[tauri::command]
fn set_source_enabled(
    state: State<'_, AppState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    state.engine.set_source_enabled(&id, enabled)
}

#[tauri::command]
fn set_category_enabled(
    state: State<'_, AppState>,
    category: String,
    enabled: bool,
) -> Result<usize, String> {
    state.engine.set_category_enabled(&category, enabled)
}

#[tauri::command]
fn add_custom_domain(
    state: State<'_, AppState>,
    action: Action,
    domain: String,
) -> Result<(), String> {
    state.engine.add_custom_domain(action, &domain)
}

#[tauri::command]
fn remove_custom_domain(
    state: State<'_, AppState>,
    action: Action,
    domain: String,
) -> Result<(), String> {
    state.engine.remove_custom_domain(action, &domain)
}

#[tauri::command]
fn add_app_rule(
    state: State<'_, AppState>,
    app_match: String,
    action: Action,
    scope: Scope,
) -> Result<AppRule, String> {
    state.engine.add_app_rule(&app_match, action, scope)
}

#[tauri::command]
fn remove_app_rule(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state.engine.remove_app_rule(&id)
}

#[tauri::command]
fn apply_app_firewall(
    state: State<'_, AppState>,
    path: String,
) -> Result<FirewallRule, String> {
    state.engine.apply_app_firewall(&path)
}

#[tauri::command]
fn apply_firewall_preset(
    state: State<'_, AppState>,
    preset: String,
) -> Result<FirewallRule, String> {
    state.engine.apply_firewall_preset(&preset)
}

#[tauri::command]
fn remove_firewall_rule(state: State<'_, AppState>, name: String) -> Result<(), String> {
    state.engine.remove_firewall_rule(&name)
}

#[tauri::command]
fn clear_firewall_rules(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.clear_firewall_rules()
}

#[tauri::command]
fn clear_logs(state: State<'_, AppState>) {
    state.engine.clear_logs();
}

#[tauri::command]
fn dns_report() -> Result<String, String> {
    system::dns_report()
}

#[tauri::command]
fn apply_system_dns(
    state: State<'_, AppState>,
    interface: String,
    port: u16,
) -> Result<system::DnsConfig, String> {
    state.engine.apply_system_dns(&interface, port)
}

#[tauri::command]
fn reset_system_dns(state: State<'_, AppState>, interface: String) -> Result<(), String> {
    state.engine.reset_system_dns(&interface)
}

#[tauri::command]
fn apply_system_dns_auto(state: State<'_, AppState>) -> Result<system::DnsConfig, String> {
    state.engine.apply_system_dns_auto()
}

#[tauri::command]
fn disable_browser_doh(state: State<'_, AppState>) -> Result<DohPolicy, String> {
    state.engine.disable_browser_doh()
}

#[tauri::command]
fn restore_browser_doh(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.restore_browser_doh()
}

#[tauri::command]
fn install_autostart(state: State<'_, AppState>) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("could not resolve the application path: {err}"))?
        .display()
        .to_string();
    state.engine.install_autostart(&exe)
}

#[tauri::command]
fn remove_autostart(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.remove_autostart()
}

#[tauri::command]
fn refresh_autostart_state(state: State<'_, AppState>) -> Result<bool, String> {
    state.engine.refresh_autostart_state()
}

/// Headless crash-safe guard mode (`--dns-guard`). Installed as an elevated
/// logon task so killing or stopping the GUI cannot leave the machine's DNS
/// pointed at a dead listener.
pub fn run_guard() -> ! {
    portmaster_core::guard::run_guard(portmaster_core::config::data_dir())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let system_wide = args
        .iter()
        .any(|arg| arg == "--system-wide" || arg == "--deploy");
    let background_mode = system_wide;

    let engine = Engine::load();
    engine.set_system_wide(system_wide);
    engine.start();
    // The persisted autostart flag can be stale after an external task removal;
    // re-query the actual scheduled tasks before showing the dashboard.
    if let Err(err) = engine.refresh_autostart_state() {
        engine.log_event("warning", format!("could not refresh autostart state: {err}"));
    }

    let mut context = tauri::generate_context!();
    if let Some(dir) = std::env::var_os("PORTMASTER_LOCAL_APP_DIR") {
        if !dir.is_empty() {
            context.config_mut().app.app_directories_override =
                Some(AppDirectoriesOverride::Root(std::path::PathBuf::from(dir)));
        }
    }

    tauri::Builder::default()
        .setup(move |app| {
            let open_item = MenuItem::with_id(app, "open", "Open dashboard", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit Portmaster-Local", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_item, &quit_item])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("Portmaster-Local — click to open dashboard")
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;

            // Login/autostart launches start in the tray; a manual launch opens
            // the dashboard. Closing the dashboard hides it instead of quitting.
            if !background_mode {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .manage(AppState { engine })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            update_filters,
            download_all_filters,
            set_settings,
            set_default_action,
            add_source,
            remove_source,
            set_source_enabled,
            set_category_enabled,
            add_custom_domain,
            remove_custom_domain,
            add_app_rule,
            remove_app_rule,
            apply_app_firewall,
            apply_firewall_preset,
            remove_firewall_rule,
            clear_firewall_rules,
            clear_logs,
            dns_report,
            apply_system_dns,
            reset_system_dns,
            apply_system_dns_auto,
            disable_browser_doh,
            restore_browser_doh,
            install_autostart,
            remove_autostart,
            refresh_autostart_state
        ])
        .build(context)
        .expect("error while building Portmaster-Local")
        .run(|app_handle, event| match event {
            RunEvent::Ready => {
                let args: Vec<String> = std::env::args().collect();
                let system_wide = args.iter().any(|arg| arg == "--system-wide");
                let deploy = args.iter().any(|arg| arg == "--deploy");
                if !system_wide && !deploy {
                    return;
                }
                let engine = Arc::clone(&app_handle.state::<AppState>().engine);
                let exe = std::env::current_exe()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default();
                thread::spawn(move || {
                    for _ in 0..50 {
                        if engine.snapshot().dns_udp_port == 53 {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    // Do not point the OS at a resolver whose upstream path is
                    // broken. This gate is what prevents the deployment from
                    // taking the machine's internet offline again.
                    if engine.snapshot().dns_udp_port != 53 {
                        engine.log_event(
                            "error",
                            "system DNS was not applied because the app does not own UDP 53",
                        );
                        return;
                    }
                    match engine.probe_upstream() {
                        Ok(detail) => engine.log_event(
                            "info",
                            format!("upstream self-test passed: {detail}"),
                        ),
                        Err(err) => {
                            engine.log_event(
                                "error",
                                format!(
                                    "system DNS was not applied; upstream self-test failed: {err}"
                                ),
                            );
                            return;
                        }
                    }
                    match engine.apply_system_dns_auto() {
                        Ok(config) => engine.log_event(
                            "info",
                            format!(
                                "system-wide DNS active on interface {}; prior servers recorded",
                                config.interface
                            ),
                        ),
                        Err(err) => engine.log_event("error", err),
                    }
                    if deploy {
                        if engine.snapshot().doh_policy_state.is_none() {
                            match engine.disable_browser_doh() {
                                Ok(_) => engine.log_event(
                                    "info",
                                    "browser DoH disabled for Brave, Chrome, and Edge",
                                ),
                                Err(err) => engine.log_event("error", err),
                            }
                        }
                        // Deploy is explicitly a one-time setup step; always
                        // (re)create the tasks with /F instead of trusting a stale
                        // persisted flag from a previous install.
                        match engine.install_autostart(&exe) {
                            Ok(()) => engine.log_event(
                                "info",
                                "login autostart installed once; tasks run elevated with --system-wide and --dns-guard at login",
                            ),
                            Err(err) => engine.log_event("error", err),
                        }
                    }
                });
            }
            RunEvent::Exit => {
                let engine = Arc::clone(&app_handle.state::<AppState>().engine);
                // Restore internet DNS before the process disappears, so even a
                // normal GUI close leaves the machine usable. The elevated guard
                // task covers the cases where this handler cannot run.
                if let Err(err) = engine.restore_recorded_system_dns() {
                    engine.log_event("error", format!("could not restore system DNS on exit: {err}"));
                }
                if let Err(err) = engine.restore_browser_doh() {
                    if !err.contains("no recorded") {
                        engine.log_event(
                            "error",
                            format!("could not restore browser DoH on exit: {err}"),
                        );
                    }
                }
                engine.remove_heartbeat();
            }
            _ => {}
        });
}

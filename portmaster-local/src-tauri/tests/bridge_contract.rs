// Verifies that the static dashboard and the Tauri command surface stay in
// sync without launching the GUI. Runtime rendering is verified separately.

const UI_JS: &str = include_str!("../../ui/app.js");
const UI_HTML: &str = include_str!("../../ui/index.html");
const SHELL: &str = include_str!("../src/lib.rs");
const TAURI_CONF: &str = include_str!("../tauri.conf.json");

fn command_names_in_ui(js: &str) -> Vec<String> {
    let mut names = Vec::new();
    for marker in ["invoke(\"", "action(\""] {
        let mut rest = js;
        while let Some(index) = rest.find(marker) {
            let after = &rest[index + marker.len()..];
            if let Some(end) = after.find('"') {
                let name = &after[..end];
                if !name.is_empty() && !name.contains('$') {
                    names.push(name.to_string());
                }
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

fn registered_commands(source: &str) -> Vec<String> {
    let start = source
        .find("generate_handler![")
        .expect("generate_handler! block is missing from lib.rs")
        + "generate_handler![".len();
    let end = source[start..]
        .find(']')
        .expect("generate_handler! block is not closed");
    let mut names: Vec<String> = source[start..start + end]
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    names
}

fn element_ids_used_by_ui(js: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let marker = "$(\"";
    let mut rest = js;
    while let Some(index) = rest.find(marker) {
        let after = &rest[index + marker.len()..];
        if let Some(end) = after.find('"') {
            ids.push(after[..end].to_string());
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn every_command_invoked_by_the_dashboard_is_registered() {
    let invoked = command_names_in_ui(UI_JS);
    let registered = registered_commands(SHELL);
    assert!(!invoked.is_empty(), "no command invocations found in app.js");
    for name in &invoked {
        assert!(
            registered.contains(name),
            "dashboard invokes `{name}` but the Tauri handler does not register it"
        );
    }
}

#[test]
fn every_literal_element_id_used_by_the_dashboard_exists_in_html() {
    for id in element_ids_used_by_ui(UI_JS) {
        assert!(
            UI_HTML.contains(&format!("id=\"{id}\"")),
            "dashboard references `{id}` but index.html has no such element"
        );
    }
}

#[test]
fn app_rule_uses_the_camel_case_argument_name() {
    // Tauri command arguments are camelCase by default; the form field itself
    // keeps the snake_case HTML name.
    assert!(UI_JS.contains("appMatch: data.get(\"app_match\")"));
    assert!(!UI_JS.contains("app_match: data.get(\"app_match\")"));
}

#[test]
fn global_tauri_bootstrap_is_enabled_for_the_bridge() {
    assert!(TAURI_CONF.contains("\"withGlobalTauri\": true"));
}

#[test]
fn update_progress_is_rendered() {
    assert!(UI_HTML.contains("id=\"update-status\""));
    assert!(UI_JS.contains("function renderUpdate"));
    assert!(UI_JS.contains("renderUpdate();"));
    assert!(UI_JS.contains("snapshot.update_total"));
}

#[test]
fn csp_allows_ipc_and_the_ui_has_no_inline_styles() {
    assert!(TAURI_CONF.contains("connect-src ipc: http://ipc.localhost"));
    assert!(!UI_HTML.contains("style=\""));
    assert!(!UI_JS.contains(".style."));
}

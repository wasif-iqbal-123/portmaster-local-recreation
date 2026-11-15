#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let guard_mode = std::env::args().any(|arg| arg == "--dns-guard");
    if guard_mode {
        portmaster_local_lib::run_guard();
    }
    portmaster_local_lib::run();
}

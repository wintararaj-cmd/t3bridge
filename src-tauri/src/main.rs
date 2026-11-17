// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::*;

fn main() {
    let app_state = init_app_state();

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_hardware_id,
            get_license_info,
            activate_license,
            get_app_profiles,
            connect_bridge,
            disconnect_bridge,
            get_session_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running t3Bridge application");
}

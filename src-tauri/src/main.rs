// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod tray;

use commands::*;
use tauri::{Manager, WindowEvent};

#[cfg(windows)]
extern "system" {
    fn CreateMutexA(
        lp_mutex_attributes: *mut std::ffi::c_void,
        b_initial_owner: i32,
        lp_name: *const u8,
    ) -> *mut std::ffi::c_void;
    fn GetLastError() -> u32;
}

const ERROR_ALREADY_EXISTS: u32 = 183;

fn is_first_instance() -> bool {
    #[cfg(windows)]
    unsafe {
        let mutex_name = b"Global\\t3Bridge_TrayUI_SingleInstance_Mutex\0";
        let handle = CreateMutexA(std::ptr::null_mut(), 1, mutex_name.as_ptr());
        if !handle.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
            return false; // Another UI instance is already running in Tray
        }
    }
    true
}

fn main() {
    if !is_first_instance() {
        return;
    }

    let start_minimized = std::env::args().any(|a| a == "--minimized");
    let app_state = init_app_state();

    tauri::Builder::default()
        .manage(app_state)
        .setup(move |app| {
            tray::setup_tray(app)?;

            if start_minimized {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Hide to System Tray instead of quitting so Tray status & auto-mount stay active
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_hardware_id,
            get_license_info,
            get_license_status,
            activate_license,
            get_app_profiles,
            connect_bridge,
            disconnect_bridge,
            get_session_status,
            start_host_mode,
            stop_host_mode,
            get_host_status,
            get_host_config,
            set_host_password,
            get_saved_client_credentials,
            save_client_credentials,
            connect_peer_only,
            list_server_shares,
            mount_selected_share,
            open_folder,
            open_external_url,
            get_service_status,
            install_windows_service,
            uninstall_windows_service,
            set_prevent_sleep,
            set_auto_start,
            trigger_service_reconnect,
            run_tunnel_benchmark
        ])
        .run(tauri::generate_context!())
        .expect("error while running t3Bridge application");
}

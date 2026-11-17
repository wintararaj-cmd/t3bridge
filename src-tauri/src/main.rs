// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::*;

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
        let mutex_name = b"Global\\t3Bridge_SingleInstance_Mutex\0";
        let handle = CreateMutexA(std::ptr::null_mut(), 1, mutex_name.as_ptr());
        if !handle.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
            return false; // Another instance is already running
        }
    }
    true
}

fn main() {
    if !is_first_instance() {
        // Exit cleanly immediately if another instance is already open
        return;
    }

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

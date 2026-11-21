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
    fn SetThreadExecutionState(es_flags: u32) -> u32;
}

#[cfg(windows)]
const ES_SYSTEM_REQUIRED: u32 = 0x00000001;
#[cfg(windows)]
const ES_AWAYMODE_REQUIRED: u32 = 0x00000040;
#[cfg(windows)]
const ES_CONTINUOUS: u32 = 0x80000000;

fn prevent_system_sleep() {
    #[cfg(windows)]
    unsafe {
        // Prevent Windows from entering sleep / standby / suspend while t3Bridge is running.
        // ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED keeps CPU and networking active.
        SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    }
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

    // Keep Windows awake for both Host and Client operations
    prevent_system_sleep();

    std::thread::spawn(|| {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            #[cfg(windows)]
            unsafe {
                SetThreadExecutionState(ES_SYSTEM_REQUIRED);
            }
        }
    });

    let app_state = init_app_state();

    tauri::Builder::default()
        .manage(app_state)
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
            connect_peer_only,
            list_server_shares,
            mount_selected_share,
            open_folder,
            open_external_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running t3Bridge application");
}

use crate::commands::AppState;
use t3_ipc::{
    send_ipc_request, ConnectionPhase, IpcRequest, IpcResponse, ServiceMode, ServiceSnapshot,
};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

pub fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let status_item = MenuItem::with_id(
        app,
        "tray_status",
        "Status: Checking Service...",
        false,
        None::<&str>,
    )?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let open_item = MenuItem::with_id(app, "tray_open", "Open t3Bridge Dashboard", true, None::<&str>)?;
    let folder_item = MenuItem::with_id(app, "tray_open_folder", "Open Mapped Drive", true, None::<&str>)?;
    let reconnect_item = MenuItem::with_id(app, "tray_reconnect", "Reconnect Now", true, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(
        app,
        "tray_quit",
        "Exit Tray (Service Keeps Running)",
        true,
        None::<&str>,
    )?;

    let menu = Menu::with_items(
        app,
        &[
            &status_item,
            &sep1,
            &open_item,
            &folder_item,
            &reconnect_item,
            &sep2,
            &quit_item,
        ],
    )?;

    let status_item_clone = status_item.clone();

    let mut builder = TrayIconBuilder::with_id("t3bridge-tray")
        .menu(&menu)
        .tooltip("t3Bridge — Checking status...")
        .show_menu_on_left_click(false)
        .on_menu_event(move |app_handle, event| match event.id.as_ref() {
            "tray_open" => {
                show_main_window(app_handle);
            }
            "tray_open_folder" => {
                let handle = app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    let state = handle.state::<AppState>();
                    let drive = state.active_drive.lock().await.unwrap_or('Z');
                    let path = format!(r"{}:\", drive);
                    let _ = std::process::Command::new("explorer.exe").arg(&path).spawn();
                });
            }
            "tray_reconnect" => {
                tauri::async_runtime::spawn(async move {
                    let _ = send_ipc_request(&IpcRequest::TriggerReconnect).await;
                });
            }
            "tray_quit" => {
                app_handle.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    let tray = builder.build(app)?;

    // Spawn background Tray Status + User-Session Drive Auto-Mount Sync loop
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let mut last_status_label = String::new();
        let mut mounted_unc_in_session: Option<(char, String)> = None;

        loop {
            let snap_opt = match send_ipc_request(&IpcRequest::GetStatus).await {
                Ok(IpcResponse::Status(s)) => Some(s),
                _ => None,
            };

            let (label, tooltip) = match &snap_opt {
                Some(snap) => format_tray_status(snap, mounted_unc_in_session.as_ref()),
                None => {
                    // Check local in-process fallback state when service is not running
                    let state = handle.state::<AppState>();
                    let hosting = *state.is_hosting.lock().await;
                    let connected = *state.is_connected.lock().await;
                    if hosting {
                        (
                            "Status: Connected (Host - Local App)".to_string(),
                            "t3Bridge — Host Active (Local Mode)".to_string(),
                        )
                    } else if connected {
                        (
                            "Status: Connected (Client - Local App)".to_string(),
                            "t3Bridge — Client Connected (Local Mode)".to_string(),
                        )
                    } else {
                        (
                            "Status: Disconnected (Service Not Running)".to_string(),
                            "t3Bridge — Disconnected (Install Service for Auto-Start)".to_string(),
                        )
                    }
                }
            };

            if label != last_status_label {
                let _ = status_item_clone.set_text(&label);
                let _ = tray.set_tooltip(Some(&tooltip));
                last_status_label = label;
            }

            // User-Session (Session 1) Drive Auto-Mount & Safe Sleep/Disconnect Unmount
            if let Some(snap) = snap_opt {
                let state = handle.state::<AppState>();
                match (snap.mode, snap.phase) {
                    (ServiceMode::Client, ConnectionPhase::Connected) => {
                        if let (Some(server_ip), Some(share), Some(letter)) = (
                            snap.client.server_ip.as_ref(),
                            snap.client.desired_share_name.as_ref(),
                            snap.client.desired_drive_letter,
                        ) {
                            let clean_share = share.trim().trim_matches('\\').trim_matches('/');
                            if !clean_share.is_empty() {
                                let desired_unc = format!(r"\\{}\{}", server_ip, clean_share);
                                let already_mounted = mounted_unc_in_session
                                    .as_ref()
                                    .map(|(l, u)| *l == letter && u == &desired_unc)
                                    .unwrap_or(false)
                                    && state.system.is_drive_in_use(letter).await.unwrap_or(false);

                                if !already_mounted {
                                    if state.system.mount_drive(letter, &desired_unc).await.is_ok() {
                                        mounted_unc_in_session = Some((letter, desired_unc.clone()));
                                        *state.active_drive.lock().await = Some(letter);
                                        *state.active_unc.lock().await = Some(desired_unc);
                                        *state.is_connected.lock().await = true;
                                    }
                                }
                            }
                        }
                    }
                    (_, ConnectionPhase::Suspended) | (_, ConnectionPhase::Disconnected) => {
                        // Rule 5.3 Anti-Corruption: cleanly unmount user-session drive on Sleep or Disconnect
                        if let Some((letter, _)) = mounted_unc_in_session.take() {
                            let _ = state.system.unmount_drive(letter).await;
                            *state.active_drive.lock().await = None;
                            *state.active_unc.lock().await = None;
                            *state.is_connected.lock().await = false;
                        }
                    }
                    _ => {}
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(2500)).await;
        }
    });

    Ok(())
}

fn format_tray_status(
    snap: &ServiceSnapshot,
    mounted: Option<&(char, String)>,
) -> (String, String) {
    match (snap.mode, snap.phase) {
        (ServiceMode::Host, ConnectionPhase::Connected) => {
            let code = &snap.host.host_code;
            let nodes = snap.host.active_nodes;
            (
                format!("Status: Connected — Host ({}, {} clients)", code, nodes),
                format!("t3Bridge Host Connected ({})\nActive clients: {}", code, nodes),
            )
        }
        (ServiceMode::Client, ConnectionPhase::Connected) => {
            let drive_info = mounted
                .map(|(l, _)| format!("Drive {}:", l))
                .unwrap_or_else(|| "Tunnel Active".into());
            let target = snap
                .client
                .target_peer_id
                .as_deref()
                .unwrap_or("Host");
            (
                format!("Status: Connected — {} ({})", target, drive_info),
                format!("t3Bridge Connected to {}\n{}", target, drive_info),
            )
        }
        (_, ConnectionPhase::Connecting) => (
            "Status: Connecting...".into(),
            "t3Bridge — Connecting...".into(),
        ),
        (_, ConnectionPhase::Reconnecting) => (
            format!("Status: Reconnecting (attempt {})...", snap.reconnect_attempts),
            format!(
                "t3Bridge — Reconnecting (attempt {})...",
                snap.reconnect_attempts
            ),
        ),
        (_, ConnectionPhase::Suspended) => (
            "Status: Paused (PC Sleep)".into(),
            "t3Bridge — Tunnel paused safely for sleep".into(),
        ),
        _ => (
            "Status: Disconnected (Service Ready)".into(),
            "t3Bridge — Disconnected (Background Service Running)".into(),
        ),
    }
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Registers or removes `t3bridge-ui.exe --minimized` in Windows `HKCU\...\Run`
/// so the System Tray icon auto-launches on every Windows user login.
pub fn set_tray_autostart_registry(enable: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let value_name = "t3BridgeTray";

        if enable {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let cmd_val = format!("\"{}\" --minimized", exe.display());
            let mut cmd = std::process::Command::new("reg");
            cmd.creation_flags(CREATE_NO_WINDOW);
            let out = cmd
                .args([
                    "add", run_key, "/v", value_name, "/t", "REG_SZ", "/d", &cmd_val, "/f",
                ])
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).to_string());
            }
        } else {
            let mut cmd = std::process::Command::new("reg");
            cmd.creation_flags(CREATE_NO_WINDOW);
            let _ = cmd
                .args(["delete", run_key, "/v", value_name, "/f"])
                .output();
        }
    }
    Ok(())
}

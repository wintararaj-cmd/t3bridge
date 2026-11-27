use crate::commands::AppState;
use t3_domain::TransportMode;
use t3_ipc::{
    send_ipc_request, ConnectionPhase, IpcRequest, IpcResponse, ServiceMode, ServiceSnapshot,
};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

/// Consecutive failed drive-health probes required before triggering an automatic remount.
/// Prevents a single brief WAN/SMB latency spike during heavy ERP DBF/DLL I/O from running
/// `net use Z: /delete /y` under an active Marg/Tally process (which causes VFP9 C0000006 crashes).
const PROBE_FAILURES_BEFORE_REMOUNT: u8 = 3;
const DRIVE_ACCESS_PROBE_TIMEOUT_MS: u64 = 5000;

/// Pure state tracker for safe SMB drive accessibility probing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DriveProbeTracker {
    consecutive_failures: u8,
}

impl DriveProbeTracker {
    fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    /// Records the result of one drive accessibility probe and returns `true` only when
    /// enough consecutive failures have occurred to justify tearing down & remounting the drive.
    fn record_probe(&mut self, accessible: bool) -> bool {
        if accessible {
            self.consecutive_failures = 0;
            false
        } else {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.consecutive_failures >= PROBE_FAILURES_BEFORE_REMOUNT
        }
    }
}

/// Checks if `AppState` already recorded an active mount matching `(letter, desired_unc)`
/// (for example right after the user clicks "Map Folder" in the UI), so the tray watchdog
/// adopts the live mapping instead of redundantly running `net use /delete` 2.5s later.
fn should_adopt_existing_mount(
    app_active_drive: Option<char>,
    app_active_unc: Option<&str>,
    desired_letter: char,
    desired_unc: &str,
) -> bool {
    app_active_drive.map(|d| d.to_ascii_uppercase()) == Some(desired_letter.to_ascii_uppercase())
        && app_active_unc
            .map(|u| u.trim().trim_end_matches(&['\\', '/'][..]))
            .map(|u| u.eq_ignore_ascii_case(desired_unc.trim().trim_end_matches(&['\\', '/'][..])))
            .unwrap_or(false)
}

/// Checks asynchronously (with a 5000ms timeout) whether a mapped Windows drive letter
/// is actually reachable and not stuck in a stale/disconnected ("Red X") SMB state.
/// Uses lightweight `std::fs::metadata` instead of `read_dir` to avoid enumerating
/// large ERP share roots over WAN/SMB.
async fn is_drive_accessible(letter: char) -> bool {
    let root = format!(r"{}:\", letter.to_ascii_uppercase());
    match tokio::time::timeout(
        tokio::time::Duration::from_millis(DRIVE_ACCESS_PROBE_TIMEOUT_MS),
        tokio::task::spawn_blocking(move || std::fs::metadata(&root).is_ok()),
    )
    .await
    {
        Ok(Ok(ok)) => ok,
        _ => false,
    }
}

/// Non-destructively checks via `net use <letter>:` whether Windows already maps `letter`
/// to `desired_unc` with status `OK`. Prevents tray restarts from tearing down an active
/// ERP drive mapping that is already healthy.
#[cfg(windows)]
async fn is_windows_drive_already_mapped(letter: char, desired_unc: &str) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let drive_spec = format!("{}:", letter.to_ascii_uppercase());
    let target_unc = desired_unc.trim().trim_end_matches(&['\\', '/'][..]).to_string();

    match tokio::time::timeout(
        tokio::time::Duration::from_millis(3000),
        tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new("net");
            cmd.creation_flags(CREATE_NO_WINDOW);
            cmd.stdin(std::process::Stdio::null());
            let Ok(out) = cmd.args(["use", &drive_spec]).output() else {
                return false;
            };
            if !out.status.success() {
                return false;
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut matches_remote = false;
            let mut status_ok = false;
            for line in stdout.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.contains("remote name") {
                    if let Some(val) = line.split("Remote name").nth(1).or_else(|| line.split_whitespace().last()) {
                        let clean = val.trim().trim_end_matches(&['\\', '/'][..]);
                        if clean.eq_ignore_ascii_case(&target_unc) {
                            matches_remote = true;
                        }
                    }
                } else if lower.contains("status") && lower.contains("ok") {
                    status_ok = true;
                }
            }
            matches_remote && status_ok
        }),
    )
    .await
    {
        Ok(Ok(ok)) => ok,
        _ => false,
    }
}

#[cfg(not(windows))]
async fn is_windows_drive_already_mapped(_letter: char, _desired_unc: &str) -> bool {
    false
}

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

    // Spawn background Tray Status + User-Session Drive Auto-Mount & Wake/Reconnect Remount Watchdog
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let mut last_status_label = String::new();
        let mut mounted_unc_in_session: Option<(char, String)> = None;
        let mut last_phase: Option<ConnectionPhase> = None;
        let mut last_seen_reconnect_event: Option<String> = None;
        let mut needs_remount = false;
        let mut accessibility_tick: u32 = 0;
        let mut probe_tracker = DriveProbeTracker::default();

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

            // User-Session (Session 1) Drive Auto-Mount, Auto-Remount on Wake/Network Switch & Safe Sleep Unmount
            if let Some(snap) = snap_opt {
                let state = handle.state::<AppState>();

                // Detect any transition through Reconnecting/Connecting/Suspended or fast reconnect event
                if matches!(
                    last_phase,
                    Some(ConnectionPhase::Reconnecting)
                        | Some(ConnectionPhase::Connecting)
                        | Some(ConnectionPhase::Suspended)
                ) && snap.phase == ConnectionPhase::Connected
                {
                    needs_remount = true;
                }
                if let Some(ref ev) = snap.last_event {
                    if ev.starts_with("Reconnected successfully")
                        && last_seen_reconnect_event.as_deref() != Some(ev.as_str())
                    {
                        last_seen_reconnect_event = Some(ev.clone());
                        needs_remount = true;
                    }
                }
                last_phase = Some(snap.phase);

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

                                // Sync from AppState if the UI already mounted this exact drive/UNC,
                                // or adopt an already-healthy Windows mapping (e.g. after tray restart)
                                // so we NEVER run `net use Z: /delete /y` under an open Marg/Tally session!
                                if !needs_remount {
                                    let already_tracked = mounted_unc_in_session
                                        .as_ref()
                                        .map(|(l, u)| *l == letter && u.eq_ignore_ascii_case(&desired_unc))
                                        .unwrap_or(false);
                                    if !already_tracked {
                                        let app_drive = *state.active_drive.lock().await;
                                        let app_unc = state.active_unc.lock().await.clone();
                                        let adopted = should_adopt_existing_mount(
                                            app_drive,
                                            app_unc.as_deref(),
                                            letter,
                                            &desired_unc,
                                        ) || is_windows_drive_already_mapped(letter, &desired_unc)
                                            .await;

                                        if adopted && is_drive_accessible(letter).await {
                                            mounted_unc_in_session = Some((letter, desired_unc.clone()));
                                            *state.active_drive.lock().await = Some(letter);
                                            *state.active_unc.lock().await = Some(desired_unc.clone());
                                            *state.is_connected.lock().await = true;
                                            probe_tracker.reset();
                                        }
                                    }
                                }

                                let matches_session = mounted_unc_in_session
                                    .as_ref()
                                    .map(|(l, u)| *l == letter && u.eq_ignore_ascii_case(&desired_unc))
                                    .unwrap_or(false)
                                    && state.system.is_drive_in_use(letter).await.unwrap_or(false);

                                // Every ~15s (6 polls), run a lightweight metadata probe.
                                // Require 3 consecutive failures (~45s) before remounting so brief
                                // WAN/DBF I/O spikes never disconnect a live ERP session (C0000006).
                                accessibility_tick = accessibility_tick.wrapping_add(1);
                                if matches_session && !needs_remount && accessibility_tick % 6 == 0 {
                                    let accessible = is_drive_accessible(letter).await;
                                    if probe_tracker.record_probe(accessible) {
                                        needs_remount = true;
                                    }
                                }

                                if !matches_session || needs_remount {
                                    if state.system.mount_drive(letter, &desired_unc).await.is_ok() {
                                        mounted_unc_in_session = Some((letter, desired_unc.clone()));
                                        *state.active_drive.lock().await = Some(letter);
                                        *state.active_unc.lock().await = Some(desired_unc);
                                        *state.is_connected.lock().await = true;
                                        needs_remount = false;
                                        probe_tracker.reset();
                                    }
                                }
                            }
                        }
                    }
                    (_, ConnectionPhase::Reconnecting) => {
                        needs_remount = true;
                        probe_tracker.reset();
                    }
                    (_, ConnectionPhase::Suspended) | (_, ConnectionPhase::Disconnected) => {
                        // Rule 5.3 Anti-Corruption: cleanly unmount user-session drive on Sleep or Disconnect
                        needs_remount = false;
                        probe_tracker.reset();
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
    let mode_tag = |m: TransportMode| -> &'static str {
        match m {
            TransportMode::DirectUdpP2p => "Direct UDP",
            TransportMode::LanDirect => "LAN Direct",
            TransportMode::WsBinaryRelay => "Cloud Relay",
            TransportMode::WsLegacyRelay => "Legacy Relay",
            TransportMode::Disconnected => "Idle",
        }
    };

    match (snap.mode, snap.phase) {
        (ServiceMode::Host, ConnectionPhase::Connected) => {
            let code = &snap.host.host_code;
            let nodes = snap.host.active_nodes;
            let m = mode_tag(snap.host.transport_mode);
            (
                format!("Status: Host ({}, {} clients • {})", code, nodes, m),
                format!(
                    "t3Bridge Host Connected ({})\nActive clients: {} ({})",
                    code, nodes, m
                ),
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
            let m = mode_tag(snap.client.transport_mode);
            let rtt = if snap.client.latency_ms > 0 {
                format!(" • {} ms", snap.client.latency_ms)
            } else {
                String::new()
            };
            (
                format!("Status: {} ({} • {}{})", target, drive_info, m, rtt),
                format!("t3Bridge Connected to {}\n{} • {}{}", target, drive_info, m, rtt),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drive_probe_tracker_requires_three_consecutive_failures() {
        let mut tracker = DriveProbeTracker::default();
        // Transient slow probes during heavy Marg/Tally DBF I/O must NOT trigger remount
        assert!(!tracker.record_probe(false));
        assert!(!tracker.record_probe(false));
        // One healthy probe resets the streak
        assert!(!tracker.record_probe(true));
        assert_eq!(tracker.consecutive_failures, 0);

        // Only 3 consecutive failures trigger remount
        assert!(!tracker.record_probe(false));
        assert!(!tracker.record_probe(false));
        assert!(tracker.record_probe(false));
    }

    #[test]
    fn test_should_adopt_existing_mount_case_and_slash_insensitive() {
        assert!(should_adopt_existing_mount(
            Some('z'),
            Some(r"\\10.99.0.1\F\"),
            'Z',
            r"\\10.99.0.1\F"
        ));
        assert!(should_adopt_existing_mount(
            Some('Z'),
            Some(r"\\10.99.0.1\margerp"),
            'Z',
            r"\\10.99.0.1\MARGERP"
        ));
        assert!(!should_adopt_existing_mount(
            Some('Y'),
            Some(r"\\10.99.0.1\F"),
            'Z',
            r"\\10.99.0.1\F"
        ));
        assert!(!should_adopt_existing_mount(
            Some('Z'),
            Some(r"\\10.99.0.1\MARGERP"),
            'Z',
            r"\\10.99.0.1\F"
        ));
        assert!(!should_adopt_existing_mount(None, None, 'Z', r"\\10.99.0.1\F"));
    }
}

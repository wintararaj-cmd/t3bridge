use async_trait::async_trait;
use t3_adapters::{
    Ed25519LicenseVerifier, FileLicenseStorage, WebSocketSignalingClient, WindowsHardwareFingerprint,
    WindowsSystemAdapter,
};
use t3_application::ports::{
    HardwareFingerprintPort, LicenseStoragePort, LicenseVerifierPort, SignalingPort, TunnelPort,
    WindowsSystemPort,
};
use t3_application::usecases::{
    ActivateLicenseUseCase, CheckLicenseStatusUseCase, ConnectToHostUseCase,
    DisconnectSessionUseCase, NetworkWatchdogUseCase,
};
use t3_domain::{
    AppProfile, ConnectionHealth, DomainResult, License, LicenseStatus, Peer, PeerRole,
    SignalingMessage, TunnelMetrics, VirtualIp,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

// Mock Tunnel for local UI preview until kernel Wintun adapter is connected
struct NativeP2pTunnel;

#[async_trait]
impl TunnelPort for NativeP2pTunnel {
    async fn start_adapter(&self, _local_ip: VirtualIp) -> DomainResult<()> {
        Ok(())
    }
    async fn connect_peer(&self, _peer: &Peer, _remote_endpoint: &str) -> DomainResult<()> {
        Ok(())
    }
    async fn disconnect(&self) -> DomainResult<()> {
        Ok(())
    }
    async fn get_metrics(&self) -> DomainResult<TunnelMetrics> {
        Ok(TunnelMetrics {
            latency_ms: 18,
            bytes_sent: 1048576,
            bytes_received: 4194304,
            packet_loss_percent: 0,
        })
    }
}

pub struct AppState {
    pub hwid_provider: Arc<dyn HardwareFingerprintPort>,
    pub verifier: Arc<dyn LicenseVerifierPort>,
    pub storage: Arc<dyn LicenseStoragePort>,
    pub system: Arc<dyn WindowsSystemPort>,
    pub tunnel: Arc<dyn TunnelPort>,
    pub active_drive: Mutex<Option<char>>,
    pub is_connected: Mutex<bool>,
    pub active_unc: Mutex<Option<String>>,
    pub host_signaling: Mutex<Option<Arc<WebSocketSignalingClient>>>,
    pub is_hosting: Mutex<bool>,
    pub host_code: Mutex<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UiHostStatus {
    pub is_hosting: bool,
    pub host_code: String,
    pub virtual_ip: Option<String>,
    pub signaling_url: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct UiSessionStatus {
    pub is_connected: bool,
    pub drive_letter: Option<char>,
    pub mapped_unc: Option<String>,
    pub latency_ms: u32,
    pub status_text: String,
    pub health_level: String,
    pub is_safe: bool,
    pub alert_message: Option<String>,
}

#[tauri::command]
pub async fn get_hardware_id(state: tauri::State<'_, AppState>) -> Result<String, String> {
    state
        .hwid_provider
        .get_hardware_id()
        .await
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_license_info(state: tauri::State<'_, AppState>) -> Result<Option<License>, String> {
    state
        .storage
        .load_license()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn activate_license(
    raw_key: String,
    state: tauri::State<'_, AppState>,
) -> Result<License, String> {
    let usecase = ActivateLicenseUseCase::new(
        Arc::clone(&state.verifier),
        Arc::clone(&state.hwid_provider),
        Arc::clone(&state.storage),
    );

    usecase.execute(&raw_key).await.map_err(|e| e.to_string())
}

#[derive(Serialize, Deserialize)]
pub struct UiLicenseStatus {
    pub is_licensed: bool,
    pub is_trial: bool,
    pub is_expired: bool,
    pub customer_name: Option<String>,
    pub tier: String,
    pub days_remaining: u32,
    pub status_badge_text: String,
}

#[tauri::command]
pub async fn get_license_status(state: tauri::State<'_, AppState>) -> Result<UiLicenseStatus, String> {
    let usecase = CheckLicenseStatusUseCase::new(
        Arc::clone(&state.hwid_provider),
        Arc::clone(&state.storage),
    );

    let status = usecase.execute().await.map_err(|e| e.to_string())?;

    match status {
        LicenseStatus::Licensed {
            customer_name,
            tier,
            ..
        } => Ok(UiLicenseStatus {
            is_licensed: true,
            is_trial: false,
            is_expired: false,
            customer_name: Some(customer_name),
            tier: format!("{:?}", tier),
            days_remaining: 0,
            status_badge_text: "Licensed".into(),
        }),
        LicenseStatus::TrialActive { days_left } => Ok(UiLicenseStatus {
            is_licensed: false,
            is_trial: true,
            is_expired: false,
            customer_name: None,
            tier: "Trial".into(),
            days_remaining: days_left,
            status_badge_text: format!("Trial ({} days left)", days_left),
        }),
        LicenseStatus::TrialExpired => Ok(UiLicenseStatus {
            is_licensed: false,
            is_trial: true,
            is_expired: true,
            customer_name: None,
            tier: "Trial Expired".into(),
            days_remaining: 0,
            status_badge_text: "Trial Expired".into(),
        }),
        LicenseStatus::TrialTampered => Ok(UiLicenseStatus {
            is_licensed: false,
            is_trial: true,
            is_expired: true,
            customer_name: None,
            tier: "Clock Tampered".into(),
            days_remaining: 0,
            status_badge_text: "Clock Error".into(),
        }),
    }
}

#[tauri::command]
pub fn get_app_profiles() -> Vec<AppProfile> {
    vec![
        AppProfile::custom("Marg ERP 9+ (Share: MargERP)", "MargERP", 'Z'),
        AppProfile::custom("Marg ERP (Share: MARG)", "MARG", 'Z'),
        AppProfile::primary_erp(),
        AppProfile::branch_share(),
        AppProfile::custom("General SMB Network Share", "Share", 'W'),
    ]
}

#[tauri::command]
pub async fn connect_bridge(
    target_peer_id: String,
    app_id: String,
    custom_name: Option<String>,
    custom_share: Option<String>,
    drive_letter: String,
    signaling_url: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let active_signaling = signaling_url
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "wss://t3bridge-signaling.onrender.com".to_string());

    // 1. Enforce 7-Day Free Trial / Commercial License check
    let license_check = CheckLicenseStatusUseCase::new(
        Arc::clone(&state.hwid_provider),
        Arc::clone(&state.storage),
    );
    let license_status = license_check.execute().await.map_err(|e| e.to_string())?;
    if !license_status.is_allowed_to_connect() {
        return Err(
            "Your 7-day free trial has expired! Please activate a commercial license in the License tab to connect."
                .into(),
        );
    }

    let host_input = target_peer_id.trim();
    if host_input.is_empty() {
        return Err("Please enter the Server IP or Connect Code (e.g. 192.168.1.100 or OFFICE-HQ-01).".into());
    }

    let letter = drive_letter
        .chars()
        .next()
        .unwrap_or('Z')
        .to_ascii_uppercase();

    let selected_app = if let (Some(name), Some(share)) = (custom_name, custom_share) {
        AppProfile::custom(&name, &share, letter)
    } else {
        let profiles = get_app_profiles();
        profiles
            .into_iter()
            .find(|p| p.id == app_id)
            .unwrap_or_else(AppProfile::primary_erp)
    };

    // Determine target host & peer:
    // Case 1: Direct IPv4 on LAN (e.g. 192.168.1.50)
    // Case 2: LAN hostname (e.g. "SERVER-PC")
    // Case 3: Connect Code via Cloud Signaling Rendezvous Server (e.g. "OFFICE-HQ-01")
    let target_peer = if let Ok(ip) = host_input.parse::<std::net::Ipv4Addr>() {
        let virtual_ip = VirtualIp::new(&ip.to_string(), 24).map_err(|e| e.to_string())?;
        Peer::new(
            host_input.to_string(),
            "LAN Server".into(),
            PeerRole::HostServer,
            virtual_ip,
        )
    } else {
        use std::net::ToSocketAddrs;
        let resolved = format!("{}:445", host_input)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| {
                addrs.find_map(|sa| {
                    if let std::net::SocketAddr::V4(v4) = sa {
                        Some(v4.ip().to_string())
                    } else {
                        None
                    }
                })
            });

        if let Some(lan_ip) = resolved {
            let virtual_ip = VirtualIp::new(&lan_ip, 24).map_err(|e| e.to_string())?;
            Peer::new(
                host_input.to_string(),
                "LAN Host".into(),
                PeerRole::HostServer,
                virtual_ip,
            )
        } else {
            // Case 3: Connect Code via Cloud Signaling Rendezvous Server (Render)
            let client = WebSocketSignalingClient::new();
            client.connect(&active_signaling).await.map_err(|e| {
                format!(
                    "Cannot reach Cloud Signaling Server ({}): {}\nPlease check your internet connection.",
                    active_signaling, e
                )
            })?;

            let found_host = client.find_host(host_input).await.map_err(|_| {
                format!(
                    "Host with code '{}' is not online!\n\nTo connect via code:\n1. Open t3Bridge on the Office Server computer.\n2. Go to the 'Host / Office Server' tab.\n3. Turn ON 'Accept Inbound Branch Connections'.",
                    host_input
                )
            })?;

            found_host
        }
    };

    let usecase = ConnectToHostUseCase::new(
        Arc::clone(&state.tunnel),
        Arc::clone(&state.system),
    );

    let res = usecase
        .execute(&target_peer, &selected_app, letter, "T3-LIC-ACTIVE")
        .await
        .map_err(|e| e.to_string())?;

    *state.active_drive.lock().await = Some(letter);
    *state.is_connected.lock().await = true;
    *state.active_unc.lock().await = Some(res.session_unc_path.clone());

    Ok(format!("Connected! Drive {}: mapped to {}", res.drive_letter, res.session_unc_path))
}

#[tauri::command]
pub async fn start_host_mode(
    connect_code: String,
    signaling_url: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<UiHostStatus, String> {
    let code = if connect_code.trim().is_empty() {
        "OFFICE-HQ-01".to_string()
    } else {
        connect_code.trim().to_uppercase()
    };

    let url = signaling_url
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "wss://t3bridge-signaling.onrender.com".to_string());

    let client = Arc::new(WebSocketSignalingClient::new());
    client
        .connect(&url)
        .await
        .map_err(|e| format!("Failed to connect to signaling server ({}): {}", url, e))?;

    let hwid = state
        .hwid_provider
        .get_hardware_id()
        .await
        .map(|h| h.to_string())
        .unwrap_or_else(|_| "UNKNOWN_HWID".to_string());

    let reg_msg = SignalingMessage::RegisterNode {
        peer_id: code.clone(),
        role: PeerRole::HostServer,
        hardware_id: hwid,
        license_key: "T3-HOST-ACTIVE".into(),
    };

    let vip = client
        .register_node(reg_msg)
        .await
        .map_err(|e| format!("Registration failed on signaling server: {}", e))?;

    // Configure Windows Firewall rule for SMB
    let _ = state.system.configure_firewall_rule("10.99.0.0/24").await;

    *state.host_signaling.lock().await = Some(Arc::clone(&client));
    *state.is_hosting.lock().await = true;
    *state.host_code.lock().await = code.clone();

    Ok(UiHostStatus {
        is_hosting: true,
        host_code: code,
        virtual_ip: Some(vip.addr().to_string()),
        signaling_url: url,
        message: "Broadcasting on Cloud P2P Mesh".into(),
    })
}

#[tauri::command]
pub async fn stop_host_mode(state: tauri::State<'_, AppState>) -> Result<(), String> {
    if let Some(client) = state.host_signaling.lock().await.take() {
        let _ = client.disconnect().await;
    }
    *state.is_hosting.lock().await = false;
    Ok(())
}

#[tauri::command]
pub async fn get_host_status(state: tauri::State<'_, AppState>) -> Result<UiHostStatus, String> {
    let hosting = *state.is_hosting.lock().await;
    let code = state.host_code.lock().await.clone();
    Ok(UiHostStatus {
        is_hosting: hosting,
        host_code: code,
        virtual_ip: if hosting { Some("10.99.0.1".into()) } else { None },
        signaling_url: "wss://t3bridge-signaling.onrender.com".into(),
        message: if hosting {
            "Broadcasting on Cloud P2P Mesh".into()
        } else {
            "Offline".into()
        },
    })
}

#[tauri::command]
pub async fn disconnect_bridge(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let drive = *state.active_drive.lock().await;
    let usecase = DisconnectSessionUseCase::new(
        Arc::clone(&state.tunnel),
        Arc::clone(&state.system),
    );

    usecase.execute(drive).await.map_err(|e| e.to_string())?;

    *state.active_drive.lock().await = None;
    *state.is_connected.lock().await = false;
    *state.active_unc.lock().await = None;

    Ok(())
}

#[tauri::command]
pub async fn get_session_status(state: tauri::State<'_, AppState>) -> Result<UiSessionStatus, String> {
    let connected = *state.is_connected.lock().await;
    let drive = *state.active_drive.lock().await;
    let mapped_unc = state.active_unc.lock().await.clone();

    if connected {
        let watchdog = NetworkWatchdogUseCase::new(Arc::clone(&state.tunnel));
        let report = watchdog.check_health().await.unwrap_or_else(|_| {
            t3_application::usecases::WatchdogReport {
                health: ConnectionHealth::Dead,
                metrics: TunnelMetrics {
                    latency_ms: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packet_loss_percent: 100,
                },
                is_safe: false,
                recommendation: Some("Network watchdog error.".into()),
            }
        });

        let health_level = format!("{:?}", report.health);

        Ok(UiSessionStatus {
            is_connected: true,
            drive_letter: drive,
            mapped_unc: drive.map(|d| {
                if let Some(unc) = &mapped_unc {
                    format!("{} -> {}:", unc, d)
                } else {
                    format!(r"\\10.99.0.1\SharedData -> {}:", d)
                }
            }),
            latency_ms: report.metrics.latency_ms,
            status_text: format!("Bridged ({})", health_level),
            health_level,
            is_safe: report.is_safe,
            alert_message: report.recommendation,
        })
    } else {
        Ok(UiSessionStatus {
            is_connected: false,
            drive_letter: None,
            mapped_unc: None,
            latency_ms: 0,
            status_text: "Disconnected".into(),
            health_level: "Dead".into(),
            is_safe: true,
            alert_message: None,
        })
    }
}

pub const EMBEDDED_PUBLIC_KEY: [u8; 32] = [
    43, 101, 126, 200, 68, 234, 28, 183, 165, 15, 64, 102, 241, 191, 202, 54, 66, 60, 238, 231,
    235, 67, 224, 174, 48, 128, 218, 184, 92, 168, 212, 128,
];

pub fn init_app_state() -> AppState {
    let verifier = Arc::new(Ed25519LicenseVerifier::new(&EMBEDDED_PUBLIC_KEY).unwrap());
    let hwid_provider = Arc::new(WindowsHardwareFingerprint::new());
    
    let storage_dir = std::env::var("LOCALAPPDATA")
        .map(|app_data| PathBuf::from(app_data).join("t3Bridge"))
        .unwrap_or_else(|_| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&storage_dir);
    let storage_path = storage_dir.join("license_store.json");

    let storage = Arc::new(FileLicenseStorage::new(storage_path));
    let system = Arc::new(WindowsSystemAdapter::new());
    let tunnel = Arc::new(NativeP2pTunnel);

    AppState {
        hwid_provider,
        verifier,
        storage,
        system,
        tunnel,
        active_drive: Mutex::new(None),
        is_connected: Mutex::new(false),
        active_unc: Mutex::new(None),
        host_signaling: Mutex::new(None),
        is_hosting: Mutex::new(false),
        host_code: Mutex::new("OFFICE-HQ-01".into()),
    }
}

use t3_adapters::{
    Ed25519LicenseVerifier, FileLicenseStorage, WebSocketSignalingClient, WindowsHardwareFingerprint,
    WindowsSystemAdapter, WintunTunnelAdapter,
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
    AppProfile, ConnectionHealth, License, LicenseStatus, Peer, PeerRole,
    SignalingMessage, TunnelMetrics, VirtualIp,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub struct AppState {
    pub hwid_provider: Arc<dyn HardwareFingerprintPort>,
    pub verifier: Arc<dyn LicenseVerifierPort>,
    pub storage: Arc<dyn LicenseStoragePort>,
    pub system: Arc<dyn WindowsSystemPort>,
    pub tunnel: Arc<WintunTunnelAdapter>,
    pub active_drive: Mutex<Option<char>>,
    pub is_connected: Mutex<bool>,
    pub active_unc: Mutex<Option<String>>,
    pub host_signaling: Mutex<Option<Arc<WebSocketSignalingClient>>>,
    pub client_signaling: Mutex<Option<Arc<WebSocketSignalingClient>>>,
    pub is_hosting: Mutex<bool>,
    pub host_code: Mutex<String>,
    pub host_status_message: Mutex<String>,
    pub active_server_ip: Mutex<Option<String>>,   // server IP after tunnel is up (for share listing)
    pub host_share_name: Mutex<String>,
    pub host_share_path: Mutex<String>,
    pub discovered_shares: Arc<Mutex<Vec<String>>>,
    pub host_connected_clients: Arc<Mutex<std::collections::HashSet<String>>>,
    pub host_max_nodes: Arc<Mutex<u32>>,
}

#[derive(Serialize, Deserialize)]
pub struct UiHostStatus {
    pub is_hosting: bool,
    pub host_code: String,
    pub virtual_ip: Option<String>,
    pub signaling_url: String,
    pub message: String,
    pub share_name: String,
    pub share_path: String,
    pub detected_shares: Vec<String>,
    pub active_nodes: u32,
    pub max_nodes: u32,
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
    pub target_ip: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostConfig {
    pub host_code: String,
    pub password_hash: String,
    pub salt: String,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UiHostConfig {
    pub host_code: String,
    pub has_password: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientConfig {
    pub saved_target: String,
    pub saved_password: String,
    pub remember: bool,
}

fn get_t3bridge_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .map(|app_data| PathBuf::from(app_data).join("t3Bridge"))
            .unwrap_or_else(|_| PathBuf::from("."))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(".")
    }
}

pub fn load_host_config() -> Result<Option<HostConfig>, String> {
    let path = get_t3bridge_dir().join("host_config.json");
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let config: HostConfig = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    Ok(Some(config))
}

pub fn save_host_config(config: &HostConfig) -> Result<(), String> {
    let dir = get_t3bridge_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("host_config.json");
    let data = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn load_client_config() -> Result<Option<ClientConfig>, String> {
    let path = get_t3bridge_dir().join("client_config.json");
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let config: ClientConfig = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    Ok(Some(config))
}

pub fn save_client_config(config: &ClientConfig) -> Result<(), String> {
    let dir = get_t3bridge_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("client_config.json");
    let data = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn hash_password_with_salt(password: &str, salt: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub async fn compute_host_code(state: &AppState) -> String {
    let license_check = CheckLicenseStatusUseCase::new(
        Arc::clone(&state.hwid_provider),
        Arc::clone(&state.storage),
    );
    let license_status = license_check.execute().await;

    let raw_user = std::env::var("USERNAME").unwrap_or_else(|_| "USER".into());
    let mut clean_user: String = raw_user
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>()
        .to_ascii_uppercase();
    if clean_user.is_empty() {
        clean_user = "USER".to_string();
    }
    if clean_user.len() > 10 {
        clean_user.truncate(10);
    }

    match license_status {
        Ok(LicenseStatus::Licensed { customer_name, .. }) => {
            let mut clean_company: String = customer_name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
                .collect::<String>()
                .to_ascii_uppercase();
            while clean_company.contains("__") {
                clean_company = clean_company.replace("__", "_");
            }
            clean_company = clean_company.trim_matches('_').to_string();
            if clean_company.is_empty() {
                clean_company = "LICENSED".to_string();
            }
            if clean_company.len() > 16 {
                clean_company.truncate(16);
            }
            format!("{}-{}", clean_company, clean_user)
        }
        _ => {
            let hwid = state
                .hwid_provider
                .get_hardware_id()
                .await
                .map(|h| h.to_string())
                .unwrap_or_else(|_| "T3-0000-0000-XXXX".to_string());
            let hwid_clean: String = hwid
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            let suffix = if hwid_clean.len() >= 4 {
                &hwid_clean[hwid_clean.len() - 4..]
            } else {
                "T301"
            };
            format!("TRIAL-{}-{}", clean_user, suffix.to_ascii_uppercase())
        }
    }
}

#[tauri::command]
pub async fn get_host_config(state: tauri::State<'_, AppState>) -> Result<UiHostConfig, String> {
    let code = compute_host_code(&state).await;
    *state.host_code.lock().await = code.clone();

    let existing = load_host_config().unwrap_or(None);
    let has_password = existing.map(|c| !c.password_hash.is_empty()).unwrap_or(false);

    Ok(UiHostConfig {
        host_code: code,
        has_password,
    })
}

#[tauri::command]
pub async fn set_host_password(
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<UiHostConfig, String> {
    let pwd = password.trim();
    if pwd.len() < 4 {
        return Err("Password must be at least 4 characters long.".into());
    }

    let code = compute_host_code(&state).await;
    *state.host_code.lock().await = code.clone();

    let salt: String = (0..8)
        .map(|_| format!("{:x}", rand::random::<u8>() % 16))
        .collect();
    let password_hash = hash_password_with_salt(pwd, &salt);

    let config = HostConfig {
        host_code: code.clone(),
        password_hash,
        salt,
        updated_at: chrono::Utc::now().timestamp(),
    };

    save_host_config(&config)?;

    Ok(UiHostConfig {
        host_code: code,
        has_password: true,
    })
}

#[tauri::command]
pub async fn get_saved_client_credentials() -> Result<ClientConfig, String> {
    let conf = load_client_config().unwrap_or(None).unwrap_or(ClientConfig {
        saved_target: "".into(),
        saved_password: "".into(),
        remember: false,
    });
    Ok(conf)
}

#[tauri::command]
pub async fn save_client_credentials(
    target: String,
    password: String,
    remember: bool,
) -> Result<(), String> {
    let config = if remember {
        ClientConfig {
            saved_target: target.trim().to_string(),
            saved_password: password.trim().to_string(),
            remember: true,
        }
    } else {
        ClientConfig {
            saved_target: "".into(),
            saved_password: "".into(),
            remember: false,
        }
    };
    save_client_config(&config)
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
    password: Option<String>,
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
        return Err("Please enter the Server IP or Connect Code (e.g. 192.168.1.100 or TRIAL-USER-XXXX).".into());
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
    // Case 0: Self-Hosting / Local Loopback Check
    // If the user inputs this host's code, or "127.0.0.1", or "localhost", connect directly via local SMB loopback!
    let my_code = compute_host_code(&state).await;
    let is_self_host = host_input.eq_ignore_ascii_case(&my_code) ||
        host_input.eq_ignore_ascii_case("127.0.0.1") ||
        host_input.eq_ignore_ascii_case("localhost");

    let target_peer = if is_self_host {
        let host_conf = load_host_config().ok().flatten().filter(|c| !c.password_hash.is_empty());
        if let Some(c) = host_conf {
            let incoming = password.as_deref().unwrap_or("").trim();
            if hash_password_with_salt(incoming, &c.salt) != c.password_hash {
                return Err("Authentication Failed: Incorrect Host Access Password".into());
            }
        }
        let virtual_ip = VirtualIp::new("127.0.0.1", 24).map_err(|e| e.to_string())?;
        Peer::new(
            "127.0.0.1".into(),
            "Local Host Server (Loopback)".into(),
            PeerRole::HostServer,
            virtual_ip,
        )
    } else if let Ok(ip) = host_input.parse::<std::net::Ipv4Addr>() {
        // Case 1: Direct LAN IP - use it directly for SMB mount
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
            // Case 2: LAN hostname - resolved to IP, use hostname for SMB (NetBIOS/DNS)
            let virtual_ip = VirtualIp::new(&lan_ip, 24).map_err(|e| e.to_string())?;
            Peer::new(
                host_input.to_string(),
                "LAN Host".into(),
                PeerRole::HostServer,
                virtual_ip,
            )
        } else {
            // Case 3: Connect Code via Cloud Signaling Rendezvous Server (WAN mode)
            let clean_code = host_input.to_uppercase();
            let client = Arc::new(WebSocketSignalingClient::new());
            client.connect(&active_signaling).await.map_err(|e| {
                format!(
                    "Cannot reach Cloud Signaling Server ({}): {}\nPlease check your internet connection.",
                    active_signaling, e
                )
            })?;

            // Auto-retry up to 3 times with 1.5s delay to allow cloud rendezvous synchronization
            let mut found_host = None;
            let mut last_err = String::new();
            for attempt in 1..=3 {
                match client.find_host(&clean_code).await {
                    Ok(host) => {
                        found_host = Some(host);
                        break;
                    }
                    Err(e) => {
                        last_err = e.to_string();
                        if attempt < 3 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                        }
                    }
                }
            }

            let _found_host = found_host.ok_or_else(|| {
                format!(
                    "Host with code '{}' is not online! (Error: {})\n\nTo connect via code:\n1. Open t3Bridge on the Office Server computer.\n2. Go to the 'Host / Office Server' tab.\n3. Turn ON 'Accept Inbound Branch Connections'.",
                    clean_code, last_err
                )
            })?;

            // Register client as a node so signaling server tracks this connection and assigns virtual IP
            let hwid = state
                .hwid_provider
                .get_hardware_id()
                .await
                .map(|h| h.to_string())
                .unwrap_or_else(|_| "CLIENT_HWID".to_string());
            let client_node_id = format!("CLIENT-{}", &hwid[..8.min(hwid.len())]);

            let reg_msg = SignalingMessage::RegisterNode {
                peer_id: client_node_id.clone(),
                role: PeerRole::ClientNode,
                hardware_id: hwid,
                license_key: "T3-CLIENT-ACTIVE".into(),
            };
            let client_vip = client.register_node(reg_msg).await.map_err(|e| {
                format!("Failed to register node with signaling server: {}", e)
            })?;

            // Start client Wintun adapter with assigned virtual IP (e.g. 10.99.0.2)
            state.tunnel.start_adapter(client_vip).await.map_err(|e| {
                format!("Failed to start virtual network adapter: {}\nMake sure t3Bridge is running as Administrator.", e)
            })?;

            // Send RelayRequest to signaling server with authentication token
            let clean_pwd = password.unwrap_or_default().trim().to_string();
            let session_id = format!("sess_{}::AUTH_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0), clean_pwd);
            let _ = client.send_message(SignalingMessage::RelayRequest {
                target_peer_id: clean_code.clone(),
                session_id: session_id.clone(),
            }).await;

            // Wait briefly for RelayAccepted before starting pump
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let inbound_rx = client.take_inbound_receiver().await;
            let tunnel_for_client = Arc::clone(&state.tunnel);
            let client_sender = client.get_sender().await;

            if let (Some(mut rx), Some(tx)) = (inbound_rx, client_sender) {
                let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                tunnel_for_client.set_outbound_channel(out_tx);
                let sess_clone = session_id.clone();

                // Pump outbound packets: client Wintun → RelayData → signaling server → host
                tokio::spawn(async move {
                    while let Some(packet) = out_rx.recv().await {
                        let _ = tx.send(SignalingMessage::RelayData {
                            session_id: sess_clone.clone(),
                            chunk: packet,
                        });
                    }
                });

                // Pump inbound packets: signaling server → inject into client Wintun
                tokio::spawn(async move {
                    while let Some(msg) = rx.recv().await {
                        match msg {
                            SignalingMessage::RelayData { session_id: _, chunk } => {
                                let _ = tunnel_for_client.inject_inbound_packet(&chunk);
                            }
                            SignalingMessage::RelayClose { session_id: _ } => {
                                break;
                            }
                            _ => {}
                        }
                    }
                });
            }

            *state.client_signaling.lock().await = Some(Arc::clone(&client));

            // Return host peer with virtual IP 10.99.0.1 (server side of tunnel)
            // The Wintun adapter is already started; skip start_adapter in ConnectToHostUseCase
            let server_vip = VirtualIp::new("10.99.0.1", 24).map_err(|e| e.to_string())?;
            Peer::new(
                "10.99.0.1".into(),         // peer_id = IP so Case A logic in connect_host.rs uses it directly
                "WAN Relay Server".into(),
                PeerRole::HostServer,
                server_vip,
            )
        }
    };

    let usecase = ConnectToHostUseCase::new(
        Arc::clone(&state.tunnel) as Arc<dyn TunnelPort>,
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

// ─────────────────────────────────────────────────────────────────
// Two-Phase Connect: Phase 1 — establish tunnel only, return server IP
// ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct PeerConnectionInfo {
    pub server_ip: String,   // IP to query shares from (virtual or real LAN IP)
    pub is_wan: bool,
    pub peer_id: String,
}

#[tauri::command]
pub async fn connect_peer_only(
    target_peer_id: String,
    password: Option<String>,
    signaling_url: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<PeerConnectionInfo, String> {
    // License check
    let license_check = CheckLicenseStatusUseCase::new(
        Arc::clone(&state.hwid_provider),
        Arc::clone(&state.storage),
    );
    if !license_check.execute().await.map_err(|e| e.to_string())?.is_allowed_to_connect() {
        return Err("Trial expired. Please activate a license.".into());
    }

    let host_input = target_peer_id.trim();
    if host_input.is_empty() {
        return Err("Please enter Server IP or Connect Code.".into());
    }

    let active_signaling = signaling_url
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "wss://t3bridge-signaling.onrender.com".to_string());

    // Reuse same peer resolution logic as connect_bridge
    let my_code = compute_host_code(&state).await;
    let is_self_host = host_input.eq_ignore_ascii_case(&my_code) ||
        host_input.eq_ignore_ascii_case("127.0.0.1") ||
        host_input.eq_ignore_ascii_case("localhost");

    let (target_peer, server_ip, is_wan) = if is_self_host {
        let host_conf = load_host_config().ok().flatten().filter(|c| !c.password_hash.is_empty());
        if let Some(c) = host_conf {
            let incoming = password.as_deref().unwrap_or("").trim();
            if hash_password_with_salt(incoming, &c.salt) != c.password_hash {
                return Err("Authentication Failed: Incorrect Host Access Password".into());
            }
        }
        let vip = VirtualIp::new("127.0.0.1", 24).map_err(|e| e.to_string())?;
        let peer = Peer::new("127.0.0.1".into(), "Local Host Server (Loopback)".into(), PeerRole::HostServer, vip);
        (peer, "127.0.0.1".to_string(), false)

    } else if let Ok(ip) = host_input.parse::<std::net::Ipv4Addr>() {
        let vip = VirtualIp::new(&ip.to_string(), 24).map_err(|e| e.to_string())?;
        let peer = Peer::new(host_input.to_string(), "LAN Server".into(), PeerRole::HostServer, vip);
        (peer, ip.to_string(), false)

    } else {
        use std::net::ToSocketAddrs;
        let resolved = format!("{}:445", host_input)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.find_map(|sa| {
                if let std::net::SocketAddr::V4(v4) = sa { Some(v4.ip().to_string()) } else { None }
            }));

        if let Some(lan_ip) = resolved {
            let vip = VirtualIp::new(&lan_ip, 24).map_err(|e| e.to_string())?;
            let peer = Peer::new(host_input.to_string(), "LAN Host".into(), PeerRole::HostServer, vip);
            (peer, host_input.to_string(), false)
        } else {
            // WAN: Cloud Signaling
            let clean_code = host_input.to_uppercase();
            let client = Arc::new(WebSocketSignalingClient::new());
            client.connect(&active_signaling).await.map_err(|e| format!("Cannot reach signaling server: {}", e))?;

            let mut found_host = None;
            for attempt in 1..=3 {
                match client.find_host(&clean_code).await {
                    Ok(h) => { found_host = Some(h); break; }
                    Err(e) => { if attempt < 3 { tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await; } else { return Err(format!("Host '{}' not online: {}", clean_code, e)); } }
                }
            }
            let _ = found_host.unwrap();

            let hwid = state.hwid_provider.get_hardware_id().await
                .map(|h| h.to_string()).unwrap_or_else(|_| "CLIENT_HWID".to_string());
            let client_node_id = format!("CLIENT-{}", &hwid[..8.min(hwid.len())]);

            let reg_msg = SignalingMessage::RegisterNode {
                peer_id: client_node_id.clone(),
                role: PeerRole::ClientNode,
                hardware_id: hwid,
                license_key: "T3-CLIENT-ACTIVE".into(),
            };
            let client_vip = client.register_node(reg_msg).await.map_err(|e| format!("Node registration failed: {}", e))?;

            state.tunnel.start_adapter(client_vip).await.map_err(|e| format!("Tunnel start failed: {}", e))?;

            let clean_pwd = password.unwrap_or_default().trim().to_string();

            // Step 1: Authenticate & query server shares via HolePunchOffer (never embed password in RelayData session_id)
            let query_offer = t3_domain::HolePunchPayload {
                peer_id: client_node_id.clone(),
                public_endpoint: "0.0.0.0:0".into(),
                wireguard_pubkey: format!("AUTH:{}::QUERY_SHARES", clean_pwd),
                local_candidate: None,
            };
            let _ = client.send_message(SignalingMessage::HolePunchOffer {
                target_peer_id: clean_code.clone(),
                offer: query_offer,
            }).await;

            // auth_tx carries Ok(session_id) on success or Err(reason) on auth failure
            let (auth_tx, mut auth_rx) = tokio::sync::mpsc::channel::<Result<String, String>>(1);
            let auth_tx_clone = auth_tx.clone();
            let clean_pwd_fallback = clean_pwd.clone();

            let inbound_rx = client.take_inbound_receiver().await;
            let tunnel_for_client = Arc::clone(&state.tunnel);
            let client_sender = client.get_sender().await;
            let discovered_shares_ref = Arc::clone(&state.discovered_shares);

            if let Some(mut rx) = inbound_rx {
                let tunnel_for_rx = Arc::clone(&tunnel_for_client);
                tokio::spawn(async move {
                    while let Some(msg) = rx.recv().await {
                        match msg {
                            SignalingMessage::RelayData { chunk, .. } => {
                                let _ = tunnel_for_rx.inject_inbound_packet(&chunk);
                            }
                            SignalingMessage::HolePunchAnswer { answer, .. } => {
                                if answer.wireguard_pubkey.starts_with("AUTH_FAILED:") {
                                    let err_msg = answer.wireguard_pubkey.trim_start_matches("AUTH_FAILED:").to_string();
                                    let _ = auth_tx_clone.send(Err(err_msg)).await;
                                } else if let Some(rest) = answer.wireguard_pubkey.strip_prefix("TOKEN:") {
                                    if let Some((tok, shares_part)) = rest.split_once("::SHARES:") {
                                        let parsed: Vec<String> = shares_part
                                            .split(',')
                                            .map(|s| s.trim().to_string())
                                            .filter(|s| !s.is_empty())
                                            .collect();
                                        *discovered_shares_ref.lock().await = parsed;
                                        let _ = auth_tx_clone.send(Ok(format!("sess_tok_{}", tok.trim()))).await;
                                    }
                                } else if answer.wireguard_pubkey.starts_with("SHARES:") {
                                    // Backwards compatibility with older host versions
                                    let csv = answer.wireguard_pubkey.trim_start_matches("SHARES:");
                                    let parsed: Vec<String> = csv
                                        .split(',')
                                        .map(|s| s.trim().to_string())
                                        .filter(|s| !s.is_empty())
                                        .collect();
                                    *discovered_shares_ref.lock().await = parsed;
                                    let legacy_sid = format!(
                                        "sess_{}::AUTH_{}",
                                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                                        clean_pwd_fallback
                                    );
                                    let _ = auth_tx_clone.send(Ok(legacy_sid)).await;
                                }
                            }
                            SignalingMessage::RelayClose { .. } => {
                                let _ = auth_tx_clone.send(Err("Incorrect Host Access Password".to_string())).await;
                                break;
                            }
                            _ => {}
                        }
                    }
                });
            }

            // Await authentication & opaque session token from host (timeout 5000ms for mobile/WAN latency)
            let session_id = match tokio::time::timeout(tokio::time::Duration::from_millis(5000), auth_rx.recv()).await {
                Ok(Some(Ok(sid))) => sid,
                Ok(Some(Err(e))) => {
                    let _ = client.disconnect().await;
                    let _ = state.tunnel.disconnect().await;
                    return Err(format!("Authentication Failed: {}", e));
                }
                Ok(None) | Err(_) => {
                    let _ = client.disconnect().await;
                    let _ = state.tunnel.disconnect().await;
                    return Err(format!(
                        "Host '{}' did not respond.\n\nPlease check:\n1. On Server PC: Ensure Host Mode is active (shows 'Broadcasting on Cloud Mesh').\n2. Verify the Host Access Password.",
                        clean_code
                    ));
                }
            };

            // Step 2: Open WAN Relay using the clean opaque session_id (no password in RelayData)
            let _ = client.send_message(SignalingMessage::RelayRequest {
                target_peer_id: clean_code.clone(),
                session_id: session_id.clone(),
            }).await;

            if let Some(tx) = client_sender {
                let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                tunnel_for_client.set_outbound_channel(out_tx);
                let sess_clone = session_id.clone();
                tokio::spawn(async move {
                    while let Some(packet) = out_rx.recv().await {
                        let _ = tx.send(SignalingMessage::RelayData { session_id: sess_clone.clone(), chunk: packet });
                    }
                });
            }

            *state.client_signaling.lock().await = Some(Arc::clone(&client));
            let server_vip = VirtualIp::new("10.99.0.1", 24).map_err(|e| e.to_string())?;
            let peer = Peer::new("10.99.0.1".into(), "WAN Relay Server".into(), PeerRole::HostServer, server_vip);
            (peer, "10.99.0.1".to_string(), true)
        }
    };

    // Store server IP for share listing
    *state.active_server_ip.lock().await = Some(server_ip.clone());

    // Connect tunnel (but don't mount drive yet)
    let is_wan_relay = target_peer.name == "WAN Relay Server";
    if !is_wan_relay {
        state.tunnel.start_adapter(target_peer.virtual_ip.clone()).await
            .map_err(|e| format!("Tunnel adapter failed: {}", e))?;
        state.tunnel.connect_peer(&target_peer, target_peer.public_endpoint.as_deref().unwrap_or("0.0.0.0:0")).await
            .map_err(|e| e.to_string())?;
    }

    Ok(PeerConnectionInfo { server_ip, is_wan, peer_id: target_peer.peer_id.clone() })
}

// ─────────────────────────────────────────────────────────────────
// Two-Phase Connect: Phase 2a — List server's available SMB shares
// ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn list_server_shares(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let server_ip = state.active_server_ip.lock().await.clone()
        .ok_or("Not connected to any server. Connect first.")?;

    let is_wan = server_ip == "10.99.0.1";

    if is_wan {
        // Wait briefly for host signaling share response
        for _ in 0..6 {
            let s = state.discovered_shares.lock().await.clone();
            if !s.is_empty() {
                return Ok(s);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
    }

    // Direct network scan via net view
    let shares = state.system.list_remote_shares(&server_ip).await.unwrap_or_default();

    Ok(shares)
}

// ─────────────────────────────────────────────────────────────────
// Two-Phase Connect: Phase 2b — Mount the user-selected share
// ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn mount_selected_share(
    share_name: String,
    drive_letter: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let server_ip = state.active_server_ip.lock().await.clone()
        .ok_or("Not connected to any server.")?;

    let letter = drive_letter.chars().next().unwrap_or('Z').to_ascii_uppercase();

    let clean_share = share_name.trim().trim_matches('\\').trim_matches('/');
    if clean_share.is_empty() {
        return Err("Share name cannot be empty.".into());
    }

    let unc_path = format!(r"\\{}\{}", server_ip, clean_share);

    state.system.mount_drive(letter, &unc_path).await.map_err(|e| e.to_string())?;

    *state.active_drive.lock().await = Some(letter);
    *state.is_connected.lock().await = true;
    *state.active_unc.lock().await = Some(unc_path.clone());

    Ok(format!("Drive {}: mapped to {}", letter, unc_path))
}

#[tauri::command]
pub async fn start_host_mode(
    _connect_code: Option<String>,
    signaling_url: Option<String>,
    share_folder_path: Option<String>,
    share_name: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<UiHostStatus, String> {
    // 1. Enforce that host password must be configured
    let host_conf = load_host_config()
        .ok()
        .flatten()
        .filter(|c| !c.password_hash.is_empty());

    if host_conf.is_none() {
        return Err("Please set a Host Access Password before starting Host Server Mode.".into());
    }

    // 2. Automatically compute unique host code by policy
    let code = compute_host_code(&state).await;
    *state.host_code.lock().await = code.clone();

    let url = signaling_url
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "wss://t3bridge-signaling.onrender.com".to_string());

    // Resolve share path and name — accept any drive/folder
    let resolved_share_name = share_name
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("SharedData")
        .to_string();

    let resolved_share_path = share_folder_path
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(r"C:\SharedData")
        .to_string();

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

    // 1. Configure Windows Firewall rule for SMB
    let _ = state.system.configure_firewall_rule("10.99.0.0/24").await;

    // 2. Ensure the user-specified folder exists and is shared over SMB
    //    Supports any drive: C:\, D:\, E:\, etc.
    let shared_folder = PathBuf::from(&resolved_share_path);
    let _ = std::fs::create_dir_all(&shared_folder);

    // Remove old share with same name (if any), then re-create
    let net_share_arg = format!("{}={}", resolved_share_name, resolved_share_path);
    let mut del_cmd = std::process::Command::new("net");
    #[cfg(windows)]
    del_cmd.creation_flags(0x08000000);
    let _ = del_cmd
        .args(["share", &resolved_share_name, "/delete", "/y"])
        .output();

    let mut cmd = std::process::Command::new("net");
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    let share_result = cmd
        .args(["share", &net_share_arg, "/grant:Everyone,FULL", "/y"])
        .output();

    if let Err(e) = share_result {
        return Err(format!(
            "Failed to create Windows share '{}' for path '{}': {}",
            resolved_share_name, resolved_share_path, e
        ));
    }

    // Set NTFS folder permissions so Everyone can read/write files over SMB
    let mut icacls_cmd = std::process::Command::new("icacls");
    #[cfg(windows)]
    icacls_cmd.creation_flags(0x08000000);
    let _ = icacls_cmd
        .args([&resolved_share_path, "/grant", "Everyone:(OI)(CI)F", "/T", "/C", "/Q"])
        .output();

    // 3. Start server Wintun adapter with 10.99.0.1
    state
        .tunnel
        .start_adapter(VirtualIp::new("10.99.0.1", 24).unwrap())
        .await
        .map_err(|e| format!("Failed to start host virtual network adapter: {}", e))?;

    // Determine allowed branch nodes based on Host license (default starter pack = 3)
    let license_usecase = CheckLicenseStatusUseCase::new(
        Arc::clone(&state.hwid_provider),
        Arc::clone(&state.storage),
    );
    let license_status = license_usecase.execute().await.unwrap_or(LicenseStatus::TrialExpired);
    let allowed_nodes: u32 = match license_status {
        LicenseStatus::Licensed { max_nodes, .. } => max_nodes,
        LicenseStatus::TrialActive { .. } => 3, // 1 Host + 3 Clients starter pack
        _ => 3,
    };
    *state.host_max_nodes.lock().await = allowed_nodes;
    state.host_connected_clients.lock().await.clear();

    // 3. Setup WAN Relay message pump
    let inbound_rx = client.take_inbound_receiver().await;
    let tunnel_for_host = Arc::clone(&state.tunnel);
    let system_for_host = Arc::clone(&state.system);
    let client_sender = client.get_sender().await;
    let share_for_pump = resolved_share_name.clone();
    let host_code_for_pump = code.clone();
    let host_clients_for_pump = Arc::clone(&state.host_connected_clients);

    if let (Some(mut rx), Some(tx)) = (inbound_rx, client_sender) {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        tunnel_for_host.set_outbound_channel(out_tx);

        tokio::spawn(async move {
            let active_session = Arc::new(tokio::sync::Mutex::new(None::<String>));
            let active_sess_for_out = Arc::clone(&active_session);
            let tx_for_out = tx.clone();
            let host_clients = host_clients_for_pump;

            // Pump outbound packets from server Wintun to client via RelayData
            tokio::spawn(async move {
                while let Some(packet) = out_rx.recv().await {
                    let sess = active_sess_for_out.lock().await.clone();
                    if let Some(session_id) = sess {
                        let _ = tx_for_out.send(SignalingMessage::RelayData {
                            session_id,
                            chunk: packet,
                        });
                    }
                }
            });

            // One-time authorized session tokens issued after password verification
            let mut authorized_tokens = std::collections::HashSet::<String>::new();

            // Pump inbound signaling messages
            while let Some(msg) = rx.recv().await {
                match msg {
                    SignalingMessage::RelayRequest { target_peer_id: _, session_id } => {
                        let is_authenticated = if let Some(tok) = session_id.strip_prefix("sess_tok_") {
                            authorized_tokens.remove(tok)
                        } else {
                            // Backwards compatibility with legacy ::AUTH_ format
                            let incoming_pwd = session_id
                                .split_once("::AUTH_")
                                .map(|(_, pwd)| pwd)
                                .unwrap_or("");
                            let host_conf = load_host_config().ok().flatten().filter(|c| !c.password_hash.is_empty());
                            match &host_conf {
                                Some(c) => hash_password_with_salt(incoming_pwd, &c.salt) == c.password_hash,
                                None => true,
                            }
                        };

                        if !is_authenticated {
                            let _ = tx.send(SignalingMessage::RelayClose { session_id });
                            continue;
                        }

                        let mut clients = host_clients.lock().await;
                        if clients.len() as u32 >= allowed_nodes && !clients.contains(&session_id) {
                            let _ = tx.send(SignalingMessage::Error {
                                code: "PEER_LIMIT_EXCEEDED".into(),
                                message: format!(
                                    "Host connection limit reached ({}/{} branch nodes connected). Please upgrade your t3Bridge commercial license to connect more branch clients.",
                                    clients.len(),
                                    allowed_nodes
                                ),
                            });
                        } else {
                            clients.insert(session_id.clone());
                            *active_session.lock().await = Some(session_id.clone());
                            let _ = tx.send(SignalingMessage::RelayAccepted {
                                session_id,
                            });
                        }
                    }
                    SignalingMessage::HolePunchOffer { target_peer_id: _, offer } => {
                        // Client is requesting server share list with password authentication
                        let incoming_pwd = if let Some(stripped) = offer.wireguard_pubkey.strip_prefix("AUTH:") {
                            stripped.split_once("::").map(|(p, _)| p).unwrap_or(stripped)
                        } else {
                            ""
                        };

                        let host_conf = load_host_config().ok().flatten().filter(|c| !c.password_hash.is_empty());
                        let is_authenticated = match &host_conf {
                            Some(c) => hash_password_with_salt(incoming_pwd, &c.salt) == c.password_hash,
                            None => true,
                        };

                        if !is_authenticated {
                            let answer = t3_domain::HolePunchPayload {
                                peer_id: host_code_for_pump.clone(),
                                public_endpoint: "0.0.0.0:0".into(),
                                wireguard_pubkey: "AUTH_FAILED:Incorrect Host Access Password".into(),
                                local_candidate: None,
                            };
                            let _ = tx.send(SignalingMessage::HolePunchAnswer {
                                target_peer_id: offer.peer_id,
                                answer,
                            });
                            continue;
                        }

                        // Issue one-time opaque session token so RelayData never carries plaintext password
                        let token: String = (0..8)
                            .map(|_| format!("{:02x}", rand::random::<u8>()))
                            .collect();
                        authorized_tokens.insert(token.clone());

                        let mut local_shares = system_for_host.list_local_shares().await.unwrap_or_default();
                        if !share_for_pump.is_empty() && !local_shares.contains(&share_for_pump) {
                            local_shares.insert(0, share_for_pump.clone());
                        }
                        let shares_csv = local_shares.join(",");
                        let answer = t3_domain::HolePunchPayload {
                            peer_id: host_code_for_pump.clone(),
                            public_endpoint: "0.0.0.0:0".into(),
                            wireguard_pubkey: format!("TOKEN:{}::SHARES:{}", token, shares_csv),
                            local_candidate: None,
                        };
                        let _ = tx.send(SignalingMessage::HolePunchAnswer {
                            target_peer_id: offer.peer_id,
                            answer,
                        });
                    }
                    SignalingMessage::RelayData { session_id, chunk } => {
                        *active_session.lock().await = Some(session_id);
                        let _ = tunnel_for_host.inject_inbound_packet(&chunk);
                    }
                    SignalingMessage::RelayClose { session_id } => {
                        host_clients.lock().await.remove(&session_id);
                        *active_session.lock().await = None;
                    }
                    _ => {}
                }
            }
        });
    }

    let detected_shares = state.system.list_local_shares().await.unwrap_or_default();

    *state.host_signaling.lock().await = Some(Arc::clone(&client));
    *state.is_hosting.lock().await = true;
    *state.host_code.lock().await = code.clone();
    *state.host_status_message.lock().await = "Broadcasting on Cloud P2P Mesh".into();
    *state.host_share_name.lock().await = resolved_share_name.clone();
    *state.host_share_path.lock().await = resolved_share_path.clone();

    Ok(UiHostStatus {
        is_hosting: true,
        host_code: code,
        virtual_ip: Some(vip.addr().to_string()),
        signaling_url: url,
        message: "Broadcasting on Cloud P2P Mesh".into(),
        share_name: resolved_share_name,
        share_path: resolved_share_path,
        detected_shares,
        active_nodes: 0,
        max_nodes: allowed_nodes,
    })
}

#[tauri::command]
pub async fn stop_host_mode(state: tauri::State<'_, AppState>) -> Result<(), String> {
    if let Some(client) = state.host_signaling.lock().await.take() {
        let _ = client.disconnect().await;
    }
    let _ = state.tunnel.disconnect().await;
    state.host_connected_clients.lock().await.clear();
    *state.is_hosting.lock().await = false;
    *state.host_status_message.lock().await = "Offline".into();
    Ok(())
}

#[tauri::command]
pub async fn get_host_status(state: tauri::State<'_, AppState>) -> Result<UiHostStatus, String> {
    let hosting = *state.is_hosting.lock().await;
    let code = state.host_code.lock().await.clone();
    let msg = state.host_status_message.lock().await.clone();
    let share_name = state.host_share_name.lock().await.clone();
    let share_path = state.host_share_path.lock().await.clone();
    let active_nodes = state.host_connected_clients.lock().await.len() as u32;
    let max_nodes = *state.host_max_nodes.lock().await;
    let detected_shares = if hosting {
        state.system.list_local_shares().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(UiHostStatus {
        is_hosting: hosting,
        host_code: code,
        virtual_ip: if hosting { Some("10.99.0.1".into()) } else { None },
        signaling_url: "wss://t3bridge-signaling.onrender.com".into(),
        message: if hosting {
            msg
        } else {
            "Offline".into()
        },
        share_name: if hosting { share_name } else { String::new() },
        share_path: if hosting { share_path } else { String::new() },
        detected_shares,
        active_nodes,
        max_nodes,
    })
}

#[tauri::command]
pub async fn disconnect_bridge(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let drive = *state.active_drive.lock().await;
    let usecase = DisconnectSessionUseCase::new(
        Arc::clone(&state.tunnel) as Arc<dyn TunnelPort>,
        Arc::clone(&state.system),
    );

    usecase.execute(drive).await.map_err(|e| e.to_string())?;

    if let Some(client) = state.client_signaling.lock().await.take() {
        let _ = client.disconnect().await;
    }

    *state.active_drive.lock().await = None;
    *state.is_connected.lock().await = false;
    *state.active_unc.lock().await = None;
    *state.active_server_ip.lock().await = None;

    Ok(())
}

#[tauri::command]
pub async fn get_session_status(state: tauri::State<'_, AppState>) -> Result<UiSessionStatus, String> {
    let connected = *state.is_connected.lock().await;
    let drive = *state.active_drive.lock().await;
    let mapped_unc = state.active_unc.lock().await.clone();

    if connected {
        let watchdog = NetworkWatchdogUseCase::new(Arc::clone(&state.tunnel) as Arc<dyn TunnelPort>);
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

        let target_ip = state.active_server_ip.lock().await.clone();
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
            target_ip,
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
            target_ip: None,
        })
    }
}

#[tauri::command]
pub async fn open_folder(
    drive_letter: Option<char>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let drive = drive_letter
        .or(*state.active_drive.lock().await)
        .unwrap_or('Z');
    let unc = state.active_unc.lock().await.clone();

    let path_to_open = format!(r"{}:\", drive);

    let target = if std::path::Path::new(&path_to_open).exists() {
        path_to_open
    } else if let Some(unc_path) = unc {
        unc_path
    } else {
        path_to_open
    };

    let mut cmd = std::process::Command::new("explorer.exe");
    let _ = cmd.arg(&target).spawn().map_err(|e| e.to_string())?;

    Ok(())
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
    let tunnel = Arc::new(WintunTunnelAdapter::new());

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
        client_signaling: Mutex::new(None),
        is_hosting: Mutex::new(false),
        host_code: Mutex::new("HOST-PENDING".into()),
        host_status_message: Mutex::new("Offline".into()),
        active_server_ip: Mutex::new(None),
        host_share_name: Mutex::new("SharedData".into()),
        host_share_path: Mutex::new(r"C:\SharedData".into()),
        discovered_shares: Arc::new(Mutex::new(Vec::new())),
        host_connected_clients: Arc::new(Mutex::new(std::collections::HashSet::new())),
        host_max_nodes: Arc::new(Mutex::new(3)),
    }
}

#[tauri::command]
pub async fn open_external_url(url: String) -> Result<(), String> {
    let target = url.trim().to_string();
    if !target.starts_with("http://") && !target.starts_with("https://") {
        return Err("Invalid URL protocol".into());
    }

    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("cmd");
        cmd.creation_flags(0x08000000);
        let _ = cmd
            .args(["/c", "start", "", &target])
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "SuperSecretPassword123";
        let salt = "a1b2c3d4";
        let hash1 = hash_password_with_salt(password, salt);
        let hash2 = hash_password_with_salt(password, salt);
        assert_eq!(hash1, hash2);

        let wrong_hash = hash_password_with_salt("WrongPassword", salt);
        assert_ne!(hash1, wrong_hash);
    }

    #[test]
    fn test_host_config_serialization() {
        let config = HostConfig {
            host_code: "TRIAL-ADMIN-4A2F".into(),
            password_hash: "abcd1234ef567890".into(),
            salt: "salt1234".into(),
            updated_at: 1732283000,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HostConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.host_code, "TRIAL-ADMIN-4A2F");
        assert_eq!(deserialized.password_hash, "abcd1234ef567890");
    }

    #[test]
    fn test_client_config_serialization() {
        let config = ClientConfig {
            saved_target: "TRIAL-ADMIN-4A2F".into(),
            saved_password: "mysecret".into(),
            remember: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ClientConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.saved_target, "TRIAL-ADMIN-4A2F");
        assert_eq!(deserialized.saved_password, "mysecret");
        assert!(deserialized.remember);
    }
}

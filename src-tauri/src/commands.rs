use async_trait::async_trait;
use t3_adapters::{
    Ed25519LicenseVerifier, FileLicenseStorage, WindowsHardwareFingerprint, WindowsSystemAdapter,
};
use t3_application::ports::{
    HardwareFingerprintPort, LicenseStoragePort, LicenseVerifierPort, TunnelPort, WindowsSystemPort,
};
use t3_application::usecases::{
    ActivateLicenseUseCase, ConnectToHostUseCase, DisconnectSessionUseCase, NetworkWatchdogUseCase,
};
use t3_domain::{
    AppProfile, ConnectionHealth, DomainResult, License, Peer, PeerRole, TunnelMetrics, VirtualIp,
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

#[tauri::command]
pub fn get_app_profiles() -> Vec<AppProfile> {
    vec![
        AppProfile::marg_erp(),
        AppProfile::tally_prime(),
        AppProfile::busy_erp(),
        AppProfile::custom("Custom Business ERP", "Data", 'W'),
    ]
}

#[tauri::command]
pub async fn connect_bridge(
    target_peer_id: String,
    app_id: String,
    drive_letter: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let letter = drive_letter
        .chars()
        .next()
        .unwrap_or('Z')
        .to_ascii_uppercase();

    let profiles = get_app_profiles();
    let selected_app = profiles
        .into_iter()
        .find(|p| p.id == app_id)
        .unwrap_or_else(AppProfile::marg_erp);

    let virtual_ip = VirtualIp::new("10.99.0.1", 24).map_err(|e| e.to_string())?;
    let dummy_peer = Peer::new(
        target_peer_id,
        "Office Server".into(),
        PeerRole::HostServer,
        virtual_ip,
    );

    let usecase = ConnectToHostUseCase::new(
        Arc::clone(&state.tunnel),
        Arc::clone(&state.system),
    );

    let res = usecase
        .execute(&dummy_peer, &selected_app, letter, "T3-LIC-ACTIVE")
        .await
        .map_err(|e| e.to_string())?;

    *state.active_drive.lock().await = Some(letter);
    *state.is_connected.lock().await = true;

    Ok(format!("Connected! Drive {}: mapped to {}", res.drive_letter, res.session_unc_path))
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

    Ok(())
}

#[tauri::command]
pub async fn get_session_status(state: tauri::State<'_, AppState>) -> Result<UiSessionStatus, String> {
    let connected = *state.is_connected.lock().await;
    let drive = *state.active_drive.lock().await;

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
            mapped_unc: drive.map(|d| format!(r"\\10.99.0.1\SharedData -> {}:", d)),
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
    let storage_path = PathBuf::from("license_store.json");
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
    }
}

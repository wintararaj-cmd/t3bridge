use crate::config::{ServiceConfig, ServiceMode};
use serde::{Deserialize, Serialize};
use t3_domain::{License, TransportMode};

pub const PIPE_NAME: &str = r"\\.\pipe\t3bridge_service";
pub const SERVICE_NAME: &str = "t3BridgeService";
pub const SERVICE_DISPLAY_NAME: &str = "t3Bridge P2P Mesh Service";
pub const SERVICE_DESCRIPTION: &str =
    "Maintains background t3Bridge Host/Client P2P tunnels with automatic startup, sleep/wake recovery, and network switch reconnect.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Suspended,
}

impl Default for ConnectionPhase {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostSnapshot {
    pub is_hosting: bool,
    pub host_code: String,
    pub has_password: bool,
    pub virtual_ip: Option<String>,
    pub signaling_url: String,
    pub message: String,
    pub share_name: String,
    pub share_path: String,
    pub detected_shares: Vec<String>,
    pub active_nodes: u32,
    pub max_nodes: u32,
    #[serde(default)]
    pub transport_mode: TransportMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientSnapshot {
    pub is_tunnel_connected: bool,
    pub target_peer_id: Option<String>,
    pub server_ip: Option<String>,
    pub is_wan: bool,
    pub discovered_shares: Vec<String>,
    pub desired_share_name: Option<String>,
    pub desired_drive_letter: Option<char>,
    pub latency_ms: u32,
    pub health_level: String,
    pub is_safe: bool,
    pub status_text: String,
    pub alert_message: Option<String>,
    #[serde(default)]
    pub transport_mode: TransportMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseSnapshot {
    pub is_licensed: bool,
    pub is_trial: bool,
    pub is_expired: bool,
    pub customer_name: Option<String>,
    pub tier: String,
    pub days_remaining: u32,
    pub status_badge_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSnapshot {
    pub service_running: bool,
    pub mode: ServiceMode,
    pub phase: ConnectionPhase,
    pub auto_start_enabled: bool,
    pub prevent_sleep_while_hosting: bool,
    pub sleep_prevented_active: bool,
    pub host: HostSnapshot,
    pub client: ClientSnapshot,
    pub last_event: Option<String>,
    pub reconnect_attempts: u32,
}

impl Default for ServiceSnapshot {
    fn default() -> Self {
        Self {
            service_running: false,
            mode: ServiceMode::Idle,
            phase: ConnectionPhase::Disconnected,
            auto_start_enabled: true,
            prevent_sleep_while_hosting: true,
            sleep_prevented_active: false,
            host: HostSnapshot::default(),
            client: ClientSnapshot::default(),
            last_event: None,
            reconnect_attempts: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    GetStatus,
    GetServiceConfig,
    GetHardwareId,
    GetLicenseStatus,
    GetLicenseInfo,
    ActivateLicense {
        raw_key: String,
    },
    GetHostConfig,
    SetHostPassword {
        password: String,
    },
    StartHost {
        signaling_url: Option<String>,
        share_folder_path: Option<String>,
        share_name: Option<String>,
        auto_start: Option<bool>,
    },
    StopHost {
        clear_autostart: bool,
    },
    ConnectClient {
        target_peer_id: String,
        password: Option<String>,
        signaling_url: Option<String>,
        share_name: Option<String>,
        drive_letter: Option<char>,
        remember_for_autostart: bool,
    },
    SetClientMountSelection {
        share_name: String,
        drive_letter: char,
    },
    DisconnectClient {
        clear_autostart: bool,
    },
    ListServerShares,
    SetPreventSleep {
        enabled: bool,
    },
    SetAutoStart {
        enabled: bool,
    },
    TriggerReconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong,
    Status(ServiceSnapshot),
    ServiceConfig(ServiceConfig),
    HardwareId(String),
    LicenseStatus(LicenseSnapshot),
    LicenseInfo(Option<License>),
    ActivatedLicense(License),
    HostConfig {
        host_code: String,
        has_password: bool,
    },
    ClientConnected {
        server_ip: String,
        is_wan: bool,
        peer_id: String,
        discovered_shares: Vec<String>,
    },
    Shares(Vec<String>),
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
}

/// Sends a single JSON-line IPC request to the running `t3BridgeService` over Windows Named Pipe.
#[cfg(windows)]
pub async fn send_ipc_request(req: &IpcRequest) -> Result<IpcResponse, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    // Retry briefly if pipe is temporarily busy (ERROR_PIPE_BUSY = 231)
    let mut client = None;
    let mut last_err = String::new();
    for _ in 0..8 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(e) if e.raw_os_error() == Some(231) => {
                last_err = e.to_string();
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            Err(e) => {
                return Err(format!("Service IPC unavailable: {}", e));
            }
        }
    }

    let mut pipe = client.ok_or_else(|| format!("Service IPC busy: {}", last_err))?;
    let mut payload = serde_json::to_string(req).map_err(|e| e.to_string())?;
    payload.push('\n');

    pipe.write_all(payload.as_bytes())
        .await
        .map_err(|e| format!("IPC write failed: {}", e))?;
    pipe.flush()
        .await
        .map_err(|e| format!("IPC flush failed: {}", e))?;

    let mut reader = BufReader::new(pipe);
    let mut line = String::new();
    tokio::time::timeout(
        tokio::time::Duration::from_secs(90),
        reader.read_line(&mut line),
    )
    .await
    .map_err(|_| "Service IPC timed out".to_string())?
    .map_err(|e| format!("IPC read failed: {}", e))?;

    if line.trim().is_empty() {
        return Err("Empty response from t3BridgeService".into());
    }

    serde_json::from_str(&line).map_err(|e| format!("Invalid IPC response JSON: {}", e))
}

#[cfg(not(windows))]
pub async fn send_ipc_request(_req: &IpcRequest) -> Result<IpcResponse, String> {
    Err("Windows Named Pipe IPC is only supported on Windows".into())
}

pub async fn is_service_reachable() -> bool {
    matches!(send_ipc_request(&IpcRequest::Ping).await, Ok(IpcResponse::Pong))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_request_response_serialization() {
        let req = IpcRequest::ConnectClient {
            target_peer_id: "ACME-SERVER".into(),
            password: Some("secret".into()),
            signaling_url: None,
            share_name: Some("MargERP".into()),
            drive_letter: Some('Z'),
            remember_for_autostart: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: IpcRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            IpcRequest::ConnectClient {
                target_peer_id,
                remember_for_autostart,
                ..
            } => {
                assert_eq!(target_peer_id, "ACME-SERVER");
                assert!(remember_for_autostart);
            }
            _ => panic!("unexpected variant"),
        }

        let mut snap = ServiceSnapshot::default();
        snap.client.transport_mode = TransportMode::DirectUdpP2p;
        snap.host.transport_mode = TransportMode::WsBinaryRelay;
        let resp = IpcResponse::Status(snap);
        let resp_json = serde_json::to_string(&resp).unwrap();
        let parsed_resp: IpcResponse = serde_json::from_str(&resp_json).unwrap();
        match parsed_resp {
            IpcResponse::Status(s) => {
                assert_eq!(s.client.transport_mode, TransportMode::DirectUdpP2p);
                assert_eq!(s.host.transport_mode, TransportMode::WsBinaryRelay);
            }
            _ => panic!("unexpected variant"),
        }
    }
}

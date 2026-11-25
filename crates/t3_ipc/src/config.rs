use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const DEFAULT_SIGNALING_URL: &str = "wss://t3bridge-signaling.onrender.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMode {
    Idle,
    Host,
    Client,
}

impl Default for ServiceMode {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostServiceSettings {
    pub host_code: String,
    pub password_hash: String,
    pub salt: String,
    pub signaling_url: String,
    pub share_name: String,
    pub share_path: String,
    pub updated_at: i64,
}

impl Default for HostServiceSettings {
    fn default() -> Self {
        Self {
            host_code: String::new(),
            password_hash: String::new(),
            salt: String::new(),
            signaling_url: DEFAULT_SIGNALING_URL.to_string(),
            share_name: "SharedData".to_string(),
            share_path: r"C:\SharedData".to_string(),
            updated_at: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientServiceSettings {
    pub target_peer_id: String,
    /// Windows DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`) protected password (base64)
    pub encrypted_password_b64: String,
    pub signaling_url: String,
    pub share_name: Option<String>,
    pub drive_letter: char,
    pub remember_credentials: bool,
    pub auto_mount: bool,
}

impl Default for ClientServiceSettings {
    fn default() -> Self {
        Self {
            target_peer_id: String::new(),
            encrypted_password_b64: String::new(),
            signaling_url: DEFAULT_SIGNALING_URL.to_string(),
            share_name: None,
            drive_letter: 'Z',
            remember_credentials: false,
            auto_mount: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Persisted role: Host, Client, or Idle.
    /// On Windows boot, if `auto_start_enabled` is true, the service resumes this role automatically.
    pub mode: ServiceMode,
    pub auto_start_enabled: bool,
    /// Option 1: Prevent Windows from entering Sleep while Host Mode is active.
    pub prevent_sleep_while_hosting: bool,
    pub host: HostServiceSettings,
    pub client: ClientServiceSettings,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            mode: ServiceMode::Idle,
            auto_start_enabled: true,
            prevent_sleep_while_hosting: true,
            host: HostServiceSettings::default(),
            client: ClientServiceSettings::default(),
        }
    }
}

/// Machine-wide shared directory (`C:\ProgramData\t3Bridge`) accessible by both
/// the `LocalSystem` Windows Service (Session 0) and the user's Tray UI (Session 1).
pub fn get_shared_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("t3Bridge"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\t3Bridge"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(".t3bridge_data")
    }
}

/// Legacy per-user directory (`%LOCALAPPDATA%\t3Bridge`) used before Windows Service migration.
pub fn get_legacy_user_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|p| PathBuf::from(p).join("t3Bridge"))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

pub fn get_service_config_path() -> PathBuf {
    get_shared_data_dir().join("service_config.json")
}

pub fn get_shared_license_path() -> PathBuf {
    get_shared_data_dir().join("license_store.json")
}

pub fn load_service_config_from(path: &Path) -> Result<ServiceConfig, String> {
    if !path.exists() {
        return Ok(ServiceConfig::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;
    serde_json::from_str(&raw).map_err(|e| format!("Failed to parse config: {}", e))
}

pub fn save_service_config_to(path: &Path, config: &ServiceConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(path, json).map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

pub fn load_service_config() -> Result<ServiceConfig, String> {
    load_service_config_from(&get_service_config_path())
}

pub fn save_service_config(config: &ServiceConfig) -> Result<(), String> {
    save_service_config_to(&get_service_config_path(), config)
}

pub fn hash_password_with_salt(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn generate_salt() -> String {
    (0..8)
        .map(|_| format!("{:x}", rand::random::<u8>() % 16))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config_roundtrip() {
        let mut cfg = ServiceConfig::default();
        cfg.mode = ServiceMode::Host;
        cfg.auto_start_enabled = true;
        cfg.prevent_sleep_while_hosting = true;
        cfg.host.host_code = "ACME-SERVER".into();
        cfg.host.salt = "abcd1234".into();
        cfg.host.password_hash = hash_password_with_salt("pass1234", "abcd1234");

        let tmp = std::env::temp_dir().join("t3bridge_test_service_config.json");
        let _ = std::fs::remove_file(&tmp);
        save_service_config_to(&tmp, &cfg).expect("save should succeed");

        let loaded = load_service_config_from(&tmp).expect("load should succeed");
        assert_eq!(loaded.mode, ServiceMode::Host);
        assert!(loaded.auto_start_enabled);
        assert!(loaded.prevent_sleep_while_hosting);
        assert_eq!(loaded.host.host_code, "ACME-SERVER");
        assert_eq!(
            loaded.host.password_hash,
            hash_password_with_salt("pass1234", "abcd1234")
        );

        let _ = std::fs::remove_file(&tmp);
    }
}

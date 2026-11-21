use async_trait::async_trait;
use base64::prelude::*;
use std::path::PathBuf;
use t3_application::ports::LicenseStoragePort;
use t3_domain::{DomainError, DomainResult, License, TrialInfo};

pub struct FileLicenseStorage {
    storage_path: PathBuf,
    trial_path: PathBuf,
    enable_system_sync: bool,
}

impl FileLicenseStorage {
    pub fn new(storage_path: PathBuf) -> Self {
        let trial_path = storage_path.with_file_name("trial_info.json");
        Self {
            storage_path,
            trial_path,
            enable_system_sync: true,
        }
    }

    #[cfg(test)]
    pub fn new_isolated(storage_path: PathBuf) -> Self {
        let trial_path = storage_path.with_file_name("trial_info.json");
        Self {
            storage_path,
            trial_path,
            enable_system_sync: false,
        }
    }
}

fn get_program_data_trial_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("ProgramData")
            .ok()
            .map(|p| PathBuf::from(p).join("t3Bridge").join("trial_info.json"))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn get_public_trial_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("PUBLIC")
            .ok()
            .map(|p| PathBuf::from(p).join("t3Bridge").join("trial_info.json"))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
fn save_to_registry(key: &str, value_name: &str, data: &str) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let _ = std::process::Command::new("reg")
        .args(["add", key, "/v", value_name, "/d", data, "/f"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

#[cfg(not(windows))]
fn save_to_registry(_key: &str, _value_name: &str, _data: &str) {}

#[cfg(windows)]
fn load_from_registry(key: &str, value_name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let output = std::process::Command::new("reg")
        .args(["query", key, "/v", value_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(value_name) {
            let mut parts = trimmed.split_whitespace();
            let _val = parts.next()?;
            let _type = parts.next()?;
            let data = parts.next()?;
            return Some(data.to_string());
        }
    }
    None
}

#[cfg(not(windows))]
fn load_from_registry(_key: &str, _value_name: &str) -> Option<String> {
    None
}

fn is_trial_sensible(trial: &TrialInfo) -> bool {
    if trial.first_started_at <= 0 || trial.expires_at <= trial.first_started_at {
        return false;
    }
    let duration = trial.expires_at - trial.first_started_at;
    // Duration must be approximately 7 days (604,800 sec) with 1 hour grace
    if duration > TrialInfo::TRIAL_PERIOD_SECS + 3600 {
        return false;
    }
    true
}

fn parse_registry_trial(raw: &str) -> Option<TrialInfo> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(bytes) = BASE64_STANDARD.decode(trimmed.as_bytes()) {
        if let Ok(trial) = serde_json::from_slice::<TrialInfo>(&bytes) {
            return Some(trial);
        }
    }
    serde_json::from_str::<TrialInfo>(trimmed).ok()
}

async fn write_file_atomic(path: &PathBuf, content: &str) -> DomainResult<()> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let tmp_path = path.with_extension("tmp");
    if tokio::fs::write(&tmp_path, content.as_bytes()).await.is_ok() {
        let _ = tokio::fs::rename(&tmp_path, path).await;
    } else {
        tokio::fs::write(path, content.as_bytes())
            .await
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to write {}: {}", path.display(), e)))?;
    }
    Ok(())
}

async fn read_trial_file(path: &PathBuf) -> Option<TrialInfo> {
    if !path.exists() {
        return None;
    }
    let content = tokio::fs::read_to_string(path).await.ok()?;
    if content.trim().is_empty() {
        let _ = tokio::fs::remove_file(path).await;
        return None;
    }
    match serde_json::from_str::<TrialInfo>(&content) {
        Ok(t) => Some(t),
        Err(_) => {
            let _ = tokio::fs::remove_file(path).await;
            None
        }
    }
}

#[async_trait]
impl LicenseStoragePort for FileLicenseStorage {
    async fn save_license(&self, license: &License) -> DomainResult<()> {
        let json = serde_json::to_string_pretty(license)
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to serialize license: {}", e)))?;

        if let Some(parent) = self.storage_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        tokio::fs::write(&self.storage_path, json)
            .await
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to save license to disk: {}", e)))?;

        Ok(())
    }

    async fn load_license(&self) -> DomainResult<Option<License>> {
        if !self.storage_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&self.storage_path)
            .await
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to read license: {}", e)))?;

        if content.trim().is_empty() {
            return Ok(None);
        }

        let license = serde_json::from_str(&content)
            .map_err(|e| DomainError::InvalidLicense(format!("Corrupted license file: {}", e)))?;

        Ok(Some(license))
    }

    async fn save_trial(&self, trial: &TrialInfo) -> DomainResult<()> {
        let json = serde_json::to_string(trial)
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to serialize trial: {}", e)))?;

        // 1. Primary path (%LOCALAPPDATA%\t3Bridge\trial_info.json)
        write_file_atomic(&self.trial_path, &json).await?;

        // 2. Secondary persistence locations across system and registry
        if self.enable_system_sync {
            let encoded = BASE64_STANDARD.encode(json.as_bytes());

            if let Some(prog_data) = get_program_data_trial_path() {
                let _ = write_file_atomic(&prog_data, &json).await;
            }

            if let Some(pub_data) = get_public_trial_path() {
                let _ = write_file_atomic(&pub_data, &json).await;
            }

            save_to_registry("HKCU\\Software\\t3Bridge", "TrialData", &encoded);
            save_to_registry("HKLM\\SOFTWARE\\t3Bridge", "TrialData", &encoded);
        }

        Ok(())
    }

    async fn load_trial(&self) -> DomainResult<Option<TrialInfo>> {
        let mut candidates: Vec<TrialInfo> = Vec::new();

        // 1. Read from primary path
        if let Some(trial) = read_trial_file(&self.trial_path).await {
            candidates.push(trial);
        }

        // 2. If system sync is enabled, query secondary stores
        if self.enable_system_sync {
            if let Some(prog_data) = get_program_data_trial_path() {
                if let Some(trial) = read_trial_file(&prog_data).await {
                    candidates.push(trial);
                }
            }

            if let Some(pub_data) = get_public_trial_path() {
                if let Some(trial) = read_trial_file(&pub_data).await {
                    candidates.push(trial);
                }
            }

            if let Some(raw) = load_from_registry("HKCU\\Software\\t3Bridge", "TrialData") {
                if let Some(trial) = parse_registry_trial(&raw) {
                    candidates.push(trial);
                }
            }

            if let Some(raw) = load_from_registry("HKLM\\SOFTWARE\\t3Bridge", "TrialData") {
                if let Some(trial) = parse_registry_trial(&raw) {
                    candidates.push(trial);
                }
            }
        }

        candidates.retain(|t| is_trial_sensible(t));

        if candidates.is_empty() {
            return Ok(None);
        }

        // Pick the earliest started trial to prevent trial resets across reinstallation
        let earliest = candidates
            .into_iter()
            .min_by_key(|t| t.first_started_at)
            .unwrap();

        // Synchronize back to all locations so deleted stores are self-healed
        let _ = self.save_trial(&earliest).await;

        Ok(Some(earliest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_or_corrupted_trial_file_self_heals() {
        let temp_dir = std::env::temp_dir().join(format!(
            "t3_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;
        let license_path = temp_dir.join("license_store.json");
        let storage = FileLicenseStorage::new_isolated(license_path);

        // 1. Write empty file (0 bytes)
        tokio::fs::write(&storage.trial_path, "").await.unwrap();
        let loaded = storage.load_trial().await.unwrap();
        assert!(loaded.is_none(), "Empty file should return None and self-heal");

        // 2. Write invalid corrupted JSON
        tokio::fs::write(&storage.trial_path, "{invalid_json:").await.unwrap();
        let loaded_corrupted = storage.load_trial().await.unwrap();
        assert!(loaded_corrupted.is_none(), "Corrupted JSON should return None and self-heal");

        // 3. Normal save and load
        let trial = TrialInfo::new("TEST-HWID-01", 1700000000);
        storage.save_trial(&trial).await.unwrap();
        let loaded_valid = storage.load_trial().await.unwrap();
        assert!(loaded_valid.is_some());
        assert_eq!(loaded_valid.unwrap().hwid_hash, trial.hwid_hash);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_trial_sanity_checks() {
        let valid = TrialInfo::new("TEST-HWID-02", 1700000000);
        assert!(is_trial_sensible(&valid));

        let mut tampered = valid.clone();
        tampered.expires_at = tampered.first_started_at + (30 * 86400); // 30 days trial attempt
        assert!(!is_trial_sensible(&tampered));

        let mut reversed = valid.clone();
        reversed.expires_at = reversed.first_started_at - 1000;
        assert!(!is_trial_sensible(&reversed));
    }
}

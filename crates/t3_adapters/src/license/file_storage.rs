use async_trait::async_trait;
use t3_application::ports::LicenseStoragePort;
use t3_domain::{DomainError, DomainResult, License, TrialInfo};
use std::path::PathBuf;

pub struct FileLicenseStorage {
    storage_path: PathBuf,
    trial_path: PathBuf,
}

impl FileLicenseStorage {
    pub fn new(storage_path: PathBuf) -> Self {
        let trial_path = storage_path.with_file_name("trial_info.json");
        Self {
            storage_path,
            trial_path,
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

        if let Some(parent) = self.trial_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        // Atomic write via temporary file to prevent 0-byte corruption on crash/exit
        let tmp_path = self.trial_path.with_extension("tmp");
        if tokio::fs::write(&tmp_path, json.as_bytes()).await.is_ok() {
            let _ = tokio::fs::rename(&tmp_path, &self.trial_path).await;
        } else {
            tokio::fs::write(&self.trial_path, json.as_bytes())
                .await
                .map_err(|e| DomainError::InvalidLicense(format!("Failed to save trial info: {}", e)))?;
        }

        Ok(())
    }

    async fn load_trial(&self) -> DomainResult<Option<TrialInfo>> {
        if !self.trial_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&self.trial_path)
            .await
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to read trial info: {}", e)))?;

        if content.trim().is_empty() {
            // Self-heal: empty file (0 bytes), clean it up so a valid trial can be initiated
            let _ = tokio::fs::remove_file(&self.trial_path).await;
            return Ok(None);
        }

        match serde_json::from_str::<TrialInfo>(&content) {
            Ok(trial) => Ok(Some(trial)),
            Err(_) => {
                // Self-heal: corrupted JSON content, remove so fresh trial can be initialized
                let _ = tokio::fs::remove_file(&self.trial_path).await;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_or_corrupted_trial_file_self_heals() {
        let temp_dir = std::env::temp_dir().join(format!("t3_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;
        let license_path = temp_dir.join("license_store.json");
        let storage = FileLicenseStorage::new(license_path);

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
}

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

        tokio::fs::write(&self.trial_path, json)
            .await
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to save trial info: {}", e)))?;

        Ok(())
    }

    async fn load_trial(&self) -> DomainResult<Option<TrialInfo>> {
        if !self.trial_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&self.trial_path)
            .await
            .map_err(|e| DomainError::InvalidLicense(format!("Failed to read trial info: {}", e)))?;

        let trial = serde_json::from_str(&content)
            .map_err(|e| DomainError::InvalidLicense(format!("Corrupted trial info: {}", e)))?;

        Ok(Some(trial))
    }
}

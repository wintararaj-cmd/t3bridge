use async_trait::async_trait;
use t3_application::ports::LicenseStoragePort;
use t3_domain::{DomainError, DomainResult, License};
use std::path::PathBuf;

pub struct FileLicenseStorage {
    storage_path: PathBuf,
}

impl FileLicenseStorage {
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
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
}

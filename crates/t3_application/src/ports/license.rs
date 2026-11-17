use async_trait::async_trait;
use t3_domain::{DomainResult, HardwareId, License};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait HardwareFingerprintPort: Send + Sync {
    /// Detects current Windows machine's unique hardware identifier
    async fn get_hardware_id(&self) -> DomainResult<HardwareId>;
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait LicenseVerifierPort: Send + Sync {
    /// Validates raw digital signature of the license string against public key
    async fn verify_signature(&self, license_raw_json: &str, signature_base64: &str) -> DomainResult<()>;
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait LicenseStoragePort: Send + Sync {
    /// Stores the active license locally on disk securely
    async fn save_license(&self, license: &License) -> DomainResult<()>;
    /// Loads the stored license from disk
    async fn load_license(&self) -> DomainResult<Option<License>>;
}

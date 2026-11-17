use crate::ports::{HardwareFingerprintPort, LicenseStoragePort, LicenseVerifierPort};
use chrono::Utc;
use marg_domain::{DomainError, DomainResult, License};
use std::sync::Arc;

pub struct ActivateLicenseUseCase {
    verifier: Arc<dyn LicenseVerifierPort>,
    hwid_provider: Arc<dyn HardwareFingerprintPort>,
    storage: Arc<dyn LicenseStoragePort>,
}

impl ActivateLicenseUseCase {
    pub fn new(
        verifier: Arc<dyn LicenseVerifierPort>,
        hwid_provider: Arc<dyn HardwareFingerprintPort>,
        storage: Arc<dyn LicenseStoragePort>,
    ) -> Self {
        Self {
            verifier,
            hwid_provider,
            storage,
        }
    }

    pub async fn execute(&self, raw_license_json: &str) -> DomainResult<License> {
        // 1. Parse JSON into License structure
        let license: License = serde_json::from_str(raw_license_json)
            .map_err(|e| DomainError::InvalidLicense(format!("JSON parse error: {}", e)))?;

        // 2. Canonical JSON string of the payload for cryptographic verification
        let payload_json = serde_json::to_string(&license.payload)
            .map_err(|e| DomainError::InvalidLicense(format!("Payload error: {}", e)))?;

        // 3. Verify digital signature using Ed25519
        self.verifier
            .verify_signature(&payload_json, &license.signature_base64)
            .await?;

        // 4. Verify that this machine matches the hardware ID in the license
        let current_hwid = self.hwid_provider.get_hardware_id().await?;
        license.validate_entitlement(&current_hwid, 0, Utc::now())?;

        // 5. Persist the license locally
        self.storage.save_license(&license).await?;

        Ok(license)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{MockHardwareFingerprintPort, MockLicenseStoragePort, MockLicenseVerifierPort};
    use marg_domain::{HardwareId, LicensePayload, LicenseTier};

    #[tokio::test]
    async fn test_successful_activation() {
        let mut mock_verifier = MockLicenseVerifierPort::new();
        mock_verifier
            .expect_verify_signature()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut mock_hwid = MockHardwareFingerprintPort::new();
        mock_hwid
            .expect_get_hardware_id()
            .times(1)
            .returning(|| Ok(HardwareId::new("CPU-MBO-123456").unwrap()));

        let mut mock_storage = MockLicenseStoragePort::new();
        mock_storage
            .expect_save_license()
            .times(1)
            .returning(|_| Ok(()));

        let usecase = ActivateLicenseUseCase::new(
            Arc::new(mock_verifier),
            Arc::new(mock_hwid),
            Arc::new(mock_storage),
        );

        let payload = LicensePayload {
            license_id: "LIC-001".into(),
            customer_name: "Test Customer".into(),
            hardware_id: "CPU-MBO-123456".into(),
            tier: LicenseTier::Standard,
            max_nodes: 3,
            issued_at: Utc::now().timestamp(),
            expires_at: None,
        };

        let license = License::new(payload, "base64_sig".into());
        let raw_json = serde_json::to_string(&license).unwrap();

        let result = usecase.execute(&raw_json).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hardware_mismatch_activation_fails() {
        let mut mock_verifier = MockLicenseVerifierPort::new();
        mock_verifier
            .expect_verify_signature()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut mock_hwid = MockHardwareFingerprintPort::new();
        mock_hwid
            .expect_get_hardware_id()
            .times(1)
            .returning(|| Ok(HardwareId::new("DIFFERENT-HWID-999").unwrap()));

        let mock_storage = MockLicenseStoragePort::new();

        let usecase = ActivateLicenseUseCase::new(
            Arc::new(mock_verifier),
            Arc::new(mock_hwid),
            Arc::new(mock_storage),
        );

        let payload = LicensePayload {
            license_id: "LIC-001".into(),
            customer_name: "Test Customer".into(),
            hardware_id: "CPU-MBO-123456".into(),
            tier: LicenseTier::Standard,
            max_nodes: 3,
            issued_at: Utc::now().timestamp(),
            expires_at: None,
        };

        let license = License::new(payload, "base64_sig".into());
        let raw_json = serde_json::to_string(&license).unwrap();

        let result = usecase.execute(&raw_json).await;
        assert!(matches!(result, Err(DomainError::HardwareMismatch { .. })));
    }
}

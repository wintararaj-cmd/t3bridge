use std::sync::Arc;
use chrono::Utc;
use t3_domain::{DomainResult, LicenseStatus, TrialEvaluation, TrialInfo};
use crate::ports::{HardwareFingerprintPort, LicenseStoragePort};

pub struct CheckLicenseStatusUseCase {
    hwid_provider: Arc<dyn HardwareFingerprintPort>,
    storage: Arc<dyn LicenseStoragePort>,
}

impl CheckLicenseStatusUseCase {
    pub fn new(
        hwid_provider: Arc<dyn HardwareFingerprintPort>,
        storage: Arc<dyn LicenseStoragePort>,
    ) -> Self {
        Self {
            hwid_provider,
            storage,
        }
    }

    pub async fn execute(&self) -> DomainResult<LicenseStatus> {
        let hwid = self.hwid_provider.get_hardware_id().await?;
        let now = Utc::now().timestamp();

        // 1. Check if an active valid license is installed
        if let Some(license) = self.storage.load_license().await? {
            let res = license.validate_entitlement(&hwid, 0, Utc::now());
            if res.is_ok() {
                return Ok(LicenseStatus::Licensed {
                    customer_name: license.payload.customer_name,
                    tier: license.payload.tier,
                    max_nodes: license.payload.max_nodes,
                });
            }
        }

        // 2. Fall back to 7-day free trial engine
        let mut trial = match self.storage.load_trial().await? {
            Some(existing) => existing,
            None => {
                let fresh = TrialInfo::new(hwid.as_str(), now);
                self.storage.save_trial(&fresh).await?;
                fresh
            }
        };

        let evaluation = trial.evaluate_status(hwid.as_str(), now);
        self.storage.save_trial(&trial).await?;

        match evaluation {
            TrialEvaluation::Active { days_left, .. } => {
                Ok(LicenseStatus::TrialActive { days_left })
            }
            TrialEvaluation::Expired => Ok(LicenseStatus::TrialExpired),
            TrialEvaluation::ClockTampered | TrialEvaluation::HwidMismatch => {
                Ok(LicenseStatus::TrialTampered)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{MockHardwareFingerprintPort, MockLicenseStoragePort};
    use t3_domain::{HardwareId, License, LicensePayload, LicenseTier};

    #[tokio::test]
    async fn test_first_launch_initiates_7_day_trial() {
        let mut mock_hwid = MockHardwareFingerprintPort::new();
        mock_hwid
            .expect_get_hardware_id()
            .times(1)
            .returning(|| Ok(HardwareId::new("T3-PC-1234").unwrap()));

        let mut mock_storage = MockLicenseStoragePort::new();
        mock_storage.expect_load_license().times(1).returning(|| Ok(None));
        mock_storage.expect_load_trial().times(1).returning(|| Ok(None));
        mock_storage.expect_save_trial().times(2).returning(|_| Ok(()));

        let usecase = CheckLicenseStatusUseCase::new(Arc::new(mock_hwid), Arc::new(mock_storage));
        let status = usecase.execute().await.unwrap();

        match status {
            LicenseStatus::TrialActive { days_left } => {
                assert!(days_left <= 7 && days_left >= 6);
                assert!(status.is_allowed_to_connect());
            }
            _ => panic!("Expected TrialActive on first launch"),
        }
    }

    #[tokio::test]
    async fn test_expired_trial_blocks_connecting() {
        let mut mock_hwid = MockHardwareFingerprintPort::new();
        mock_hwid
            .expect_get_hardware_id()
            .times(1)
            .returning(|| Ok(HardwareId::new("T3-PC-1234").unwrap()));

        let mut expired_trial = TrialInfo::new("T3-PC-1234", 100000);
        expired_trial.expires_at = 200000; // Past

        let mut mock_storage = MockLicenseStoragePort::new();
        mock_storage.expect_load_license().times(1).returning(|| Ok(None));
        mock_storage.expect_load_trial().times(1).returning(move || Ok(Some(expired_trial.clone())));
        mock_storage.expect_save_trial().times(1).returning(|_| Ok(()));

        let usecase = CheckLicenseStatusUseCase::new(Arc::new(mock_hwid), Arc::new(mock_storage));
        let status = usecase.execute().await.unwrap();

        assert_eq!(status, LicenseStatus::TrialExpired);
        assert!(!status.is_allowed_to_connect());
    }

    #[tokio::test]
    async fn test_licensed_user_bypasses_trial() {
        let mut mock_hwid = MockHardwareFingerprintPort::new();
        mock_hwid
            .expect_get_hardware_id()
            .times(1)
            .returning(|| Ok(HardwareId::new("T3-PC-1234").unwrap()));

        let license = License::new(
            LicensePayload {
                license_id: "LIC-001".into(),
                customer_name: "Kolkata Traders".into(),
                hardware_id: "T3-PC-1234".into(),
                tier: LicenseTier::Standard,
                max_nodes: 5,
                issued_at: Utc::now().timestamp(),
                expires_at: None,
            },
            "sig".into(),
        );

        let mut mock_storage = MockLicenseStoragePort::new();
        mock_storage.expect_load_license().times(1).returning(move || Ok(Some(license.clone())));

        let usecase = CheckLicenseStatusUseCase::new(Arc::new(mock_hwid), Arc::new(mock_storage));
        let status = usecase.execute().await.unwrap();

        match status {
            LicenseStatus::Licensed { ref customer_name, .. } => {
                assert_eq!(customer_name, "Kolkata Traders");
                assert!(status.is_allowed_to_connect());
            }
            _ => panic!("Expected Licensed status"),
        }
    }
}

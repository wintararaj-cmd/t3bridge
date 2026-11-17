use crate::errors::{DomainError, DomainResult};
use crate::value_objects::HardwareId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseTier {
    Trial,
    Standard,
    Professional,
    Enterprise,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicensePayload {
    pub license_id: String,
    pub customer_name: String,
    pub hardware_id: String,
    pub tier: LicenseTier,
    pub max_nodes: u32,
    pub issued_at: i64,
    pub expires_at: Option<i64>, // Unix timestamp in seconds (None = Lifetime)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct License {
    pub payload: LicensePayload,
    pub signature_base64: String,
}

impl License {
    pub fn new(payload: LicensePayload, signature_base64: String) -> Self {
        Self {
            payload,
            signature_base64,
        }
    }

    /// Verifies machine binding, expiration, and active node limits
    pub fn validate_entitlement(
        &self,
        current_hwid: &HardwareId,
        current_active_peers: u32,
        current_time: DateTime<Utc>,
    ) -> DomainResult<()> {
        // 1. Hardware ID verification
        if self.payload.hardware_id != current_hwid.as_str() {
            return Err(DomainError::HardwareMismatch {
                expected: self.payload.hardware_id.clone(),
                actual: current_hwid.to_string(),
            });
        }

        // 2. Expiration verification
        if let Some(exp_sec) = self.payload.expires_at {
            let exp_dt = DateTime::from_timestamp(exp_sec, 0)
                .ok_or_else(|| DomainError::InvalidLicense("Corrupt expiry timestamp".into()))?;

            if current_time > exp_dt {
                return Err(DomainError::LicenseExpired(exp_dt.to_rfc3339()));
            }
        }

        // 3. Node/Branch limit check
        if current_active_peers >= self.payload.max_nodes {
            return Err(DomainError::PeerLimitExceeded {
                max: self.payload.max_nodes,
                current: current_active_peers,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialInfo {
    pub first_started_at: i64,
    pub expires_at: i64,
    pub last_checked_at: i64,
    pub hwid_hash: String,
}

impl TrialInfo {
    pub const TRIAL_PERIOD_SECS: i64 = 7 * 86400; // 7 Days

    pub fn new(hwid: &str, now: i64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(format!("t3_trial_{}", hwid).as_bytes());
        let hwid_hash = format!("{:x}", hasher.finalize());

        Self {
            first_started_at: now,
            expires_at: now + Self::TRIAL_PERIOD_SECS,
            last_checked_at: now,
            hwid_hash,
        }
    }

    pub fn evaluate_status(&mut self, hwid: &str, now: i64) -> TrialEvaluation {
        // Clock tampering check: time moved backwards by > 60 seconds
        if now < self.last_checked_at - 60 {
            return TrialEvaluation::ClockTampered;
        }

        let mut hasher = Sha256::new();
        hasher.update(format!("t3_trial_{}", hwid).as_bytes());
        let expected_hash = format!("{:x}", hasher.finalize());

        if self.hwid_hash != expected_hash {
            return TrialEvaluation::HwidMismatch;
        }

        self.last_checked_at = now;

        if now >= self.expires_at {
            TrialEvaluation::Expired
        } else {
            let secs_left = (self.expires_at - now) as u64;
            let days_left = ((self.expires_at - now + 86399) / 86400) as u32;
            TrialEvaluation::Active {
                days_left,
                secs_left,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrialEvaluation {
    Active { days_left: u32, secs_left: u64 },
    Expired,
    ClockTampered,
    HwidMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseStatus {
    Licensed {
        customer_name: String,
        tier: LicenseTier,
        max_nodes: u32,
    },
    TrialActive {
        days_left: u32,
    },
    TrialExpired,
    TrialTampered,
}

impl LicenseStatus {
    pub fn is_allowed_to_connect(&self) -> bool {
        matches!(
            self,
            LicenseStatus::Licensed { .. } | LicenseStatus::TrialActive { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_validation_success() {
        let hwid = HardwareId::new("CPU-MBO-123456").unwrap();
        let payload = LicensePayload {
            license_id: "LIC-001".into(),
            customer_name: "ABC Pharmaceuticals".into(),
            hardware_id: hwid.to_string(),
            tier: LicenseTier::Standard,
            max_nodes: 5,
            issued_at: Utc::now().timestamp(),
            expires_at: Some(Utc::now().timestamp() + 86400 * 30), // 30 days
        };

        let license = License::new(payload, "mock_sig".into());
        assert!(license.validate_entitlement(&hwid, 2, Utc::now()).is_ok());
    }

    #[test]
    fn test_license_hardware_mismatch() {
        let licensed_hwid = HardwareId::new("CPU-MBO-123456").unwrap();
        let current_hwid = HardwareId::new("OTHER-MACHINE-999").unwrap();

        let payload = LicensePayload {
            license_id: "LIC-001".into(),
            customer_name: "ABC Pharmaceuticals".into(),
            hardware_id: licensed_hwid.to_string(),
            tier: LicenseTier::Standard,
            max_nodes: 5,
            issued_at: Utc::now().timestamp(),
            expires_at: None,
        };

        let license = License::new(payload, "mock_sig".into());
        let res = license.validate_entitlement(&current_hwid, 0, Utc::now());
        assert!(matches!(res, Err(DomainError::HardwareMismatch { .. })));
    }

    #[test]
    fn test_license_node_limit_exceeded() {
        let hwid = HardwareId::new("CPU-MBO-123456").unwrap();
        let payload = LicensePayload {
            license_id: "LIC-001".into(),
            customer_name: "ABC Pharmaceuticals".into(),
            hardware_id: hwid.to_string(),
            tier: LicenseTier::Standard,
            max_nodes: 3,
            issued_at: Utc::now().timestamp(),
            expires_at: None,
        };

        let license = License::new(payload, "mock_sig".into());
        let res = license.validate_entitlement(&hwid, 3, Utc::now());
        assert!(matches!(res, Err(DomainError::PeerLimitExceeded { max: 3, current: 3 })));
    }

    #[test]
    fn test_trial_lifecycle_and_tamper_detection() {
        let hwid = "T3-TEST-HWID-01";
        let start_time = 1000000;
        let mut trial = TrialInfo::new(hwid, start_time);

        // Day 1: 7 days left
        let status = trial.evaluate_status(hwid, start_time + 100);
        match status {
            TrialEvaluation::Active { days_left, .. } => assert_eq!(days_left, 7),
            _ => panic!("Expected active trial"),
        }

        // Day 4: 4 days left
        let status_day_4 = trial.evaluate_status(hwid, start_time + (4 * 86400));
        match status_day_4 {
            TrialEvaluation::Active { days_left, .. } => assert_eq!(days_left, 3),
            _ => panic!("Expected active trial"),
        }

        // Clock rollback: current time < last_checked_at
        let tampered = trial.evaluate_status(hwid, start_time + 50);
        assert_eq!(tampered, TrialEvaluation::ClockTampered);

        // After 8 days: Expired
        let mut fresh_trial = TrialInfo::new(hwid, start_time);
        let expired = fresh_trial.evaluate_status(hwid, start_time + (8 * 86400));
        assert_eq!(expired, TrialEvaluation::Expired);
    }
}

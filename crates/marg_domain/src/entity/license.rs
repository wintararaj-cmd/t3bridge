use crate::errors::{DomainError, DomainResult};
use crate::value_objects::HardwareId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

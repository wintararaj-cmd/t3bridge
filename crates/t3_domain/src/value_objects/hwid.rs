use crate::errors::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HardwareId(String);

impl HardwareId {
    pub fn new(raw_id: &str) -> DomainResult<Self> {
        let trimmed = raw_id.trim();
        if trimmed.len() < 8 {
            return Err(DomainError::InvalidHardwareId("HWID is too short".into()));
        }
        Ok(Self(trimmed.to_uppercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HardwareId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

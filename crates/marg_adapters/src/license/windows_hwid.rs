use async_trait::async_trait;
use marg_application::ports::HardwareFingerprintPort;
use marg_domain::{DomainResult, HardwareId};
use sha2::{Digest, Sha256};

pub struct WindowsHardwareFingerprint;

impl WindowsHardwareFingerprint {
    pub fn new() -> Self {
        Self
    }

    fn calculate_local_hash() -> String {
        // Collect identifying hardware attributes:
        // On Windows, USERDOMAIN, COMPUTERNAME, and PROCESSOR_IDENTIFIER provide stable machine bounds
        let computer_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN_PC".into());
        let processor = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "UNKNOWN_CPU".into());
        let user_domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "UNKNOWN_DOMAIN".into());

        let raw_fingerprint = format!("{}:{}:{}", computer_name, processor, user_domain);
        let mut hasher = Sha256::new();
        hasher.update(raw_fingerprint.as_bytes());
        let result = hasher.finalize();

        // Format into readable groups: e.g. T3-ABCD-1234-EF56-7890
        let hex = format!("{:X}", result);
        format!("T3-{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])
    }
}

impl Default for WindowsHardwareFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HardwareFingerprintPort for WindowsHardwareFingerprint {
    async fn get_hardware_id(&self) -> DomainResult<HardwareId> {
        let hash = Self::calculate_local_hash();
        HardwareId::new(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hwid_generation() {
        let provider = WindowsHardwareFingerprint::new();
        let hwid = provider.get_hardware_id().await.unwrap();
        assert!(hwid.as_str().starts_with("T3-") || hwid.as_str().len() >= 8);
    }
}

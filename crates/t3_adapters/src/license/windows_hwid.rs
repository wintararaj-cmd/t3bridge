use async_trait::async_trait;
use t3_application::ports::HardwareFingerprintPort;
use t3_domain::{DomainResult, HardwareId};
use sha2::{Digest, Sha256};

pub struct WindowsHardwareFingerprint;

impl WindowsHardwareFingerprint {
    pub fn new() -> Self {
        Self
    }

    fn compute_hash_from_parts(
        computer_name: Option<&str>,
        processor: Option<&str>,
        user_domain: Option<&str>,
    ) -> String {
        let computer = computer_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("UNKNOWN_PC");
        let cpu = processor
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("UNKNOWN_CPU");
        // On Windows, USERDOMAIN is a per-user logon env var. In Session 0 (LocalSystem Windows
        // Service), USERDOMAIN is unset or "NT AUTHORITY" / "WORKGROUP", whereas in interactive
        // workgroup sessions (Session 1 UI) it equals COMPUTERNAME. Fall back to COMPUTERNAME so
        // the Service and UI always derive the exact same HWID while staying backwards-compatible
        // with existing trials and commercial licenses.
        let domain = user_domain
            .map(str::trim)
            .filter(|s| {
                !s.is_empty()
                    && !s.eq_ignore_ascii_case("NT AUTHORITY")
                    && !s.eq_ignore_ascii_case("WORKGROUP")
            })
            .unwrap_or(computer);

        let raw_fingerprint = format!("{}:{}:{}", computer, cpu, domain);
        let mut hasher = Sha256::new();
        hasher.update(raw_fingerprint.as_bytes());
        let result = hasher.finalize();

        // Format into readable groups: e.g. T3-ABCD-1234-EF56
        let hex = format!("{:X}", result);
        format!("T3-{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])
    }

    fn calculate_local_hash() -> String {
        let computer_name = std::env::var("COMPUTERNAME").ok();
        let processor = std::env::var("PROCESSOR_IDENTIFIER").ok();
        let user_domain = std::env::var("USERDOMAIN").ok();

        Self::compute_hash_from_parts(
            computer_name.as_deref(),
            processor.as_deref(),
            user_domain.as_deref(),
        )
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

    #[test]
    fn test_hwid_matches_between_user_session_and_localsystem_service() {
        let cpu = Some("Intel64 Family 6 Model 69 Stepping 1, GenuineIntel");
        let ui_session = WindowsHardwareFingerprint::compute_hash_from_parts(
            Some("CLIENT-PC"),
            cpu,
            Some("CLIENT-PC"),
        );
        let service_no_domain = WindowsHardwareFingerprint::compute_hash_from_parts(
            Some("CLIENT-PC"),
            cpu,
            None,
        );
        let service_nt_authority = WindowsHardwareFingerprint::compute_hash_from_parts(
            Some("CLIENT-PC"),
            cpu,
            Some("NT AUTHORITY"),
        );
        let service_workgroup = WindowsHardwareFingerprint::compute_hash_from_parts(
            Some("CLIENT-PC"),
            cpu,
            Some("WORKGROUP"),
        );

        assert_eq!(ui_session, service_no_domain);
        assert_eq!(ui_session, service_nt_authority);
        assert_eq!(ui_session, service_workgroup);
    }
}

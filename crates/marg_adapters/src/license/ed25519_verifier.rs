use async_trait::async_trait;
use base64::prelude::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use marg_application::ports::LicenseVerifierPort;
use marg_domain::{DomainError, DomainResult};

pub struct Ed25519LicenseVerifier {
    public_key: VerifyingKey,
}

impl Ed25519LicenseVerifier {
    pub fn new(public_key_bytes: &[u8; 32]) -> DomainResult<Self> {
        let public_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| DomainError::InvalidLicense(format!("Invalid public key: {}", e)))?;
        Ok(Self { public_key })
    }
}

#[async_trait]
impl LicenseVerifierPort for Ed25519LicenseVerifier {
    async fn verify_signature(&self, license_raw_json: &str, signature_base64: &str) -> DomainResult<()> {
        let sig_bytes = BASE64_STANDARD
            .decode(signature_base64)
            .map_err(|e| DomainError::InvalidLicense(format!("Base64 signature decode error: {}", e)))?;

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| DomainError::InvalidLicense(format!("Invalid signature format: {}", e)))?;

        self.public_key
            .verify(license_raw_json.as_bytes(), &signature)
            .map_err(|_| DomainError::InvalidLicense("Cryptographic signature check failed! License was tampered with.".into()))?;

        Ok(())
    }
}

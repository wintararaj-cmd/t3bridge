use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum DomainError {
    #[error("Invalid IP address or CIDR: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid Hardware ID: {0}")]
    InvalidHardwareId(String),

    #[error("License is invalid or corrupted: {0}")]
    InvalidLicense(String),

    #[error("License has expired on {0}")]
    LicenseExpired(String),

    #[error("License peer limit exceeded (Max allowed: {max}, Current: {current})")]
    PeerLimitExceeded { max: u32, current: u32 },

    #[error("Hardware ID mismatch (Licensed for: {expected}, Current machine: {actual})")]
    HardwareMismatch { expected: String, actual: String },

    #[error("Invalid connection state transition: cannot transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Drive letter is already in use: {0}")]
    DriveLetterInUse(char),

    #[error("Network connection failure: {0}")]
    NetworkFailure(String),

    #[error("Operation timed out: {0}")]
    Timeout(String),
}

pub type DomainResult<T> = Result<T, DomainError>;

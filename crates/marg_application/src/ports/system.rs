use async_trait::async_trait;
use marg_domain::DomainResult;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait WindowsSystemPort: Send + Sync {
    /// Mounts Windows SMB share to drive letter (e.g. 'Z')
    async fn mount_drive(&self, letter: char, unc_path: &str) -> DomainResult<()>;

    /// Unmounts network drive cleanly
    async fn unmount_drive(&self, letter: char) -> DomainResult<()>;

    /// Checks if a drive letter is currently occupied
    async fn is_drive_in_use(&self, letter: char) -> DomainResult<bool>;

    /// Adds or updates Windows Firewall rule to allow SMB across virtual subnet
    async fn configure_firewall_rule(&self, subnet_cidr: &str) -> DomainResult<()>;
}

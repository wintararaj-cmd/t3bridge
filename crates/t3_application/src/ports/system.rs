use async_trait::async_trait;
use t3_domain::DomainResult;

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

    /// Lists available SMB shares on a remote host (e.g. via `net view \\<host>`)
    async fn list_remote_shares(&self, host: &str) -> DomainResult<Vec<String>>;

    /// Lists locally shared folders on this machine (e.g. via `net share`)
    async fn list_local_shares(&self) -> DomainResult<Vec<String>>;
}

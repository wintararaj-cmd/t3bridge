use async_trait::async_trait;
use t3_application::ports::WindowsSystemPort;
use t3_domain::{DomainError, DomainResult};
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct WindowsSystemAdapter;

impl WindowsSystemAdapter {
    pub fn new() -> Self {
        Self
    }

    fn hidden_command(program: &str) -> Command {
        let mut cmd = Command::new(program);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }
}

impl Default for WindowsSystemAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsSystemPort for WindowsSystemAdapter {
    async fn mount_drive(&self, letter: char, unc_path: &str) -> DomainResult<()> {
        let drive_spec = format!("{}:", letter.to_ascii_uppercase());

        // First clean up any existing disconnected or ghost drive mapping:
        let _ = Self::hidden_command("net")
            .args(["use", &drive_spec, "/delete", "/y"])
            .output();

        // Run: net use Z: \\10.99.0.1\Share /persistent:no
        let output = Self::hidden_command("net")
            .args(["use", &drive_spec, unc_path, "/persistent:no"])
            .output()
            .map_err(|e| DomainError::InvalidIpAddress(format!("Failed to spawn 'net use': {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(DomainError::InvalidIpAddress(format!(
                "Failed to mount drive {}: {} {}",
                drive_spec, stdout, stderr
            )));
        }

        Ok(())
    }

    async fn unmount_drive(&self, letter: char) -> DomainResult<()> {
        let drive_spec = format!("{}:", letter.to_ascii_uppercase());

        // Run: net use Z: /delete /y
        let _ = Self::hidden_command("net")
            .args(["use", &drive_spec, "/delete", "/y"])
            .output();

        Ok(())
    }

    async fn is_drive_in_use(&self, letter: char) -> DomainResult<bool> {
        let path_str = format!(r"{}:\", letter.to_ascii_uppercase());
        let exists = Path::new(&path_str).exists();
        Ok(exists)
    }

    async fn configure_firewall_rule(&self, subnet_cidr: &str) -> DomainResult<()> {
        // Run: netsh advfirewall firewall add rule name="t3Bridge-SMB" dir=in action=allow protocol=TCP localport=445 remoteip=10.99.0.0/24
        let _ = Self::hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=t3Bridge-SMB",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                "localport=445",
                &format!("remoteip={}", subnet_cidr),
            ])
            .output();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_c_drive_is_in_use() {
        let adapter = WindowsSystemAdapter::new();
        // C: drive is always in use on Windows
        assert!(adapter.is_drive_in_use('C').await.unwrap());
    }
}

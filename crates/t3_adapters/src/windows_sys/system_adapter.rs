use async_trait::async_trait;
use t3_application::ports::WindowsSystemPort;
use t3_domain::{DomainError, DomainResult};
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Parses `net view \\<host>` output and returns a list of Disk share names.
/// Skips header lines, separator lines, and the final status line.
fn parse_net_view_output(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Skip empty, separator, header, or summary lines
            if trimmed.is_empty()
                || trimmed.starts_with('-')
                || trimmed.starts_with("Shared resources")
                || trimmed.starts_with("Share name")
                || trimmed.starts_with("The command")
            {
                return None;
            }
            // Each share line: "ShareName   Disk   ..."
            // Split by whitespace and check second token is "Disk"
            let mut parts = trimmed.split_whitespace();
            let name = parts.next()?;
            let kind = parts.next().unwrap_or("");
            if kind.eq_ignore_ascii_case("Disk") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Parses `net share` output and returns a list of non-administrative share names.
/// Skips header lines, separator lines, default administrative shares (ending in $), and status lines.
fn parse_net_share_output(raw: &str) -> Vec<String> {
    let mut shares = Vec::new();
    let mut past_header = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('-') {
            past_header = true;
            continue;
        }
        if trimmed.starts_with("The command") {
            break;
        }
        if !past_header {
            continue;
        }

        // First whitespace-separated column is the share name
        if let Some(name) = trimmed.split_whitespace().next() {
            // Ignore administrative shares like ADMIN$, C$, IPC$, D$, etc.
            if !name.ends_with('$') {
                shares.push(name.to_string());
            }
        }
    }
    shares
}

pub struct WindowsSystemAdapter;

impl WindowsSystemAdapter {
    pub fn new() -> Self {
        Self
    }

    fn hidden_command(program: &str) -> Command {
        let mut cmd = Command::new(program);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.stdin(std::process::Stdio::null());
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

        // Ensure EnableLinkedConnections = 1 is set in Registry
        // (Allows Windows Explorer running under non-elevated user token to see drives mapped by elevated t3Bridge)
        let _ = Self::hidden_command("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "/v",
                "EnableLinkedConnections",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        // 2. Enable Insecure Guest Auth for SMB client (critical for Windows 10/11 WAN connections)
        let _ = Self::hidden_command("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "/v",
                "EnableInsecureGuestAuth",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        let _ = Self::hidden_command("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "/v",
                "AllowInsecureGuestAuth",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        // 3. Clear any existing mapping or stale connection on this drive letter
        let _ = Self::hidden_command("net")
            .args(["use", &drive_spec, "/delete", "/y"])
            .output();

        // 4. Run: net use Z: \\host\Share /persistent:no /y with a 18s timeout for WAN connections
        let run_cmd = |args: Vec<String>| async move {
            let mut cmd = tokio::process::Command::new("net");
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
            cmd.stdin(std::process::Stdio::null());
            cmd.args(args);
            tokio::time::timeout(tokio::time::Duration::from_secs(18), cmd.output()).await
        };

        let output = run_cmd(vec![
            "use".into(),
            drive_spec.clone(),
            unc_path.to_string(),
            "/persistent:no".into(),
            "/y".into(),
        ]).await;

        let success = match &output {
            Ok(Ok(out)) => out.status.success(),
            _ => false,
        };

        if !success {
            // 5. Fallback with anonymous / Guest credentials if direct mount failed
            let fallback_output = run_cmd(vec![
                "use".into(),
                drive_spec.clone(),
                unc_path.to_string(),
                r#""""#.into(),
                "/user:Guest".into(),
                "/persistent:no".into(),
                "/y".into(),
            ]).await;

            if let Ok(Ok(fb)) = fallback_output {
                if fb.status.success() {
                    return Ok(());
                }
            }

            let err_msg = if let Ok(Ok(out)) = output {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                format!("{} {}", stdout.trim(), stderr.trim())
            } else {
                "Connection timed out. Server or SMB port unreachable.".to_string()
            };

            return Err(DomainError::NetworkFailure(format!(
                "Failed to mount {}: {}",
                drive_spec, err_msg
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
        // Enable File and Printer Sharing firewall rule group
        let _ = Self::hidden_command("netsh")
            .args(["advfirewall", "firewall", "set", "rule", "group=File and Printer Sharing", "new", "enable=Yes"])
            .output();

        // Remove old rules first to prevent duplicate entries
        let _ = Self::hidden_command("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=t3Bridge-SMB"])
            .output();
        let _ = Self::hidden_command("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=t3Bridge-NetBIOS"])
            .output();

        // Add TCP 445 (SMB) rule for all profiles (Domain, Private, Public)
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
                "profile=any",
                &format!("remoteip={}", subnet_cidr),
            ])
            .output();

        // Add TCP 139 (NetBIOS Session) rule for all profiles
        let _ = Self::hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=t3Bridge-NetBIOS",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                "localport=139",
                "profile=any",
                &format!("remoteip={}", subnet_cidr),
            ])
            .output();

        // Add ICMP rule for ping across virtual subnet
        let _ = Self::hidden_command("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=t3Bridge-ICMP"])
            .output();
        let _ = Self::hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=t3Bridge-ICMP",
                "dir=in",
                "action=allow",
                "protocol=ICMPv4",
                "profile=any",
                &format!("remoteip={}", subnet_cidr),
            ])
            .output();

        Ok(())
    }

    async fn list_remote_shares(&self, host: &str) -> DomainResult<Vec<String>> {
        // Run: net view \\<host> and parse share names from output
        let unc_host = format!(r"\\{}", host);
        let output = Self::hidden_command("net")
            .args(["view", &unc_host])
            .output()
            .map_err(|e| DomainError::InvalidIpAddress(format!("Failed to run 'net view': {}", e)))?;

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        let shares = parse_net_view_output(&raw);
        Ok(shares)
    }

    async fn list_local_shares(&self) -> DomainResult<Vec<String>> {
        // Run: net share and parse local share names from output
        let output = Self::hidden_command("net")
            .args(["share"])
            .output()
            .map_err(|e| DomainError::InvalidIpAddress(format!("Failed to run 'net share': {}", e)))?;

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        let shares = parse_net_share_output(&raw);
        Ok(shares)
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

    #[test]
    fn test_parse_net_share_output() {
        let sample = r#"
Share name   Resource                        Remark

-------------------------------------------------------------------------------
ADMIN$       C:\Windows                      Remote Admin
C$           C:\                             Default share
IPC$                                         Remote IPC
python       F:\python
MargERP      C:\MargERP
The command completed successfully.
"#;
        let shares = parse_net_share_output(sample);
        assert_eq!(shares, vec!["python", "MargERP"]);
    }

    #[test]
    fn test_parse_net_view_output() {
        let sample = r#"
Shared resources at \\192.168.0.120

Share name  Type  Used as  Comment
-------------------------------------------------------------------------------
MargERP     Disk
python      Disk
The command completed successfully.
"#;
        let shares = parse_net_view_output(sample);
        assert_eq!(shares, vec!["MargERP", "python"]);
    }
}

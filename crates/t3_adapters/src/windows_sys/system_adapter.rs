use async_trait::async_trait;
use t3_application::ports::WindowsSystemPort;
use t3_domain::{DomainError, DomainResult};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const LANMAN_WORKSTATION_PARAMS_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
const LANMAN_SERVER_PARAMS_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

/// Registry DWORD tuning entry (`key_path`, `value_name`, `dword_value`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistryDwordEntry {
    pub key: &'static str,
    pub value_name: &'static str,
    pub data: u32,
}

/// Windows SMB Client (`LanmanWorkstation`) registry tuning for high-latency WAN & DBF/FoxPro ERPs.
///
/// - `DisableBandwidthThrottling = 1`: disables Windows SMB WAN throughput throttling.
/// - `DisableLargeMtu = 0`: enables SMB 2/3 Large MTU (up to 1 MB multi-credit reads/writes).
/// - Raised metadata cache capacities (`FileInfoCacheEntriesMax`, `DirectoryCacheEntriesMax`,
///   `FileNotFoundCacheEntriesMax`) & lifetimes reduce repetitive SMB round-trips when legacy
///   file-based ERPs (Marg/FoxPro/VB `.dbf`/`.cdx`) probe hundreds of files on startup.
/// - `MaxCmds = 2048`: raises concurrent in-flight SMB requests over WAN links.
pub(crate) fn smb_client_wan_tuning_entries() -> &'static [RegistryDwordEntry] {
    &[
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "EnableInsecureGuestAuth",
            data: 1,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "AllowInsecureGuestAuth",
            data: 1,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "DisableBandwidthThrottling",
            data: 1,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "DisableLargeMtu",
            data: 0,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "FileInfoCacheEntriesMax",
            data: 1024,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "DirectoryCacheEntriesMax",
            data: 128,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "FileNotFoundCacheEntriesMax",
            data: 512,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "FileInfoCacheLifetime",
            data: 10,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "DirectoryCacheLifetime",
            data: 10,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "FileNotFoundCacheLifetime",
            data: 10,
        },
        RegistryDwordEntry {
            key: LANMAN_WORKSTATION_PARAMS_KEY,
            value_name: "MaxCmds",
            data: 2048,
        },
    ]
}

/// Windows SMB Server (`LanmanServer`) registry tuning on Host PCs serving DBF/ERP shares over WAN.
///
/// - `SizReqBuf = 65536`: 64 KB server request buffer (default 16 KB).
/// - `IRPStackSize = 32`: prevents filter/antivirus stalls under heavy file-lock traffic.
/// - `AsynchronousCredits = 512`: allows higher concurrent async SMB2/3 requests.
/// - `DisableStrictNameChecking = 1`: allows clean SMB access via virtual tunnel IP (`10.99.0.1`).
pub(crate) fn smb_server_wan_tuning_entries() -> &'static [RegistryDwordEntry] {
    &[
        RegistryDwordEntry {
            key: LANMAN_SERVER_PARAMS_KEY,
            value_name: "SizReqBuf",
            data: 65536,
        },
        RegistryDwordEntry {
            key: LANMAN_SERVER_PARAMS_KEY,
            value_name: "IRPStackSize",
            data: 32,
        },
        RegistryDwordEntry {
            key: LANMAN_SERVER_PARAMS_KEY,
            value_name: "AsynchronousCredits",
            data: 512,
        },
        RegistryDwordEntry {
            key: LANMAN_SERVER_PARAMS_KEY,
            value_name: "DisableStrictNameChecking",
            data: 1,
        },
    ]
}

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

    fn apply_registry_dword_entries(entries: &[RegistryDwordEntry]) {
        for entry in entries {
            let data_str = entry.data.to_string();
            let _ = Self::hidden_command("reg")
                .args([
                    "add",
                    entry.key,
                    "/v",
                    entry.value_name,
                    "/t",
                    "REG_DWORD",
                    "/d",
                    &data_str,
                    "/f",
                ])
                .output();
        }
    }

    /// Applies Windows SMB Client (`LanmanWorkstation`) WAN & DBF/ERP caching/Large-MTU tuning.
    /// Safe and idempotent; requires Administrator / LocalSystem privileges for HKLM writes.
    pub fn apply_smb_client_wan_tuning() {
        Self::apply_registry_dword_entries(smb_client_wan_tuning_entries());
    }

    /// Applies Windows SMB Server (`LanmanServer`) WAN & DBF/ERP throughput tuning on Host PCs.
    pub fn apply_smb_server_wan_tuning() {
        Self::apply_registry_dword_entries(smb_server_wan_tuning_entries());
    }

    /// Adds Windows Defender Firewall inbound & outbound UDP allow rules for `t3bridge-service.exe`
    /// and `t3bridge_ui.exe` (with `edgetraversal=yes`) so Direct WireGuard UDP P2P packets are never silently blocked.
    pub fn allow_p2p_udp_firewall_rules() {
        let Ok(current_exe) = std::env::current_exe() else {
            return;
        };
        let exe_paths = collect_firewall_udp_program_paths(&current_exe);
        for (idx, exe_path) in exe_paths.iter().enumerate() {
            let rule_in = format!("t3Bridge-P2P-UDP-In-{}", idx);
            let rule_out = format!("t3Bridge-P2P-UDP-Out-{}", idx);
            let prog_arg = format!("program={}", exe_path.display());

            let _ = Self::hidden_command("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_in)])
                .output();
            let _ = Self::hidden_command("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_in),
                    "dir=in",
                    "action=allow",
                    "protocol=UDP",
                    &prog_arg,
                    "profile=any",
                    "edgetraversal=yes",
                ])
                .output();

            let _ = Self::hidden_command("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_out)])
                .output();
            let _ = Self::hidden_command("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_out),
                    "dir=out",
                    "action=allow",
                    "protocol=UDP",
                    &prog_arg,
                    "profile=any",
                ])
                .output();
        }
    }

    /// Explicitly opens the bound P2P UDP ports in Windows Defender Firewall with Edge Traversal enabled.
    pub fn allow_p2p_udp_port_firewall_rules(ports: &[u16]) {
        let valid_ports: Vec<String> = ports
            .iter()
            .copied()
            .filter(|p| *p > 0)
            .map(|p| p.to_string())
            .collect();
        if valid_ports.is_empty() {
            return;
        }
        let ports_csv = valid_ports.join(",");
        let port_arg = format!("localport={}", ports_csv);

        let _ = Self::hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=t3Bridge-P2P-UDP-Ports",
            ])
            .output();
        let _ = Self::hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=t3Bridge-P2P-UDP-Ports",
                "dir=in",
                "action=allow",
                "protocol=UDP",
                &port_arg,
                "profile=any",
                "edgetraversal=yes",
            ])
            .output();
    }
}

/// Collects deduplicated executable paths (current binary + sibling t3Bridge binaries that exist)
/// for Windows Firewall UDP allow rules.
pub(crate) fn collect_firewall_udp_program_paths(current_exe: &Path) -> Vec<PathBuf> {
    let mut paths = vec![current_exe.to_path_buf()];
    if let Some(dir) = current_exe.parent() {
        for sibling_name in ["t3bridge-service.exe", "t3bridge_ui.exe", "t3Bridge.exe"] {
            let candidate = dir.join(sibling_name);
            if candidate.exists() && !paths.iter().any(|p| p == &candidate) {
                paths.push(candidate);
            }
        }
    }
    paths
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

        // 2. Apply SMB Client WAN & DBF/ERP Performance Registry Tuning
        //    (Guest Auth, DisableBandwidthThrottling=1, DisableLargeMtu=0, metadata cache sizes & lifetimes, MaxCmds)
        Self::apply_smb_client_wan_tuning();

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
            tokio::time::timeout(tokio::time::Duration::from_secs(75), cmd.output()).await
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
            // Only retry with Guest credentials if the first attempt returned an error
            // (not when it timed out — a second long wait would just double the delay).
            if matches!(output, Ok(Ok(_))) {
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
            }

            let err_msg = if let Ok(Ok(out)) = output {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                format!("{} {}", stdout.trim(), stderr.trim())
            } else {
                "Connection timed out waiting for the SMB handshake over the relay.".to_string()
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
        // Apply SMB Server WAN & DBF throughput registry tuning on Host PCs
        Self::apply_smb_server_wan_tuning();
        // Allow inbound & outbound Direct UDP P2P traffic for t3Bridge executables
        Self::allow_p2p_udp_firewall_rules();

        // Ensure Windows SMB Server (LanmanServer) service is set to Auto and running
        let _ = Self::hidden_command("sc")
            .args(["config", "LanmanServer", "start=", "auto"])
            .output();
        let _ = Self::hidden_command("net")
            .args(["start", "LanmanServer"])
            .output();

        // Enable File and Printer Sharing firewall rule group (both netsh & PowerShell rule IDs)
        let _ = Self::hidden_command("netsh")
            .args(["advfirewall", "firewall", "set", "rule", "group=File and Printer Sharing", "new", "enable=Yes"])
            .output();
        let _ = Self::hidden_command("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Enable-NetFirewallRule -Name 'FPS-SMB-In-TCP','FPS-NB_Session-In-TCP','FPS-ICMP4-ERQ-In' -ErrorAction SilentlyContinue; Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue",
            ])
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

    #[test]
    fn test_smb_client_wan_tuning_entries_cover_dbf_and_large_mtu() {
        let entries = smb_client_wan_tuning_entries();
        let find = |name: &str| entries.iter().find(|e| e.value_name == name).map(|e| e.data);

        assert_eq!(find("DisableBandwidthThrottling"), Some(1));
        assert_eq!(find("DisableLargeMtu"), Some(0));
        assert_eq!(find("FileInfoCacheEntriesMax"), Some(1024));
        assert_eq!(find("DirectoryCacheEntriesMax"), Some(128));
        assert_eq!(find("FileNotFoundCacheEntriesMax"), Some(512));
        assert_eq!(find("MaxCmds"), Some(2048));
        assert!(entries
            .iter()
            .all(|e| e.key == LANMAN_WORKSTATION_PARAMS_KEY));
    }

    #[test]
    fn test_smb_server_wan_tuning_entries_cover_host_throughput() {
        let entries = smb_server_wan_tuning_entries();
        let find = |name: &str| entries.iter().find(|e| e.value_name == name).map(|e| e.data);

        assert_eq!(find("SizReqBuf"), Some(65536));
        assert_eq!(find("IRPStackSize"), Some(32));
        assert_eq!(find("AsynchronousCredits"), Some(512));
        assert_eq!(find("DisableStrictNameChecking"), Some(1));
        assert!(entries.iter().all(|e| e.key == LANMAN_SERVER_PARAMS_KEY));
    }

    #[test]
    fn test_collect_firewall_udp_program_paths_includes_current_exe() {
        let cur = std::env::current_exe().unwrap();
        let paths = collect_firewall_udp_program_paths(&cur);
        assert!(!paths.is_empty());
        assert_eq!(paths[0], cur);
    }
}

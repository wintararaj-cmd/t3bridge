use crate::ports::{TunnelPort, WindowsSystemPort};
use t3_domain::{
    AppProfile, ConnectionMachine, DomainError, DomainResult, Peer,
};
use std::sync::Arc;

pub struct ConnectToHostUseCase {
    tunnel: Arc<dyn TunnelPort>,
    system: Arc<dyn WindowsSystemPort>,
}

#[derive(Debug, Clone)]
pub struct ConnectSessionResult {
    pub session_unc_path: String,
    pub drive_letter: char,
    pub peer_id: String,
}

impl ConnectToHostUseCase {
    pub fn new(tunnel: Arc<dyn TunnelPort>, system: Arc<dyn WindowsSystemPort>) -> Self {
        Self { tunnel, system }
    }

    pub async fn execute(
        &self,
        target_peer: &Peer,
        app_profile: &AppProfile,
        requested_drive_letter: char,
        license_id: &str,
    ) -> DomainResult<ConnectSessionResult> {
        let drive_letter = requested_drive_letter.to_ascii_uppercase();

        // 1. Check if the chosen drive letter is already occupied on the Windows PC
        if self.system.is_drive_in_use(drive_letter).await? {
            return Err(DomainError::DriveLetterInUse(drive_letter));
        }

        // 2. Initialize connection machine with compile-time type-safety
        let machine = ConnectionMachine::new().mark_licensed(license_id.to_string());

        // 3. Start Wintun adapter and peer-to-peer tunnel
        //    WAN mode: peer_id == "10.99.0.1" means adapter was already started in commands.rs
        //              with client IP 10.99.0.2 before calling this use case. Skip start_adapter.
        //    LAN mode: start adapter with the peer's IP (direct LAN connection).
        let remote_endpoint = target_peer
            .public_endpoint
            .as_deref()
            .unwrap_or("0.0.0.0:0");

        let is_wan_relay = target_peer.name == "WAN Relay Server";
        if !is_wan_relay {
            self.tunnel
                .start_adapter(target_peer.virtual_ip.clone())
                .await?;
        }

        if let Err(e) = self.tunnel.connect_peer(target_peer, remote_endpoint).await {
            // Rollback adapter if connection fails (only if we started it)
            if !is_wan_relay {
                let _ = self.tunnel.disconnect().await;
            }
            return Err(e);
        }

        // 4. Transition machine to TunnelActive
        let active_machine = machine.mark_tunnel_active(
            target_peer.virtual_ip.clone(),
            remote_endpoint.to_string(),
        );

        // 5. Build the UNC path.
        //    - Case A: Direct LAN IP typed by user (e.g. 192.168.1.100) → peer_id IS the IP
        //    - Case B: LAN hostname resolved (e.g. SERVER-PC) → peer_id IS the hostname, name="LAN Host"
        //    - Case C: Cloud Signaling connect code (e.g. OFFICE-HQ-01) → peer_id is connect code,
        //              name ends with "-Node" (set by signaling registry), virtual_ip is the real
        //              WAN IP assigned by signaling server for hole-punch/UNC routing
        let smb_host = if target_peer.peer_id.parse::<std::net::Ipv4Addr>().is_ok() {
            // Case A: Direct LAN IP → use directly
            target_peer.peer_id.clone()
        } else if target_peer.name == "LAN Host" || target_peer.name == "LAN Server" {
            // Case B: LAN hostname → use directly for Windows name resolution
            target_peer.peer_id.clone()
        } else {
            // Case C: Cloud Signaling peer → use virtual_ip (assigned by cloud signaling server)
            target_peer.virtual_ip.addr().to_string()
        };

        let share_name = app_profile.default_share_name.trim_matches('\\').trim_matches('/');
        let unc_path = format!(r"\\{}\{}", smb_host, share_name);

        // 6. Mount the network drive to Windows OS (e.g. Z: -> \\192.168.1.100\SharedData)
        //    WAN relay: wait a moment for the tunnel to be ready before mounting SMB
        if is_wan_relay {
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
        }
        if let Err(e) = self.system.mount_drive(drive_letter, &unc_path).await {
            // Rollback tunnel if drive mounting fails
            if !is_wan_relay {
                let _ = self.tunnel.disconnect().await;
            }
            return Err(e);
        }

        // 7. Transition machine to DriveMounted state
        let _ = active_machine.mark_drive_mounted(drive_letter)?;

        Ok(ConnectSessionResult {
            session_unc_path: unc_path,
            drive_letter,
            peer_id: target_peer.peer_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{MockTunnelPort, MockWindowsSystemPort};
    use t3_domain::{PeerRole, VirtualIp};

    fn dummy_peer() -> Peer {
        Peer::new(
            "node_office_server".into(),
            "Main Office Server".into(),
            PeerRole::HostServer,
            VirtualIp::new("10.99.0.1", 24).unwrap(),
        )
    }

    #[tokio::test]
    async fn test_connect_to_host_happy_path() {
        let mut mock_tunnel = MockTunnelPort::new();
        mock_tunnel.expect_start_adapter().times(1).returning(|_| Ok(()));
        mock_tunnel
            .expect_connect_peer()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut mock_system = MockWindowsSystemPort::new();
        mock_system
            .expect_is_drive_in_use()
            .with(mockall::predicate::eq('Z'))
            .times(1)
            .returning(|_| Ok(false));

        mock_system
            .expect_mount_drive()
            .with(
                mockall::predicate::eq('Z'),
                // Cloud peer (name="Main Office Server", not "LAN Host") → uses virtual_ip
                mockall::predicate::eq(r"\\10.99.0.1\SharedData"),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let usecase = ConnectToHostUseCase::new(Arc::new(mock_tunnel), Arc::new(mock_system));

        let peer = dummy_peer();
        let app = AppProfile::primary_erp();
        let res = usecase.execute(&peer, &app, 'Z', "LIC-123").await;

        assert!(res.is_ok());
        let session = res.unwrap();
        assert_eq!(session.drive_letter, 'Z');
        assert_eq!(session.session_unc_path, r"\\10.99.0.1\SharedData");
    }

    #[tokio::test]
    async fn test_connect_lan_ip_uses_peer_id_as_host() {
        let mut mock_tunnel = MockTunnelPort::new();
        mock_tunnel.expect_start_adapter().times(1).returning(|_| Ok(()));
        mock_tunnel.expect_connect_peer().times(1).returning(|_, _| Ok(()));

        let mut mock_system = MockWindowsSystemPort::new();
        mock_system.expect_is_drive_in_use().times(1).returning(|_| Ok(false));
        mock_system
            .expect_mount_drive()
            .with(
                mockall::predicate::eq('Z'),
                // LAN IP peer → peer_id (the IP) is used directly, NOT virtual_ip
                mockall::predicate::eq(r"\\192.168.1.50\SharedData"),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let usecase = ConnectToHostUseCase::new(Arc::new(mock_tunnel), Arc::new(mock_system));

        // peer_id is a valid IPv4 → Case A
        let lan_peer = Peer::new(
            "192.168.1.50".into(),
            "LAN Server".into(),
            PeerRole::HostServer,
            VirtualIp::new("10.99.0.1", 24).unwrap(),
        );
        let app = AppProfile::primary_erp();
        let res = usecase.execute(&lan_peer, &app, 'Z', "LIC-123").await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap().session_unc_path, r"\\192.168.1.50\SharedData");
    }

    #[tokio::test]
    async fn test_connect_lan_hostname_uses_peer_id_as_host() {
        let mut mock_tunnel = MockTunnelPort::new();
        mock_tunnel.expect_start_adapter().times(1).returning(|_| Ok(()));
        mock_tunnel.expect_connect_peer().times(1).returning(|_, _| Ok(()));

        let mut mock_system = MockWindowsSystemPort::new();
        mock_system.expect_is_drive_in_use().times(1).returning(|_| Ok(false));
        mock_system
            .expect_mount_drive()
            .with(
                mockall::predicate::eq('Z'),
                // LAN hostname peer → peer_id (hostname) used directly
                mockall::predicate::eq(r"\\SERVER-PC\SharedData"),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let usecase = ConnectToHostUseCase::new(Arc::new(mock_tunnel), Arc::new(mock_system));

        // name="LAN Host" → Case B
        let lan_peer = Peer::new(
            "SERVER-PC".into(),
            "LAN Host".into(),
            PeerRole::HostServer,
            VirtualIp::new("192.168.1.50", 24).unwrap(),
        );
        let app = AppProfile::primary_erp();
        let res = usecase.execute(&lan_peer, &app, 'Z', "LIC-123").await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap().session_unc_path, r"\\SERVER-PC\SharedData");
    }

    #[tokio::test]
    async fn test_connect_fails_if_drive_already_in_use() {
        let mock_tunnel = MockTunnelPort::new();
        let mut mock_system = MockWindowsSystemPort::new();

        mock_system
            .expect_is_drive_in_use()
            .with(mockall::predicate::eq('Z'))
            .times(1)
            .returning(|_| Ok(true)); // Drive Z is occupied!

        let usecase = ConnectToHostUseCase::new(Arc::new(mock_tunnel), Arc::new(mock_system));

        let peer = dummy_peer();
        let app = AppProfile::marg_erp();
        let res = usecase.execute(&peer, &app, 'Z', "LIC-123").await;

        assert!(matches!(res, Err(DomainError::DriveLetterInUse('Z'))));
    }

    #[tokio::test]
    async fn test_rollback_tunnel_if_drive_mount_fails() {
        let mut mock_tunnel = MockTunnelPort::new();
        mock_tunnel.expect_start_adapter().times(1).returning(|_| Ok(()));
        mock_tunnel
            .expect_connect_peer()
            .times(1)
            .returning(|_, _| Ok(()));
        mock_tunnel
            .expect_disconnect()
            .times(1) // Verifies rollback was triggered!
            .returning(|| Ok(()));

        let mut mock_system = MockWindowsSystemPort::new();
        mock_system
            .expect_is_drive_in_use()
            .times(1)
            .returning(|_| Ok(false));

        mock_system
            .expect_mount_drive()
            .times(1)
            .returning(|_, _| Err(DomainError::InvalidIpAddress("SMB Timeout".into())));

        let usecase = ConnectToHostUseCase::new(Arc::new(mock_tunnel), Arc::new(mock_system));

        let peer = dummy_peer();
        let app = AppProfile::marg_erp();
        let res = usecase.execute(&peer, &app, 'Z', "LIC-123").await;

        assert!(res.is_err());
    }
}

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
        let remote_endpoint = target_peer
            .public_endpoint
            .as_deref()
            .unwrap_or("0.0.0.0:0");

        self.tunnel
            .start_adapter(target_peer.virtual_ip.clone())
            .await?;

        if let Err(e) = self.tunnel.connect_peer(target_peer, remote_endpoint).await {
            // Rollback adapter if connection fails
            let _ = self.tunnel.disconnect().await;
            return Err(e);
        }

        // 4. Transition machine to TunnelActive
        let active_machine = machine.mark_tunnel_active(
            target_peer.virtual_ip.clone(),
            remote_endpoint.to_string(),
        );

        let unc_path = active_machine.smb_unc_path(&app_profile.default_share_name);

        // 5. Mount the network drive to Windows OS (e.g. Z: -> \\10.99.0.1\MargERP)
        if let Err(e) = self.system.mount_drive(drive_letter, &unc_path).await {
            // Rollback tunnel if drive mounting fails
            let _ = self.tunnel.disconnect().await;
            return Err(e);
        }

        // 6. Transition machine to DriveMounted state
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
                mockall::predicate::eq(r"\\10.99.0.1\MargERP"),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let usecase = ConnectToHostUseCase::new(Arc::new(mock_tunnel), Arc::new(mock_system));

        let peer = dummy_peer();
        let app = AppProfile::marg_erp();
        let res = usecase.execute(&peer, &app, 'Z', "LIC-123").await;

        assert!(res.is_ok());
        let session = res.unwrap();
        assert_eq!(session.drive_letter, 'Z');
        assert_eq!(session.session_unc_path, r"\\10.99.0.1\MargERP");
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

use crate::ports::{TunnelPort, WindowsSystemPort};
use t3_domain::DomainResult;
use std::sync::Arc;

pub struct DisconnectSessionUseCase {
    tunnel: Arc<dyn TunnelPort>,
    system: Arc<dyn WindowsSystemPort>,
}

impl DisconnectSessionUseCase {
    pub fn new(tunnel: Arc<dyn TunnelPort>, system: Arc<dyn WindowsSystemPort>) -> Self {
        Self { tunnel, system }
    }

    pub async fn execute(&self, active_drive_letter: Option<char>) -> DomainResult<()> {
        // 1. Unmount network drive if one was mounted
        if let Some(letter) = active_drive_letter {
            let _ = self.system.unmount_drive(letter).await;
        }

        // 2. Tear down the encrypted P2P tunnel & Wintun adapter
        self.tunnel.disconnect().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{MockTunnelPort, MockWindowsSystemPort};

    #[tokio::test]
    async fn test_clean_disconnect() {
        let mut mock_tunnel = MockTunnelPort::new();
        mock_tunnel
            .expect_disconnect()
            .times(1)
            .returning(|| Ok(()));

        let mut mock_system = MockWindowsSystemPort::new();
        mock_system
            .expect_unmount_drive()
            .with(mockall::predicate::eq('Z'))
            .times(1)
            .returning(|_| Ok(()));

        let usecase = DisconnectSessionUseCase::new(Arc::new(mock_tunnel), Arc::new(mock_system));
        let res = usecase.execute(Some('Z')).await;

        assert!(res.is_ok());
    }
}

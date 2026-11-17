use std::sync::Arc;
use t3_domain::{ConnectionHealth, DomainResult, TunnelMetrics};
use crate::ports::TunnelPort;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogReport {
    pub health: ConnectionHealth,
    pub metrics: TunnelMetrics,
    pub is_safe: bool,
    pub recommendation: Option<String>,
}

pub struct NetworkWatchdogUseCase {
    tunnel: Arc<dyn TunnelPort>,
}

impl NetworkWatchdogUseCase {
    pub fn new(tunnel: Arc<dyn TunnelPort>) -> Self {
        Self { tunnel }
    }

    pub async fn check_health(&self) -> DomainResult<WatchdogReport> {
        let metrics = self.tunnel.get_metrics().await?;
        let health = ConnectionHealth::evaluate(&metrics);
        let is_safe = health.is_safe_for_file_erp();

        let recommendation = match health {
            ConnectionHealth::Optimal => None,
            ConnectionHealth::Acceptable => Some("Network is stable. Normal ERP operations.".into()),
            ConnectionHealth::Degraded => Some(
                "Warning: Elevated latency detected (>120ms). Save vouchers before continuing.".into(),
            ),
            ConnectionHealth::Unstable => Some(
                "CRITICAL: High packet loss or latency (>250ms)! High risk of Marg/Tally database index corruption. Pause entries.".into(),
            ),
            ConnectionHealth::Dead => Some("Connection lost. Session paused.".into()),
        };

        Ok(WatchdogReport {
            health,
            metrics,
            is_safe,
            recommendation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::MockTunnelPort;

    #[tokio::test]
    async fn test_watchdog_detects_optimal_conditions() {
        let mut mock_tunnel = MockTunnelPort::new();
        mock_tunnel.expect_get_metrics().times(1).returning(|| {
            Ok(TunnelMetrics {
                latency_ms: 22,
                bytes_sent: 5000,
                bytes_received: 12000,
                packet_loss_percent: 0,
            })
        });

        let watchdog = NetworkWatchdogUseCase::new(Arc::new(mock_tunnel));
        let report = watchdog.check_health().await.unwrap();

        assert_eq!(report.health, ConnectionHealth::Optimal);
        assert!(report.is_safe);
        assert_eq!(report.recommendation, None);
    }

    #[tokio::test]
    async fn test_watchdog_warns_on_unstable_network() {
        let mut mock_tunnel = MockTunnelPort::new();
        mock_tunnel.expect_get_metrics().times(1).returning(|| {
            Ok(TunnelMetrics {
                latency_ms: 320,
                bytes_sent: 1000,
                bytes_received: 2000,
                packet_loss_percent: 12,
            })
        });

        let watchdog = NetworkWatchdogUseCase::new(Arc::new(mock_tunnel));
        let report = watchdog.check_health().await.unwrap();

        assert_eq!(report.health, ConnectionHealth::Unstable);
        assert!(!report.is_safe);
        assert!(report.recommendation.is_some());
        assert!(report.recommendation.unwrap().contains("CRITICAL"));
    }
}

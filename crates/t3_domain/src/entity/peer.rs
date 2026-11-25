use crate::value_objects::VirtualIp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerRole {
    HostServer, // Office PC hosting Marg ERP
    ClientNode, // Branch / Home laptop accessing Marg
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TransportMode {
    #[default]
    Disconnected,
    LanDirect,
    DirectUdpP2p,
    WsBinaryRelay,
    WsLegacyRelay,
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportMode::Disconnected => write!(f, "Disconnected"),
            TransportMode::LanDirect => write!(f, "LAN Direct"),
            TransportMode::DirectUdpP2p => write!(f, "Direct P2P (WireGuard UDP)"),
            TransportMode::WsBinaryRelay => write!(f, "Cloud Relay (Encrypted Binary WS)"),
            TransportMode::WsLegacyRelay => write!(f, "Cloud Relay (Legacy WS)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub latency_ms: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_loss_percent: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionHealth {
    Optimal,     // < 50ms, 0% loss
    Acceptable,  // 50ms - 120ms, <= 2% loss
    Degraded,    // 120ms - 250ms, or packet loss 2% - 10%
    Unstable,    // > 250ms or > 10% loss - high risk for DBF/CDX index corruption
    Dead,        // Complete disconnection
}

impl ConnectionHealth {
    pub fn evaluate(metrics: &TunnelMetrics) -> Self {
        if metrics.packet_loss_percent > 10 || metrics.latency_ms > 250 {
            ConnectionHealth::Unstable
        } else if metrics.packet_loss_percent > 2 || metrics.latency_ms > 120 {
            ConnectionHealth::Degraded
        } else if metrics.latency_ms > 50 {
            ConnectionHealth::Acceptable
        } else {
            ConnectionHealth::Optimal
        }
    }

    pub fn is_safe_for_file_erp(&self) -> bool {
        matches!(self, ConnectionHealth::Optimal | ConnectionHealth::Acceptable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: String,
    pub name: String,
    pub role: PeerRole,
    pub virtual_ip: VirtualIp,
    pub public_endpoint: Option<String>,
    pub is_online: bool,
}

impl Peer {
    pub fn new(peer_id: String, name: String, role: PeerRole, virtual_ip: VirtualIp) -> Self {
        Self {
            peer_id,
            name,
            role,
            virtual_ip,
            public_endpoint: None,
            is_online: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_health_evaluation() {
        let optimal = TunnelMetrics {
            latency_ms: 25,
            bytes_sent: 100,
            bytes_received: 200,
            packet_loss_percent: 0,
        };
        assert_eq!(ConnectionHealth::evaluate(&optimal), ConnectionHealth::Optimal);
        assert!(ConnectionHealth::evaluate(&optimal).is_safe_for_file_erp());

        let degraded = TunnelMetrics {
            latency_ms: 150,
            bytes_sent: 100,
            bytes_received: 200,
            packet_loss_percent: 1,
        };
        assert_eq!(ConnectionHealth::evaluate(&degraded), ConnectionHealth::Degraded);
        assert!(!ConnectionHealth::evaluate(&degraded).is_safe_for_file_erp());

        let unstable = TunnelMetrics {
            latency_ms: 300,
            bytes_sent: 100,
            bytes_received: 200,
            packet_loss_percent: 15,
        };
        assert_eq!(ConnectionHealth::evaluate(&unstable), ConnectionHealth::Unstable);
        assert!(!ConnectionHealth::evaluate(&unstable).is_safe_for_file_erp());
    }
}

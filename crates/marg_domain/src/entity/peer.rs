use crate::value_objects::VirtualIp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerRole {
    HostServer, // Office PC hosting Marg ERP
    ClientNode, // Branch / Home laptop accessing Marg
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub latency_ms: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_loss_percent: u8,
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

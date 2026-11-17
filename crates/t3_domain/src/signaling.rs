use crate::entity::{Peer, PeerRole};
use crate::value_objects::VirtualIp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolePunchPayload {
    pub peer_id: String,
    pub public_endpoint: String,
    pub wireguard_pubkey: String,
    pub local_candidate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum SignalingMessage {
    // 1. Node Registration & Authentication
    RegisterNode {
        peer_id: String,
        role: PeerRole,
        hardware_id: String,
        license_key: String,
    },
    NodeRegistered {
        assigned_virtual_ip: VirtualIp,
        session_token: String,
    },

    // 2. Peer Discovery
    FindHost {
        connect_code: String,
    },
    HostFound {
        host_peer: Peer,
    },

    // 3. UDP Hole-Punch Handshake
    HolePunchOffer {
        target_peer_id: String,
        offer: HolePunchPayload,
    },
    HolePunchAnswer {
        target_peer_id: String,
        answer: HolePunchPayload,
    },

    // 4. Connection Keepalive
    Ping {
        peer_id: String,
    },
    Pong {
        timestamp: i64,
    },

    // 5. Error Reporting
    Error {
        code: String,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signaling_serialization_roundtrip() {
        let msg = SignalingMessage::HolePunchOffer {
            target_peer_id: "host_main_office".into(),
            offer: HolePunchPayload {
                peer_id: "client_branch_1".into(),
                public_endpoint: "103.21.244.2:51820".into(),
                wireguard_pubkey: "dGhpcyBpcyBhIHdpcmVndWFyZCBwdWJrZXk=".into(),
                local_candidate: Some("192.168.1.50:51820".into()),
            },
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: SignalingMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, decoded);
    }
}

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

    // 4. WAN Relay — SMB-over-WebSocket (TURN-style)
    /// Client requests a relay session through the signaling server to a registered host
    RelayRequest {
        target_peer_id: String,
        session_id: String,
    },
    /// Server signals it has accepted and is ready to relay
    RelayAccepted {
        session_id: String,
    },
    /// Binary SMB data chunk tunnelled through the signaling server relay
    RelayData {
        session_id: String,
        #[serde(with = "base64_bytes")]
        chunk: Vec<u8>,
    },
    /// Either side signals relay session teardown
    RelayClose {
        session_id: String,
    },

    // 5. Connection Keepalive
    Ping {
        peer_id: String,
    },
    Pong {
        timestamp: i64,
    },

    // 6. Error Reporting
    Error {
        code: String,
        message: String,
    },
}

/// Base64 serde helper for binary relay chunks (JSON transport)
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::{Engine, engine::general_purpose::STANDARD};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
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

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

/// Binary WebSocket Relay frame magic byte ('T' for t3Bridge)
pub const BINARY_RELAY_MAGIC: u8 = 0x54;

/// Encodes a zero-JSON, zero-Base64 binary relay frame:
/// `[1B magic=0x54][1B session_id_len][session_id UTF-8 bytes][raw encrypted payload]`
pub fn encode_binary_relay_frame(session_id: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let sid_bytes = session_id.as_bytes();
    if sid_bytes.is_empty() || sid_bytes.len() > 255 {
        return None;
    }
    let mut frame = Vec::with_capacity(2 + sid_bytes.len() + payload.len());
    frame.push(BINARY_RELAY_MAGIC);
    frame.push(sid_bytes.len() as u8);
    frame.extend_from_slice(sid_bytes);
    frame.extend_from_slice(payload);
    Some(frame)
}

/// Decodes a binary relay frame into `(session_id, raw_payload_slice)` without allocating.
pub fn decode_binary_relay_frame(frame: &[u8]) -> Option<(&str, &[u8])> {
    if frame.len() < 3 || frame[0] != BINARY_RELAY_MAGIC {
        return None;
    }
    let sid_len = frame[1] as usize;
    if sid_len == 0 || frame.len() < 2 + sid_len {
        return None;
    }
    let session_id = std::str::from_utf8(&frame[2..2 + sid_len]).ok()?;
    let payload = &frame[2 + sid_len..];
    Some((session_id, payload))
}

/// Parsed fields from client's `HolePunchOffer.wireguard_pubkey` field (backward-compatible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientOffer {
    pub password: String,
    pub wg_pubkey: Option<String>,
    pub virtual_ip: Option<String>,
}

/// Formats client offer metadata cleanly while remaining backward-compatible with legacy hosts.
pub fn format_client_offer_meta(password: &str, wg_pubkey: &str, client_vip: &str) -> String {
    format!("AUTH:{}::WG:{}::VIP:{}::QUERY_SHARES", password, wg_pubkey, client_vip)
}

/// Parses client offer metadata from `HolePunchPayload.wireguard_pubkey`.
pub fn parse_client_offer_meta(raw: &str) -> ParsedClientOffer {
    let mut password = String::new();
    let mut wg_pubkey = None;
    let mut virtual_ip = None;

    for part in raw.split("::") {
        if let Some(v) = part.strip_prefix("AUTH:") {
            password = v.to_string();
        } else if let Some(v) = part.strip_prefix("WG:") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                wg_pubkey = Some(trimmed.to_string());
            }
        } else if let Some(v) = part.strip_prefix("VIP:") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                virtual_ip = Some(trimmed.to_string());
            }
        }
    }

    ParsedClientOffer {
        password,
        wg_pubkey,
        virtual_ip,
    }
}

/// Parsed fields from host's `HolePunchAnswer.wireguard_pubkey` field (backward-compatible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHostAnswer {
    pub token: Option<String>,
    pub wg_pubkey: Option<String>,
    pub shares: Vec<String>,
    pub auth_error: Option<String>,
}

/// Formats host answer metadata cleanly while remaining backward-compatible.
pub fn format_host_answer_meta(token: &str, wg_pubkey: &str, shares_csv: &str) -> String {
    format!("TOKEN:{}::WG:{}::SHARES:{}", token, wg_pubkey, shares_csv)
}

/// Parses host answer metadata from `HolePunchPayload.wireguard_pubkey`.
pub fn parse_host_answer_meta(raw: &str) -> ParsedHostAnswer {
    if let Some(err) = raw.strip_prefix("AUTH_FAILED:") {
        return ParsedHostAnswer {
            token: None,
            wg_pubkey: None,
            shares: Vec::new(),
            auth_error: Some(err.to_string()),
        };
    }

    let mut token = None;
    let mut wg_pubkey = None;
    let mut shares = Vec::new();

    for part in raw.split("::") {
        if let Some(v) = part.strip_prefix("TOKEN:") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                token = Some(trimmed.to_string());
            }
        } else if let Some(v) = part.strip_prefix("WG:") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                wg_pubkey = Some(trimmed.to_string());
            }
        } else if let Some(v) = part.strip_prefix("SHARES:") {
            shares = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }

    ParsedHostAnswer {
        token,
        wg_pubkey,
        shares,
        auth_error: None,
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

    #[test]
    fn test_binary_relay_frame_roundtrip() {
        let sid = "sess_tok_0123456789abcdef";
        let payload = vec![0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let encoded = encode_binary_relay_frame(sid, &payload).unwrap();
        let (decoded_sid, decoded_payload) = decode_binary_relay_frame(&encoded).unwrap();
        assert_eq!(decoded_sid, sid);
        assert_eq!(decoded_payload, payload.as_slice());
        assert!(decode_binary_relay_frame(&[0x00, 0x01, 0x41]).is_none());
    }

    #[test]
    fn test_hole_punch_metadata_roundtrip_and_compat() {
        let client_meta = format_client_offer_meta("secret123", "WG_CLIENT_PUB==", "10.99.0.2");
        let parsed_client = parse_client_offer_meta(&client_meta);
        assert_eq!(parsed_client.password, "secret123");
        assert_eq!(parsed_client.wg_pubkey.as_deref(), Some("WG_CLIENT_PUB=="));
        assert_eq!(parsed_client.virtual_ip.as_deref(), Some("10.99.0.2"));

        // Legacy client format without WG/VIP still parses password
        let legacy_client = parse_client_offer_meta("AUTH:mypass::QUERY_SHARES");
        assert_eq!(legacy_client.password, "mypass");
        assert_eq!(legacy_client.wg_pubkey, None);

        let host_meta = format_host_answer_meta("tok123", "WG_HOST_PUB==", "MargData,BusyData");
        let parsed_host = parse_host_answer_meta(&host_meta);
        assert_eq!(parsed_host.token.as_deref(), Some("tok123"));
        assert_eq!(parsed_host.wg_pubkey.as_deref(), Some("WG_HOST_PUB=="));
        assert_eq!(parsed_host.shares, vec!["MargData", "BusyData"]);
        assert_eq!(parsed_host.auth_error, None);

        let err_host = parse_host_answer_meta("AUTH_FAILED:Wrong password");
        assert_eq!(err_host.auth_error.as_deref(), Some("Wrong password"));
    }
}

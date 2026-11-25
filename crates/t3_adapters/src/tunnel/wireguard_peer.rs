use base64::{engine::general_purpose::STANDARD, Engine};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use t3_domain::TransportMode;

/// Direct UDP P2P is considered active if we received a valid authenticated
/// WireGuard datagram directly over UDP within this window.
const DIRECT_UDP_FRESH_WINDOW: Duration = Duration::from_secs(30);

/// Local WireGuard X25519 keypair for a t3Bridge node.
pub struct WireGuardKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl WireGuardKeypair {
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let secret = StaticSecret::from(raw);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn secret_clone(&self) -> StaticSecret {
        StaticSecret::from(self.secret.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public.as_bytes())
    }

    pub fn decode_public_key_b64(b64: &str) -> Result<PublicKey, String> {
        let bytes = STANDARD
            .decode(b64.trim())
            .map_err(|e| format!("Invalid WireGuard public key base64: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid WireGuard public key length: {} (expected 32)",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from(arr))
    }
}

/// Outcome of decapsulating an incoming WireGuard packet.
pub struct DecapOutput {
    /// Decrypted IPv4 packet ready to inject into Wintun (if any).
    pub tunnel_ipv4: Option<Vec<u8>>,
    /// Handshake/control WireGuard packets to send back to the peer.
    pub network_replies: Vec<Vec<u8>>,
    /// True if `boringtun` authenticated this packet as valid for this peer.
    pub authenticated: bool,
}

/// Per-peer WireGuard encryption state + dual-path transport state (Direct UDP P2P + Binary WS Fallback).
pub struct WgPeerSession {
    pub virtual_ip: Ipv4Addr,
    pub session_id: String,
    pub tunn: Tunn,
    pub direct_endpoint: Option<SocketAddr>,
    pub candidates: Vec<SocketAddr>,
    pub last_direct_rx: Option<Instant>,
    pub last_relay_rx: Option<Instant>,
}

impl WgPeerSession {
    pub fn new(
        virtual_ip: Ipv4Addr,
        session_id: String,
        local_secret: StaticSecret,
        remote_public: PublicKey,
        peer_index: u32,
        candidates: Vec<SocketAddr>,
    ) -> Self {
        let tunn = Tunn::new(
            local_secret,
            remote_public,
            None,
            Some(15), // 15s WireGuard persistent keepalive for NAT mappings
            peer_index,
            None,
        );

        Self {
            virtual_ip,
            session_id,
            tunn,
            direct_endpoint: candidates.first().copied(),
            candidates,
            last_direct_rx: None,
            last_relay_rx: None,
        }
    }

    pub fn is_direct_udp_active(&self) -> bool {
        if self.direct_endpoint.is_none() {
            return false;
        }
        match self.last_direct_rx {
            Some(t) => t.elapsed() < DIRECT_UDP_FRESH_WINDOW,
            None => false,
        }
    }

    pub fn active_transport_mode(&self) -> TransportMode {
        if self.is_direct_udp_active() {
            TransportMode::DirectUdpP2p
        } else {
            TransportMode::WsBinaryRelay
        }
    }

    pub fn mark_direct_rx(&mut self, from: SocketAddr) {
        self.direct_endpoint = Some(from);
        self.last_direct_rx = Some(Instant::now());
        if !self.candidates.contains(&from) {
            self.candidates.insert(0, from);
        }
    }

    pub fn mark_relay_rx(&mut self) {
        self.last_relay_rx = Some(Instant::now());
    }

    /// Encrypts an outbound IPv4 packet into a WireGuard UDP datagram.
    pub fn encapsulate_ipv4(&mut self, ipv4_pkt: &[u8]) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; ipv4_pkt.len() + 148];
        match self.tunn.encapsulate(ipv4_pkt, &mut dst) {
            TunnResult::WriteToNetwork(slice) => Some(slice.to_vec()),
            _ => None,
        }
    }

    /// Initiates a WireGuard handshake packet proactively.
    pub fn initiate_handshake(&mut self, force_resend: bool) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; 256];
        match self.tunn.format_handshake_initiation(&mut dst, force_resend) {
            TunnResult::WriteToNetwork(slice) => Some(slice.to_vec()),
            _ => None,
        }
    }

    /// Drives WireGuard timers (keepalives, handshake retransmits, key rotation).
    pub fn tick_timers(&mut self) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; 256];
        match self.tunn.update_timers(&mut dst) {
            TunnResult::WriteToNetwork(slice) => Some(slice.to_vec()),
            _ => None,
        }
    }

    /// Decapsulates an incoming WireGuard packet (received from either UDP or Binary WS).
    pub fn decapsulate_wg(&mut self, src_ip: Option<IpAddr>, wg_pkt: &[u8]) -> DecapOutput {
        let mut out = DecapOutput {
            tunnel_ipv4: None,
            network_replies: Vec::new(),
            authenticated: false,
        };

        let mut dst = vec![0u8; wg_pkt.len().max(2048) + 148];
        match self.tunn.decapsulate(src_ip, wg_pkt, &mut dst) {
            TunnResult::Done => {
                // Valid keepalive or state update packet
                out.authenticated = true;
            }
            TunnResult::WriteToTunnelV4(slice, _) => {
                out.authenticated = true;
                out.tunnel_ipv4 = Some(slice.to_vec());
            }
            TunnResult::WriteToNetwork(slice) => {
                out.authenticated = true;
                out.network_replies.push(slice.to_vec());

                // Per boringtun docs: after WriteToNetwork, call decapsulate with empty slice
                // until Done to flush any queued packets waiting on handshake completion.
                loop {
                    let mut flush_buf = vec![0u8; 2048];
                    match self.tunn.decapsulate(None, &[], &mut flush_buf) {
                        TunnResult::WriteToNetwork(more) => {
                            out.network_replies.push(more.to_vec());
                        }
                        _ => break,
                    }
                }
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                out.authenticated = true;
            }
            TunnResult::Err(_) => {
                out.authenticated = false;
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boringtun_two_peers_handshake_and_ipv4_roundtrip() {
        let host_keys = WireGuardKeypair::generate();
        let client_keys = WireGuardKeypair::generate();

        let host_pub = WireGuardKeypair::decode_public_key_b64(&host_keys.public_key_b64()).unwrap();
        let client_pub = WireGuardKeypair::decode_public_key_b64(&client_keys.public_key_b64()).unwrap();

        let mut host = WgPeerSession::new(
            Ipv4Addr::new(10, 99, 0, 2),
            "sess_1".into(),
            host_keys.secret_clone(),
            client_pub,
            1,
            vec![],
        );

        let mut client = WgPeerSession::new(
            Ipv4Addr::new(10, 99, 0, 1),
            "sess_1".into(),
            client_keys.secret_clone(),
            host_pub,
            2,
            vec![],
        );

        // Construct a synthetic IPv4 packet from client (10.99.0.2) to host (10.99.0.1)
        let mut ipv4_pkt = vec![0u8; 40];
        ipv4_pkt[0] = 0x45; // IPv4, IHL=5
        ipv4_pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        ipv4_pkt[9] = 6; // TCP
        ipv4_pkt[12..16].copy_from_slice(&[10, 99, 0, 2]);
        ipv4_pkt[16..20].copy_from_slice(&[10, 99, 0, 1]);
        ipv4_pkt[20..24].copy_from_slice(b"SMBv");

        // 1. Client encapsulates -> triggers handshake initiation (queues ipv4_pkt internally)
        let init_msg = client.encapsulate_ipv4(&ipv4_pkt).expect("handshake initiation");

        // 2. Host receives handshake initiation -> produces handshake response
        let host_decap = host.decapsulate_wg(None, &init_msg);
        assert!(host_decap.authenticated);
        assert_eq!(host_decap.network_replies.len(), 1);

        // 3. Client receives handshake response -> flushes queued encrypted ipv4_pkt!
        let client_decap = client.decapsulate_wg(None, &host_decap.network_replies[0]);
        assert!(client_decap.authenticated);
        assert!(
            !client_decap.network_replies.is_empty(),
            "Client should emit queued encrypted data packet after handshake"
        );

        // 4. Host decrypts the data packet and recovers exact IPv4 bytes
        let mut decrypted = None;
        for reply in &client_decap.network_replies {
            let out = host.decapsulate_wg(None, reply);
            assert!(out.authenticated);
            if let Some(pkt) = out.tunnel_ipv4 {
                decrypted = Some(pkt);
            }
        }
        assert_eq!(decrypted.as_deref(), Some(ipv4_pkt.as_slice()));

        // 5. Subsequent data packet encrypts/decrypts in 1 shot without handshake
        let reply_enc = host.encapsulate_ipv4(&ipv4_pkt).expect("encrypted data");
        let client_rx = client.decapsulate_wg(None, &reply_enc);
        assert!(client_rx.authenticated);
        assert_eq!(client_rx.tunnel_ipv4.as_deref(), Some(ipv4_pkt.as_slice()));
    }
}

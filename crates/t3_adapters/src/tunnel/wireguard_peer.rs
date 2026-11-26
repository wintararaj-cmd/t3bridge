use base64::{engine::general_purpose::STANDARD, Engine};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use t3_domain::TransportMode;

/// Direct UDP P2P is considered active if we received a valid authenticated
/// WireGuard datagram or authenticated UDP P2P probe within this window.
/// (Active peers exchange UDP keepalive probes every 5s; if UDP drops, failover
/// to Binary WS Relay happens automatically after 20s.)
const DIRECT_UDP_FRESH_WINDOW: Duration = Duration::from_secs(20);

/// Wire magic prefix (`"T3"`) for authenticated out-of-band P2P/Relay probes.
/// First byte `0x54` never collides with WireGuard message types (`0x01..=0x04`)
/// or STUN packets (`0x00`/`0x01`).
pub const P2P_PROBE_MAGIC: [u8; 2] = [0x54, 0x33];
pub const P2P_PROBE_LEN: usize = 27;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum P2pProbeKind {
    UdpPing = 1,
    UdpPong = 2,
    RelayPing = 3,
    RelayPong = 4,
    BenchPayload = 5,
    BenchAck = 6,
}

impl P2pProbeKind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::UdpPing),
            2 => Some(Self::UdpPong),
            3 => Some(Self::RelayPing),
            4 => Some(Self::RelayPong),
            5 => Some(Self::BenchPayload),
            6 => Some(Self::BenchAck),
            _ => None,
        }
    }
}

/// Derives a symmetric 16-byte probe authentication token from `session_id` and the
/// X25519 Diffie-Hellman shared secret between Host and Client.
/// Because the shared secret never crosses the signaling server, even a compromised
/// signaling server cannot forge P2P probes or hijack endpoints.
pub fn derive_p2p_probe_token(session_id: &str, dh_shared_secret: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"t3Bridge-P2P-Probe-v2-DH:");
    hasher.update(session_id.as_bytes());
    hasher.update(dh_shared_secret);
    let digest = hasher.finalize();
    let mut token = [0u8; 16];
    token.copy_from_slice(&digest[..16]);
    token
}

/// Encodes an authenticated 27-byte P2P/Relay probe packet:
/// `[0x54, 0x33][kind: 1B][token: 16B][timestamp_or_tag: 8B BE]`
pub fn encode_p2p_probe(kind: P2pProbeKind, token: &[u8; 16], ts_ms: u64) -> [u8; P2P_PROBE_LEN] {
    let mut out = [0u8; P2P_PROBE_LEN];
    out[0..2].copy_from_slice(&P2P_PROBE_MAGIC);
    out[2] = kind as u8;
    out[3..19].copy_from_slice(token);
    out[19..27].copy_from_slice(&ts_ms.to_be_bytes());
    out
}

/// Encodes an authenticated variable-length benchmark packet (`BenchPayload`):
/// `[27-byte probe header][deterministic fill bytes up to total_len]`.
pub fn encode_bench_payload(token: &[u8; 16], tag: u64, total_len: usize) -> Vec<u8> {
    let len = total_len.max(P2P_PROBE_LEN).min(1340);
    let mut out = vec![0xA5u8; len];
    let hdr = encode_p2p_probe(P2pProbeKind::BenchPayload, token, tag);
    out[..P2P_PROBE_LEN].copy_from_slice(&hdr);
    out
}

/// Decodes an authenticated P2P/Relay/Benchmark probe packet.
/// Returns `None` for WireGuard/STUN/garbage packets.
pub fn decode_p2p_probe(buf: &[u8]) -> Option<(P2pProbeKind, [u8; 16], u64)> {
    if buf.len() < P2P_PROBE_LEN || buf[0..2] != P2P_PROBE_MAGIC {
        return None;
    }
    let kind = P2pProbeKind::from_byte(buf[2])?;
    if kind != P2pProbeKind::BenchPayload && buf.len() != P2P_PROBE_LEN {
        return None;
    }
    let mut token = [0u8; 16];
    token.copy_from_slice(&buf[3..19]);
    let ts_ms = u64::from_be_bytes([
        buf[19], buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26],
    ]);
    Some((kind, token, ts_ms))
}

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
    pub probe_token: [u8; 16],
    pub tunn: Tunn,
    pub direct_endpoint: Option<SocketAddr>,
    pub candidates: Vec<SocketAddr>,
    pub created_at: Instant,
    pub confirmed: bool,
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
        let shared_secret = local_secret.diffie_hellman(&remote_public);
        let probe_token = derive_p2p_probe_token(&session_id, shared_secret.as_bytes());

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
            probe_token,
            tunn,
            direct_endpoint: candidates.first().copied(),
            candidates,
            created_at: Instant::now(),
            confirmed: false,
            last_direct_rx: None,
            last_relay_rx: None,
        }
    }

    /// Marks this peer session as confirmed (e.g. after `RelayRequest` or client-side registration).
    pub fn mark_confirmed(&mut self) {
        self.confirmed = true;
    }

    /// Returns `true` if this peer was pre-registered on `HolePunchOffer` but never confirmed
    /// by `RelayRequest` and never sent any authenticated UDP/Relay traffic within `timeout`.
    pub fn is_stale_unconfirmed(&self, timeout: Duration) -> bool {
        !self.confirmed
            && self.last_direct_rx.is_none()
            && self.last_relay_rx.is_none()
            && self.created_at.elapsed() >= timeout
    }

    /// Constant-time check whether a received probe token authenticates this peer.
    pub fn matches_probe_token(&self, candidate: &[u8; 16]) -> bool {
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= self.probe_token[i] ^ candidate[i];
        }
        diff == 0
    }

    pub fn build_probe(&self, kind: P2pProbeKind, ts_ms: u64) -> [u8; P2P_PROBE_LEN] {
        encode_p2p_probe(kind, &self.probe_token, ts_ms)
    }

    pub fn build_bench_payload(&self, tag: u64, total_len: usize) -> Vec<u8> {
        encode_bench_payload(&self.probe_token, tag, total_len)
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
        self.confirmed = true;
        self.direct_endpoint = Some(from);
        self.last_direct_rx = Some(Instant::now());
        if !self.candidates.contains(&from) {
            self.candidates.insert(0, from);
        }
    }

    pub fn mark_relay_rx(&mut self) {
        self.confirmed = true;
        self.last_relay_rx = Some(Instant::now());
    }

    /// Zero-allocation hot-path encryption of an outbound IPv4 packet into caller-provided `dst` buffer.
    pub fn encapsulate_ipv4_into<'a>(
        &mut self,
        ipv4_pkt: &[u8],
        dst: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        match self.tunn.encapsulate(ipv4_pkt, dst) {
            TunnResult::WriteToNetwork(slice) => Some(slice),
            _ => None,
        }
    }

    /// Encrypts an outbound IPv4 packet into a WireGuard UDP datagram.
    pub fn encapsulate_ipv4(&mut self, ipv4_pkt: &[u8]) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; ipv4_pkt.len() + 148];
        self.encapsulate_ipv4_into(ipv4_pkt, &mut dst)
            .map(|slice| slice.to_vec())
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

    /// Decapsulates an incoming WireGuard packet reusing caller-provided scratch buffer `dst`
    /// to avoid per-packet heap allocations on the receive hot path.
    pub fn decapsulate_wg_with_buf(
        &mut self,
        src_ip: Option<IpAddr>,
        wg_pkt: &[u8],
        dst: &mut Vec<u8>,
    ) -> DecapOutput {
        let mut out = DecapOutput {
            tunnel_ipv4: None,
            network_replies: Vec::new(),
            authenticated: false,
        };

        let needed = wg_pkt.len().max(2048) + 148;
        if dst.len() < needed {
            dst.resize(needed, 0);
        }

        match self.tunn.decapsulate(src_ip, wg_pkt, dst.as_mut_slice()) {
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
                let mut flush_buf = [0u8; 2048];
                loop {
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

    /// Decapsulates an incoming WireGuard packet (received from either UDP or Binary WS).
    pub fn decapsulate_wg(&mut self, src_ip: Option<IpAddr>, wg_pkt: &[u8]) -> DecapOutput {
        let mut dst = vec![0u8; wg_pkt.len().max(2048) + 148];
        self.decapsulate_wg_with_buf(src_ip, wg_pkt, &mut dst)
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

    #[test]
    fn test_p2p_probe_token_symmetry_and_direct_udp_promotion() {
        let host_keys = WireGuardKeypair::generate();
        let client_keys = WireGuardKeypair::generate();
        let host_pub = WireGuardKeypair::decode_public_key_b64(&host_keys.public_key_b64()).unwrap();
        let client_pub = WireGuardKeypair::decode_public_key_b64(&client_keys.public_key_b64()).unwrap();

        let mut host = WgPeerSession::new(
            Ipv4Addr::new(10, 99, 0, 2),
            "sess_tok_abcdef01".into(),
            host_keys.secret_clone(),
            client_pub,
            1,
            vec![],
        );
        let mut client = WgPeerSession::new(
            Ipv4Addr::new(10, 99, 0, 1),
            "sess_tok_abcdef01".into(),
            client_keys.secret_clone(),
            host_pub,
            2,
            vec![],
        );

        // Both peers must derive the exact same 16-byte authentication token
        assert_eq!(host.probe_token, client.probe_token);
        assert_eq!(host.active_transport_mode(), TransportMode::WsBinaryRelay);
        assert_eq!(client.active_transport_mode(), TransportMode::WsBinaryRelay);

        // Client sends UDP P2P_PING (bypasses boringtun anti-replay counter completely)
        let ping_pkt = client.build_probe(P2pProbeKind::UdpPing, 123456789);
        let (kind, tok, ts) = decode_p2p_probe(&ping_pkt).expect("valid probe");
        assert_eq!(kind, P2pProbeKind::UdpPing);
        assert_eq!(ts, 123456789);
        assert!(host.matches_probe_token(&tok));

        // Host receives ping from Client's real NAT-mapped address -> promotes immediately!
        let client_nat_addr: SocketAddr = "203.0.113.55:49152".parse().unwrap();
        host.mark_direct_rx(client_nat_addr);
        assert_eq!(host.active_transport_mode(), TransportMode::DirectUdpP2p);
        assert_eq!(host.direct_endpoint, Some(client_nat_addr));

        // Host replies with UDP P2P_PONG echoing timestamp
        let pong_pkt = host.build_probe(P2pProbeKind::UdpPong, ts);
        let (p_kind, p_tok, p_ts) = decode_p2p_probe(&pong_pkt).expect("valid pong");
        assert_eq!(p_kind, P2pProbeKind::UdpPong);
        assert_eq!(p_ts, 123456789);
        assert!(client.matches_probe_token(&p_tok));

        let host_nat_addr: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        client.mark_direct_rx(host_nat_addr);
        assert_eq!(client.active_transport_mode(), TransportMode::DirectUdpP2p);
        assert_eq!(client.direct_endpoint, Some(host_nat_addr));

        // WireGuard packets and random garbage must NOT decode as P2P probes
        assert!(decode_p2p_probe(&[0x01, 0x00, 0x00, 0x00]).is_none());
        assert!(decode_p2p_probe(&[0x04; 27]).is_none());

        // Security check: a third party (e.g. signaling server) knowing session_id + both public keys
        // cannot derive the same DH-authenticated probe token!
        let attacker_keys = WireGuardKeypair::generate();
        let attacker_peer = WgPeerSession::new(
            Ipv4Addr::new(10, 99, 0, 2),
            "sess_tok_abcdef01".into(),
            attacker_keys.secret_clone(),
            client_pub,
            3,
            vec![],
        );
        assert!(!host.matches_probe_token(&attacker_peer.probe_token));

        // Benchmark payload roundtrip check
        let bench_pkt = client.build_bench_payload(999, 1200);
        assert_eq!(bench_pkt.len(), 1200);
        let (b_kind, b_tok, b_tag) = decode_p2p_probe(&bench_pkt).expect("valid bench payload");
        assert_eq!(b_kind, P2pProbeKind::BenchPayload);
        assert_eq!(b_tag, 999);
        assert!(host.matches_probe_token(&b_tok));
    }

    #[test]
    fn test_orphan_unconfirmed_peer_detection_and_hot_path_throughput_benchmark() {
        let host_keys = WireGuardKeypair::generate();
        let client_keys = WireGuardKeypair::generate();
        let host_pub = host_keys.public_key();
        let client_pub = client_keys.public_key();

        let mut host = WgPeerSession::new(
            Ipv4Addr::new(10, 99, 0, 2),
            "sess_tok_bench".into(),
            host_keys.secret_clone(),
            client_pub,
            1,
            vec![],
        );
        assert!(host.is_stale_unconfirmed(Duration::from_secs(0)));
        assert!(!host.is_stale_unconfirmed(Duration::from_secs(60)));
        host.mark_confirmed();
        assert!(!host.is_stale_unconfirmed(Duration::from_secs(0)));

        let mut client = WgPeerSession::new(
            Ipv4Addr::new(10, 99, 0, 1),
            "sess_tok_bench".into(),
            client_keys.secret_clone(),
            host_pub,
            2,
            vec![],
        );

        // Complete WireGuard handshake
        let mut ipv4_pkt = vec![0x55u8; 1340];
        ipv4_pkt[0] = 0x45;
        ipv4_pkt[2..4].copy_from_slice(&(1340u16).to_be_bytes());
        ipv4_pkt[9] = 6;
        ipv4_pkt[12..16].copy_from_slice(&[10, 99, 0, 2]);
        ipv4_pkt[16..20].copy_from_slice(&[10, 99, 0, 1]);

        let init = client.encapsulate_ipv4(&ipv4_pkt).unwrap();
        let h_resp = host.decapsulate_wg(None, &init);
        let c_done = client.decapsulate_wg(None, &h_resp.network_replies[0]);
        for r in &c_done.network_replies {
            let _ = host.decapsulate_wg(None, r);
        }

        // Micro-benchmark zero-alloc hot path (500 x 1340B packets encrypt + decrypt)
        let mut enc_buf = vec![0u8; 2048];
        let mut dec_buf = vec![0u8; 2048];
        let start = Instant::now();
        for _ in 0..500 {
            let wire = client
                .encapsulate_ipv4_into(&ipv4_pkt, &mut enc_buf)
                .expect("encapsulate into");
            let out = host.decapsulate_wg_with_buf(None, wire, &mut dec_buf);
            assert!(out.authenticated);
            assert_eq!(out.tunnel_ipv4.as_ref().map(|v| v.len()), Some(1340));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "Hot path crypto unexpectedly slow: {:?}",
            elapsed
        );
    }
}

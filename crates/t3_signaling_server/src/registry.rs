use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::{mpsc, RwLock};
use t3_domain::{Peer, PeerRole, SignalingMessage, VirtualIp};

#[allow(dead_code)]
pub struct ConnectedPeer {
    pub peer: Peer,
    pub tx: mpsc::UnboundedSender<SignalingMessage>,
    pub binary_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub remote_addr: SocketAddr,
}

#[derive(Clone)]
pub struct RelayPair {
    pub client_tx: mpsc::UnboundedSender<SignalingMessage>,
    pub host_tx: mpsc::UnboundedSender<SignalingMessage>,
    pub client_bin_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub host_bin_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub client_id: String,
    pub host_id: String,
}

#[allow(dead_code)]
impl ConnectedPeer {
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

pub struct PeerRegistry {
    peers: RwLock<HashMap<String, ConnectedPeer>>,
    next_ip_suffix: RwLock<u8>,
    relay_sessions: RwLock<HashMap<String, RelayPair>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            next_ip_suffix: RwLock::new(2),
            relay_sessions: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(
        &self,
        peer_id: String,
        role: PeerRole,
        tx: mpsc::UnboundedSender<SignalingMessage>,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<VirtualIp> {
        let ip_str = if role == PeerRole::HostServer {
            "10.99.0.1".to_string()
        } else {
            let used_ips: std::collections::HashSet<String> = {
                let map = self.peers.read().await;
                map.values()
                    .map(|cp| cp.peer.virtual_ip.addr().to_string())
                    .collect()
            };

            let mut suffix = self.next_ip_suffix.write().await;
            let mut chosen = if *suffix < 2 || *suffix > 254 { 2 } else { *suffix };
            for _ in 0..253 {
                let candidate = format!("10.99.0.{}", chosen);
                let next = if chosen >= 254 { 2 } else { chosen + 1 };
                if !used_ips.contains(&candidate) {
                    *suffix = next;
                    break;
                }
                chosen = next;
            }
            if chosen < 2 || chosen > 254 {
                chosen = 2;
            }
            format!("10.99.0.{}", chosen)
        };

        let vip = VirtualIp::new(&ip_str, 24)
            .map_err(|e| anyhow::anyhow!("IP allocation error: {}", e))?;

        let peer = Peer {
            peer_id: peer_id.clone(),
            name: format!("{}-Node", peer_id),
            role,
            virtual_ip: vip.clone(),
            public_endpoint: Some(remote_addr.to_string()),
            is_online: true,
        };

        let mut map = self.peers.write().await;
        map.insert(
            peer_id,
            ConnectedPeer {
                peer,
                tx,
                binary_tx: None,
                remote_addr,
            },
        );

        Ok(vip)
    }

    pub async fn attach_binary_tx(&self, peer_id: &str, binary_tx: mpsc::Sender<Vec<u8>>) {
        let mut map = self.peers.write().await;
        if let Some(cp) = map.get_mut(peer_id) {
            cp.binary_tx = Some(binary_tx);
        }
    }

    pub async fn unregister(&self, peer_id: &str, sender_tx: Option<&mpsc::UnboundedSender<SignalingMessage>>) {
        {
            let mut map = self.peers.write().await;
            if let Some(expected_tx) = sender_tx {
                if let Some(cp) = map.get(peer_id) {
                    if cp.tx.same_channel(expected_tx) {
                        map.remove(peer_id);
                    }
                }
            } else {
                map.remove(peer_id);
            }
        }

        // Notify and clean up any relay sessions involving this peer
        let mut to_close = Vec::new();
        {
            let mut sessions = self.relay_sessions.write().await;
            sessions.retain(|sid, pair| {
                if pair.client_id == peer_id {
                    to_close.push((pair.host_tx.clone(), sid.clone()));
                    false
                } else if pair.host_id == peer_id {
                    to_close.push((pair.client_tx.clone(), sid.clone()));
                    false
                } else {
                    true
                }
            });
        }

        for (tx, sid) in to_close {
            let _ = tx.send(SignalingMessage::RelayClose { session_id: sid });
        }
    }

    pub async fn get_peer_tx(&self, peer_id: &str) -> Option<mpsc::UnboundedSender<SignalingMessage>> {
        let map = self.peers.read().await;
        map.get(peer_id).map(|cp| cp.tx.clone())
    }

    pub async fn register_relay_pair(
        &self,
        session_id: String,
        client_id: String,
        client_tx: mpsc::UnboundedSender<SignalingMessage>,
        host_id: String,
        host_tx: mpsc::UnboundedSender<SignalingMessage>,
    ) {
        let (client_bin_tx, host_bin_tx) = {
            let map = self.peers.read().await;
            (
                map.get(&client_id).and_then(|cp| cp.binary_tx.clone()),
                map.get(&host_id).and_then(|cp| cp.binary_tx.clone()),
            )
        };
        let mut sessions = self.relay_sessions.write().await;
        sessions.insert(
            session_id,
            RelayPair {
                client_tx,
                host_tx,
                client_bin_tx,
                host_bin_tx,
                client_id,
                host_id,
            },
        );
    }

    /// Resolves the destination bounded binary channel for a relay session so callers can cache it
    /// locally and bypass global `RwLock` + `HashMap` lookups on every subsequent binary frame.
    pub async fn lookup_binary_relay_target(
        &self,
        session_id: &str,
        sender_bin_tx: &mpsc::Sender<Vec<u8>>,
    ) -> Option<mpsc::Sender<Vec<u8>>> {
        let sessions = self.relay_sessions.read().await;
        let pair = sessions.get(session_id)?;
        let is_from_client = pair
            .client_bin_tx
            .as_ref()
            .map(|tx| tx.same_channel(sender_bin_tx))
            .unwrap_or(false);
        if is_from_client {
            pair.host_bin_tx.clone()
        } else {
            pair.client_bin_tx.clone()
        }
    }

    /// Zero-JSON, zero-Base64 binary WebSocket frame forwarding between paired peers.
    /// Uses non-blocking `try_send` on bounded channels to prevent bufferbloat and OOM on slow links.
    #[allow(dead_code)]
    pub async fn forward_binary_relay(
        &self,
        session_id: &str,
        sender_bin_tx: &mpsc::Sender<Vec<u8>>,
        raw_frame: Vec<u8>,
    ) -> bool {
        if let Some(target_tx) = self.lookup_binary_relay_target(session_id, sender_bin_tx).await {
            return target_tx.try_send(raw_frame).is_ok();
        }
        false
    }

    pub async fn forward_relay_data(
        &self,
        session_id: &str,
        sender_tx: &mpsc::UnboundedSender<SignalingMessage>,
        chunk: Vec<u8>,
    ) -> bool {
        let sessions = self.relay_sessions.read().await;
        if let Some(pair) = sessions.get(session_id) {
            let msg = SignalingMessage::RelayData {
                session_id: session_id.to_string(),
                chunk,
            };
            if sender_tx.same_channel(&pair.client_tx) {
                pair.host_tx.send(msg).is_ok()
            } else {
                pair.client_tx.send(msg).is_ok()
            }
        } else {
            false
        }
    }

    pub async fn forward_relay_accepted(
        &self,
        session_id: &str,
    ) -> bool {
        let sessions = self.relay_sessions.read().await;
        if let Some(pair) = sessions.get(session_id) {
            pair.client_tx
                .send(SignalingMessage::RelayAccepted {
                    session_id: session_id.to_string(),
                })
                .is_ok()
        } else {
            false
        }
    }

    pub async fn close_relay_session(
        &self,
        session_id: &str,
        sender_tx: &mpsc::UnboundedSender<SignalingMessage>,
    ) {
        let mut sessions = self.relay_sessions.write().await;
        if let Some(pair) = sessions.remove(session_id) {
            let msg = SignalingMessage::RelayClose {
                session_id: session_id.to_string(),
            };
            if sender_tx.same_channel(&pair.client_tx) {
                let _ = pair.host_tx.send(msg);
            } else {
                let _ = pair.client_tx.send(msg);
            }
        }
    }

    pub async fn find_host(&self, connect_code: &str) -> Option<Peer> {
        let map = self.peers.read().await;
        map.get(connect_code).map(|cp| cp.peer.clone())
    }

    pub async fn route_message(&self, target_id: &str, msg: SignalingMessage) -> bool {
        let map = self.peers.read().await;
        if let Some(target) = map.get(target_id) {
            target.tx.send(msg).is_ok()
        } else {
            false
        }
    }

    #[allow(dead_code)]
    pub async fn count(&self) -> usize {
        self.peers.read().await.len()
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_ip_assignment() {
        let registry = PeerRegistry::new();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut _rx2) = mpsc::unbounded_channel();

        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        // Host gets 10.99.0.1
        let host_ip = registry
            .register("OFFICE-HQ".into(), PeerRole::HostServer, tx1, addr)
            .await
            .unwrap();
        assert_eq!(host_ip.addr().to_string(), "10.99.0.1");

        // Client gets 10.99.0.2
        let client_ip = registry
            .register("BRANCH-01".into(), PeerRole::ClientNode, tx2, addr)
            .await
            .unwrap();
        assert_eq!(client_ip.addr().to_string(), "10.99.0.2");

        // Check host lookup
        let found = registry.find_host("OFFICE-HQ").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().role, PeerRole::HostServer);

        // Check routing
        let sent = registry
            .route_message(
                "OFFICE-HQ",
                SignalingMessage::Ping {
                    peer_id: "BRANCH-01".into(),
                },
            )
            .await;
        assert!(sent);

        let received = rx1.recv().await.unwrap();
        match received {
            SignalingMessage::Ping { peer_id } => assert_eq!(peer_id, "BRANCH-01"),
            _ => panic!("Unexpected message received!"),
        }

        // Unregister
        registry.unregister("BRANCH-01", None).await;
        assert_eq!(registry.count().await, 1);
    }

    #[tokio::test]
    async fn test_registry_ip_wraps_within_2_to_254() {
        let registry = PeerRegistry::new();
        let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        for i in 0..260u32 {
            let (tx, _rx) = mpsc::unbounded_channel();
            let peer_id = format!("CLIENT-{}", i);
            let vip = registry
                .register(peer_id.clone(), PeerRole::ClientNode, tx, addr)
                .await
                .unwrap();
            let last_octet = vip.addr().octets()[3];
            assert!(
                (2..=254).contains(&last_octet),
                "Client IP {} had invalid last octet {}",
                vip.addr(),
                last_octet
            );
            registry.unregister(&peer_id, None).await;
        }
    }

    #[tokio::test]
    async fn test_binary_relay_forwarding_bidirectional() {
        let registry = PeerRegistry::new();
        let addr: SocketAddr = "127.0.0.1:9003".parse().unwrap();

        let (host_tx, _host_rx) = mpsc::unbounded_channel();
        let (host_bin_tx, mut host_bin_rx) = mpsc::channel(64);
        let (client_tx, _client_rx) = mpsc::unbounded_channel();
        let (client_bin_tx, mut client_bin_rx) = mpsc::channel(64);

        registry
            .register("HOST-1".into(), PeerRole::HostServer, host_tx.clone(), addr)
            .await
            .unwrap();
        registry.attach_binary_tx("HOST-1", host_bin_tx.clone()).await;

        registry
            .register("CLIENT-1".into(), PeerRole::ClientNode, client_tx.clone(), addr)
            .await
            .unwrap();
        registry
            .attach_binary_tx("CLIENT-1", client_bin_tx.clone())
            .await;

        registry
            .register_relay_pair(
                "sess_bin_1".into(),
                "CLIENT-1".into(),
                client_tx,
                "HOST-1".into(),
                host_tx,
            )
            .await;

        let frame_c2h = t3_domain::encode_binary_relay_frame("sess_bin_1", b"wg-encrypted-c2h").unwrap();
        assert!(
            registry
                .forward_binary_relay("sess_bin_1", &client_bin_tx, frame_c2h.clone())
                .await
        );
        assert_eq!(host_bin_rx.recv().await.unwrap(), frame_c2h);

        let frame_h2c = t3_domain::encode_binary_relay_frame("sess_bin_1", b"wg-encrypted-h2c").unwrap();
        assert!(
            registry
                .forward_binary_relay("sess_bin_1", &host_bin_tx, frame_h2c.clone())
                .await
        );
        assert_eq!(client_bin_rx.recv().await.unwrap(), frame_h2c);
    }
}

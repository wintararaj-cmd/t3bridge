use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::{mpsc, RwLock};
use t3_domain::{Peer, PeerRole, SignalingMessage, VirtualIp};

#[allow(dead_code)]
pub struct ConnectedPeer {
    pub peer: Peer,
    pub tx: mpsc::UnboundedSender<SignalingMessage>,
    pub remote_addr: SocketAddr,
}

#[derive(Clone)]
pub struct RelayPair {
    pub client_tx: mpsc::UnboundedSender<SignalingMessage>,
    pub host_tx: mpsc::UnboundedSender<SignalingMessage>,
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
            let mut suffix = self.next_ip_suffix.write().await;
            let current = *suffix;
            *suffix = suffix.saturating_add(1);
            format!("10.99.0.{}", current)
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
                remote_addr,
            },
        );

        Ok(vip)
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
        let mut sessions = self.relay_sessions.write().await;
        sessions.insert(
            session_id,
            RelayPair {
                client_tx,
                host_tx,
                client_id,
                host_id,
            },
        );
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
}

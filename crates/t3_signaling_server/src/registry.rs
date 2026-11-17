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

#[allow(dead_code)]
impl ConnectedPeer {
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

pub struct PeerRegistry {
    peers: RwLock<HashMap<String, ConnectedPeer>>,
    next_ip_suffix: RwLock<u8>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            next_ip_suffix: RwLock::new(2),
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

    pub async fn unregister(&self, peer_id: &str) {
        let mut map = self.peers.write().await;
        map.remove(peer_id);
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
        registry.unregister("BRANCH-01").await;
        assert_eq!(registry.count().await, 1);
    }
}

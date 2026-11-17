use async_trait::async_trait;
use t3_domain::{DomainResult, HolePunchPayload, SignalingMessage, VirtualIp};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignalingPort: Send + Sync {
    /// Connects to cloud signaling rendezvous server over secure WebSocket
    async fn connect(&self, signaling_url: &str) -> DomainResult<()>;

    /// Registers the node and gets assigned its virtual IP lease
    async fn register_node(&self, register_msg: SignalingMessage) -> DomainResult<VirtualIp>;

    /// Transmits hole-punch offer to the target peer via signaling relay
    async fn send_hole_punch_offer(&self, target_peer_id: &str, offer: HolePunchPayload) -> DomainResult<()>;

    /// Awaits answer from the remote peer
    async fn wait_for_hole_punch_answer(&self, target_peer_id: &str) -> DomainResult<HolePunchPayload>;

    /// Closes connection to signaling server
    async fn disconnect(&self) -> DomainResult<()>;
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait NatTraversalPort: Send + Sync {
    /// Uses STUN (RFC 5389) to detect public reflexive IP:Port behind NAT/Firewall
    async fn discover_public_endpoint(&self, stun_server: &str, local_port: u16) -> DomainResult<String>;

    /// Sends UDP burst packets to punch holes in the stateful firewall
    async fn send_hole_punch_burst(&self, local_port: u16, remote_endpoint: &str) -> DomainResult<()>;
}

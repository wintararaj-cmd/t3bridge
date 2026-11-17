use async_trait::async_trait;
use marg_domain::{DomainResult, Peer, TunnelMetrics, VirtualIp};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TunnelPort: Send + Sync {
    /// Creates and configures the local Wintun virtual network adapter
    async fn start_adapter(&self, local_ip: VirtualIp) -> DomainResult<()>;

    /// Connects to remote P2P peer via WireGuard/UDP
    async fn connect_peer(&self, peer: &Peer, remote_endpoint: &str) -> DomainResult<()>;

    /// Disconnects the active tunnel
    async fn disconnect(&self) -> DomainResult<()>;

    /// Gathers live connection metrics (latency, bytes, packet loss)
    async fn get_metrics(&self) -> DomainResult<TunnelMetrics>;
}

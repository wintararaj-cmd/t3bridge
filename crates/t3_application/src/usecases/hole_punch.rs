use crate::ports::{NatTraversalPort, SignalingPort};
use t3_domain::{DomainResult, HolePunchPayload};
use std::sync::Arc;

pub struct PerformHolePunchUseCase {
    signaling: Arc<dyn SignalingPort>,
    nat: Arc<dyn NatTraversalPort>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolePunchResult {
    pub remote_peer_id: String,
    pub remote_endpoint: String,
    pub remote_wireguard_pubkey: String,
}

impl PerformHolePunchUseCase {
    pub fn new(signaling: Arc<dyn SignalingPort>, nat: Arc<dyn NatTraversalPort>) -> Self {
        Self { signaling, nat }
    }

    pub async fn execute(
        &self,
        local_peer_id: &str,
        local_wireguard_pubkey: &str,
        target_peer_id: &str,
        stun_server: &str,
        local_udp_port: u16,
    ) -> DomainResult<HolePunchResult> {
        // 1. Discover local node's public IP and mapped NAT port using STUN
        let public_endpoint = self
            .nat
            .discover_public_endpoint(stun_server, local_udp_port)
            .await?;

        // 2. Build local hole punch candidate offer
        let local_offer = HolePunchPayload {
            peer_id: local_peer_id.to_string(),
            public_endpoint,
            wireguard_pubkey: local_wireguard_pubkey.to_string(),
            local_candidate: Some(format!("0.0.0.0:{}", local_udp_port)),
        };

        // 3. Send offer to target peer over signaling channel
        self.signaling
            .send_hole_punch_offer(target_peer_id, local_offer)
            .await?;

        // 4. Wait for remote peer's answer containing their public endpoint
        let remote_answer = self
            .signaling
            .wait_for_hole_punch_answer(target_peer_id)
            .await?;

        // 5. Fire UDP burst packets directly to remote peer's public endpoint to punch the NAT hole
        self.nat
            .send_hole_punch_burst(local_udp_port, &remote_answer.public_endpoint)
            .await?;

        Ok(HolePunchResult {
            remote_peer_id: remote_answer.peer_id,
            remote_endpoint: remote_answer.public_endpoint,
            remote_wireguard_pubkey: remote_answer.wireguard_pubkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{MockNatTraversalPort, MockSignalingPort};

    #[tokio::test]
    async fn test_hole_punch_orchestration_success() {
        let mut mock_nat = MockNatTraversalPort::new();
        mock_nat
            .expect_discover_public_endpoint()
            .with(
                mockall::predicate::eq("stun.l.google.com:19302"),
                mockall::predicate::eq(51820),
            )
            .times(1)
            .returning(|_, _| Ok("103.21.244.10:49152".into()));

        mock_nat
            .expect_send_hole_punch_burst()
            .with(
                mockall::predicate::eq(51820),
                mockall::predicate::eq("14.139.220.5:54321"),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let mut mock_signaling = MockSignalingPort::new();
        mock_signaling
            .expect_send_hole_punch_offer()
            .with(
                mockall::predicate::eq("office_server_01"),
                mockall::predicate::always(),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        mock_signaling
            .expect_wait_for_hole_punch_answer()
            .with(mockall::predicate::eq("office_server_01"))
            .times(1)
            .returning(|_| {
                Ok(HolePunchPayload {
                    peer_id: "office_server_01".into(),
                    public_endpoint: "14.139.220.5:54321".into(),
                    wireguard_pubkey: "cmVtb3RlX3B1YmtleQ==".into(),
                    local_candidate: None,
                })
            });

        let usecase = PerformHolePunchUseCase::new(
            Arc::new(mock_signaling),
            Arc::new(mock_nat),
        );

        let result = usecase
            .execute(
                "branch_client_01",
                "bG9jYWxfcHVia2V5",
                "office_server_01",
                "stun.l.google.com:19302",
                51820,
            )
            .await;

        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.remote_peer_id, "office_server_01");
        assert_eq!(res.remote_endpoint, "14.139.220.5:54321");
        assert_eq!(res.remote_wireguard_pubkey, "cmVtb3RlX3B1YmtleQ==");
    }
}

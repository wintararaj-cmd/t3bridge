use std::sync::Arc;
use t3_adapters::WebSocketSignalingClient;
use t3_application::ports::SignalingPort;
use t3_domain::{HolePunchPayload, PeerRole, SignalingMessage};
use t3_signaling_server::{handle_connection, PeerRegistry};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_e2e_peer_rendezvous_and_hole_punch_exchange() {
    // 1. Bind in-process signaling server to ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ws_url = format!("ws://{}", addr);

    let registry = Arc::new(PeerRegistry::new());
    let server_registry = Arc::clone(&registry);

    // Spawn server accept loop
    tokio::spawn(async move {
        while let Ok((stream, client_addr)) = listener.accept().await {
            let reg = Arc::clone(&server_registry);
            tokio::spawn(async move {
                handle_connection(stream, client_addr, reg).await;
            });
        }
    });

    // 2. Connect Client A (Host Server: OFFICE-HQ)
    let client_a = WebSocketSignalingClient::new();
    client_a.connect(&ws_url).await.unwrap();

    let reg_msg_a = SignalingMessage::RegisterNode {
        peer_id: "OFFICE-HQ".into(),
        role: PeerRole::HostServer,
        hardware_id: "T3-HOST-1234".into(),
        license_key: "LIC-VALID".into(),
    };
    let host_vip = client_a.register_node(reg_msg_a).await.unwrap();
    assert_eq!(host_vip.addr().to_string(), "10.99.0.1");

    // 3. Connect Client B (Branch Node: BRANCH-01)
    let client_b = WebSocketSignalingClient::new();
    client_b.connect(&ws_url).await.unwrap();

    let reg_msg_b = SignalingMessage::RegisterNode {
        peer_id: "BRANCH-01".into(),
        role: PeerRole::ClientNode,
        hardware_id: "T3-CLIENT-5678".into(),
        license_key: "LIC-VALID".into(),
    };
    let branch_vip = client_b.register_node(reg_msg_b).await.unwrap();
    assert_eq!(branch_vip.addr().to_string(), "10.99.0.2");

    // 4. Branch sends HolePunchOffer to Host across relay
    let offer = HolePunchPayload {
        peer_id: "BRANCH-01".into(),
        public_endpoint: "203.0.113.50:41194".into(),
        wireguard_pubkey: "WgPubBranchKey==".into(),
        local_candidate: Some("192.168.1.100:41194".into()),
    };

    client_b
        .send_hole_punch_offer("OFFICE-HQ", offer.clone())
        .await
        .unwrap();

    // 5. Host responds with HolePunchAnswer
    let host_answer = HolePunchPayload {
        peer_id: "OFFICE-HQ".into(),
        public_endpoint: "198.51.100.80:51820".into(),
        wireguard_pubkey: "WgPubHostKey==".into(),
        local_candidate: Some("192.168.0.10:51820".into()),
    };

    // Client B awaits answer in background
    let wait_handle = tokio::spawn(async move {
        client_b.wait_for_hole_punch_answer("OFFICE-HQ").await
    });

    // Simulate relaying answer to Client B
    registry
        .route_message(
            "BRANCH-01",
            SignalingMessage::HolePunchAnswer {
                target_peer_id: "BRANCH-01".into(),
                answer: host_answer.clone(),
            },
        )
        .await;

    let received_answer = wait_handle.await.unwrap().unwrap();
    assert_eq!(received_answer.peer_id, "OFFICE-HQ");
    assert_eq!(received_answer.public_endpoint, "198.51.100.80:51820");
    assert_eq!(received_answer.wireguard_pubkey, "WgPubHostKey==");
}

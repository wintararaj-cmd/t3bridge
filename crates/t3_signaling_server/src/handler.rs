use crate::registry::PeerRegistry;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use t3_domain::SignalingMessage;

pub async fn handle_connection(raw_stream: TcpStream, addr: SocketAddr, registry: Arc<PeerRegistry>) {
    let ws_stream = match tokio_tungstenite::accept_async(raw_stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("[!] WebSocket handshake error from {}: {}", addr, e);
            return;
        }
    };

    println!("[+] WebSocket connection established: {}", addr);
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<SignalingMessage>();

    // Spawn outbound message pump
    let pump_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                if ws_sender.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut registered_peer_id: Option<String> = None;

    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(Message::Text(text)) => {
                if let Ok(signaling_msg) = serde_json::from_str::<SignalingMessage>(&text) {
                    match signaling_msg {
                        SignalingMessage::RegisterNode { peer_id, role, .. } => {
                            match registry.register(peer_id.clone(), role, tx.clone(), addr).await {
                                Ok(vip) => {
                                    registered_peer_id = Some(peer_id);
                                    let resp = SignalingMessage::NodeRegistered {
                                        assigned_virtual_ip: vip,
                                        session_token: "t3-session-ok".into(),
                                    };
                                    let _ = tx.send(resp);
                                }
                                Err(e) => {
                                    let _ = tx.send(SignalingMessage::Error {
                                        code: "REG_FAIL".into(),
                                        message: e.to_string(),
                                    });
                                }
                            }
                        }
                        SignalingMessage::FindHost { connect_code } => {
                            if let Some(host) = registry.find_host(&connect_code).await {
                                let _ = tx.send(SignalingMessage::HostFound { host_peer: host });
                            } else {
                                let _ = tx.send(SignalingMessage::Error {
                                    code: "HOST_NOT_FOUND".into(),
                                    message: format!("Host with code '{}' not found", connect_code),
                                });
                            }
                        }
                        SignalingMessage::HolePunchOffer { target_peer_id, offer } => {
                            let relayed = registry
                                .route_message(
                                    &target_peer_id,
                                    SignalingMessage::HolePunchOffer {
                                        target_peer_id: target_peer_id.clone(),
                                        offer,
                                    },
                                )
                                .await;
                            if !relayed {
                                let _ = tx.send(SignalingMessage::Error {
                                    code: "PEER_OFFLINE".into(),
                                    message: format!("Target peer '{}' is offline", target_peer_id),
                                });
                            }
                        }
                        SignalingMessage::HolePunchAnswer { target_peer_id, answer } => {
                            let relayed = registry
                                .route_message(
                                    &target_peer_id,
                                    SignalingMessage::HolePunchAnswer {
                                        target_peer_id: target_peer_id.clone(),
                                        answer,
                                    },
                                )
                                .await;
                            if !relayed {
                                let _ = tx.send(SignalingMessage::Error {
                                    code: "PEER_OFFLINE".into(),
                                    message: format!("Target peer '{}' is offline", target_peer_id),
                                });
                            }
                        }
                        SignalingMessage::Ping { peer_id: _ } => {
                            let _ = tx.send(SignalingMessage::Pong {
                                timestamp: chrono::Utc::now().timestamp(),
                            });
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }

    if let Some(ref id) = registered_peer_id {
        println!("[-] Peer disconnected: {}", id);
        registry.unregister(id).await;
    }

    pump_handle.abort();
}

use crate::registry::PeerRegistry;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use t3_domain::SignalingMessage;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

pub async fn handle_connection(raw_stream: TcpStream, addr: SocketAddr, registry: Arc<PeerRegistry>) {
    // 1. Check for standard HTTP health-check requests (Render / uptime checks / browser visits)
    let mut peek_buf = [0u8; 1024];
    let n = raw_stream.peek(&mut peek_buf).await.unwrap_or(0);
    let peek_str = String::from_utf8_lossy(&peek_buf[..n]);

    let is_ws_upgrade = peek_str.to_lowercase().contains("upgrade: websocket");

    if !is_ws_upgrade {
        crate::admin_http::handle_http(raw_stream, addr).await;
        return;
    }

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
    let (bin_tx, mut bin_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Spawn outbound message pump (handles both JSON signaling & zero-overhead Binary relay frames)
    let pump_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                maybe_bin = bin_rx.recv() => {
                    match maybe_bin {
                        Some(raw_frame) => {
                            if ws_sender.send(Message::Binary(raw_frame)).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                maybe_msg = rx.recv() => {
                    match maybe_msg {
                        Some(msg) => {
                            if let Ok(json) = serde_json::to_string(&msg) {
                                if ws_sender.send(Message::Text(json)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        None => break,
                    }
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
                                    registry.attach_binary_tx(&peer_id, bin_tx.clone()).await;
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
                        SignalingMessage::RelayRequest { target_peer_id, session_id } => {
                            let source_id = registered_peer_id.clone().unwrap_or_else(|| "anonymous_client".into());
                            if let Some(host_tx) = registry.get_peer_tx(&target_peer_id).await {
                                registry
                                    .register_relay_pair(
                                        session_id.clone(),
                                        source_id,
                                        tx.clone(),
                                        target_peer_id.clone(),
                                        host_tx.clone(),
                                    )
                                    .await;
                                let _ = host_tx.send(SignalingMessage::RelayRequest {
                                    target_peer_id: target_peer_id.clone(),
                                    session_id: session_id.clone(),
                                });
                            } else {
                                let _ = tx.send(SignalingMessage::Error {
                                    code: "PEER_OFFLINE".into(),
                                    message: format!("Target host '{}' is offline", target_peer_id),
                                });
                            }
                        }
                        SignalingMessage::RelayAccepted { session_id } => {
                            let _ = registry.forward_relay_accepted(&session_id).await;
                        }
                        SignalingMessage::RelayData { session_id, chunk } => {
                            let _ = registry.forward_relay_data(&session_id, &tx, chunk).await;
                        }
                        SignalingMessage::RelayClose { session_id } => {
                            registry.close_relay_session(&session_id, &tx).await;
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
            Ok(Message::Binary(frame)) => {
                // Fast-path: zero-JSON, zero-Base64 encrypted relay frame forwarding
                if let Some((session_id, _)) = t3_domain::decode_binary_relay_frame(&frame) {
                    let sid = session_id.to_string();
                    let _ = registry.forward_binary_relay(&sid, &bin_tx, frame).await;
                }
            }
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }

    if let Some(ref id) = registered_peer_id {
        println!("[-] Peer disconnected: {}", id);
        registry.unregister(id, Some(&tx)).await;
    }

    pump_handle.abort();
}

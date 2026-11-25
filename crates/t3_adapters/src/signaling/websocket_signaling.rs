use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use t3_application::ports::SignalingPort;
use t3_domain::{DomainError, DomainResult, HolePunchPayload, Peer, SignalingMessage, VirtualIp};

pub struct WebSocketSignalingClient {
    tx: Arc<Mutex<Option<mpsc::UnboundedSender<SignalingMessage>>>>,
    inbound_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<SignalingMessage>>>>,
    binary_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    binary_inbound_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>>,
}

impl WebSocketSignalingClient {
    pub fn new() -> Self {
        Self {
            tx: Arc::new(Mutex::new(None)),
            inbound_rx: Arc::new(Mutex::new(None)),
            binary_tx: Arc::new(Mutex::new(None)),
            binary_inbound_rx: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn send_message(&self, msg: SignalingMessage) -> DomainResult<()> {
        let guard = self.tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            tx.send(msg)
                .map_err(|e| DomainError::NetworkFailure(format!("Failed to send signaling message: {}", e)))?;
            Ok(())
        } else {
            Err(DomainError::NetworkFailure("Signaling client not connected".into()))
        }
    }

    pub async fn take_inbound_receiver(&self) -> Option<mpsc::UnboundedReceiver<SignalingMessage>> {
        self.inbound_rx.lock().await.take()
    }

    pub async fn get_sender(&self) -> Option<mpsc::UnboundedSender<SignalingMessage>> {
        self.tx.lock().await.clone()
    }

    /// Returns a zero-JSON sender for raw `Message::Binary` relay frames.
    pub async fn get_binary_sender(&self) -> Option<mpsc::UnboundedSender<Vec<u8>>> {
        self.binary_tx.lock().await.clone()
    }

    /// Takes the receiver for inbound `Message::Binary` relay frames.
    pub async fn take_binary_receiver(&self) -> Option<mpsc::UnboundedReceiver<Vec<u8>>> {
        self.binary_inbound_rx.lock().await.take()
    }

    pub async fn is_connected(&self) -> bool {
        let guard = self.tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            !tx.is_closed()
        } else {
            false
        }
    }
}

impl Default for WebSocketSignalingClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignalingPort for WebSocketSignalingClient {
    async fn connect(&self, signaling_url: &str) -> DomainResult<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (ws_stream, _) = connect_async(signaling_url)
            .await
            .map_err(|e| DomainError::NetworkFailure(format!("Signaling connect error: {}", e)))?;

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let (bin_outbound_tx, mut bin_outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (raw_tx, mut raw_rx) = mpsc::unbounded_channel::<Message>();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let (bin_inbound_tx, bin_inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Bridge SignalingMessage outbound channel -> raw WebSocket Text frames
        let raw_tx_for_app = raw_tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                if let Ok(json) = serde_json::to_string(&msg) {
                    if raw_tx_for_app.send(Message::Text(json)).is_err() {
                        break;
                    }
                }
            }
        });

        // Bridge raw binary relay outbound channel -> raw WebSocket Binary frames (zero JSON/Base64)
        let raw_tx_for_bin = raw_tx.clone();
        tokio::spawn(async move {
            while let Some(frame) = bin_outbound_rx.recv().await {
                if raw_tx_for_bin.send(Message::Binary(frame)).is_err() {
                    break;
                }
            }
        });

        // Outbound WebSocket frame pump (handles Binary, Text, Ping, Pong)
        tokio::spawn(async move {
            while let Some(frame) = raw_rx.recv().await {
                if ws_sender.send(frame).await.is_err() {
                    break;
                }
            }
        });

        // Inbound pump
        let raw_tx_for_pong = raw_tx.clone();
        tokio::spawn(async move {
            loop {
                match ws_receiver.next().await {
                    Some(Ok(Message::Binary(bytes))) => {
                        let _ = bin_inbound_tx.send(bytes);
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(msg) = serde_json::from_str::<SignalingMessage>(&text) {
                            // Consume keepalive pong frames so they do not disrupt request/response channels
                            if matches!(msg, SignalingMessage::Pong { .. }) {
                                continue;
                            }
                            if inbound_tx.send(msg).is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        // Explicitly reply with WebSocket Pong so reverse proxies / mobile NATs keep the socket alive
                        let _ = raw_tx_for_pong.send(Message::Pong(payload));
                    }
                    Some(Ok(Message::Close(_))) => {
                        break;
                    }
                    Some(Ok(_)) => {
                        // Pong frames must not terminate the pump
                    }
                    Some(Err(_)) | None => {
                        break;
                    }
                }
            }
        });

        // Background Keepalive Ping every 15 seconds to survive mobile hotspot / CGNAT / Render idle timeouts
        let ping_tx = outbound_tx.clone();
        let raw_ping_tx = raw_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
            interval.tick().await; // Initial tick completes immediately
            loop {
                interval.tick().await;
                let app_ok = ping_tx
                    .send(SignalingMessage::Ping {
                        peer_id: "keepalive".into(),
                    })
                    .is_ok();
                let ws_ok = raw_ping_tx.send(Message::Ping(Vec::new())).is_ok();
                if !app_ok || !ws_ok {
                    break;
                }
            }
        });

        *self.tx.lock().await = Some(outbound_tx);
        *self.inbound_rx.lock().await = Some(inbound_rx);
        *self.binary_tx.lock().await = Some(bin_outbound_tx);
        *self.binary_inbound_rx.lock().await = Some(bin_inbound_rx);

        Ok(())
    }

    async fn register_node(&self, register_msg: SignalingMessage) -> DomainResult<VirtualIp> {
        let tx = {
            let guard = self.tx.lock().await;
            guard
                .clone()
                .ok_or_else(|| DomainError::NetworkFailure("Not connected to signaling".into()))?
        };

        tx.send(register_msg)
            .map_err(|e| DomainError::NetworkFailure(format!("Send register error: {}", e)))?;

        let mut rx_guard = self.inbound_rx.lock().await;
        let rx = rx_guard
            .as_mut()
            .ok_or_else(|| DomainError::NetworkFailure("No receiver configured".into()))?;

        let timeout = tokio::time::Duration::from_secs(10);
        let resp = tokio::time::timeout(timeout, rx.recv())
            .await
            .map_err(|_| DomainError::Timeout("Registration timed out".into()))?
            .ok_or_else(|| DomainError::NetworkFailure("Connection closed during registration".into()))?;

        match resp {
            SignalingMessage::NodeRegistered {
                assigned_virtual_ip, ..
            } => Ok(assigned_virtual_ip),
            SignalingMessage::Error { code, message } => {
                Err(DomainError::NetworkFailure(format!("Registration rejected [{code}]: {message}")))
            }
            _ => Err(DomainError::NetworkFailure("Unexpected response during registration".into())),
        }
    }

    async fn find_host(&self, connect_code: &str) -> DomainResult<Peer> {
        let tx = {
            let guard = self.tx.lock().await;
            guard
                .clone()
                .ok_or_else(|| DomainError::NetworkFailure("Not connected to signaling".into()))?
        };

        tx.send(SignalingMessage::FindHost {
            connect_code: connect_code.to_string(),
        })
        .map_err(|e| DomainError::NetworkFailure(format!("Send find_host error: {}", e)))?;

        let mut rx_guard = self.inbound_rx.lock().await;
        let rx = rx_guard
            .as_mut()
            .ok_or_else(|| DomainError::NetworkFailure("No receiver configured".into()))?;

        let timeout = tokio::time::Duration::from_secs(10);
        let resp = tokio::time::timeout(timeout, rx.recv())
            .await
            .map_err(|_| DomainError::Timeout(format!("Finding host '{}' timed out", connect_code)))?
            .ok_or_else(|| DomainError::NetworkFailure("Connection closed while finding host".into()))?;

        match resp {
            SignalingMessage::HostFound { host_peer } => Ok(host_peer),
            SignalingMessage::Error { code, message } => {
                Err(DomainError::NetworkFailure(format!("[{code}]: {message}")))
            }
            _ => Err(DomainError::NetworkFailure("Unexpected response while finding host".into())),
        }
    }

    async fn send_hole_punch_offer(&self, target_peer_id: &str, offer: HolePunchPayload) -> DomainResult<()> {
        let tx = {
            let guard = self.tx.lock().await;
            guard
                .clone()
                .ok_or_else(|| DomainError::NetworkFailure("Not connected to signaling".into()))?
        };

        let msg = SignalingMessage::HolePunchOffer {
            target_peer_id: target_peer_id.to_string(),
            offer,
        };

        tx.send(msg)
            .map_err(|e| DomainError::NetworkFailure(format!("Send offer error: {}", e)))?;

        Ok(())
    }

    async fn wait_for_hole_punch_answer(&self, target_peer_id: &str) -> DomainResult<HolePunchPayload> {
        let mut rx_guard = self.inbound_rx.lock().await;
        let rx = rx_guard
            .as_mut()
            .ok_or_else(|| DomainError::NetworkFailure("No receiver configured".into()))?;

        let timeout = tokio::time::Duration::from_secs(15);
        let resp = tokio::time::timeout(timeout, rx.recv())
            .await
            .map_err(|_| {
                DomainError::Timeout(format!("Waiting for answer from {target_peer_id} timed out"))
            })?
            .ok_or_else(|| DomainError::NetworkFailure("Signaling closed while waiting for answer".into()))?;

        match resp {
            SignalingMessage::HolePunchAnswer { answer, .. } => Ok(answer),
            SignalingMessage::Error { code, message } => {
                Err(DomainError::NetworkFailure(format!("Hole punch failed [{code}]: {message}")))
            }
            _ => Err(DomainError::NetworkFailure("Unexpected message received".into())),
        }
    }

    async fn disconnect(&self) -> DomainResult<()> {
        *self.tx.lock().await = None;
        *self.inbound_rx.lock().await = None;
        *self.binary_tx.lock().await = None;
        *self.binary_inbound_rx.lock().await = None;
        Ok(())
    }
}

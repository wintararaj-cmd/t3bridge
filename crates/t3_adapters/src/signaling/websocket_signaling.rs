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
}

impl WebSocketSignalingClient {
    pub fn new() -> Self {
        Self {
            tx: Arc::new(Mutex::new(None)),
            inbound_rx: Arc::new(Mutex::new(None)),
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
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<SignalingMessage>();

        // Outbound pump
        tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                if let Ok(json) = serde_json::to_string(&msg) {
                    if ws_sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
        });

        // Inbound pump
        tokio::spawn(async move {
            while let Some(Ok(Message::Text(text))) = ws_receiver.next().await {
                if let Ok(msg) = serde_json::from_str::<SignalingMessage>(&text) {
                    if inbound_tx.send(msg).is_err() {
                        break;
                    }
                }
            }
        });

        *self.tx.lock().await = Some(outbound_tx);
        *self.inbound_rx.lock().await = Some(inbound_rx);

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
        Ok(())
    }
}

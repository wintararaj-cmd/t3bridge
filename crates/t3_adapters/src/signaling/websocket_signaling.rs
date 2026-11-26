use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use socket2::SockRef;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_with_config, MaybeTlsStream};
use t3_application::ports::SignalingPort;
use t3_domain::{DomainError, DomainResult, HolePunchPayload, Peer, SignalingMessage, VirtualIp};

/// Desired TCP socket buffer size (2 MB) for low-latency WebSocket relay bursts
const WS_TCP_SOCKET_BUFFER_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of queued WebSocket frames coalesced into a single TLS flush
const WS_SEND_BATCH_MAX: usize = 64;
/// Bounded queue capacity for outbound Binary WS relay frames (prevents bufferbloat on slow 4G/5G links)
const WS_BINARY_CHANNEL_CAPACITY: usize = 512;

fn tune_ws_tcp_socket(tcp: &tokio::net::TcpStream) {
    let _ = tcp.set_nodelay(true);
    let sock_ref = SockRef::from(tcp);
    let _ = sock_ref.set_recv_buffer_size(WS_TCP_SOCKET_BUFFER_BYTES);
    let _ = sock_ref.set_send_buffer_size(WS_TCP_SOCKET_BUFFER_BYTES);
}

pub struct WebSocketSignalingClient {
    tx: Arc<Mutex<Option<mpsc::UnboundedSender<SignalingMessage>>>>,
    inbound_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<SignalingMessage>>>>,
    binary_tx: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
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

    /// Returns a zero-JSON bounded sender for raw `Message::Binary` relay frames.
    pub async fn get_binary_sender(&self) -> Option<mpsc::Sender<Vec<u8>>> {
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

        // Connect with disable_nagle = true (TCP_NODELAY) to eliminate 40-200ms Nagle stalls on SMB/DBF traffic
        let (ws_stream, _) = connect_async_with_config(signaling_url, None, true)
            .await
            .map_err(|e| DomainError::NetworkFailure(format!("Signaling connect error: {}", e)))?;

        match ws_stream.get_ref() {
            MaybeTlsStream::Plain(tcp) => tune_ws_tcp_socket(tcp),
            MaybeTlsStream::Rustls(tls) => tune_ws_tcp_socket(tls.get_ref().0),
            _ => {}
        }

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let (bin_outbound_tx, mut bin_outbound_rx) =
            mpsc::channel::<Vec<u8>>(WS_BINARY_CHANNEL_CAPACITY);
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

        // Single-hop outbound WebSocket frame pump: reads bounded binary frames directly (zero extra task/hop)
        // and coalesces bursts up to WS_SEND_BATCH_MAX into a single TLS flush for low latency.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    maybe_bin = bin_outbound_rx.recv() => {
                        match maybe_bin {
                            Some(first_bin) => {
                                if ws_sender.feed(Message::Binary(first_bin)).await.is_err() {
                                    break;
                                }
                                let mut batched = 1usize;
                                while batched < WS_SEND_BATCH_MAX {
                                    match bin_outbound_rx.try_recv() {
                                        Ok(next_bin) => {
                                            if ws_sender.feed(Message::Binary(next_bin)).await.is_err() {
                                                return;
                                            }
                                            batched += 1;
                                        }
                                        Err(_) => break,
                                    }
                                }
                                // Also drain any pending control/ping/pong frames into the same flush
                                while batched < WS_SEND_BATCH_MAX {
                                    match raw_rx.try_recv() {
                                        Ok(ctrl) => {
                                            if ws_sender.feed(ctrl).await.is_err() {
                                                return;
                                            }
                                            batched += 1;
                                        }
                                        Err(_) => break,
                                    }
                                }
                                if ws_sender.flush().await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    maybe_raw = raw_rx.recv() => {
                        match maybe_raw {
                            Some(first_frame) => {
                                if ws_sender.feed(first_frame).await.is_err() {
                                    break;
                                }
                                let mut batched = 1usize;
                                while batched < WS_SEND_BATCH_MAX {
                                    match raw_rx.try_recv() {
                                        Ok(next_frame) => {
                                            if ws_sender.feed(next_frame).await.is_err() {
                                                return;
                                            }
                                            batched += 1;
                                        }
                                        Err(_) => break,
                                    }
                                }
                                if ws_sender.flush().await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
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

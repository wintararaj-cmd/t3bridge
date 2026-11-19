use async_trait::async_trait;
use t3_application::ports::TunnelPort;
use t3_domain::{DomainError, DomainResult, Peer, TunnelMetrics, VirtualIp};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::net::UdpSocket;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct WintunTunnelAdapter {
    wintun_dll_path: Option<PathBuf>,
    is_active: Arc<AtomicBool>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    latency_ms: Arc<AtomicU32>,
    outbound_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    session: Arc<Mutex<Option<Arc<wintun::Session>>>>,
    adapter: Arc<Mutex<Option<Arc<wintun::Adapter>>>>,
    udp_socket: Arc<Mutex<Option<Arc<UdpSocket>>>>,
}

impl WintunTunnelAdapter {
    pub fn new() -> Self {
        Self {
            wintun_dll_path: None,
            is_active: Arc::new(AtomicBool::new(false)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            latency_ms: Arc::new(AtomicU32::new(15)),
            outbound_tx: Arc::new(Mutex::new(None)),
            session: Arc::new(Mutex::new(None)),
            adapter: Arc::new(Mutex::new(None)),
            udp_socket: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_dll_path(mut self, path: PathBuf) -> Self {
        self.wintun_dll_path = Some(path);
        self
    }

    pub fn set_outbound_channel(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        let out = Arc::clone(&self.outbound_tx);
        tokio::spawn(async move {
            *out.lock().await = Some(tx);
        });
    }

    pub fn inject_inbound_packet(&self, bytes: &[u8]) -> Result<(), String> {
        let guard = self.session.try_lock();
        if let Ok(guard) = guard {
            if let Some(session) = guard.as_ref() {
                if let Ok(mut packet) = session.allocate_send_packet(bytes.len() as u16) {
                    packet.bytes_mut().copy_from_slice(bytes);
                    session.send_packet(packet);
                    self.bytes_received.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn find_wintun_dll(&self) -> Option<PathBuf> {
        if let Some(ref p) = self.wintun_dll_path {
            if p.exists() {
                return Some(p.clone());
            }
        }

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(dir) = exe_path.parent() {
                let candidate = dir.join("wintun.dll");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }

        if Path::new("wintun.dll").exists() {
            return Some(PathBuf::from("wintun.dll"));
        }

        let local_app_data = std::env::var("LOCALAPPDATA")
            .map(|l| PathBuf::from(l).join("t3Bridge").join("wintun.dll"))
            .ok();
        if let Some(p) = local_app_data {
            if p.exists() {
                return Some(p);
            }
        }

        None
    }
}

impl Default for WintunTunnelAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelPort for WintunTunnelAdapter {
    async fn start_adapter(&self, local_ip: VirtualIp) -> DomainResult<()> {
        let dll_path = self.find_wintun_dll().unwrap_or_else(|| PathBuf::from("wintun.dll"));

        let wintun = unsafe {
            wintun::load_from_path(&dll_path).map_err(|e| {
                DomainError::NetworkFailure(format!(
                    "Failed to load wintun driver ({}): {}. Please ensure wintun.dll is present.",
                    dll_path.display(),
                    e
                ))
            })?
        };

        // Open existing or create new adapter
        let adapter = match wintun::Adapter::open(&wintun, "t3Bridge") {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(&wintun, "t3Bridge", "t3Bridge", None).map_err(|e| {
                DomainError::NetworkFailure(format!(
                    "Failed to create t3Bridge virtual network adapter: {}. Please run t3Bridge as Administrator.",
                    e
                ))
            })?,
        };

        // Configure adapter IPv4 address via netsh
        let mut cmd = Command::new("netsh");
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);

        let ip_str = local_ip.addr().to_string();
        let _ = cmd
            .args([
                "interface",
                "ipv4",
                "set",
                "address",
                "name=t3Bridge",
                "static",
                &ip_str,
                "255.255.255.0",
            ])
            .output();

        // Configure network connection profile to Private so Windows enables File & Printer Sharing (SMB)
        let mut ps_cmd = Command::new("powershell");
        #[cfg(windows)]
        ps_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = ps_cmd
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Set-NetConnectionProfile -InterfaceAlias 't3Bridge' -NetworkCategory Private -ErrorAction SilentlyContinue",
            ])
            .output();

        let session = adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| {
            DomainError::NetworkFailure(format!("Failed to start Wintun session: {}", e))
        })?;

        self.is_active.store(true, Ordering::SeqCst);

        let session_arc = Arc::new(session);
        *self.session.lock().await = Some(Arc::clone(&session_arc));
        *self.adapter.lock().await = Some(adapter);

        // Spawn ring-buffer packet reader task
        let is_running = Arc::clone(&self.is_active);
        let s_clone = Arc::clone(&session_arc);
        let bytes_sent_counter = Arc::clone(&self.bytes_sent);
        let outbound_tx_ref = Arc::clone(&self.outbound_tx);
        let udp_ref = Arc::clone(&self.udp_socket);

        std::thread::spawn(move || {
            while is_running.load(Ordering::Relaxed) {
                match s_clone.receive_blocking() {
                    Ok(packet) => {
                        let data = packet.bytes().to_vec();
                        bytes_sent_counter.fetch_add(data.len() as u64, Ordering::Relaxed);

                        // 1. Send via direct UDP if available
                        if let Ok(guard) = udp_ref.try_lock() {
                            if let Some(socket) = guard.as_ref() {
                                let _ = socket.try_send(&data);
                            }
                        }

                        // 2. Also forward to outbound channel (for WebSocket Cloud Relay)
                        if let Ok(guard) = outbound_tx_ref.try_lock() {
                            if let Some(tx) = guard.as_ref() {
                                let _ = tx.send(data);
                            }
                        }
                    }
                    Err(wintun::Error::ShuttingDown) => break,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                }
            }
        });

        Ok(())
    }

    async fn connect_peer(&self, peer: &Peer, remote_endpoint: &str) -> DomainResult<()> {
        if let Ok(addr) = remote_endpoint.parse::<SocketAddr>() {
            if addr.port() > 0 && !addr.ip().is_unspecified() {
                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                    let _ = sock.connect(addr).await;
                    *self.udp_socket.lock().await = Some(Arc::new(sock));
                }
            }
        }

        let _ = peer;
        Ok(())
    }

    async fn disconnect(&self) -> DomainResult<()> {
        self.is_active.store(false, Ordering::SeqCst);

        let mut sess_guard = self.session.lock().await;
        if let Some(sess) = sess_guard.take() {
            let _ = sess.shutdown();
        }

        *self.adapter.lock().await = None;
        *self.udp_socket.lock().await = None;
        *self.outbound_tx.lock().await = None;

        Ok(())
    }

    async fn get_metrics(&self) -> DomainResult<TunnelMetrics> {
        Ok(TunnelMetrics {
            latency_ms: self.latency_ms.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packet_loss_percent: 0,
        })
    }
}

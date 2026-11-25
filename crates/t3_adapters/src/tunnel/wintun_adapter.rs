use crate::nat::StunClientAdapter;
use crate::tunnel::packet_filter::{clamp_tcp_mss, extract_routable_ipv4_dst};
use crate::tunnel::wireguard_peer::{WgPeerSession, WireGuardKeypair};
use async_trait::async_trait;
use rand::RngCore;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use t3_application::ports::TunnelPort;
use t3_domain::{
    decode_binary_relay_frame, encode_binary_relay_frame, DomainError, DomainResult, Peer,
    TransportMode, TunnelMetrics, VirtualIp,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// MTU for WireGuard UDP over standard 1500 Ethernet / 1492 PPPoE (leaves room for IP+UDP+WG headers)
const WIREGUARD_TUNNEL_MTU: &str = "mtu=1380";
/// TCP MSS clamped inside the tunnel (1380 - 20 IPv4 - 20 TCP = 1340)
const WIREGUARD_TCP_MSS: u16 = 1340;
/// NAT hole-punch probe marker (ignored by boringtun receive path)
const HOLE_PUNCH_PROBE: &[u8] = b"\x00\x00t3Bridge_PUNCH\x00";

const STUN_SERVERS: &[&str] = &["stun.l.google.com:19302", "stun1.l.google.com:19302"];

type PeerMap = HashMap<Ipv4Addr, Arc<std::sync::Mutex<WgPeerSession>>>;

pub struct WintunTunnelAdapter {
    wintun_dll_path: Option<PathBuf>,
    is_active: Arc<AtomicBool>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    latency_ms: Arc<AtomicU32>,
    outbound_tx: Arc<std::sync::RwLock<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    binary_relay_tx: Arc<std::sync::RwLock<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    session: Arc<std::sync::RwLock<Option<Arc<wintun::Session>>>>,
    adapter: Arc<Mutex<Option<Arc<wintun::Adapter>>>>,
    udp_socket: Arc<Mutex<Option<Arc<UdpSocket>>>>,
    p2p_udp_socket: Arc<std::sync::RwLock<Option<Arc<UdpSocket>>>>,
    wg_keypair: Arc<WireGuardKeypair>,
    wg_peers: Arc<std::sync::RwLock<PeerMap>>,
    session_to_vip: Arc<std::sync::RwLock<HashMap<String, Ipv4Addr>>>,
    p2p_gen: Arc<AtomicU64>,
    peer_index_seq: AtomicU32,
}

impl WintunTunnelAdapter {
    pub fn new() -> Self {
        Self {
            wintun_dll_path: None,
            is_active: Arc::new(AtomicBool::new(false)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            latency_ms: Arc::new(AtomicU32::new(15)),
            outbound_tx: Arc::new(std::sync::RwLock::new(None)),
            binary_relay_tx: Arc::new(std::sync::RwLock::new(None)),
            session: Arc::new(std::sync::RwLock::new(None)),
            adapter: Arc::new(Mutex::new(None)),
            udp_socket: Arc::new(Mutex::new(None)),
            p2p_udp_socket: Arc::new(std::sync::RwLock::new(None)),
            wg_keypair: Arc::new(WireGuardKeypair::generate()),
            wg_peers: Arc::new(std::sync::RwLock::new(HashMap::new())),
            session_to_vip: Arc::new(std::sync::RwLock::new(HashMap::new())),
            p2p_gen: Arc::new(AtomicU64::new(0)),
            peer_index_seq: AtomicU32::new(1),
        }
    }

    pub fn with_dll_path(mut self, path: PathBuf) -> Self {
        self.wintun_dll_path = Some(path);
        self
    }

    /// Returns this node's base64-encoded WireGuard X25519 public key.
    pub fn local_wg_pubkey_b64(&self) -> String {
        self.wg_keypair.public_key_b64()
    }

    /// Returns the currently active WAN transport mode across registered WireGuard peers.
    pub fn active_transport_mode(&self) -> TransportMode {
        if !self.is_active.load(Ordering::Relaxed) {
            return TransportMode::Disconnected;
        }
        if let Ok(peers) = self.wg_peers.read() {
            if peers.is_empty() {
                return TransportMode::WsLegacyRelay;
            }
            for peer_mtx in peers.values() {
                if let Ok(p) = peer_mtx.lock() {
                    if p.is_direct_udp_active() {
                        return TransportMode::DirectUdpP2p;
                    }
                }
            }
            return TransportMode::WsBinaryRelay;
        }
        TransportMode::Disconnected
    }

    pub fn set_outbound_channel(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        if let Ok(mut guard) = self.outbound_tx.write() {
            *guard = Some(tx);
        }
    }

    /// Attaches the zero-JSON WebSocket `Message::Binary` sender used as fallback when Direct UDP is not yet active.
    pub fn set_binary_relay_channel(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        if let Ok(mut guard) = self.binary_relay_tx.write() {
            *guard = Some(tx);
        }
    }

    /// Binds a single persistent UDP socket, discovers our STUN public IP:port and local LAN IP:port
    /// on that exact socket, and spawns the WireGuard UDP receiver & timer loops.
    ///
    /// Returns `(public_endpoint, local_candidate)`.
    pub async fn init_p2p_udp(&self) -> (String, Option<String>) {
        let gen = self.p2p_gen.fetch_add(1, Ordering::SeqCst) + 1;

        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("[t3_tunnel] Failed to bind P2P UDP socket: {}", e);
                return ("0.0.0.0:0".into(), None);
            }
        };

        let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let local_candidate = discover_local_lan_ipv4().map(|ip| format!("{}:{}", ip, local_port));

        // Discover public reflexive endpoint using the EXACT same UDP socket (critical for NAT traversal)
        let mut public_endpoint = "0.0.0.0:0".to_string();
        for server in STUN_SERVERS {
            let mut tx_id = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut tx_id);
            let req = StunClientAdapter::build_binding_request(&tx_id);
            if sock.send_to(&req, server).await.is_ok() {
                let mut buf = [0u8; 512];
                if let Ok(Ok((len, _))) =
                    timeout(Duration::from_millis(1400), sock.recv_from(&mut buf)).await
                {
                    if let Ok(addr) = StunClientAdapter::parse_binding_response(&buf[..len], &tx_id)
                    {
                        public_endpoint = addr.to_string();
                        break;
                    }
                }
            }
        }

        if let Ok(mut guard) = self.p2p_udp_socket.write() {
            *guard = Some(Arc::clone(&sock));
        }

        // 1. Spawn UDP Inbound Receiver Task (handles WireGuard decrypt + NAT roaming + direct promotion)
        let sock_rx = Arc::clone(&sock);
        let peers_rx = Arc::clone(&self.wg_peers);
        let session_rx = Arc::clone(&self.session);
        let bytes_rx = Arc::clone(&self.bytes_received);
        let gen_rx = Arc::clone(&self.p2p_gen);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while gen_rx.load(Ordering::Relaxed) == gen {
                let recv = timeout(Duration::from_secs(2), sock_rx.recv_from(&mut buf)).await;
                let (len, src) = match recv {
                    Ok(Ok(pair)) => pair,
                    Ok(Err(_)) => break,
                    Err(_) => continue,
                };

                if len < 4 || &buf[..len] == HOLE_PUNCH_PROBE {
                    continue;
                }

                let packet = &buf[..len];
                let peer_list: Vec<Arc<std::sync::Mutex<WgPeerSession>>> = {
                    match peers_rx.read() {
                        Ok(map) => map.values().cloned().collect(),
                        Err(_) => continue,
                    }
                };

                for peer_mtx in peer_list {
                    let decap = {
                        match peer_mtx.lock() {
                            Ok(mut peer) => {
                                let out = peer.decapsulate_wg(Some(src.ip()), packet);
                                if out.authenticated {
                                    peer.mark_direct_rx(src);
                                }
                                out
                            }
                            Err(_) => continue,
                        }
                    };

                    if decap.authenticated {
                        if let Some(ipv4_pkt) = decap.tunnel_ipv4 {
                            inject_into_wintun(&session_rx, &bytes_rx, &ipv4_pkt);
                        }
                        for reply in decap.network_replies {
                            let _ = sock_rx.send_to(&reply, src).await;
                        }
                        break;
                    }
                }
            }
        });

        // 2. Spawn WireGuard Timer & Direct-Path Re-probe Task (250ms tick)
        let sock_timer = Arc::clone(&sock);
        let peers_timer = Arc::clone(&self.wg_peers);
        let bin_tx_timer = Arc::clone(&self.binary_relay_tx);
        let gen_timer = Arc::clone(&self.p2p_gen);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            let mut tick_count: u64 = 0;
            while gen_timer.load(Ordering::Relaxed) == gen {
                interval.tick().await;
                tick_count = tick_count.wrapping_add(1);

                let peer_list: Vec<Arc<std::sync::Mutex<WgPeerSession>>> = {
                    match peers_timer.read() {
                        Ok(map) => map.values().cloned().collect(),
                        Err(_) => continue,
                    }
                };

                for peer_mtx in peer_list {
                    let (timer_pkt, direct_active, direct_ep, candidates, session_id, reprobe_pkt) = {
                        match peer_mtx.lock() {
                            Ok(mut peer) => {
                                let t_pkt = peer.tick_timers();
                                let is_direct = peer.is_direct_udp_active();
                                // Every 20s (80 ticks), if still on relay fallback, re-probe direct UDP
                                let reprobe = if !is_direct
                                    && tick_count % 80 == 0
                                    && !peer.candidates.is_empty()
                                {
                                    peer.initiate_handshake(false)
                                } else {
                                    None
                                };
                                (
                                    t_pkt,
                                    is_direct,
                                    peer.direct_endpoint,
                                    peer.candidates.clone(),
                                    peer.session_id.clone(),
                                    reprobe,
                                )
                            }
                            Err(_) => continue,
                        }
                    };

                    if let Some(pkt) = timer_pkt {
                        if direct_active {
                            if let Some(ep) = direct_ep {
                                let _ = sock_timer.send_to(&pkt, ep).await;
                            }
                        } else {
                            for cand in &candidates {
                                let _ = sock_timer.send_to(&pkt, cand).await;
                            }
                            send_binary_fallback(&bin_tx_timer, &session_id, &pkt);
                        }
                    }

                    if let Some(rpkt) = reprobe_pkt {
                        for cand in &candidates {
                            let _ = sock_timer.send_to(HOLE_PUNCH_PROBE, cand).await;
                            let _ = sock_timer.send_to(&rpkt, cand).await;
                        }
                    }
                }
            }
        });

        (public_endpoint, local_candidate)
    }

    /// Registers an authenticated WireGuard peer (Host registers each Client; Client registers Host 10.99.0.1).
    pub async fn register_wg_peer(
        &self,
        virtual_ip: Ipv4Addr,
        session_id: String,
        remote_pubkey_b64: &str,
        candidates: Vec<SocketAddr>,
        initiate_handshake: bool,
    ) -> Result<(), String> {
        let remote_pub = WireGuardKeypair::decode_public_key_b64(remote_pubkey_b64)?;
        let peer_idx = self.peer_index_seq.fetch_add(1, Ordering::Relaxed);

        let mut peer = WgPeerSession::new(
            virtual_ip,
            session_id.clone(),
            self.wg_keypair.secret_clone(),
            remote_pub,
            peer_idx,
            candidates.clone(),
        );

        let init_pkt = if initiate_handshake {
            peer.initiate_handshake(true)
        } else {
            None
        };

        let peer_arc = Arc::new(std::sync::Mutex::new(peer));
        if let Ok(mut map) = self.wg_peers.write() {
            map.insert(virtual_ip, peer_arc);
        }
        if let Ok(mut s2v) = self.session_to_vip.write() {
            s2v.insert(session_id.clone(), virtual_ip);
        }

        // Fire hole-punch burst + initial handshake over direct UDP candidates
        let maybe_sock = self
            .p2p_udp_socket
            .read()
            .ok()
            .and_then(|g| g.clone());

        if let Some(sock) = maybe_sock {
            for cand in &candidates {
                for _ in 0..3 {
                    let _ = sock.send_to(HOLE_PUNCH_PROBE, cand).await;
                }
                if let Some(ref pkt) = init_pkt {
                    let _ = sock.send_to(pkt, cand).await;
                }
            }
        }

        // Also send handshake via Binary WS fallback so connection establishes immediately even behind Symmetric NAT
        if let Some(pkt) = init_pkt {
            send_binary_fallback(&self.binary_relay_tx, &session_id, &pkt);
        }

        Ok(())
    }

    /// Removes a WireGuard peer when its session closes.
    pub fn remove_wg_peer_by_session(&self, session_id: &str) {
        let maybe_vip = self
            .session_to_vip
            .write()
            .ok()
            .and_then(|mut m| m.remove(session_id));
        if let Some(vip) = maybe_vip {
            if let Ok(mut peers) = self.wg_peers.write() {
                peers.remove(&vip);
            }
        }
    }

    /// Handles an incoming raw WebSocket `Message::Binary` relay frame.
    pub fn handle_inbound_binary_relay(&self, raw_frame: &[u8]) {
        let Some((session_id, payload)) = decode_binary_relay_frame(raw_frame) else {
            return;
        };

        let maybe_peer = {
            let vip_opt = self
                .session_to_vip
                .read()
                .ok()
                .and_then(|m| m.get(session_id).copied());
            vip_opt.and_then(|vip| {
                self.wg_peers
                    .read()
                    .ok()
                    .and_then(|m| m.get(&vip).cloned())
            })
        };

        let Some(peer_mtx) = maybe_peer else {
            // Legacy unencrypted fallback
            let _ = self.inject_inbound_packet(payload);
            return;
        };

        let (decap, direct_ep, candidates, direct_active) = match peer_mtx.lock() {
            Ok(mut peer) => {
                let out = peer.decapsulate_wg(None, payload);
                if out.authenticated {
                    peer.mark_relay_rx();
                }
                (
                    out,
                    peer.direct_endpoint,
                    peer.candidates.clone(),
                    peer.is_direct_udp_active(),
                )
            }
            Err(_) => return,
        };

        if decap.authenticated {
            if let Some(ipv4_pkt) = decap.tunnel_ipv4 {
                inject_into_wintun(&self.session, &self.bytes_received, &ipv4_pkt);
            }
            let maybe_sock = self.p2p_udp_socket.read().ok().and_then(|g| g.clone());
            for reply in decap.network_replies {
                if let Some(ref sock) = maybe_sock {
                    if direct_active {
                        if let Some(ep) = direct_ep {
                            let _ = sock.try_send_to(&reply, ep);
                        }
                    } else {
                        for cand in &candidates {
                            let _ = sock.try_send_to(&reply, *cand);
                        }
                    }
                }
                if !direct_active {
                    send_binary_fallback(&self.binary_relay_tx, session_id, &reply);
                }
            }
        }
    }

    pub fn inject_inbound_packet(&self, bytes: &[u8]) -> Result<(), String> {
        inject_into_wintun(&self.session, &self.bytes_received, bytes);
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

fn inject_into_wintun(
    session_lock: &std::sync::RwLock<Option<Arc<wintun::Session>>>,
    bytes_received: &AtomicU64,
    bytes: &[u8],
) {
    if bytes.is_empty() || bytes.len() > 65535 {
        return;
    }
    if let Ok(guard) = session_lock.read() {
        if let Some(session) = guard.as_ref() {
            if let Ok(mut packet) = session.allocate_send_packet(bytes.len() as u16) {
                packet.bytes_mut().copy_from_slice(bytes);
                session.send_packet(packet);
                bytes_received.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

fn send_binary_fallback(
    bin_tx_lock: &std::sync::RwLock<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    session_id: &str,
    payload: &[u8],
) {
    if let Some(frame) = encode_binary_relay_frame(session_id, payload) {
        if let Ok(guard) = bin_tx_lock.read() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(frame);
            }
        }
    }
}

/// Discovers the primary local LAN IPv4 address without sending any network traffic.
fn discover_local_lan_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Parses a list of optional `IP:Port` endpoint strings into valid routable `SocketAddr` candidates.
pub fn parse_endpoint_candidates(public_ep: &str, local_ep: Option<&str>) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for raw in [Some(public_ep), local_ep].into_iter().flatten() {
        if let Ok(addr) = raw.trim().parse::<SocketAddr>() {
            if addr.port() > 0 && !addr.ip().is_unspecified() && !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

impl Default for WintunTunnelAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunnelPort for WintunTunnelAdapter {
    async fn start_adapter(&self, local_ip: VirtualIp) -> DomainResult<()> {
        // 0. Cleanly teardown previous session if still running
        if self.is_active.load(Ordering::SeqCst) {
            let _ = self.disconnect().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        }

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

        // Validate virtual IPv4 host address (reject network .0 and broadcast .255)
        let octets = local_ip.addr().octets();
        if octets[3] == 0 || octets[3] == 255 {
            return Err(DomainError::NetworkFailure(format!(
                "Invalid virtual IP '{}' assigned for /24 tunnel subnet.",
                local_ip.addr()
            )));
        }

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

        // Start Wintun session FIRST so the adapter link state transitions to Connected/UP
        let session = adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| {
            DomainError::NetworkFailure(format!("Failed to start Wintun session: {}", e))
        })?;

        // Configure adapter IPv4 address via netsh (with PowerShell fallback) and verify assignment
        let ip_str = local_ip.addr().to_string();
        let mut ip_assigned = false;
        for attempt in 0..15 {
            let mut cmd = Command::new("netsh");
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
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

            let mut verify_cmd = Command::new("netsh");
            #[cfg(windows)]
            verify_cmd.creation_flags(CREATE_NO_WINDOW);
            if let Ok(out) = verify_cmd
                .args(["interface", "ipv4", "show", "addresses", "t3Bridge"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains(&ip_str) {
                    ip_assigned = true;
                    break;
                }
            }

            if attempt == 4 || attempt == 9 {
                let mut ps_ip_cmd = Command::new("powershell");
                #[cfg(windows)]
                ps_ip_cmd.creation_flags(CREATE_NO_WINDOW);
                let ps_script = format!(
                    "Get-NetIPAddress -InterfaceAlias 't3Bridge' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; New-NetIPAddress -InterfaceAlias 't3Bridge' -IPAddress '{}' -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null",
                    ip_str
                );
                let _ = ps_ip_cmd
                    .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                    .output();
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }

        if !ip_assigned {
            let _ = session.shutdown();
            return Err(DomainError::NetworkFailure(format!(
                "Failed to assign virtual IP '{}' to t3Bridge network adapter. Please ensure t3Bridge is running as Administrator or Windows Service.",
                ip_str
            )));
        }

        // Ensure interface metric is set to 1 so Windows prioritizes t3Bridge for 10.99.0.x
        let mut if_cmd = Command::new("netsh");
        #[cfg(windows)]
        if_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = if_cmd
            .args(["interface", "ipv4", "set", "interface", "name=t3Bridge", "metric=1"])
            .output();

        // Optimize MTU for WireGuard UDP P2P (1380 leaves clean room for IPv4+UDP+WG headers)
        let mut mtu_cmd = Command::new("netsh");
        #[cfg(windows)]
        mtu_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = mtu_cmd
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                "t3Bridge",
                WIREGUARD_TUNNEL_MTU,
                "store=active",
            ])
            .output();

        // Enable Insecure Guest Auth & Linked Connections in Windows Registry
        let mut reg_cmd1 = Command::new("reg");
        #[cfg(windows)]
        reg_cmd1.creation_flags(CREATE_NO_WINDOW);
        let _ = reg_cmd1
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "/v",
                "EnableInsecureGuestAuth",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        let mut reg_cmd1b = Command::new("reg");
        #[cfg(windows)]
        reg_cmd1b.creation_flags(CREATE_NO_WINDOW);
        let _ = reg_cmd1b
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "/v",
                "AllowInsecureGuestAuth",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        let mut reg_cmd2 = Command::new("reg");
        #[cfg(windows)]
        reg_cmd2.creation_flags(CREATE_NO_WINDOW);
        let _ = reg_cmd2
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "/v",
                "EnableLinkedConnections",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
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

        self.is_active.store(true, Ordering::SeqCst);

        let session_arc = Arc::new(session);
        if let Ok(mut guard) = self.session.write() {
            *guard = Some(Arc::clone(&session_arc));
        }
        *self.adapter.lock().await = Some(adapter);

        // Spawn high-throughput Wintun ring-buffer packet reader thread
        let is_running = Arc::clone(&self.is_active);
        let s_clone = Arc::clone(&session_arc);
        let bytes_sent_counter = Arc::clone(&self.bytes_sent);
        let outbound_tx_ref = Arc::clone(&self.outbound_tx);
        let bin_tx_ref = Arc::clone(&self.binary_relay_tx);
        let udp_ref = Arc::clone(&self.udp_socket);
        let p2p_sock_ref = Arc::clone(&self.p2p_udp_socket);
        let wg_peers_ref = Arc::clone(&self.wg_peers);

        std::thread::spawn(move || {
            while is_running.load(Ordering::Relaxed) {
                match s_clone.receive_blocking() {
                    Ok(packet) => {
                        let mut data = packet.bytes().to_vec();

                        // Fast-path: WireGuard (boringtun) encrypted P2P UDP + Binary WS fallback
                        let has_wg_peers = wg_peers_ref
                            .read()
                            .map(|m| !m.is_empty())
                            .unwrap_or(false);

                        if has_wg_peers {
                            let Some(dst_ip) = extract_routable_ipv4_dst(&data) else {
                                // Drop non-IPv4, multicast, broadcast, and OS discovery chatter
                                continue;
                            };

                            // Clamp TCP MSS on SYN packets so SMB never fragments
                            clamp_tcp_mss(&mut data, WIREGUARD_TCP_MSS);
                            bytes_sent_counter.fetch_add(data.len() as u64, Ordering::Relaxed);

                            let peer_opt = wg_peers_ref
                                .read()
                                .ok()
                                .and_then(|m| m.get(&dst_ip).cloned());

                            if let Some(peer_mtx) = peer_opt {
                                let send_plan = {
                                    match peer_mtx.lock() {
                                        Ok(mut peer) => peer.encapsulate_ipv4(&data).map(|wg_pkt| {
                                            (
                                                wg_pkt,
                                                peer.is_direct_udp_active(),
                                                peer.direct_endpoint,
                                                peer.candidates.clone(),
                                                peer.session_id.clone(),
                                            )
                                        }),
                                        Err(_) => None,
                                    }
                                };

                                if let Some((wg_pkt, direct_active, direct_ep, candidates, sid)) =
                                    send_plan
                                {
                                    let sock_opt =
                                        p2p_sock_ref.read().ok().and_then(|g| g.clone());
                                    if direct_active {
                                        // Direct P2P UDP active: zero bytes go to Render!
                                        if let (Some(sock), Some(ep)) = (sock_opt, direct_ep) {
                                            let _ = sock.try_send_to(&wg_pkt, ep);
                                        }
                                    } else {
                                        // Still punching NAT or behind Symmetric NAT:
                                        // send to UDP candidates AND Binary WS fallback simultaneously
                                        if let Some(sock) = sock_opt {
                                            for cand in &candidates {
                                                let _ = sock.try_send_to(&wg_pkt, *cand);
                                            }
                                        }
                                        send_binary_fallback(&bin_tx_ref, &sid, &wg_pkt);
                                    }
                                }
                            }
                            continue;
                        }

                        // Legacy fallback path (LAN or older host without WireGuard pubkey)
                        bytes_sent_counter.fetch_add(data.len() as u64, Ordering::Relaxed);

                        if let Ok(guard) = udp_ref.try_lock() {
                            if let Some(socket) = guard.as_ref() {
                                let _ = socket.try_send(&data);
                            }
                        }

                        if let Ok(guard) = outbound_tx_ref.read() {
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
        self.p2p_gen.fetch_add(1, Ordering::SeqCst);

        let maybe_sess = if let Ok(mut guard) = self.session.write() {
            guard.take()
        } else {
            None
        };
        if let Some(sess) = maybe_sess {
            let _ = sess.shutdown();
        }

        *self.adapter.lock().await = None;
        *self.udp_socket.lock().await = None;
        if let Ok(mut guard) = self.p2p_udp_socket.write() {
            *guard = None;
        }
        if let Ok(mut guard) = self.wg_peers.write() {
            guard.clear();
        }
        if let Ok(mut guard) = self.session_to_vip.write() {
            guard.clear();
        }
        if let Ok(mut guard) = self.outbound_tx.write() {
            *guard = None;
        }
        if let Ok(mut guard) = self.binary_relay_tx.write() {
            *guard = None;
        }

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

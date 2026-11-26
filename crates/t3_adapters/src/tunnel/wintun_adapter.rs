use crate::nat::StunClientAdapter;
use crate::tunnel::packet_filter::{clamp_tcp_mss, extract_routable_ipv4_dst};
use crate::tunnel::wireguard_peer::{
    decode_p2p_probe, P2pProbeKind, WgPeerSession, WireGuardKeypair,
};
use crate::windows_sys::WindowsSystemAdapter;
use async_trait::async_trait;
use rand::RngCore;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
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
/// Desired UDP socket receive/send buffer size (4 MB) to absorb SMB/DBF burst traffic without OS drops
const UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const UDP_SOCKET_BUFFER_FALLBACK_BYTES: usize = 1024 * 1024;

const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

const STUN_V6_SERVERS: &[&str] = &[
    "[2001:4860:4864:5:8000::1]:19302",
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Disables Windows `SIO_UDP_CONNRESET` (0x9800000C) on an unconnected UDP socket so ICMP
/// Port Unreachable replies from NAT hole-punch probes never poison the socket state.
#[cfg(windows)]
fn disable_windows_udp_connreset(sock: &Socket) {
    use std::os::windows::io::AsRawSocket;
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    extern "system" {
        fn WSAIoctl(
            s: usize,
            dwIoControlCode: u32,
            lpvInBuffer: *const std::ffi::c_void,
            cbInBuffer: u32,
            lpvOutBuffer: *mut std::ffi::c_void,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
            lpCompletionRoutine: *mut std::ffi::c_void,
        ) -> i32;
    }
    let mut bytes_returned: u32 = 0;
    let enable: u32 = 0; // FALSE
    unsafe {
        let _ = WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            &enable as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

#[cfg(not(windows))]
fn disable_windows_udp_connreset(_sock: &Socket) {}

/// Creates an IPv4 UDP socket with enlarged OS receive/send buffers (4 MB, falling back to 1 MB)
/// so high-burst SMB/DBF traffic over WireGuard P2P does not overflow Windows' 64 KB default buffer.
fn bind_tuned_udp_socket() -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if sock.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES).is_err() {
        let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUFFER_FALLBACK_BYTES);
    }
    if sock.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES).is_err() {
        let _ = sock.set_send_buffer_size(UDP_SOCKET_BUFFER_FALLBACK_BYTES);
    }
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().expect("valid IPv4 bind address");
    sock.bind(&bind_addr.into())?;
    disable_windows_udp_connreset(&sock);
    sock.set_nonblocking(true)?;
    let std_udp: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_udp)
}

/// Creates a native IPv6 UDP socket (`[::]:0`) with enlarged OS buffers to bypass IPv4 CGNAT
/// on dual-stack ISP networks (e.g. Reliance Jio, Airtel, JioFiber).
fn bind_tuned_udp_v6_socket() -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = sock.set_only_v6(true);
    if sock.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES).is_err() {
        let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUFFER_FALLBACK_BYTES);
    }
    if sock.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES).is_err() {
        let _ = sock.set_send_buffer_size(UDP_SOCKET_BUFFER_FALLBACK_BYTES);
    }
    let bind_addr: SocketAddr = "[::]:0".parse().expect("valid IPv6 bind address");
    sock.bind(&bind_addr.into())?;
    disable_windows_udp_connreset(&sock);
    sock.set_nonblocking(true)?;
    let std_udp: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_udp)
}

/// Returns `true` for transient UDP `recv_from` errors that must NOT kill the P2P receiver loop.
///
/// Critical on Windows: sending a hole-punch probe to an unreachable LAN/NAT candidate triggers
/// an ICMP Port Unreachable reply which Winsock surfaces on the next `recv_from()` as
/// `WSAECONNRESET` (OS error 10054). Breaking on that error previously terminated Direct UDP P2P!
fn is_transient_udp_recv_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::TimedOut
    ) || matches!(
        err.raw_os_error(),
        Some(10040) // WSAEMSGSIZE (oversized datagram)
            | Some(10049) // WSAEADDRNOTAVAIL
            | Some(10051) // WSAENETUNREACH
            | Some(10052) // WSAENETRESET
            | Some(10053) // WSAECONNABORTED
            | Some(10054) // WSAECONNRESET (ICMP Port Unreachable on Windows)
            | Some(10061) // WSAECONNREFUSED
            | Some(10065) // WSAEHOSTUNREACH
    )
}

type PeerMap = HashMap<Ipv4Addr, Arc<std::sync::Mutex<WgPeerSession>>>;

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn direct_active_has_target(
    is_direct: bool,
    direct_ep: Option<SocketAddr>,
    candidates: &[SocketAddr],
) -> bool {
    if is_direct {
        direct_ep.is_some()
    } else {
        !candidates.is_empty()
    }
}

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
    p2p_udp_v6_socket: Arc<std::sync::RwLock<Option<Arc<UdpSocket>>>>,
    cached_public_ep: Arc<std::sync::RwLock<String>>,
    cached_local_cand: Arc<std::sync::RwLock<Option<String>>>,
    active_stun_tx_id: Arc<std::sync::Mutex<Option<[u8; 12]>>>,
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
            latency_ms: Arc::new(AtomicU32::new(0)),
            outbound_tx: Arc::new(std::sync::RwLock::new(None)),
            binary_relay_tx: Arc::new(std::sync::RwLock::new(None)),
            session: Arc::new(std::sync::RwLock::new(None)),
            adapter: Arc::new(Mutex::new(None)),
            udp_socket: Arc::new(Mutex::new(None)),
            p2p_udp_socket: Arc::new(std::sync::RwLock::new(None)),
            p2p_udp_v6_socket: Arc::new(std::sync::RwLock::new(None)),
            cached_public_ep: Arc::new(std::sync::RwLock::new("0.0.0.0:0".into())),
            cached_local_cand: Arc::new(std::sync::RwLock::new(None)),
            active_stun_tx_id: Arc::new(std::sync::Mutex::new(None)),
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

    /// Returns the most recently STUN-refreshed `(public_endpoint, local_candidate)` for this UDP socket.
    pub fn current_p2p_endpoints(&self) -> (String, Option<String>) {
        let pub_ep = self
            .cached_public_ep
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "0.0.0.0:0".into());
        let local = self
            .cached_local_cand
            .read()
            .ok()
            .and_then(|g| g.clone());
        (pub_ep, local)
    }

    /// Actively sends an on-demand STUN Binding Request on the bound P2P UDP socket and waits up to 220ms
    /// for `cached_public_ep` to update so Host `HolePunchAnswer` always carries a live NAT port.
    pub async fn refresh_p2p_endpoints(&self) -> (String, Option<String>) {
        let maybe_sock = self
            .p2p_udp_socket
            .read()
            .ok()
            .and_then(|g| g.clone());

        if let Some(sock) = maybe_sock {
            let mut tx_id = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut tx_id);
            if let Ok(mut g) = self.active_stun_tx_id.lock() {
                *g = Some(tx_id);
            }
            let req = StunClientAdapter::build_binding_request(&tx_id);
            let _ = sock.send_to(&req, STUN_SERVERS[0]).await;
            let _ = sock.send_to(&req, STUN_SERVERS[1]).await;
            tokio::time::sleep(Duration::from_millis(180)).await;
        }

        self.current_p2p_endpoints()
    }

    /// Returns the currently bound local UDP port for the P2P socket, if initialized.
    pub fn local_udp_port(&self) -> Option<u16> {
        self.p2p_udp_socket
            .read()
            .ok()
            .and_then(|g| g.as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port()))
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

    /// Binds persistent IPv4 + IPv6 UDP sockets, opens Windows Defender Firewall rules (with Edge Traversal),
    /// discovers STUN public IPv4:port, local LAN IPv4:port, and global IPv6:[addr]:port candidates,
    /// and spawns the WireGuard UDP receiver & timer loops.
    ///
    /// Returns `(public_endpoint, local_candidate_csv)`.
    pub async fn init_p2p_udp(&self) -> (String, Option<String>) {
        let gen = self.p2p_gen.fetch_add(1, Ordering::SeqCst) + 1;

        let sock = match bind_tuned_udp_socket() {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("[t3_tunnel] Failed to bind P2P UDP socket: {}", e);
                return ("0.0.0.0:0".into(), None);
            }
        };
        let sock_v6 = bind_tuned_udp_v6_socket().ok().map(Arc::new);

        let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let local_v6_port = sock_v6
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port());

        // Ensure Windows Defender Firewall allows inbound UDP on both binaries and bound ports (non-blocking)
        let fw_v4_port = local_port;
        let fw_v6_port = local_v6_port.unwrap_or(0);
        std::thread::spawn(move || {
            WindowsSystemAdapter::allow_p2p_udp_firewall_rules();
            WindowsSystemAdapter::allow_p2p_udp_port_firewall_rules(&[fw_v4_port, fw_v6_port]);
        });

        // Discover public reflexive IPv4 endpoint using the EXACT same IPv4 UDP socket
        let mut public_endpoint = "0.0.0.0:0".to_string();
        for server in STUN_SERVERS {
            let mut tx_id = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut tx_id);
            let req = StunClientAdapter::build_binding_request(&tx_id);
            if sock.send_to(&req, server).await.is_ok() {
                let mut buf = [0u8; 512];
                if let Ok(Ok((len, _))) =
                    timeout(Duration::from_millis(1200), sock.recv_from(&mut buf)).await
                {
                    if let Ok(addr) = StunClientAdapter::parse_binding_response(&buf[..len], &tx_id)
                    {
                        public_endpoint = addr.to_string();
                        break;
                    }
                }
            }
        }

        // Discover public global IPv6 reflexive endpoint on the IPv6 UDP socket (bypasses IPv4 CGNAT on Jio/Airtel!)
        let mut stun_v6_endpoint: Option<SocketAddr> = None;
        if let Some(ref s6) = sock_v6 {
            for server in STUN_V6_SERVERS {
                let mut tx_id = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut tx_id);
                let req = StunClientAdapter::build_binding_request(&tx_id);
                if s6.send_to(&req, server).await.is_ok() {
                    let mut buf = [0u8; 512];
                    if let Ok(Ok((len, _))) =
                        timeout(Duration::from_millis(900), s6.recv_from(&mut buf)).await
                    {
                        if let Ok(addr) =
                            StunClientAdapter::parse_binding_response(&buf[..len], &tx_id)
                        {
                            if addr.is_ipv6() {
                                stun_v6_endpoint = Some(addr);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let local_candidate =
            discover_all_local_candidates(local_port, local_v6_port, stun_v6_endpoint);

        if let Ok(mut guard) = self.cached_public_ep.write() {
            *guard = public_endpoint.clone();
        }
        if let Ok(mut guard) = self.cached_local_cand.write() {
            *guard = local_candidate.clone();
        }
        if let Ok(mut guard) = self.p2p_udp_socket.write() {
            *guard = Some(Arc::clone(&sock));
        }
        if let Ok(mut guard) = self.p2p_udp_v6_socket.write() {
            *guard = sock_v6.clone();
        }

        // 1a. Spawn IPv4 UDP Inbound Receiver Task
        spawn_udp_receiver_task(
            Arc::clone(&sock),
            Arc::clone(&self.wg_peers),
            Arc::clone(&self.session),
            Arc::clone(&self.bytes_received),
            Arc::clone(&self.latency_ms),
            Arc::clone(&self.active_stun_tx_id),
            Arc::clone(&self.cached_public_ep),
            Arc::clone(&self.p2p_gen),
            gen,
            true,
        );

        // 1b. Spawn IPv6 UDP Inbound Receiver Task (if IPv6 socket available)
        if let Some(ref s6) = sock_v6 {
            spawn_udp_receiver_task(
                Arc::clone(s6),
                Arc::clone(&self.wg_peers),
                Arc::clone(&self.session),
                Arc::clone(&self.bytes_received),
                Arc::clone(&self.latency_ms),
                Arc::clone(&self.active_stun_tx_id),
                Arc::clone(&self.cached_public_ep),
                Arc::clone(&self.p2p_gen),
                gen,
                false,
            );
        }

        // 2. Spawn WireGuard Timer, UDP-First Promotion Probe, Live RTT & 10s STUN Keepalive Task (250ms tick)
        let sock_timer = Arc::clone(&sock);
        let sock_v6_timer = sock_v6.clone();
        let peers_timer = Arc::clone(&self.wg_peers);
        let bin_tx_timer = Arc::clone(&self.binary_relay_tx);
        let stun_tx_timer = Arc::clone(&self.active_stun_tx_id);
        let gen_timer = Arc::clone(&self.p2p_gen);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            let mut tick_count: u64 = 0;
            while gen_timer.load(Ordering::Relaxed) == gen {
                interval.tick().await;
                tick_count = tick_count.wrapping_add(1);

                // Every 10s (40 ticks), refresh STUN binding on this exact UDP socket
                // so Android Mobile Hotspot & CGNAT UDP mappings never expire while idle!
                if tick_count % 40 == 0 {
                    let mut tx_id = [0u8; 12];
                    rand::thread_rng().fill_bytes(&mut tx_id);
                    if let Ok(mut g) = stun_tx_timer.lock() {
                        *g = Some(tx_id);
                    }
                    let req = StunClientAdapter::build_binding_request(&tx_id);
                    let srv_idx = ((tick_count / 40) as usize) % STUN_SERVERS.len();
                    let _ = sock_timer.send_to(&req, STUN_SERVERS[srv_idx]).await;
                    if let Some(ref s6) = sock_v6_timer {
                        let _ = s6.send_to(&req, STUN_V6_SERVERS[0]).await;
                    }
                }

                let peer_list: Vec<Arc<std::sync::Mutex<WgPeerSession>>> = {
                    match peers_timer.read() {
                        Ok(map) => map.values().cloned().collect(),
                        Err(_) => continue,
                    }
                };

                let now_ms = now_epoch_ms();

                for peer_mtx in peer_list {
                    let (
                        timer_pkt,
                        direct_active,
                        direct_ep,
                        candidates,
                        session_id,
                        udp_ping_pkt,
                        relay_ping_pkt,
                    ) = {
                        match peer_mtx.lock() {
                            Ok(mut peer) => {
                                let t_pkt = peer.tick_timers();
                                let is_direct = peer.is_direct_udp_active();

                                // UDP-First Discovery + Keepalive schedule:
                                // - First 15s while not direct: send UDP_PING every 500ms (2 ticks)
                                // - After 15s while not direct: retry UDP_PING every 3s (12 ticks)
                                // - While direct: send UDP_PING every 5s (20 ticks) for NAT keepalive + live RTT
                                let should_udp_ping = if is_direct {
                                    tick_count % 20 == 0
                                } else if peer.created_at.elapsed() < Duration::from_secs(15) {
                                    tick_count % 2 == 0
                                } else {
                                    tick_count % 12 == 0
                                };

                                let udp_ping = if should_udp_ping
                                    && (direct_active_has_target(
                                        is_direct,
                                        peer.direct_endpoint,
                                        &peer.candidates,
                                    ))
                                {
                                    Some(peer.build_probe(P2pProbeKind::UdpPing, now_ms))
                                } else {
                                    None
                                };

                                // Measure real Cloud Relay RTT every 5s while falling back to Relay
                                let relay_ping = if !is_direct && tick_count % 20 == 0 {
                                    Some(peer.build_probe(P2pProbeKind::RelayPing, now_ms))
                                } else {
                                    None
                                };

                                (
                                    t_pkt,
                                    is_direct,
                                    peer.direct_endpoint,
                                    peer.candidates.clone(),
                                    peer.session_id.clone(),
                                    udp_ping,
                                    relay_ping,
                                )
                            }
                            Err(_) => continue,
                        }
                    };

                    if let Some(pkt) = timer_pkt {
                        if direct_active {
                            if let Some(ep) = direct_ep {
                                send_p2p_datagram(
                                    &sock_timer,
                                    sock_v6_timer.as_deref(),
                                    &pkt,
                                    ep,
                                )
                                .await;
                            }
                        } else {
                            send_binary_fallback(&bin_tx_timer, &session_id, &pkt);
                        }
                    }

                    if let Some(ping) = udp_ping_pkt {
                        if direct_active {
                            if let Some(ep) = direct_ep {
                                send_p2p_datagram(
                                    &sock_timer,
                                    sock_v6_timer.as_deref(),
                                    &ping,
                                    ep,
                                )
                                .await;
                            }
                        } else {
                            let spray_targets = expand_probe_targets(&candidates);
                            for cand in &spray_targets {
                                send_p2p_datagram(
                                    &sock_timer,
                                    sock_v6_timer.as_deref(),
                                    &ping,
                                    *cand,
                                )
                                .await;
                            }
                        }
                    }

                    if let Some(rping) = relay_ping_pkt {
                        send_binary_fallback(&bin_tx_timer, &session_id, &rping);
                    }
                }
            }
        });

        (public_endpoint, local_candidate)
    }

    async fn send_udp_probe_burst(&self, candidates: &[SocketAddr], udp_ping: &[u8]) {
        let maybe_sock = self.p2p_udp_socket.read().ok().and_then(|g| g.clone());
        let maybe_sock_v6 = self.p2p_udp_v6_socket.read().ok().and_then(|g| g.clone());
        let Some(sock) = maybe_sock else {
            return;
        };
        let spray_targets = expand_probe_targets(candidates);
        for round in 0..3 {
            let targets = if round == 0 {
                spray_targets.as_slice()
            } else {
                candidates
            };
            for cand in targets {
                send_p2p_datagram(&sock, maybe_sock_v6.as_deref(), udp_ping, *cand).await;
            }
        }
    }

    /// Registers an authenticated WireGuard peer (Host registers each Client; Client registers Host 10.99.0.1).
    /// Idempotent if called again with the same `(virtual_ip, session_id)` so pre-registering on `HolePunchOffer`
    /// and confirming on `RelayRequest` never resets an already-promoted Direct UDP session.
    pub async fn register_wg_peer(
        &self,
        virtual_ip: Ipv4Addr,
        session_id: String,
        remote_pubkey_b64: &str,
        candidates: Vec<SocketAddr>,
        initiate_handshake: bool,
    ) -> Result<(), String> {
        let existing_probe = {
            if let Ok(map) = self.wg_peers.read() {
                if let Some(existing_mtx) = map.get(&virtual_ip) {
                    if let Ok(mut existing) = existing_mtx.lock() {
                        if existing.session_id == session_id {
                            for c in &candidates {
                                if !existing.candidates.contains(c) {
                                    existing.candidates.push(*c);
                                }
                            }
                            if existing.direct_endpoint.is_none() {
                                existing.direct_endpoint = existing.candidates.first().copied();
                            }
                            Some(existing.build_probe(P2pProbeKind::UdpPing, now_epoch_ms()))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(udp_ping) = existing_probe {
            self.send_udp_probe_burst(&candidates, &udp_ping).await;
            return Ok(());
        }

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
        let now_ms = now_epoch_ms();
        let udp_ping = peer.build_probe(P2pProbeKind::UdpPing, now_ms);
        let relay_ping = peer.build_probe(P2pProbeKind::RelayPing, now_ms);

        let peer_arc = Arc::new(std::sync::Mutex::new(peer));
        if let Ok(mut map) = self.wg_peers.write() {
            map.insert(virtual_ip, peer_arc);
        }
        if let Ok(mut s2v) = self.session_to_vip.write() {
            s2v.insert(session_id.clone(), virtual_ip);
        }

        // UDP-First: fire authenticated UDP P2P_PING burst to all candidates + CGNAT port-spray window immediately
        self.send_udp_probe_burst(&candidates, &udp_ping).await;

        // Establish WireGuard handshake + initial RTT measurement over Binary WS fallback
        // so SMB works immediately even if both peers are behind Symmetric CGNAT
        if let Some(pkt) = init_pkt {
            send_binary_fallback(&self.binary_relay_tx, &session_id, &pkt);
        }
        send_binary_fallback(&self.binary_relay_tx, &session_id, &relay_ping);

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

        // Handle out-of-band Relay RTT probes without touching boringtun or promoting Direct UDP
        if let Some((probe_kind, probe_token, ts_ms)) = decode_p2p_probe(payload) {
            if matches!(probe_kind, P2pProbeKind::RelayPing | P2pProbeKind::RelayPong) {
                let maybe_pong = match peer_mtx.lock() {
                    Ok(mut peer) => {
                        if peer.matches_probe_token(&probe_token) {
                            peer.mark_relay_rx();
                            if probe_kind == P2pProbeKind::RelayPing {
                                Some(peer.build_probe(P2pProbeKind::RelayPong, ts_ms))
                            } else {
                                if !peer.is_direct_udp_active() {
                                    let rtt =
                                        now_epoch_ms().saturating_sub(ts_ms).clamp(1, 5000) as u32;
                                    self.latency_ms.store(rtt, Ordering::Relaxed);
                                }
                                None
                            }
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                };
                if let Some(pong) = maybe_pong {
                    send_binary_fallback(&self.binary_relay_tx, session_id, &pong);
                }
            }
            return;
        }

        let (decap, direct_ep, direct_active) = match peer_mtx.lock() {
            Ok(mut peer) => {
                let out = peer.decapsulate_wg(None, payload);
                if out.authenticated {
                    peer.mark_relay_rx();
                }
                (out, peer.direct_endpoint, peer.is_direct_udp_active())
            }
            Err(_) => return,
        };

        if decap.authenticated {
            if let Some(ipv4_pkt) = decap.tunnel_ipv4 {
                inject_into_wintun(&self.session, &self.bytes_received, &ipv4_pkt);
            }
            for reply in decap.network_replies {
                if direct_active {
                    if let Some(ep) = direct_ep {
                        try_send_p2p_datagram(
                            &self.p2p_udp_socket,
                            &self.p2p_udp_v6_socket,
                            &reply,
                            ep,
                        );
                    }
                } else {
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

fn spawn_udp_receiver_task(
    sock_rx: Arc<UdpSocket>,
    peers_rx: Arc<std::sync::RwLock<PeerMap>>,
    session_rx: Arc<std::sync::RwLock<Option<Arc<wintun::Session>>>>,
    bytes_rx: Arc<AtomicU64>,
    latency_rx: Arc<AtomicU32>,
    stun_tx_rx: Arc<std::sync::Mutex<Option<[u8; 12]>>>,
    cached_pub_rx: Arc<std::sync::RwLock<String>>,
    gen_rx: Arc<AtomicU64>,
    gen: u64,
    update_ipv4_stun_cache: bool,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while gen_rx.load(Ordering::Relaxed) == gen {
            let recv = timeout(Duration::from_secs(2), sock_rx.recv_from(&mut buf)).await;
            let (len, mut src) = match recv {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) if is_transient_udp_recv_error(&e) => continue,
                Ok(Err(_)) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                Err(_) => continue,
            };

            if let SocketAddr::V6(ref mut v6) = src {
                v6.set_scope_id(0);
            }

            if len < 4 || &buf[..len] == HOLE_PUNCH_PROBE {
                continue;
            }

            let packet = &buf[..len];

            // (a) Check if this packet is a STUN Binding Response (refreshes cached public IP:Port)
            if len >= 20 && packet[0] == 0x01 && packet[1] == 0x01 {
                let expected_tx = stun_tx_rx.lock().ok().and_then(|g| *g);
                if let Some(tx_id) = expected_tx {
                    if let Ok(addr) = StunClientAdapter::parse_binding_response(packet, &tx_id) {
                        if update_ipv4_stun_cache && addr.is_ipv4() {
                            if let Ok(mut g) = cached_pub_rx.write() {
                                *g = addr.to_string();
                            }
                        }
                        continue;
                    }
                }
            }

            let peer_list: Vec<Arc<std::sync::Mutex<WgPeerSession>>> = {
                match peers_rx.read() {
                    Ok(map) => map.values().cloned().collect(),
                    Err(_) => continue,
                }
            };

            // (b) Check for authenticated UDP-only P2P_PING / P2P_PONG probe
            //     (Bypasses boringtun anti-replay counters so Direct UDP promotes reliably!)
            if let Some((probe_kind, probe_token, ts_ms)) = decode_p2p_probe(packet) {
                if matches!(probe_kind, P2pProbeKind::UdpPing | P2pProbeKind::UdpPong) {
                    for peer_mtx in peer_list {
                        let reply_opt = match peer_mtx.lock() {
                            Ok(mut peer) => {
                                if peer.matches_probe_token(&probe_token) {
                                    peer.mark_direct_rx(src);
                                    if probe_kind == P2pProbeKind::UdpPing {
                                        Some(peer.build_probe(P2pProbeKind::UdpPong, ts_ms))
                                    } else {
                                        let rtt = now_epoch_ms()
                                            .saturating_sub(ts_ms)
                                            .clamp(1, 5000)
                                            as u32;
                                        latency_rx.store(rtt, Ordering::Relaxed);
                                        None
                                    }
                                } else {
                                    continue;
                                }
                            }
                            Err(_) => continue,
                        };

                        if let Some(pong) = reply_opt {
                            let _ = sock_rx.send_to(&pong, src).await;
                        }
                        break;
                    }
                }
                continue;
            }

            // (c) Standard WireGuard encrypted datagram
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
}

async fn send_p2p_datagram(
    sock_v4: &UdpSocket,
    sock_v6: Option<&UdpSocket>,
    payload: &[u8],
    target: SocketAddr,
) {
    match target {
        SocketAddr::V4(_) => {
            let _ = sock_v4.send_to(payload, target).await;
        }
        SocketAddr::V6(_) => {
            if let Some(s6) = sock_v6 {
                let _ = s6.send_to(payload, target).await;
            }
        }
    }
}

fn try_send_p2p_datagram(
    sock_v4_lock: &std::sync::RwLock<Option<Arc<UdpSocket>>>,
    sock_v6_lock: &std::sync::RwLock<Option<Arc<UdpSocket>>>,
    payload: &[u8],
    target: SocketAddr,
) {
    match target {
        SocketAddr::V4(_) => {
            if let Some(sock) = sock_v4_lock.read().ok().and_then(|g| g.clone()) {
                let _ = sock.try_send_to(payload, target);
            }
        }
        SocketAddr::V6(_) => {
            if let Some(sock6) = sock_v6_lock.read().ok().and_then(|g| g.clone()) {
                let _ = sock6.try_send_to(payload, target);
            }
        }
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
        std::net::IpAddr::V4(v4)
            if !v4.is_loopback()
                && !v4.is_unspecified()
                && !(v4.octets()[0] == 10 && v4.octets()[1] == 99 && v4.octets()[2] == 0) =>
        {
            Some(v4)
        }
        _ => None,
    }
}

/// Discovers the primary global unicast IPv6 address without sending any network traffic.
fn discover_global_ipv6() -> Option<Ipv6Addr> {
    let sock = std::net::UdpSocket::bind("[::]:0").ok()?;
    sock.connect("[2001:4860:4860::8888]:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V6(v6)
            if !v6.is_loopback()
                && !v6.is_unspecified()
                && (v6.segments()[0] & 0xfe00) != 0xfc00 // not ULA
                && (v6.segments()[0] & 0xffc0) != 0xfe80 =>
        {
            // Global unicast IPv6 (e.g. 2409:... on Jio, 2401:4900:... on Airtel)
            Some(v6)
        }
        _ => None,
    }
}

/// Builds a comma-separated list of all local LAN IPv4 and global IPv6 `IP:Port` candidates.
fn discover_all_local_candidates(
    v4_port: u16,
    v6_port: Option<u16>,
    stun_v6_ep: Option<SocketAddr>,
) -> Option<String> {
    let mut cands = Vec::<String>::new();

    // 1. Global IPv6 candidates first (zero CGNAT on Jio/Airtel/Broadband!)
    if let Some(mut v6_sa) = stun_v6_ep {
        if let SocketAddr::V6(ref mut s6) = v6_sa {
            s6.set_scope_id(0);
        }
        let s = v6_sa.to_string();
        if !cands.contains(&s) {
            cands.push(s);
        }
    }
    if let (Some(p6), Some(ip6)) = (v6_port, discover_global_ipv6()) {
        if p6 > 0 {
            let s = SocketAddr::V6(SocketAddrV6::new(ip6, p6, 0, 0)).to_string();
            if !cands.contains(&s) {
                cands.push(s);
            }
        }
    }

    // 2. Primary LAN IPv4 candidate
    if v4_port > 0 {
        if let Some(ip4) = discover_local_lan_ipv4() {
            let s = SocketAddr::V4(SocketAddrV4::new(ip4, v4_port)).to_string();
            if !cands.contains(&s) {
                cands.push(s);
            }
        }
    }

    if cands.is_empty() {
        None
    } else {
        Some(cands.join(","))
    }
}

/// Expands direct endpoint candidates with a small adjacent port-spray window (`+1..+6`, `-1..-2`)
/// for public WAN IPv4 endpoints so Port-Restricted NAT + Sequential/Symmetric CGNAT punches through.
pub fn expand_probe_targets(candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(candidates.len() + 8);
    for c in candidates {
        if !out.contains(c) {
            out.push(*c);
        }
    }
    const PORT_DELTAS: &[i32] = &[1, 2, -1, 3, 4, -2, 5, 6];
    for c in candidates {
        if let SocketAddr::V4(v4) = c {
            let ip = *v4.ip();
            let is_wan_public = !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !(ip.octets()[0] == 10 && ip.octets()[1] == 99 && ip.octets()[2] == 0);
            if is_wan_public {
                let base_port = v4.port() as i32;
                for delta in PORT_DELTAS {
                    let p = base_port + delta;
                    if (1024..=65535).contains(&p) {
                        let sprayed = SocketAddr::V4(SocketAddrV4::new(ip, p as u16));
                        if !out.contains(&sprayed) {
                            out.push(sprayed);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Parses a list of optional `IP:Port` (or comma-separated `IP:Port,[IPv6]:Port`) endpoint strings
/// into valid routable `SocketAddr` candidates.
pub fn parse_endpoint_candidates(public_ep: &str, local_ep: Option<&str>) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for raw_group in [Some(public_ep), local_ep].into_iter().flatten() {
        for part in raw_group.split(',') {
            if let Ok(mut addr) = part.trim().parse::<SocketAddr>() {
                if let SocketAddr::V6(ref mut v6) = addr {
                    v6.set_scope_id(0);
                }
                if addr.port() > 0 && !addr.ip().is_unspecified() && !out.contains(&addr) {
                    out.push(addr);
                }
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

        // Resolve the ACTUAL Windows interface alias and numeric Win32 InterfaceIndex.
        // Windows may auto-rename the adapter (e.g. "t3Bridge 2") if a ghost/stale adapter exists,
        // so using InterfaceIndex / actual alias prevents netsh & PowerShell from targeting the wrong adapter.
        let adapter_name = adapter
            .get_name()
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "t3Bridge".to_string());
        let adapter_index = adapter.get_adapter_index().ok();
        let netsh_target = adapter_index
            .map(|idx| idx.to_string())
            .unwrap_or_else(|| adapter_name.clone());
        let netsh_name_arg = format!("name={}", netsh_target);

        // Configure adapter IPv4 address via netsh (with PowerShell fallback) and verify via Win32 IP Helper API
        let target_v4 = *local_ip.addr();
        let ip_str = target_v4.to_string();
        let mut ip_assigned = false;
        for attempt in 0..20 {
            let mut cmd = Command::new("netsh");
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
            let _ = cmd
                .args([
                    "interface",
                    "ipv4",
                    "set",
                    "address",
                    &netsh_name_arg,
                    "static",
                    &ip_str,
                    "255.255.255.0",
                ])
                .output();

            // 1. Primary verification: direct Win32 GetAdaptersAddresses by GUID (immune to alias/locale)
            if let Ok(addrs) = adapter.get_addresses() {
                if addrs.iter().any(|a| *a == std::net::IpAddr::V4(target_v4)) {
                    ip_assigned = true;
                    break;
                }
            }

            // 2. Secondary verification via netsh show addresses
            let mut verify_cmd = Command::new("netsh");
            #[cfg(windows)]
            verify_cmd.creation_flags(CREATE_NO_WINDOW);
            if let Ok(out) = verify_cmd
                .args(["interface", "ipv4", "show", "addresses", &netsh_target])
                .output()
            {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains(&ip_str) {
                    ip_assigned = true;
                    break;
                }
            }

            if attempt == 2 || attempt == 7 || attempt == 13 {
                let mut ps_ip_cmd = Command::new("powershell");
                #[cfg(windows)]
                ps_ip_cmd.creation_flags(CREATE_NO_WINDOW);
                let escaped_alias = adapter_name.replace('\'', "''");
                let ps_script = if let Some(idx) = adapter_index {
                    format!(
                        "Get-NetIPAddress -InterfaceIndex {} -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; New-NetIPAddress -InterfaceIndex {} -IPAddress '{}' -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null",
                        idx, idx, ip_str
                    )
                } else {
                    format!(
                        "Get-NetIPAddress -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; New-NetIPAddress -InterfaceAlias '{}' -IPAddress '{}' -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null",
                        escaped_alias, escaped_alias, ip_str
                    )
                };
                let _ = ps_ip_cmd
                    .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                    .output();

                if let Ok(addrs) = adapter.get_addresses() {
                    if addrs.iter().any(|a| *a == std::net::IpAddr::V4(target_v4)) {
                        ip_assigned = true;
                        break;
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }

        if !ip_assigned {
            let _ = session.shutdown();
            return Err(DomainError::NetworkFailure(format!(
                "Failed to assign virtual IP '{}' to t3Bridge network adapter (alias='{}', index={:?}). Please ensure t3Bridge is running as Administrator or Windows Service.",
                ip_str, adapter_name, adapter_index
            )));
        }

        // Ensure interface metric is set to 1 so Windows prioritizes t3Bridge for 10.99.0.x
        let mut if_cmd = Command::new("netsh");
        #[cfg(windows)]
        if_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = if_cmd
            .args(["interface", "ipv4", "set", "interface", &netsh_name_arg, "metric=1"])
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
                &netsh_target,
                WIREGUARD_TUNNEL_MTU,
                "store=active",
            ])
            .output();

        // Apply SMB Client WAN & DBF/ERP Registry Tuning (Guest Auth, DisableBandwidthThrottling,
        // DisableLargeMtu=0, metadata cache capacities, MaxCmds) while running under elevated/SYSTEM context
        WindowsSystemAdapter::apply_smb_client_wan_tuning();
        // Ensure Windows Firewall allows Direct UDP P2P packets on both Host and Client
        WindowsSystemAdapter::allow_p2p_udp_firewall_rules();

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
        let profile_ps = if let Some(idx) = adapter_index {
            format!(
                "Set-NetConnectionProfile -InterfaceIndex {} -NetworkCategory Private -ErrorAction SilentlyContinue",
                idx
            )
        } else {
            format!(
                "Set-NetConnectionProfile -InterfaceAlias '{}' -NetworkCategory Private -ErrorAction SilentlyContinue",
                adapter_name.replace('\'', "''")
            )
        };
        let mut ps_cmd = Command::new("powershell");
        #[cfg(windows)]
        ps_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = ps_cmd
            .args(["-NoProfile", "-NonInteractive", "-Command", &profile_ps])
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
        let p2p_sock_v6_ref = Arc::clone(&self.p2p_udp_v6_socket);
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
                                                peer.session_id.clone(),
                                            )
                                        }),
                                        Err(_) => None,
                                    }
                                };

                                if let Some((wg_pkt, direct_active, direct_ep, sid)) = send_plan {
                                    if direct_active {
                                        // Direct P2P UDP (IPv4 or IPv6) active: 100% peer-to-peer, zero bytes go to Cloud Relay!
                                        if let Some(ep) = direct_ep {
                                            try_send_p2p_datagram(
                                                &p2p_sock_ref,
                                                &p2p_sock_v6_ref,
                                                &wg_pkt,
                                                ep,
                                            );
                                        }
                                    } else {
                                        // Relay Fallback while UDP P2P_PING probes negotiate direct NAT path
                                        // (avoids duplicating WireGuard nonces across both paths)
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
                if let Ok(sock) = bind_tuned_udp_socket() {
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
        if let Ok(mut guard) = self.p2p_udp_v6_socket.write() {
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
        if let Ok(mut guard) = self.cached_public_ep.write() {
            *guard = "0.0.0.0:0".into();
        }
        if let Ok(mut guard) = self.cached_local_cand.write() {
            *guard = None;
        }
        if let Ok(mut guard) = self.active_stun_tx_id.lock() {
            *guard = None;
        }
        self.latency_ms.store(0, Ordering::Relaxed);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_tuned_udp_socket_binds_and_enlarges_buffers() {
        let sock = bind_tuned_udp_socket().expect("tuned UDP socket should bind");
        assert!(sock.local_addr().unwrap().port() > 0);
        let sock_ref = socket2::SockRef::from(&sock);
        let rcv_buf = sock_ref.recv_buffer_size().unwrap_or(0);
        let snd_buf = sock_ref.send_buffer_size().unwrap_or(0);
        assert!(
            rcv_buf >= 256 * 1024,
            "Expected enlarged UDP recv buffer, got {} bytes",
            rcv_buf
        );
        assert!(
            snd_buf >= 256 * 1024,
            "Expected enlarged UDP send buffer, got {} bytes",
            snd_buf
        );
    }

    #[test]
    fn test_transient_udp_recv_error_ignores_windows_wsaeconnreset() {
        let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "WSAECONNRESET");
        assert!(is_transient_udp_recv_error(&reset));

        let os_10054 = std::io::Error::from_raw_os_error(10054);
        assert!(is_transient_udp_recv_error(&os_10054));

        let os_10040 = std::io::Error::from_raw_os_error(10040);
        assert!(is_transient_udp_recv_error(&os_10040));

        let fatal = std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad fd");
        assert!(!is_transient_udp_recv_error(&fatal));
    }

    #[test]
    fn test_parse_multi_candidates_and_cgnat_port_spray() {
        let cands = parse_endpoint_candidates(
            "152.58.163.162:49633",
            Some("[2409:40e1:432:2c7a:dcf0:b718:b32b:dc88]:49634,10.17.120.176:49633"),
        );
        assert_eq!(cands.len(), 3);
        assert!(cands[0].is_ipv4());
        assert!(cands[1].is_ipv6());
        assert!(cands[2].is_ipv4());

        let sprayed = expand_probe_targets(&cands);
        // Should contain the 3 original candidates + 8 sprayed ports for public WAN IP 152.58.163.162
        assert_eq!(sprayed.len(), 11);
        assert!(sprayed.contains(&"152.58.163.162:49634".parse().unwrap()));
        assert!(sprayed.contains(&"152.58.163.162:49635".parse().unwrap()));
        assert!(sprayed.contains(&"152.58.163.162:49632".parse().unwrap()));
        // Private LAN IP 10.17.120.176 should NOT be port-sprayed
        assert!(!sprayed.contains(&"10.17.120.176:49634".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_udp_first_promotion_works_even_with_one_sided_symmetric_nat() {
        let host = WintunTunnelAdapter::new();
        let client = WintunTunnelAdapter::new();
        host.is_active.store(true, Ordering::SeqCst);
        client.is_active.store(true, Ordering::SeqCst);

        let _ = host.init_p2p_udp().await;
        let _ = client.init_p2p_udp().await;

        let host_port = host.local_udp_port().expect("host UDP port bound");
        let host_loopback: SocketAddr = format!("127.0.0.1:{}", host_port).parse().unwrap();

        let session_id = "sess_tok_e2e_udp_first".to_string();

        // Simulate one-sided Symmetric NAT:
        // Host does NOT know Client's real UDP port (candidates = empty!),
        // only Client knows Host's endpoint. Client's P2P_PING must teach Host
        // Client's real source address and promote BOTH sides to DirectUdpP2p!
        host.register_wg_peer(
            Ipv4Addr::new(10, 99, 0, 2),
            session_id.clone(),
            &client.local_wg_pubkey_b64(),
            vec![],
            false,
        )
        .await
        .unwrap();

        client
            .register_wg_peer(
                Ipv4Addr::new(10, 99, 0, 1),
                session_id.clone(),
                &host.local_wg_pubkey_b64(),
                vec![host_loopback],
                true,
            )
            .await
            .unwrap();

        // Wait up to 1.5s for UDP_PING -> UDP_PONG roundtrip
        let mut promoted = false;
        for _ in 0..30 {
            if host.active_transport_mode() == TransportMode::DirectUdpP2p
                && client.active_transport_mode() == TransportMode::DirectUdpP2p
            {
                promoted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(
            promoted,
            "Expected both peers to promote to DirectUdpP2p (host={:?}, client={:?})",
            host.active_transport_mode(),
            client.active_transport_mode()
        );
        let client_metrics = client.get_metrics().await.unwrap();
        assert!(
            client_metrics.latency_ms >= 1,
            "Expected live measured RTT >= 1ms, got {}",
            client_metrics.latency_ms
        );

        let _ = host.disconnect().await;
        let _ = client.disconnect().await;
    }
}

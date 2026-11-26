use crate::power::SleepPreventionController;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use t3_adapters::{
    Ed25519LicenseVerifier, FileLicenseStorage, WebSocketSignalingClient,
    WindowsHardwareFingerprint, WindowsSystemAdapter, WintunTunnelAdapter,
};
use t3_application::ports::{
    HardwareFingerprintPort, LicenseStoragePort, LicenseVerifierPort, SignalingPort, TunnelPort,
    WindowsSystemPort,
};
use t3_application::usecases::{
    ActivateLicenseUseCase, CheckLicenseStatusUseCase, NetworkWatchdogUseCase,
};
use t3_domain::{
    ConnectionHealth, HolePunchPayload, LicenseStatus, Peer, PeerRole, SignalingMessage,
    TransportMode, TunnelMetrics, VirtualIp,
};
use t3_ipc::{
    generate_salt, get_shared_data_dir, get_shared_license_path, hash_password_with_salt,
    load_service_config, protect_secret, save_service_config, unprotect_secret, ClientSnapshot,
    ConnectionPhase, HostSnapshot, IpcRequest, IpcResponse, LicenseSnapshot, ServiceConfig,
    ServiceMode, ServiceSnapshot, DEFAULT_SIGNALING_URL,
};
use tokio::sync::Mutex;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub const EMBEDDED_PUBLIC_KEY: [u8; 32] = [
    43, 101, 126, 200, 68, 234, 28, 183, 165, 15, 64, 102, 241, 191, 202, 54, 66, 60, 238, 231,
    235, 67, 224, 174, 48, 128, 218, 184, 92, 168, 212, 128,
];

pub struct ServiceEngine {
    pub hwid_provider: Arc<dyn HardwareFingerprintPort>,
    pub verifier: Arc<dyn LicenseVerifierPort>,
    pub storage: Arc<dyn LicenseStoragePort>,
    pub system: Arc<dyn WindowsSystemPort>,
    pub tunnel: Arc<WintunTunnelAdapter>,
    pub sleep_ctrl: Arc<SleepPreventionController>,

    config: Mutex<ServiceConfig>,
    phase: Mutex<ConnectionPhase>,
    last_event: Mutex<Option<String>>,
    reconnect_attempts: AtomicU32,
    reconnect_gen: AtomicU64,

    // Active runtime handles
    host_signaling: Mutex<Option<Arc<WebSocketSignalingClient>>>,
    client_signaling: Mutex<Option<Arc<WebSocketSignalingClient>>>,
    host_status_message: Mutex<String>,
    host_connected_clients: Arc<Mutex<HashSet<String>>>,
    host_max_nodes: Arc<Mutex<u32>>,

    active_server_ip: Mutex<Option<String>>,
    active_is_wan: Mutex<bool>,
    discovered_shares: Arc<Mutex<Vec<String>>>,
    active_client_password: Mutex<Option<String>>,
}

impl ServiceEngine {
    pub fn new() -> Arc<Self> {
        let shared_dir = get_shared_data_dir();
        let _ = std::fs::create_dir_all(&shared_dir);

        let verifier = Arc::new(Ed25519LicenseVerifier::new(&EMBEDDED_PUBLIC_KEY).unwrap());
        let hwid_provider = Arc::new(WindowsHardwareFingerprint::new());
        let storage = Arc::new(FileLicenseStorage::new(get_shared_license_path()));
        let system = Arc::new(WindowsSystemAdapter::new());
        let tunnel = Arc::new(WintunTunnelAdapter::new());
        let sleep_ctrl = Arc::new(SleepPreventionController::new());

        let config = load_service_config().unwrap_or_default();

        Arc::new(Self {
            hwid_provider,
            verifier,
            storage,
            system,
            tunnel,
            sleep_ctrl,
            config: Mutex::new(config),
            phase: Mutex::new(ConnectionPhase::Disconnected),
            last_event: Mutex::new(Some("Service initialized".into())),
            reconnect_attempts: AtomicU32::new(0),
            reconnect_gen: AtomicU64::new(0),
            host_signaling: Mutex::new(None),
            client_signaling: Mutex::new(None),
            host_status_message: Mutex::new("Offline".into()),
            host_connected_clients: Arc::new(Mutex::new(HashSet::new())),
            host_max_nodes: Arc::new(Mutex::new(3)),
            active_server_ip: Mutex::new(None),
            active_is_wan: Mutex::new(false),
            discovered_shares: Arc::new(Mutex::new(Vec::new())),
            active_client_password: Mutex::new(None),
        })
    }

    async fn log_event(&self, msg: impl Into<String>) {
        let text = msg.into();
        eprintln!("[t3_service] {}", text);
        *self.last_event.lock().await = Some(text);
    }

    /// Called once when the Windows Service starts on boot (or manual start).
    /// Automatically restores saved Host or Client mode if `auto_start_enabled` is true.
    pub async fn startup_auto_resume(self: &Arc<Self>) {
        let cfg = self.config.lock().await.clone();
        if !cfg.auto_start_enabled || cfg.mode == ServiceMode::Idle {
            self.log_event("Service started (Idle — waiting for user action)")
                .await;
            return;
        }

        match cfg.mode {
            ServiceMode::Host => {
                if cfg.host.password_hash.is_empty() {
                    self.log_event("Auto-start Host skipped: host password not configured")
                        .await;
                    return;
                }
                self.log_event("Auto-starting saved Host mode after Windows boot...")
                    .await;
                self.schedule_reconnect_loop("Windows boot auto-start (Host)");
            }
            ServiceMode::Client => {
                if cfg.client.target_peer_id.trim().is_empty() {
                    self.log_event("Auto-start Client skipped: no saved server target")
                        .await;
                    return;
                }
                self.log_event("Auto-starting saved Client mode after Windows boot...")
                    .await;
                self.schedule_reconnect_loop("Windows boot auto-start (Client)");
            }
            ServiceMode::Idle => {}
        }
    }

    /// Option 2: Called on Windows `PBT_APMSUSPEND` (Sleep / Hibernate).
    /// Cleanly tears down active tunnel & signaling so SMB handles flush before suspend.
    pub async fn on_system_suspend(&self) {
        self.reconnect_gen.fetch_add(1, Ordering::SeqCst);
        self.log_event("System entering sleep — pausing tunnel safely")
            .await;
        self.teardown_runtime_only().await;
        *self.phase.lock().await = ConnectionPhase::Suspended;
        *self.host_status_message.lock().await = "Suspended (PC Sleeping)".into();
    }

    /// Option 2: Called on Windows `PBT_APMRESUMEAUTOMATIC` / `PBT_APMRESUMESUSPEND`.
    /// Immediately initiates fast reconnect without waiting for dead TCP/UDP timeouts.
    pub async fn on_system_resume(self: &Arc<Self>) {
        let cfg = self.config.lock().await.clone();
        if cfg.mode == ServiceMode::Idle {
            *self.phase.lock().await = ConnectionPhase::Disconnected;
            return;
        }
        self.log_event("System resumed from sleep — reconnecting tunnel")
            .await;
        self.schedule_reconnect_loop("System wake-up recovery");
    }

    /// Option 3: Called when Windows network interface / default route changes (Wi-Fi <-> Hotspot).
    pub async fn on_network_change(self: &Arc<Self>, reason: String) {
        let cfg = self.config.lock().await.clone();
        let phase = *self.phase.lock().await;
        if cfg.mode == ServiceMode::Idle || phase == ConnectionPhase::Suspended {
            return;
        }
        self.log_event(format!("{} — re-establishing tunnel", reason))
            .await;
        self.schedule_reconnect_loop(&reason);
    }

    /// Spawns a single cancellable exponential-backoff reconnect loop for the current persisted mode.
    pub fn schedule_reconnect_loop(self: &Arc<Self>, trigger: &str) {
        let gen = self.reconnect_gen.fetch_add(1, Ordering::SeqCst) + 1;
        self.reconnect_attempts.store(0, Ordering::SeqCst);

        let engine = Arc::clone(self);
        let trigger_str = trigger.to_string();

        tokio::spawn(async move {
            *engine.phase.lock().await = ConnectionPhase::Reconnecting;
            let delays_secs = [1u64, 2, 4, 8, 12, 15];
            let mut attempt: u32 = 0;

            loop {
                if engine.reconnect_gen.load(Ordering::SeqCst) != gen {
                    return; // Superseded by another user action or power event
                }

                let cfg = engine.config.lock().await.clone();
                if cfg.mode == ServiceMode::Idle {
                    *engine.phase.lock().await = ConnectionPhase::Disconnected;
                    return;
                }

                attempt = attempt.saturating_add(1);
                engine.reconnect_attempts.store(attempt, Ordering::SeqCst);
                *engine.phase.lock().await = ConnectionPhase::Reconnecting;
                if cfg.mode == ServiceMode::Host {
                    *engine.host_status_message.lock().await =
                        format!("Reconnecting to Cloud Mesh (attempt {})...", attempt);
                }

                engine.teardown_runtime_only().await;

                let res = match cfg.mode {
                    ServiceMode::Host => engine.establish_host_runtime(&cfg).await.map(|_| ()),
                    ServiceMode::Client => engine.establish_client_runtime(&cfg, None).await.map(|_| ()),
                    ServiceMode::Idle => return,
                };

                if engine.reconnect_gen.load(Ordering::SeqCst) != gen {
                    return;
                }

                match res {
                    Ok(()) => {
                        engine.reconnect_attempts.store(0, Ordering::SeqCst);
                        engine
                            .log_event(format!(
                                "Reconnected successfully ({}, attempt {})",
                                trigger_str, attempt
                            ))
                            .await;
                        return;
                    }
                    Err(e) => {
                        let wait = delays_secs
                            .get((attempt as usize).saturating_sub(1))
                            .copied()
                            .unwrap_or(15);
                        engine
                            .log_event(format!(
                                "Reconnect attempt {} failed ({}): retrying in {}s",
                                attempt, e, wait
                            ))
                            .await;
                        tokio::time::sleep(tokio::time::Duration::from_secs(wait)).await;
                    }
                }
            }
        });
    }

    pub async fn shutdown(&self) {
        self.reconnect_gen.fetch_add(1, Ordering::SeqCst);
        self.sleep_ctrl.set_prevent_sleep(false);
        self.teardown_runtime_only().await;
        *self.phase.lock().await = ConnectionPhase::Disconnected;
    }

    async fn teardown_runtime_only(&self) {
        if let Some(c) = self.host_signaling.lock().await.take() {
            let _ = c.disconnect().await;
        }
        if let Some(c) = self.client_signaling.lock().await.take() {
            let _ = c.disconnect().await;
        }
        let _ = self.tunnel.disconnect().await;
        self.host_connected_clients.lock().await.clear();
        *self.active_server_ip.lock().await = None;
        *self.active_is_wan.lock().await = false;
        self.sleep_ctrl.set_prevent_sleep(false);
    }

    pub async fn compute_host_code(&self) -> String {
        let license_check = CheckLicenseStatusUseCase::new(
            Arc::clone(&self.hwid_provider),
            Arc::clone(&self.storage),
        );
        let license_status = license_check.execute().await;

        let raw_name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "SERVER".into());
        let mut clean_name: String = raw_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect::<String>()
            .to_ascii_uppercase();
        if clean_name.is_empty() {
            clean_name = "SERVER".into();
        }
        if clean_name.len() > 10 {
            clean_name.truncate(10);
        }

        match license_status {
            Ok(LicenseStatus::Licensed { customer_name, .. }) => {
                let mut clean_company: String = customer_name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>()
                    .to_ascii_uppercase();
                while clean_company.contains("__") {
                    clean_company = clean_company.replace("__", "_");
                }
                clean_company = clean_company.trim_matches('_').to_string();
                if clean_company.is_empty() {
                    clean_company = "LICENSED".into();
                }
                if clean_company.len() > 16 {
                    clean_company.truncate(16);
                }
                let licensed_code = format!("{}-{}", clean_company, clean_name);
                // Replace any stale TRIAL-* code cached before license activation
                {
                    let mut cfg = self.config.lock().await;
                    if cfg.host.host_code.trim().is_empty()
                        || cfg.host.host_code.starts_with("TRIAL-")
                    {
                        cfg.host.host_code = licensed_code.clone();
                        let _ = save_service_config(&cfg);
                    }
                }
                licensed_code
            }
            _ => {
                // Reuse persisted host_code if already generated so Session 0 (SYSTEM) and Session 1 (User) match!
                {
                    let cfg = self.config.lock().await;
                    if !cfg.host.host_code.trim().is_empty() {
                        return cfg.host.host_code.clone();
                    }
                }

                let hwid = self
                    .hwid_provider
                    .get_hardware_id()
                    .await
                    .map(|h| h.to_string())
                    .unwrap_or_else(|_| "T3-0000-0000-XXXX".into());
                let hwid_clean: String = hwid
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect();
                let suffix = if hwid_clean.len() >= 4 {
                    &hwid_clean[hwid_clean.len() - 4..]
                } else {
                    "T301"
                };
                format!("TRIAL-{}-{}", clean_name, suffix.to_ascii_uppercase())
            }
        }
    }

    async fn establish_host_runtime(self: &Arc<Self>, cfg: &ServiceConfig) -> Result<HostSnapshot, String> {
        if cfg.host.password_hash.is_empty() {
            return Err("Please set a Host Access Password before starting Host Server Mode.".into());
        }

        let code = if cfg.host.host_code.trim().is_empty()
            || cfg.host.host_code.starts_with("TRIAL-")
        {
            self.compute_host_code().await
        } else {
            cfg.host.host_code.clone()
        };

        let url = if cfg.host.signaling_url.trim().is_empty() {
            DEFAULT_SIGNALING_URL.to_string()
        } else {
            cfg.host.signaling_url.clone()
        };

        let resolved_share_name = if cfg.host.share_name.trim().is_empty() {
            "SharedData".to_string()
        } else {
            cfg.host.share_name.clone()
        };

        let resolved_share_path = if cfg.host.share_path.trim().is_empty() {
            r"C:\SharedData".to_string()
        } else {
            cfg.host.share_path.clone()
        };

        let client = Arc::new(WebSocketSignalingClient::new());
        client
            .connect(&url)
            .await
            .map_err(|e| format!("Failed to connect to signaling server ({}): {}", url, e))?;

        let hwid = self
            .hwid_provider
            .get_hardware_id()
            .await
            .map(|h| h.to_string())
            .unwrap_or_else(|_| "UNKNOWN_HWID".into());

        let reg_msg = SignalingMessage::RegisterNode {
            peer_id: code.clone(),
            role: PeerRole::HostServer,
            hardware_id: hwid,
            license_key: "T3-HOST-ACTIVE".into(),
        };

        let vip = client
            .register_node(reg_msg)
            .await
            .map_err(|e| format!("Registration failed on signaling server: {}", e))?;

        let _ = self.system.configure_firewall_rule("10.99.0.0/24").await;

        let shared_folder = PathBuf::from(&resolved_share_path);
        let _ = std::fs::create_dir_all(&shared_folder);

        let net_share_arg = format!("{}={}", resolved_share_name, resolved_share_path);
        let mut del_cmd = std::process::Command::new("net");
        #[cfg(windows)]
        del_cmd.creation_flags(0x08000000);
        let _ = del_cmd
            .args(["share", &resolved_share_name, "/delete", "/y"])
            .output();

        let mut cmd = std::process::Command::new("net");
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        let _ = cmd
            .args(["share", &net_share_arg, "/grant:Everyone,FULL", "/y"])
            .output();

        // Run icacls asynchronously so large shared folders never block StartHost IPC
        let icacls_path = resolved_share_path.clone();
        tokio::task::spawn_blocking(move || {
            let mut icacls_cmd = std::process::Command::new("icacls");
            #[cfg(windows)]
            icacls_cmd.creation_flags(0x08000000);
            let _ = icacls_cmd
                .args([
                    &icacls_path,
                    "/grant",
                    "Everyone:(OI)(CI)F",
                    "/T",
                    "/C",
                    "/Q",
                ])
                .output();
        });

        self.tunnel
            .start_adapter(VirtualIp::new("10.99.0.1", 24).unwrap())
            .await
            .map_err(|e| format!("Failed to start host virtual network adapter: {}", e))?;

        // Initialize single-socket STUN + WireGuard P2P UDP listener (auto-refreshes STUN every 25s)
        let (_initial_public_ep, _initial_local_cand) = self.tunnel.init_p2p_udp().await;
        let host_wg_pubkey = self.tunnel.local_wg_pubkey_b64();
        if let Some(bin_tx) = client.get_binary_sender().await {
            self.tunnel.set_binary_relay_channel(bin_tx);
        }
        if let Some(mut bin_rx) = client.take_binary_receiver().await {
            let tunnel_for_bin = Arc::clone(&self.tunnel);
            tokio::spawn(async move {
                while let Some(frame) = bin_rx.recv().await {
                    tunnel_for_bin.handle_inbound_binary_relay(&frame);
                }
            });
        }

        // Option 1: Prevent system sleep while hosting if enabled
        self.sleep_ctrl
            .set_prevent_sleep(cfg.prevent_sleep_while_hosting);

        let license_usecase = CheckLicenseStatusUseCase::new(
            Arc::clone(&self.hwid_provider),
            Arc::clone(&self.storage),
        );
        let license_status = license_usecase
            .execute()
            .await
            .unwrap_or(LicenseStatus::TrialExpired);
        let allowed_nodes: u32 = match license_status {
            LicenseStatus::Licensed { max_nodes, .. } => max_nodes,
            _ => 3,
        };
        *self.host_max_nodes.lock().await = allowed_nodes;
        self.host_connected_clients.lock().await.clear();

        let inbound_rx = client.take_inbound_receiver().await;
        let tunnel_for_host = Arc::clone(&self.tunnel);
        let system_for_host = Arc::clone(&self.system);
        let client_sender = client.get_sender().await;
        let share_for_pump = resolved_share_name.clone();
        let host_code_for_pump = code.clone();
        let host_clients_for_pump = Arc::clone(&self.host_connected_clients);
        let engine_weak = Arc::downgrade(self);
        let pump_gen = self.reconnect_gen.load(Ordering::SeqCst);

        if let (Some(mut rx), Some(tx)) = (inbound_rx, client_sender) {
            let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            tunnel_for_host.set_outbound_channel(out_tx);

            tokio::spawn(async move {
                let active_session = Arc::new(tokio::sync::Mutex::new(None::<String>));
                let active_sess_for_out = Arc::clone(&active_session);
                let tx_for_out = tx.clone();

                tokio::spawn(async move {
                    while let Some(packet) = out_rx.recv().await {
                        let sess = active_sess_for_out.lock().await.clone();
                        if let Some(session_id) = sess {
                            let _ = tx_for_out.send(SignalingMessage::RelayData {
                                session_id,
                                chunk: packet,
                            });
                        }
                    }
                });

                let mut authorized_tokens = HashSet::<String>::new();
                let mut pending_wg_peers = std::collections::HashMap::<
                    String,
                    (Option<String>, Option<String>, String, Option<String>),
                >::new();
                let mut vip_to_session = std::collections::HashMap::<String, String>::new();

                while let Some(msg) = rx.recv().await {
                    match msg {
                        SignalingMessage::RelayRequest {
                            target_peer_id: _,
                            session_id,
                        } => {
                            let matched_token = session_id
                                .strip_prefix("sess_tok_")
                                .map(|t| t.to_string());
                            let is_authenticated = if let Some(ref tok) = matched_token {
                                authorized_tokens.remove(tok)
                            } else {
                                let incoming_pwd = session_id
                                    .split_once("::AUTH_")
                                    .map(|(_, pwd)| pwd)
                                    .unwrap_or("");
                                let latest_cfg = load_service_config().unwrap_or_default();
                                if !latest_cfg.host.password_hash.is_empty() {
                                    hash_password_with_salt(incoming_pwd, &latest_cfg.host.salt)
                                        == latest_cfg.host.password_hash
                                } else {
                                    true
                                }
                            };

                            if !is_authenticated {
                                let _ = tx.send(SignalingMessage::RelayClose { session_id });
                                continue;
                            }

                            let mut clients = host_clients_for_pump.lock().await;
                            // If a reconnecting client already evicted its old session or if stale sessions accumulated,
                            // ensure we don't lock out an authenticated client due to ghost sessions.
                            if clients.len() as u32 >= allowed_nodes
                                && !clients.contains(&session_id)
                            {
                                if let Some(stale_sid) = clients.iter().next().cloned() {
                                    clients.remove(&stale_sid);
                                }
                            }
                            clients.insert(session_id.clone());
                            *active_session.lock().await = Some(session_id.clone());

                            // Register WireGuard (boringtun) P2P peer if client provided WG pubkey + VIP
                            if let Some(ref tok) = matched_token {
                                if let Some((
                                    Some(client_wg_pub),
                                    Some(client_vip_str),
                                    client_pub_ep,
                                    client_local_ep,
                                )) = pending_wg_peers.remove(tok)
                                {
                                    if let Some(old_sid) =
                                        vip_to_session.insert(client_vip_str.clone(), session_id.clone())
                                    {
                                        if old_sid != session_id {
                                            clients.remove(&old_sid);
                                        }
                                    }
                                    if let Ok(client_vip) =
                                        client_vip_str.parse::<std::net::Ipv4Addr>()
                                    {
                                        let candidates = t3_adapters::parse_endpoint_candidates(
                                            &client_pub_ep,
                                            client_local_ep.as_deref(),
                                        );
                                        let _ = tunnel_for_host
                                            .register_wg_peer(
                                                client_vip,
                                                session_id.clone(),
                                                &client_wg_pub,
                                                candidates,
                                                false,
                                            )
                                            .await;
                                    }
                                }
                            }

                            let _ = tx.send(SignalingMessage::RelayAccepted { session_id });
                        }
                        SignalingMessage::HolePunchOffer {
                            target_peer_id: _,
                            offer,
                        } => {
                            let parsed_offer =
                                t3_domain::parse_client_offer_meta(&offer.wireguard_pubkey);

                            let latest_cfg = load_service_config().unwrap_or_default();
                            let is_authenticated = if !latest_cfg.host.password_hash.is_empty() {
                                hash_password_with_salt(
                                    &parsed_offer.password,
                                    &latest_cfg.host.salt,
                                ) == latest_cfg.host.password_hash
                            } else {
                                true
                            };

                            if !is_authenticated {
                                let answer = HolePunchPayload {
                                    peer_id: host_code_for_pump.clone(),
                                    public_endpoint: "0.0.0.0:0".into(),
                                    wireguard_pubkey:
                                        "AUTH_FAILED:Incorrect Host Access Password".into(),
                                    local_candidate: None,
                                };
                                let _ = tx.send(SignalingMessage::HolePunchAnswer {
                                    target_peer_id: offer.peer_id,
                                    answer,
                                });
                                continue;
                            }

                            let token: String = (0..8)
                                .map(|_| format!("{:02x}", rand::random::<u8>()))
                                .collect();
                            let pre_session_id = format!("sess_tok_{}", token);
                            authorized_tokens.insert(token.clone());
                            pending_wg_peers.insert(
                                token.clone(),
                                (
                                    parsed_offer.wg_pubkey.clone(),
                                    parsed_offer.virtual_ip.clone(),
                                    offer.public_endpoint.clone(),
                                    offer.local_candidate.clone(),
                                ),
                            );

                            // Clean up any previous stale session from the same client virtual IP
                            if let Some(ref client_vip_str) = parsed_offer.virtual_ip {
                                if let Some(old_sid) = vip_to_session
                                    .insert(client_vip_str.clone(), pre_session_id.clone())
                                {
                                    host_clients_for_pump.lock().await.remove(&old_sid);
                                }
                            }

                            // Refresh STUN endpoint & immediately pre-register WireGuard peer + punch Host NAT
                            // BEFORE HolePunchAnswer reaches Client (eliminates 700ms RelayRequest race condition!)
                            let (fresh_public_ep, fresh_local_cand) =
                                tunnel_for_host.refresh_p2p_endpoints().await;

                            if let (Some(client_wg_pub), Some(client_vip_str)) =
                                (&parsed_offer.wg_pubkey, &parsed_offer.virtual_ip)
                            {
                                if let Ok(client_vip) =
                                    client_vip_str.parse::<std::net::Ipv4Addr>()
                                {
                                    let candidates = t3_adapters::parse_endpoint_candidates(
                                        &offer.public_endpoint,
                                        offer.local_candidate.as_deref(),
                                    );
                                    let _ = tunnel_for_host
                                        .register_wg_peer(
                                            client_vip,
                                            pre_session_id,
                                            client_wg_pub,
                                            candidates,
                                            false,
                                        )
                                        .await;
                                }
                            }

                            let mut local_shares = system_for_host
                                .list_local_shares()
                                .await
                                .unwrap_or_default();
                            if !share_for_pump.is_empty()
                                && !local_shares.contains(&share_for_pump)
                            {
                                local_shares.insert(0, share_for_pump.clone());
                            }
                            let shares_csv = local_shares.join(",");
                            let answer = HolePunchPayload {
                                peer_id: host_code_for_pump.clone(),
                                public_endpoint: fresh_public_ep,
                                wireguard_pubkey: t3_domain::format_host_answer_meta(
                                    &token,
                                    &host_wg_pubkey,
                                    &shares_csv,
                                ),
                                local_candidate: fresh_local_cand,
                            };
                            let _ = tx.send(SignalingMessage::HolePunchAnswer {
                                target_peer_id: offer.peer_id,
                                answer,
                            });
                        }
                        SignalingMessage::RelayData { session_id, chunk } => {
                            *active_session.lock().await = Some(session_id);
                            let _ = tunnel_for_host.inject_inbound_packet(&chunk);
                        }
                        SignalingMessage::RelayClose { session_id } => {
                            host_clients_for_pump.lock().await.remove(&session_id);
                            tunnel_for_host.remove_wg_peer_by_session(&session_id);
                            *active_session.lock().await = None;
                        }
                        _ => {}
                    }
                }

                // Signaling WebSocket closed unexpectedly — auto-reconnect if still in Host mode!
                if let Some(eng) = engine_weak.upgrade() {
                    if eng.reconnect_gen.load(Ordering::SeqCst) == pump_gen {
                        let current_mode = eng.config.lock().await.mode;
                        let current_phase = *eng.phase.lock().await;
                        if current_mode == ServiceMode::Host
                            && current_phase != ConnectionPhase::Suspended
                        {
                            eng.schedule_reconnect_loop("Host signaling stream dropped");
                        }
                    }
                }
            });
        }

        let detected_shares = self.system.list_local_shares().await.unwrap_or_default();
        *self.host_signaling.lock().await = Some(client);
        *self.phase.lock().await = ConnectionPhase::Connected;
        *self.host_status_message.lock().await = "Broadcasting on Cloud P2P Mesh".into();

        Ok(HostSnapshot {
            is_hosting: true,
            host_code: code,
            has_password: true,
            virtual_ip: Some(vip.addr().to_string()),
            signaling_url: url,
            message: "Broadcasting on Cloud P2P Mesh".into(),
            share_name: resolved_share_name,
            share_path: resolved_share_path,
            detected_shares,
            active_nodes: 0,
            max_nodes: allowed_nodes,
            transport_mode: TransportMode::Disconnected,
        })
    }

    async fn establish_client_runtime(
        self: &Arc<Self>,
        cfg: &ServiceConfig,
        password_override: Option<String>,
    ) -> Result<(String, bool, String, Vec<String>), String> {
        let license_check = CheckLicenseStatusUseCase::new(
            Arc::clone(&self.hwid_provider),
            Arc::clone(&self.storage),
        );
        match license_check.execute().await.map_err(|e| e.to_string())? {
            LicenseStatus::Licensed { .. } | LicenseStatus::TrialActive { .. } => {}
            LicenseStatus::TrialExpired => {
                return Err("Trial expired. Please activate a license.".into());
            }
            LicenseStatus::TrialTampered => {
                return Err(
                    "Trial verification failed (system clock or hardware ID mismatch). Please check PC date/time or activate a license."
                        .into(),
                );
            }
        }

        let host_input = cfg.client.target_peer_id.trim();
        if host_input.is_empty() {
            return Err("Please enter Server IP or Connect Code.".into());
        }

        let clean_pwd = if let Some(p) = password_override {
            p.trim().to_string()
        } else if let Some(cached) = self.active_client_password.lock().await.clone() {
            cached
        } else if !cfg.client.encrypted_password_b64.is_empty() {
            unprotect_secret(&cfg.client.encrypted_password_b64).unwrap_or_default()
        } else {
            String::new()
        };

        let active_signaling = if cfg.client.signaling_url.trim().is_empty() {
            DEFAULT_SIGNALING_URL.to_string()
        } else {
            cfg.client.signaling_url.clone()
        };

        let my_code = self.compute_host_code().await;
        let is_self_host = host_input.eq_ignore_ascii_case(&my_code)
            || host_input.eq_ignore_ascii_case("127.0.0.1")
            || host_input.eq_ignore_ascii_case("localhost");

        let (target_peer, server_ip, is_wan) = if is_self_host {
            if !cfg.host.password_hash.is_empty()
                && hash_password_with_salt(&clean_pwd, &cfg.host.salt) != cfg.host.password_hash
            {
                return Err("Authentication Failed: Incorrect Host Access Password".into());
            }
            let vip = VirtualIp::new("127.0.0.1", 24).map_err(|e| e.to_string())?;
            let peer = Peer::new(
                "127.0.0.1".into(),
                "Local Host Server (Loopback)".into(),
                PeerRole::HostServer,
                vip,
            );
            (peer, "127.0.0.1".to_string(), false)
        } else if let Ok(ip) = host_input.parse::<std::net::Ipv4Addr>() {
            let vip = VirtualIp::new(&ip.to_string(), 24).map_err(|e| e.to_string())?;
            let peer = Peer::new(
                host_input.to_string(),
                "LAN Server".into(),
                PeerRole::HostServer,
                vip,
            );
            (peer, ip.to_string(), false)
        } else {
            use std::net::ToSocketAddrs;
            let resolved = format!("{}:445", host_input)
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| {
                    a.find_map(|sa| {
                        if let std::net::SocketAddr::V4(v4) = sa {
                            Some(v4.ip().to_string())
                        } else {
                            None
                        }
                    })
                });

            if let Some(lan_ip) = resolved {
                let vip = VirtualIp::new(&lan_ip, 24).map_err(|e| e.to_string())?;
                let peer = Peer::new(
                    host_input.to_string(),
                    "LAN Host".into(),
                    PeerRole::HostServer,
                    vip,
                );
                (peer, host_input.to_string(), false)
            } else {
                // WAN Cloud Signaling
                let clean_code = host_input.to_uppercase();
                let client = Arc::new(WebSocketSignalingClient::new());
                client
                    .connect(&active_signaling)
                    .await
                    .map_err(|e| format!("Cannot reach signaling server: {}", e))?;

                let mut found_host = None;
                for attempt in 1..=3 {
                    match client.find_host(&clean_code).await {
                        Ok(h) => {
                            found_host = Some(h);
                            break;
                        }
                        Err(e) => {
                            if attempt < 3 {
                                tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                            } else {
                                return Err(format!("Host '{}' not online: {}", clean_code, e));
                            }
                        }
                    }
                }
                let _ = found_host.unwrap();

                let hwid = self
                    .hwid_provider
                    .get_hardware_id()
                    .await
                    .map(|h| h.to_string())
                    .unwrap_or_else(|_| "CLIENT_HWID".into());
                let client_node_id = format!("CLIENT-{}", &hwid[..8.min(hwid.len())]);

                let reg_msg = SignalingMessage::RegisterNode {
                    peer_id: client_node_id.clone(),
                    role: PeerRole::ClientNode,
                    hardware_id: hwid,
                    license_key: "T3-CLIENT-ACTIVE".into(),
                };
                let client_vip = client
                    .register_node(reg_msg)
                    .await
                    .map_err(|e| format!("Node registration failed: {}", e))?;

                let client_vip_str = client_vip.addr().to_string();
                self.tunnel
                    .start_adapter(client_vip)
                    .await
                    .map_err(|e| format!("Tunnel start failed: {}", e))?;

                // Initialize single-socket STUN + WireGuard P2P UDP listener
                let (client_public_ep, client_local_cand) = self.tunnel.init_p2p_udp().await;
                let client_wg_pubkey = self.tunnel.local_wg_pubkey_b64();
                if let Some(bin_tx) = client.get_binary_sender().await {
                    self.tunnel.set_binary_relay_channel(bin_tx);
                }
                if let Some(mut bin_rx) = client.take_binary_receiver().await {
                    let tunnel_for_bin = Arc::clone(&self.tunnel);
                    tokio::spawn(async move {
                        while let Some(frame) = bin_rx.recv().await {
                            tunnel_for_bin.handle_inbound_binary_relay(&frame);
                        }
                    });
                }

                let query_offer = HolePunchPayload {
                    peer_id: client_node_id.clone(),
                    public_endpoint: client_public_ep,
                    wireguard_pubkey: t3_domain::format_client_offer_meta(
                        &clean_pwd,
                        &client_wg_pubkey,
                        &client_vip_str,
                    ),
                    local_candidate: client_local_cand,
                };
                let _ = client
                    .send_message(SignalingMessage::HolePunchOffer {
                        target_peer_id: clean_code.clone(),
                        offer: query_offer,
                    })
                    .await;

                // Carries Ok((session_id, host_wg_pubkey, host_udp_candidates)) or Err(reason)
                type AuthOutcome =
                    Result<(String, Option<String>, Vec<std::net::SocketAddr>), String>;
                let (auth_tx, mut auth_rx) = tokio::sync::mpsc::channel::<AuthOutcome>(1);
                let auth_tx_clone = auth_tx.clone();
                let clean_pwd_fallback = clean_pwd.clone();

                let inbound_rx = client.take_inbound_receiver().await;
                let tunnel_for_client = Arc::clone(&self.tunnel);
                let client_sender = client.get_sender().await;
                let discovered_shares_ref = Arc::clone(&self.discovered_shares);
                let engine_weak = Arc::downgrade(self);
                let pump_gen = self.reconnect_gen.load(Ordering::SeqCst);

                if let Some(mut rx) = inbound_rx {
                    let tunnel_for_rx = Arc::clone(&tunnel_for_client);
                    tokio::spawn(async move {
                        while let Some(msg) = rx.recv().await {
                            match msg {
                                SignalingMessage::RelayData { chunk, .. } => {
                                    let _ = tunnel_for_rx.inject_inbound_packet(&chunk);
                                }
                                SignalingMessage::HolePunchAnswer { answer, .. } => {
                                    let parsed =
                                        t3_domain::parse_host_answer_meta(&answer.wireguard_pubkey);
                                    if let Some(err_msg) = parsed.auth_error {
                                        let _ = auth_tx_clone.send(Err(err_msg)).await;
                                    } else if let Some(tok) = parsed.token {
                                        *discovered_shares_ref.lock().await = parsed.shares;
                                        let candidates = t3_adapters::parse_endpoint_candidates(
                                            &answer.public_endpoint,
                                            answer.local_candidate.as_deref(),
                                        );
                                        let _ = auth_tx_clone
                                            .send(Ok((
                                                format!("sess_tok_{}", tok),
                                                parsed.wg_pubkey,
                                                candidates,
                                            )))
                                            .await;
                                    } else if !parsed.shares.is_empty()
                                        || answer.wireguard_pubkey.starts_with("SHARES:")
                                    {
                                        *discovered_shares_ref.lock().await = parsed.shares;
                                        let legacy_sid = format!(
                                            "sess_{}::AUTH_{}",
                                            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                                            clean_pwd_fallback
                                        );
                                        let _ = auth_tx_clone
                                            .send(Ok((legacy_sid, None, Vec::new())))
                                            .await;
                                    }
                                }
                                SignalingMessage::RelayClose { .. } => {
                                    let _ = auth_tx_clone
                                        .send(Err("Incorrect Host Access Password".to_string()))
                                        .await;
                                    break;
                                }
                                _ => {}
                            }
                        }

                        // Auto-reconnect if client signaling stream drops unexpectedly
                        if let Some(eng) = engine_weak.upgrade() {
                            if eng.reconnect_gen.load(Ordering::SeqCst) == pump_gen {
                                let current_mode = eng.config.lock().await.mode;
                                let current_phase = *eng.phase.lock().await;
                                if current_mode == ServiceMode::Client
                                    && current_phase != ConnectionPhase::Suspended
                                {
                                    eng.schedule_reconnect_loop("Client signaling stream dropped");
                                }
                            }
                        }
                    });
                }

                let (session_id, host_wg_pubkey, host_candidates) = match tokio::time::timeout(
                    tokio::time::Duration::from_millis(5000),
                    auth_rx.recv(),
                )
                .await
                {
                    Ok(Some(Ok(res))) => res,
                    Ok(Some(Err(e))) => {
                        let _ = client.disconnect().await;
                        let _ = self.tunnel.disconnect().await;
                        return Err(format!("Authentication Failed: {}", e));
                    }
                    Ok(None) | Err(_) => {
                        let _ = client.disconnect().await;
                        let _ = self.tunnel.disconnect().await;
                        return Err(format!("Host '{}' did not respond.", clean_code));
                    }
                };

                let _ = client
                    .send_message(SignalingMessage::RelayRequest {
                        target_peer_id: clean_code.clone(),
                        session_id: session_id.clone(),
                    })
                    .await;

                if let Some(host_pub_b64) = host_wg_pubkey {
                    // Register Host (10.99.0.1) as boringtun WireGuard peer & fire Direct UDP hole-punch + handshake
                    let _ = tunnel_for_client
                        .register_wg_peer(
                            std::net::Ipv4Addr::new(10, 99, 0, 1),
                            session_id.clone(),
                            &host_pub_b64,
                            host_candidates,
                            true,
                        )
                        .await;
                } else if let Some(tx) = client_sender {
                    // Legacy host fallback (JSON RelayData)
                    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    tunnel_for_client.set_outbound_channel(out_tx);
                    let sess_clone = session_id.clone();
                    tokio::spawn(async move {
                        while let Some(packet) = out_rx.recv().await {
                            let _ = tx.send(SignalingMessage::RelayData {
                                session_id: sess_clone.clone(),
                                chunk: packet,
                            });
                        }
                    });
                }

                *self.client_signaling.lock().await = Some(client);
                let server_vip = VirtualIp::new("10.99.0.1", 24).map_err(|e| e.to_string())?;
                let peer = Peer::new(
                    "10.99.0.1".into(),
                    "WAN Relay Server".into(),
                    PeerRole::HostServer,
                    server_vip,
                );
                (peer, "10.99.0.1".to_string(), true)
            }
        };

        if !is_wan {
            self.tunnel
                .start_adapter(target_peer.virtual_ip.clone())
                .await
                .map_err(|e| format!("Tunnel adapter failed: {}", e))?;
            self.tunnel
                .connect_peer(
                    &target_peer,
                    target_peer
                        .public_endpoint
                        .as_deref()
                        .unwrap_or("0.0.0.0:0"),
                )
                .await
                .map_err(|e| e.to_string())?;
        }

        *self.active_server_ip.lock().await = Some(server_ip.clone());
        *self.active_is_wan.lock().await = is_wan;
        *self.phase.lock().await = ConnectionPhase::Connected;
        *self.active_client_password.lock().await = Some(clean_pwd);

        let shares = if is_wan {
            self.discovered_shares.lock().await.clone()
        } else {
            self.system
                .list_remote_shares(&server_ip)
                .await
                .unwrap_or_default()
        };

        Ok((server_ip, is_wan, target_peer.peer_id, shares))
    }

    pub async fn get_snapshot(&self) -> ServiceSnapshot {
        let cfg = self.config.lock().await.clone();
        let phase = *self.phase.lock().await;
        // Keep Host toggle ON while connecting/reconnecting so brief mobile hotspot drops
        // do not visually flip the UI toggle off and back on.
        let is_hosting = cfg.mode == ServiceMode::Host
            && matches!(
                phase,
                ConnectionPhase::Connected
                    | ConnectionPhase::Connecting
                    | ConnectionPhase::Reconnecting
            );
        let is_client_connected =
            cfg.mode == ServiceMode::Client && phase == ConnectionPhase::Connected;

        let host_code = if !cfg.host.host_code.is_empty() {
            cfg.host.host_code.clone()
        } else {
            self.compute_host_code().await
        };

        let detected_shares = if is_hosting {
            self.system.list_local_shares().await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let active_nodes = self.host_connected_clients.lock().await.len() as u32;
        let host_transport_mode = if is_hosting && active_nodes > 0 {
            self.tunnel.active_transport_mode()
        } else {
            TransportMode::Disconnected
        };

        let host_snap = HostSnapshot {
            is_hosting,
            host_code,
            has_password: !cfg.host.password_hash.is_empty(),
            virtual_ip: if is_hosting {
                Some("10.99.0.1".into())
            } else {
                None
            },
            signaling_url: cfg.host.signaling_url.clone(),
            message: self.host_status_message.lock().await.clone(),
            share_name: cfg.host.share_name.clone(),
            share_path: cfg.host.share_path.clone(),
            detected_shares,
            active_nodes,
            max_nodes: *self.host_max_nodes.lock().await,
            transport_mode: host_transport_mode,
        };

        let (latency_ms, health_level, is_safe, alert_message) = if is_client_connected {
            let watchdog =
                NetworkWatchdogUseCase::new(Arc::clone(&self.tunnel) as Arc<dyn TunnelPort>);
            let report = watchdog.check_health().await.unwrap_or_else(|_| {
                t3_application::usecases::WatchdogReport {
                    health: ConnectionHealth::Optimal,
                    metrics: TunnelMetrics {
                        latency_ms: 15,
                        bytes_sent: 0,
                        bytes_received: 0,
                        packet_loss_percent: 0,
                    },
                    is_safe: true,
                    recommendation: None,
                }
            });
            (
                report.metrics.latency_ms,
                format!("{:?}", report.health),
                report.is_safe,
                report.recommendation,
            )
        } else {
            (0, "Dead".into(), true, None)
        };

        let status_text = match phase {
            ConnectionPhase::Connected => format!("Bridged ({})", health_level),
            ConnectionPhase::Connecting => "Connecting...".into(),
            ConnectionPhase::Reconnecting => format!(
                "Reconnecting (attempt {})...",
                self.reconnect_attempts.load(Ordering::SeqCst)
            ),
            ConnectionPhase::Suspended => "Paused (PC Sleep)".into(),
            ConnectionPhase::Disconnected => "Disconnected".into(),
        };

        let is_wan = *self.active_is_wan.lock().await;
        let client_transport_mode = if !is_client_connected {
            TransportMode::Disconnected
        } else if !is_wan {
            TransportMode::LanDirect
        } else {
            self.tunnel.active_transport_mode()
        };

        let client_snap = ClientSnapshot {
            is_tunnel_connected: is_client_connected,
            target_peer_id: if cfg.client.target_peer_id.is_empty() {
                None
            } else {
                Some(cfg.client.target_peer_id.clone())
            },
            server_ip: self.active_server_ip.lock().await.clone(),
            is_wan,
            discovered_shares: self.discovered_shares.lock().await.clone(),
            desired_share_name: cfg.client.share_name.clone(),
            desired_drive_letter: Some(cfg.client.drive_letter),
            latency_ms,
            health_level,
            is_safe,
            status_text,
            alert_message,
            transport_mode: client_transport_mode,
        };

        ServiceSnapshot {
            service_running: true,
            mode: cfg.mode,
            phase,
            auto_start_enabled: cfg.auto_start_enabled,
            prevent_sleep_while_hosting: cfg.prevent_sleep_while_hosting,
            sleep_prevented_active: self.sleep_ctrl.is_active(),
            host: host_snap,
            client: client_snap,
            last_event: self.last_event.lock().await.clone(),
            reconnect_attempts: self.reconnect_attempts.load(Ordering::SeqCst),
        }
    }

    pub async fn handle_request(self: &Arc<Self>, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::Ping => IpcResponse::Pong,
            IpcRequest::GetStatus => IpcResponse::Status(self.get_snapshot().await),
            IpcRequest::GetServiceConfig => {
                IpcResponse::ServiceConfig(self.config.lock().await.clone())
            }
            IpcRequest::GetHardwareId => match self.hwid_provider.get_hardware_id().await {
                Ok(h) => IpcResponse::HardwareId(h.to_string()),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            IpcRequest::GetLicenseInfo => match self.storage.load_license().await {
                Ok(lic) => IpcResponse::LicenseInfo(lic),
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            IpcRequest::GetLicenseStatus => {
                let uc = CheckLicenseStatusUseCase::new(
                    Arc::clone(&self.hwid_provider),
                    Arc::clone(&self.storage),
                );
                match uc.execute().await {
                    Ok(LicenseStatus::Licensed {
                        customer_name,
                        tier,
                        ..
                    }) => IpcResponse::LicenseStatus(LicenseSnapshot {
                        is_licensed: true,
                        is_trial: false,
                        is_expired: false,
                        customer_name: Some(customer_name),
                        tier: format!("{:?}", tier),
                        days_remaining: 0,
                        status_badge_text: "Licensed".into(),
                    }),
                    Ok(LicenseStatus::TrialActive { days_left }) => {
                        IpcResponse::LicenseStatus(LicenseSnapshot {
                            is_licensed: false,
                            is_trial: true,
                            is_expired: false,
                            customer_name: None,
                            tier: "Trial".into(),
                            days_remaining: days_left,
                            status_badge_text: format!("Trial ({} days left)", days_left),
                        })
                    }
                    Ok(LicenseStatus::TrialExpired) => {
                        IpcResponse::LicenseStatus(LicenseSnapshot {
                            is_licensed: false,
                            is_trial: true,
                            is_expired: true,
                            customer_name: None,
                            tier: "Trial Expired".into(),
                            days_remaining: 0,
                            status_badge_text: "Trial Expired".into(),
                        })
                    }
                    Ok(LicenseStatus::TrialTampered) => {
                        IpcResponse::LicenseStatus(LicenseSnapshot {
                            is_licensed: false,
                            is_trial: true,
                            is_expired: true,
                            customer_name: None,
                            tier: "Clock Tampered".into(),
                            days_remaining: 0,
                            status_badge_text: "Clock Error".into(),
                        })
                    }
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            IpcRequest::ActivateLicense { raw_key } => {
                let uc = ActivateLicenseUseCase::new(
                    Arc::clone(&self.verifier),
                    Arc::clone(&self.hwid_provider),
                    Arc::clone(&self.storage),
                );
                match uc.execute(&raw_key).await {
                    Ok(lic) => {
                        // Refresh cached host_code so TRIAL-* upgrades immediately to the licensed code
                        let new_code = self.compute_host_code().await;
                        let mut cfg = self.config.lock().await;
                        if cfg.host.host_code != new_code {
                            cfg.host.host_code = new_code;
                            let _ = save_service_config(&cfg);
                        }
                        IpcResponse::ActivatedLicense(lic)
                    }
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            IpcRequest::GetHostConfig => {
                let code = self.compute_host_code().await;
                let mut cfg = self.config.lock().await;
                if cfg.host.host_code.is_empty() || cfg.host.host_code != code {
                    cfg.host.host_code = code.clone();
                    let _ = save_service_config(&cfg);
                }
                IpcResponse::HostConfig {
                    host_code: code,
                    has_password: !cfg.host.password_hash.is_empty(),
                }
            }
            IpcRequest::SetHostPassword { password } => {
                let pwd = password.trim();
                if pwd.len() < 4 {
                    return IpcResponse::Error {
                        message: "Password must be at least 4 characters long.".into(),
                    };
                }
                let code = self.compute_host_code().await;
                let salt = generate_salt();
                let hash = hash_password_with_salt(pwd, &salt);
                let mut cfg = self.config.lock().await;
                cfg.host.host_code = code.clone();
                cfg.host.salt = salt;
                cfg.host.password_hash = hash;
                cfg.host.updated_at = chrono::Utc::now().timestamp();
                if let Err(e) = save_service_config(&cfg) {
                    return IpcResponse::Error { message: e };
                }
                IpcResponse::HostConfig {
                    host_code: code,
                    has_password: true,
                }
            }
            IpcRequest::StartHost {
                signaling_url,
                share_folder_path,
                share_name,
                auto_start,
            } => {
                self.reconnect_gen.fetch_add(1, Ordering::SeqCst);
                self.teardown_runtime_only().await;

                let code = self.compute_host_code().await;
                let updated_cfg = {
                    let mut cfg = self.config.lock().await;
                    if cfg.host.password_hash.is_empty() {
                        return IpcResponse::Error {
                            message: "Please set a Host Access Password before starting Host Server Mode.".into(),
                        };
                    }
                    cfg.mode = ServiceMode::Host;
                    if let Some(a) = auto_start {
                        cfg.auto_start_enabled = a;
                    } else {
                        cfg.auto_start_enabled = true;
                    }
                    cfg.host.host_code = code;
                    if let Some(u) = signaling_url.filter(|s| !s.trim().is_empty()) {
                        cfg.host.signaling_url = u;
                    }
                    if let Some(p) = share_folder_path.filter(|s| !s.trim().is_empty()) {
                        cfg.host.share_path = p;
                    }
                    if let Some(n) = share_name.filter(|s| !s.trim().is_empty()) {
                        cfg.host.share_name = n;
                    }
                    let _ = save_service_config(&cfg);
                    cfg.clone()
                };

                *self.phase.lock().await = ConnectionPhase::Connecting;
                match self.establish_host_runtime(&updated_cfg).await {
                    Ok(_) => {
                        self.log_event("Host Mode started & saved for Windows auto-start")
                            .await;
                        IpcResponse::Status(self.get_snapshot().await)
                    }
                    Err(e) => {
                        *self.phase.lock().await = ConnectionPhase::Disconnected;
                        *self.host_status_message.lock().await = "Offline (Error)".into();
                        IpcResponse::Error { message: e }
                    }
                }
            }
            IpcRequest::StopHost { clear_autostart } => {
                self.reconnect_gen.fetch_add(1, Ordering::SeqCst);
                self.teardown_runtime_only().await;
                *self.phase.lock().await = ConnectionPhase::Disconnected;
                *self.host_status_message.lock().await = "Offline".into();
                if clear_autostart {
                    let mut cfg = self.config.lock().await;
                    cfg.mode = ServiceMode::Idle;
                    let _ = save_service_config(&cfg);
                }
                self.log_event("Host Mode stopped by user").await;
                IpcResponse::Ok {
                    message: "Host stopped".into(),
                }
            }
            IpcRequest::ConnectClient {
                target_peer_id,
                password,
                signaling_url,
                share_name,
                drive_letter,
                remember_for_autostart,
            } => {
                self.reconnect_gen.fetch_add(1, Ordering::SeqCst);
                self.teardown_runtime_only().await;

                let clean_target = target_peer_id.trim().to_string();
                let clean_pwd = password.clone().unwrap_or_default().trim().to_string();

                let updated_cfg = {
                    let mut cfg = self.config.lock().await;
                    cfg.mode = ServiceMode::Client;
                    cfg.auto_start_enabled = remember_for_autostart;
                    cfg.client.target_peer_id = clean_target;
                    cfg.client.remember_credentials = remember_for_autostart;
                    if remember_for_autostart {
                        if let Ok(enc) = protect_secret(&clean_pwd) {
                            cfg.client.encrypted_password_b64 = enc;
                        }
                    } else {
                        cfg.client.encrypted_password_b64.clear();
                    }
                    if let Some(u) = signaling_url.filter(|s| !s.trim().is_empty()) {
                        cfg.client.signaling_url = u;
                    }
                    if let Some(s) = share_name.filter(|s| !s.trim().is_empty()) {
                        cfg.client.share_name = Some(s);
                    }
                    if let Some(d) = drive_letter {
                        cfg.client.drive_letter = d.to_ascii_uppercase();
                    }
                    let _ = save_service_config(&cfg);
                    cfg.clone()
                };

                *self.phase.lock().await = ConnectionPhase::Connecting;
                match self
                    .establish_client_runtime(&updated_cfg, Some(clean_pwd))
                    .await
                {
                    Ok((server_ip, is_wan, peer_id, discovered_shares)) => {
                        self.log_event(format!(
                            "Client connected to {} (auto-start={})",
                            updated_cfg.client.target_peer_id, remember_for_autostart
                        ))
                        .await;
                        IpcResponse::ClientConnected {
                            server_ip,
                            is_wan,
                            peer_id,
                            discovered_shares,
                        }
                    }
                    Err(e) => {
                        *self.phase.lock().await = ConnectionPhase::Disconnected;
                        IpcResponse::Error { message: e }
                    }
                }
            }
            IpcRequest::SetClientMountSelection {
                share_name,
                drive_letter,
            } => {
                let mut cfg = self.config.lock().await;
                cfg.client.share_name = Some(share_name.trim().to_string());
                cfg.client.drive_letter = drive_letter.to_ascii_uppercase();
                cfg.client.auto_mount = true;
                let _ = save_service_config(&cfg);
                IpcResponse::Ok {
                    message: "Mount selection saved".into(),
                }
            }
            IpcRequest::DisconnectClient { clear_autostart } => {
                self.reconnect_gen.fetch_add(1, Ordering::SeqCst);
                self.teardown_runtime_only().await;
                *self.phase.lock().await = ConnectionPhase::Disconnected;
                if clear_autostart {
                    let mut cfg = self.config.lock().await;
                    cfg.mode = ServiceMode::Idle;
                    let _ = save_service_config(&cfg);
                }
                self.log_event("Client disconnected by user").await;
                IpcResponse::Ok {
                    message: "Client disconnected".into(),
                }
            }
            IpcRequest::ListServerShares => {
                let server_ip = self.active_server_ip.lock().await.clone();
                let Some(ip) = server_ip else {
                    return IpcResponse::Error {
                        message: "Not connected to any server.".into(),
                    };
                };
                if ip == "10.99.0.1" {
                    for _ in 0..6 {
                        let s = self.discovered_shares.lock().await.clone();
                        if !s.is_empty() {
                            return IpcResponse::Shares(s);
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                    }
                }
                let shares = self
                    .system
                    .list_remote_shares(&ip)
                    .await
                    .unwrap_or_default();
                IpcResponse::Shares(shares)
            }
            IpcRequest::SetPreventSleep { enabled } => {
                let mut cfg = self.config.lock().await;
                cfg.prevent_sleep_while_hosting = enabled;
                let is_host_active =
                    cfg.mode == ServiceMode::Host && *self.phase.lock().await == ConnectionPhase::Connected;
                let _ = save_service_config(&cfg);
                self.sleep_ctrl.set_prevent_sleep(enabled && is_host_active);
                IpcResponse::Ok {
                    message: format!("Sleep prevention set to {}", enabled),
                }
            }
            IpcRequest::SetAutoStart { enabled } => {
                let mut cfg = self.config.lock().await;
                cfg.auto_start_enabled = enabled;
                let _ = save_service_config(&cfg);
                IpcResponse::Ok {
                    message: format!("Auto-start set to {}", enabled),
                }
            }
            IpcRequest::TriggerReconnect => {
                self.schedule_reconnect_loop("Manual reconnect requested");
                IpcResponse::Ok {
                    message: "Reconnect triggered".into(),
                }
            }
        }
    }
}

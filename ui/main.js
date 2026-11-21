// Tauri v2 IPC Bridge
const invoke = (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke)
  ? window.__TAURI__.core.invoke
  : (window.__TAURI__ && window.__TAURI__.invoke)
    ? window.__TAURI__.invoke
    : async (cmd, args) => {
  console.log(`[Mock Invoke] ${cmd}`, args);
  if (cmd === 'get_hardware_id') return "T3-D03F-944C-857E";
  if (cmd === 'get_license_status') return {
    is_licensed: false,
    is_trial: true,
    is_expired: false,
    customer_name: null,
    tier: "Trial",
    days_remaining: 7,
    status_badge_text: "Trial (7 days left)"
  };
  if (cmd === 'get_session_status') return {
    is_connected: false,
    drive_letter: null,
    mapped_unc: null,
    latency_ms: 0,
    status_text: "Disconnected",
    health_level: "Optimal",
    is_safe: true,
    alert_message: null
  };
  if (cmd === 'connect_bridge') return "Connected successfully!";
  if (cmd === 'disconnect_bridge') return true;
  return null;
};

// State
let isConnected = false;

// DOM Elements
const tabBtns = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');
const displayHwid = document.getElementById('displayHwid');
const btnCopyHwid = document.getElementById('btnCopyHwid');
const btnConnect = document.getElementById('btnConnect');
const btnDisconnect = document.getElementById('btnDisconnect');
const btnOpenFolder = document.getElementById('btnOpenFolder');
const appProfileSelect = document.getElementById('appProfileSelect');
const targetPeerId = document.getElementById('targetPeerId');
const driveLetter = document.getElementById('driveLetter');
const headerStatusBadge = document.getElementById('headerStatusBadge');
const statusText = document.getElementById('statusText');
const metricLatency = document.getElementById('metricLatency');
const metricHealth = document.getElementById('metricHealth');
const metricIp = document.getElementById('metricIp');
const metricPath = document.getElementById('metricPath');
const watchdogBanner = document.getElementById('watchdogBanner');
const watchdogIcon = document.getElementById('watchdogIcon');
const watchdogText = document.getElementById('watchdogText');
const btnActivateLicense = document.getElementById('btnActivateLicense');
const DEFAULT_SIGNALING_URL = 'wss://t3bridge-signaling.onrender.com';
const licenseInput = document.getElementById('licenseInput');
const licenseAlert = document.getElementById('licenseAlert');

// Trial & License DOM Elements
const headerTrialBadge = document.getElementById('headerTrialBadge');
const trialText = document.getElementById('trialText');
const trialExpiredBanner = document.getElementById('trialExpiredBanner');
const btnGoToLicense = document.getElementById('btnGoToLicense');
const displayLicenseTier = document.getElementById('displayLicenseTier');
const displayLicenseDetail = document.getElementById('displayLicenseDetail');

// Discovered Shares DOM Elements
const sharesCard = document.getElementById('sharesCard');
const sharesList = document.getElementById('sharesList');
const sharesCountBadge = document.getElementById('sharesCountBadge');
const customShareInput = document.getElementById('customShareInput');
const btnUseCustomShare = document.getElementById('btnUseCustomShare');
const btnMountShare = document.getElementById('btnMountShare');
let selectedShareName = null;

function selectShare(name) {
  selectedShareName = name;
  document.querySelectorAll('.share-card-item').forEach(card => {
    if (card.dataset.share === name) {
      card.classList.add('selected');
    } else {
      card.classList.remove('selected');
    }
  });
  if (customShareInput) {
    customShareInput.value = name;
  }
  const letter = driveLetter ? driveLetter.value : 'Z';
  if (btnMountShare) {
    btnMountShare.disabled = false;
    btnMountShare.textContent = `Map "${name}" to Drive ${letter}:`;
  }
}

function renderDiscoveredShares(shares) {
  if (!sharesList) return;
  sharesList.innerHTML = '';
  selectedShareName = null;
  if (btnMountShare) {
    btnMountShare.disabled = true;
    btnMountShare.textContent = "Select a Folder to Map";
  }

  if (!shares || shares.length === 0) {
    if (sharesCountBadge) {
      sharesCountBadge.textContent = "Suggested";
      sharesCountBadge.className = "badge-secondary";
    }
    sharesList.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 10px 14px; background: rgba(59, 130, 246, 0.1); border: 1px dashed rgba(59, 130, 246, 0.4); border-radius: 8px; color: #93c5fd; font-size: 12px; line-height: 1.5;">
        💡 <b>Click your shared folder below</b> or type its name in the box:
      </div>
      <div class="share-card-item" data-share="python">
        <span class="share-card-icon">📁</span>
        <div class="share-card-info">
          <span class="share-card-name">python</span>
          <span class="share-card-type">Suggested Share</span>
        </div>
      </div>
      <div class="share-card-item" data-share="SharedData">
        <span class="share-card-icon">📁</span>
        <div class="share-card-info">
          <span class="share-card-name">SharedData</span>
          <span class="share-card-type">Suggested Share</span>
        </div>
      </div>
      <div class="share-card-item" data-share="MargERP">
        <span class="share-card-icon">📁</span>
        <div class="share-card-info">
          <span class="share-card-name">MargERP</span>
          <span class="share-card-type">Suggested Share</span>
        </div>
      </div>
    `;
    sharesList.querySelectorAll('.share-card-item').forEach(card => {
      card.addEventListener('click', () => {
        selectShare(card.dataset.share);
      });
    });
    // Auto-select python by default so the Mount button is immediately ready
    selectShare("python");
    return;
  }

  if (sharesCountBadge) {
    sharesCountBadge.textContent = `${shares.length} folder${shares.length > 1 ? 's' : ''}`;
    sharesCountBadge.className = "badge-success";
  }

  shares.forEach(share => {
    const card = document.createElement('div');
    card.className = "share-card-item";
    card.dataset.share = share;
    card.innerHTML = `
      <span class="share-card-icon">📁</span>
      <div class="share-card-info">
        <span class="share-card-name">${share}</span>
        <span class="share-card-type">Shared Folder</span>
      </div>
    `;
    card.addEventListener('click', () => {
      selectShare(share);
    });
    sharesList.appendChild(card);
  });

  // Automatically select the first share
  if (shares.length > 0) {
    selectShare(shares[0]);
  }
}

if (customShareInput) {
  // Reactive typing: immediately update selected share as user types
  customShareInput.addEventListener('input', () => {
    const val = customShareInput.value.trim();
    if (val) {
      selectedShareName = val;
      const letter = driveLetter ? driveLetter.value : 'Z';
      if (btnMountShare) {
        btnMountShare.disabled = false;
        btnMountShare.textContent = `Map "${val}" to Drive ${letter}:`;
      }
    } else {
      selectedShareName = null;
      if (btnMountShare) {
        btnMountShare.disabled = true;
        btnMountShare.textContent = "Select a Folder to Map";
      }
    }
  });

  // Press Enter inside input to instantly mount
  customShareInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = customShareInput.value.trim();
      if (val) {
        selectShare(val);
        if (btnMountShare && !btnMountShare.disabled) {
          btnMountShare.click();
        }
      }
    }
  });
}

if (btnUseCustomShare && customShareInput) {
  btnUseCustomShare.addEventListener('click', () => {
    const val = customShareInput.value.trim();
    if (val) {
      selectShare(val);
    }
  });
}

if (driveLetter) {
  driveLetter.addEventListener('change', () => {
    const letter = driveLetter.value;
    if (selectedShareName && btnMountShare) {
      btnMountShare.textContent = `Map "${selectedShareName}" to Drive ${letter}:`;
    }
  });
}

// 1. Tab Switching
tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    tabPanes.forEach(p => p.classList.remove('active'));

    btn.classList.add('active');
    const target = btn.dataset.tab;
    document.getElementById(target).classList.add('active');
  });
});

// 2. Initial Setup: Load Hardware ID
async function loadHwid() {
  try {
    const hwid = await invoke('get_hardware_id');
    displayHwid.textContent = hwid;
  } catch (err) {
    displayHwid.textContent = "Error detecting HWID";
  }
}

// Copy HWID
btnCopyHwid.addEventListener('click', () => {
  navigator.clipboard.writeText(displayHwid.textContent);
  btnCopyHwid.textContent = "Copied!";
  setTimeout(() => btnCopyHwid.textContent = "Copy HWID", 2000);
});

// Connection Animation Elements
const connAnimPanel = document.getElementById('connectionAnimPanel');
const connLine = document.getElementById('connLine');
const dataPackets = document.getElementById('dataPackets');
const connEstablished = document.getElementById('connEstablished');
const connStatusText = document.getElementById('connStatusText');
const leftScreen = document.getElementById('leftScreen');
const rightScreen = document.getElementById('rightScreen');
const serverLed1 = document.getElementById('serverLed1');
const serverLed2 = document.getElementById('serverLed2');
const serverLed3 = document.getElementById('serverLed3');

function setAnimationIdle() {
  connAnimPanel.classList.remove('connecting', 'connected');
  connLine.setAttribute('class', '');
  connLine.setAttribute('stroke', '#1f293d');
  connLine.setAttribute('stroke-width', '2');
  connLine.setAttribute('stroke-dasharray', '8 6');
  dataPackets.style.display = 'none';
  connEstablished.style.display = 'none';
  connEstablished.setAttribute('class', '');
  connStatusText.textContent = 'AWAITING CONNECTION';
  connStatusText.setAttribute('class', '');
  leftScreen.setAttribute('class', '');
  rightScreen.setAttribute('class', '');
  serverLed1.setAttribute('class', '');
  serverLed2.setAttribute('class', '');
  serverLed3.setAttribute('class', '');
  serverLed1.setAttribute('fill', '#64748b');
  serverLed2.setAttribute('fill', '#64748b');
  serverLed3.setAttribute('fill', '#64748b');
}

function setAnimationConnecting() {
  connAnimPanel.classList.remove('connected');
  connAnimPanel.classList.add('connecting');
  connLine.setAttribute('class', 'conn-line-connecting');
  dataPackets.style.display = 'block';
  connEstablished.style.display = 'none';
  connStatusText.textContent = 'ESTABLISHING P2P BRIDGE...';
  connStatusText.setAttribute('class', 'status-text-connecting');
  leftScreen.setAttribute('class', 'screen-connecting');
  rightScreen.setAttribute('class', 'screen-connecting');
  serverLed1.setAttribute('class', 'led-active');
  serverLed2.setAttribute('class', 'led-active');
  serverLed2.style.animationDelay = '0.2s';
  serverLed3.setAttribute('class', 'led-active');
  serverLed3.style.animationDelay = '0.4s';
}

function setAnimationConnected() {
  connAnimPanel.classList.remove('connecting');
  connAnimPanel.classList.add('connected');
  connLine.setAttribute('class', 'conn-line-connected');
  dataPackets.style.display = 'none';
  connEstablished.style.display = 'block';
  connEstablished.setAttribute('class', 'checkmark-enter');
  connStatusText.textContent = '✓ CONNECTION ESTABLISHED';
  connStatusText.setAttribute('class', 'status-text-connected');
  leftScreen.setAttribute('class', 'screen-connected');
  rightScreen.setAttribute('class', 'screen-connected');
  serverLed1.setAttribute('class', 'led-connected');
  serverLed2.setAttribute('class', 'led-connected');
  serverLed3.setAttribute('class', 'led-connected');
}

// 3. Connect to Server & Discover Shares
btnConnect.addEventListener('click', async () => {
  const hostVal = targetPeerId.value.trim();
  if (!hostVal) {
    alert("Please enter the Office Server IP address or Connect Code (e.g. 192.168.1.100 or OFFICE-HO-01).");
    targetPeerId.focus();
    return;
  }

  btnConnect.disabled = true;
  btnConnect.textContent = "Connecting to Server...";

  // Start connecting animation
  setAnimationConnecting();
  if (sharesCard) sharesCard.style.display = "none";

  try {
    const activeSignaling = DEFAULT_SIGNALING_URL;

    // Phase 1: Establish tunnel / link
    const peerInfo = await invoke('connect_peer_only', {
      targetPeerId: hostVal,
      signalingUrl: activeSignaling
    });

    btnConnect.textContent = "Discovering Folders...";

    // Phase 2: Fetch list of shares from the server
    let shares = [];
    try {
      shares = await invoke('list_server_shares');
    } catch (e) {
      console.warn("list_server_shares warning:", e);
      shares = [];
    }

    if (sharesCard) {
      sharesCard.style.display = "block";
      renderDiscoveredShares(shares);
    }

    btnConnect.textContent = "✓ Server Connected";
    btnConnect.className = "btn btn-secondary";
  } catch (err) {
    setAnimationIdle();
    btnConnect.textContent = "Connect & View Folders";
    btnConnect.className = "btn btn-primary";
    alert(`Connection Error: ${err}`);
  } finally {
    btnConnect.disabled = false;
  }
});

// Map Selected Folder to Drive
if (btnMountShare) {
  btnMountShare.addEventListener('click', async () => {
    const shareToMount = selectedShareName || (customShareInput ? customShareInput.value.trim() : null);
    if (!shareToMount) {
      alert("Please select or enter a shared folder name first.");
      return;
    }

    btnMountShare.disabled = true;
    btnMountShare.textContent = `Mapping "${shareToMount}" to Drive ${driveLetter ? driveLetter.value : 'Z'}: ...`;

    try {
      const letter = driveLetter ? driveLetter.value : 'Z';
      await invoke('mount_selected_share', {
        shareName: shareToMount,
        driveLetter: letter
      });

      isConnected = true;
      const status = await invoke('get_session_status');
      setAnimationConnected();
      updateUiStatus(status);

      if (sharesCard) {
        sharesCard.style.display = "none";
      }
    } catch (err) {
      alert(`Mount Error:\n${err}\n\nPlease check:\n1. On Server PC: Ensure Host Mode is active and shows "Broadcasting on Cloud Mesh".\n2. Share Name: Verify the share "${shareToMount}" exists on the Host.`);
    } finally {
      btnMountShare.disabled = false;
      const letter = driveLetter ? driveLetter.value : 'Z';
      btnMountShare.textContent = selectedShareName
        ? `Map "${selectedShareName}" to Drive ${letter}:`
        : `Map Selected Folder to Drive ${letter}:`;
    }
  });
}

// 4. Disconnect Bridge
btnDisconnect.addEventListener('click', async () => {
  try {
    await invoke('disconnect_bridge');
    isConnected = false;
    selectedShareName = null;
    if (sharesCard) sharesCard.style.display = "none";
    btnConnect.textContent = "Connect & View Folders";
    btnConnect.className = "btn btn-primary";
    const status = await invoke('get_session_status');
    setAnimationIdle();
    updateUiStatus(status);
  } catch (err) {
    alert(`Disconnect Error: ${err}`);
  }
});

// Open Mapped Folder in Windows Explorer
if (btnOpenFolder) {
  btnOpenFolder.addEventListener('click', async () => {
    try {
      await invoke('open_folder', { driveLetter: driveLetter ? driveLetter.value : null });
    } catch (err) {
      alert(`Could not open folder in Explorer: ${err}`);
    }
  });
}

// 5. Activate License
btnActivateLicense.addEventListener('click', async () => {
  const key = licenseInput.value.trim();
  if (!key) return;

  try {
    const lic = await invoke('activate_license', { rawKey: key });
    licenseAlert.style.display = "block";
    licenseAlert.style.backgroundColor = "rgba(16, 185, 129, 0.2)";
    licenseAlert.style.color = "#10b981";
    licenseAlert.textContent = `License activated successfully for: ${lic.payload.customer_name}!`;
    await loadLicenseStatus();
  } catch (err) {
    licenseAlert.style.display = "block";
    licenseAlert.style.backgroundColor = "rgba(239, 68, 68, 0.2)";
    licenseAlert.style.color = "#ef4444";
    licenseAlert.textContent = `Activation Failed: ${err}`;
  }
});

// Load License & 7-Day Trial Status
async function loadLicenseStatus() {
  try {
    const status = await invoke('get_license_status');
    if (!status) return;

    if (status.is_licensed) {
      headerTrialBadge.className = "trial-badge licensed";
      trialText.textContent = "Licensed";
      trialExpiredBanner.style.display = "none";
      if (displayLicenseTier) {
        displayLicenseTier.textContent = `${status.tier} (${status.customer_name || 'Active'})`;
        displayLicenseTier.className = "tier-pill licensed";
        displayLicenseDetail.textContent = "Commercial license active with unrestricted P2P access.";
      }
      btnConnect.disabled = false;
    } else if (status.is_trial && !status.is_expired) {
      headerTrialBadge.className = "trial-badge";
      trialText.textContent = `Trial (${status.days_remaining}d left)`;
      trialExpiredBanner.style.display = "none";
      if (displayLicenseTier) {
        displayLicenseTier.textContent = `Free Trial (${status.days_remaining} days left)`;
        displayLicenseTier.className = "tier-pill";
        displayLicenseDetail.textContent = "7-day free evaluation period active with full feature access.";
      }
      btnConnect.disabled = false;
    } else {
      headerTrialBadge.className = "trial-badge expired";
      trialText.textContent = "Trial Expired";
      trialExpiredBanner.style.display = "flex";
      if (displayLicenseTier) {
        displayLicenseTier.textContent = "Trial Expired";
        displayLicenseTier.className = "tier-pill expired";
        displayLicenseDetail.textContent = "Your 7-day free trial has expired. Activate a license to continue using t3Bridge.";
      }
      btnConnect.disabled = true;
    }
  } catch (err) {
    console.error("License status check error", err);
  }
}

if (btnGoToLicense) {
  btnGoToLicense.addEventListener('click', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    tabPanes.forEach(p => p.classList.remove('active'));
    const licTab = document.querySelector('[data-tab="tab-license"]');
    if (licTab) licTab.classList.add('active');
    document.getElementById('tab-license').classList.add('active');
  });
}

function updateUiStatus(status) {
  const connected = status.is_connected;
  const dot = headerStatusBadge.querySelector('.status-dot');
  metricHealth.className = "metric-value";

  if (connected) {
    dot.className = "status-dot connected";
    statusText.textContent = `Bridged (${status.drive_letter || 'Z'}:)`;
    btnConnect.style.display = "none";
    btnDisconnect.style.display = "inline-block";
    if (btnOpenFolder) {
      btnOpenFolder.style.display = "inline-block";
      btnOpenFolder.textContent = `📂 Open Folder (${status.drive_letter || 'Z'}:)`;
    }
    metricLatency.textContent = `${status.latency_ms} ms`;
    metricIp.textContent = status.target_ip || "10.99.0.1";
    metricPath.textContent = status.mapped_unc || `${status.drive_letter || 'Z'}:`;

    metricHealth.textContent = status.health_level || "Optimal";
    if (status.health_level === "Optimal") metricHealth.classList.add("health-optimal");
    else if (status.health_level === "Acceptable") metricHealth.classList.add("health-acceptable");
    else if (status.health_level === "Degraded") metricHealth.classList.add("health-degraded");
    else metricHealth.classList.add("health-unstable");

    // Sync animation to connected state
    if (!connAnimPanel.classList.contains('connected')) {
      setAnimationConnected();
    }

    if (status.alert_message) {
      watchdogBanner.style.display = "flex";
      watchdogText.textContent = status.alert_message;
      if (status.is_safe) {
        watchdogBanner.className = "watchdog-banner warning";
        watchdogIcon.textContent = "ℹ️";
      } else {
        watchdogBanner.className = "watchdog-banner critical";
        watchdogIcon.textContent = "⚠️";
      }
    } else {
      watchdogBanner.style.display = "none";
    }
  } else {
    dot.className = "status-dot disconnected";
    statusText.textContent = "Disconnected";
    btnConnect.style.display = "inline-block";
    btnDisconnect.style.display = "none";
    if (btnOpenFolder) btnOpenFolder.style.display = "none";
    metricLatency.textContent = "-- ms";
    metricHealth.textContent = "--";
    metricIp.textContent = "--";
    metricPath.textContent = "None";
    watchdogBanner.style.display = "none";

    // Sync animation to idle state
    if (connAnimPanel.classList.contains('connected') || connAnimPanel.classList.contains('connecting')) {
      setAnimationIdle();
    }
  }
}

// 6. Polling Status from Rust Backend
setInterval(async () => {
  try {
    const status = await invoke('get_session_status');
    isConnected = status.is_connected;
    updateUiStatus(status);
  } catch (err) {
    // Ignore offline poll errors
  }
  try {
    await loadHostStatus();
  } catch (err) {
    // Ignore host poll errors
  }
}, 2500);

// 7. Host / Office Server Mode Handler
const toggleHostMode = document.getElementById('toggleHostMode');
const hostConnectCodeInput = document.getElementById('hostConnectCodeInput');
const hostStatusBadge = document.getElementById('hostStatusBadge');
const btnCopyHostCode = document.getElementById('btnCopyHostCode');
const hostActiveSharesContainer = document.getElementById('hostActiveSharesContainer');

if (btnCopyHostCode && hostConnectCodeInput) {
  btnCopyHostCode.addEventListener('click', () => {
    navigator.clipboard.writeText(hostConnectCodeInput.value.trim());
    btnCopyHostCode.textContent = "Copied!";
    setTimeout(() => { btnCopyHostCode.textContent = "Copy Code"; }, 2000);
  });
}

function renderHostShares(shares) {
  if (!hostActiveSharesContainer) return;
  hostActiveSharesContainer.innerHTML = '';
  if (!shares || shares.length === 0) {
    hostActiveSharesContainer.innerHTML = '<span class="badge-secondary">None detected (C:\\SharedData active)</span>';
    return;
  }
  shares.forEach(s => {
    const chip = document.createElement('span');
    chip.className = 'badge-success';
    chip.style.cssText = 'padding: 4px 10px; font-size: 12px; display: inline-flex; align-items: center; gap: 4px;';
    chip.innerHTML = `📁 <strong>${s}</strong>`;
    hostActiveSharesContainer.appendChild(chip);
  });
}

if (toggleHostMode) {
  toggleHostMode.addEventListener('change', async () => {
    if (toggleHostMode.checked) {
      const code = hostConnectCodeInput ? hostConnectCodeInput.value.trim().toUpperCase() : "OFFICE-HQ-01";
      const signalingUrl = DEFAULT_SIGNALING_URL;

      try {
        hostStatusBadge.textContent = "Connecting to Cloud Mesh...";
        hostStatusBadge.className = "badge-secondary";
        const res = await invoke('start_host_mode', {
          connectCode: code,
          signalingUrl: signalingUrl,
          shareFolderPath: null,
          shareName: null,
        });
        hostStatusBadge.textContent = "● Broadcasting on Cloud Mesh (" + res.host_code + ")";
        hostStatusBadge.className = "badge-success";
        renderHostShares(res.detected_shares);
        if (hostActiveNodesBadge) {
          const act = res.active_nodes || 0;
          const max = res.max_nodes || 3;
          hostActiveNodesBadge.textContent = `${act} / ${max} Nodes Connected`;
          hostActiveNodesBadge.className = "badge-success";
        }
      } catch (err) {
        toggleHostMode.checked = false;
        hostStatusBadge.textContent = "Offline (Error)";
        hostStatusBadge.className = "badge-danger";
        if (hostActiveNodesBadge) {
          hostActiveNodesBadge.textContent = "0 / 3 Nodes (Offline)";
          hostActiveNodesBadge.className = "badge-secondary";
        }
        alert("Failed to start Host Server Mode: " + err);
      }
    } else {
      try {
        await invoke('stop_host_mode');
        hostStatusBadge.textContent = "Offline (Toggle to Start)";
        hostStatusBadge.className = "badge-secondary";
        if (hostActiveNodesBadge) {
          hostActiveNodesBadge.textContent = "0 / 3 Nodes (Offline)";
          hostActiveNodesBadge.className = "badge-secondary";
        }
        if (hostActiveSharesContainer) {
          hostActiveSharesContainer.innerHTML = '<span class="badge-secondary">Auto-detected when host starts</span>';
        }
      } catch (err) {
        console.error(err);
      }
    }
  });
}

// Auto-Update and Node Badge Elements
const CURRENT_APP_VERSION = "0.1.0";
const updateBanner = document.getElementById('updateBanner');
const updateVersionTitle = document.getElementById('updateVersionTitle');
const updateNotes = document.getElementById('updateNotes');
const btnDownloadUpdate = document.getElementById('btnDownloadUpdate');
const btnDismissUpdate = document.getElementById('btnDismissUpdate');
const hostActiveNodesBadge = document.getElementById('hostActiveNodesBadge');

let latestDownloadUrl = 'https://github.com/t3bridge/t3SharePlus/releases/latest';

if (btnDismissUpdate && updateBanner) {
  btnDismissUpdate.addEventListener('click', () => {
    updateBanner.style.display = 'none';
  });
}

if (btnDownloadUpdate) {
  btnDownloadUpdate.addEventListener('click', async () => {
    try {
      await invoke('open_external_url', { url: latestDownloadUrl });
    } catch (_) {
      window.open(latestDownloadUrl, '_blank');
    }
  });
}

async function checkForUpdates() {
  try {
    const res = await fetch('https://t3bridge-signaling.onrender.com/api/version');
    if (!res.ok) return;
    const data = await res.json();
    if (data.version && data.version !== CURRENT_APP_VERSION) {
      if (updateBanner && updateVersionTitle) {
        updateVersionTitle.textContent = `New Version ${data.version} Available!`;
        if (updateNotes) updateNotes.textContent = data.release_notes || 'Improvements & bug fixes.';
        if (data.download_url) latestDownloadUrl = data.download_url;
        updateBanner.style.display = 'flex';
      }
    }
  } catch (_) {
    // Silent fail if offline or rendering sleeping
  }
}

// Initialize on page load
loadHwid();
loadLicenseStatus();
loadHostStatus();
checkForUpdates();

// Check for updates every 30 minutes in background
setInterval(checkForUpdates, 30 * 60 * 1000);

async function loadHostStatus() {
  try {
    const status = await invoke('get_host_status');
    if (toggleHostMode && hostStatusBadge) {
      toggleHostMode.checked = status.is_hosting;
      if (status.is_hosting) {
        hostStatusBadge.textContent = "● " + status.message + " (" + status.host_code + ")";
        hostStatusBadge.className = status.message.toLowerCase().includes("broadcasting") ? "badge-success" : "badge-secondary";
        renderHostShares(status.detected_shares);
        if (hostActiveNodesBadge) {
          const act = status.active_nodes || 0;
          const max = status.max_nodes || 3;
          hostActiveNodesBadge.textContent = `${act} / ${max} Nodes Connected`;
          hostActiveNodesBadge.className = act >= max ? "badge-secondary" : "badge-success";
        }
      } else {
        hostStatusBadge.textContent = "Offline (Toggle to Start)";
        hostStatusBadge.className = "badge-secondary";
        if (hostActiveNodesBadge) {
          hostActiveNodesBadge.textContent = "0 / 3 Nodes (Offline)";
          hostActiveNodesBadge.className = "badge-secondary";
        }
      }
    }
  } catch (err) {
    console.error("loadHostStatus error:", err);
  }
}

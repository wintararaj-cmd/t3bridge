// Tauri v2 IPC Bridge
const invoke = window.__TAURI__ ? window.__TAURI__.core.invoke : async (cmd, args) => {
  console.log(`[Mock Invoke] ${cmd}`, args);
  if (cmd === 'get_hardware_id') return "T3-D03F-944C-857E";
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
const licenseInput = document.getElementById('licenseInput');
const licenseAlert = document.getElementById('licenseAlert');

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

// 3. Connect Bridge
btnConnect.addEventListener('click', async () => {
  btnConnect.disabled = true;
  btnConnect.textContent = "Connecting...";

  try {
    const res = await invoke('connect_bridge', {
      targetPeerId: targetPeerId.value.trim(),
      appId: appProfileSelect.value,
      driveLetter: driveLetter.value
    });

    isConnected = true;
    const status = await invoke('get_session_status');
    updateUiStatus(status);
  } catch (err) {
    alert(`Connection Error: ${err}`);
  } finally {
    btnConnect.disabled = false;
    btnConnect.textContent = "Connect Bridge";
  }
});

// 4. Disconnect Bridge
btnDisconnect.addEventListener('click', async () => {
  try {
    await invoke('disconnect_bridge');
    isConnected = false;
    const status = await invoke('get_session_status');
    updateUiStatus(status);
  } catch (err) {
    alert(`Disconnect Error: ${err}`);
  }
});

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
  } catch (err) {
    licenseAlert.style.display = "block";
    licenseAlert.style.backgroundColor = "rgba(239, 68, 68, 0.2)";
    licenseAlert.style.color = "#ef4444";
    licenseAlert.textContent = `Activation Failed: ${err}`;
  }
});

function updateUiStatus(status) {
  const connected = status.is_connected;
  const dot = headerStatusBadge.querySelector('.status-dot');
  metricHealth.className = "metric-value";

  if (connected) {
    dot.className = "status-dot connected";
    statusText.textContent = `Bridged (${status.drive_letter || 'Z'}:)`;
    btnConnect.style.display = "none";
    btnDisconnect.style.display = "inline-block";
    metricLatency.textContent = `${status.latency_ms} ms`;
    metricIp.textContent = "10.99.0.1";
    metricPath.textContent = `${status.drive_letter || 'Z'}: -> SharedData`;

    metricHealth.textContent = status.health_level || "Optimal";
    if (status.health_level === "Optimal") metricHealth.classList.add("health-optimal");
    else if (status.health_level === "Acceptable") metricHealth.classList.add("health-acceptable");
    else if (status.health_level === "Degraded") metricHealth.classList.add("health-degraded");
    else metricHealth.classList.add("health-unstable");

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
    metricLatency.textContent = "-- ms";
    metricHealth.textContent = "--";
    metricIp.textContent = "--";
    metricPath.textContent = "None";
    watchdogBanner.style.display = "none";
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
}, 2500);

// Initialize on page load
loadHwid();

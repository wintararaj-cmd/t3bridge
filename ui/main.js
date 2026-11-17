// Tauri v2 IPC Bridge
const invoke = window.__TAURI__ ? window.__TAURI__.core.invoke : async (cmd, args) => {
  console.log(`[Mock Invoke] ${cmd}`, args);
  if (cmd === 'get_hardware_id') return "T3-A1B2-C3D4";
  if (cmd === 'get_session_status') return { is_connected: false, drive_letter: null, mapped_unc: null, latency_ms: 0, status_text: "Disconnected" };
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
const metricIp = document.getElementById('metricIp');
const metricPath = document.getElementById('metricPath');
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
    updateUiStatus(true, driveLetter.value);
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
    updateUiStatus(false);
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

function updateUiStatus(connected, letter = null) {
  const dot = headerStatusBadge.querySelector('.status-dot');
  if (connected) {
    dot.className = "status-dot connected";
    statusText.textContent = `Bridged (${letter || 'Z'}:)`;
    btnConnect.style.display = "none";
    btnDisconnect.style.display = "inline-block";
    metricLatency.textContent = "18 ms";
    metricIp.textContent = "10.99.0.1";
    metricPath.textContent = `${letter || 'Z'}: -> SharedData`;
  } else {
    dot.className = "status-dot disconnected";
    statusText.textContent = "Disconnected";
    btnConnect.style.display = "inline-block";
    btnDisconnect.style.display = "none";
    metricLatency.textContent = "-- ms";
    metricIp.textContent = "--";
    metricPath.textContent = "None";
  }
}

// 6. Polling Status from Rust Backend
setInterval(async () => {
  try {
    const status = await invoke('get_session_status');
    if (status.is_connected !== isConnected) {
      isConnected = status.is_connected;
      updateUiStatus(isConnected, status.drive_letter);
    }
    if (isConnected && status.latency_ms > 0) {
      metricLatency.textContent = `${status.latency_ms} ms`;
    }
  } catch (err) {
    // Ignore offline poll errors
  }
}, 3000);

// Initialize on page load
loadHwid();

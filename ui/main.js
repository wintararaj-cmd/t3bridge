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

// Trial & License DOM Elements
const headerTrialBadge = document.getElementById('headerTrialBadge');
const trialText = document.getElementById('trialText');
const trialExpiredBanner = document.getElementById('trialExpiredBanner');
const btnGoToLicense = document.getElementById('btnGoToLicense');
const displayLicenseTier = document.getElementById('displayLicenseTier');
const displayLicenseDetail = document.getElementById('displayLicenseDetail');

// Custom Profile Elements
const btnToggleNewProfile = document.getElementById('btnToggleNewProfile');
const newProfileContainer = document.getElementById('newProfileContainer');
const btnCloseProfileBox = document.getElementById('btnCloseProfileBox');
const newProfileName = document.getElementById('newProfileName');
const newProfileShare = document.getElementById('newProfileShare');
const btnSaveCustomProfile = document.getElementById('btnSaveCustomProfile');
const btnDeleteProfile = document.getElementById('btnDeleteProfile');

// Default Profiles
const defaultProfiles = [
  { id: "primary_erp", name: "Primary Business ERP (Database & Share)", share: "SharedData" },
  { id: "branch_share", name: "Branch Accounting & Document Share", share: "BranchData" },
  { id: "smb_share", name: "General SMB Network Share", share: "Share" },
];

function getCustomProfiles() {
  try {
    return JSON.parse(localStorage.getItem('t3_custom_profiles')) || [];
  } catch {
    return [];
  }
}

function saveCustomProfiles(profiles) {
  localStorage.setItem('t3_custom_profiles', JSON.stringify(profiles));
}

function renderProfiles(selectedId = null) {
  const customs = getCustomProfiles();
  const allProfiles = [...defaultProfiles, ...customs];

  appProfileSelect.innerHTML = '';
  allProfiles.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.isCustom ? `${p.name} (Custom)` : p.name;
    opt.dataset.isCustom = p.isCustom ? "true" : "false";
    opt.dataset.share = p.share || "SharedData";
    opt.dataset.name = p.name;
    appProfileSelect.appendChild(opt);
  });

  if (selectedId && allProfiles.some(p => p.id === selectedId)) {
    appProfileSelect.value = selectedId;
  }

  updateProfileButtons();
}

function updateProfileButtons() {
  const selectedOpt = appProfileSelect.options[appProfileSelect.selectedIndex];
  if (selectedOpt && selectedOpt.dataset.isCustom === "true") {
    btnDeleteProfile.style.display = "inline-block";
  } else {
    btnDeleteProfile.style.display = "none";
  }
}

appProfileSelect.addEventListener('change', updateProfileButtons);

btnToggleNewProfile.addEventListener('click', () => {
  newProfileContainer.style.display = newProfileContainer.style.display === "none" ? "block" : "none";
  if (newProfileContainer.style.display === "block") {
    newProfileName.focus();
  }
});

btnCloseProfileBox.addEventListener('click', () => {
  newProfileContainer.style.display = "none";
});

btnSaveCustomProfile.addEventListener('click', () => {
  const name = newProfileName.value.trim();
  const share = newProfileShare.value.trim() || "SharedData";

  if (!name) {
    alert("Please enter an Application Name (e.g. 'My Godown Inventory')");
    return;
  }

  const customs = getCustomProfiles();
  const id = `custom_${Date.now()}`;
  customs.push({ id, name, share, isCustom: true });
  saveCustomProfiles(customs);

  newProfileName.value = '';
  newProfileShare.value = 'SharedData';
  newProfileContainer.style.display = "none";

  renderProfiles(id);
});

btnDeleteProfile.addEventListener('click', () => {
  const selectedId = appProfileSelect.value;
  if (!confirm("Are you sure you want to remove this custom profile?")) return;

  const customs = getCustomProfiles().filter(p => p.id !== selectedId);
  saveCustomProfiles(customs);
  renderProfiles("primary_erp");
});

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
    const selectedOpt = appProfileSelect.options[appProfileSelect.selectedIndex];
    const isCustom = selectedOpt && selectedOpt.dataset.isCustom === "true";
    const customName = isCustom ? selectedOpt.dataset.name : null;
    const customShare = isCustom ? selectedOpt.dataset.share : null;

    const res = await invoke('connect_bridge', {
      targetPeerId: targetPeerId.value.trim(),
      appId: appProfileSelect.value,
      customName: customName,
      customShare: customShare,
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
renderProfiles();
loadHwid();
loadLicenseStatus();

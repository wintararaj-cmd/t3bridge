use base64::prelude::*;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::sync::Mutex;
use t3_domain::entity::license::{License, LicensePayload, LicenseTier};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_PRIVATE_KEY_BYTES: [u8; 32] = [
    30, 34, 161, 125, 224, 57, 56, 44, 48, 112, 68, 79, 130, 226, 85, 166, 247, 243, 196, 127,
    211, 251, 138, 113, 158, 142, 63, 188, 51, 188, 178, 154,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedLicenseRecord {
    pub license_id: String,
    pub customer_name: String,
    pub hardware_id: String,
    pub max_nodes: u32,
    pub tier: String,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub license_json: String,
}

static LICENSE_HISTORY: Mutex<Vec<IssuedLicenseRecord>> = Mutex::new(Vec::new());

fn get_admin_secret() -> String {
    env::var("ADMIN_SECRET").unwrap_or_else(|_| "t3master2026".to_string())
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut arr = [0u8; 32];
    for i in 0..32 {
        arr[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(arr)
}

fn get_signing_key() -> SigningKey {
    // 1. Check MASTER_PRIVATE_KEY env var
    if let Ok(val) = env::var("MASTER_PRIVATE_KEY") {
        if let Some(arr) = decode_hex_32(&val) {
            return SigningKey::from_bytes(&arr);
        }
        if let Ok(bytes) = BASE64_STANDARD.decode(val.trim().as_bytes()) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return SigningKey::from_bytes(&arr);
            }
        }
    }

    // 2. Check local file master_private.key
    if let Ok(bytes) = std::fs::read("master_private.key") {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return SigningKey::from_bytes(&arr);
        }
    }

    // 3. Built-in default keypair fallback
    SigningKey::from_bytes(&DEFAULT_PRIVATE_KEY_BYTES)
}

fn random_id_suffix() -> String {
    let mut rng = rand::thread_rng();
    let num: u32 = rng.gen_range(100000..999999);
    format!("{:06X}", num)
}

#[derive(Deserialize)]
struct IssueLicenseReq {
    customer_name: String,
    hardware_id: String,
    max_nodes: Option<u32>,
    days: Option<i64>,
    tier: Option<String>,
    passcode: Option<String>,
}

pub async fn handle_http(mut stream: TcpStream, addr: SocketAddr) {
    let mut buf = Vec::with_capacity(8192);
    let mut temp = [0u8; 2048];

    // Read full HTTP request headers
    let header_end_pos;
    loop {
        match stream.read(&mut temp).await {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&temp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end_pos = pos + 4;
                    break;
                }
                if buf.len() > 65536 {
                    return; // Request too large
                }
            }
            Err(_) => return,
        }
    }

    let header_str = String::from_utf8_lossy(&buf[..header_end_pos]);
    let first_line = header_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    println!("[HTTP] {} {} from {}", method, path, addr);

    if method == "OPTIONS" {
        let resp = "HTTP/1.1 200 OK\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
Content-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        return;
    }

    if path == "/api/version" {
        let latest_version = env::var("LATEST_VERSION").unwrap_or_else(|_| "0.1.0".into());
        let release_notes = env::var("RELEASE_NOTES").unwrap_or_else(|_| {
            "Official Release: WAN P2P mesh relay, persistent trial, and sleep prevention.".into()
        });
        let download_url = env::var("DOWNLOAD_URL").unwrap_or_else(|_| {
            "https://github.com/t3bridge/t3SharePlus/releases/latest".into()
        });

        let body = serde_json::json!({
            "version": latest_version,
            "release_notes": release_notes,
            "download_url": download_url,
            "mandatory": false,
            "pub_date": Utc::now().to_rfc3339()
        })
        .to_string();

        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        return;
    }

    if path == "/admin" || path == "/admin/" {
        let html = get_admin_dashboard_html();
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        return;
    }

    if path == "/api/admin/issue" && method == "POST" {
        // Read Content-Length
        let content_len = header_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);

        let mut body_bytes = buf[header_end_pos..].to_vec();
        while body_bytes.len() < content_len {
            match stream.read(&mut temp).await {
                Ok(0) => break,
                Ok(n) => body_bytes.extend_from_slice(&temp[..n]),
                Err(_) => break,
            }
        }

        let req: IssueLicenseReq = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => {
                send_json_error(
                    &mut stream,
                    400,
                    &format!("Invalid JSON request payload: {}", e),
                )
                .await;
                return;
            }
        };

        // Authenticate passcode
        let expected_secret = get_admin_secret();
        let provided = req.passcode.as_deref().unwrap_or("");
        if provided != expected_secret {
            send_json_error(&mut stream, 401, "Invalid Master Passcode! Access Denied.").await;
            return;
        }

        if req.customer_name.trim().is_empty() || req.hardware_id.trim().is_empty() {
            send_json_error(
                &mut stream,
                400,
                "Customer Name and Hardware ID (HWID) are required.",
            )
            .await;
            return;
        }

        let signing_key = get_signing_key();
        let now = Utc::now().timestamp();
        let nodes = req.max_nodes.unwrap_or(3).max(1);
        let expires_at = req.days.filter(|d| *d > 0).map(|d| now + (d * 86400));

        let tier = match req.tier.as_deref() {
            Some("Professional") => LicenseTier::Professional,
            Some("Enterprise") => LicenseTier::Enterprise,
            _ => {
                if nodes > 10 {
                    LicenseTier::Enterprise
                } else {
                    LicenseTier::Standard
                }
            }
        };

        let license_id = format!("LIC-{}", random_id_suffix());
        let payload = LicensePayload {
            license_id: license_id.clone(),
            customer_name: req.customer_name.trim().to_string(),
            hardware_id: req.hardware_id.trim().to_string(),
            tier,
            max_nodes: nodes,
            issued_at: now,
            expires_at,
        };

        let payload_json = match serde_json::to_string(&payload) {
            Ok(j) => j,
            Err(e) => {
                send_json_error(&mut stream, 500, &format!("Serialization error: {}", e)).await;
                return;
            }
        };

        let signature = signing_key.sign(payload_json.as_bytes());
        let signature_base64 = BASE64_STANDARD.encode(signature.to_bytes());
        let license = License::new(payload.clone(), signature_base64);
        let license_json = serde_json::to_string_pretty(&license).unwrap_or_default();

        let record = IssuedLicenseRecord {
            license_id: license_id.clone(),
            customer_name: payload.customer_name.clone(),
            hardware_id: payload.hardware_id.clone(),
            max_nodes: nodes,
            tier: format!("{:?}", tier),
            issued_at: now,
            expires_at,
            license_json: license_json.clone(),
        };

        {
            let mut hist = LICENSE_HISTORY.lock().unwrap();
            hist.insert(0, record);
            if hist.len() > 50 {
                hist.truncate(50);
            }
        }

        let resp_body = serde_json::json!({
            "success": true,
            "license_id": license_id,
            "customer_name": payload.customer_name,
            "hardware_id": payload.hardware_id,
            "max_nodes": nodes,
            "tier": format!("{:?}", tier),
            "issued_at": now,
            "expires_at": expires_at,
            "license_json": license_json,
        })
        .to_string();

        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        return;
    }

    if path.starts_with("/api/admin/history") {
        let hist = {
            let lock = LICENSE_HISTORY.lock().unwrap();
            lock.clone()
        };
        let body = serde_json::to_string(&hist).unwrap_or_else(|_| "[]".into());
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        return;
    }

    // Default healthcheck
    let body = "{\"status\":\"ok\",\"service\":\"t3Bridge Cloud Signaling & Licensing Server\"}\n";
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

async fn send_json_error(stream: &mut TcpStream, status_code: u16, msg: &str) {
    let body = serde_json::json!({
        "success": false,
        "error": msg
    })
    .to_string();

    let resp = format!(
        "HTTP/1.1 {} ERROR\r\n\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

fn get_admin_dashboard_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>t3Bridge — Commercial License Manager</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #0b0f19; color: #f1f5f9; padding: 16px; min-height: 100vh; }
    .container { max-width: 680px; margin: 0 auto; }
    .header { text-align: center; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid #1e293b; }
    .header h1 { font-size: 22px; color: #38bdf8; font-weight: 700; letter-spacing: -0.5px; }
    .header p { font-size: 13px; color: #94a3b8; margin-top: 4px; }
    .card { background: #131d31; border: 1px solid #1e293b; border-radius: 12px; padding: 18px; margin-bottom: 16px; box-shadow: 0 4px 16px rgba(0,0,0,0.3); }
    .card-title { font-size: 15px; font-weight: 600; color: #e2e8f0; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
    .form-group { margin-bottom: 14px; }
    label { display: block; font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    input, select { width: 100%; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; padding: 10px 12px; font-size: 14px; outline: none; transition: border-color 0.2s; }
    input:focus, select:focus { border-color: #38bdf8; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 500px) { .grid-2 { grid-template-columns: 1fr; } }
    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; width: 100%; padding: 12px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; border: none; transition: all 0.2s; }
    .btn-primary { background: linear-gradient(135deg, #0284c7, #2563eb); color: #fff; box-shadow: 0 4px 12px rgba(37, 99, 235, 0.35); }
    .btn-primary:active { transform: scale(0.98); }
    .btn-copy { background: #1e293b; color: #38bdf8; border: 1px solid #334155; }
    .btn-whatsapp { background: #16a34a; color: #fff; }
    .result-box { display: none; background: #0a0f1d; border: 1px solid #0284c7; border-radius: 8px; padding: 14px; margin-top: 14px; }
    .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-size: 13px; font-weight: 600; color: #38bdf8; }
    textarea { width: 100%; height: 110px; background: #030712; border: 1px solid #1e293b; border-radius: 6px; color: #a5f3fc; font-family: monospace; font-size: 11px; padding: 8px; resize: none; margin-bottom: 10px; }
    .actions-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .status-msg { margin-top: 10px; font-size: 12px; text-align: center; color: #ef4444; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; background: #0369a1; color: #e0f2fe; }
    .history-item { padding: 10px; border-bottom: 1px solid #1e293b; font-size: 12px; display: flex; justify-content: space-between; align-items: center; }
    .history-item:last-child { border-bottom: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>⚡ t3Bridge License Generator</h1>
      <p>Secure Commercial License Management Portal</p>
    </div>

    <!-- Auth / Passcode Card -->
    <div class="card" id="authCard">
      <div class="card-title">🔐 Master Security Access</div>
      <div class="form-group">
        <label for="adminPasscode">Master Passcode</label>
        <input type="password" id="adminPasscode" placeholder="Enter admin passcode" />
      </div>
    </div>

    <!-- Generator Card -->
    <div class="card">
      <div class="card-title">📝 Issue Commercial License</div>
      
      <div class="form-group">
        <label for="custName">Customer / Company Name</label>
        <input type="text" id="custName" placeholder="e.g. ABC Trading Co." />
      </div>

      <div class="form-group">
        <label for="hwid">Target Machine HWID</label>
        <input type="text" id="hwid" placeholder="e.g. T3-0B86-8ED7-EBE4" style="text-transform: uppercase;" />
      </div>

      <div class="grid-2">
        <div class="form-group">
          <label for="nodePlan">Package & Seats</label>
          <select id="nodePlan">
            <option value="3" selected>1 Host + 3 Clients (Starter Pack - 3 Nodes)</option>
            <option value="5">1 Host + 5 Clients (Extended - 5 Nodes)</option>
            <option value="10">1 Host + 10 Clients (Enterprise - 10 Nodes)</option>
            <option value="1">Single Node (Client Add-on)</option>
            <option value="custom">Custom Node Count...</option>
          </select>
        </div>

        <div class="form-group" id="customNodeGroup" style="display: none;">
          <label for="customNodes">Custom Nodes</label>
          <input type="number" id="customNodes" min="1" max="100" value="4" />
        </div>

        <div class="form-group">
          <label for="validity">License Validity</label>
          <select id="validity">
            <option value="365" selected>1 Year (365 Days) — Standard</option>
            <option value="730">2 Years (730 Days)</option>
            <option value="0">Lifetime / Perpetual (No Expiry)</option>
            <option value="30">30 Days (Extended Trial)</option>
          </select>
        </div>
      </div>

      <button type="button" id="btnGenerate" class="btn btn-primary">⚡ Generate &amp; Sign License</button>
      <div id="statusMsg" class="status-msg"></div>

      <!-- Result Section -->
      <div id="resultBox" class="result-box">
        <div class="result-header">
          <span id="resultTitle">✔ License Created</span>
          <span id="resultBadge" class="badge">3 Nodes</span>
        </div>
        <textarea id="licenseOutput" readonly></textarea>
        <div class="actions-grid">
          <button type="button" id="btnCopy" class="btn btn-copy">📋 Copy Key</button>
          <button type="button" id="btnWhatsApp" class="btn btn-whatsapp">💬 WhatsApp</button>
        </div>
      </div>
    </div>

    <!-- History Card -->
    <div class="card">
      <div class="card-title">🕒 Recently Issued Licenses</div>
      <div id="historyList" style="max-height: 200px; overflow-y: auto;">
        <div style="font-size: 12px; color: #64748b; text-align: center; padding: 12px;">No licenses issued in this session yet.</div>
      </div>
    </div>
  </div>

  <script>
    const adminPasscode = document.getElementById('adminPasscode');
    const custName = document.getElementById('custName');
    const hwid = document.getElementById('hwid');
    const nodePlan = document.getElementById('nodePlan');
    const customNodeGroup = document.getElementById('customNodeGroup');
    const customNodes = document.getElementById('customNodes');
    const validity = document.getElementById('validity');
    const btnGenerate = document.getElementById('btnGenerate');
    const statusMsg = document.getElementById('statusMsg');
    const resultBox = document.getElementById('resultBox');
    const licenseOutput = document.getElementById('licenseOutput');
    const resultBadge = document.getElementById('resultBadge');
    const btnCopy = document.getElementById('btnCopy');
    const btnWhatsApp = document.getElementById('btnWhatsApp');
    const historyList = document.getElementById('historyList');

    // Auto-load saved passcode from phone/browser localStorage
    const savedToken = localStorage.getItem('t3_admin_secret');
    if (savedToken) adminPasscode.value = savedToken;
    adminPasscode.addEventListener('change', () => {
      localStorage.setItem('t3_admin_secret', adminPasscode.value.trim());
    });

    nodePlan.addEventListener('change', () => {
      customNodeGroup.style.display = nodePlan.value === 'custom' ? 'block' : 'none';
    });

    btnGenerate.addEventListener('click', async () => {
      statusMsg.textContent = '';
      const passcode = adminPasscode.value.trim();
      const customer = custName.value.trim();
      const rawHwid = hwid.value.trim().toUpperCase();

      if (!passcode) {
        statusMsg.textContent = 'Please enter the Master Passcode.';
        return;
      }
      if (!customer) {
        statusMsg.textContent = 'Customer Name is required.';
        return;
      }
      if (!rawHwid) {
        statusMsg.textContent = 'Hardware ID (HWID) is required.';
        return;
      }

      let nodes = parseInt(nodePlan.value, 10);
      if (nodePlan.value === 'custom') {
        nodes = parseInt(customNodes.value, 10) || 3;
      }

      const days = parseInt(validity.value, 10);

      btnGenerate.disabled = true;
      btnGenerate.textContent = 'Signing License...';

      try {
        const res = await fetch('/api/admin/issue', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            customer_name: customer,
            hardware_id: rawHwid,
            max_nodes: nodes,
            days: days,
            passcode: passcode
          })
        });

        const data = await res.json();
        if (!res.ok || !data.success) {
          statusMsg.textContent = data.error || 'Failed to issue license.';
          resultBox.style.display = 'none';
        } else {
          licenseOutput.value = data.license_json;
          resultBadge.textContent = `${data.max_nodes} Nodes (${data.tier})`;
          resultBox.style.display = 'block';

          // Update WhatsApp button URL
          const msg = `Hello ${customer},\nHere is your official t3Bridge Commercial License Key:\n\n${data.license_json}\n\nSimply paste this in your t3Bridge License tab to activate.`;
          btnWhatsApp.onclick = () => {
            window.open('https://api.whatsapp.com/send?text=' + encodeURIComponent(msg), '_blank');
          };

          loadHistory();
        }
      } catch (err) {
        statusMsg.textContent = 'Connection error: ' + err.message;
      } finally {
        btnGenerate.disabled = false;
        btnGenerate.textContent = '⚡ Generate & Sign License';
      }
    });

    btnCopy.addEventListener('click', () => {
      navigator.clipboard.writeText(licenseOutput.value);
      btnCopy.textContent = '✔ Copied!';
      setTimeout(() => { btnCopy.textContent = '📋 Copy Key'; }, 2000);
    });

    async function loadHistory() {
      try {
        const res = await fetch('/api/admin/history');
        if (!res.ok) return;
        const list = await res.json();
        if (!list || list.length === 0) return;

        historyList.innerHTML = '';
        list.forEach(item => {
          const div = document.createElement('div');
          div.className = 'history-item';
          const expText = item.expires_at ? new Date(item.expires_at * 1000).toLocaleDateString() : 'Lifetime';
          div.innerHTML = `
            <div>
              <strong>${item.customer_name}</strong> (${item.max_nodes} Nodes)
              <div style="color: #64748b; font-size: 11px;">HWID: ${item.hardware_id} | Expiry: ${expText}</div>
            </div>
            <button class="btn btn-copy" style="width: auto; padding: 4px 8px; font-size: 11px;">Copy</button>
          `;
          div.querySelector('button').onclick = () => {
            navigator.clipboard.writeText(item.license_json);
            div.querySelector('button').textContent = '✔';
            setTimeout(() => { div.querySelector('button').textContent = 'Copy'; }, 1500);
          };
          historyList.appendChild(div);
        });
      } catch (_) {}
    }

    loadHistory();
  </script>
</body>
</html>
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_derivation_and_verification() {
        let signing_key = get_signing_key();
        let verifying_key = signing_key.verifying_key();

        let msg = b"Test License Payload for t3Bridge";
        let signature = signing_key.sign(msg);

        // Verifying with public key must succeed
        assert!(verifying_key.verify_strict(msg, &signature).is_ok());
    }

    #[test]
    fn test_admin_dashboard_html_contains_critical_elements() {
        let html = get_admin_dashboard_html();
        assert!(html.contains("t3Bridge License Generator"));
        assert!(html.contains("Master Passcode"));
        assert!(html.contains("Hardware ID"));
        assert!(html.contains("1 Host + 3 Clients"));
    }
}

# Deploying t3Bridge Cloud Signaling Server to Render (render.com)

`t3_signaling_server` is a high-performance, asynchronous WebSocket rendezvous & NAT-traversal signaling server written in Rust. Deploying it on **Render** gives you a free, global cloud signaling endpoint (`wss://your-app.onrender.com`) that enables P2P connections across WAN, 4G/5G, CGNAT, and LAN.

---

## 🚀 1-Click / Blueprint Deployment (Recommended)

1. **Push your code to GitHub / GitLab**.
2. Log in to [dashboard.render.com](https://dashboard.render.com).
3. Click **New +** -> **Blueprint**.
4. Connect your `t3SharePlus` repository.
5. Render will automatically detect [`render.yaml`](file:///e:/Project/t3SharePlus/render.yaml) and configure:
   - **Service Name:** `t3bridge-signaling`
   - **Environment:** Docker (`Dockerfile.signaling`)
   - **Health Check:** `/health` (HTTP 200 OK)
   - **Plan:** Free
6. Click **Apply**.
7. In ~2-3 minutes, your server will be live at:
   ```text
   https://t3bridge-signaling.onrender.com
   ```
   WebSocket endpoint:
   ```text
   wss://t3bridge-signaling.onrender.com
   ```

---

## 🛠 Manual Web Service Deployment

If you prefer setting it up manually without Blueprint:

1. In Render Dashboard, click **New +** -> **Web Service**.
2. Connect your Git repository.
3. Configure the settings:
   - **Name:** `t3bridge-signaling`
   - **Language / Runtime:** `Docker`
   - **Dockerfile Path:** `./Dockerfile.signaling`
   - **Instance Type:** `Free`
   - **Health Check Path:** `/health`
4. Click **Create Web Service**.

---

## 🔍 Verifying the Deployment

1. **Browser / HTTP Check:**
   Visit your Render URL in the browser (e.g., `https://t3bridge-signaling.onrender.com`).
   You will see:
   ```json
   {
     "status": "ok",
     "service": "t3Bridge Cloud Signaling Rendezvous Server"
   }
   ```

2. **WebSocket Signaling Check:**
   When connecting via WebSockets:
   ```text
   wss://t3bridge-signaling.onrender.com
   ```
   Render terminates SSL automatically, providing end-to-end TLS encryption.

---

## 🌐 How WAN & LAN Connections Work with Cloud Signaling

```
+------------------------------------+
|  Render Cloud Signaling Server    |
|   wss://t3bridge.onrender.com      |
+-----------------+------------------+
                  ^
                  |  WebSocket Signaling
        +---------+---------+
        |                   |
+-------+--------+  +-------+--------+
|  Host Server   |  |  Remote Client |
|  (Office Marg) |  |  (Home/Branch) |
| Connect Code:  |  | Target Code:   |
|  OFFICE-HQ-01  |  |  OFFICE-HQ-01  |
+----------------+  +----------------+
        |                   |
        +========[ P2P ]====+
         Encrypted LAN/WAN Mesh
          (Marg ERP on Z: Drive)
```

1. **Office Host Server:** Runs `t3Bridge` in Host Mode. It connects to the Render server and registers as `OFFICE-HQ-01`.
2. **Branch / Home Laptop (WAN):** Enters `OFFICE-HQ-01`. It queries the Render server, finds the host, performs STUN NAT hole punching, and connects directly P2P.
3. **Local LAN Fallback:** If both PCs are on the same Wi-Fi / LAN, they can also connect directly via Local IP (`192.168.x.x`).

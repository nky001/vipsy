# Vipsy — User Guide

Vipsy is a Home Assistant add-on that provides secure remote access via TLS, an optional Cloudflare Tunnel, and an optional WireGuard VPN that lets your devices join your home LAN from anywhere.

---

## Quick-start

1. Install Vipsy in the HA Supervisor add-on store.
2. Open the add-on **Configuration** tab and set your options (all are optional for a basic install).
3. Start the add-on. The ingress dashboard opens via **Open Web UI**.

---

## Configuration Options

| Option | Default | Description |
|---|---|---|
| `domain` | _(empty)_ | Your public domain, e.g. `ha.example.com`. Leave blank for LAN-only. |
| `certfile` | `fullchain.pem` | TLS cert file in `/ssl/`. Ignored if file has no SANs (auto-cert is used). |
| `keyfile` | `privkey.pem` | TLS key file in `/ssl/`. |
| `enable_turn` | `true` | Enable coturn for WebRTC cameras and voice. |
| `tunnel_enabled` | `false` | Enable Cloudflare Tunnel for zero-config remote access. |
| `vpn_subnet` | `10.8.0.0/24` | WireGuard VPN subnet. Change only if it conflicts with your LAN range. |
| `vpn_port` | `51820` | WireGuard UDP port. Must match the port you forward on your router. |

---

## TLS Certificate

- If `/ssl/<certfile>` exists and has Subject Alternative Names (SANs), it is used as-is.  
- Otherwise a self-signed certificate is auto-generated covering your domain, public IP, and host IP. Browsers will show a security warning — click **Advanced → Proceed**.  
- For a trusted cert, use the **Let's Encrypt** add-on or the **Duck DNS** add-on and point `certfile`/`keyfile` at their output.

---

## Cloudflare Tunnel

When `tunnel_enabled: true`, cloudflared runs inside the add-on and creates an outbound tunnel — **no port forwarding required**.

- If the backend service key is configured, a stable named subdomain is provisioned automatically (e.g. `abc12345-vipsy.example.com`).
- Without a service key, a temporary `trycloudflare.com` URL is used. It changes every restart.

---

## WireGuard VPN

The VPN gives remote devices full LAN access (split-tunnel — only LAN and VPN traffic is routed, not your general internet). It is **off by default** and must be enabled explicitly.

### Prerequisites

**Router port forward:** Forward UDP port `51820` on your router to the IP of your Home Assistant host.

> If you changed `vpn_port`, forward that port instead.

---

### Step 1 — Enable the VPN

Open the ingress dashboard (**Open Web UI**), scroll to the **WireGuard VPN** section, and click **Enable VPN**.

The server key is generated once and stored securely. It persists across restarts.

---

### Step 2 — Add a Peer (device)

Click **+ Add Peer** and fill in:

| Field | Notes |
|---|---|
| **Name** | A label for the device, e.g. `Laptop` or `Phone`. |
| **Expires in (hours)** | Set to `0` for no expiry, or e.g. `72` for a 3-day peer. |
| **Persistent** | Tick if the peer should survive restarts even when its TTL has elapsed. |

Click **Create Peer**. You will immediately see:

- **Config text** — copy and paste into WireGuard app
- **Download .conf** — download the config file
- **QR Code** — scan with the WireGuard mobile app

> The private key is shown only once. Download or copy the config before closing.

---

### Step 3 — Install WireGuard on the client device

| Platform | Client | Download |
|---|---|---|
| Windows | WireGuard for Windows | [wireguard.com/install](https://www.wireguard.com/install/) |
| macOS | WireGuard for macOS | App Store or [wireguard.com/install](https://www.wireguard.com/install/) |
| iOS | WireGuard | App Store |
| Android | WireGuard | Play Store or F-Droid |
| Linux | `wireguard-tools` | `apt install wireguard` / `dnf install wireguard-tools` |

---

### Step 4 — Import the configuration

**Mobile (iOS/Android):**
1. Open WireGuard → tap **+**.
2. Tap **Create from QR code** and scan the QR shown in the dashboard.
3. Give the tunnel a name and tap **Save**.

**Desktop (Windows/macOS):**
1. Open WireGuard → Click **Import tunnel(s) from file**.
2. Select the downloaded `.conf` file.

**Linux:**
```bash
sudo cp vipsy-<peer_id>.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

---

### Step 5 — Connect

Toggle the tunnel **On** in the WireGuard app. After a few seconds the handshake completes, the peer shows **Connected** in the Vipsy dashboard, and your device is on the home LAN.

You can now reach Home Assistant at `https://<your-ha-lan-ip>` or any other LAN device by its IP address.

---

### What the VPN routes

The config uses **split-tunnel** — only traffic for your home LAN and VPN subnet is sent through the tunnel. Your normal internet browsing is unaffected.

```
AllowedIPs = 192.168.x.x/24, 10.8.0.0/24   ← LAN + VPN only
```

---

### Peer management

| Action | How |
|---|---|
| **List peers** | Dashboard → Peers table shows each peer's IP, connected status, and expiry |
| **Re-download config** | Click ⬇ button next to the peer |
| **View QR** | Click ◻ button next to the peer |
| **Remove a peer** | Click ✕ — the peer is disconnected immediately |
| **Kill switch** | Red **Kill Switch** button — removes ALL peers and shuts down the interface instantly |

---

### Peer TTL (expiry)

Peers with a TTL expire automatically. The add-on checks every 30 seconds. Expired peers are removed from WireGuard live — no restart needed. Peers marked **Persistent** are kept across restarts even if their TTL has elapsed.

---

### Troubleshooting

**No handshake after connecting:**
- Confirm UDP `51820` is port-forwarded on your router to the HA host.
- Check the dashboard shows your public IP in the Access section — if it shows "unknown", the host has no internet access.
- Temporarily disable the firewall on the client to rule out local blocking.

**`overlap_warning` in the dashboard:**
- Your `vpn_subnet` (`10.8.0.0/24`) conflicts with your LAN subnet. Change `vpn_subnet` to `10.9.0.0/24` or another unused range in the add-on configuration and restart.

**Peer shows "Idle" but tunnel is enabled:**
- The WireGuard app may be in a disconnected state. Toggle the tunnel off and on in the app.
- Handshakes only appear after actual traffic is sent — the status updates every 20 seconds.

---

## Security notes

- The add-on ingress (port 8099) is firewalled to the HA Supervisor subnet only — it is never reachable from the internet.
- HTTPS is always on; there is no plaintext fallback.
- WireGuard peer private keys are stored in `/data/wireguard/peers.json` (mode `0600`) and are only served back through the protected ingress.
- Each peer gets a unique preshared key for additional forward-secrecy.
- NAT rules are applied only while the VPN is enabled and flushed on disable/kill.
- `net.ipv4.ip_forward` is enabled at startup only — it does not persist beyond the container lifetime.

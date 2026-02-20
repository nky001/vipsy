# Vipsy

Secure remote access to Home Assistant — no VPN, no client apps, no LAN exposure.

Vipsy is a single Home Assistant add-on that acts as an application-layer gateway. It terminates TLS, reverse-proxies exclusively to Home Assistant Core, and optionally relays WebRTC media via coturn. Users never join the LAN; the add-on mediates all access at the application layer.

## What it does

- HTTPS reverse proxy (Caddy) to Home Assistant Core only
- Full WebSocket support for the HA frontend and real-time state
- Optional TURN/STUN relay (coturn) for cameras and voice
- Default-deny firewall (nftables) inside the container
- Ingress-based status dashboard — no extra ports for UI
- Relies entirely on Home Assistant authentication

## What it does NOT do

- No VPN, no mesh, no tunneling
- No SSH proxy or bastion
- No LAN exposure or arbitrary IP forwarding
- No client-side OS changes or apps
- No generic TCP/UDP forwarding

## Installation

1. Copy this repository into your Home Assistant `addons/local/vipsy` folder
2. In Supervisor → Add-on Store → Local add-ons, click **Vipsy**
3. Configure your domain and TLS certificates in the add-on options
4. Start the add-on

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `domain` | string | `""` | Your public domain (e.g. `ha.example.com`) |
| `certfile` | string | `fullchain.pem` | TLS certificate filename in `/ssl/` |
| `keyfile` | string | `privkey.pem` | TLS private key filename in `/ssl/` |
| `enable_turn` | bool | `true` | Enable coturn TURN/STUN relay |

## Architecture

```
Client (browser / HA app)
  │
  │ HTTPS / WebSocket / WebRTC
  │
Public Internet
  │
Router (port 443 forwarded)
  │
HAOS
  │
┌──────────────────────────────────┐
│  Vipsy Add-on Container         │
│                                  │
│  nftables (default-deny)         │
│  Caddy (TLS + reverse proxy)    │
│  coturn (TURN/STUN, optional)   │
│  gateway.py (status API)        │
└──────────────────────────────────┘
  │
  │ HTTP (internal only)
  │
Home Assistant Core (:8123)
  │
IoT devices (LAN only, never exposed)
```

## Security model

The gateway follows a zero-trust application access model. Users authenticate to Home Assistant through a single hardened entry point. Only Home Assistant application traffic is exposed; the underlying network remains inaccessible. No device joins the LAN, and no client-side VPN is required.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 443 | TCP | HTTPS reverse proxy (Caddy) |
| 3478 | UDP | TURN/STUN relay (coturn) |

## Development

```bash
pip install -r requirements.txt
pytest
docker build -t vipsy .
docker run --rm -p 443:443 -p 3478:3478/udp vipsy
```

## License

MIT


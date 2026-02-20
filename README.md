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
| `tunnel_enabled` | bool | `false` | Enable Cloudflare Tunnel for zero-config remote access |
| `cf_api_token` | string | `""` | Cloudflare API token (Tunnel:Edit + DNS:Edit). Leave empty if baked at build time. |
| `cf_account_id` | string | `""` | Cloudflare Account ID |
| `cf_zone_id` | string | `""` | Cloudflare Zone ID for the tunnel domain |
| `cf_domain` | string | `""` | Base domain for tunnel subdomains (e.g. `vipsy.example.com`) |

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

## Cloudflare Tunnel

When `tunnel_enabled` is set, Vipsy automatically provisions a Cloudflare Tunnel for each installation. Each instance gets a unique 8-character ID and a permanent URL like `abcd1234.vipsy.example.com`. No port forwarding, no dynamic DNS, no client apps required.

**How it works:**
- On first start, the add-on calls the Cloudflare API to create a named tunnel, configure ingress, and set up a DNS CNAME record.
- Credentials are persisted in `/data/tunnel/` so the tunnel survives restarts.
- If CF credentials are not available, the add-on falls back to a free Quick Tunnel (ephemeral URL that changes on restart).

**Providing Cloudflare credentials:**
- **Add-on options (recommended):** Set `cf_api_token`, `cf_account_id`, `cf_zone_id`, and `cf_domain` in the add-on configuration.
- **Build-time args:** Pass via `docker build --build-arg VIPSY_CF_TOKEN=... --build-arg VIPSY_CF_ACCOUNT_ID=... --build-arg VIPSY_CF_ZONE_ID=... --build-arg VIPSY_CF_DOMAIN=...`

Never commit real credentials to source control.

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


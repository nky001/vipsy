# Vipsy — Quick Reference

Vipsy is a Home Assistant add‑on for secure remote access.
It bundles:

* HTTPS reverse proxy (Caddy) to your HA core
* Optional Cloudflare Tunnel (egress‑only; no port forwarding)
* Optional WireGuard VPN providing full LAN access

The add‑on runs in host network mode and exposes an ingress UI on port 8099.

---

## Configuration

Set options from the Supervisor add‑on configuration screen. Most are optional; minimal setup is:

```yaml
domain: ""           # public domain (leave blank for LAN-only)
enable_turn: true      # coturn for WebRTC/voice
tunnel_enabled: false  # set true if you want a cloudflared tunnel
vpn_subnet: 10.8.0.0/24 # change only if this overlaps your LAN
vpn_port: 51820        # UDP port for WireGuard; forward it on your router
```

The add‑on will auto‑generate a self‑signed TLS certificate if none is provided in
`/ssl`. For a trusted cert use the Duck DNS or Let’s Encrypt add‑on and point
`certfile`/`keyfile` accordingly.

---

## Cloudflare Tunnel

Enable `tunnel_enabled` to have the add‑on spawn `cloudflared` and
establish an outbound tunnel.  With a valid backend service key you get a
stable subdomain (e.g. `abc12345-vipsy.example.com`).  Otherwise an
ephemeral `trycloudflare.com` URL is used and changes on restart.

No inbound ports are required on your router.

---

## WireGuard VPN

### Requirements

* Forward the chosen `vpn_port` (default 51820/UDP) from your router to
  the Home Assistant host.
* The VPN is **off by default**; enable it explicitly in the ingress UI.

### Basic workflow

1. **Enable VPN** – generates a server key and brings up `wg-hub`.
2. **Add a peer** – supply a name, TTL (0=no expiry), and optional
   “persistent” flag.  Copy the config text, download the `.conf` file or
   scan the QR code.  The private key is shown only once.
3. **Import on client** – use the WireGuard app on desktop/mobile or
   `wg-quick` on Linux.
4. **Connect** – toggle on the tunnel; after a handshake you’re on the LAN.

Configurations use split‑tunnel: only the LAN subnet and VPN subnet are
routed through WireGuard.  Internet traffic takes the client’s normal path.

### Peer management

| Action | Where |
|--------|-------|
| List peers | Dashboard table |
| Download config | ⬇ button |
| Show QR code | ◻ button |
| Remove peer | ✕ button |
| Kill switch (drop all) | Red **Kill Switch** button |

Peers expire automatically.  A background thread checks every 30 s and
removes expired entries; persistent peers survive restarts regardless of
TTL.

---

## Troubleshooting

*No handshake / cannot access LAN* → confirm UDP port is forwarded and the
public IP reported on the dashboard matches your actual IP.  On the VPS
`wg show wg0` should list the home peer with `allowed ips` containing both
`10.100.0.x/32` and your LAN CIDR.

*Overlap warning* → change `vpn_subnet` if it overlaps any network you
offline or remote device uses.

*Icon not appearing in Supervisor* → ensure an `icon.png` file is present
at the container root (the Dockerfile now copies it there).

---

## Security notes

* Ingress UI is accessible only from the Supervisor network.
* TLS always enforced; no HTTP only option.
* Peer keys live under `/data/wireguard` with `0600` permissions.
* NAT and forwarding rules are added only when VPN is active and flushed
  when it stops.
* WireGuard keep‑alive set to 25 s; every peer gets a unique preshared key.


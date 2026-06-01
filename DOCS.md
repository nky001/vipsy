# Vipsy — Quick Reference

Vipsy is a Home Assistant add-on that gives you a safe ingress UI, optional Cloudflare Tunnel, and optional WireGuard LAN access.

---

## Configuration

Set options from the Supervisor add-on configuration screen. Keep it simple:

```yaml
tunnel_enabled: false   # flip true to run the Cloudflare Tunnel
instance_name: place1   # optional friendly name for this installation
vpn_enabled: false      # turn on only when you need WireGuard VPN
vpn_subnet: 10.8.0.0/24 # change only if this overlaps another network you actually use
```

The `domain` field is only for your own manually managed hostname. Managed Cloudflare Tunnel hostnames are issued under `vipsy.in`. If you do have your own TLS cert/key pair, drop them into `/ssl` before starting the add-on; otherwise the add-on will auto-generate a self-signed cert.

---

## Cloudflare Tunnel

1. Enable the toggle in the add-on or ingress UI and start the tunnel; this launches `cloudflared` and gives you a temporary `trycloudflare.com` URL.
2. Sign in, complete the account flow, and the dashboard will refresh with your **static** URL under `vipsy.in`.
3. Set an instance name such as `place1` before creating the static URL when you want a human-friendly name. Existing legacy managed hostnames, including `niti.life`, are automatically replaced with `vipsy.in` on the next tunnel start. The old connector stays active until replacement DNS succeeds.
4. Every restart or update of the add-on will rotate the temporary `trycloudflare.com` URL, so only the static URL survives restarts.

If the tunnel ever reports a backend error or timeout, the UI still works—just refresh after a moment and it should settle.

The production backend URL is `https://api.vipsy.in`. When moving backend infrastructure, build or run the add-on with `VIPSY_BACKEND_URL` pointing at the new Worker. The gateway UI, tunnel manager, and remote-access manager all read that same environment variable, so login, static tunnels, and hub VPN registration stay on the same backend.

## Wrapper control API

Updated add-ons report a compact heartbeat to `POST /addon/heartbeat`. The report includes the instance ID, instance name, permanent URL, tunnel health, VPN state, agent health, and add-on version. It excludes secrets and expires automatically when an add-on stops reporting.

The future wrapper can read `GET /control/addons/:instance_id` and enqueue an idempotent Supervisor restart with `POST /control/addons/:instance_id/restart`. These wrapper-only endpoints stay disabled until a separate Cloudflare Worker secret is configured:

```sh
npx wrangler secret put CONTROL_API_KEY
```

Use the secret only from the wrapper backend. Never ship it to a browser or add-on image.

---

## WireGuard VPN

* Enable the VPN explicitly via the dashboard (it does not auto-start).
* Add peers from the UI, copy/download the `.conf`, or scan the QR.
* Clients get split-tunnel configs: only the LAN and VPN subnets go through WireGuard; other traffic follows the client’s normal route.
* Remote Access VPN configs no longer force a DNS server, so normal internet and DNS stay on the client’s current network while LAN routes use WireGuard.
* For networks that block UDP, create a local VPN peer and download the Relay ZIP. It includes a one-click Windows setup script and a Python relay that carries WireGuard packets through the Cloudflare Tunnel.
* Persistent peers survive restarts even if they have a TTL.
* Use the red **Kill Switch** button to drop every peer instantly.

---

## Notes

* The add-on’s ingress UI is reachable only from the Supervisor network.
* WireGuard server keys live under `/data/wireguard` with tight (`0600`) permissions.
* NAT/forwarding rules appear only when VPN is active and are removed when it stops.
* The status page reports whether the tunnel is running in quick or static mode, and whether WireGuard handshakes are healthy.

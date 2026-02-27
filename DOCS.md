# Vipsy — Quick Reference

Vipsy is a Home Assistant add-on that gives you a safe ingress UI, optional Cloudflare Tunnel, and optional WireGuard LAN access.

---

## Configuration

Set options from the Supervisor add-on configuration screen. Keep it simple:

```yaml
tunnel_enabled: false   # flip true to run the Cloudflare Tunnel
vpn_enabled: false      # turn on only when you need WireGuard VPN
vpn_subnet: 10.8.0.0/24 # change only if this overlaps another network you actually use
```

The `domain` field currently does nothing, so you can leave it blank. If you do have your own TLS cert/key pair, drop them into `/ssl` before starting the add-on; otherwise the add-on will auto-generate a self-signed cert.

---

## Cloudflare Tunnel

1. Enable the toggle in the add-on or ingress UI and start the tunnel; this launches `cloudflared` and gives you a temporary `trycloudflare.com` URL.
2. Open the **Sign in with Google** flow, complete the login, and the dashboard will refresh with your **static** URL (`<id>.niti.life`).
3. The static URL stays valid until you uninstall the add-on. If you reinstall, the static hostname is lost and you must sign in again.
4. Every restart or update of the add-on will rotate the temporary `trycloudflare.com` URL, so only the static URL survives restarts.

If the tunnel ever reports a backend error or timeout, the UI still works—just refresh after a moment and it should settle.

---

## WireGuard VPN

* Enable the VPN explicitly via the dashboard (it does not auto-start).
* Add peers from the UI, copy/download the `.conf`, or scan the QR.
* Clients get split-tunnel configs: only the LAN and VPN subnets go through WireGuard; other traffic follows the client’s normal route.
* Persistent peers survive restarts even if they have a TTL.
* Use the red **Kill Switch** button to drop every peer instantly.

---

## Notes

* The add-on’s ingress UI is reachable only from the Supervisor network.
* WireGuard server keys live under `/data/wireguard` with tight (`0600`) permissions.
* NAT/forwarding rules appear only when VPN is active and are removed when it stops.
* The status page reports whether the tunnel is running in quick or static mode, and whether WireGuard handshakes are healthy.

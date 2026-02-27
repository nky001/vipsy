# Vipsy

Secure remote access to Home Assistant — no VPN, no client apps, no LAN exposure.

Vipsy is a single Home Assistant add-on that acts as an application-layer gateway. It terminates TLS, reverse-proxies exclusively to Home Assistant Core, and optionally relays WebRTC media via coturn. Users never join the LAN; the add-on mediates all access at the application layer.


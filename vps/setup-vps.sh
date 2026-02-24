#!/usr/bin/env bash
set -euo pipefail

echo "=== Vipsy VPS Hub Setup ==="
echo "This script configures WireGuard hub + sync on the VPS."
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash setup-vps.sh"
    exit 1
fi

read -rp "Backend URL [https://vipsy-backend.nitinexus.workers.dev]: " BACKEND_URL
BACKEND_URL="${BACKEND_URL:-https://vipsy-backend.nitinexus.workers.dev}"

read -rp "API Key: " API_KEY
if [ -z "$API_KEY" ]; then
    echo "ERROR: API key is required"
    exit 1
fi

read -rp "WireGuard listen port [51820]: " WG_PORT
WG_PORT="${WG_PORT:-51820}"

read -rp "Hub subnet [10.100.0.0/24]: " HUB_SUBNET
HUB_SUBNET="${HUB_SUBNET:-10.100.0.0/24}"

read -rp "Server VPN IP [10.100.0.1]: " SERVER_IP
SERVER_IP="${SERVER_IP:-10.100.0.1}"

apt-get update -qq && apt-get install -y -qq wireguard jq curl

if [ ! -f /etc/wireguard/wg0-private.key ]; then
    wg genkey | tee /etc/wireguard/wg0-private.key | wg pubkey > /etc/wireguard/wg0-public.key
    chmod 600 /etc/wireguard/wg0-private.key
    echo "Generated WireGuard keys."
    echo ""
    echo "===> VPS PUBLIC KEY: $(cat /etc/wireguard/wg0-public.key)"
    echo ""
    echo "Set this as the VPS_PUBKEY secret on the backend:"
    echo "  cd vipsy-backend && npx wrangler secret put VPS_PUBKEY"
    echo ""
fi

PRIVKEY=$(cat /etc/wireguard/wg0-private.key)
PREFIX=$(echo "$HUB_SUBNET" | cut -d/ -f2)

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $PRIVKEY
Address = $SERVER_IP/$PREFIX
ListenPort = $WG_PORT
EOF

echo "Wrote /etc/wireguard/wg0.conf"

sysctl -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

DEFAULT_IF=$(ip route show default | awk '{print $5; exit}')

cat > /etc/wireguard/wg0-postup.sh <<'POSTUP'
#!/bin/bash
DEFAULT_IF=$(ip route show default | awk '{print $5; exit}')
iptables -t nat -A POSTROUTING -s HUB_SUBNET -o "$DEFAULT_IF" -j MASQUERADE
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
POSTUP
sed -i "s|HUB_SUBNET|$HUB_SUBNET|g" /etc/wireguard/wg0-postup.sh
chmod +x /etc/wireguard/wg0-postup.sh

cat > /etc/wireguard/wg0-postdown.sh <<'POSTDOWN'
#!/bin/bash
DEFAULT_IF=$(ip route show default | awk '{print $5; exit}')
iptables -t nat -D POSTROUTING -s HUB_SUBNET -o "$DEFAULT_IF" -j MASQUERADE
iptables -D FORWARD -i wg0 -j ACCEPT
iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
POSTDOWN
sed -i "s|HUB_SUBNET|$HUB_SUBNET|g" /etc/wireguard/wg0-postdown.sh
chmod +x /etc/wireguard/wg0-postdown.sh

sed -i '/PostUp\|PostDown/d' /etc/wireguard/wg0.conf
cat >> /etc/wireguard/wg0.conf <<EOF

PostUp = /etc/wireguard/wg0-postup.sh
PostDown = /etc/wireguard/wg0-postdown.sh
EOF

cat > /etc/vipsy.env <<EOF
VIPSY_BACKEND_URL=$BACKEND_URL
VIPSY_API_KEY=$API_KEY
WG_INTERFACE=wg0
EOF
chmod 600 /etc/vipsy.env
echo "Wrote /etc/vipsy.env"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cp "$SCRIPT_DIR/vipsy-sync.sh" /usr/local/bin/vipsy-sync.sh
chmod +x /usr/local/bin/vipsy-sync.sh
echo "Installed /usr/local/bin/vipsy-sync.sh"

cat > /etc/systemd/system/vipsy-sync.service <<EOF
[Unit]
Description=Vipsy Hub Peer Sync
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vipsy-sync.sh
EOF

cat > /etc/systemd/system/vipsy-sync.timer <<EOF
[Unit]
Description=Vipsy Hub Peer Sync Timer

[Timer]
OnBootSec=15s
OnUnitActiveSec=30s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now wg-quick@wg0
systemctl enable --now vipsy-sync.timer

echo ""
echo "=== Setup complete ==="
echo "WireGuard interface: wg0"
echo "Public key: $(cat /etc/wireguard/wg0-public.key)"
echo "Sync timer: every 30s"
echo ""
echo "Verify with:"
echo "  wg show wg0"
echo "  systemctl status vipsy-sync.timer"
echo "  journalctl -t vipsy-sync --no-pager -n 20"

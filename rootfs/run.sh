#!/usr/bin/env bash
set -e

OPTIONS_FILE="/data/options.json"
DOMAIN=$(jq -r '.domain // ""' "$OPTIONS_FILE")
CERTFILE=$(jq -r '.certfile // "fullchain.pem"' "$OPTIONS_FILE")
KEYFILE=$(jq -r '.keyfile // "privkey.pem"' "$OPTIONS_FILE")
ENABLE_TURN=$(jq -r '.enable_turn // true' "$OPTIONS_FILE")
TUNNEL_ENABLED=$(jq -r '.tunnel_enabled // false' "$OPTIONS_FILE")
OPTIONS_SERVICE_KEY=$(jq -r '.service_key // ""' "$OPTIONS_FILE")
if [ -n "$OPTIONS_SERVICE_KEY" ]; then
    export VIPSY_SERVICE_KEY="$OPTIONS_SERVICE_KEY"
fi

SSL_CERT="/ssl/${CERTFILE}"
SSL_KEY="/ssl/${KEYFILE}"
DATA_CERT="/data/selfsigned.crt"
DATA_KEY="/data/selfsigned.key"
CERT_IP_FILE="/data/cert_public_ip"

echo "[vipsy] detecting public IP"
PUBLIC_IP=$(curl -sf --max-time 5 https://api.ipify.org || curl -sf --max-time 5 https://checkip.amazonaws.com || echo "")
PUBLIC_IP=$(echo "$PUBLIC_IP" | tr -d '[:space:]')
echo "[vipsy] public IP: ${PUBLIC_IP:-unknown}"

HOST_IP=""
INGRESS_ENTRY=""
HTTPS_HOST_PORT="443"
if [ -n "${SUPERVISOR_TOKEN:-}" ]; then
    ADDON_INFO=$(curl -sf -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" http://supervisor/addons/self/info 2>/dev/null || echo "{}")
    INGRESS_ENTRY=$(echo "$ADDON_INFO" | jq -r '.data.ingress_entry // ""')
    HTTPS_HOST_PORT=$(echo "$ADDON_INFO" | jq -r '.data.network."443/tcp" // 443')

    NETWORK_RAW=$(curl -sf -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" http://supervisor/network/info 2>/dev/null || echo "")
    echo "[vipsy] network api response (first 400 chars): $(echo "$NETWORK_RAW" | head -c 400)"
    if [ -n "$NETWORK_RAW" ]; then
        ALL_IPS=$(echo "$NETWORK_RAW" | jq -r '.data.interfaces[]?.ipv4?.address[]?' 2>/dev/null || echo "")
        echo "[vipsy] all interface IPs: $ALL_IPS"
        HOST_IP=$(echo "$ALL_IPS" | grep -v "^172\." | grep -v "^$" | head -1 | cut -d/ -f1)
        if [ -z "$HOST_IP" ]; then
            HOST_IP=$(echo "$ALL_IPS" | grep -v "^$" | head -1 | cut -d/ -f1)
        fi
    fi
    echo "[vipsy] ingress entry: ${INGRESS_ENTRY:-not set}"
    echo "[vipsy] HTTPS host port: ${HTTPS_HOST_PORT}"
    echo "[vipsy] host IP: ${HOST_IP:-unknown}"
fi
export INGRESS_ENTRY
export HTTPS_HOST_PORT
export HOST_IP
export TUNNEL_ENABLED

build_san() {
    local san="DNS:${DOMAIN:-localhost},IP:127.0.0.1"
    [ -n "$PUBLIC_IP" ] && san="${san},IP:${PUBLIC_IP}"
    [ -n "$HOST_IP" ] && san="${san},IP:${HOST_IP}"
    echo "$san"
}

if [ -f "$SSL_CERT" ] && [ -f "$SSL_KEY" ]; then
    HAS_SAN=$(openssl x509 -in "$SSL_CERT" -noout -ext subjectAltName 2>/dev/null | grep -c "DNS\|IP" || true)
    if [ "$HAS_SAN" -gt 0 ]; then
        export TLS_CERT="$SSL_CERT"
        export TLS_KEY="$SSL_KEY"
        echo "[vipsy] using user cert: $SSL_CERT"
    else
        echo "[vipsy] user cert has no SANs — Caddy requires SANs, generating replacement"
        SAN=$(build_san)
        echo "[vipsy] cert SAN: $SAN"
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$DATA_KEY" -out "$DATA_CERT" \
            -days 3650 -subj "/CN=${DOMAIN:-${PUBLIC_IP:-localhost}}" \
            -addext "subjectAltName=${SAN}" 2>/dev/null
        echo "$PUBLIC_IP" > "$CERT_IP_FILE"
        export TLS_CERT="$DATA_CERT"
        export TLS_KEY="$DATA_KEY"
    fi
else
    REGEN=0
    if [ ! -f "$DATA_CERT" ] || [ ! -f "$DATA_KEY" ]; then
        REGEN=1
    else
        DATA_SAN=$(openssl x509 -in "$DATA_CERT" -noout -ext subjectAltName 2>/dev/null | grep -c "DNS\|IP" || true)
        PREV_IP=$(cat "$CERT_IP_FILE" 2>/dev/null || echo "")
        if [ "$DATA_SAN" -eq 0 ]; then
            REGEN=1
        elif [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "$PREV_IP" ]; then
            echo "[vipsy] public IP changed ($PREV_IP -> $PUBLIC_IP) — regenerating cert"
            REGEN=1
        elif [ -n "$HOST_IP" ]; then
            EXISTING_SAN=$(openssl x509 -in "$DATA_CERT" -noout -ext subjectAltName 2>/dev/null || echo "")
            if ! echo "$EXISTING_SAN" | grep -q "$HOST_IP"; then
                echo "[vipsy] host IP $HOST_IP not in cert SAN — regenerating"
                REGEN=1
            fi
        fi
    fi
    if [ "$REGEN" -eq 1 ]; then
        echo "[vipsy] generating self-signed certificate with SANs"
        SAN=$(build_san)
        echo "[vipsy] cert SAN: $SAN"
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$DATA_KEY" -out "$DATA_CERT" \
            -days 3650 -subj "/CN=${DOMAIN:-${PUBLIC_IP:-localhost}}" \
            -addext "subjectAltName=${SAN}" 2>/dev/null
        echo "$PUBLIC_IP" > "$CERT_IP_FILE"
    fi
    export TLS_CERT="$DATA_CERT"
    export TLS_KEY="$DATA_KEY"
    echo "[vipsy] using self-signed cert"
fi

export HA_CORE_URL="http://homeassistant:8123"
export HA_PROXY_HOST="homeassistant"
export CADDY_HTTPS_PORT=443

echo "[vipsy] applying firewall rules"
nft -f /etc/nftables.conf 2>/dev/null || echo "[vipsy] nftables skipped"

if [ "$ENABLE_TURN" = "true" ]; then
    TURN_SECRET_FILE="/data/turn_secret"
    if [ ! -f "$TURN_SECRET_FILE" ]; then
        echo "[vipsy] generating persistent TURN secret"
        openssl rand -hex 32 > "$TURN_SECRET_FILE"
    fi
    TURN_SECRET=$(cat "$TURN_SECRET_FILE")
    TURN_REALM="${DOMAIN:-homeassistant.local}"
    sed "s|{TURN_SECRET}|${TURN_SECRET}|g; s|{TURN_REALM}|${TURN_REALM}|g" \
        /coturn/turnserver.conf > /tmp/turnserver.conf
    echo "[vipsy] starting coturn"
    turnserver -c /tmp/turnserver.conf &
else
    echo "[vipsy] TURN disabled"
fi

echo "[vipsy] starting caddy"
caddy run --config /caddy/Caddyfile --adapter caddyfile &

echo "[vipsy] starting gateway on :8099"
exec python3 /server/gateway.py

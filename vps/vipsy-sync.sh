#!/usr/bin/env bash
set -euo pipefail

source /etc/vipsy.env

BACKEND_URL="${VIPSY_BACKEND_URL:-https://vipsy-backend.nitinexus.workers.dev}"
API_KEY="${VIPSY_API_KEY}"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
LOG_TAG="vipsy-sync"

log() { logger -t "$LOG_TAG" "$*"; echo "$(date -u +%FT%TZ) $*"; }

if [ -z "$API_KEY" ]; then
    log "ERROR: VIPSY_API_KEY not set in /etc/vipsy.env"
    exit 1
fi

RESPONSE=$(curl -sf --max-time 15 \
    -H "Authorization: Bearer $API_KEY" \
    "$BACKEND_URL/hub/sync") || {
    log "ERROR: Failed to fetch sync data from backend"
    exit 1
}

PARSED=$(python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
if not data.get("ok"):
    sys.stderr.write("ERROR: " + data.get("error", "unknown") + "\n")
    sys.exit(1)
peers = data.get("data", {}).get("peers", [])
print("COUNT:" + str(len(peers)))
for p in peers:
    pub = p.get("pubkey", "").strip()
    ips = p.get("allowed_ips", "").strip()
    if pub and ips:
        print(pub + "\t" + ips)
' <<< "$RESPONSE") || {
    log "ERROR: Failed to parse backend response"
    exit 1
}

PEER_COUNT=$(echo "$PARSED" | head -1 | sed 's/^COUNT://')
PEER_LINES=$(echo "$PARSED" | tail -n +2)

HUB_SUBNET="${HUB_SUBNET:-10.100.0.0/24}"

log "Sync: $PEER_COUNT active peers from backend"

WANTED_KEYS=""
WANTED_ROUTES=""
while IFS=$'\t' read -r PUBKEY ALLOWED; do
    [ -z "$PUBKEY" ] && continue
    WANTED_KEYS="${WANTED_KEYS}${PUBKEY}"$'\n'

    CURRENT_ALLOWED=$(wg show "$WG_INTERFACE" allowed-ips 2>/dev/null \
        | awk -v pk="$PUBKEY" '$1==pk {$1=""; sub(/^ /,""); print; exit}') || true

    ALLOWED_NORM=$(echo "$ALLOWED" | tr -d ' ')
    CURRENT_NORM=$(echo "$CURRENT_ALLOWED" | tr -d ' ' | tr '\t' ',')

    if [ "$CURRENT_NORM" != "$ALLOWED_NORM" ]; then
        log "Adding/updating peer ${PUBKEY:0:12}... allowed-ips=$ALLOWED"
        wg set "$WG_INTERFACE" peer "$PUBKEY" allowed-ips "$ALLOWED" || {
            log "ERROR: Failed to set peer $PUBKEY"
        }
    fi

    IFS=',' read -ra CIDRS <<< "$ALLOWED_NORM"
    for cidr in "${CIDRS[@]}"; do
        [ -z "$cidr" ] && continue
        if python3 -c "
import ipaddress, sys
subnet = ipaddress.ip_network('$cidr', strict=False)
hub = ipaddress.ip_network('$HUB_SUBNET', strict=False)
sys.exit(0 if not subnet.subnet_of(hub) and subnet != hub else 1)
" 2>/dev/null; then
            WANTED_ROUTES="${WANTED_ROUTES}${cidr}"$'\n'
            if ! ip route show "$cidr" dev "$WG_INTERFACE" 2>/dev/null | grep -q .; then
                log "Adding route $cidr dev $WG_INTERFACE"
                ip route add "$cidr" dev "$WG_INTERFACE" 2>/dev/null || true
            fi
        fi
    done
done <<< "$PEER_LINES"

CURRENT_KEYS=$(wg show "$WG_INTERFACE" peers 2>/dev/null || true)
while IFS= read -r key; do
    [ -z "$key" ] && continue
    if ! echo "$WANTED_KEYS" | grep -qF "$key"; then
        OLD_ALLOWED=$(wg show "$WG_INTERFACE" allowed-ips 2>/dev/null \
            | awk -v pk="$key" '$1==pk {$1=""; sub(/^ /,""); print; exit}') || true
        log "Removing stale peer ${key:0:12}..."
        wg set "$WG_INTERFACE" peer "$key" remove || true
        for cidr in $(echo "$OLD_ALLOWED" | tr '\t' ',' | tr ',' '\n'); do
            [ -z "$cidr" ] && continue
            if echo "$WANTED_ROUTES" | grep -qF "$cidr"; then continue; fi
            ip route del "$cidr" dev "$WG_INTERFACE" 2>/dev/null || true
        done
    fi
done <<< "$CURRENT_KEYS"

log "Sync complete"
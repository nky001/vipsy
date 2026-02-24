DEFAULTS = {
    "domain": "",
    "certfile": "fullchain.pem",
    "keyfile": "privkey.pem",
    "enable_turn": True,
    "vpn_subnet": "10.8.0.0/24",
    "vpn_port": 51820,
}

INGRESS_PORT = 8099
HA_CORE_URL = "http://homeassistant:8123"
VIPSY_BACKEND_URL = "https://vipsy-backend.nitinexus.workers.dev"
VIPSY_SERVICE_KEY = ""

VPN_DATA_DIR = "/data/wireguard"
VPN_PEERS_FILE = "/data/wireguard/peers.json"
VPN_SERVER_KEY = "/data/wireguard/server.key"
VPN_AUDIT_LOG = "/data/wireguard/audit.json"
VPN_INTERFACE = "wg0"
VPN_DEFAULT_SUBNET = "10.8.0.0/24"
VPN_DEFAULT_PORT = 51820
VPN_MAX_PEERS = 250
VPN_RATE_LIMIT = 10
VPN_RATE_WINDOW = 60
VPN_TTL_CHECK_INTERVAL = 30

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "vipsy_core")))

try:
    from vipsy_core.config import VPN_DATA_DIR
except ImportError:
    VPN_DATA_DIR = "/data/wireguard"

import ssl
import urllib.error
import urllib.request

HUB_INTERFACE = "wg-hub"
HUB_KEY_FILE = os.path.join(VPN_DATA_DIR, "hub.key")
HUB_PUB_FILE = os.path.join(VPN_DATA_DIR, "hub.pub")
HUB_CONFIG_FILE = os.path.join(VPN_DATA_DIR, "hub_config.json")
HUB_CLIENT_PEERS_FILE = os.path.join(VPN_DATA_DIR, "hub_peers.json")
HUB_ENABLED_FILE = os.path.join(VPN_DATA_DIR, "hub_enabled")

BACKEND_URL = os.environ.get("VIPSY_BACKEND_URL", "")
AUTH_TOKEN_PATH = Path("/data/auth_token")

_lock = threading.Lock()
_auth_cache: str = ""


def _bearer():
    global _auth_cache
    if _auth_cache:
        return _auth_cache
    try:
        if AUTH_TOKEN_PATH.exists():
            tok = AUTH_TOKEN_PATH.read_text().strip()
            if tok:
                _auth_cache = tok
                return tok
    except Exception:
        pass
    return os.environ.get("VIPSY_SERVICE_KEY", "")


def _api(method, path, body=None):
    url = f"{BACKEND_URL.rstrip('/')}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Authorization": f"Bearer {_bearer()}", "Content-Type": "application/json", "User-Agent": "vipsy-addon/1.0"},
    )
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            parsed = json.loads(raw)
            msg = parsed.get("error", raw[:200])
        except Exception:
            msg = raw[:200]
        raise RuntimeError(f"Backend {method} {path} HTTP {e.code}: {msg}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Backend {method} {path} network error: {e}")


def _run(cmd, check=True):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _data_dir():
    d = Path(VPN_DATA_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_or_create_hub_keys():
    key_path = Path(HUB_KEY_FILE)
    pub_path = Path(HUB_PUB_FILE)
    _data_dir()
    if key_path.exists() and pub_path.exists():
        return key_path.read_text().strip(), pub_path.read_text().strip()
    privkey = _run(["wg", "genkey"])
    pub = subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True, text=True, timeout=10)
    pubkey = pub.stdout.strip()
    key_path.write_text(privkey)
    key_path.chmod(0o600)
    pub_path.write_text(pubkey)
    return privkey, pubkey


def _load_client_peers():
    try:
        p = Path(HUB_CLIENT_PEERS_FILE)
        if p.exists():
            return json.loads(p.read_text())
    except Exception:
        pass
    return {}


def _save_client_peers(peers_map):
    _data_dir()
    p = Path(HUB_CLIENT_PEERS_FILE)
    p.write_text(json.dumps(peers_map, indent=2))
    p.chmod(0o600)


def _load_hub_config():
    try:
        cfg_path = Path(HUB_CONFIG_FILE)
        if cfg_path.exists():
            return json.loads(cfg_path.read_text())
    except Exception:
        pass
    return None


def _save_hub_config(cfg):
    _data_dir()
    p = Path(HUB_CONFIG_FILE)
    p.write_text(json.dumps(cfg, indent=2))
    p.chmod(0o600)


def _backend_available():
    return bool(BACKEND_URL and _bearer())


def _interface_exists():
    try:
        _run(["ip", "link", "show", HUB_INTERFACE])
        return True
    except RuntimeError:
        return False


def _get_lan_subnet():
    host_cidr = os.environ.get("HOST_CIDR", "")
    if host_cidr and "/" in host_cidr:
        try:
            return str(ipaddress.IPv4Network(host_cidr, strict=False))
        except ValueError:
            pass
    host_ip = os.environ.get("HOST_IP", "")
    if host_ip:
        return str(ipaddress.IPv4Network(f"{host_ip}/24", strict=False))
    return "192.168.1.0/24"


def _get_instance_id():
    uid_file = Path("/data/tunnel/uid")
    try:
        if uid_file.exists():
            uid = uid_file.read_text().strip()
            if len(uid) == 8:
                return uid
    except Exception:
        pass
    return None


logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
_log = logging.getLogger("vipsy.hub")

_HUB_NFT_COMMENT = "vipsy-hub"
_NFT_FAMILY = "ip"


def _nft_cmd(*args):
    cmd = ["nft"] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True
        print(f"[vipsy.hub] nft FAIL: {' '.join(args)[:120]} -> {r.stderr.strip()[:200]}", flush=True)
    except Exception as e:
        print(f"[vipsy.hub] nft ERROR: {e}", flush=True)
    return False


def _remove_nft_rules_by_comment(comment):
    for tbl, chains in [("filter", ["DOCKER-USER", "FORWARD"]), ("nat", ["POSTROUTING"])]:
        for chain_name in chains:
            try:
                r = subprocess.run(
                    ["nft", "-a", "list", "chain", _NFT_FAMILY, tbl, chain_name],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode != 0:
                    continue
                for line in r.stdout.splitlines():
                    if f'comment "{comment}"' in line:
                        m = re.search(r'# handle (\d+)', line)
                        if m:
                            _nft_cmd("delete", "rule", _NFT_FAMILY, tbl, chain_name, "handle", m.group(1))
            except Exception:
                pass


def _inject_docker_rules(iface, comment, hub_subnet):
    _remove_nft_rules_by_comment(comment)
    print(f"[vipsy.hub] injecting rules into {_NFT_FAMILY} filter + nat for {iface}", flush=True)
    results = []
    for chain in ("DOCKER-USER", "FORWARD"):
        ok1 = _nft_cmd("insert", "rule", _NFT_FAMILY, "filter", chain,
                       "iifname", iface, "counter", "accept", "comment", f'"{comment}"')
        ok2 = _nft_cmd("insert", "rule", _NFT_FAMILY, "filter", chain,
                       "oifname", iface, "ct", "state", "established,related",
                       "counter", "accept", "comment", f'"{comment}"')
        results.extend([ok1, ok2])
        print(f"[vipsy.hub] {chain}: iif_accept={ok1} oif_related={ok2}", flush=True)
    ok_nat = _nft_cmd("add", "rule", _NFT_FAMILY, "nat", "POSTROUTING",
                      "ip", "saddr", hub_subnet, "oifname", "!=", iface,
                      "masquerade", "comment", f'"{comment}"')
    results.append(ok_nat)
    print(f"[vipsy.hub] POSTROUTING masquerade: {ok_nat}", flush=True)
    return any(results)


def _ensure_forwarding(iface=None):
    for cmd in [["sysctl", "-w", "net.ipv4.ip_forward=1"]]:
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except Exception:
            pass
    for path in ["/proc/sys/net/ipv4/ip_forward",
                 "/proc/sys/net/ipv4/conf/all/forwarding"]:
        try:
            with open(path, "w") as f:
                f.write("1\n")
        except Exception:
            pass
    for rp in ["/proc/sys/net/ipv4/conf/all/rp_filter",
               "/proc/sys/net/ipv4/conf/default/rp_filter"]:
        try:
            with open(rp, "w") as f:
                f.write("0\n")
        except Exception:
            pass
    if iface:
        for key, val in [("rp_filter", "0"), ("forwarding", "1")]:
            try:
                with open(f"/proc/sys/net/ipv4/conf/{iface}/{key}", "w") as f:
                    f.write(val + "\n")
            except Exception:
                pass
    enabled = False
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            enabled = f.read().strip() == "1"
    except Exception:
        pass
    print(f"[vipsy.hub] ip_forward={enabled} iface={iface}", flush=True)
    return enabled


def _apply_hub_nat(hub_subnet):
    _ensure_forwarding(HUB_INTERFACE)
    lan = os.environ.get("HOST_CIDR", "")
    if not lan or "/" not in lan:
        host_ip = os.environ.get("HOST_IP", "")
        lan = f"{host_ip}/24" if host_ip else "192.168.1.0/24"
    try:
        lan = str(ipaddress.IPv4Network(lan, strict=False))
    except ValueError:
        lan = "192.168.1.0/24"
    print(f"[vipsy.hub] apply hub NAT: hub={hub_subnet} lan={lan} iface={HUB_INTERFACE}", flush=True)

    ok = _inject_docker_rules(HUB_INTERFACE, _HUB_NFT_COMMENT, hub_subnet)
    print(f"[vipsy.hub] rules injected: {ok}", flush=True)

    for lbl, cmd in [
        ("DOCKER-USER", ["nft", "list", "chain", _NFT_FAMILY, "filter", "DOCKER-USER"]),
        ("FORWARD", ["nft", "list", "chain", _NFT_FAMILY, "filter", "FORWARD"]),
        ("NAT", ["nft", "list", "chain", _NFT_FAMILY, "nat", "POSTROUTING"]),
    ]:
        try:
            vfy = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if vfy.returncode == 0:
                print(f"[vipsy.hub] {lbl}:\n{vfy.stdout.strip()}", flush=True)
            else:
                print(f"[vipsy.hub] {lbl}: {vfy.stderr.strip()[:100]}", flush=True)
        except Exception as e:
            print(f"[vipsy.hub] {lbl}: {e}", flush=True)


def _flush_hub_nat():
    print("[vipsy.hub] flushing hub NAT", flush=True)
    _remove_nft_rules_by_comment(_HUB_NFT_COMMENT)


def _register():
    if not _backend_available():
        return {"ok": False, "error": "Backend not configured"}
    instance_id = _get_instance_id()
    if not instance_id:
        return {"ok": False, "error": "Instance ID not set — sign in first to generate one"}
    _, pubkey = _get_or_create_hub_keys()
    lan_subnet = _get_lan_subnet()
    try:
        resp = _api("POST", "/hub/register", {"instance_id": instance_id, "pubkey": pubkey, "lan_subnet": lan_subnet})
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    if not resp.get("ok"):
        return {"ok": False, "error": resp.get("error", "Registration failed")}
    data = resp["data"]
    cfg = {
        "instance_id": instance_id,
        "vpn_ip": data["peer"]["vpn_ip"],
        "pubkey": data["peer"]["pubkey"],
        "lan_subnet": lan_subnet,
        "vps_endpoint": data["config"]["vps_endpoint"],
        "vps_pubkey": data["config"]["vps_pubkey"],
        "subnet": data["config"]["subnet"],
        "server_ip": data["config"]["server_ip"],
        "registered": True,
    }
    _save_hub_config(cfg)
    return {"ok": True, "config": cfg}


def enable():
    with _lock:
        if _interface_exists():
            return {"ok": True, "message": "Already connected"}
        cfg = _load_hub_config()
        if not cfg:
            reg = _register()
            if not reg.get("ok"):
                return reg
            cfg = _load_hub_config()
        if not cfg:
            return {"ok": False, "error": "Registration failed"}
        privkey, _ = _get_or_create_hub_keys()
        vpn_ip = cfg["vpn_ip"]
        subnet = cfg["subnet"]
        prefix = ipaddress.IPv4Network(subnet, strict=False).prefixlen
        vps_endpoint = cfg["vps_endpoint"]
        vps_pubkey = cfg["vps_pubkey"]
        try:
            _run(["ip", "link", "add", "dev", HUB_INTERFACE, "type", "wireguard"])
            _run(["ip", "address", "add", "dev", HUB_INTERFACE, f"{vpn_ip}/{prefix}"])
            proc = subprocess.run(
                ["wg", "set", HUB_INTERFACE, "listen-port", "0", "private-key", "/dev/stdin"],
                input=privkey, capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"wg set failed: {proc.stderr}")
            _run(["wg", "set", HUB_INTERFACE, "peer", vps_pubkey,
                  "endpoint", vps_endpoint,
                  "allowed-ips", subnet,
                  "persistent-keepalive", "25"])
            _run(["ip", "link", "set", "up", "dev", HUB_INTERFACE])
            fwd_ok = _ensure_forwarding(HUB_INTERFACE)
            _apply_hub_nat(subnet)
            try:
                Path(HUB_ENABLED_FILE).write_text("1")
            except Exception:
                pass
            msg = "Remote access enabled"
            if not fwd_ok:
                msg += " (WARNING: ip_forward could not be enabled — only this device is reachable, not other LAN hosts)"
            return {"ok": True, "message": msg, "forwarding_enabled": fwd_ok}
        except RuntimeError as e:
            try:
                _run(["ip", "link", "del", "dev", HUB_INTERFACE], check=False)
            except Exception:
                pass
            return {"ok": False, "error": str(e)}


def disable():
    with _lock:
        _flush_hub_nat()
        if _interface_exists():
            try:
                _run(["ip", "link", "del", "dev", HUB_INTERFACE])
            except RuntimeError:
                pass
        try:
            Path(HUB_ENABLED_FILE).unlink(missing_ok=True)
        except Exception:
            pass
        return {"ok": True, "message": "Remote access disabled"}


def startup_reconnect():
    enabled_flag = Path(HUB_ENABLED_FILE)
    if not enabled_flag.exists():
        print("[vipsy.hub] startup_reconnect: no hub_enabled flag, skipping", flush=True)
        return
    cfg = _load_hub_config()
    if not cfg:
        print("[vipsy.hub] startup_reconnect: no hub_config.json, skipping", flush=True)
        return
    if _interface_exists():
        print("[vipsy.hub] startup_reconnect: wg-hub already up", flush=True)
        return
    print("[vipsy.hub] startup_reconnect: hub was previously enabled, reconnecting...", flush=True)
    result = enable()
    if result.get("ok"):
        print(f"[vipsy.hub] startup_reconnect OK: {result.get('message')}", flush=True)
    else:
        print(f"[vipsy.hub] startup_reconnect FAILED: {result.get('error')}", flush=True)


def status():
    cfg = _load_hub_config()
    connected = _interface_exists()
    peer_count = 0
    try:
        local = _load_client_peers()
        peer_count = len(local)
    except Exception:
        pass
    fwd = False
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            fwd = f.read().strip() == "1"
    except Exception:
        pass
    return {
        "registered": cfg is not None,
        "connected": connected,
        "vpn_ip": cfg.get("vpn_ip") if cfg else None,
        "lan_subnet": cfg.get("lan_subnet") if cfg else None,
        "peer_count": peer_count,
        "forwarding_enabled": fwd,
    }


def add_peer(name):
    if not _backend_available():
        return {"ok": False, "error": "Backend not configured"}
    cfg = _load_hub_config()
    if not cfg:
        return {"ok": False, "error": "Enable remote access first"}
    instance_id = cfg.get("instance_id") or _get_instance_id()
    if not instance_id:
        return {"ok": False, "error": "Instance ID not found"}
    privkey = _run(["wg", "genkey"])
    pub = subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True, text=True, timeout=10)
    pubkey = pub.stdout.strip()
    try:
        resp = _api("POST", "/hub/peers", {"instance_id": instance_id, "pubkey": pubkey, "name": name})
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    if not resp.get("ok"):
        return {"ok": False, "error": resp.get("error", "Peer creation failed")}
    peer_data = resp["data"]["peer"]
    peer_cfg = _generate_client_config(peer_data, privkey, cfg)
    peers_map = _load_client_peers()
    peers_map[peer_data["peer_id"]] = {
        "peer_id": peer_data["peer_id"],
        "name": peer_data.get("name", name),
        "vpn_ip": peer_data["vpn_ip"],
        "config": peer_cfg,
    }
    _save_client_peers(peers_map)
    return {
        "ok": True,
        "peer": {**peer_data, "privkey": privkey},
        "config": peer_cfg,
        "wg_conf": peer_cfg,
    }


def _generate_client_config(peer_data, privkey, hub_cfg):
    vpn_ip = peer_data["vpn_ip"]
    subnet = hub_cfg["subnet"]
    prefix = ipaddress.IPv4Network(subnet, strict=False).prefixlen
    lan_subnet = hub_cfg.get("lan_subnet", "192.168.1.0/24")
    vps_endpoint = hub_cfg["vps_endpoint"]
    vps_pubkey = hub_cfg["vps_pubkey"]
    allowed_ips = f"{subnet}, {lan_subnet}"
    lines = [
        "[Interface]",
        f"PrivateKey = {privkey}",
        f"Address = {vpn_ip}/{prefix}",
        "DNS = 1.1.1.1, 1.0.0.1",
        "",
        "[Peer]",
        f"PublicKey = {vps_pubkey}",
        f"AllowedIPs = {allowed_ips}",
        f"Endpoint = {vps_endpoint}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def remove_peer(peer_id):
    if not _backend_available():
        return {"ok": False, "error": "Backend not configured"}
    cfg = _load_hub_config()
    instance_id = (cfg.get("instance_id") if cfg else None) or _get_instance_id()
    if not instance_id:
        return {"ok": False, "error": "Instance ID not found"}
    try:
        resp = _api("DELETE", f"/hub/peers/{peer_id}?instance_id={instance_id}")
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    if not resp.get("ok"):
        return {"ok": False, "error": resp.get("error", "Remove failed")}
    local = _load_client_peers()
    if peer_id in local:
        del local[peer_id]
        _save_client_peers(local)
    return {"ok": True}


def list_peers():
    if not _backend_available():
        return {"ok": False, "error": "Backend not configured"}
    cfg = _load_hub_config()
    instance_id = (cfg.get("instance_id") if cfg else None) or _get_instance_id()
    try:
        resp = _api("GET", "/hub/peers")
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    if not resp.get("ok"):
        return {"ok": False, "error": resp.get("error", "List failed")}
    peers = resp["data"]["peers"]
    if instance_id:
        peers = [p for p in peers if p.get("instance_id") == instance_id]
    local = _load_client_peers()
    for p in peers:
        cached = local.get(p.get("peer_id", ""))
        if cached:
            p["config"] = cached.get("config")
    return {"ok": True, "peers": peers}


def get_peer_config(peer_id):
    local = _load_client_peers()
    cached = local.get(peer_id)
    if cached:
        return cached.get("config")
    return None


def get_peer_qr(peer_id):
    config = get_peer_config(peer_id)
    if not config:
        return None
    return _generate_qr(config)


def _generate_qr(config_text):
    try:
        proc = subprocess.run(
            ["qrencode", "-t", "PNG", "-o", "-"],
            input=config_text.encode(), capture_output=True, timeout=10,
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        import qrcode
        import io
        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(config_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        pass
    return None


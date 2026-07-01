import hashlib
import json
import logging
import os
import ssl
import subprocess
import socket
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import re

logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s", force=True)
logging.getLogger("vipsy").setLevel(logging.INFO)
logging.getLogger("werkzeug").setLevel(logging.WARNING)

from flask import Flask, jsonify, render_template, request, redirect, Response

import threading

_PEER_ID_RE = re.compile(r'^[0-9a-f]{8}$')
_VPN_ITEM_ID_RE = re.compile(r'^[0-9a-f]{8,16}$')
_INSTANCE_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$')
import tunnel_manager
import vpn_manager
import hub_manager
import agent
import dns_manager
import control_plane

OPTIONS_PATH = os.environ.get("OPTIONS_PATH", "/data/options.json")
INGRESS_PORT = int(os.environ.get("INGRESS_PORT", 18099))
HA_CORE_HOST = os.environ.get("HA_CORE_HOST", "homeassistant")
HA_CORE_PORT = int(os.environ.get("HA_CORE_PORT", 8123))
HTTPS_HOST_PORT = int(os.environ.get("HTTPS_HOST_PORT", 443))
AUTH_TOKEN_PATH = Path("/data/auth_token")
DEFAULT_BACKEND_URL = "https://api.vipsy.in"
BACKEND_URL = os.environ.get("VIPSY_BACKEND_URL", DEFAULT_BACKEND_URL).strip()
CAMERA_MJPEG_INTERVAL = float(os.environ.get("VIPSY_CAMERA_MJPEG_INTERVAL", "1.0"))
CAMERA_MJPEG_BOUNDARY = "vipsyframe"


def load_options():
    p = Path(OPTIONS_PATH)
    if p.exists():
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_options(data):
    p = Path(OPTIONS_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f)


def _normalize_instance_name(value):
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    name = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
    name = re.sub(r"-{2,}", "-", name)
    if len(name) < 3 or len(name) > 32 or not _INSTANCE_NAME_RE.match(name):
        return None
    return name


def _download_slug():
    name = _normalize_instance_name(options.get("instance_name", ""))
    if name:
        return name
    uid = tunnel_manager.get_unique_id() or "instance"
    return re.sub(r"[^a-z0-9-]+", "-", uid.lower()).strip("-") or "instance"


def _download_filename(peer_id, network, extension="conf"):
    return f"vipsy-{_download_slug()}-{peer_id}-{network}.{extension}"


def _service_running(name):
    try:
        out = subprocess.check_output(["pgrep", "-x", name], stderr=subprocess.DEVNULL)
        return bool(out.strip())
    except Exception:
        return False


def _cert_expiry(cert_path):
    try:
        p = Path(cert_path)
        if p.exists():
            out = subprocess.check_output(
                ["openssl", "x509", "-enddate", "-noout", "-in", str(p)],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return out.strip().replace("notAfter=", "")
    except Exception:
        pass
    return "unknown"


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _get_public_ip():
    for url in ("https://api.ipify.org", "https://checkip.amazonaws.com"):
        try:
            req = urllib.request.urlopen(url, timeout=4)
            return req.read().decode().strip()
        except Exception:
            continue
    return None


def _port_open(host, port, timeout=4):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _ha_reachable():
    return _port_open(HA_CORE_HOST, HA_CORE_PORT)


def _ha_proxy_ok():
    try:
        req = urllib.request.Request(
            f"http://{HA_CORE_HOST}:{HA_CORE_PORT}/",
            headers={"Host": HA_CORE_HOST},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def _get_host_ip():
    host_ip = os.environ.get("HOST_IP", "")
    if host_ip:
        return host_ip
    return _get_local_ip()


def _normalize_dns_hostname(value):
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/", 1)[0].strip().rstrip(".")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if ":" in raw and raw.count(":") == 1:
        host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            raw = host
    return raw


def _normalize_dns_upstream(value):
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.hostname or ""
    else:
        raw = raw.split("/", 1)[0].strip()
        if raw.count(":") == 1:
            host, maybe_port = raw.rsplit(":", 1)
            if maybe_port.isdigit():
                raw = host
    return raw.strip()


def _suggest_dns_hostname():
    explicit = _normalize_dns_hostname(options.get("smart_dns_hostname", ""))
    if explicit:
        return explicit
    tunnel = tunnel_manager.status()
    hostname = _normalize_dns_hostname(tunnel.get("hostname"))
    if hostname:
        return hostname
    tunnel_url = _normalize_dns_hostname(tunnel.get("url"))
    if tunnel_url:
        return tunnel_url
    domain = _normalize_dns_hostname(options.get("domain", ""))
    if domain:
        return domain
    return ""


def _suggest_dns_upstream():
    explicit = _normalize_dns_upstream(options.get("smart_dns_upstream", ""))
    if explicit:
        return explicit
    try:
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line.startswith("nameserver "):
                    continue
                candidate = _normalize_dns_upstream(line.split(None, 1)[1])
                if candidate and candidate not in {"127.0.0.1", "::1"}:
                    return candidate
    except Exception:
        pass
    return "1.1.1.1"


def _validate_dns_upstream(value):
    if not value:
        return False
    if re.match(r"^[a-zA-Z0-9.-]+$", value):
        return True
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value):
        return True
    return False


def _camera_still_url(entity_id):
    pairs = [(key, value) for key, value in request.args.items(multi=True) if key != "authSig"]
    if not any(key == "token" for key, _ in pairs):
        return None
    if not any(key == "width" for key, _ in pairs):
        pairs.append(("width", "1280"))
    if not any(key == "height" for key, _ in pairs):
        pairs.append(("height", "0"))
    query = urllib.parse.urlencode(pairs, doseq=True)
    return f"http://{HA_CORE_HOST}:{HA_CORE_PORT}/api/camera_proxy/{entity_id}?{query}"


def _fetch_camera_still(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vipsy-camera-stream/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read(), resp.headers.get("Content-Type", "image/jpeg")


def _mjpeg_camera_stream(entity_id):
    still_url = _camera_still_url(entity_id)
    if not still_url:
        return Response("Camera token unavailable", status=401, mimetype="text/plain")

    def generate():
        while True:
            try:
                frame, content_type = _fetch_camera_still(still_url)
                yield (
                    f"--{CAMERA_MJPEG_BOUNDARY}\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(frame)}\r\n\r\n"
                ).encode()
                yield frame
                yield b"\r\n"
                time.sleep(max(CAMERA_MJPEG_INTERVAL, 0.25))
            except GeneratorExit:
                return
            except Exception as exc:
                print(f"[vipsy.camera] still fetch failed for {entity_id}: {exc}", flush=True)
                time.sleep(max(CAMERA_MJPEG_INTERVAL, 0.25))

    return Response(
        generate(),
        mimetype=f"multipart/x-mixed-replace; boundary={CAMERA_MJPEG_BOUNDARY}",
        headers={"Cache-Control": "no-store"},
    )


_access_cache: dict = {}
_ACCESS_TTL = 60


def _get_our_cert_fingerprint():
    cert_path = os.environ.get("TLS_CERT", "")
    if cert_path and Path(cert_path).exists():
        try:
            out = subprocess.check_output(
                ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
                stderr=subprocess.DEVNULL,
            )
            return hashlib.sha256(out).hexdigest()
        except Exception:
            pass
    return None


def _vipsy_reachable(host, port, timeout=5):
    if not host:
        return False
    our_fp = _get_our_cert_fingerprint()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as ssock:
                peer_der = ssock.getpeercert(binary_form=True)
                if not our_fp:
                    return True
                return hashlib.sha256(peer_der).hexdigest() == our_fp
    except Exception:
        return False


def _fmt_url(host, port):
    if port == 443:
        return f"https://{host}"
    return f"https://{host}:{port}"


def _build_access_info(domain):
    now = time.monotonic()
    cached = _access_cache.get("data")
    if cached and (now - _access_cache.get("ts", 0)) < _ACCESS_TTL:
        return cached

    port = HTTPS_HOST_PORT
    local_ip = _get_host_ip()
    local_reachable = _port_open("127.0.0.1", 443) if local_ip else False
    public_ip = _get_public_ip()

    if domain:
        ext_host = domain
        ext_url = _fmt_url(domain, port)
        ext_mode = "domain"
    elif public_ip:
        ext_host = public_ip
        ext_url = _fmt_url(public_ip, port)
        ext_mode = "ip"
    else:
        ext_host = None
        ext_url = None
        ext_mode = "none"

    external_reachable = _vipsy_reachable(ext_host, port) if ext_host else False

    result = {
        "local": {
            "ip": local_ip,
            "port": port,
            "url": _fmt_url(local_ip, port) if local_ip else None,
            "reachable": local_reachable,
        },
        "external": {
            "domain": domain or None,
            "public_ip": public_ip,
            "port": port,
            "url": ext_url,
            "reachable": external_reachable,
            "configured": ext_mode != "none",
            "mode": ext_mode,
        },
        "ha_core": {
            "reachable": _ha_reachable(),
            "proxy_ok": _ha_proxy_ok(),
        },
        "tunnel": tunnel_manager.status(),
    }
    _access_cache["data"] = result
    _access_cache["ts"] = now
    return result


options = load_options()

INGRESS_ENTRY = os.environ.get("INGRESS_ENTRY", "")

def _tunnel_worker():
    for attempt in range(5):
        try:
            if tunnel_manager.start():
                return
        except Exception:
            pass
        if not tunnel_manager.is_enabled():
            return
        time.sleep(min(60, 10 * (2 ** attempt)))

if tunnel_manager.is_enabled():
    threading.Thread(target=_tunnel_worker, daemon=True).start()

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)


@app.route("/")
def index():
    return render_template("index.html", **_index_context())


@app.route("/api/health")
def health():
    return jsonify(status="ok", ts=datetime.now(timezone.utc).isoformat())


@app.route("/api/status")
def status():
    domain = options.get("domain", "")
    enable_turn = options.get("enable_turn", True)
    cert_path = os.environ.get("TLS_CERT", f"/ssl/{options.get('certfile', 'fullchain.pem')}")

    return jsonify(
        caddy=_service_running("caddy"),
        turn=_service_running("turnserver") if enable_turn else None,
        tunnel=tunnel_manager.is_running() if tunnel_manager.is_enabled() else None,
        wireguard=vpn_manager._interface_exists(),
        tls=_cert_expiry(cert_path),
        mode="remote" if domain else "lan-only",
        domain=domain,
    )


@app.route("/api/access")
def access():
    domain = options.get("domain", "")
    return jsonify(_build_access_info(domain))


@app.route("/api/dns")
def dns_status():
    return jsonify(dns_manager.status())


@app.route("/api/dns", methods=["POST"])
def dns_configure():
    global options
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", False))
    hostname = _normalize_dns_hostname(body.get("hostname", "")) or _suggest_dns_hostname()
    upstream = _normalize_dns_upstream(body.get("upstream", "")) or _suggest_dns_upstream()
    ttl = body.get("ttl", 30)

    if enabled and not re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", hostname):
        return jsonify(ok=False, error="Invalid hostname"), 400
    if not _validate_dns_upstream(upstream):
        return jsonify(ok=False, error="Invalid upstream DNS server"), 400
    try:
        ttl = int(ttl)
    except Exception:
        return jsonify(ok=False, error="Invalid TTL"), 400
    if ttl < 1 or ttl > 3600:
        return jsonify(ok=False, error="TTL must be 1-3600"), 400

    options["smart_dns_enabled"] = enabled
    options["smart_dns_hostname"] = hostname
    options["smart_dns_upstream"] = upstream
    options["smart_dns_ttl"] = ttl
    save_options(options)

    state = dns_manager.apply_config(
        enabled=enabled,
        hostname=hostname,
        local_ip=_get_host_ip() or "",
        upstream=upstream,
        ttl=ttl,
        port=53,
    )
    return jsonify(ok=True, data=state)


@app.route("/api/tunnel")
def tunnel_status():
    return jsonify(tunnel_manager.status())


@app.route("/api/instance", methods=["POST"])
def instance_update():
    global options
    body = request.get_json(silent=True) or {}
    name = _normalize_instance_name(body.get("instance_name", ""))
    if name is None:
        return jsonify(ok=False, error="Use 3-32 lowercase letters, numbers, or dashes"), 400
    options["instance_name"] = name
    save_options(options)
    os.environ["INSTANCE_NAME"] = name
    return jsonify(ok=True, instance_name=name, tunnel_recreated=False)


@app.route("/api/diagnostics")
def diagnostics():
    warnings = []
    domain = options.get("domain", "")
    cert_path = os.environ.get("TLS_CERT", f"/ssl/{options.get('certfile', 'fullchain.pem')}")

    if not _service_running("caddy"):
        warnings.append("Caddy is not running — HTTPS proxy is down")
    if not Path(cert_path).exists():
        warnings.append("TLS certificate file not found")
    if options.get("enable_turn", True) and not _service_running("turnserver"):
        warnings.append("coturn is not running — WebRTC relay unavailable")
    if not domain and not _get_public_ip():
        warnings.append("No domain and no public IP detected — remote access unavailable")
    if not _ha_reachable():
        warnings.append("Home Assistant Core is not reachable")
    if not _ha_proxy_ok():
        warnings.append("HA Core returned 400 — add trusted_proxies to configuration.yaml")
    if tunnel_manager.is_enabled() and not tunnel_manager.is_running():
        err = tunnel_manager.status().get("error")
        msg = f"Cloudflare Tunnel failed to start: {err}" if err else "Cloudflare Tunnel is enabled but not running"
        warnings.append(msg)
    if tunnel_manager.is_enabled() and tunnel_manager.is_running() and not tunnel_manager.is_healthy():
        warnings.append("Cloudflare Tunnel is running but not yet healthy — check connectivity or wait a few seconds")

    vpn_status = vpn_manager.status()
    if vpn_status["enabled"] and vpn_status.get("overlap_warning"):
        warnings.append(vpn_status["overlap_warning"])
    if vpn_status["enabled"]:
        ep = vpn_manager._endpoint_info()
        if ep.get("port_forward_needed"):
            pub = ep.get("remote") or "your public IP"
            lan = ep.get("lan") or "your HA device"
            port = ep.get("port", 51820)
            warnings.append(
                f"Direct WAN VPN requires port forwarding: forward UDP {port} "
                f"on your router from {pub} to {lan}. Relay ZIP clients do not require this."
            )
        if not vpn_status.get("relay_ready"):
            detail = vpn_status.get("relay_error")
            msg = "Cloudflare VPN relay is not ready - Relay ZIP clients cannot connect"
            warnings.append(f"{msg}: {detail}" if detail else msg)

    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() != "1":
                warnings.append(
                    "IP forwarding is disabled — VPN clients can reach this device "
                    "but NOT other LAN hosts. The add-on will try to enable it when "
                    "a VPN is activated."
                )
    except Exception:
        pass

    hub_status = hub_manager.status()
    if hub_status.get("enabled") and hub_status.get("interface_up") and not hub_status.get("connected"):
        warnings.append(
            "Remote Access VPN is enabled but the VPS handshake has not completed. "
            "Verify that the VPS sync timer is running and its assigned UDP port is listening."
        )
    if hub_status.get("enabled") or vpn_status["enabled"]:
        try:
            with open("/proc/sys/net/ipv4/ip_forward") as f:
                if f.read().strip() != "1":
                    warnings.append(
                        "CRITICAL: A VPN is active but IP forwarding is still disabled. "
                        "Only this device is reachable — other LAN devices are NOT accessible."
                    )
        except Exception:
            pass

    return jsonify(warnings=warnings, count=len(warnings))


def _read_auth_token():
    try:
        if AUTH_TOKEN_PATH.exists():
            tok = AUTH_TOKEN_PATH.read_text().strip()
            if tok:
                return tok
    except Exception:
        pass
    return None


def _save_auth_token(token):
    AUTH_TOKEN_PATH.write_text(token)
    try:
        AUTH_TOKEN_PATH.chmod(0o600)
    except Exception:
        pass


def _backend_api(method, path, body=None, token=None):
    if not BACKEND_URL:
        return None
    url = f"{BACKEND_URL.rstrip('/')}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "vipsy-addon/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req_obj = urllib.request.Request(url, data=data, method=method, headers=headers)
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req_obj, context=ctx, timeout=15)
        return json.loads(resp.read())
    except Exception:
        return None


@app.route("/oauth/finish")
def oauth_finish():
    code = request.args.get("code", "")
    if not code:
        return jsonify(ok=False, error="No authorization code received"), 400
    result = _backend_api("POST", "/auth/exchange", {"code": code})
    if not result or not result.get("ok"):
        err_msg = (result or {}).get("error", "Token exchange failed")
        return jsonify(ok=False, error=err_msg), 400
    _save_auth_token(result["data"]["token"])
    tunnel_manager.reload_auth_token()
    threading.Thread(target=tunnel_manager.try_upgrade_to_static, daemon=True).start()
    return jsonify(ok=True)


@app.route("/api/auth")
def auth_status():
    token = _read_auth_token()
    if not token or not BACKEND_URL:
        return jsonify(logged_in=False, email=None, sub=None)
    info = _backend_api("GET", "/auth/me", token=token)
    if info and info.get("ok"):
        data = info.get("data", {})
        return jsonify(logged_in=True, email=data.get("email"), sub=data.get("sub"), tunnel_count=data.get("tunnel_count", 0))
    return jsonify(logged_in=False, email=None, sub=None)


@app.route("/api/auth/begin")
def auth_begin():
    if not BACKEND_URL:
        return jsonify(ok=False, error="Backend not configured"), 503
    uid = tunnel_manager.get_unique_id() or ""
    if not uid:
        try:
            uid = tunnel_manager._get_or_create_uid()
        except Exception:
            pass
    if not uid:
        return jsonify(ok=False, error="Instance ID unavailable"), 503
    result = _backend_api("GET", f"/auth/google?instance_id={urllib.parse.quote(uid)}&mode=poll")
    if not result or not result.get("ok"):
        return jsonify(ok=False, error="Failed to start OAuth flow"), 502
    data = result.get("data", {})
    return jsonify(ok=True, state=data.get("state"), auth_url=data.get("auth_url"))


@app.route("/api/auth/poll")
def auth_poll():
    if not BACKEND_URL:
        return jsonify(ok=False, error="Backend not configured"), 503
    state = request.args.get("state", "")
    if not state or len(state) < 32:
        return jsonify(ok=True, ready=False)
    result = _backend_api("GET", f"/auth/poll?state={urllib.parse.quote(state)}")
    if not result or not result.get("ok"):
        return jsonify(ok=True, ready=False)
    data = result.get("data", {})
    if data.get("ready"):
        return jsonify(ok=True, ready=True, exchange_code=data.get("exchange_code"))
    return jsonify(ok=True, ready=False)


@app.route("/logout")
def logout():
    try:
        tunnel_manager.deprovision()
    except Exception:
        pass
    hub_manager.reload_auth_cache()
    AUTH_TOKEN_PATH.unlink(missing_ok=True)
    tunnel_manager.reload_auth_token()
    return redirect(f"{INGRESS_ENTRY}/")


@app.route("/api/vpn")
def vpn_status():
    return jsonify(vpn_manager.status())


@app.route("/api/vpn/enable", methods=["POST"])
def vpn_enable():
    result = vpn_manager.enable()
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/vpn/disable", methods=["POST"])
def vpn_disable():
    result = vpn_manager.disable()
    return jsonify(result)


@app.route("/api/vpn/kill", methods=["POST"])
def vpn_kill():
    result = vpn_manager.kill()
    return jsonify(result)


@app.route("/api/vpn/peers", methods=["GET"])
def vpn_peers_list():
    return jsonify(peers=vpn_manager.list_peers())


@app.route("/api/vpn/routes", methods=["GET"])
def vpn_routes_list():
    return jsonify(ok=True, routes=vpn_manager.list_extra_subnets())


@app.route("/api/vpn/routes", methods=["POST"])
def vpn_routes_add():
    data = request.get_json(silent=True) or {}
    result = vpn_manager.add_extra_subnet(data.get("subnet", ""), data.get("name", ""))
    return jsonify(result), 201 if result.get("ok") else 400


@app.route("/api/vpn/routes/<route_id>", methods=["DELETE"])
def vpn_routes_delete(route_id):
    if not _VPN_ITEM_ID_RE.match(route_id):
        return jsonify(ok=False, error="Invalid route ID"), 400
    result = vpn_manager.remove_extra_subnet(route_id)
    return jsonify(result), 200 if result.get("ok") else 404


@app.route("/api/vpn/port-maps", methods=["GET"])
def vpn_port_maps_list():
    return jsonify(ok=True, maps=vpn_manager.list_port_maps())


@app.route("/api/vpn/port-maps", methods=["POST"])
def vpn_port_maps_add():
    data = request.get_json(silent=True) or {}
    result = vpn_manager.add_port_map(
        data.get("name", ""),
        data.get("protocol", "tcp"),
        data.get("listen_port"),
        data.get("target_ip", ""),
        data.get("target_port"),
    )
    return jsonify(result), 201 if result.get("ok") else 400


@app.route("/api/camera_proxy_stream/<path:entity_id>")
def camera_proxy_stream(entity_id):
    return _mjpeg_camera_stream(entity_id)


@app.route("/api/vpn/port-maps/<map_id>", methods=["DELETE"])
def vpn_port_maps_delete(map_id):
    if not _VPN_ITEM_ID_RE.match(map_id):
        return jsonify(ok=False, error="Invalid port map ID"), 400
    result = vpn_manager.remove_port_map(map_id)
    return jsonify(result), 200 if result.get("ok") else 404


@app.route("/api/vpn/peers", methods=["POST"])
def vpn_peers_create():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    ttl = data.get("ttl")
    persistent = data.get("persistent", False)
    dns = data.get("dns")
    if ttl is not None:
        try:
            ttl = int(ttl)
        except (ValueError, TypeError):
            return jsonify(ok=False, error="Invalid TTL value"), 400
    result = vpn_manager.add_peer(name, ttl=ttl, persistent=persistent, dns=dns)
    code = 201 if result.get("ok") else (429 if "Rate limit" in result.get("error", "") else 400)
    return jsonify(result), code


@app.route("/api/vpn/peers/<peer_id>", methods=["DELETE"])
def vpn_peers_delete(peer_id):
    if not _PEER_ID_RE.match(peer_id):
        return jsonify(ok=False, error="Invalid peer ID"), 400
    result = vpn_manager.remove_peer(peer_id)
    code = 200 if result.get("ok") else 404
    return jsonify(result), code


@app.route("/api/vpn/peers/<peer_id>/config")
def vpn_peer_config(peer_id):
    if not _PEER_ID_RE.match(peer_id):
        return jsonify(ok=False, error="Invalid peer ID"), 400
    network = request.args.get("network", "lan")
    if network not in ("remote", "lan", "tunnel"):
        network = "lan"
    config = vpn_manager.get_peer_config(peer_id, network)
    if not config:
        return jsonify(ok=False, error="Peer not found"), 404
    from flask import Response
    return Response(config, mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename={_download_filename(peer_id, network)}"})


@app.route("/api/vpn/peers/<peer_id>/qr")
def vpn_peer_qr(peer_id):
    if not _PEER_ID_RE.match(peer_id):
        return jsonify(ok=False, error="Invalid peer ID"), 400
    network = request.args.get("network", "lan")
    if network not in ("remote", "lan", "tunnel"):
        network = "lan"
    qr_data = vpn_manager.get_peer_qr(peer_id, network)
    if not qr_data:
        return jsonify(ok=False, error="Peer not found or QR generation failed"), 404
    from flask import Response
    return Response(qr_data, mimetype="image/png")


@app.route("/api/vpn/peers/<peer_id>/tunnel-bundle")
def vpn_peer_tunnel_bundle(peer_id):
    if not _PEER_ID_RE.match(peer_id):
        return jsonify(ok=False, error="Invalid peer ID"), 400
    bundle = vpn_manager.get_peer_tunnel_bundle(peer_id)
    if not bundle:
        return jsonify(ok=False, error="Tunnel URL not available yet"), 404
    from flask import Response
    return Response(bundle, mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename={_download_filename(peer_id, 'relay', 'zip')}"})





@app.route("/api/hub/status")
def hub_status():
    return jsonify(ok=True, data=hub_manager.status())


@app.route("/api/hub/enable", methods=["POST"])
def hub_enable():
    result = hub_manager.enable()
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/hub/disable", methods=["POST"])
def hub_disable():
    result = hub_manager.disable()
    return jsonify(result)


@app.route("/api/hub/peers", methods=["GET"])
def hub_list_peers():
    result = hub_manager.list_peers()
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/hub/peers", methods=["POST"])
def hub_add_peer():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    if not name:
        return jsonify(ok=False, error="name required"), 400
    result = hub_manager.add_peer(name)
    code = 201 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/hub/peers/<peer_id>", methods=["DELETE"])
def hub_remove_peer(peer_id):
    if not _PEER_ID_RE.match(peer_id):
        return jsonify(ok=False, error="Invalid peer ID"), 400
    result = hub_manager.remove_peer(peer_id)
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/hub/peers/<peer_id>/config")
def hub_peer_config(peer_id):
    if not _PEER_ID_RE.match(peer_id):
        return jsonify(ok=False, error="Invalid peer ID"), 400
    cfg_text = hub_manager.get_peer_config(peer_id)
    if not cfg_text:
        return jsonify(ok=False, error="Config not available — re-add peer to regenerate"), 404
    from flask import Response
    return Response(cfg_text, mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename={_download_filename(peer_id, 'remote')}"})


@app.route("/api/hub/peers/<peer_id>/qr")
def hub_peer_qr(peer_id):
    if not _PEER_ID_RE.match(peer_id):
        return jsonify(ok=False, error="Invalid peer ID"), 400
    qr_data = hub_manager.get_peer_qr(peer_id)
    if not qr_data:
        return jsonify(ok=False, error="Peer not found or QR generation failed"), 404
    from flask import Response
    return Response(qr_data, mimetype="image/png")


@app.route("/api/agent")
def agent_status():
    return jsonify(agent.status())


@app.route("/api/control")
def control_status():
    return jsonify(control_plane.status())


@app.route("/api/agent/enable", methods=["POST"])
def agent_enable():
    result = agent.start()
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/agent/disable", methods=["POST"])
def agent_disable():
    result = agent.stop()
    return jsonify(result)


def _hub_peers_for_template():
    try:
        result = hub_manager.list_peers()
        if result.get("ok"):
            peers = result.get("peers", [])
            return [p for p in peers if p.get("role") == "client" and p.get("active") is not False]
    except Exception:
        pass
    return []


def _index_context(**extra):
    domain = options.get("domain", "")
    instance_name = options.get("instance_name", "")
    enable_turn = options.get("enable_turn", True)
    cert_path = os.environ.get("TLS_CERT", f"/ssl/{options.get('certfile', 'fullchain.pem')}")
    caddy_up = _service_running("caddy")
    turn_up = _service_running("turnserver") if enable_turn else None
    cert_status = _cert_expiry(cert_path)
    access = _build_access_info(domain)
    tunnel = tunnel_manager.status()
    auth_token = _read_auth_token()
    uid = tunnel_manager.get_unique_id() or ""
    if not uid:
        try:
            uid = tunnel_manager._get_or_create_uid()
        except Exception:
            pass
    return dict(
        domain=domain,
        instance_name=instance_name,
        mode="Remote" if domain else "LAN-only",
        caddy_up=caddy_up,
        turn_up=turn_up,
        enable_turn=enable_turn,
        cert_status=cert_status,
        access=access,
        tunnel=tunnel,
        vpn=vpn_manager.status(),
        vpn_peers=vpn_manager.list_peers(),
        hub=hub_manager.status(),
        hub_peers=_hub_peers_for_template(),
        agent=agent.status(),
        dns=dns_manager.status(),
        dns_hostname_default=_suggest_dns_hostname(),
        dns_upstream_default=_suggest_dns_upstream(),
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        ingress_entry=INGRESS_ENTRY,
        version=options.get("_version", "2.8.8"),
        logged_in=bool(auth_token),
        backend_available=bool(BACKEND_URL),
        backend_url=BACKEND_URL,
        instance_id=uid,
        auth_error=None,
        **extra,
    )


def _control_snapshot():
    tunnel = tunnel_manager.status()
    hub = hub_manager.status()
    vpn = vpn_manager.status()
    agent_state = agent.status()
    return {
        "instance_name": options.get("instance_name") or None,
        "permanent_url": tunnel.get("url") if tunnel.get("mode") == "static" else None,
        "tunnel": {
            "enabled": tunnel.get("enabled") is True,
            "running": tunnel.get("running") is True,
            "healthy": tunnel.get("healthy") is True,
            "mode": tunnel.get("mode"),
            "hostname": tunnel.get("hostname"),
            "error": tunnel.get("error"),
        },
        "hub_connected": hub.get("connected") is True,
        "local_vpn_enabled": vpn.get("enabled") is True,
        "agent_healthy": agent_state.get("healthy") is True,
        "addon_version": options.get("_version", "2.8.8"),
    }


if __name__ == "__main__":
    tunnel_manager.start()
    vpn_manager.startup_reconnect()
    hub_manager.startup_reconnect()
    dns_manager.apply_config(
        enabled=bool(options.get("smart_dns_enabled", False)),
        hostname=_suggest_dns_hostname(),
        local_ip=_get_host_ip() or "",
        upstream=_suggest_dns_upstream(),
        ttl=int(options.get("smart_dns_ttl", 30) or 30),
        port=53,
    )
    control_plane.start(
        _control_snapshot,
        tunnel_manager._get_or_create_uid,
        tunnel_manager._get_bearer_token,
    )

    for _attempt in range(10):
        try:
            _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _s.bind(("0.0.0.0", INGRESS_PORT))
            _s.close()
            break
        except OSError:
            _s.close()
            if _attempt == 0:
                logging.warning("port %d busy, waiting for release...", INGRESS_PORT)
            time.sleep(1)
    else:
        _who = ""
        try:
            _r = subprocess.run(
                ["ss", "-tlnpH", f"sport = :{INGRESS_PORT}"],
                capture_output=True, text=True, timeout=5,
            )
            _who = _r.stdout.strip()
        except Exception:
            pass
        logging.error(
            "port %d still in use after waiting 10 s. holder: %s",
            INGRESS_PORT, _who or "unknown",
        )

    app.run(host="0.0.0.0", port=INGRESS_PORT)

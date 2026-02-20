import hashlib
import json
import os
import ssl
import subprocess
import socket
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template

OPTIONS_PATH = os.environ.get("OPTIONS_PATH", "/data/options.json")
INGRESS_PORT = int(os.environ.get("INGRESS_PORT", 8099))
HA_CORE_HOST = os.environ.get("HA_CORE_HOST", "homeassistant")
HA_CORE_PORT = int(os.environ.get("HA_CORE_PORT", 8123))
HTTPS_HOST_PORT = int(os.environ.get("HTTPS_HOST_PORT", 443))


def load_options():
    p = Path(OPTIONS_PATH)
    if p.exists():
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {}


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
    }
    _access_cache["data"] = result
    _access_cache["ts"] = now
    return result


options = load_options()

INGRESS_ENTRY = os.environ.get("INGRESS_ENTRY", "")

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)


@app.route("/")
def index():
    domain = options.get("domain", "")
    enable_turn = options.get("enable_turn", True)
    cert_path = os.environ.get("TLS_CERT", f"/ssl/{options.get('certfile', 'fullchain.pem')}")

    caddy_up = _service_running("caddy")
    turn_up = _service_running("turnserver") if enable_turn else None
    cert_status = _cert_expiry(cert_path)
    access = _build_access_info(domain)

    return render_template(
        "index.html",
        domain=domain,
        mode="Remote" if domain else "LAN-only",
        caddy_up=caddy_up,
        turn_up=turn_up,
        enable_turn=enable_turn,
        cert_status=cert_status,
        access=access,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        ingress_entry=INGRESS_ENTRY,
        version=options.get("_version", "1.0.7"),
    )


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
        tls=_cert_expiry(cert_path),
        mode="remote" if domain else "lan-only",
        domain=domain,
    )


@app.route("/api/access")
def access():
    domain = options.get("domain", "")
    return jsonify(_build_access_info(domain))


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

    return jsonify(warnings=warnings, count=len(warnings))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=INGRESS_PORT)

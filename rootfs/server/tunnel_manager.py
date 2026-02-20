import json
import os
import re
import secrets
import ssl
import string
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from threading import Lock

TUNNEL_DATA_DIR = Path("/data/tunnel")
TUNNEL_PID_FILE = TUNNEL_DATA_DIR / "cloudflared.pid"
TUNNEL_LOG_FILE = TUNNEL_DATA_DIR / "cloudflared.log"
TUNNEL_CREDS_FILE = TUNNEL_DATA_DIR / "creds.json"
TUNNEL_UID_FILE = TUNNEL_DATA_DIR / "uid"
TUNNEL_URL_FILE = TUNNEL_DATA_DIR / "tunnel_url"
TUNNEL_FALLBACK_LOG_FILE = TUNNEL_DATA_DIR / "cloudflared_fallback.log"
TUNNEL_FALLBACK_URL_FILE = TUNNEL_DATA_DIR / "tunnel_fallback_url"
METRICS_URL = "http://127.0.0.1:20241/ready"
METRICS_FALLBACK_URL = "http://127.0.0.1:20242/ready"
_QUICK_URL_RE = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
_CF_API = "https://api.cloudflare.com/client/v4"

CF_API_TOKEN = os.environ.get("VIPSY_CF_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("VIPSY_CF_ACCOUNT_ID", "")
CF_ZONE_ID = os.environ.get("VIPSY_CF_ZONE_ID", "")
CF_DOMAIN = os.environ.get("VIPSY_CF_DOMAIN", "")
HA_CORE_URL = os.environ.get("HA_CORE_URL", "http://homeassistant:8123")

_lock = Lock()
_process = None
_fallback_process = None
_provision_error: str = ""


def _ensure_dirs():
    TUNNEL_DATA_DIR.mkdir(parents=True, exist_ok=True)


def is_enabled():
    return os.environ.get("TUNNEL_ENABLED", "false").lower() == "true"


def _managed():
    return bool(CF_API_TOKEN and CF_ACCOUNT_ID and CF_ZONE_ID and CF_DOMAIN)


_CF_FRIENDLY = {
    10000: "API token authentication failed — token may be invalid or revoked.",
    9109: "API token does not have permission for this resource.",
    7003: "Zone not found — check cf_zone_id.",
    7000: "Account not found — check cf_account_id.",
}


def _cf(method, path, body=None, _retries=2):
    last_err = None
    for attempt in range(_retries + 1):
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            f"{_CF_API}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {CF_API_TOKEN}",
                "Content-Type": "application/json",
            },
        )
        ctx = ssl.create_default_context()
        try:
            resp = urllib.request.urlopen(req, context=ctx, timeout=15)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            friendly = ""
            try:
                codes = [err.get("code") for err in json.loads(raw).get("errors", [])]
                for code in codes:
                    if code in _CF_FRIENDLY:
                        friendly = _CF_FRIENDLY[code]
                        break
                if not friendly and e.code == 403:
                    friendly = "Permission denied — check your API token scopes."
            except Exception:
                pass
            msg = friendly or raw
            last_err = RuntimeError(f"CF {method} {path} HTTP {e.code}: {msg}")
            if e.code < 500:
                raise last_err
        except (urllib.error.URLError, OSError) as e:
            last_err = RuntimeError(f"CF {method} {path} network error: {e}")
        if attempt < _retries:
            time.sleep(2 * (attempt + 1))
    raise last_err


def _get_or_create_uid():
    try:
        if TUNNEL_UID_FILE.exists():
            uid = TUNNEL_UID_FILE.read_text().strip()
            if len(uid) == 8:
                return uid
    except Exception:
        pass
    alphabet = string.ascii_lowercase + string.digits
    uid = "".join(secrets.choice(alphabet) for _ in range(8))
    TUNNEL_UID_FILE.write_text(uid)
    TUNNEL_UID_FILE.chmod(0o600)
    return uid


def _load_creds():
    try:
        if TUNNEL_CREDS_FILE.exists():
            return json.loads(TUNNEL_CREDS_FILE.read_text())
    except Exception:
        pass
    return None


def _build_hostname(uid):
    labels = CF_DOMAIN.split(".")
    if len(labels) >= 3:
        prefix = labels[0]
        base = ".".join(labels[1:])
        return f"{uid}-{prefix}.{base}"
    return f"{uid}.{CF_DOMAIN}"


def _provision():
    global _provision_error
    _provision_error = ""
    _ensure_dirs()
    uid = _get_or_create_uid()
    hostname = _build_hostname(uid)
    tunnel_name = f"vipsy-{uid}"

    tunnel_id = None
    connector_token = None
    try:
        r = _cf("GET", f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel?name={tunnel_name}&is_deleted=false")
        existing = [t for t in r.get("result", []) if t.get("name") == tunnel_name]
        if existing:
            tunnel_id = existing[0]["id"]
    except Exception:
        pass

    if not tunnel_id:
        r = _cf("POST", f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel", {
            "name": tunnel_name,
            "config_src": "cloudflare",
        })
        if not r.get("success"):
            raise RuntimeError(f"Tunnel create failed: {r.get('errors')}")
        tunnel_id = r["result"]["id"]
        connector_token = r["result"].get("token")

    if not connector_token:
        r = _cf("GET", f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/token")
        tok = r.get("result", "")
        connector_token = tok if isinstance(tok, str) else str(tok)

    if not connector_token:
        raise RuntimeError("Could not obtain tunnel connector token")

    _cf("PUT", f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/configurations", {
        "config": {
            "ingress": [
                {
                    "hostname": hostname,
                    "service": "https://localhost:443",
                    "originRequest": {"noTLSVerify": True},
                },
                {"service": "http_status:404"},
            ]
        }
    })

    creds = {
        "uid": uid,
        "tunnel_id": tunnel_id,
        "connector_token": connector_token,
        "hostname": hostname,
        "url": f"https://{hostname}",
        "dns_ok": False,
    }
    TUNNEL_CREDS_FILE.write_text(json.dumps(creds))
    TUNNEL_CREDS_FILE.chmod(0o600)
    TUNNEL_URL_FILE.write_text(creds["url"])
    _ensure_dns(creds)
    return creds


def _ensure_dns(creds):
    if creds.get("dns_ok"):
        return
    if not _managed():
        return
    hostname = creds.get("hostname")
    tunnel_id = creds.get("tunnel_id")
    if not hostname or not tunnel_id:
        return
    cname_content = f"{tunnel_id}.cfargotunnel.com"
    try:
        resp = _cf("GET", f"/zones/{CF_ZONE_ID}/dns_records?name={hostname}&type=CNAME")
        records = resp.get("result", [])
        if records:
            _cf("PUT", f"/zones/{CF_ZONE_ID}/dns_records/{records[0]['id']}", {
                "type": "CNAME", "name": hostname,
                "content": cname_content, "proxied": True, "ttl": 1,
            })
        else:
            _cf("POST", f"/zones/{CF_ZONE_ID}/dns_records", {
                "type": "CNAME", "name": hostname,
                "content": cname_content, "proxied": True, "ttl": 1,
            })
        creds["dns_ok"] = True
        TUNNEL_CREDS_FILE.write_text(json.dumps(creds))
    except RuntimeError as exc:
        global _provision_error
        msg = str(exc)
        if "403" in msg or "Permission denied" in msg or "authentication" in msg.lower():
            _provision_error = (
                "DNS setup failed (403): your API token is missing Zone DNS Edit "
                "permission. Edit your token in Cloudflare and add Zone:DNS:Edit."
            )
        else:
            _provision_error = f"DNS setup failed: {msg}"
    except Exception:
        pass


def _ensure_ingress(creds):
    hostname = creds.get("hostname")
    tunnel_id = creds.get("tunnel_id")
    if not hostname or not tunnel_id:
        return
    try:
        _cf("PUT", f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/configurations", {
            "config": {
                "ingress": [
                    {
                        "hostname": hostname,
                        "service": "https://localhost:443",
                        "originRequest": {"noTLSVerify": True},
                    },
                    {"service": "http_status:404"},
                ]
            }
        })
    except Exception:
        pass


def _migrate_creds(creds):
    uid = creds.get("uid", "")
    if not uid:
        return creds
    expected = _build_hostname(uid)
    old_hostname = creds.get("hostname", "")
    if old_hostname and old_hostname != expected:
        try:
            resp = _cf("GET", f"/zones/{CF_ZONE_ID}/dns_records?name={old_hostname}&type=CNAME")
            for rec in resp.get("result", []):
                try:
                    _cf("DELETE", f"/zones/{CF_ZONE_ID}/dns_records/{rec['id']}")
                except Exception:
                    pass
        except Exception:
            pass
        creds["hostname"] = expected
        creds["url"] = f"https://{expected}"
        creds["dns_ok"] = False
        TUNNEL_CREDS_FILE.write_text(json.dumps(creds))
        TUNNEL_URL_FILE.write_text(creds["url"])
    return creds


def deprovision():
    stop()
    creds = _load_creds()
    if not creds or not _managed():
        return
    tunnel_id = creds.get("tunnel_id")
    hostname = creds.get("hostname")
    if tunnel_id:
        try:
            _cf("DELETE", f"/accounts/{CF_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}?cascade=true")
        except Exception:
            pass
    if hostname:
        try:
            resp = _cf("GET", f"/zones/{CF_ZONE_ID}/dns_records?name={hostname}")
            for rec in resp.get("result", []):
                try:
                    _cf("DELETE", f"/zones/{CF_ZONE_ID}/dns_records/{rec['id']}")
                except Exception:
                    pass
        except Exception:
            pass
    TUNNEL_CREDS_FILE.unlink(missing_ok=True)
    TUNNEL_URL_FILE.unlink(missing_ok=True)


def _parse_quick_url():
    try:
        if TUNNEL_URL_FILE.exists():
            url = TUNNEL_URL_FILE.read_text().strip()
            if url.startswith("https://"):
                return url
    except Exception:
        pass
    try:
        if TUNNEL_LOG_FILE.exists():
            content = TUNNEL_LOG_FILE.read_text(errors="replace")
            m = _QUICK_URL_RE.search(content)
            if m:
                TUNNEL_URL_FILE.write_text(m.group(0))
                return m.group(0)
    except Exception:
        pass
    return None


def _parse_fallback_url():
    try:
        if TUNNEL_FALLBACK_URL_FILE.exists():
            url = TUNNEL_FALLBACK_URL_FILE.read_text().strip()
            if url.startswith("https://"):
                return url
    except Exception:
        pass
    try:
        if TUNNEL_FALLBACK_LOG_FILE.exists():
            content = TUNNEL_FALLBACK_LOG_FILE.read_text(errors="replace")
            m = _QUICK_URL_RE.search(content)
            if m:
                TUNNEL_FALLBACK_URL_FILE.write_text(m.group(0))
                return m.group(0)
    except Exception:
        pass
    return None


def _is_fallback_running():
    global _fallback_process
    return _fallback_process is not None and _fallback_process.poll() is None


def _start_fallback():
    global _fallback_process
    if _is_fallback_running():
        return
    TUNNEL_FALLBACK_URL_FILE.unlink(missing_ok=True)
    log_fd = open(TUNNEL_FALLBACK_LOG_FILE, "w")
    try:
        _fallback_process = subprocess.Popen(
            [
                "cloudflared", "tunnel",
                "--no-autoupdate",
                "--no-tls-verify",
                "--metrics", "127.0.0.1:20242",
                "--url", "https://localhost:443",
            ],
            stdout=log_fd,
            stderr=log_fd,
        )
        log_fd.close()
    except Exception:
        log_fd.close()


def get_hostname():
    creds = _load_creds()
    if creds:
        return creds.get("hostname")
    url = _parse_quick_url()
    return url.replace("https://", "").strip("/") if url else None


def get_unique_id():
    creds = _load_creds()
    if creds:
        return creds.get("uid")
    try:
        if TUNNEL_UID_FILE.exists():
            return TUNNEL_UID_FILE.read_text().strip() or None
    except Exception:
        pass
    return None


def is_running():
    global _process
    if _process is not None and _process.poll() is None:
        return True
    try:
        out = subprocess.check_output(
            ["pgrep", "-x", "cloudflared"], stderr=subprocess.DEVNULL
        )
        return bool(out.strip())
    except Exception:
        return False


def is_healthy():
    if not is_running():
        return False
    if _managed():
        try:
            resp = urllib.request.urlopen(METRICS_URL, timeout=3)
            return resp.status == 200
        except Exception:
            return False
    return _parse_quick_url() is not None


def start():
    global _process, _provision_error
    with _lock:
        if is_running():
            return True
        if not is_enabled():
            return False
        _ensure_dirs()
        log_fd = open(TUNNEL_LOG_FILE, "w")
        try:
            if _managed():
                creds = _load_creds()
                if not creds:
                    creds = _provision()
                else:
                    creds = _migrate_creds(creds)
                    _ensure_ingress(creds)
                    _ensure_dns(creds)
                TUNNEL_URL_FILE.write_text(creds["url"])
                cmd = [
                    "cloudflared", "tunnel",
                    "--no-autoupdate",
                    "--metrics", "127.0.0.1:20241",
                    "run", "--token", creds["connector_token"],
                ]
            else:
                TUNNEL_URL_FILE.unlink(missing_ok=True)
                cmd = [
                    "cloudflared", "tunnel",
                    "--no-autoupdate",
                    "--no-tls-verify",
                    "--url", "https://localhost:443",
                ]
            _process = subprocess.Popen(cmd, stdout=log_fd, stderr=log_fd)
            log_fd.close()
            TUNNEL_PID_FILE.write_text(str(_process.pid))
            if _managed():
                _start_fallback()
            return True
        except Exception as exc:
            log_fd.close()
            _provision_error = str(exc)
            _start_fallback()
            return False


def stop():
    global _process, _fallback_process
    with _lock:
        if _process is not None and _process.poll() is None:
            _process.terminate()
            try:
                _process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _process.kill()
                _process.wait(timeout=5)
            _process = None
        if _fallback_process is not None and _fallback_process.poll() is None:
            _fallback_process.terminate()
            try:
                _fallback_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _fallback_process.kill()
                _fallback_process.wait(timeout=3)
            _fallback_process = None
        try:
            subprocess.run(
                ["pkill", "-x", "cloudflared"],
                stderr=subprocess.DEVNULL, check=False,
            )
        except Exception:
            pass
        TUNNEL_PID_FILE.unlink(missing_ok=True)
        TUNNEL_FALLBACK_URL_FILE.unlink(missing_ok=True)
        return True


def restart():
    stop()
    time.sleep(1)
    return start()


def status():
    running = is_running()
    healthy = is_healthy() if running else False
    creds = _load_creds()
    fallback_url = _parse_fallback_url() if _is_fallback_running() else None
    if creds:
        mode = "static"
        hostname = creds.get("hostname")
        url = creds.get("url")
        uid = creds.get("uid")
    else:
        mode = "quick"
        url = _parse_quick_url() if running else None
        hostname = url.replace("https://", "").strip("/") if url else None
        uid = get_unique_id()
        fallback_url = None
    return {
        "enabled": is_enabled(),
        "managed": _managed(),
        "running": running,
        "healthy": healthy,
        "mode": mode,
        "hostname": hostname,
        "unique_id": uid,
        "url": url,
        "fallback_url": fallback_url,
        "provider": "cloudflare",
        "error": _provision_error or None,
    }


def tail_log(lines=50):
    try:
        if TUNNEL_LOG_FILE.exists():
            all_lines = TUNNEL_LOG_FILE.read_text().splitlines()
            return "\n".join(all_lines[-lines:])
    except Exception:
        pass
    return ""

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

BACKEND_URL = os.environ.get("VIPSY_BACKEND_URL", "")
SERVICE_KEY = os.environ.get("VIPSY_SERVICE_KEY", "7ae5a1d9a1d4ecf98c2d08f23441638924c370e1686deba790f0cd3d1fc26426")
AUTH_TOKEN_PATH = Path("/data/auth_token")

_lock = Lock()
_process = None
_fallback_process = None
_provision_error: str = ""
_auth_token_cache: str = ""


def _get_bearer_token():
    global _auth_token_cache
    if _auth_token_cache:
        return _auth_token_cache
    try:
        if AUTH_TOKEN_PATH.exists():
            tok = AUTH_TOKEN_PATH.read_text().strip()
            if tok:
                _auth_token_cache = tok
                return tok
    except Exception:
        pass
    return SERVICE_KEY


def reload_auth_token():
    global _auth_token_cache
    _auth_token_cache = ""


def _ensure_dirs():
    TUNNEL_DATA_DIR.mkdir(parents=True, exist_ok=True)


def is_enabled():
    return os.environ.get("TUNNEL_ENABLED", "false").lower() == "true"


def _backend_available():
    return bool(BACKEND_URL and _get_bearer_token())


def _api(method, path, body=None):
    url = f"{BACKEND_URL.rstrip('/')}{path}"
    data = json.dumps(body).encode() if body else None
    bearer = _get_bearer_token()
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "User-Agent": "vipsy-addon/1.0",
        },
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
            code = parsed.get("code", "")
        except Exception:
            msg = raw[:200]
            code = ""
        raise RuntimeError(f"Backend {method} {path} HTTP {e.code}: {msg} [{code}]")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Backend {method} {path} network error: {e}")


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
    _ensure_dirs()
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


def _save_creds(creds):
    _ensure_dirs()
    TUNNEL_CREDS_FILE.write_text(json.dumps(creds))
    TUNNEL_CREDS_FILE.chmod(0o600)
    if creds.get("url"):
        TUNNEL_URL_FILE.write_text(creds["url"])


def _register():
    global _provision_error
    uid = _get_or_create_uid()
    resp = _api("POST", "/tunnel/register", {"instance_id": uid})
    if not resp.get("ok"):
        msg = resp.get("error", "Registration failed")
        _provision_error = msg
        raise RuntimeError(msg)
    data = resp["data"]
    creds = {
        "uid": uid,
        "tunnel_id": data["tunnel_id"],
        "connector_token": data["connector_token"],
        "hostname": data["hostname"],
        "url": data["url"],
        "dns_ok": data.get("dns_ok", False),
    }
    _save_creds(creds)
    return creds


def deprovision():
    stop()
    if not _backend_available():
        return
    uid = _get_or_create_uid()
    try:
        _api("POST", "/tunnel/deregister", {"instance_id": uid})
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
    _ensure_dirs()
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
    if _backend_available() and _load_creds():
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
            if _backend_available():
                creds = _load_creds()
                if not creds:
                    creds = _register()
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
            if _backend_available():
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


def try_upgrade_to_static():
    if not is_enabled():
        return False
    if not _backend_available():
        return False
    if _load_creds():
        return False
    if not is_running():
        return start()
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
    return {
        "enabled": is_enabled(),
        "managed": _backend_available(),
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

import hashlib
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from threading import Lock

TUNNEL_DATA_DIR = Path("/data/tunnel")
TUNNEL_PID_FILE = TUNNEL_DATA_DIR / "cloudflared.pid"
TUNNEL_LOG_FILE = TUNNEL_DATA_DIR / "cloudflared.log"
METRICS_URL = "http://127.0.0.1:20241/ready"

_lock = Lock()
_process = None


def _ensure_dirs():
    TUNNEL_DATA_DIR.mkdir(parents=True, exist_ok=True)


def is_enabled():
    return (
        os.environ.get("TUNNEL_ENABLED", "false").lower() == "true"
        and bool(os.environ.get("TUNNEL_TOKEN", "").strip())
    )


def get_hostname():
    return os.environ.get("TUNNEL_HOSTNAME", "").strip()


def get_unique_id():
    hostname = get_hostname()
    if hostname:
        parts = hostname.split(".")
        if len(parts) > 2:
            return parts[0]
        return hostname
    token = os.environ.get("TUNNEL_TOKEN", "").strip()
    if token:
        return hashlib.sha256(token.encode()).hexdigest()[:12]
    return ""


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
    try:
        resp = urllib.request.urlopen(METRICS_URL, timeout=3)
        return resp.status == 200
    except Exception:
        return False


def start():
    global _process
    with _lock:
        if is_running():
            return True
        if not is_enabled():
            return False
        _ensure_dirs()
        token = os.environ.get("TUNNEL_TOKEN", "").strip()
        if not token:
            return False
        log_fd = open(TUNNEL_LOG_FILE, "a")
        _process = subprocess.Popen(
            [
                "cloudflared", "tunnel",
                "--no-autoupdate",
                "--metrics", "127.0.0.1:20241",
                "run", "--token", token,
            ],
            stdout=log_fd,
            stderr=log_fd,
        )
        TUNNEL_PID_FILE.write_text(str(_process.pid))
        return True


def stop():
    global _process
    with _lock:
        if _process is not None and _process.poll() is None:
            _process.terminate()
            try:
                _process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _process.kill()
                _process.wait(timeout=5)
            _process = None
        try:
            subprocess.run(
                ["pkill", "-x", "cloudflared"],
                stderr=subprocess.DEVNULL, check=False,
            )
        except Exception:
            pass
        TUNNEL_PID_FILE.unlink(missing_ok=True)
        return True


def restart():
    stop()
    time.sleep(1)
    return start()


def status():
    running = is_running()
    healthy = is_healthy() if running else False
    hostname = get_hostname()
    uid = get_unique_id()
    return {
        "enabled": is_enabled(),
        "running": running,
        "healthy": healthy,
        "hostname": hostname or None,
        "unique_id": uid or None,
        "url": f"https://{hostname}" if hostname else None,
        "provider": "cloudflare",
    }


def tail_log(lines=50):
    try:
        if TUNNEL_LOG_FILE.exists():
            all_lines = TUNNEL_LOG_FILE.read_text().splitlines()
            return "\n".join(all_lines[-lines:])
    except Exception:
        pass
    return ""

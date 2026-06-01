import json
import logging
import os
import re
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path

BACKEND_URL = os.environ.get("VIPSY_BACKEND_URL", "https://api.vipsy.in").strip()
SUPERVISOR_URL = os.environ.get("SUPERVISOR_URL", "http://supervisor").rstrip("/")
LAST_COMMAND_PATH = Path(os.environ.get("VIPSY_CONTROL_LAST_COMMAND_PATH", "/data/control_last_command"))
HEARTBEAT_INTERVAL = max(30, min(300, int(os.environ.get("VIPSY_CONTROL_HEARTBEAT_INTERVAL", "60"))))
INITIAL_DELAY = max(5, min(120, int(os.environ.get("VIPSY_CONTROL_INITIAL_DELAY", "15"))))
_COMMAND_ID_RE = re.compile(r"^[a-f0-9-]{36}$")

_log = logging.getLogger("vipsy.control")
_stop = threading.Event()
_thread = None
_state_lock = threading.Lock()
_state = {
    "running": False,
    "last_success": None,
    "last_error": None,
    "last_command_id": None,
}


def _update_state(**changes):
    with _state_lock:
        _state.update(changes)


def status():
    with _state_lock:
        return dict(_state)


def _load_last_command_id():
    try:
        command_id = LAST_COMMAND_PATH.read_text(encoding="utf-8").strip()
        return command_id if _COMMAND_ID_RE.match(command_id) else None
    except Exception:
        return None


def _persist_last_command_id(command_id):
    if not _COMMAND_ID_RE.match(command_id or ""):
        return False
    try:
        LAST_COMMAND_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = LAST_COMMAND_PATH.with_suffix(".tmp")
        tmp.write_text(command_id, encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(LAST_COMMAND_PATH)
        LAST_COMMAND_PATH.chmod(0o600)
        _update_state(last_command_id=command_id)
        return True
    except Exception as exc:
        _log.warning("could not persist restart command marker: %s", exc)
        return False


def _post_heartbeat(payload, bearer):
    if not BACKEND_URL or not bearer:
        raise RuntimeError("backend URL or bearer token unavailable")
    req = urllib.request.Request(
        f"{BACKEND_URL.rstrip('/')}/addon/heartbeat",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "User-Agent": "vipsy-addon-control/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=10) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")[:200]
        raise RuntimeError(f"heartbeat HTTP {exc.code}: {raw}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"heartbeat failed: {exc}") from exc


def _request_supervisor_restart():
    token = os.environ.get("SUPERVISOR_TOKEN", "").strip()
    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN unavailable")
    req = urllib.request.Request(
        f"{SUPERVISOR_URL}/addons/self/restart",
        data=b"{}",
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status < 300
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")[:200]
        raise RuntimeError(f"Supervisor restart HTTP {exc.code}: {raw}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"Supervisor restart failed: {exc}") from exc


def _fresh_restart_command(command):
    if not isinstance(command, dict):
        return None
    command_id = command.get("id")
    if command.get("type") != "restart_addon" or not isinstance(command_id, str):
        return None
    if not _COMMAND_ID_RE.match(command_id):
        return None
    if command_id == _load_last_command_id():
        return None
    return command_id


def _heartbeat_once(snapshot_provider, instance_id_provider, bearer_provider):
    snapshot = snapshot_provider()
    instance_id = instance_id_provider()
    if not instance_id:
        raise RuntimeError("instance ID unavailable")
    payload = {"instance_id": instance_id, **snapshot}
    last_command_id = _load_last_command_id()
    if last_command_id:
        payload["last_command_id"] = last_command_id
    result = _post_heartbeat(payload, bearer_provider())
    command = ((result or {}).get("data") or {}).get("command")
    command_id = _fresh_restart_command(command)
    if not command_id:
        return False

    # Persist before restart so a delayed Supervisor response cannot create a loop.
    if not _persist_last_command_id(command_id):
        return False
    payload["last_command_id"] = command_id
    try:
        _post_heartbeat(payload, bearer_provider())
    except Exception as exc:
        _log.warning("restart command acknowledgement delayed: %s", exc)
    _log.info("requesting Supervisor restart for command %s", command_id)
    _request_supervisor_restart()
    return True


def _worker(snapshot_provider, instance_id_provider, bearer_provider):
    _update_state(running=True, last_command_id=_load_last_command_id())
    if _stop.wait(INITIAL_DELAY):
        _update_state(running=False)
        return
    while not _stop.is_set():
        try:
            _heartbeat_once(snapshot_provider, instance_id_provider, bearer_provider)
            from datetime import datetime, timezone
            _update_state(last_success=datetime.now(timezone.utc).isoformat(), last_error=None)
        except Exception as exc:
            _update_state(last_error=str(exc)[:240])
            _log.warning("heartbeat skipped: %s", exc)
        if _stop.wait(HEARTBEAT_INTERVAL):
            break
    _update_state(running=False)


def start(snapshot_provider, instance_id_provider, bearer_provider):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(
        target=_worker,
        args=(snapshot_provider, instance_id_provider, bearer_provider),
        daemon=True,
        name="vipsy-control-plane",
    )
    _thread.start()


def stop():
    _stop.set()

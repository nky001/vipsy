import asyncio
import json
import os
import re
from typing import Any

import websockets

LISTEN_HOST = os.environ.get("HA_WS_PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("HA_WS_PROXY_PORT", "18100"))
UPSTREAM_URL = os.environ.get("HA_WS_UPSTREAM_URL", "ws://homeassistant:8123/api/websocket")
ENABLE_HLS_FALLBACK = os.environ.get("VIPSY_GENERIC_CAMERA_HLS_FALLBACK", "true").lower() == "true"
GENERIC_CAMERA_RE = re.compile(
    os.environ.get(
        "VIPSY_GENERIC_CAMERA_PATTERN",
        r"^camera\.(generic_|[0-9]{1,3}(?:_[0-9]{1,3}){3}(?:_|$))",
    )
)
WEBRTC_TYPES = {"web_rtc", "webrtc"}
HLS_TYPES = {"hls"}


def _stream_type_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_")


def _update_camera_meta(camera_meta: dict[str, dict[str, str]], payload: Any) -> None:
    if isinstance(payload, list):
        for item in payload:
            _update_camera_meta(camera_meta, item)
        return
    if not isinstance(payload, dict):
        return
    entity_id = payload.get("entity_id")
    if not isinstance(entity_id, str) or not entity_id.startswith("camera."):
        return
    attrs = payload.get("attributes")
    if not isinstance(attrs, dict):
        return
    camera_meta[entity_id] = {
        "brand": str(attrs.get("brand") or attrs.get("manufacturer") or "").strip().lower(),
        "model": str(attrs.get("model_name") or attrs.get("model") or "").strip().lower(),
        "friendly_name": str(attrs.get("friendly_name") or "").strip().lower(),
    }


def _is_generic_camera(entity_id: str, camera_meta: dict[str, dict[str, str]]) -> bool:
    meta = camera_meta.get(entity_id, {})
    if "generic" in {meta.get("brand"), meta.get("model")}:
        return True
    if GENERIC_CAMERA_RE.search(entity_id):
        return True
    return False


def _downgrade_capabilities_if_needed(
    message: str,
    pending_capabilities: dict[int, str],
    camera_meta: dict[str, dict[str, str]],
) -> str:
    try:
        data = json.loads(message)
    except (TypeError, json.JSONDecodeError):
        return message

    if isinstance(data, dict) and data.get("type") == "result" and data.get("success"):
        _update_camera_meta(camera_meta, data.get("result"))
        msg_id = data.get("id")
        entity_id = pending_capabilities.pop(msg_id, None) if isinstance(msg_id, int) else None
        result = data.get("result")
        if ENABLE_HLS_FALLBACK and entity_id and _is_generic_camera(entity_id, camera_meta) and isinstance(result, dict):
            stream_types = result.get("frontend_stream_types")
            if isinstance(stream_types, list):
                keys = {_stream_type_key(item) for item in stream_types}
                if keys & WEBRTC_TYPES and keys & HLS_TYPES:
                    result["frontend_stream_types"] = [
                        item for item in stream_types if _stream_type_key(item) not in WEBRTC_TYPES
                    ]
                    print(f"[vipsy.ws] forcing HLS camera stream for {entity_id}", flush=True)
                    return json.dumps(data, separators=(",", ":"))
    elif isinstance(data, dict):
        event = data.get("event")
        if isinstance(event, dict):
            _update_camera_meta(camera_meta, event.get("data", {}).get("new_state"))
    return message


async def _client_to_ha(client_ws, ha_ws, pending_capabilities: dict[int, str]) -> None:
    async for message in client_ws:
        if isinstance(message, str):
            try:
                data = json.loads(message)
                if isinstance(data, dict) and data.get("type") == "camera/capabilities":
                    msg_id = data.get("id")
                    entity_id = data.get("entity_id")
                    if isinstance(msg_id, int) and isinstance(entity_id, str):
                        pending_capabilities[msg_id] = entity_id
            except json.JSONDecodeError:
                pass
        await ha_ws.send(message)


async def _ha_to_client(client_ws, ha_ws, pending_capabilities: dict[int, str], camera_meta: dict[str, dict[str, str]]) -> None:
    async for message in ha_ws:
        if isinstance(message, str):
            message = _downgrade_capabilities_if_needed(message, pending_capabilities, camera_meta)
        await client_ws.send(message)


async def _handle_client(client_ws, path=None) -> None:
    pending_capabilities: dict[int, str] = {}
    camera_meta: dict[str, dict[str, str]] = {}
    try:
        async with websockets.connect(UPSTREAM_URL, max_size=None, ping_interval=20, ping_timeout=20) as ha_ws:
            to_ha = asyncio.create_task(_client_to_ha(client_ws, ha_ws, pending_capabilities))
            to_client = asyncio.create_task(_ha_to_client(client_ws, ha_ws, pending_capabilities, camera_meta))
            done, pending = await asyncio.wait({to_ha, to_client}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                task.result()
    except Exception as exc:
        print(f"[vipsy.ws] websocket proxy closed: {exc}", flush=True)


async def _run() -> None:
    print(f"[vipsy.ws] listening on {LISTEN_HOST}:{LISTEN_PORT}, upstream={UPSTREAM_URL}", flush=True)
    async with websockets.serve(_handle_client, LISTEN_HOST, LISTEN_PORT, max_size=None):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_run())

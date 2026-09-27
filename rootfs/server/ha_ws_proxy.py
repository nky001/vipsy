"""Transparent HA websocket relay with non-blocking camera diagnostics."""
import asyncio
import json
import os
import re

import websockets
from camera_diagnostics import CameraDiagnostics

LISTEN_HOST = os.environ.get("HA_WS_PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("HA_WS_PROXY_PORT", "18100"))
UPSTREAM_URL = os.environ.get("HA_WS_UPSTREAM_URL", "ws://homeassistant:8123/api/websocket")
UPSTREAM_HEADER_ALLOWLIST = {
    "authorization", "cookie", "user-agent", "x-ha-access",
    "x-hassio-key", "x-supervisor-token",
}
CAMERA_ENTITY = re.compile(r"camera\.[a-z0-9_]{1,200}\Z")
MAX_PENDING = 128
diagnostics = CameraDiagnostics()


def _json_object(message):
    if not isinstance(message, str):
        return {}
    try:
        data = json.loads(message)
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


async def _client_to_ha(client_ws, ha_ws, pending):
    async for message in client_ws:
        data = _json_object(message)
        command, entity, msg_id = data.get("type"), data.get("entity_id"), data.get("id")
        if (command in ("camera/capabilities", "camera/stream")
                and type(msg_id) is int and isinstance(entity, str)
                and CAMERA_ENTITY.fullmatch(entity)):
            if len(pending) >= MAX_PENDING:
                pending.pop(next(iter(pending)))
            pending[msg_id] = (command, entity)
        await ha_ws.send(message)


async def _ha_to_client(client_ws, ha_ws, pending):
    async for message in ha_ws:
        # Never invent capabilities or disable WebRTC based on entity names.
        # Forward first: camera diagnostics must not stall the HA UI.
        await client_ws.send(message)
        data = _json_object(message)
        if data.get("type") != "result" or type(data.get("id")) is not int:
            continue
        tracked = pending.pop(data["id"], None)
        if not tracked:
            continue
        command, entity = tracked
        if data.get("success") is not True:
            # Upstream error messages can contain camera passwords/bearer URLs.
            diagnostics.record(entity, {"event": "ha_request_failed", "command": command})
            continue
        result = data.get("result")
        if not isinstance(result, dict):
            continue
        if command == "camera/capabilities":
            types = result.get("frontend_stream_types")
            if isinstance(types, list):
                diagnostics.record(entity, {
                    "event": "capabilities", "transports": [
                        value for value in types if value in ("hls", "web_rtc")
                    ], "policy": "native",
                })
        elif isinstance(result.get("url"), str):
            diagnostics.schedule(entity, result["url"])


def _upstream_headers(client_ws):
    headers = getattr(client_ws, "request_headers", None)
    if not headers:
        return []
    return [(name, value) for name, value in headers.raw_items()
            if name.lower() in UPSTREAM_HEADER_ALLOWLIST]


def _upstream_origin(client_ws):
    headers = getattr(client_ws, "request_headers", None)
    return headers.get("Origin") if headers else None


async def _handle_client(client_ws, path=None):
    pending, tasks = {}, set()
    try:
        async with websockets.connect(
            UPSTREAM_URL, extra_headers=_upstream_headers(client_ws),
            origin=_upstream_origin(client_ws), max_size=None,
            ping_interval=20, ping_timeout=20,
        ) as ha_ws:
            tasks = {
                asyncio.create_task(_client_to_ha(client_ws, ha_ws, pending)),
                asyncio.create_task(_ha_to_client(client_ws, ha_ws, pending)),
            }
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
    except websockets.ConnectionClosed:
        pass
    except Exception as exc:
        print(f"[vipsy.ws] upstream connection failed: {type(exc).__name__}", flush=True)
        await client_ws.close(code=1011, reason="Home Assistant connection unavailable")
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        pending.clear()


async def _run():
    print(f"[vipsy.ws] listening on {LISTEN_HOST}:{LISTEN_PORT}; camera policy=native", flush=True)
    async with websockets.serve(_handle_client, LISTEN_HOST, LISTEN_PORT, max_size=None):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_run())

import asyncio
import os

import websockets

LISTEN_HOST = os.environ.get("HA_WS_PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("HA_WS_PROXY_PORT", "18100"))
UPSTREAM_URL = os.environ.get("HA_WS_UPSTREAM_URL", "ws://homeassistant:8123/api/websocket")
UPSTREAM_HEADER_ALLOWLIST = {
    "authorization",
    "cookie",
    "user-agent",
    "x-ha-access",
    "x-hassio-key",
    "x-supervisor-token",
}


async def _client_to_ha(client_ws, ha_ws) -> None:
    async for message in client_ws:
        await ha_ws.send(message)


async def _ha_to_client(client_ws, ha_ws) -> None:
    async for message in ha_ws:
        await client_ws.send(message)


def _upstream_headers(client_ws) -> list[tuple[str, str]]:
    headers = getattr(client_ws, "request_headers", None)
    if not headers:
        return []
    forwarded: list[tuple[str, str]] = []
    for name, value in headers.raw_items():
        if name.lower() in UPSTREAM_HEADER_ALLOWLIST:
            forwarded.append((name, value))
    return forwarded


def _upstream_origin(client_ws) -> str | None:
    headers = getattr(client_ws, "request_headers", None)
    if not headers:
        return None
    return headers.get("Origin")


async def _handle_client(client_ws, path=None) -> None:
    try:
        async with websockets.connect(
            UPSTREAM_URL,
            extra_headers=_upstream_headers(client_ws),
            origin=_upstream_origin(client_ws),
            max_size=None,
            ping_interval=20,
            ping_timeout=20,
        ) as ha_ws:
            to_ha = asyncio.create_task(_client_to_ha(client_ws, ha_ws))
            to_client = asyncio.create_task(_ha_to_client(client_ws, ha_ws))
            done, pending = await asyncio.wait({to_ha, to_client}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                try:
                    task.result()
                except websockets.ConnectionClosed:
                    pass
    except Exception as exc:
        print(f"[vipsy.ws] websocket proxy closed: {exc}", flush=True)


async def _run() -> None:
    print(f"[vipsy.ws] listening on {LISTEN_HOST}:{LISTEN_PORT}, upstream={UPSTREAM_URL}", flush=True)
    async with websockets.serve(_handle_client, LISTEN_HOST, LISTEN_PORT, max_size=None):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_run())

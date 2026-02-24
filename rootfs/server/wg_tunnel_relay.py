import asyncio
import logging
import os
import signal
import socket

logging.basicConfig(level=logging.INFO, format="[wg-relay] %(message)s")
log = logging.getLogger("wg-relay")

LISTEN_HOST = os.environ.get("WG_RELAY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("WG_RELAY_PORT", "51821"))
WG_HOST = "127.0.0.1"
WG_PORT = int(os.environ.get("VPN_PORT", "51820"))
MAX_CLIENTS = 50
IDLE_TIMEOUT = 120

_active = 0
_active_lock = asyncio.Lock()


async def _handle(ws):
    import websockets
    global _active
    async with _active_lock:
        if _active >= MAX_CLIENTS:
            await ws.close(1013, "too many clients")
            return
        _active += 1

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setblocking(False)
    udp.connect((WG_HOST, WG_PORT))
    loop = asyncio.get_event_loop()
    remote = ws.remote_address
    log.info("client connected %s (active: %d)", remote, _active)

    async def ws_to_udp():
        try:
            async for msg in ws:
                if isinstance(msg, bytes):
                    udp.send(msg)
        except websockets.ConnectionClosed:
            pass

    async def udp_to_ws():
        try:
            while True:
                data = await asyncio.wait_for(loop.sock_recv(udp, 65535), timeout=IDLE_TIMEOUT)
                await ws.send(data)
        except (asyncio.TimeoutError, websockets.ConnectionClosed, OSError):
            pass

    try:
        done, pending = await asyncio.wait(
            [asyncio.ensure_future(ws_to_udp()), asyncio.ensure_future(udp_to_ws())],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
    finally:
        udp.close()
        try:
            await ws.close()
        except Exception:
            pass
        async with _active_lock:
            _active -= 1
        log.info("client disconnected %s (active: %d)", remote, _active)


async def main():
    import websockets
    async with websockets.serve(
        _handle, LISTEN_HOST, LISTEN_PORT,
        max_size=65536, ping_interval=30, ping_timeout=30,
    ):
        log.info("relay listening ws://%s:%d -> udp %s:%d", LISTEN_HOST, LISTEN_PORT, WG_HOST, WG_PORT)
        stop = asyncio.Event()
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass
        await stop.wait()
    log.info("relay stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

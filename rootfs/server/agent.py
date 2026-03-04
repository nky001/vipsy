import asyncio
import json
import logging
import os
import socket
import ssl
import struct
import time
import threading
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
_log = logging.getLogger("vipsy.agent")

AUTH_TOKEN_PATH = Path("/data/auth_token")
AGENT_STATE_FILE = Path("/data/agent_state.json")
AGENT_ENABLED_FILE = Path("/data/agent_enabled")

VPS_HOST = os.environ.get("AGENT_VPS_HOST", "")
VPS_AGENT_PORT = int(os.environ.get("AGENT_VPS_PORT", "8443"))
_DEFAULT_VPS_HOST = "vipsy-vps.niti.life"
LOCAL_RELAY_PORT = int(os.environ.get("AGENT_LOCAL_PORT", "51822"))

PING_INTERVAL = 15
RECONNECT_BASE = 2
RECONNECT_MAX = 120
MAX_STREAMS = 256
MAX_UDP_PER_SECOND = 200
STREAM_QUEUE_SIZE = 64

_lock = threading.Lock()
_agent_task: asyncio.Task | None = None
_event_loop: asyncio.AbstractEventLoop | None = None
_loop_thread: threading.Thread | None = None
_running = False
_healthy = False
_stats = {
    "connected": False,
    "reconnects": 0,
    "streams_opened": 0,
    "streams_active": 0,
    "udp_relayed": 0,
    "bytes_in": 0,
    "bytes_out": 0,
    "last_ping_rtt_ms": 0,
    "uptime_seconds": 0,
}
_connect_time: float = 0


def _get_bearer_token():
    return os.environ.get("VIPSY_SERVICE_KEY", "")


def _get_instance_id():
    for src in [Path("/data/tunnel/uid"), Path("/data/wireguard/instance_id")]:
        try:
            if src.exists():
                uid = src.read_text().strip()
                if len(uid) == 8:
                    return uid
        except Exception:
            pass
    return ""


def _get_vps_host():
    if VPS_HOST:
        return VPS_HOST
    host = os.environ.get("VPS_ENDPOINT", "")
    if host and ":" in host:
        return host.split(":")[0]
    if host:
        return host
    try:
        cfg_path = Path("/data/wireguard/hub_config.json")
        if cfg_path.exists():
            cfg = json.loads(cfg_path.read_text())
            ep = cfg.get("vps_endpoint", "")
            if ep and ":" in ep:
                return ep.split(":")[0]
            if ep:
                return ep
    except Exception:
        pass
    return _DEFAULT_VPS_HOST


def _save_state(state: dict):
    try:
        AGENT_STATE_FILE.write_text(json.dumps(state))
    except Exception:
        pass


def _load_state() -> dict:
    try:
        if AGENT_STATE_FILE.exists():
            return json.loads(AGENT_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


class AgentClient:
    def __init__(self):
        self._ws = None
        self._streams: dict[int, asyncio.Queue] = {}
        self._next_stream_id = 1
        self._ping_seq = 0
        self._ping_sent_at: float = 0
        self._udp_counter: list[float] = []
        self._stop_event = asyncio.Event()
        self._connected = False

    async def connect(self, url: str, token: str):
        import websockets
        import websockets.client
        ssl_ctx = ssl.create_default_context()
        headers = {"Authorization": f"Bearer {token}"}
        self._ws = await websockets.connect(
            url,
            ssl=ssl_ctx,
            extra_headers=headers,
            max_size=2 ** 17,
            ping_interval=None,
            close_timeout=5,
        )
        self._connected = True

    async def disconnect(self):
        self._connected = False
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        self._streams.clear()

    async def send_raw(self, data: bytes):
        global _stats
        if self._ws:
            await self._ws.send(data)
            _stats["bytes_out"] += len(data)

    async def recv_raw(self) -> bytes:
        global _stats
        if not self._ws:
            raise ConnectionError("not connected")
        data = await self._ws.recv()
        if isinstance(data, str):
            data = data.encode()
        _stats["bytes_in"] += len(data)
        return data

    def _alloc_stream_id(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id += 2
        if self._next_stream_id > 0xFFFFFFFE:
            self._next_stream_id = 1
        return sid

    def _check_udp_rate(self) -> bool:
        now = time.monotonic()
        cutoff = now - 1.0
        self._udp_counter = [t for t in self._udp_counter if t > cutoff]
        if len(self._udp_counter) >= MAX_UDP_PER_SECOND:
            return False
        self._udp_counter.append(now)
        return True

    async def open_stream(self, proto: str, dst: str, port: int) -> int | None:
        global _stats
        if len(self._streams) >= MAX_STREAMS:
            return None
        sid = self._alloc_stream_id()
        self._streams[sid] = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE)
        from agent_protocol import make_stream_open
        await self.send_raw(make_stream_open(sid, proto, dst, port))
        _stats["streams_opened"] += 1
        _stats["streams_active"] = len(self._streams)
        return sid

    async def close_stream(self, stream_id: int):
        global _stats
        from agent_protocol import make_stream_close
        await self.send_raw(make_stream_close(stream_id))
        self._streams.pop(stream_id, None)
        _stats["streams_active"] = len(self._streams)

    async def send_data(self, stream_id: int, data: bytes):
        from agent_protocol import make_stream_data
        await self.send_raw(make_stream_data(stream_id, data))

    async def send_udp(self, stream_id: int, dst_ip: str, dst_port: int, data: bytes):
        global _stats
        if not self._check_udp_rate():
            return
        from agent_protocol import make_udp_datagram
        await self.send_raw(make_udp_datagram(stream_id, dst_ip, dst_port, data))
        _stats["udp_relayed"] += 1

    async def send_ping(self):
        from agent_protocol import make_ping
        self._ping_seq += 1
        self._ping_sent_at = time.monotonic()
        await self.send_raw(make_ping(self._ping_seq))

    def handle_pong(self, payload: bytes):
        global _stats
        if self._ping_sent_at > 0:
            rtt = (time.monotonic() - self._ping_sent_at) * 1000
            _stats["last_ping_rtt_ms"] = round(rtt, 1)
            self._ping_sent_at = 0

    async def handle_incoming_frame(self, stream_id: int, frame_type: int, flags: int, payload: bytes):
        from agent_protocol import FrameType, parse_udp_datagram, parse_stream_open, parse_ctrl
        if frame_type == FrameType.PONG:
            self.handle_pong(payload)
            return
        if frame_type == FrameType.PING:
            from agent_protocol import make_pong
            seq = struct.unpack("!I", payload)[0] if len(payload) >= 4 else 0
            await self.send_raw(make_pong(seq))
            return
        if frame_type == FrameType.CTRL:
            ctrl = parse_ctrl(payload)
            _log.info("ctrl from VPS: %s", ctrl)
            return
        if frame_type == FrameType.STREAM_OPEN:
            meta = parse_stream_open(payload)
            await self._handle_remote_stream_open(stream_id, meta)
            return
        if frame_type == FrameType.STREAM_DATA:
            q = self._streams.get(stream_id)
            if q:
                try:
                    q.put_nowait(("data", payload))
                except asyncio.QueueFull:
                    _log.warning("stream %d queue full, dropping", stream_id)
            return
        if frame_type == FrameType.STREAM_CLOSE:
            q = self._streams.get(stream_id)
            if q:
                try:
                    q.put_nowait(("close", b""))
                except asyncio.QueueFull:
                    pass
                self._streams.pop(stream_id, None)
                _stats["streams_active"] = len(self._streams)
            return
        if frame_type == FrameType.UDP_DATAGRAM:
            dst_ip, dst_port, data = parse_udp_datagram(payload)
            await self._deliver_udp(dst_ip, dst_port, data)
            return

    async def _handle_remote_stream_open(self, stream_id: int, meta: dict):
        global _stats
        if len(self._streams) >= MAX_STREAMS:
            from agent_protocol import make_stream_close, FrameFlag
            await self.send_raw(make_stream_close(stream_id, FrameFlag.ERR))
            return
        proto = meta.get("proto", "tcp")
        dst = meta.get("dst", "")
        port = meta.get("port", 0)
        self._streams[stream_id] = asyncio.Queue(maxsize=STREAM_QUEUE_SIZE)
        _stats["streams_opened"] += 1
        _stats["streams_active"] = len(self._streams)
        if proto == "tcp":
            asyncio.ensure_future(self._tcp_proxy(stream_id, dst, port))
        elif proto == "udp":
            asyncio.ensure_future(self._udp_proxy(stream_id, dst, port))

    async def _tcp_proxy(self, stream_id: int, dst: str, port: int):
        from agent_protocol import make_stream_data, make_stream_close, FrameFlag
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(dst, port), timeout=10
            )
        except Exception:
            await self.send_raw(make_stream_close(stream_id, FrameFlag.ERR))
            self._streams.pop(stream_id, None)
            _stats["streams_active"] = len(self._streams)
            return

        async def relay_lan_to_vps():
            try:
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    await self.send_raw(make_stream_data(stream_id, chunk))
            except Exception:
                pass
            finally:
                await self.send_raw(make_stream_close(stream_id))
                self._streams.pop(stream_id, None)
                _stats["streams_active"] = len(self._streams)

        async def relay_vps_to_lan():
            q = self._streams.get(stream_id)
            if not q:
                return
            try:
                while True:
                    msg_type, data = await asyncio.wait_for(q.get(), timeout=120)
                    if msg_type == "close":
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(relay_lan_to_vps(), relay_vps_to_lan())

    async def _udp_proxy(self, stream_id: int, dst: str, port: int):
        from agent_protocol import make_udp_datagram, make_stream_close, FrameFlag
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.connect((dst, port))
            loop = asyncio.get_event_loop()
        except Exception:
            await self.send_raw(make_stream_close(stream_id, FrameFlag.ERR))
            self._streams.pop(stream_id, None)
            _stats["streams_active"] = len(self._streams)
            return

        async def relay_vps_to_target():
            q = self._streams.get(stream_id)
            if not q:
                return
            try:
                while True:
                    msg_type, data = await asyncio.wait_for(q.get(), timeout=120)
                    if msg_type == "close":
                        break
                    sock.send(data)
            except Exception:
                pass

        async def relay_target_to_vps():
            try:
                while True:
                    data = await asyncio.wait_for(
                        loop.sock_recv(sock, 65535), timeout=120
                    )
                    if not data:
                        break
                    await self.send_raw(make_udp_datagram(stream_id, dst, port, data))
            except Exception:
                pass

        try:
            await asyncio.gather(relay_vps_to_target(), relay_target_to_vps())
        finally:
            sock.close()
            self._streams.pop(stream_id, None)
            _stats["streams_active"] = len(self._streams)

    async def _deliver_udp(self, dst_ip: str, dst_port: int, data: bytes):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.sendto(data, (dst_ip, dst_port))
            sock.close()
        except Exception:
            pass


_client: AgentClient | None = None


async def _agent_loop():
    global _running, _healthy, _connect_time, _stats, _client
    _running = True
    _client = AgentClient()
    attempt = 0

    while _running:
        vps_host = _get_vps_host()
        instance_id = _get_instance_id()
        token = _get_bearer_token()

        if not vps_host or not instance_id or not token:
            _log.warning("agent missing config: vps=%s id=%s token=%s",
                         bool(vps_host), bool(instance_id), bool(token))
            await asyncio.sleep(30)
            continue

        url = f"wss://{vps_host}:{VPS_AGENT_PORT}/agent/{instance_id}"
        _log.info("connecting to %s", url)

        try:
            await _client.connect(url, token)
            _healthy = True
            _stats["connected"] = True
            _connect_time = time.monotonic()
            attempt = 0
            _log.info("agent connected, sending auth frame")

            from agent_protocol import make_ctrl
            auth_payload = {
                "type": "auth",
                "instance_id": instance_id,
                "version": "1.0",
                "token": token,
            }
            await _client.send_raw(make_ctrl(auth_payload))
            _log.info("auth frame sent (%d bytes token)", len(token))

            ping_task = asyncio.ensure_future(_ping_loop(_client))
            recv_task = asyncio.ensure_future(_recv_loop(_client))

            done, pending = await asyncio.wait(
                [ping_task, recv_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

        except Exception as e:
            _log.warning("agent connection error: %s %s", type(e).__name__, e)

        _healthy = False
        _stats["connected"] = False
        _stats["reconnects"] += 1
        await _client.disconnect()

        delay = min(RECONNECT_MAX, RECONNECT_BASE * (2 ** min(attempt, 6)))
        _log.info("reconnecting in %ds (attempt %d)", delay, attempt + 1)
        await asyncio.sleep(delay)
        attempt += 1


async def _ping_loop(client: AgentClient):
    while True:
        await asyncio.sleep(PING_INTERVAL)
        try:
            await client.send_ping()
        except Exception:
            return


async def _recv_loop(client: AgentClient):
    from agent_protocol import decode_header, HEADER_SIZE, FrameReader
    reader = FrameReader()
    while True:
        try:
            data = await client.recv_raw()
            reader.feed(data)
            for stream_id, frame_type, flags, payload in reader.pop_frames():
                await client.handle_incoming_frame(stream_id, frame_type, flags, payload)
        except Exception as e:
            import websockets.exceptions
            if isinstance(e, websockets.exceptions.ConnectionClosedError):
                _log.warning("server closed connection: code=%s reason=%s", e.rcvd.code if e.rcvd else "?", e.rcvd.reason if e.rcvd else "?")
            elif isinstance(e, websockets.exceptions.ConnectionClosedOK):
                _log.info("connection closed normally")
            else:
                _log.warning("recv error: %s %s", type(e).__name__, e)
            return


async def _local_relay_server():
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        global _client
        if not _client or not _client._connected:
            writer.close()
            return
        try:
            header = await asyncio.wait_for(reader.readexactly(6), timeout=10)
            proto = "udp" if header[0] == 1 else "tcp"
            dst_port = struct.unpack("!H", header[1:3])[0]
            dst_len = header[3]
            dst_bytes = await asyncio.wait_for(reader.readexactly(dst_len), timeout=5)
            dst = dst_bytes.decode()

            sid = await _client.open_stream(proto, dst, dst_port)
            if sid is None:
                writer.close()
                return

            async def relay_in():
                try:
                    while True:
                        chunk = await reader.read(4096)
                        if not chunk:
                            break
                        await _client.send_data(sid, chunk)
                except Exception:
                    pass
                await _client.close_stream(sid)

            async def relay_out():
                q = _client._streams.get(sid)
                if not q:
                    return
                try:
                    while True:
                        msg_type, data = await asyncio.wait_for(q.get(), timeout=120)
                        if msg_type == "close":
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception:
                    pass

            await asyncio.gather(relay_in(), relay_out())
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    try:
        server = await asyncio.start_server(
            handle_client, "127.0.0.1", LOCAL_RELAY_PORT, reuse_address=True
        )
    except OSError as e:
        _log.warning("local relay could not bind port %d: %s", LOCAL_RELAY_PORT, e)
        return
    _log.info("local relay listening on 127.0.0.1:%d", LOCAL_RELAY_PORT)
    async with server:
        await server.serve_forever()


async def _run_agent():
    relay_task = asyncio.ensure_future(_local_relay_server())
    try:
        await _agent_loop()
    finally:
        relay_task.cancel()
        try:
            await relay_task
        except (asyncio.CancelledError, Exception):
            pass


def _loop_entry():
    global _event_loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _event_loop = loop
    try:
        loop.run_until_complete(_run_agent())
    except Exception:
        pass
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        loop.close()
        _event_loop = None


def is_enabled():
    return AGENT_ENABLED_FILE.exists() or os.environ.get("AGENT_ENABLED", "").lower() == "true"


def start():
    global _loop_thread, _running
    with _lock:
        if _loop_thread and _loop_thread.is_alive():
            return {"ok": True, "message": "Already running"}
        vps = _get_vps_host()
        iid = _get_instance_id()
        if not vps:
            return {"ok": False, "error": "VPS host not configured (set AGENT_VPS_HOST or VPS_ENDPOINT)"}
        if not iid:
            return {"ok": False, "error": "Instance ID not available — sign in first"}
        _running = True
        _loop_thread = threading.Thread(target=_loop_entry, daemon=True, name="agent")
        _loop_thread.start()
        try:
            AGENT_ENABLED_FILE.write_text("1")
        except Exception:
            pass
        _log.info("agent started")
        return {"ok": True, "message": "Agent started"}


def stop():
    global _running, _healthy, _loop_thread, _event_loop
    with _lock:
        _running = False
        _healthy = False
        _stats["connected"] = False
        if _event_loop:
            _event_loop.call_soon_threadsafe(_event_loop.stop)
        _loop_thread = None
        _event_loop = None
        try:
            AGENT_ENABLED_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        _log.info("agent stopped")
        return {"ok": True, "message": "Agent stopped"}


def status():
    global _connect_time
    uptime = 0
    if _healthy and _connect_time > 0:
        uptime = int(time.monotonic() - _connect_time)
    return {
        "enabled": is_enabled(),
        "running": _running and _loop_thread is not None and _loop_thread.is_alive() if _loop_thread else False,
        "healthy": _healthy,
        "connected": _stats.get("connected", False),
        "reconnects": _stats.get("reconnects", 0),
        "streams_active": _stats.get("streams_active", 0),
        "streams_total": _stats.get("streams_opened", 0),
        "udp_relayed": _stats.get("udp_relayed", 0),
        "bytes_in": _stats.get("bytes_in", 0),
        "bytes_out": _stats.get("bytes_out", 0),
        "ping_rtt_ms": _stats.get("last_ping_rtt_ms", 0),
        "uptime_seconds": uptime,
        "vps_host": _get_vps_host() or None,
        "instance_id": _get_instance_id() or None,
    }


def startup_reconnect():
    if is_enabled():
        _log.info("startup_reconnect: agent was previously enabled, restarting")
        start()

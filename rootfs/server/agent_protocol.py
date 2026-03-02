import struct
import json
from enum import IntEnum

HEADER_SIZE = 8
MAX_PAYLOAD = 65535


class FrameType(IntEnum):
    CTRL = 0
    STREAM_OPEN = 1
    STREAM_DATA = 2
    STREAM_CLOSE = 3
    UDP_DATAGRAM = 4
    PING = 5
    PONG = 6


class FrameFlag:
    NONE = 0x00
    FIN = 0x01
    ACK = 0x02
    ERR = 0x04
    BACKPRESSURE = 0x08


HEADER_FMT = "!IBBH"


def encode_frame(stream_id: int, frame_type: int, flags: int, payload: bytes) -> bytes:
    length = len(payload)
    if length > MAX_PAYLOAD:
        raise ValueError(f"payload too large: {length} > {MAX_PAYLOAD}")
    header = struct.pack(HEADER_FMT, stream_id, frame_type, flags, length)
    return header + payload


def decode_header(data: bytes) -> tuple:
    if len(data) < HEADER_SIZE:
        raise ValueError(f"header too short: {len(data)} < {HEADER_SIZE}")
    stream_id, frame_type, flags, length = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    return stream_id, frame_type, flags, length


def make_ctrl(payload: dict, flags: int = FrameFlag.NONE) -> bytes:
    return encode_frame(0, FrameType.CTRL, flags, json.dumps(payload).encode())


def make_stream_open(stream_id: int, proto: str, dst: str, port: int, meta: dict | None = None) -> bytes:
    body = {"proto": proto, "dst": dst, "port": port}
    if meta:
        body["meta"] = meta
    return encode_frame(stream_id, FrameType.STREAM_OPEN, FrameFlag.NONE, json.dumps(body).encode())


def make_stream_data(stream_id: int, data: bytes, flags: int = FrameFlag.NONE) -> bytes:
    return encode_frame(stream_id, FrameType.STREAM_DATA, flags, data)


def make_stream_close(stream_id: int, flags: int = FrameFlag.FIN) -> bytes:
    return encode_frame(stream_id, FrameType.STREAM_CLOSE, flags, b"")


def make_udp_datagram(stream_id: int, dst_ip: str, dst_port: int, data: bytes) -> bytes:
    parts = dst_ip.split(".")
    ip_bytes = bytes(int(p) for p in parts)
    port_bytes = struct.pack("!H", dst_port)
    payload = ip_bytes + port_bytes + data
    return encode_frame(stream_id, FrameType.UDP_DATAGRAM, FrameFlag.NONE, payload)


def parse_udp_datagram(payload: bytes) -> tuple:
    if len(payload) < 6:
        raise ValueError("udp datagram too short")
    dst_ip = ".".join(str(b) for b in payload[:4])
    dst_port = struct.unpack("!H", payload[4:6])[0]
    data = payload[6:]
    return dst_ip, dst_port, data


def make_ping(seq: int = 0) -> bytes:
    return encode_frame(0, FrameType.PING, FrameFlag.NONE, struct.pack("!I", seq))


def make_pong(seq: int = 0) -> bytes:
    return encode_frame(0, FrameType.PONG, FrameFlag.NONE, struct.pack("!I", seq))


def parse_ctrl(payload: bytes) -> dict:
    return json.loads(payload.decode())


def parse_stream_open(payload: bytes) -> dict:
    return json.loads(payload.decode())


class FrameReader:
    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)

    def pop_frames(self) -> list:
        frames = []
        while len(self._buf) >= HEADER_SIZE:
            stream_id, frame_type, flags, length = struct.unpack(
                HEADER_FMT, self._buf[:HEADER_SIZE]
            )
            total = HEADER_SIZE + length
            if len(self._buf) < total:
                break
            payload = bytes(self._buf[HEADER_SIZE:total])
            del self._buf[:total]
            frames.append((stream_id, frame_type, flags, payload))
        return frames

import os
import sys
import struct
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

from agent_protocol import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    FrameType,
    FrameFlag,
    encode_frame,
    decode_header,
    make_ctrl,
    make_stream_open,
    make_stream_data,
    make_stream_close,
    make_udp_datagram,
    make_ping,
    make_pong,
    parse_ctrl,
    parse_stream_open,
    parse_udp_datagram,
    FrameReader,
)


def test_header_size_constant():
    assert HEADER_SIZE == 8


def test_encode_decode_roundtrip():
    payload = b"hello world"
    frame = encode_frame(42, FrameType.STREAM_DATA, FrameFlag.NONE, payload)
    assert len(frame) == HEADER_SIZE + len(payload)
    sid, ft, fl, length = decode_header(frame[:HEADER_SIZE])
    assert sid == 42
    assert ft == FrameType.STREAM_DATA
    assert fl == FrameFlag.NONE
    assert length == len(payload)
    assert frame[HEADER_SIZE:] == payload


def test_encode_empty_payload():
    frame = encode_frame(0, FrameType.STREAM_CLOSE, FrameFlag.FIN, b"")
    sid, ft, fl, length = decode_header(frame)
    assert length == 0
    assert len(frame) == HEADER_SIZE


def test_encode_max_payload():
    payload = b"\x00" * MAX_PAYLOAD
    frame = encode_frame(1, FrameType.STREAM_DATA, FrameFlag.NONE, payload)
    assert len(frame) == HEADER_SIZE + MAX_PAYLOAD


def test_encode_payload_too_large():
    try:
        encode_frame(1, FrameType.STREAM_DATA, FrameFlag.NONE, b"\x00" * (MAX_PAYLOAD + 1))
        assert False, "should have raised"
    except ValueError:
        pass


def test_decode_header_too_short():
    try:
        decode_header(b"\x00" * 7)
        assert False, "should have raised"
    except ValueError:
        pass


def test_make_ctrl():
    frame = make_ctrl({"action": "auth", "token": "abc"})
    sid, ft, fl, length = decode_header(frame)
    assert sid == 0
    assert ft == FrameType.CTRL
    payload = json.loads(frame[HEADER_SIZE:])
    assert payload["action"] == "auth"
    assert payload["token"] == "abc"


def test_make_ctrl_with_flags():
    frame = make_ctrl({"ok": True}, flags=FrameFlag.ACK)
    _, _, fl, _ = decode_header(frame)
    assert fl == FrameFlag.ACK


def test_make_stream_open():
    frame = make_stream_open(100, "tcp", "192.168.1.5", 8080)
    sid, ft, fl, length = decode_header(frame)
    assert sid == 100
    assert ft == FrameType.STREAM_OPEN
    body = parse_stream_open(frame[HEADER_SIZE:])
    assert body["proto"] == "tcp"
    assert body["dst"] == "192.168.1.5"
    assert body["port"] == 8080
    assert "meta" not in body


def test_make_stream_open_with_meta():
    frame = make_stream_open(101, "udp", "10.0.0.1", 53, meta={"source": "client-1"})
    body = parse_stream_open(frame[HEADER_SIZE:])
    assert body["meta"]["source"] == "client-1"


def test_make_stream_data():
    payload = b"\xde\xad\xbe\xef"
    frame = make_stream_data(200, payload, flags=FrameFlag.BACKPRESSURE)
    sid, ft, fl, length = decode_header(frame)
    assert sid == 200
    assert ft == FrameType.STREAM_DATA
    assert fl == FrameFlag.BACKPRESSURE
    assert frame[HEADER_SIZE:] == payload


def test_make_stream_close():
    frame = make_stream_close(300)
    sid, ft, fl, length = decode_header(frame)
    assert sid == 300
    assert ft == FrameType.STREAM_CLOSE
    assert fl == FrameFlag.FIN
    assert length == 0


def test_make_stream_close_with_err():
    frame = make_stream_close(301, flags=FrameFlag.ERR)
    _, _, fl, _ = decode_header(frame)
    assert fl == FrameFlag.ERR


def test_make_udp_datagram():
    data = b"DNS query here"
    frame = make_udp_datagram(10, "192.168.1.1", 53, data)
    sid, ft, fl, length = decode_header(frame)
    assert sid == 10
    assert ft == FrameType.UDP_DATAGRAM
    parsed_ip, parsed_port, parsed_data = parse_udp_datagram(frame[HEADER_SIZE:])
    assert parsed_ip == "192.168.1.1"
    assert parsed_port == 53
    assert parsed_data == data


def test_parse_udp_datagram_min_size():
    payload = bytes([10, 0, 0, 1]) + struct.pack("!H", 1234)
    ip, port, data = parse_udp_datagram(payload)
    assert ip == "10.0.0.1"
    assert port == 1234
    assert data == b""


def test_parse_udp_datagram_too_short():
    try:
        parse_udp_datagram(b"\x00" * 5)
        assert False, "should have raised"
    except ValueError:
        pass


def test_make_ping_pong():
    ping = make_ping(seq=7)
    sid, ft, fl, length = decode_header(ping)
    assert sid == 0
    assert ft == FrameType.PING
    assert length == 4
    seq = struct.unpack("!I", ping[HEADER_SIZE:])[0]
    assert seq == 7

    pong = make_pong(seq=7)
    sid, ft, fl, length = decode_header(pong)
    assert ft == FrameType.PONG
    seq = struct.unpack("!I", pong[HEADER_SIZE:])[0]
    assert seq == 7


def test_parse_ctrl():
    payload_dict = {"status": "ok", "version": 1}
    raw = json.dumps(payload_dict).encode()
    result = parse_ctrl(raw)
    assert result == payload_dict


def test_frame_reader_single_frame():
    reader = FrameReader()
    frame = make_ctrl({"hello": "world"})
    reader.feed(frame)
    frames = reader.pop_frames()
    assert len(frames) == 1
    sid, ft, fl, payload = frames[0]
    assert sid == 0
    assert ft == FrameType.CTRL
    assert json.loads(payload) == {"hello": "world"}


def test_frame_reader_multiple_frames():
    reader = FrameReader()
    f1 = make_ping(seq=1)
    f2 = make_pong(seq=1)
    f3 = make_stream_data(5, b"payload")
    reader.feed(f1 + f2 + f3)
    frames = reader.pop_frames()
    assert len(frames) == 3
    assert frames[0][1] == FrameType.PING
    assert frames[1][1] == FrameType.PONG
    assert frames[2][1] == FrameType.STREAM_DATA
    assert frames[2][3] == b"payload"


def test_frame_reader_partial_header():
    reader = FrameReader()
    frame = make_ctrl({"x": 1})
    reader.feed(frame[:4])
    assert reader.pop_frames() == []
    reader.feed(frame[4:])
    frames = reader.pop_frames()
    assert len(frames) == 1


def test_frame_reader_partial_payload():
    reader = FrameReader()
    payload = b"A" * 100
    frame = make_stream_data(1, payload)
    reader.feed(frame[:HEADER_SIZE + 50])
    assert reader.pop_frames() == []
    reader.feed(frame[HEADER_SIZE + 50:])
    frames = reader.pop_frames()
    assert len(frames) == 1
    assert frames[0][3] == payload


def test_frame_reader_incremental_byte_by_byte():
    reader = FrameReader()
    frame = make_ping(seq=99)
    for byte in frame:
        reader.feed(bytes([byte]))
    frames = reader.pop_frames()
    assert len(frames) == 1
    seq = struct.unpack("!I", frames[0][3])[0]
    assert seq == 99


def test_frame_reader_leftover_preserved():
    reader = FrameReader()
    f1 = make_ping(seq=1)
    f2 = make_pong(seq=2)
    reader.feed(f1 + f2[:5])
    frames = reader.pop_frames()
    assert len(frames) == 1
    reader.feed(f2[5:])
    frames = reader.pop_frames()
    assert len(frames) == 1
    assert frames[0][1] == FrameType.PONG


def test_frame_type_values():
    assert FrameType.CTRL == 0
    assert FrameType.STREAM_OPEN == 1
    assert FrameType.STREAM_DATA == 2
    assert FrameType.STREAM_CLOSE == 3
    assert FrameType.UDP_DATAGRAM == 4
    assert FrameType.PING == 5
    assert FrameType.PONG == 6


def test_frame_flag_values():
    assert FrameFlag.NONE == 0x00
    assert FrameFlag.FIN == 0x01
    assert FrameFlag.ACK == 0x02
    assert FrameFlag.ERR == 0x04
    assert FrameFlag.BACKPRESSURE == 0x08


def test_all_frame_types_encode_decode():
    for ft in FrameType:
        frame = encode_frame(0, ft, 0, b"test")
        sid, decoded_ft, flags, length = decode_header(frame)
        assert decoded_ft == ft
        assert length == 4


def test_combined_flags():
    flags = FrameFlag.FIN | FrameFlag.ERR
    frame = encode_frame(0, FrameType.STREAM_CLOSE, flags, b"")
    _, _, decoded_flags, _ = decode_header(frame)
    assert decoded_flags & FrameFlag.FIN
    assert decoded_flags & FrameFlag.ERR
    assert not (decoded_flags & FrameFlag.BACKPRESSURE)


def test_large_stream_id():
    sid = 0xFFFFFFFF
    frame = encode_frame(sid, FrameType.STREAM_DATA, 0, b"x")
    decoded_sid, _, _, _ = decode_header(frame)
    assert decoded_sid == sid


def test_binary_payload_integrity():
    payload = bytes(range(256))
    frame = make_stream_data(1, payload)
    reader = FrameReader()
    reader.feed(frame)
    frames = reader.pop_frames()
    assert frames[0][3] == payload

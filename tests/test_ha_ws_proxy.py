import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

import ha_ws_proxy


class FakeHeaders:
    def __init__(self, items):
        self._items = items

    def raw_items(self):
        return self._items

    def get(self, name):
        for key, value in self._items:
            if key.lower() == name.lower():
                return value
        return None


class FakeWebSocket:
    def __init__(self, headers):
        self.request_headers = headers


class FakeMessageSocket:
    def __init__(self, messages):
        self.messages = messages
        self.sent = []

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.messages:
            raise StopAsyncIteration
        return self.messages.pop(0)

    async def send(self, message):
        self.sent.append(message)


def test_generic_camera_keeps_hls_and_skips_broken_webrtc_provider():
    capabilities = '{"id":12,"type":"result","success":true,"result":{"frontend_stream_types":["hls","web_rtc"]}}'
    upstream = FakeMessageSocket([capabilities])
    client = FakeMessageSocket([])
    pending = {12: "camera.192_168_7_130"}

    asyncio.run(ha_ws_proxy._ha_to_client(client, upstream, pending, {}))

    assert len(client.sent) == 1
    assert '"frontend_stream_types":["hls"]' in client.sent[0]


def test_non_generic_camera_web_rtc_capability_is_preserved():
    capabilities = '{"id":12,"type":"result","success":true,"result":{"frontend_stream_types":["hls","web_rtc"]}}'
    upstream = FakeMessageSocket([capabilities])
    client = FakeMessageSocket([])

    asyncio.run(ha_ws_proxy._ha_to_client(client, upstream, {12: "camera.hikvision_driveway"}, {}))

    assert client.sent == [capabilities]


def test_upstream_headers_forward_auth_but_not_websocket_hop_headers():
    ws = FakeWebSocket(
        FakeHeaders(
            [
                ("Cookie", "session=abc"),
                ("Authorization", "Bearer token"),
                ("Sec-WebSocket-Key", "drop-me"),
                ("Connection", "Upgrade"),
            ]
        )
    )

    assert ha_ws_proxy._upstream_headers(ws) == [
        ("Cookie", "session=abc"),
        ("Authorization", "Bearer token"),
    ]


def test_upstream_origin_preserves_browser_origin():
    ws = FakeWebSocket(FakeHeaders([("Origin", "https://example.vipsy.in")]))

    assert ha_ws_proxy._upstream_origin(ws) == "https://example.vipsy.in"

import asyncio
import os
import sys
import json
from unittest.mock import patch

import pytest

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


@pytest.mark.parametrize("types", [["hls", "web_rtc"], ["web_rtc"], [], ["hls"]])
@pytest.mark.parametrize("entity", ["camera.192_168_7_130", "camera.generic_drive", "camera.hikvision_driveway"])
def test_native_capabilities_are_never_invented_or_removed(types, entity):
    capabilities = json.dumps({"id":12,"type":"result","success":True,"result":{"frontend_stream_types":types}})
    upstream = FakeMessageSocket([capabilities])
    client = FakeMessageSocket([])
    pending = {12: ("camera/capabilities", entity)}

    asyncio.run(ha_ws_proxy._ha_to_client(client, upstream, pending))

    assert client.sent == [capabilities]
    assert pending == {}


def test_failed_request_is_removed_without_logging_private_error():
    message = '{"id":12,"type":"result","success":false,"error":{"message":"rtsp://user:secret@camera"}}'
    upstream = FakeMessageSocket([message])
    client = FakeMessageSocket([])
    pending = {12: ("camera/stream", "camera.kitchen")}
    with patch.object(ha_ws_proxy.diagnostics, "record") as record:
        asyncio.run(ha_ws_proxy._ha_to_client(client, upstream, pending))
    assert client.sent == [message]
    assert pending == {}
    assert "secret" not in repr(record.call_args)


def test_authorized_hls_probe_is_scheduled_after_forwarding():
    message = '{"id":12,"type":"result","success":true,"result":{"url":"/api/hls/abcdefghijklmnop/master_playlist.m3u8"}}'
    upstream = FakeMessageSocket([message])
    client = FakeMessageSocket([])
    def schedule(entity, url):
        assert client.sent == [message]
    with patch.object(ha_ws_proxy.diagnostics, "schedule", side_effect=schedule) as probe:
        asyncio.run(ha_ws_proxy._ha_to_client(client, upstream, {12:("camera/stream","camera.kitchen")}))
    probe.assert_called_once()


def test_non_camera_and_binary_messages_are_unchanged():
    messages = [b"binary", "invalid-json", "[]", '{"type":"event","event":{}}']
    upstream = FakeMessageSocket(messages.copy())
    client = FakeMessageSocket([])
    asyncio.run(ha_ws_proxy._ha_to_client(client, upstream, {}))
    assert client.sent == messages


def test_pending_camera_requests_are_bounded():
    messages = [json.dumps({"id":i,"type":"camera/stream","entity_id":"camera.kitchen"}) for i in range(200)]
    pending = {}
    upstream = FakeMessageSocket([])
    asyncio.run(ha_ws_proxy._client_to_ha(FakeMessageSocket(messages.copy()), upstream, pending))
    assert len(pending) == ha_ws_proxy.MAX_PENDING
    assert upstream.sent == messages


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

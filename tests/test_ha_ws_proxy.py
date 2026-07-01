import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

import ha_ws_proxy


def test_generic_ip_camera_capabilities_are_downgraded_to_hls():
    pending = {12: "camera.192_168_7_130"}
    meta = {}
    message = json.dumps(
        {
            "id": 12,
            "type": "result",
            "success": True,
            "result": {"frontend_stream_types": ["hls", "web_rtc"]},
        }
    )

    rewritten = ha_ws_proxy._downgrade_capabilities_if_needed(message, pending, meta)
    data = json.loads(rewritten)

    assert data["result"]["frontend_stream_types"] == ["hls"]
    assert pending == {}


def test_native_webrtc_only_camera_capabilities_are_not_changed():
    pending = {12: "camera.front_door"}
    meta = {}
    message = json.dumps(
        {
            "id": 12,
            "type": "result",
            "success": True,
            "result": {"frontend_stream_types": ["web_rtc"]},
        }
    )

    assert ha_ws_proxy._downgrade_capabilities_if_needed(message, pending, meta) == message


def test_non_generic_camera_with_hls_and_webrtc_is_not_changed():
    pending = {12: "camera.hikvision_driveway"}
    meta = {"camera.hikvision_driveway": {"brand": "hikvision", "model": "", "friendly_name": "driveway"}}
    message = json.dumps(
        {
            "id": 12,
            "type": "result",
            "success": True,
            "result": {"frontend_stream_types": ["hls", "web_rtc"]},
        }
    )

    assert ha_ws_proxy._downgrade_capabilities_if_needed(message, pending, meta) == message


def test_generic_brand_camera_capabilities_are_downgraded_to_hls():
    pending = {44: "camera.side_gate"}
    meta = {"camera.side_gate": {"brand": "generic", "model": "", "friendly_name": "side gate"}}
    message = json.dumps(
        {
            "id": 44,
            "type": "result",
            "success": True,
            "result": {"frontend_stream_types": ["hls", "web_rtc"]},
        }
    )

    rewritten = ha_ws_proxy._downgrade_capabilities_if_needed(message, pending, meta)
    data = json.loads(rewritten)

    assert data["result"]["frontend_stream_types"] == ["hls"]

import os
import sys
from unittest.mock import patch, MagicMock
from io import BytesIO

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

import vpn_manager
_vpn_iface_patch = patch.object(vpn_manager, "_interface_exists", return_value=False)
_vpn_iface_patch.start()

_vpn_detect_lan_patch = patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24")
_vpn_detect_lan_patch.start()

import hub_manager
_hub_iface_patch = patch.object(hub_manager, "_interface_exists", return_value=False)
_hub_iface_patch.start()

import gateway
from gateway import app


def _client():
    app.config["TESTING"] = True
    return app.test_client()


def test_health():
    resp = _client().get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "ts" in data


def test_status():
    resp = _client().get("/api/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "caddy" in data
    assert "mode" in data
    assert data["mode"] in ("remote", "lan-only")


def test_access_shape():
    resp = _client().get("/api/access")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "local" in data
    assert "external" in data
    assert "ha_core" in data
    assert "ip" in data["local"]
    assert "reachable" in data["local"]
    assert "public_ip" in data["external"]
    assert "domain" in data["external"]
    assert "configured" in data["external"]
    assert "reachable" in data["ha_core"]


def test_diagnostics():
    resp = _client().get("/api/diagnostics")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "warnings" in data
    assert isinstance(data["warnings"], list)
    assert "count" in data


def test_diagnostics_warn_when_cloudflare_vpn_relay_is_not_ready():
    vpn_state = {
        "enabled": True,
        "overlap_warning": None,
        "relay_ready": False,
        "relay_error": "listener exited",
    }
    with patch.object(gateway.vpn_manager, "status", return_value=vpn_state):
        with patch.object(gateway.vpn_manager, "_endpoint_info", return_value={"port_forward_needed": False}):
            resp = _client().get("/api/diagnostics")

    assert resp.status_code == 200
    warnings = resp.get_json()["warnings"]
    assert any("Cloudflare VPN relay is not ready" in warning for warning in warnings)
    assert any("listener exited" in warning for warning in warnings)


def test_hub_status_requires_recent_handshake_for_connected_state():
    cfg = {"vpn_ip": "10.100.2.2", "lan_subnet": "192.168.4.0/24"}
    with patch.object(hub_manager, "_load_hub_config", return_value=cfg):
        with patch.object(hub_manager, "_interface_exists", return_value=True):
            with patch.object(hub_manager, "_latest_handshake_age_seconds", return_value=None):
                state = hub_manager.status()

    assert state["enabled"] is True
    assert state["interface_up"] is True
    assert state["connected"] is False
    assert state["handshake_age_seconds"] is None


def test_hub_status_reports_recent_handshake_as_connected():
    cfg = {"vpn_ip": "10.100.2.2", "lan_subnet": "192.168.4.0/24"}
    with patch.object(hub_manager, "_load_hub_config", return_value=cfg):
        with patch.object(hub_manager, "_interface_exists", return_value=True):
            with patch.object(hub_manager, "_latest_handshake_age_seconds", return_value=12.25):
                state = hub_manager.status()

    assert state["enabled"] is True
    assert state["connected"] is True
    assert state["handshake_age_seconds"] == 12.2


def test_hub_identity_keeps_existing_wireguard_id_when_tunnel_uid_changes(tmp_path):
    wireguard_id = tmp_path / "wireguard-instance-id"
    tunnel_id = tmp_path / "tunnel-uid"
    wireguard_id.write_text("oldhome1")
    tunnel_id.write_text("newtunl2")

    with patch.object(hub_manager, "INSTANCE_ID_FILE", str(wireguard_id)):
        with patch.object(hub_manager, "TUNNEL_UID_FILE", str(tunnel_id)):
            assert hub_manager._get_instance_id() == "oldhome1"


def test_hub_identity_pins_tunnel_uid_only_for_first_wireguard_setup(tmp_path):
    wireguard_id = tmp_path / "wireguard-instance-id"
    tunnel_id = tmp_path / "tunnel-uid"
    tunnel_id.write_text("newtunl2")

    with patch.object(hub_manager, "INSTANCE_ID_FILE", str(wireguard_id)):
        with patch.object(hub_manager, "TUNNEL_UID_FILE", str(tunnel_id)):
            assert hub_manager._get_instance_id() == "newtunl2"

    assert wireguard_id.read_text() == "newtunl2"


def test_hub_endpoint_replaces_legacy_vps_domain_without_changing_port():
    assert hub_manager._normalize_vps_endpoint("vipsy-vps.niti.life:51830") == "vipsy-vps.vipsy.in:51830"
    assert hub_manager._normalize_vps_endpoint("vipsy-vps.vipsy.in:51830") == "vipsy-vps.vipsy.in:51830"


def test_hub_config_load_migrates_cached_legacy_vps_domain(tmp_path):
    config_path = tmp_path / "hub-config.json"
    config_path.write_text('{"vps_endpoint":"vipsy-vps.niti.life:51830","subnet":"10.100.10.0/24"}')

    with patch.object(hub_manager, "HUB_CONFIG_FILE", str(config_path)):
        cfg = hub_manager._load_hub_config()

    assert cfg["vps_endpoint"] == "vipsy-vps.vipsy.in:51830"
    assert "vipsy-vps.vipsy.in:51830" in config_path.read_text()
    assert "niti.life" not in config_path.read_text()


def test_hub_client_config_download_migrates_cached_legacy_vps_domain():
    config = "[Peer]\nEndpoint = vipsy-vps.niti.life:51830\nAllowedIPs = 10.100.10.0/24\n"

    sanitized = hub_manager._sanitize_client_config(config)

    assert "Endpoint = vipsy-vps.vipsy.in:51830" in sanitized
    assert "niti.life" not in sanitized


def test_hub_recovery_adopts_unique_legacy_lan_identity(tmp_path):
    wireguard_id = tmp_path / "wireguard-instance-id"
    peers = {
        "data": {
            "peers": [
                {"role": "home", "active": True, "instance_id": "oldhome1", "pubkey": "OLDKEY", "lan_subnet": "192.168.4.0/24"},
                {"role": "home", "active": True, "instance_id": "otherlan", "pubkey": "OTHER", "lan_subnet": "192.168.88.0/23"},
            ],
        },
    }

    with patch.object(hub_manager, "INSTANCE_ID_FILE", str(wireguard_id)):
        with patch.object(hub_manager, "_api", return_value=peers):
            recovered = hub_manager._recover_legacy_instance_id("newtunl2", "NEWKEY", "192.168.4.0/24")

    assert recovered == "oldhome1"
    assert wireguard_id.read_text() == "oldhome1"


def test_hub_recovery_prefers_exact_key_over_lan_match(tmp_path):
    wireguard_id = tmp_path / "wireguard-instance-id"
    peers = {
        "data": {
            "peers": [
                {"role": "home", "active": True, "instance_id": "keyhome1", "pubkey": "SAMEKEY", "lan_subnet": "192.168.1.0/24"},
                {"role": "home", "active": True, "instance_id": "lanhome2", "pubkey": "OTHER", "lan_subnet": "192.168.4.0/24"},
            ],
        },
    }

    with patch.object(hub_manager, "INSTANCE_ID_FILE", str(wireguard_id)):
        with patch.object(hub_manager, "_api", return_value=peers):
            recovered = hub_manager._recover_legacy_instance_id("newtunl2", "SAMEKEY", "192.168.4.0/24")

    assert recovered == "keyhome1"


def test_hub_recovery_refuses_ambiguous_lan_match(tmp_path):
    peers = {
        "data": {
            "peers": [
                {"role": "home", "active": True, "instance_id": "homeone1", "pubkey": "KEY1", "lan_subnet": "192.168.1.0/24"},
                {"role": "home", "active": True, "instance_id": "hometwo2", "pubkey": "KEY2", "lan_subnet": "192.168.1.0/24"},
            ],
        },
    }

    with patch.object(hub_manager, "_api", return_value=peers):
        recovered = hub_manager._recover_legacy_instance_id("current1", "NEWKEY", "192.168.1.0/24")

    assert recovered == "current1"


def test_hub_startup_reconnect_does_not_rebuild_settling_interface(tmp_path):
    enabled_flag = tmp_path / "hub-enabled"
    enabled_flag.write_text("1")
    cfg = {"subnet": "10.100.1.0/24"}

    with patch.object(hub_manager, "HUB_ENABLED_FILE", str(enabled_flag)):
        with patch.object(hub_manager, "_interface_exists", return_value=True):
            with patch.object(hub_manager, "_load_hub_config", return_value=cfg):
                with patch.object(hub_manager, "_ensure_forwarding") as forwarding:
                    with patch.object(hub_manager, "_apply_hub_nat") as apply_nat:
                        with patch.object(hub_manager, "enable") as enable:
                            hub_manager.startup_reconnect()

    forwarding.assert_called_once_with(hub_manager.HUB_INTERFACE)
    apply_nat.assert_called_once_with("10.100.1.0/24")
    enable.assert_not_called()


def test_diagnostics_warn_when_hub_interface_has_no_handshake():
    hub_state = {"enabled": True, "interface_up": True, "connected": False}
    with patch.object(gateway.hub_manager, "status", return_value=hub_state):
        resp = _client().get("/api/diagnostics")

    assert resp.status_code == 200
    warnings = resp.get_json()["warnings"]
    assert any("VPS handshake has not completed" in warning for warning in warnings)


def test_tunnel_endpoint():
    resp = _client().get("/api/tunnel")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "enabled" in data
    assert "running" in data
    assert "healthy" in data
    assert "hostname" in data
    assert "provider" in data
    assert "mode" in data
    assert "fallback_url" in data
    assert data["provider"] == "cloudflare"
    assert data["enabled"] is False
    assert data["mode"] in ("quick", "static")
    assert "managed" in data
    assert "error" in data


def test_control_status_endpoint():
    resp = _client().get("/api/control")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "running" in data
    assert "last_error" in data


def test_access_includes_tunnel():
    resp = _client().get("/api/access")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "tunnel" in data
    assert "enabled" in data["tunnel"]
    assert "provider" in data["tunnel"]


def test_index_returns_html():
    resp = _client().get("/")
    assert resp.status_code == 200
    assert b"Vipsy" in resp.data
    assert b"Local Network" in resp.data
    assert b"Remote Access" in resp.data


def test_vpn_status():
    resp = _client().get("/api/vpn")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "enabled" in data
    assert "subnet" in data
    assert "port" in data
    assert "peer_count" in data
    assert isinstance(data["peer_count"], int)


def test_vpn_peers_list():
    resp = _client().get("/api/vpn/peers")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "peers" in data
    assert isinstance(data["peers"], list)


def test_vpn_enable_requires_post():
    resp = _client().get("/api/vpn/enable")
    assert resp.status_code == 405


def test_status_includes_wireguard():
    resp = _client().get("/api/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "wireguard" in data


def test_instance_name_save_does_not_restart_or_deprovision_tunnel():
    with patch.dict(gateway.options, {}, clear=True):
        with patch.dict(os.environ, {}, clear=False):
            with patch.object(gateway, "save_options"):
                with patch.object(gateway.tunnel_manager, "deprovision") as deprovision:
                    with patch.object(gateway.tunnel_manager, "start") as start:
                        resp = _client().post("/api/instance", json={"instance_name": "place1"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["instance_name"] == "place1"
    assert data["tunnel_recreated"] is False
    deprovision.assert_not_called()
    start.assert_not_called()


def test_wireguard_downloads_use_friendly_instance_name():
    with patch.dict(gateway.options, {"instance_name": "place1"}):
        with patch.object(gateway.vpn_manager, "get_peer_config", return_value="[Interface]\n"):
            vpn_resp = _client().get("/api/vpn/peers/abc12345/config?network=lan")
        with patch.object(gateway.vpn_manager, "get_peer_tunnel_bundle", return_value=b"zip"):
            relay_resp = _client().get("/api/vpn/peers/abc12345/tunnel-bundle")
        with patch.object(gateway.hub_manager, "get_peer_config", return_value="[Interface]\n"):
            hub_resp = _client().get("/api/hub/peers/abc12345/config")

    assert "filename=vipsy-place1-abc12345-lan.conf" in vpn_resp.headers["Content-Disposition"]
    assert "filename=vipsy-place1-abc12345-relay.zip" in relay_resp.headers["Content-Disposition"]
    assert "filename=vipsy-place1-abc12345-remote.conf" in hub_resp.headers["Content-Disposition"]


def test_vpn_routes_api_add_and_remove():
    route = {"id": "abcd1234", "subnet": "192.168.20.0/24", "name": "CCTV"}
    with patch.object(gateway.vpn_manager, "add_extra_subnet", return_value={"ok": True, "route": route}) as add_route:
        add_resp = _client().post("/api/vpn/routes", json={"name": "CCTV", "subnet": "192.168.20.0/24"})
    with patch.object(gateway.vpn_manager, "remove_extra_subnet", return_value={"ok": True, "routes": []}) as remove_route:
        del_resp = _client().delete("/api/vpn/routes/abcd1234")

    assert add_resp.status_code == 201
    assert del_resp.status_code == 200
    add_route.assert_called_once_with("192.168.20.0/24", "CCTV")
    remove_route.assert_called_once_with("abcd1234")


def test_vpn_port_maps_api_add_and_remove():
    mapping = {"id": "deadbeef", "protocol": "tcp", "listen_port": 18080, "target_ip": "192.168.20.10", "target_port": 80}
    with patch.object(gateway.vpn_manager, "add_port_map", return_value={"ok": True, "map": mapping}) as add_map:
        add_resp = _client().post("/api/vpn/port-maps", json={
            "name": "Camera",
            "protocol": "tcp",
            "listen_port": 18080,
            "target_ip": "192.168.20.10",
            "target_port": 80,
        })
    with patch.object(gateway.vpn_manager, "remove_port_map", return_value={"ok": True, "maps": []}) as remove_map:
        del_resp = _client().delete("/api/vpn/port-maps/deadbeef")

    assert add_resp.status_code == 201
    assert del_resp.status_code == 200
    add_map.assert_called_once_with("Camera", "tcp", 18080, "192.168.20.10", 80)
    remove_map.assert_called_once_with("deadbeef")


def test_camera_still_url_uses_stream_token_and_drops_authsig():
    with app.test_request_context(
        "/api/camera_proxy_stream/camera.192_168_7_130"
        "?token=abc&authSig=expired"
    ):
        url = gateway._camera_still_url("camera.192_168_7_130")

    assert url == (
        "http://homeassistant:8123/api/camera_proxy/camera.192_168_7_130"
        "?token=abc&width=1280&height=0"
    )


class FakeStillResponse:
    headers = {"Content-Type": "image/jpeg"}

    def __init__(self, body=b"jpeg"):
        self._body = BytesIO(body)

    def read(self):
        return self._body.read()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_camera_proxy_stream_serves_mjpeg_from_stills():
    calls = {"count": 0}

    def fake_urlopen(req, timeout=0):
        calls["count"] += 1
        if calls["count"] > 1:
            raise GeneratorExit
        assert req.full_url == (
            "http://homeassistant:8123/api/camera_proxy/camera.192_168_7_130"
            "?token=abc&width=1280&height=0"
        )
        assert timeout == 15
        return FakeStillResponse()

    with patch.object(gateway.urllib.request, "urlopen", side_effect=fake_urlopen):
        with patch.object(gateway.time, "sleep", return_value=None):
            with app.test_request_context("/api/camera_proxy_stream/camera.192_168_7_130?token=abc"):
                resp = gateway.camera_proxy_stream("camera.192_168_7_130")
                chunks = [next(resp.response), next(resp.response), next(resp.response)]
                resp.response.close()

    assert resp.status_code == 200
    assert resp.mimetype == "multipart/x-mixed-replace"
    assert b"Content-Type: image/jpeg" in b"".join(chunks)
    assert b"jpeg" in b"".join(chunks)

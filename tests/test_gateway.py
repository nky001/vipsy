import os
import sys
from unittest.mock import patch, MagicMock

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

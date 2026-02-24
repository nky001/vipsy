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

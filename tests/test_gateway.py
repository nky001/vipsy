import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

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


def test_index_returns_html():
    resp = _client().get("/")
    assert resp.status_code == 200
    assert b"Vipsy" in resp.data
    assert b"Local Network" in resp.data
    assert b"Remote Access" in resp.data

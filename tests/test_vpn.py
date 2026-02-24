import json
import os
import sys
import tempfile
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

import vpn_manager


class FakePeersDir:
    def __init__(self, tmp):
        self.tmp = tmp
        self.data_dir = os.path.join(tmp, "wireguard")
        os.makedirs(self.data_dir, exist_ok=True)

    def patch_paths(self):
        return [
            patch.object(vpn_manager, "VPN_DATA_DIR", self.data_dir),
            patch.object(vpn_manager, "VPN_PEERS_FILE", os.path.join(self.data_dir, "peers.json")),
            patch.object(vpn_manager, "VPN_SERVER_KEY", os.path.join(self.data_dir, "server.key")),
            patch.object(vpn_manager, "VPN_AUDIT_LOG", os.path.join(self.data_dir, "audit.json")),
        ]


def _apply_patches(fake):
    patches = fake.patch_paths()
    for p in patches:
        p.start()
    return patches


def _stop_patches(patches):
    for p in patches:
        p.stop()


def test_load_empty_peers():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            peers = vpn_manager._load_peers()
            assert peers == []
        finally:
            _stop_patches(patches)


def test_save_and_load_peers():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            test_peers = [
                {"peer_id": "abc12345", "name": "Test", "pubkey": "pk1", "vpn_ip": "10.8.0.2"},
                {"peer_id": "def67890", "name": "Test2", "pubkey": "pk2", "vpn_ip": "10.8.0.3"},
            ]
            vpn_manager._save_peers(test_peers)
            loaded = vpn_manager._load_peers()
            assert len(loaded) == 2
            assert loaded[0]["peer_id"] == "abc12345"
            assert loaded[1]["vpn_ip"] == "10.8.0.3"
        finally:
            _stop_patches(patches)


def test_allocate_ip():
    peers = []
    ip = vpn_manager._allocate_ip(peers, "10.8.0.0/24")
    assert ip == "10.8.0.2"

    peers = [{"vpn_ip": "10.8.0.2"}]
    ip = vpn_manager._allocate_ip(peers, "10.8.0.0/24")
    assert ip == "10.8.0.3"


def test_allocate_ip_full():
    peers = [{"vpn_ip": f"10.8.0.{i}"} for i in range(2, 255)]
    ip = vpn_manager._allocate_ip(peers, "10.8.0.0/24")
    assert ip is None


def test_server_ip():
    ip = vpn_manager._server_ip("10.8.0.0/24")
    assert ip == "10.8.0.1"


def test_network():
    net = vpn_manager._network("10.8.0.0/24")
    assert str(net) == "10.8.0.0/24"
    assert net.prefixlen == 24


def test_sanitize_peer():
    peer = {
        "peer_id": "abc12345",
        "name": "Test",
        "pubkey": "pk1",
        "privkey": "secret",
        "preshared_key": "psk",
        "vpn_ip": "10.8.0.2",
        "created_at": "2024-01-01T00:00:00+00:00",
        "expires_at": None,
        "persistent": False,
    }
    safe = vpn_manager._sanitize_peer(peer)
    assert "privkey" not in safe
    assert "preshared_key" not in safe
    assert safe["peer_id"] == "abc12345"
    assert safe["vpn_ip"] == "10.8.0.2"


def test_audit_log():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            vpn_manager._audit("test_action", "peer1", "TestPeer")
            ap = Path(os.path.join(fake.data_dir, "audit.json"))
            assert ap.exists()
            entries = json.loads(ap.read_text())
            assert len(entries) == 1
            assert entries[0]["action"] == "test_action"
            assert entries[0]["peer_id"] == "peer1"
        finally:
            _stop_patches(patches)


def test_rate_limit():
    vpn_manager._rate_buckets.clear()
    for _ in range(vpn_manager.VPN_RATE_LIMIT):
        assert vpn_manager._check_rate_limit() is True
    assert vpn_manager._check_rate_limit() is False
    vpn_manager._rate_buckets.clear()


def test_generate_client_config():
    peer = {
        "peer_id": "abc12345",
        "name": "Test",
        "pubkey": "clientpub",
        "privkey": "clientpriv",
        "preshared_key": "psk123",
        "vpn_ip": "10.8.0.2",
    }
    with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
        with patch.object(vpn_manager, "_subnet", return_value="10.8.0.0/24"):
            config = vpn_manager._generate_client_config(
                peer, "serverpub", "1.2.3.4"
            )
    assert "[Interface]" in config
    assert "PrivateKey = clientpriv" in config
    assert "Address = 10.8.0.2/24" in config
    assert "[Peer]" in config
    assert "PublicKey = serverpub" in config
    assert "PresharedKey = psk123" in config
    assert "192.168.1.0/24" in config
    assert "Endpoint = 1.2.3.4:51820" in config
    assert "PersistentKeepalive = 25" in config


def test_expire_peers():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            now = datetime.now(timezone.utc)
            expired_time = (now - timedelta(hours=1)).isoformat()
            future_time = (now + timedelta(hours=1)).isoformat()
            peers = [
                {"peer_id": "exp1", "name": "Expired", "pubkey": "pk1", "vpn_ip": "10.8.0.2",
                 "expires_at": expired_time},
                {"peer_id": "act1", "name": "Active", "pubkey": "pk2", "vpn_ip": "10.8.0.3",
                 "expires_at": future_time},
                {"peer_id": "noe1", "name": "NoExpiry", "pubkey": "pk3", "vpn_ip": "10.8.0.4",
                 "expires_at": None},
            ]
            vpn_manager._save_peers(peers)
            with patch.object(vpn_manager, "_interface_exists", return_value=False):
                vpn_manager._expire_peers()
            remaining = vpn_manager._load_peers()
            assert len(remaining) == 2
            ids = [p["peer_id"] for p in remaining]
            assert "exp1" not in ids
            assert "act1" in ids
            assert "noe1" in ids
        finally:
            _stop_patches(patches)


def test_startup_cleanup():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            now = datetime.now(timezone.utc)
            expired_time = (now - timedelta(hours=1)).isoformat()
            peers = [
                {"peer_id": "exp1", "name": "Expired", "pubkey": "pk1", "vpn_ip": "10.8.0.2",
                 "expires_at": expired_time, "persistent": False},
                {"peer_id": "per1", "name": "Persistent", "pubkey": "pk2", "vpn_ip": "10.8.0.3",
                 "expires_at": expired_time, "persistent": True},
            ]
            vpn_manager._save_peers(peers)
            with patch.object(vpn_manager, "_flush_nat_rules"):
                with patch.object(vpn_manager, "_interface_exists", return_value=False):
                    with patch.object(vpn_manager, "_destroy_interface"):
                        vpn_manager.startup_cleanup()
            remaining = vpn_manager._load_peers()
            assert len(remaining) == 1
            assert remaining[0]["peer_id"] == "per1"
        finally:
            _stop_patches(patches)


def test_status_when_disabled():
    with patch.object(vpn_manager, "_interface_exists", return_value=False):
        with patch.object(vpn_manager, "_load_peers", return_value=[]):
            s = vpn_manager.status()
    assert s["enabled"] is False
    assert s["interface"] is None
    assert s["peer_count"] == 0
    assert s["nat_active"] is False


def test_add_peer_vpn_not_enabled():
    vpn_manager._rate_buckets.clear()
    with patch.object(vpn_manager, "_interface_exists", return_value=False):
        result = vpn_manager.add_peer("TestPeer")
    assert result["ok"] is False
    assert "not enabled" in result["error"]
    vpn_manager._rate_buckets.clear()


def test_check_subnet_overlap_no_overlap():
    with patch.object(vpn_manager, "_subnet", return_value="10.8.0.0/24"):
        with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
            result = vpn_manager._check_subnet_overlap()
    assert result is None


def test_check_subnet_overlap_detected():
    with patch.object(vpn_manager, "_subnet", return_value="192.168.1.0/24"):
        with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
            result = vpn_manager._check_subnet_overlap()
    assert result is not None
    assert "overlaps" in result


def test_remove_peer_not_found():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            vpn_manager._save_peers([])
            result = vpn_manager.remove_peer("nonexistent")
            assert result["ok"] is False
            assert "not found" in result["error"]
        finally:
            _stop_patches(patches)


def test_get_peer():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            peers = [{"peer_id": "abc12345", "name": "Test", "pubkey": "pk1", "vpn_ip": "10.8.0.2"}]
            vpn_manager._save_peers(peers)
            p = vpn_manager.get_peer("abc12345")
            assert p is not None
            assert p["name"] == "Test"
            assert "privkey" not in p
            absent = vpn_manager.get_peer("nonexistent")
            assert absent is None
        finally:
            _stop_patches(patches)

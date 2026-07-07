import json
import io
import os
import sys
import tempfile
import threading
import zipfile
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
    assert "DNS =" not in config


def test_generate_client_config_keeps_explicit_dns_opt_in():
    peer = {"privkey": "clientpriv", "vpn_ip": "10.8.0.2"}
    with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
        with patch.object(vpn_manager, "_subnet", return_value="10.8.0.0/24"):
            config = vpn_manager._generate_client_config(peer, "serverpub", "1.2.3.4", "192.168.1.1")
    assert "DNS = 192.168.1.1" in config


def test_extra_subnet_is_added_to_client_allowed_ips():
    peer = {"privkey": "clientpriv", "vpn_ip": "10.8.0.2"}
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            added = vpn_manager.add_extra_subnet("192.168.20.0/24", "CCTV")
            assert added["ok"] is True
            with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
                with patch.object(vpn_manager, "_subnet", return_value="10.8.0.0/24"):
                    config = vpn_manager._generate_client_config(peer, "serverpub", "1.2.3.4")
        finally:
            _stop_patches(patches)
    assert "AllowedIPs = 192.168.1.0/24, 192.168.20.0/24, 10.8.0.0/24" in config


def test_extra_subnet_rejects_public_or_duplicate_subnet():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            assert vpn_manager.add_extra_subnet("8.8.8.0/24")["ok"] is False
            assert vpn_manager.add_extra_subnet("192.168.20.0/24")["ok"] is True
            assert vpn_manager.add_extra_subnet("192.168.20.0/24")["ok"] is False
        finally:
            _stop_patches(patches)


def test_extra_subnet_reapplies_rules_when_vpn_is_active():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            with patch.object(vpn_manager, "_interface_exists", return_value=True):
                with patch.object(vpn_manager, "_apply_nat_rules") as apply_rules:
                    added = vpn_manager.add_extra_subnet("192.168.20.0/24", "CCTV")
                    removed = vpn_manager.remove_extra_subnet(added["route"]["id"])
            assert added["ok"] is True
            assert removed["ok"] is True
            assert apply_rules.call_count == 2
        finally:
            _stop_patches(patches)


def test_port_map_validation_and_remove():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            with patch.object(vpn_manager, "_interface_exists", return_value=False):
                assert vpn_manager.add_port_map("bad", "tcp", 80, "192.168.20.10", 80)["ok"] is False
                added = vpn_manager.add_port_map("camera", "tcp", 18080, "192.168.20.10", 80)
            assert added["ok"] is True
            assert len(vpn_manager.list_port_maps()) == 1
            with patch.object(vpn_manager, "_interface_exists", return_value=False):
                removed = vpn_manager.remove_port_map(added["map"]["id"])
            assert removed["ok"] is True
            assert vpn_manager.list_port_maps() == []
        finally:
            _stop_patches(patches)


def test_apply_port_map_rules_creates_dnat_and_masquerade_rules():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        calls = []
        try:
            with patch.object(vpn_manager, "_interface_exists", return_value=False):
                vpn_manager.add_port_map("cam", "tcp", 18080, "192.168.20.10", 80)
            with patch.object(vpn_manager, "_remove_nft_rules_by_comment"):
                with patch.object(vpn_manager, "_nft_cmd", side_effect=lambda *args: calls.append(args) or True):
                    assert vpn_manager._apply_port_map_rules() is True
        finally:
            _stop_patches(patches)
    joined = [" ".join(call) for call in calls]
    assert any("nat PREROUTING tcp dport 18080 dnat to 192.168.20.10:80" in call for call in joined)
    assert any("nat POSTROUTING ip daddr 192.168.20.10 tcp dport 80 masquerade" in call for call in joined)


def test_tunnel_bundle_default_does_not_hijack_dns():
    peer = {"privkey": "clientpriv", "vpn_ip": "10.8.0.2"}
    with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
        with patch.object(vpn_manager, "_subnet", return_value="10.8.0.0/24"):
            with patch.object(vpn_manager, "_tunnel_url", return_value="https://place1.vipsy.in"):
                bundle = vpn_manager.get_tunnel_bundle("abc12345", peer, "serverpub")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        config = archive.read("vipsy-tunnel/vipsy-tunnel.conf").decode()
        linux_config = archive.read("vipsy-tunnel/vipsy-tunnel-linux.conf").decode()
    assert "DNS =" not in config
    assert "DNS =" not in linux_config
    assert "1.1.1.1/32" not in config


def test_tunnel_bundle_routes_wireguard_through_cloudflare_wss_relay():
    peer = {"privkey": "clientpriv", "vpn_ip": "10.8.0.2"}
    with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
        with patch.object(vpn_manager, "_subnet", return_value="10.8.0.0/24"):
            with patch.object(vpn_manager, "_tunnel_url", return_value="https://place1.vipsy.in"):
                bundle = vpn_manager.get_tunnel_bundle("abc12345", peer, "serverpub")
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        config = archive.read("vipsy-tunnel/vipsy-tunnel.conf").decode()
        relay_script = archive.read("vipsy-tunnel/vipsy-relay.py").decode()
    assert "Endpoint = 127.0.0.1:51820" in config
    assert 'WS_URL = "wss://place1.vipsy.in/wg-tunnel"' in relay_script


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


def test_startup_cleanup_remembers_active_local_vpn_before_destroying_interface():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            with patch.object(vpn_manager, "_stop_relay"):
                with patch.object(vpn_manager, "_flush_nat_rules"):
                    with patch.object(vpn_manager, "_interface_exists", return_value=True):
                        with patch.object(vpn_manager, "_destroy_interface") as destroy:
                            vpn_manager.startup_cleanup()
            assert vpn_manager.is_enabled() is True
            destroy.assert_called_once_with()
        finally:
            _stop_patches(patches)


def test_startup_reconnect_restores_enabled_local_vpn():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            vpn_manager._remember_enabled(True)
            with patch.object(vpn_manager, "enable", return_value={"ok": True, "message": "VPN enabled"}) as enable:
                result = vpn_manager.startup_reconnect()
            assert result["ok"] is True
            enable.assert_called_once_with()
        finally:
            _stop_patches(patches)


def test_startup_reconnect_skips_disabled_local_vpn():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            with patch.object(vpn_manager, "enable") as enable:
                result = vpn_manager.startup_reconnect()
            assert result["ok"] is True
            assert result["message"] == "Local VPN disabled"
            enable.assert_not_called()
        finally:
            _stop_patches(patches)


def test_disable_forgets_local_vpn_enabled_state():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            vpn_manager._remember_enabled(True)
            with patch.object(vpn_manager, "_stop_ttl_watcher"):
                with patch.object(vpn_manager, "_stop_relay"):
                    with patch.object(vpn_manager, "_interface_exists", return_value=False):
                        with patch.object(vpn_manager, "_flush_nat_rules"):
                            vpn_manager.disable()
            assert vpn_manager.is_enabled() is False
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


def test_enable_restores_relay_when_interface_is_already_active():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            with patch.object(vpn_manager, "_interface_exists", return_value=True):
                with patch.object(vpn_manager, "_interface_ready", return_value=True):
                    with patch.object(vpn_manager, "_apply_nat_rules"):
                        with patch.object(vpn_manager, "_restore_peers"):
                            with patch.object(vpn_manager, "_start_ttl_watcher") as start_ttl:
                                with patch.object(vpn_manager, "_start_relay", return_value=True) as start_relay:
                                    result = vpn_manager.enable()
        finally:
            _stop_patches(patches)

    assert result["ok"] is True
    assert result["message"] == "VPN already enabled"
    start_ttl.assert_called_once_with()
    start_relay.assert_called_once_with()


def test_enable_recreates_stale_interface_before_starting():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            with patch.object(vpn_manager, "_interface_exists", side_effect=[True, True]):
                with patch.object(vpn_manager, "_interface_ready", return_value=False):
                    with patch.object(vpn_manager, "_get_or_create_server_keys", return_value=("priv", "pub")):
                        with patch.object(vpn_manager, "_check_subnet_overlap", return_value=None):
                            with patch.object(vpn_manager, "_create_interface") as create_iface:
                                with patch.object(vpn_manager, "_apply_nat_rules"):
                                    with patch.object(vpn_manager, "_restore_peers"):
                                        with patch.object(vpn_manager, "_start_ttl_watcher"):
                                            with patch.object(vpn_manager, "_start_relay", return_value=True):
                                                with patch.object(vpn_manager, "_destroy_interface") as destroy:
                                                    result = vpn_manager.enable()
        finally:
            _stop_patches(patches)

    assert result["ok"] is True
    destroy.assert_called_once_with()
    create_iface.assert_called_once()


def test_enable_returns_json_error_and_cleans_partial_interface_on_port_conflict():
    with tempfile.TemporaryDirectory() as tmp:
        fake = FakePeersDir(tmp)
        patches = _apply_patches(fake)
        try:
            with patch.object(vpn_manager, "_interface_exists", return_value=False):
                with patch.object(vpn_manager, "_get_or_create_server_keys", return_value=("priv", "pub")):
                    with patch.object(vpn_manager, "_check_subnet_overlap", return_value=None):
                        with patch.object(vpn_manager, "_create_interface", side_effect=RuntimeError("RTNETLINK answers: Address in use")):
                            with patch.object(vpn_manager, "_destroy_interface") as destroy:
                                with patch.object(vpn_manager, "_flush_nat_rules") as flush:
                                    with patch.object(vpn_manager, "_stop_relay") as stop_relay:
                                        result = vpn_manager.enable()
        finally:
            _stop_patches(patches)

    assert result["ok"] is False
    assert "51820/udp is already in use" in result["error"]
    stop_relay.assert_called_once_with()
    destroy.assert_called()
    flush.assert_called()


def test_start_relay_accepts_existing_ready_listener_without_owned_process():
    old_retry = vpn_manager._relay_retry_after
    old_error = vpn_manager._relay_last_error
    old_process = vpn_manager._relay_process
    vpn_manager._relay_retry_after = 999999999.0
    vpn_manager._relay_last_error = "old failure"
    vpn_manager._relay_process = None
    try:
        with patch.object(vpn_manager, "_relay_ready", return_value=True):
            with patch.object(vpn_manager, "_stop_relay") as stop_relay:
                assert vpn_manager._start_relay() is True
    finally:
        vpn_manager._relay_retry_after = old_retry
        vpn_manager._relay_last_error = old_error
        vpn_manager._relay_process = old_process

    stop_relay.assert_not_called()
    assert vpn_manager._relay_last_error is None


def test_status_recovers_missing_relay_for_active_vpn():
    with patch.object(vpn_manager, "_interface_exists", return_value=True):
        with patch.object(vpn_manager, "_is_relay_running", side_effect=[False, True]):
            with patch.object(vpn_manager, "_relay_ready", return_value=True):
                with patch.object(vpn_manager, "_start_relay", return_value=True) as start_relay:
                    with patch.object(vpn_manager, "_load_peers", return_value=[]):
                        with patch.object(vpn_manager, "_get_wg_show", return_value={}):
                            with patch.object(vpn_manager, "_check_subnet_overlap", return_value=None):
                                with patch.object(vpn_manager, "_detect_lan_subnet", return_value="192.168.1.0/24"):
                                    with patch.object(vpn_manager, "_relay_last_error", None):
                                        state = vpn_manager.status()

    start_relay.assert_called_once_with()
    assert state["enabled"] is True
    assert state["relay_running"] is True
    assert state["relay_ready"] is True


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

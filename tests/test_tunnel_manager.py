import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

import tunnel_manager


def test_start_keeps_old_connector_when_domain_migration_is_delayed():
    old_creds = {
        "uid": "abcd1234",
        "tunnel_id": "old-tunnel",
        "connector_token": "old-token",
        "hostname": "old.example.com",
        "url": "https://old.example.com",
    }
    process = MagicMock(pid=1234)
    process.poll.return_value = None
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "cloudflared.log"
        with patch.object(tunnel_manager, "TUNNEL_LOG_FILE", log_path):
            with patch.object(tunnel_manager, "_process", None):
                with patch.object(tunnel_manager, "is_running", return_value=False):
                    with patch.object(tunnel_manager, "is_enabled", return_value=True):
                        with patch.object(tunnel_manager, "_ensure_dirs"):
                            with patch.object(tunnel_manager, "_backend_available", return_value=True):
                                with patch.object(tunnel_manager, "_load_creds", return_value=old_creds):
                                    with patch.object(tunnel_manager, "_creds_need_migration", return_value=True):
                                        with patch.object(tunnel_manager, "_register", side_effect=RuntimeError("backend delayed")):
                                            with patch.object(tunnel_manager, "_start_fallback"):
                                                with patch.object(tunnel_manager.subprocess, "Popen", return_value=process) as popen:
                                                    assert tunnel_manager.start() is True
    command = popen.call_args.args[0]
    assert command[-1] == "old-token"
    assert "Domain migration delayed" in tunnel_manager._provision_error

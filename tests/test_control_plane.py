import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

import control_plane


COMMAND_ID = "12345678-1234-1234-1234-123456789abc"


def test_restart_command_is_persisted_before_supervisor_call():
    with tempfile.TemporaryDirectory() as tmp:
        marker = Path(tmp) / "last-command"
        responses = [
            {"ok": True, "data": {"command": {"id": COMMAND_ID, "type": "restart_addon"}}},
            {"ok": True, "data": {"command": None}},
        ]
        with patch.object(control_plane, "LAST_COMMAND_PATH", marker):
            with patch.object(control_plane, "_post_heartbeat", side_effect=responses):
                with patch.object(control_plane, "_request_supervisor_restart", return_value=True) as restart:
                    assert control_plane._heartbeat_once(lambda: {}, lambda: "abcd1234", lambda: "key") is True
                    assert marker.read_text() == COMMAND_ID
                    restart.assert_called_once()


def test_processed_restart_command_does_not_restart_again():
    with tempfile.TemporaryDirectory() as tmp:
        marker = Path(tmp) / "last-command"
        marker.write_text(COMMAND_ID)
        response = {"ok": True, "data": {"command": {"id": COMMAND_ID, "type": "restart_addon"}}}
        with patch.object(control_plane, "LAST_COMMAND_PATH", marker):
            with patch.object(control_plane, "_post_heartbeat", return_value=response):
                with patch.object(control_plane, "_request_supervisor_restart") as restart:
                    assert control_plane._heartbeat_once(lambda: {}, lambda: "abcd1234", lambda: "key") is False
                    restart.assert_not_called()


def test_invalid_restart_command_is_ignored():
    assert control_plane._fresh_restart_command({"id": "../../bad", "type": "restart_addon"}) is None

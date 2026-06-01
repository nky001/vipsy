import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rootfs", "server")))

import agent


def test_agent_prefers_pinned_wireguard_identity(tmp_path):
    wireguard_id = tmp_path / "wireguard-instance-id"
    tunnel_id = tmp_path / "tunnel-uid"
    wireguard_id.write_text("oldhome1")
    tunnel_id.write_text("newtunl2")

    with patch.object(agent, "WIREGUARD_INSTANCE_ID_FILE", wireguard_id):
        with patch.object(agent, "TUNNEL_UID_FILE", tunnel_id):
            assert agent._get_instance_id() == "oldhome1"

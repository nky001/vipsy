from pathlib import Path


def test_startup_discovers_the_home_assistant_core_port():
    startup = (Path(__file__).parents[1] / "rootfs" / "run.sh").read_text()

    assert "http://supervisor/core/info" in startup
    assert "HA_CORE_PORT=\"8123\"" in startup
    assert "SUPERVISOR_CORE_PORT" in startup
    assert 'HA_CORE_HOST="127.0.0.1"' in startup
    assert 'export HA_CORE_URL="http://${HA_CORE_HOST}:${HA_CORE_PORT}"' in startup
    assert 'export HA_WS_UPSTREAM_URL="ws://${HA_CORE_HOST}:${HA_CORE_PORT}/api/websocket"' in startup

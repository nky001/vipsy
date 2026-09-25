from pathlib import Path


def test_ha_proxy_strips_forwarded_headers_for_default_install():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()
    generic_proxy = config.rsplit("reverse_proxy {$HA_CORE_URL", 1)[1]

    assert "header_up -X-Forwarded-For" in generic_proxy
    assert "header_up -X-Forwarded-Proto" in generic_proxy
    assert "header_up -X-Forwarded-Host" in generic_proxy
    assert "header_up -X-Real-IP" in generic_proxy


def test_webrtc_camera_route_preserves_tunnel_origin_before_generic_proxy():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()

    route = "reverse_proxy @ha_webrtc"
    assert "path /api/webrtc*" in config
    assert "path /api/webrtc* /api/hls* /api/stream*" not in config
    assert "path /api/webrtc* /api/camera_proxy* /api/hls* /api/stream*" not in config
    assert "header_up Host {host}" in config
    assert "header_up X-Forwarded-Host {host}" in config
    assert "header_up X-Forwarded-Proto https" in config
    assert config.index(route) < config.index("reverse_proxy @websocket")


def test_ha_websocket_uses_compatibility_proxy_for_camera_capabilities():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()

    websocket_block = config.split("reverse_proxy @websocket", 1)[1].split("reverse_proxy {$HA_CORE_URL", 1)[0]
    assert "path /api/websocket" in config
    assert "reverse_proxy @websocket 127.0.0.1:18100" in config
    assert "flush_interval -1" in websocket_block


def test_home_assistant_camera_and_media_streams_are_forwarded_without_buffering():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()

    stream_block = config.split("reverse_proxy @ha_media_stream", 1)[1].split("@ha_webrtc", 1)[0]
    assert "path /api/camera_proxy_stream* /api/hls* /api/stream*" in config
    assert "reverse_proxy @ha_media_stream {$HA_CORE_URL:http://homeassistant:8123}" in config
    assert config.index("reverse_proxy @ha_media_stream") < config.index("reverse_proxy @ha_webrtc")
    assert "header_up Host {$HA_PROXY_HOST:homeassistant}" in stream_block
    assert "header_up -X-Forwarded-Proto" in stream_block
    assert 'header_down Cache-Control "no-store, no-transform"' in stream_block
    assert "flush_interval -1" in stream_block


def test_cloudflare_wireguard_relay_route_precedes_ha_websocket_proxy():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()

    relay_route = "reverse_proxy @wgtunnel 127.0.0.1:51821"
    assert "path /wg-tunnel" in config
    assert relay_route in config
    assert config.index(relay_route) < config.index("reverse_proxy @websocket")

from pathlib import Path


def test_ha_proxy_strips_forwarded_headers_for_default_install():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()

    assert config.count("header_up -X-Forwarded-For") == 2
    assert config.count("header_up -X-Forwarded-Proto") == 2
    assert config.count("header_up -X-Forwarded-Host") == 2
    assert config.count("header_up -X-Real-IP") == 2


def test_cloudflare_wireguard_relay_route_precedes_ha_websocket_proxy():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()

    relay_route = "reverse_proxy @wgtunnel 127.0.0.1:51821"
    assert "path /wg-tunnel" in config
    assert relay_route in config
    assert config.index(relay_route) < config.index("reverse_proxy @websocket")

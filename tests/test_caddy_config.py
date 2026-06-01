from pathlib import Path


def test_ha_proxy_strips_forwarded_headers_for_default_install():
    config = (Path(__file__).parents[1] / "rootfs" / "caddy" / "Caddyfile").read_text()

    assert config.count("header_up -X-Forwarded-For") == 2
    assert config.count("header_up -X-Forwarded-Proto") == 2
    assert config.count("header_up -X-Forwarded-Host") == 2
    assert config.count("header_up -X-Real-IP") == 2

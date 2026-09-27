import asyncio
import json
import os
from pathlib import Path
import struct
import sys
from unittest.mock import patch
import urllib.error

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "rootfs/server"))
import camera_diagnostics as cd

PATH = "/api/hls/abcdef0123456789/master_playlist.m3u8"


def box(kind, payload):
    return struct.pack(">I", len(payload) + 8) + kind + payload


def init(codec):
    payload = box(b"stsd", b"\0\0\0\0" + struct.pack(">I", 1) + box(codec, b"\0" * 32))
    for kind in (b"stbl", b"minf", b"mdia", b"trak", b"moov"):
        payload = box(kind, payload)
    return payload


@pytest.mark.parametrize("codec", [b"mp4v", b"avc1", b"hvc1", b"mp4a"])
def test_reads_actual_sample_description(codec):
    assert cd.sample_codecs(init(codec)) == [codec.decode()]


def test_does_not_mistake_arbitrary_payload_for_codec():
    assert cd.sample_codecs(box(b"mdat", b"mp4vavc1hvc1")) == []


@pytest.mark.parametrize("payload", [b"\0\0\0\4moov", struct.pack(">I", 100) + b"moov", box(b"stsd", b"x")])
def test_bad_mp4_is_rejected(payload):
    with pytest.raises(ValueError):
        cd.sample_codecs(payload)


@pytest.mark.parametrize("path", ["https://evil/api/hls/a/b", "//evil/a", "/api/config", PATH + "?auth=x", PATH.replace("master_playlist.m3u8", "../config"), PATH.replace("master_playlist.m3u8", "%2e%2e")])
def test_rejects_arbitrary_or_credential_urls(path):
    with pytest.raises(ValueError):
        cd._safe_path(path)


@pytest.mark.parametrize("child", ["../init.mp4", "https://evil/init.mp4", "//evil/init.mp4", "%2e%2e", "init.mp4?token=x", ".."])
def test_manifest_cannot_escape_authorized_stream(child):
    with pytest.raises(ValueError):
        cd._child_path(PATH, child)


class Response:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, count):
        return self.data[:count]


@pytest.mark.parametrize("codec,status", [(b"mp4v", "mp4v_requires_compatible_source_or_transcoding"), (b"avc1", "h264_origin_available"), (b"hvc1", "hevc_browser_support_required")])
def test_probe_verifies_init_not_only_manifest(codec, status):
    responses = [Response(b'#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1,CODECS="mp4v"\nplaylist.m3u8\n'),
                 Response(b'#EXTM3U\n#EXT-X-MAP:URI="init.mp4"\n#EXT-X-PART:DURATION=1,URI="0.0.m4s"'),
                 Response(init(codec))]
    with patch.object(cd.urllib.request, "build_opener") as build:
        build.return_value.open.side_effect = responses
        result = cd.probe_hls(PATH)
    assert result["status"] == status
    assert result["sample_codecs"] == [codec.decode()]
    assert "abcdef0123456789" not in json.dumps(result)


def test_probe_reports_http_failure_without_url_or_error_body():
    with patch.object(cd.urllib.request, "build_opener") as build:
        build.return_value.open.side_effect = urllib.error.HTTPError("secret", 404, "private", {}, None)
        result = cd.probe_hls(PATH)
    assert result["http_status"] == 404
    assert "secret" not in json.dumps(result)
    assert "private" not in json.dumps(result)


def test_background_probes_are_deduplicated_and_bounded(tmp_path):
    async def scenario():
        diagnostics = cd.CameraDiagnostics(tmp_path / "report.json")
        event = asyncio.Event()
        async def waiting(*args):
            await event.wait()
        with patch.object(diagnostics, "_probe", side_effect=waiting):
            for entity in ("camera.one", "camera.one", "camera.two", "camera.three"):
                diagnostics.schedule(entity, PATH)
            assert len(diagnostics.tasks) == 2
            event.set()
            await asyncio.gather(*diagnostics.tasks)
    asyncio.run(scenario())


def test_report_write_and_staleness(tmp_path):
    path = tmp_path / "report.json"
    diagnostics = cd.CameraDiagnostics(path)
    diagnostics._save('{"cameras": {"camera.one": {"status": "h264_origin_available"}}}')
    assert cd.read_report(path)["cameras"]["camera.one"]["status"] == "h264_origin_available"
    os.utime(path, (0, 0))
    assert cd.read_report(path)["status"] == "stale"


def test_records_are_bounded_and_failed_probe_clears_old_codec(tmp_path):
    diagnostics = cd.CameraDiagnostics(tmp_path / "report.json")
    for i in range(70):
        diagnostics.record(f"camera.{i}", {"event": "capabilities"})
    assert len(diagnostics.records) == 64
    diagnostics.record("camera.x", {"event": "hls_origin_probe", "sample_codecs": ["mp4v"]})
    diagnostics.record("camera.x", {"event": "hls_origin_probe", "status": "probe_failed"})
    assert "sample_codecs" not in diagnostics.records["camera.x"]

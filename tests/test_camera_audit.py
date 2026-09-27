import io
from fractions import Fraction
from pathlib import Path
import sys
from unittest.mock import Mock, patch
from contextlib import contextmanager

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))
from camera_audit import HomeAssistant, Preview, suggested_values, verify_saved_source


def test_suggested_values_preserve_nested_camera_options():
    schema = [{"name": "stream_source", "description": {"suggested_value": "rtsp://camera/profile4"}},
              {"name": "advanced", "schema": [
                  {"name": "rtsp_transport", "description": {"suggested_value": "tcp"}},
                  {"name": "verify_ssl", "description": {"suggested_value": True}},
                  {"name": "framerate", "default": 2},
              ]}]
    assert suggested_values(schema) == {"stream_source": "rtsp://camera/profile4",
                                        "advanced": {"rtsp_transport": "tcp", "verify_ssl": True, "framerate": 2}}


def test_unsaved_preview_stops_stream_before_deleting_flow():
    client = Mock()
    client.json.return_value = {"step_id": "user_confirm"}
    client.rpc.return_value = {"attributes": {"stream_url": "https://example/api/hls/token/master_playlist.m3u8"}}
    preview = Preview(client, {"flow_id": "flow", "data_schema": []})
    preview.start({"stream_source": "rtsp://camera/profile1"})
    preview.close()
    calls = client.json.call_args_list
    assert calls[-2].args[1] == {"confirmed_ok": False}
    assert calls[-1].kwargs == {"method": "DELETE"}
    assert not any(call.args[1:] == ({"confirmed_ok": True},) for call in calls)


def test_preview_cannot_commit_before_validation():
    client = Mock()
    preview = Preview(client, {"flow_id": "flow", "data_schema": []})
    with pytest.raises(RuntimeError):
        preview.commit()
    client.json.assert_not_called()


def test_successfully_committed_flow_is_not_deleted_again():
    client = Mock()
    client.json.return_value = {"type": "create_entry"}
    preview = Preview(client, {"flow_id": "flow", "data_schema": []})
    preview.preview = True
    preview.commit()
    preview.close()
    assert client.json.call_count == 1


def test_saved_source_failure_rolls_back_original_settings():
    client = Mock()
    client.rpc.return_value = {"url": "internal"}
    client.media_info.return_value = {"codec": "mjpeg"}
    rollback = Mock()
    @contextmanager
    def options(entity):
        yield rollback
    client.options = options
    original = {"stream_source": "rtsp://camera/original", "advanced": {"framerate": 2}}
    with patch("camera_audit.time.sleep"), pytest.raises(RuntimeError, match="original source restored"):
        verify_saved_source(client, "camera.test", original)
    rollback.start.assert_called_once_with(original)
    rollback.commit.assert_called_once()


def test_saved_source_reload_retry_does_not_modify_other_settings():
    client = Mock()
    client.rpc.return_value = {"url": "internal"}
    client.media_info.side_effect = [RuntimeError("reloading"), {"codec": "h264"}]
    with patch("camera_audit.time.sleep"):
        assert verify_saved_source(client, "camera.test", {})["codec"] == "h264"
    client.options.assert_not_called()


@pytest.mark.parametrize("codec,expected", [("libx264", "h264"), ("mjpeg", "mjpeg")])
def test_audit_decodes_real_fragmented_mp4_frames(codec, expected):
    av = pytest.importorskip("av")
    Image = pytest.importorskip("PIL.Image")
    encoded = io.BytesIO()
    with av.open(encoded, "w", format="mp4", options={"movflags": "frag_keyframe+empty_moov+default_base_moof"}) as container:
        video = container.add_stream(codec, rate=25)
        video.width, video.height = 64, 48
        video.pix_fmt = "yuv420p" if codec == "libx264" else "yuvj420p"
        video.gop_size = 50
        for i in range(50):
            frame = av.VideoFrame.from_image(Image.new("RGB", (64, 48), (i * 4, 64, 128)))
            frame.pts, frame.time_base = i, Fraction(1, 25)
            for packet in video.encode(frame):
                container.mux(packet)
        for packet in video.encode():
            container.mux(packet)
    data = encoded.getvalue()
    position = 0
    while data[position + 4:position + 8] != b"moof":
        size = int.from_bytes(data[position:position + 4], "big")
        assert size > 0
        position += size
    prefix = "/api/hls/abcdef0123456789/"
    fixtures = {
        prefix + "master_playlist.m3u8": b'#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\nplaylist.m3u8\n',
        prefix + "playlist.m3u8": b'#EXTM3U\n#EXT-X-MAP:URI="init.mp4"\n#EXTINF:2.0,\n./segment/0.m4s\n',
        prefix + "init.mp4": data[:position],
        prefix + "segment/0.m4s": data[position:],
    }
    client = object.__new__(HomeAssistant)
    client.fetch = lambda path, **kwargs: fixtures[path]
    stats = client.media_info(prefix + "master_playlist.m3u8")
    assert stats["codec"] == expected
    assert stats["decoded_frames"] == 50
    assert stats["fps"] == 25
    assert (stats["width"], stats["height"]) == (64, 48)

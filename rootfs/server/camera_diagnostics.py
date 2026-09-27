"""Read-only probes of HA-authorized HLS streams; never record bearer URLs."""
import asyncio
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

REPORT_PATH = Path(os.environ.get("VIPSY_CAMERA_DIAGNOSTICS_PATH", "/data/camera_diagnostics.json"))
HLS_PATH = re.compile(r"/api/hls/[a-zA-Z0-9_-]{16,256}/[a-zA-Z0-9][a-zA-Z0-9_.-]*\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _safe_path(path):
    if not isinstance(path, str) or not HLS_PATH.fullmatch(path):
        raise ValueError("not a local HA HLS resource")
    return path


def _child_path(parent, uri):
    # No external hosts, queries, escapes or traversal from a manifest.
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", uri) or uri in {".", ".."}:
        raise ValueError("invalid HLS child")
    return _safe_path(parent.rsplit("/", 1)[0] + "/" + uri)


def sample_codecs(data):
    """Read actual stsd sample FourCCs, not arbitrary strings in the MP4."""
    codecs = set()

    def boxes(start, end, depth=0):
        if depth > 8:
            raise ValueError("MP4 nesting limit")
        while start + 8 <= end:
            size = int.from_bytes(data[start:start + 4], "big")
            kind, header = data[start + 4:start + 8], 8
            if size == 1:
                if start + 16 > end:
                    raise ValueError("truncated MP4")
                size, header = int.from_bytes(data[start + 8:start + 16], "big"), 16
            elif size == 0:
                size = end - start
            if size < header or start + size > end:
                raise ValueError("invalid MP4 box")
            body, stop = start + header, start + size
            if kind in {b"moov", b"trak", b"mdia", b"minf", b"stbl"}:
                boxes(body, stop, depth + 1)
            elif kind == b"stsd":
                if body + 8 > stop:
                    raise ValueError("truncated stsd")
                count = int.from_bytes(data[body + 4:body + 8], "big")
                pos = body + 8
                for _ in range(min(count, 32)):
                    if pos + 8 > stop:
                        raise ValueError("truncated sample entry")
                    length = int.from_bytes(data[pos:pos + 4], "big")
                    if length < 8 or pos + length > stop:
                        raise ValueError("invalid sample entry")
                    codec = data[pos + 4:pos + 8].decode("ascii", errors="replace")
                    if re.fullmatch(r"[a-zA-Z0-9 ._-]{4}", codec):
                        codecs.add(codec)
                    pos += length
            start = stop

    boxes(0, len(data))
    return sorted(codecs)


def probe_hls(path, origin=None):
    _safe_path(path)
    origin = (origin or os.environ.get("HA_CORE_URL", "http://homeassistant:8123")).rstrip("/")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    started = time.monotonic()
    report = {"event": "hls_origin_probe", "stage": "master"}

    def fetch(resource, limit):
        req = urllib.request.Request(origin + resource, headers={
            "Accept-Encoding": "identity", "Cache-Control": "no-cache",
            "User-Agent": "vipsy-camera-diagnostics/1",
        })
        # Cold HA streams may need two GOPs before the master exists.
        with opener.open(req, timeout=20) as response:
            payload = response.read(limit + 1)
            if len(payload) > limit:
                raise ValueError("response exceeds limit")
            return payload

    try:
        text = fetch(path, 65536).decode("utf-8")
        if not text.startswith("#EXTM3U"):
            raise ValueError("not a playlist")
        match = re.search(r'CODECS="([a-zA-Z0-9., _-]{1,200})"', text)
        if match:
            report["advertised_codecs"] = match[1]
        if "#EXT-X-STREAM-INF:" in text:
            children = [line.strip() for line in text.splitlines()
                        if line.strip() and not line.startswith("#")]
            if not children:
                raise ValueError("empty master")
            path = _child_path(path, children[0])
            report["stage"] = "playlist"
            text = fetch(path, 65536).decode("utf-8")
        if not text.startswith("#EXTM3U"):
            raise ValueError("not a playlist")
        report["low_latency_hls"] = "#EXT-X-PART:" in text
        match = re.search(r'#EXT-X-MAP:.*?URI="([^"]+)"', text)
        if not match:
            report["status"] = "no_fmp4_init"
        else:
            report["stage"] = "init"
            report["sample_codecs"] = codecs = sample_codecs(fetch(_child_path(path, match[1]), 2097152))
            if "mp4v" in codecs:
                # mp4v is a sample entry, not proof of MPEG-4 Part 2:
                # FFmpeg can also put MJPEG under this tag (ESDS object type).
                report["status"] = "mp4v_requires_compatible_source_or_transcoding"
            elif any(codec in {"avc1", "avc3"} for codec in codecs):
                report["status"] = "h264_origin_available"
            elif any(codec in {"hvc1", "hev1"} for codec in codecs):
                report["status"] = "hevc_browser_support_required"
            else:
                report["status"] = "unrecognized_codec"
    except urllib.error.HTTPError as exc:
        report.update(status="origin_http_error", http_status=exc.code)
    except Exception as exc:
        report.update(status="probe_failed", error_type=type(exc).__name__)
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return report


class CameraDiagnostics:
    def __init__(self, path=REPORT_PATH):
        self.path, self.records, self.last_probe, self.tasks = path, {}, {}, set()
        self.write_lock = asyncio.Lock()

    def record(self, entity, data):
        previous = self.records.pop(entity, {})
        if data.get("event") == "hls_origin_probe":
            previous = {key: previous[key] for key in ("transports", "policy") if key in previous}
        self.records[entity] = {**previous, **data, "updated_at": int(time.time())}
        while len(self.records) > 64:
            self.records.pop(next(iter(self.records)))
        print(f"[vipsy.camera] {entity} {json.dumps(data, separators=(',', ':'))}", flush=True)

    async def _probe(self, entity, path):
        try:
            self.record(entity, await asyncio.to_thread(probe_hls, path))
            async with self.write_lock:
                await asyncio.to_thread(self._save, json.dumps({"cameras": dict(self.records)}))
        except Exception as exc:
            print(f"[vipsy.camera] diagnostics failed: {type(exc).__name__}", flush=True)

    def _save(self, snapshot):
        import tempfile
        self.path.parent.mkdir(parents=True, exist_ok=True)
        name = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent,
                                             prefix="camera-diagnostics-", delete=False) as handle:
                name = handle.name
                handle.write(snapshot)
            os.replace(name, self.path)
        finally:
            if name and os.path.exists(name):
                os.unlink(name)

    def schedule(self, entity, path):
        try:
            _safe_path(path)
        except ValueError:
            return
        now = time.monotonic()
        if len(self.tasks) >= 2 or now - self.last_probe.get(entity, -float("inf")) < 60:
            return
        self.last_probe[entity] = now
        while len(self.last_probe) > 64:
            self.last_probe.pop(next(iter(self.last_probe)))
        task = asyncio.create_task(self._probe(entity, path))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)


def read_report(path=REPORT_PATH):
    try:
        if time.time() - path.stat().st_mtime > 3600:
            return {"cameras": {}, "status": "stale"}
        if path.stat().st_size > 131072:
            return {"cameras": {}}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("cameras"), dict):
            return {"cameras": {}}
        return {"cameras": {
            entity: report for entity, report in data["cameras"].items()
            if re.fullmatch(r"camera\.[a-z0-9_]{1,200}", entity)
            and isinstance(report, dict)
            and isinstance(report.get("updated_at", 0), (int, float))
        }}
    except (OSError, ValueError):
        return {"cameras": {}, "status": "not_observed"}

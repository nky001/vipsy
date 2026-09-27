"""Audit actual HA camera media and preview a candidate source without saving.

Run with the repository venv (extra audit dependencies: av, Pillow).
Credentials are prompted, kept in memory and never written to the report.
Changing a camera requires an explicit --apply flag and a validated H.264 preview.
"""
import argparse
from contextlib import contextmanager
import getpass
import io
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

from websockets.sync.client import connect


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def suggested_values(schema):
    values = {}
    for field in schema:
        if "schema" in field:
            values[field["name"]] = suggested_values(field["schema"])
        elif "suggested_value" in field.get("description", {}):
            values[field["name"]] = field["description"]["suggested_value"]
        elif "default" in field:
            values[field["name"]] = field["default"]
    return values


class HomeAssistant:
    def __init__(self, url, username, password):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Use the HTTPS Home Assistant origin without credentials")
        self.base = f"https://{parsed.netloc}"
        self.token = self.refresh = self.ws = None
        self.msg_id = 0
        self.opener = urllib.request.build_opener(NoRedirect())
        flow = self.json("/auth/login_flow", {
            "client_id": self.base + "/", "handler": ["homeassistant", None],
            "redirect_uri": self.base + "/?auth_callback=1",
        })
        result = self.json("/auth/login_flow/" + flow["flow_id"], {
            "client_id": self.base + "/", "username": username, "password": password,
        })
        if result.get("type") != "create_entry":
            raise RuntimeError("Login did not complete; check credentials/MFA")
        tokens = self.json("/auth/token", {
            "grant_type": "authorization_code", "code": result["result"],
            "client_id": self.base + "/",
        }, form=True)
        self.token, self.refresh = tokens["access_token"], tokens["refresh_token"]
        try:
            self.ws = connect(self.base.replace("https:", "wss:") + "/api/websocket",
                              origin=self.base, user_agent_header="Mozilla/5.0 VipsyCameraAudit/1",
                              open_timeout=20)
            self.version = json.loads(self.ws.recv(timeout=20)).get("ha_version")
            self.ws.send(json.dumps({"type": "auth", "access_token": self.token}))
            if json.loads(self.ws.recv(timeout=20)).get("type") != "auth_ok":
                raise RuntimeError("Websocket authentication failed")
        except Exception:
            self.close()
            raise

    def close(self):
        try:
            if self.ws:
                self.ws.close()
        finally:
            if self.refresh:
                self.json("/auth/token", {"action": "revoke", "token": self.refresh}, form=True)
                self.token = self.refresh = None

    def fetch(self, path, data=None, *, form=False, method=None, limit=32 * 1024 * 1024):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Only same-origin paths are allowed")
        body = None if data is None else (
            urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode())
        headers = {"User-Agent": "Mozilla/5.0 VipsyCameraAudit/1", "Origin": self.base,
                   "Accept-Encoding": "identity", "Cache-Control": "no-cache",
                   "Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        with self.opener.open(urllib.request.Request(self.base + path, data=body,
                                                     headers=headers, method=method), timeout=40) as response:
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise ValueError("Response exceeds audit limit")
            return raw

    def json(self, *args, **kwargs):
        raw = self.fetch(*args, **kwargs)
        return json.loads(raw) if raw else {}

    def rpc(self, command, **params):
        self.msg_id += 1
        self.ws.send(json.dumps({"id": self.msg_id, "type": command, **params}))
        deadline = time.monotonic() + 45
        while True:
            result = json.loads(self.ws.recv(timeout=max(0.1, deadline - time.monotonic())))
            if result.get("id") != self.msg_id:
                continue
            if result.get("success") is False:
                raise RuntimeError("HA command failed: " + command)
            return result.get("result", result.get("event"))

    @contextmanager
    def options(self, entity):
        entry = self.rpc("config/entity_registry/get", entity_id=entity)
        if entry.get("platform") != "generic":
            raise ValueError("Only Generic Camera sources are in scope")
        flow = self.json("/api/config/config_entries/options/flow", {"handler": entry["config_entry_id"]})
        transaction = Preview(self, flow)
        try:
            yield transaction
        finally:
            transaction.close()

    def media_info(self, path, frame_path=None):
        import av  # Optional CLI-only dependency, never used by the add-on.
        path = urllib.parse.urlsplit(path).path
        if not re.fullmatch(r"/api/hls/[a-f0-9]+/[a-z_.0-9]+", path):
            raise ValueError("Expected a HA-authorized HLS path")
        directory = path.rsplit("/", 1)[0] + "/"

        def child(uri):
            uri = uri.removeprefix("./")
            if not re.fullmatch(r"(?:segment/)?[a-zA-Z0-9_.-]+", uri) or ".." in uri:
                raise ValueError("Unexpected HLS resource")
            return directory + uri

        start = time.monotonic()
        master = self.fetch(path, limit=65536).decode()
        variant = next(line for line in master.splitlines() if line and not line.startswith("#"))
        playlist = self.fetch(child(variant), limit=65536).decode()
        init_uri = re.search(r'#EXT-X-MAP:.*?URI="([^"]+)"', playlist)[1]
        init = self.fetch(child(init_uri), limit=2097152)
        # Decode one complete segment, beginning at a keyframe.
        segments = re.findall(r"#EXTINF:([0-9.]+),[^\n]*\n([^\n]+)", playlist)
        if not segments:
            raise RuntimeError("No complete media segment yet")
        duration, uri = segments[-1]
        data = self.fetch(child(uri.strip()))
        with av.open(io.BytesIO(init + data)) as container:
            video = container.streams.video[0]
            codec = video.codec_context.name
            width, height = video.codec_context.width, video.codec_context.height
            timestamps, count = [], 0
            for frame in container.decode(video):
                if count == 0 and frame_path:
                    frame.to_image().save(frame_path)
                if frame.time is not None:
                    timestamps.append(frame.time)
                count += 1
        if count < 2 or len(timestamps) < 2 or timestamps[-1] <= timestamps[0]:
            raise RuntimeError("No advancing video frames decoded")
        return {"codec": codec, "width": width, "height": height, "decoded_frames": count,
                "fps": round((len(timestamps) - 1) / (timestamps[-1] - timestamps[0]), 2),
                "segment_seconds": float(duration), "sample_bytes": len(data),
                "fetch_and_decode_seconds": round(time.monotonic() - start, 2)}


class Preview:
    def __init__(self, client, flow):
        self.client, self.flow = client, flow
        self.path = "/api/config/config_entries/options/flow/" + flow["flow_id"]
        self.original = suggested_values(flow["data_schema"])
        self.preview = self.committed = False

    def start(self, settings):
        result = self.client.json(self.path, settings)
        if result.get("step_id") != "user_confirm":
            raise RuntimeError("Candidate source failed Home Assistant validation")
        self.preview = True
        event = self.client.rpc("generic_camera/start_preview", flow_id=self.flow["flow_id"],
                                flow_type="options_flow")
        url = event["attributes"]["stream_url"]
        if not url:
            raise RuntimeError("No preview stream")
        return url

    def commit(self):
        if not self.preview:
            raise RuntimeError("Cannot save an unvalidated source")
        result = self.client.json(self.path, {"confirmed_ok": True})
        if result.get("type") != "create_entry":
            raise RuntimeError("Source update not confirmed")
        self.committed = True

    def close(self):
        if self.committed:
            return
        try:
            if self.preview:
                self.client.json(self.path, {"confirmed_ok": False})
        finally:
            self.client.json(self.path, method="DELETE")


def verify_saved_source(client, entity, original):
    """Allow an integration reload, then rollback a failed source migration."""
    for attempt in range(3):
        try:
            path = client.rpc("camera/stream", entity_id=entity)["url"]
            result = client.media_info(path)
            if result["codec"] == "h264":
                return result
        except Exception:
            pass
        if attempt < 2:
            time.sleep(2)
    try:
        with client.options(entity) as rollback:
            rollback.start(original)
            rollback.commit()
    except Exception:
        raise RuntimeError("Saved source verification AND rollback failed; inspect this camera before proceeding") from None
    raise RuntimeError("Saved source verification failed; original source restored")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--entity", action="append", required=True)
    parser.add_argument("--preview-path", help="Explicit camera RTSP profile path to preview")
    parser.add_argument("--apply", action="store_true", help="Save the explicit H.264 candidate after decoding it")
    args = parser.parse_args()
    if args.apply and not args.preview_path:
        parser.error("--apply requires --preview-path; no profile is guessed")
    client = HomeAssistant(args.url, input("HA username: "), getpass.getpass("HA password: "))
    try:
        for entity in args.entity:
            if not args.preview_path:
                result = client.rpc("camera/stream", entity_id=entity)
                print(entity, json.dumps(client.media_info(result["url"])))
                continue
            with client.options(entity) as preview:
                candidate = json.loads(json.dumps(preview.original))
                source = urllib.parse.urlsplit(candidate["stream_source"])
                if source.scheme not in ("rtsp", "rtsps") or not args.preview_path.startswith("/"):
                    raise ValueError("Expected an RTSP source and absolute profile path")
                candidate["stream_source"] = urllib.parse.urlunsplit(source._replace(path=args.preview_path))
                stats = client.media_info(preview.start(candidate))
                print(entity, json.dumps(stats))
                if args.apply:
                    if stats["codec"] != "h264":
                        raise RuntimeError("Refusing to apply a non-H.264 source")
                    preview.commit()
                    verified = verify_saved_source(client, entity, preview.original)
                    print(entity, "saved stream verified", json.dumps(verified))
    finally:
        client.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # URL-bearing HTTP/decoder exceptions must not leak source tokens.
        # Our own RuntimeError messages contain no upstream bodies or URLs.
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        raise SystemExit(f"Camera audit stopped: {detail}") from None

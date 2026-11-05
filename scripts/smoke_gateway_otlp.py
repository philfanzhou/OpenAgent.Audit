"""End-to-end: real uvicorn process, real OTLP transports, real HTTP.

Boots the Masking Gateway (and a fake Langfuse OTLP receiver) as actual
processes and drives them over HTTP the way the .NET OpenAgent platform
does — protobuf first, since that is ASP.NET Core's default export protocol.

    python scripts/smoke_gateway_otlp.py
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.conftest import PASSPHRASE, generate_keypair  # noqa: E402

GATEWAY_PORT = 8192
LANGFUSE_PORT = 8193
GATEWAY_TOKEN = "smoke-gateway-token"


def wait_ready(url: str, timeout: float = 40.0, headers: dict | None = None) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"service not ready: {url}")


def http_post(url: str, body: bytes, headers: dict) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method="POST")
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class FakeLangfuse:
    """Accepts Langfuse's native OTLP/HTTP JSON trace endpoint."""

    def __init__(self) -> None:
        self.payloads: list[dict] = []
        self.auth: list[str] = []
        self.status = 200
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                if self.path != "/api/public/otel/v1/traces":
                    self.send_response(404)
                    self.end_headers()
                    return
                outer.auth.append(self.headers.get("Authorization", ""))
                if outer.status == 200:
                    outer.payloads.append(json.loads(raw))
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, *args):  # silence
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", LANGFUSE_PORT), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()


def protobuf_export_request() -> bytes:
    """Serialise an ExportTraceServiceRequest the way the .NET SDK does."""
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    request = ExportTraceServiceRequest()
    resource_spans = request.resource_spans.add()
    service = resource_spans.resource.attributes.add()
    service.key = "service.name"
    service.value.string_value = "openagent-engine"
    span = resource_spans.scope_spans.add().spans.add()
    span.trace_id = bytes.fromhex("b" * 32)
    span.span_id = bytes.fromhex("2" * 16)
    span.name = "POST /api/v1/agent/chat"
    span.start_time_unix_nano = int(time.time() * 1e9)
    span.end_time_unix_nano = int(time.time() * 1e9) + 1_000_000
    for key, value in (
        ("openagent.conversation_id", "smoke-conv-1"),
        ("openagent.user_id", "usr_smoke_1"),
        ("agent.id", "cs-bot"),
        ("gen_ai.prompt.0.content", "帮我联系张伟，电话 13812345678，身份证 110101199003078515"),
        ("http.request.method", "POST"),
    ):
        attribute = span.attributes.add()
        attribute.key = key
        attribute.value.string_value = value
    return request.SerializeToString()


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="openagent-audit-gw-smoke-"))
    pub, _priv = generate_keypair(PASSPHRASE)
    (tmp / "pub.pem").write_bytes(pub)

    fake_langfuse = FakeLangfuse()
    fake_langfuse.start()

    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(ROOT / "src"),
        "AUDIT_DB_URL": (tmp / "audit.db").as_uri().replace("file:///", "sqlite:///"),
        "AUDIT_PUBLIC_KEY_PATH": str(tmp / "pub.pem"),
        "AUDIT_GATEWAY_TOKEN": GATEWAY_TOKEN,
        "AUDIT_GATEWAY_REQUIRE_AUTH": "true",
        "LANGFUSE_HOST": f"http://127.0.0.1:{LANGFUSE_PORT}",
        "LANGFUSE_PUBLIC_KEY": "pk-smoke",
        "LANGFUSE_SECRET_KEY": "sk-smoke",
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "openagent_audit.gateway.app:create_app",
         "--port", str(GATEWAY_PORT), "--log-level", "warning"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{GATEWAY_PORT}"
    try:
        wait_ready(f"{base}/healthz")
        print("[ok] masking gateway booted under real uvicorn")

        body = protobuf_export_request()
        auth = {"Authorization": f"Bearer {GATEWAY_TOKEN}",
                "Content-Type": "application/x-protobuf"}

        # 1. protobuf ingest (ASP.NET Core default)
        status, payload = http_post(f"{base}/v1/traces", body, auth)
        assert status == 200, (status, payload)
        print("[ok] http/protobuf accepted on /v1/traces")

        # 2. the SDK's double-path variant
        status, payload = http_post(f"{base}/v1/traces/v1/traces", body, auth)
        assert status == 200, (status, payload)
        print("[ok] /v1/traces/v1/traces variant accepted")

        # 3. gRPC framing
        framed = b"\x00" + len(body).to_bytes(4, "big") + body
        status, payload = http_post(
            f"{base}/opentelemetry.proto.collector.trace.v1.TraceService/Export",
            framed,
            {"Authorization": f"Bearer {GATEWAY_TOKEN}", "Content-Type": "application/grpc"},
        )
        assert status == 200, (status, payload)
        print("[ok] gRPC-framed export accepted")

        # 4. auth is enforced
        status, _ = http_post(f"{base}/v1/traces", body, {"Content-Type": "application/x-protobuf"})
        assert status == 401, status
        print("[ok] unauthenticated protobuf ingest rejected")

        # 5. mask + seal + forward actually happened
        assert len(fake_langfuse.payloads) == 3, len(fake_langfuse.payloads)
        for forwarded in fake_langfuse.payloads:
            text = json.dumps(forwarded, ensure_ascii=False)
            assert "13812345678" not in text, "plaintext phone leaked upstream"
            assert "110101199003078515" not in text, "plaintext id card leaked upstream"
            assert "⟦PHONE_NUMBER#" in text
            span = forwarded["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
            attrs = {a["key"]: a.get("value", {}).get("stringValue")
                     for a in span["attributes"]}
            assert attrs["langfuse.session.id"] == "smoke-conv-1"
            assert attrs["langfuse.user.id"] == "usr_smoke_1"
            assert attrs["langfuse.tag.agent"] == "cs-bot"
            assert attrs["http.request.method"] == "POST"  # untouched
        print("[ok] masked OTLP/JSON forwarded to Langfuse, plaintext never left the gateway")

        # 6. ciphertext landed in the vault with trace ownership
        import sqlite3

        conn = sqlite3.connect(tmp / "audit.db")
        try:
            rows = conn.execute(
                "SELECT entity_type, trace_id, session_id FROM entity_ciphertext"
            ).fetchall()
        finally:
            conn.close()
        assert rows, "no ciphertext rows"
        assert all(r[1] == "b" * 32 and r[2] == "smoke-conv-1" for r in rows), rows
        kinds = {r[0] for r in rows}
        assert "PHONE_NUMBER" in kinds, kinds
        print(f"[ok] {len(rows)} ciphertext rows sealed with trace/session ownership: {sorted(kinds)}")

        # 7. metrics expose the counters
        metrics = json.loads(urllib.request.urlopen(f"{base}/internal/metrics").read())
        gw = metrics["gateway"]
        # rejected before the pipeline, so not counted as a received batch
        assert gw["batches_unauthorized"] == 1 and gw["batches_received"] == 3, gw
        assert gw["forwarded_batches"] == 3 and gw["batches_dropped"] == 0, gw
        print(f"[ok] metrics: {gw}")

        print("GATEWAY SMOKE PASS")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        fake_langfuse.stop()


if __name__ == "__main__":
    raise SystemExit(main())
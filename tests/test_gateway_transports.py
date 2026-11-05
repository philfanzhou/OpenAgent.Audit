"""Masking Gateway transport + auth hardening (OpenAgent .NET ingestion).

Covers the failure modes that made the documented "point OTEL_EXPORTER_OTLP_
ENDPOINT at the gateway" integration unusable against the real .NET platform:

* ``http/protobuf`` (ASP.NET Core's default export protocol) is decoded;
* OTLP/gRPC-framed bodies are unwrapped;
* every route an SDK can compose (``/v1/traces``, ``/v1/traces/v1/traces``,
  the gRPC service path, ``/``) reaches the same ingest logic;
* the bearer token is accepted in both header shapes and compared in
  constant time, and a deployment can force auth on;
* a bad body is rejected (never confused with "empty batch");
* counter helpers are actually thread-safe (the old ``threading.Lock()``
  misuse raised ``TypeError`` on the very first request).
"""

from __future__ import annotations

import json
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient

from openagent_audit.config import Settings
from openagent_audit.gateway.app import GatewayCounters, GatewayDeps, create_gateway_app
from openagent_audit.gateway.otlp import (
    GatewayPayloadError,
    decode_otlp_body,
    encode_otlp_json,
)
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter

PASSPHRASE = b"unit-test-passphrase"
PHONE = "13812345678"


def _json_payload() -> dict:
    return {
        "resourceSpans": [{
            "resource": {"attributes": []},
            "scopeSpans": [{
                "scope": {"name": "OpenAgent.Engine"},
                "spans": [{
                    "traceId": "a" * 32,
                    "spanId": "1" * 16,
                    "name": "POST /api/v1/agent/chat",
                    "attributes": [
                        {"key": "openagent.conversation_id", "value": {"stringValue": "conv-1"}},
                        {"key": "openagent.user_id", "value": {"stringValue": "usr_1"}},
                        {"key": "agent.id", "value": {"stringValue": "cs-bot"}},
                        {"key": "gen_ai.prompt.0.content",
                         "value": {"stringValue": f"帮我联系张伟，电话 {PHONE}"}},
                    ],
                }],
            }],
        }],
    }


def _protobuf_payload_bytes() -> bytes:
    """Serialise the same span tree with the real OTLP protobuf bindings."""
    pytest.importorskip("opentelemetry.proto")
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    request = ExportTraceServiceRequest()
    span = request.resource_spans.add().scope_spans.add().spans.add()
    span.trace_id = bytes.fromhex("a" * 32)
    span.span_id = bytes.fromhex("1" * 16)
    span.name = "POST /api/v1/agent/chat"
    for key, value in (
        ("openagent.conversation_id", "conv-1"),
        ("openagent.user_id", "usr_1"),
        ("agent.id", "cs-bot"),
        ("gen_ai.prompt.0.content", f"帮我联系张伟，电话 {PHONE}"),
    ):
        attribute = span.attributes.add()
        attribute.key = key
        attribute.value.string_value = value
    return request.SerializeToString()


def _grpc_frame(message: bytes) -> bytes:
    return b"\x00" + len(message).to_bytes(4, "big") + message


def _build(settings: Settings, tmp_path) -> tuple[TestClient, list, GatewayDeps]:
    from openagent_audit.bootstrap import build_db, build_write_cipher

    db = build_db(settings)
    forwarded: list[bytes] = []
    deps = GatewayDeps(
        settings=settings,
        pipeline=MaskingPipeline(
            cipher=build_write_cipher(settings), vault_writer=VaultWriter(db)
        ),
        forwarder=lambda payload: forwarded.append(payload),
    )
    return TestClient(create_gateway_app(deps)), forwarded, deps


@pytest.fixture()
def gw(tmp_path, keypair):
    public_pem, _ = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        audit_db_url=f"sqlite:///{(tmp_path / 'audit.db')}",
        public_key_path=str(key_dir / "audit_public_key.pem"),
        gateway_ingest_token="gw-secret",
        gateway_require_auth=True,
    )
    client, forwarded, deps = _build(settings, tmp_path)
    return {
        "client": client,
        "forwarded": forwarded,
        "deps": deps,
        "settings": settings,
        "db_path": tmp_path / "audit.db",
    }


AUTH = {"Authorization": "Bearer gw-secret"}


# ---------------------------------------------------------------------------
# P0-1: counters are really thread-safe (the old code raised TypeError)
# ---------------------------------------------------------------------------


def test_counters_are_stable_under_concurrency():
    counters = GatewayCounters()
    errors: list[BaseException] = []

    def hammer() -> None:
        try:
            for _ in range(200):
                counters.record_batch_received()
                counters.record_spans_masked(2)
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    snap = counters.snapshot()
    assert snap["batches_received"] == 1600
    assert snap["spans_masked"] == 3200


# ---------------------------------------------------------------------------
# P0-2: protobuf + gRPC framing
# ---------------------------------------------------------------------------


def test_json_ingest_masks_and_forwards(gw):
    r = gw["client"].post("/v1/traces", json=_json_payload(), headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True

    assert len(gw["forwarded"]) == 1
    span = json.loads(gw["forwarded"][0])["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    serialized = json.dumps(span, ensure_ascii=False)
    assert PHONE not in serialized
    assert "⟦PHONE_NUMBER#" in serialized
    attrs = {a["key"]: a["value"] for a in span["attributes"]}
    assert attrs["langfuse.session.id"]["stringValue"] == "conv-1"
    assert attrs["langfuse.user.id"]["stringValue"] == "usr_1"
    assert attrs["langfuse.tag.agent"]["stringValue"] == "cs-bot"

    rows = sqlite3.connect(gw["db_path"]).execute(
        "SELECT entity_id, trace_id, session_id FROM entity_ciphertext"
    ).fetchall()
    assert rows and all(row[1] == "a" * 32 and row[2] == "conv-1" for row in rows)


def test_protobuf_ingest_is_masked_and_forwarded_as_json(gw):
    body = _protobuf_payload_bytes()
    r = gw["client"].post(
        "/v1/traces",
        content=body,
        headers={**AUTH, "content-type": "application/x-protobuf"},
    )
    assert r.status_code == 200, r.text

    forwarded = json.loads(gw["forwarded"][0])
    span = forwarded["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    serialized = json.dumps(span, ensure_ascii=False)
    assert PHONE not in serialized
    assert "⟦PHONE_NUMBER#" in serialized
    # trace/span ids stay base64 (OTLP JSON form) after protobuf decoding
    assert isinstance(span["traceId"], str) and span["traceId"]

    rows = sqlite3.connect(gw["db_path"]).execute(
        "SELECT session_id FROM entity_ciphertext"
    ).fetchall()
    assert rows and all(row[0] == "conv-1" for row in rows)


def test_protobuf_detected_without_content_type(gw):
    """Some SDK builds omit the protobuf content type; sniff by first byte."""
    r = gw["client"].post("/v1/traces", content=_protobuf_payload_bytes(), headers=AUTH)
    assert r.status_code == 200, r.text


def test_vault_trace_id_is_hex_whichever_transport_used(gw):
    """OTLP/JSON carries base64 ids, protobuf carries raw bytes; the vault must
    record the same 32-char hex id either way or retention can never match."""
    gw["client"].post("/v1/traces", json=_json_payload(), headers=AUTH)
    gw["client"].post(
        "/v1/traces",
        content=_protobuf_payload_bytes(),
        headers={**AUTH, "content-type": "application/x-protobuf"},
    )
    rows = sqlite3.connect(gw["db_path"]).execute(
        "SELECT DISTINCT trace_id, session_id FROM entity_ciphertext"
    ).fetchall()
    assert rows == [("a" * 32, "conv-1")], rows


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("a" * 32, "a" * 32),                       # already hex
        ("A" * 32, "a" * 32),                       # uppercase hex normalised
        ("q" * 21 + "g==", "a" * 32),                # base64 of 0xaa * 16
        ("", None),
        ("not-a-trace-id", None),
    ],
)
def test_hex_trace_id_normalisation(raw, expected):
    from openagent_audit.gateway.otlp import _hex_trace_id

    assert _hex_trace_id(raw) == expected


def test_grpc_framed_body_reaches_same_pipeline(gw):
    body = _grpc_frame(_protobuf_payload_bytes())
    r = gw["client"].post(
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        content=body,
        headers={**AUTH, "content-type": "application/grpc"},
    )
    assert r.status_code == 200, r.text
    span = json.loads(gw["forwarded"][0])["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert PHONE not in json.dumps(span, ensure_ascii=False)


def test_compressed_grpc_frame_is_rejected(gw):
    body = b"\x01" + (4).to_bytes(4, "big") + b"abcd"
    r = gw["client"].post(
        "/v1/traces", content=body, headers={**AUTH, "content-type": "application/grpc"}
    )
    assert r.status_code == 400
    assert "压缩" in r.json()["detail"]
    assert gw["forwarded"] == []


def test_protobuf_without_extra_reports_actionable_error(monkeypatch):
    """Without the otlp extra the gateway must say how to fix it, not 500."""
    import builtins

    real_import = builtins.__import__

    def no_proto(name, *args, **kwargs):
        if name.startswith("opentelemetry.proto") or name == "google.protobuf.json_format":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_proto)
    with pytest.raises(GatewayPayloadError) as exc:
        decode_otlp_body(b"\x0a\x00", content_type="application/x-protobuf")
    assert "openagent-audit[otlp]" in str(exc.value)


# ---------------------------------------------------------------------------
# P0-3: endpoint composition variants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "route",
    [
        "/v1/traces",
        "/v1/traces/v1/traces",  # SDK appended the signal path to a pathed URL
        "/",                     # grpc-configured exporter posts to base URL
    ],
)
def test_all_sdk_route_shapes_reach_ingest(gw, route):
    r = gw["client"].post(route, json=_json_payload(), headers=AUTH)
    assert r.status_code == 200, (route, r.text)
    assert len(gw["forwarded"]) == 1


# ---------------------------------------------------------------------------
# P0-4: authentication shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer gw-secret"},
        {"authorization": "bearer gw-secret"},   # case-insensitive scheme
        {"x-api-key": "gw-secret"},              # OTEL_EXPORTER_OTLP_HEADERS shape
    ],
)
def test_accepted_auth_shapes(gw, headers):
    assert gw["client"].post("/v1/traces", json=_json_payload(), headers=headers).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong"},
        {"x-api-key": "wrong"},
        {"Authorization": "Basic gw-secret"},
    ],
)
def test_rejected_auth_shapes(gw, headers):
    r = gw["client"].post("/v1/traces", json=_json_payload(), headers=headers)
    assert r.status_code == 401
    assert gw["forwarded"] == []
    assert gw["deps"].counters.snapshot()["batches_unauthorized"] == 1


def test_require_auth_closes_gateway_when_token_missing(tmp_path, keypair):
    public_pem, _ = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        public_key_path=str(key_dir / "audit_public_key.pem"),
        gateway_ingest_token="",
        gateway_require_auth=True,
    )
    client, forwarded, _ = _build(settings, tmp_path)
    assert client.post("/v1/traces", json=_json_payload()).status_code == 401
    assert forwarded == []


def test_auth_disabled_only_in_dev_without_token_and_flag(tmp_path, keypair):
    public_pem, _ = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        public_key_path=str(key_dir / "audit_public_key.pem"),
        gateway_ingest_token="",
        gateway_require_auth=False,
    )
    client, forwarded, _ = _build(settings, tmp_path)
    assert client.post("/v1/traces", json=_json_payload()).status_code == 200
    assert len(forwarded) == 1


def test_require_auth_env_flag_parsed(monkeypatch):
    monkeypatch.setenv("AUDIT_GATEWAY_REQUIRE_AUTH", "true")
    assert Settings.from_env().gateway_require_auth is True
    monkeypatch.setenv("AUDIT_GATEWAY_REQUIRE_AUTH", "")
    assert Settings.from_env().gateway_require_auth is False


# ---------------------------------------------------------------------------
# Body handling: bad input must never look like a successful empty batch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", [b"", b"   ", b"not-json", b"Is this JSON?", b"[1,2]"])
def test_malformed_body_is_400_and_not_forwarded(gw, body):
    r = gw["client"].post(
        "/v1/traces", content=body, headers={**AUTH, "content-type": "application/json"}
    )
    assert r.status_code == 400, r.text
    assert gw["forwarded"] == []
    assert gw["deps"].counters.snapshot()["batches_rejected"] >= 1


def test_empty_resource_spans_is_accepted_without_forwarding(gw):
    r = gw["client"].post("/v1/traces", json={"resourceSpans": []}, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["spans"] == 0
    assert gw["forwarded"] == []


# ---------------------------------------------------------------------------
# Forward failure carries an actionable reason into the counters
# ---------------------------------------------------------------------------


def test_forward_failure_records_error_detail(tmp_path, keypair):
    public_pem, _ = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        audit_db_url=f"sqlite:///{(tmp_path / 'audit.db')}",
        public_key_path=str(key_dir / "audit_public_key.pem"),
        gateway_ingest_token="gw",
    )
    from openagent_audit.bootstrap import build_db, build_write_cipher

    def failing_forwarder(payload: bytes) -> None:
        raise RuntimeError("langfuse forward failed after retries: 401 Unauthorized")

    deps = GatewayDeps(
        settings=settings,
        pipeline=MaskingPipeline(
            cipher=build_write_cipher(settings), vault_writer=VaultWriter(build_db(settings))
        ),
        forwarder=failing_forwarder,
    )
    client = TestClient(create_gateway_app(deps))
    r = client.post("/v1/traces", json=_json_payload(), headers={"Authorization": "Bearer gw"})
    assert r.status_code == 502
    snap = deps.counters.snapshot()
    assert snap["forward_failures"] == 1
    assert "401" in snap["last_forward_error"]

    metrics = client.get("/internal/metrics").json()["gateway"]
    assert metrics["last_forward_error"] == snap["last_forward_error"]


def test_encode_otlp_json_roundtrip():
    payload = _json_payload()
    assert json.loads(encode_otlp_json(payload)) == payload
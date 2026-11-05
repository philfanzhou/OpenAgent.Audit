"""Ingest resource limits.

Undocumented finding: the gateway read the whole request body with
``await request.body()`` and processed every span regardless of count. A
single oversized POST could therefore exhaust the process that holds the
masking and key duties for every agent — no authentication protects against
it beyond the shared token holder.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from openagent_audit.config import Settings
from openagent_audit.gateway.app import create_gateway_app
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter


def _deps(tmp_path, keypair, *, max_body=1024, max_spans=10):
    from openagent_audit.bootstrap import build_db, build_write_cipher

    public_pem, _ = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir(exist_ok=True)
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)

    settings = Settings(
        audit_db_url=f"sqlite:///{(tmp_path / 'audit.db')}",
        public_key_path=str(key_dir / "audit_public_key.pem"),
        gateway_ingest_token="tok",
        gateway_max_body_bytes=max_body,
        gateway_max_spans=max_spans,
    )
    db = build_db(settings)
    deps = __import__(
        "openagent_audit.gateway.app", fromlist=["GatewayDeps"]
    ).GatewayDeps(
        settings=settings,
        pipeline=MaskingPipeline(
            cipher=build_write_cipher(settings), vault_writer=VaultWriter(db)
        ),
        forwarder=lambda _payload: None,
    )
    return deps


def _payload(n_spans: int) -> dict:
    spans = [
        {"traceId": "a" * 32, "spanId": f"{i:016x}", "name": "chat", "attributes": []}
        for i in range(n_spans)
    ]
    return {
        "resourceSpans": [{
            "resource": {"attributes": []},
            "scopeSpans": [{"scope": {"name": "svc"}, "spans": spans}],
        }]
    }


AUTH = {"Authorization": "Bearer tok"}


def test_oversized_body_is_rejected_with_413(tmp_path, keypair):
    deps = _deps(tmp_path, keypair, max_body=512)
    client = TestClient(create_gateway_app(deps))

    body = "x" * 5000
    r = client.post("/v1/traces", content=body, headers={**AUTH, "content-type": "application/json"})

    assert r.status_code == 413, r.text
    assert deps.counters.snapshot()["batches_rejected"] == 1


def test_oversized_body_without_content_length_is_still_bounded(tmp_path, keypair):
    """Chunked bodies declare no length; the incremental read must still stop."""
    deps = _deps(tmp_path, keypair, max_body=1024)
    client = TestClient(create_gateway_app(deps))

    def chunks():
        for _ in range(100):
            yield b"y" * 512

    r = client.post("/v1/traces", content=chunks(), headers={**AUTH, "content-type": "application/json"})
    assert r.status_code == 413, r.text


def test_body_within_limit_is_accepted(tmp_path, keypair):
    deps = _deps(tmp_path, keypair, max_body=1_000_000, max_spans=100)
    client = TestClient(create_gateway_app(deps))

    r = client.post("/v1/traces", json=_payload(3), headers=AUTH)
    assert r.status_code == 200, r.text


def test_too_many_spans_is_rejected(tmp_path, keypair):
    deps = _deps(tmp_path, keypair, max_body=10_000_000, max_spans=5)
    client = TestClient(create_gateway_app(deps))

    r = client.post("/v1/traces", json=_payload(6), headers=AUTH)

    assert r.status_code == 413, r.text
    assert "span" in r.json()["detail"]
    assert deps.counters.snapshot()["batches_rejected"] == 1


def test_span_count_at_the_limit_is_accepted(tmp_path, keypair):
    deps = _deps(tmp_path, keypair, max_body=10_000_000, max_spans=5)
    client = TestClient(create_gateway_app(deps))

    assert client.post("/v1/traces", json=_payload(5), headers=AUTH).status_code == 200


def test_empty_export_is_not_treated_as_rejected(tmp_path, keypair):
    deps = _deps(tmp_path, keypair)
    client = TestClient(create_gateway_app(deps))

    r = client.post("/v1/traces", json={"resourceSpans": []}, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["spans"] == 0
    assert deps.counters.snapshot()["batches_rejected"] == 0


def test_limits_default_to_sane_values():
    settings = Settings.from_env({})
    assert settings.gateway_max_body_bytes == 16 * 1024 * 1024
    assert settings.gateway_max_spans == 5000
"""Masking Gateway: OTLP ingest -> mask/seal -> forward, fail-closed semantics."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from openagent_audit.config import Settings, UserEntry
from openagent_audit.gateway.app import GatewayCounters, GatewayDeps, create_gateway_app
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
from openagent_audit.services.audit_api import build_container

PASSPHRASE = b"unit-test-passphrase"


def _otlp_payload() -> dict:
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": []},
                "scopeSpans": [
                    {
                        "scope": {"name": "openagent-engine"},
                        "spans": [
                            {
                                "traceId": "a" * 32,
                                "spanId": "1" * 16,
                                "name": "llm.call",
                                "attributes": [
                                    {"key": "openagent.conversation_id",
                                     "value": {"stringValue": "conv-1001"}},
                                    {"key": "openagent.user_id",
                                     "value": {"stringValue": "usr_20077120"}},
                                    {"key": "agent.id",
                                     "value": {"stringValue": "cs-bot"}},
                                    {"key": "gen_ai.prompt.0.content",
                                     "value": {"stringValue": "帮我联系张伟，电话 13812345678"}},
                                    {"key": "gen_ai.completion.1.content",
                                     "value": {"stringValue": "已联系 zhangwei@example.com"}},
                                    {"key": "http.method", "value": {"stringValue": "POST"}},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


@pytest.fixture()
def gateway(tmp_path, keypair, monkeypatch):
    public_pem, private_pem = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "audit_private_key.pem").write_bytes(private_pem)
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        audit_db_url=f"sqlite:///{(tmp_path / 'audit.db')}",
        service_token="svc",
        users=(UserEntry("tok-a", "alice", "auditor"),),
        public_key_path=str(key_dir / "audit_public_key.pem"),
        object_store="local",
        object_store_root=str(tmp_path / "objects"),
        gateway_ingest_token="gw-secret",
        local_private_key_passphrase=PASSPHRASE.decode(),
    )

    db_path = tmp_path / "audit.db"
    forwarded: list[dict] = []

    def forwarder(payload: bytes) -> None:
        forwarded.append(json.loads(payload))

    deps = build_test_deps(settings, forwarder)
    return {
        "settings": settings,
        "client": TestClient(create_gateway_app(deps)),
        "db_path": db_path,
        "forwarded": forwarded,
        "deps": deps,
    }


def build_test_deps(settings: Settings, forwarder) -> GatewayDeps:
    from openagent_audit.bootstrap import build_db, build_write_cipher

    db = build_db(settings)
    pipeline = MaskingPipeline(
        cipher=build_write_cipher(settings), vault_writer=VaultWriter(db)
    )
    return GatewayDeps(settings=settings, pipeline=pipeline, forwarder=forwarder)


def test_ingest_requires_bearer_token(gateway):
    r = gateway["client"].post("/v1/traces", json=_otlp_payload())
    assert r.status_code == 401
    r = gateway["client"].post("/v1/traces", json=_otlp_payload(),
                               headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_mask_seal_forward(gateway):
    r = gateway["client"].post("/v1/traces", json=_otlp_payload(),
                               headers={"Authorization": "Bearer gw-secret"})
    assert r.status_code == 200

    # forwarded payload is fully masked and identifier-tagged
    assert len(gateway["forwarded"]) == 1
    spans = (gateway["forwarded"][0]["resourceSpans"][0]["scopeSpans"][0]["spans"])
    span = spans[0]
    serialized = json.dumps(span, ensure_ascii=False)
    assert "13812345678" not in serialized
    assert "zhangwei@example.com" not in serialized
    assert "138****5678" in serialized
    keys = {a["key"]: a.get("value", {}).get("stringValue") for a in span["attributes"]}
    assert keys["langfuse.session.id"] == "conv-1001"
    assert keys["langfuse.user.id"] == "usr_20077120"
    assert keys["langfuse.tag.agent"] == "cs-bot"
    # non-content attribute untouched
    assert keys["http.method"] == "POST"

    # ciphertext sealed into the audit-domain vault with trace ownership
    import sqlite3

    conn = sqlite3.connect(gateway["db_path"])
    try:
        rows = conn.execute(
            "SELECT entity_id, trace_id, session_id FROM entity_ciphertext"
        ).fetchall()
    finally:
        conn.close()
    assert rows and all(row[1] == "a" * 32 and row[2] == "conv-1001" for row in rows)

    snap = gateway["deps"].counters.snapshot()
    assert snap["forwarded_batches"] == 1 and snap["spans_masked"] == 1


def test_fail_closed_on_vault_failure(tmp_path, keypair):
    """Masking/vault failure -> batch dropped, nothing forwarded, 500."""
    class FailingVault:
        def insert_entities(self, rows):
            raise RuntimeError("db down")

    public_pem, _ = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir(exist_ok=True)
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        public_key_path=str(key_dir / "audit_public_key.pem"),
        gateway_ingest_token="gw",
    )
    forwarded: list[dict] = []
    from openagent_audit.bootstrap import build_write_cipher

    deps = GatewayDeps(
        settings=settings,
        pipeline=MaskingPipeline(
            cipher=build_write_cipher(settings),
            vault_writer=VaultWriter(FailingVault(), attempts=1),
        ),
        forwarder=lambda payload: forwarded.append(payload),
    )
    client = TestClient(create_gateway_app(deps))
    r = client.post("/v1/traces", json=_otlp_payload(),
                    headers={"Authorization": "Bearer gw"})
    assert r.status_code == 500
    assert forwarded == []
    assert deps.counters.snapshot()["batches_dropped"] == 1
    assert deps.drop_monitor.has_drops()


def test_forward_failure_counted_not_leaked(tmp_path, keypair):
    """Forward failure after successful masking -> 502, masked data dropped,
    counter incremented (observability loss, never a plaintext leak)."""
    public_pem, _ = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir(exist_ok=True)
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        audit_db_url=f"sqlite:///{(tmp_path / 'audit.db')}",
        public_key_path=str(key_dir / "audit_public_key.pem"),
        gateway_ingest_token="gw",
        local_private_key_passphrase=PASSPHRASE.decode(),
    )

    def failing_forwarder(payload: bytes) -> None:
        raise RuntimeError("langfuse down")

    deps = build_test_deps(settings, failing_forwarder)
    client = TestClient(create_gateway_app(deps))
    r = client.post("/v1/traces", json=_otlp_payload(),
                    headers={"Authorization": "Bearer gw"})
    assert r.status_code == 502
    snap = deps.counters.snapshot()
    assert snap["forward_failures"] == 1 and snap["forwarded_batches"] == 0
    # the vault still holds the sealed entities (restorable), nothing forwarded
    assert snap["batches_dropped"] == 0


def test_metrics_endpoint(gateway):
    gateway["client"].post("/v1/traces", json=_otlp_payload(),
                           headers={"Authorization": "Bearer gw-secret"})
    m = gateway["client"].get("/internal/metrics").json()
    assert m["gateway"]["batches_received"] == 1
    assert m["gateway"]["forwarded_batches"] == 1

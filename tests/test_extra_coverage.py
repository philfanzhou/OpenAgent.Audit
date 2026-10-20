"""Additional coverage: decrypt-svc media path, decrypt_app entry point,
LangfuseTraceSink, audit-api web reveal for media."""

from __future__ import annotations

import base64
import os
import pathlib

import pytest
from fastapi.testclient import TestClient

from openagent_audit.media.objectstore import LocalObjectStore
from openagent_audit.media.service import MediaService
from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.services.decrypt_app import _build_app
from openagent_audit.services.decrypt_svc import DecryptServiceDeps, create_decrypt_app
from openagent_audit.vault.models import RestoreRequest, RestoreStatus


def _media_world(cipher, tmp_path):
    db = __import__("openagent_audit.vault.store", fromlist=["SQLiteAuditDatabase"]).SQLiteAuditDatabase(":memory:")
    store = LocalObjectStore(tmp_path / "objects")
    audit = AuditLogService(db)
    media = MediaService(cipher, store)
    deps = DecryptServiceDeps(cipher=cipher, db=db, audit=audit, service_token="st", object_store=store)
    return db, media, TestClient(create_decrypt_app(deps))


def test_decrypt_media_endpoint(cipher, tmp_path):
    db, media, client = _media_world(cipher, tmp_path)
    payload = b"\x89PNG-media-endpoint-bytes"
    ref = media.encrypt_and_upload(payload, "image/png")
    req = RestoreRequest(id="req-media001", object_type="media", object_id=ref.key,
                         reason="核查", requested_by="bob", status=RestoreStatus.APPROVED,
                         approver="carol")
    db.insert_restore_request(req)
    r = client.post(
        "/v1/decrypt-media",
        headers={"Authorization": "Bearer st"},
        json={"key": ref.key, "request_id": req.id, "requested_by": "bob"},
    )
    assert r.status_code == 200
    assert r.content == payload
    assert "DECRYPT_PERFORMED" in [e.action for e in db.iter_audit()]


def test_decrypt_media_tamper_rejected(cipher, tmp_path):
    db, media, client = _media_world(cipher, tmp_path)
    ref = media.encrypt_and_upload(b"photo", "image/png")
    # tamper with the stored ciphertext
    (tmp_path / "objects" / ref.key).write_bytes(b"corrupted")
    req = RestoreRequest(id="req-media002", object_type="media", object_id=ref.key,
                         reason="核查", requested_by="bob", status=RestoreStatus.APPROVED,
                         approver="carol")
    db.insert_restore_request(req)
    r = client.post(
        "/v1/decrypt-media",
        headers={"Authorization": "Bearer st"},
        json={"key": ref.key, "request_id": req.id, "requested_by": "bob"},
    )
    assert r.status_code == 422


def test_decrypt_app_builds_from_env(cipher, tmp_path, monkeypatch):
    public_pem, private_pem = None, None
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    from openagent_audit.crypto.keys import generate_keypair

    pub, priv = generate_keypair()
    (key_dir / "audit_private_key.pem").write_bytes(priv)
    (key_dir / "audit_public_key.pem").write_bytes(pub)
    monkeypatch.setenv("AUDIT_DB_URL", f"sqlite:///{(tmp_path / 'audit.db')}")
    monkeypatch.setenv("AUDIT_SERVICE_TOKEN", "env-token")
    monkeypatch.setenv("AUDIT_KEY_PROVIDER", "local")
    monkeypatch.setenv("AUDIT_PRIVATE_KEY_PATH", str(key_dir / "audit_private_key.pem"))
    monkeypatch.setenv("AUDIT_PRIVATE_KEY_PASSPHRASE", "")
    monkeypatch.setenv("AUDIT_PUBLIC_KEY_PATH", str(key_dir / "audit_public_key.pem"))
    monkeypatch.setenv("AUDIT_OBJECT_STORE", "none")
    app = _build_app()
    client = TestClient(app)
    assert client.get("/healthz").json()["service"] == "decrypt-svc"


def test_langfuse_trace_sink(tmp_path, cipher):
    """LangfuseTraceSink drives the SDK's observation tree with identifiers."""
    from openagent_audit.agent.instrument import AgentInstrument, LangfuseTraceSink

    class FakeObservation:
        def __init__(self, name=None, **kwargs) -> None:
            self.name = name
            self.kwargs = kwargs
            self.attrs: dict = {}
            self.updates: dict = {}
            self.children: list[FakeObservation] = []
            self.ended = False

        def set_attribute(self, key, value) -> None:
            self.attrs[key] = value

        def start_observation(self, **kwargs) -> "FakeObservation":
            child = FakeObservation(**kwargs)
            self.children.append(child)
            return child

        def update(self, **kwargs) -> None:
            self.updates.update(kwargs)

        def end(self) -> None:
            self.ended = True

    root = FakeObservation("root")
    client = type("FakeClient", (), {"start_observation": staticmethod(lambda name, trace_id: root)})()
    instrument = AgentInstrument(LangfuseTraceSink(client), media=None)
    instrument.report_request(
        trace_id="tr-lf-1", conversation_id="conv-9", internal_user_id="usr-9",
        agent_id="cs-bot", name="run",
        messages=[{"role": "user", "content": "hi"}],
        llm_calls=[{"name": "g", "model": "m", "input": "i", "output": "o", "usage": {"input": 1},
                    "latency_ms": 5}],
    )
    assert root.attrs["langfuse.session.id"] == "conv-9"
    assert root.attrs["langfuse.user.id"] == "usr-9"
    assert root.ended is True
    assert any(c.name == "g" for c in root.children)

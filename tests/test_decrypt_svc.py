"""decrypt-svc: service contract, independent approval check, audit trail."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.services.decrypt_client import HttpDecryptService
from openagent_audit.services.decrypt_svc import DecryptServiceDeps, create_decrypt_app
from openagent_audit.vault.models import RestoreRequest, RestoreStatus
from openagent_audit.vault.store import SQLiteAuditDatabase


@pytest.fixture()
def svc_db() -> SQLiteAuditDatabase:
    return SQLiteAuditDatabase(":memory:")


@pytest.fixture()
def svc_deps(svc_db, cipher, audit):
    svc_db.insert_entities([
        {"entity_id": "a" * 16, "entity_type": "PHONE_NUMBER",
         "ciphertext": cipher.seal("13812345678", aad=("a" * 16).encode()),
         "trace_id": "t1", "session_id": "s1"},
    ])
    return DecryptServiceDeps(
        cipher=cipher, db=svc_db, audit=AuditLogService(svc_db),
        service_token="svc-secret", object_store=None,
    )


@pytest.fixture()
def svc_client(svc_deps):
    return TestClient(create_decrypt_app(svc_deps))


def _approved_request(db, entity_id):
    req = RestoreRequest(
        id="req-12345678", object_type="entity", object_id=entity_id,
        reason="调查", requested_by="bob", status=RestoreStatus.APPROVED,
        approver="carol",
    )
    db.insert_restore_request(req)
    return req.id


def test_service_token_required(svc_client):
    r = svc_client.post("/v1/decrypt", json={"entity_id": "a" * 16, "request_id": "req-12345678",
                                             "requested_by": "bob"})
    assert r.status_code == 401


def test_decrypt_returns_plaintext(svc_client, svc_db):
    request_id = _approved_request(svc_db, "a" * 16)
    r = svc_client.post(
        "/v1/decrypt",
        headers={"Authorization": "Bearer svc-secret"},
        json={"entity_id": "a" * 16, "request_id": request_id, "requested_by": "bob"},
    )
    assert r.status_code == 200
    assert base64.b64decode(r.json()["plaintext_b64"]) == b"13812345678"


def test_unapproved_request_rejected(svc_client, svc_db):
    req = RestoreRequest(id="req-pending1", object_type="entity", object_id="a" * 16,
                         reason="调查", requested_by="bob", status=RestoreStatus.PENDING)
    svc_db.insert_restore_request(req)
    r = svc_client.post(
        "/v1/decrypt",
        headers={"Authorization": "Bearer svc-secret"},
        json={"entity_id": "a" * 16, "request_id": req.id, "requested_by": "bob"},
    )
    assert r.status_code == 409


def test_unknown_request_404(svc_client):
    r = svc_client.post(
        "/v1/decrypt",
        headers={"Authorization": "Bearer svc-secret"},
        json={"entity_id": "a" * 16, "request_id": "req-missing00", "requested_by": "bob"},
    )
    assert r.status_code == 404


def test_unknown_entity_404(svc_client, svc_db):
    request_id = _approved_request(svc_db, "a" * 16)
    r = svc_client.post(
        "/v1/decrypt",
        headers={"Authorization": "Bearer svc-secret"},
        json={"entity_id": "b" * 16, "request_id": request_id, "requested_by": "bob"},
    )
    assert r.status_code == 404


def test_every_decrypt_audited(svc_client, svc_db):
    request_id = _approved_request(svc_db, "a" * 16)
    svc_client.post(
        "/v1/decrypt",
        headers={"Authorization": "Bearer svc-secret"},
        json={"entity_id": "a" * 16, "request_id": request_id, "requested_by": "bob"},
    )
    entries = [e.action for e in svc_db.iter_audit()]
    assert "DECRYPT_PERFORMED" in entries
    (entry,) = [e for e in svc_db.iter_audit() if e.action == "DECRYPT_PERFORMED"]
    assert entry.detail["request_id"] == request_id
    assert "plaintext" not in str(entry.detail)


def test_http_client_adapter():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["auth"] = request.headers.get("Authorization")
        captured["body"] = json.loads(request.content)
        if captured["body"]["entity_id"] == "a" * 16:
            return httpx.Response(200, json={"plaintext_b64": base64.b64encode(b"13812345678").decode()})
        return httpx.Response(404, json={"detail": "entity not found"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://decrypt.test")
    svc = HttpDecryptService("http://decrypt.test", "svc-secret", client=client)
    plaintext = svc.decrypt_entity("a" * 16, request_id="req-12345678", requested_by="bob")
    assert plaintext == b"13812345678"
    assert captured["path"] == "/v1/decrypt"
    assert captured["auth"] == "Bearer svc-secret"
    assert captured["body"]["request_id"] == "req-12345678"

    with pytest.raises(httpx.HTTPStatusError):
        svc.decrypt_entity("f" * 16, request_id="req-12345678", requested_by="bob")

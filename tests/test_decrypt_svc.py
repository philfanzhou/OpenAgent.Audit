"""decrypt-svc: the only process holding the private key.

The console's model is a single administrator action, so the service no longer
gates on an approved "restore request". What it still enforces:

* the shared service token (constant-time compare);
* one object per call — no bulk decryption;
* a named actor on every call, and an audit record written by the service
  itself, independent of what the console logged.
"""

from __future__ import annotations

import base64

import httpx
import pytest
from fastapi.testclient import TestClient

from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.services.decrypt_client import HttpDecryptService
from openagent_audit.services.decrypt_svc import DecryptServiceDeps, create_decrypt_app
from openagent_audit.vault.store import SQLiteAuditDatabase

SERVICE_TOKEN = "svc-token"


@pytest.fixture()
def svc(tmp_path, cipher, db):
    deps = DecryptServiceDeps(
        cipher=cipher,
        db=db,
        service_token=SERVICE_TOKEN,
        object_store=None,
        audit=AuditLogService(db),
    )
    client = TestClient(create_decrypt_app(deps))
    # seal one entity so there is something to decrypt
    from openagent_audit.pii.masking import MaskingPipeline, VaultWriter

    pipeline = MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(db))
    result = pipeline.protect("电话13812345678", trace_id="t1", session_id="s1")
    entity_id = result.entities[0].entity_id
    return client, entity_id, db


def _headers(token: str = SERVICE_TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _body(entity_id: str, actor: str = "admin") -> dict:
    return {"entity_id": entity_id, "actor": actor, "session_user": "alice"}


def test_service_token_required(svc):
    client, entity_id, _ = svc

    assert client.post("/v1/decrypt", json=_body(entity_id)).status_code == 401
    assert client.post(
        "/v1/decrypt", json=_body(entity_id), headers=_headers("wrong")
    ).status_code == 401


def test_decrypt_returns_plaintext(svc):
    client, entity_id, _ = svc

    resp = client.post("/v1/decrypt", json=_body(entity_id), headers=_headers())

    assert resp.status_code == 200, resp.text
    assert base64.b64decode(resp.json()["plaintext_b64"]).decode() == "13812345678"


def test_unknown_entity_404(svc):
    client, _, _ = svc

    resp = client.post("/v1/decrypt", json=_body("deadbeefdeadbeef"), headers=_headers())

    assert resp.status_code == 404


def test_actor_is_required(svc):
    """Every decryption must name a person; an anonymous call is refused."""
    client, entity_id, _ = svc

    resp = client.post(
        "/v1/decrypt", json={"entity_id": entity_id}, headers=_headers()
    )

    assert resp.status_code == 422


def test_every_decrypt_is_audited_with_actor(svc):
    client, entity_id, db = svc

    client.post("/v1/decrypt", json=_body(entity_id, actor="admin"), headers=_headers())

    entries = [e for e in db.iter_audit() if e.action == "DECRYPT_PERFORMED"]
    assert entries
    assert entries[-1].actor == "admin"
    assert entries[-1].object_id == entity_id
    assert entries[-1].detail["session_user"] == "alice"


def test_failed_decrypt_is_audited(svc):
    client, _, db = svc

    client.post("/v1/decrypt", json=_body("nope-nope"), headers=_headers())

    actions = [e.action for e in db.iter_audit()]
    assert "DECRYPT_FAILED" in actions


def test_plaintext_never_enters_the_audit_log(svc):
    client, entity_id, db = svc

    client.post("/v1/decrypt", json=_body(entity_id), headers=_headers())

    import json as jsonlib

    blob = jsonlib.dumps([e.detail for e in db.iter_audit()], ensure_ascii=False)
    assert "13812345678" not in blob


def test_tampered_ciphertext_is_rejected(svc):
    client, entity_id, db = svc

    import sqlite3

    conn = sqlite3.connect(db._path)
    conn.execute(
        "UPDATE entity_ciphertext SET ciphertext = 'bm90LWEtcmVhbC1lbnZlbG9wZQ==' "
        "WHERE entity_id = ?",
        (entity_id,),
    )
    conn.commit()
    conn.close()

    resp = client.post("/v1/decrypt", json=_body(entity_id), headers=_headers())

    assert resp.status_code == 422


def test_media_endpoint_requires_object_store(svc):
    client, _, _ = svc

    resp = client.post(
        "/v1/decrypt-media",
        json={"object_key": "k", "actor": "admin", "session_user": "alice"},
        headers=_headers(),
    )

    assert resp.status_code == 501


def test_http_client_adapter(cipher, db):
    """The client used by audit-api speaks the new contract."""
    from openagent_audit.pii.masking import MaskingPipeline, VaultWriter

    pipeline = MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(db))
    entity_id = pipeline.protect("电话13812345678", trace_id="t", session_id="s").entities[0].entity_id

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as jsonlib

        seen.update(jsonlib.loads(request.content))
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(
            200, json={"plaintext_b64": base64.b64encode(b"13812345678").decode()}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://svc")
    service = HttpDecryptService("http://svc", SERVICE_TOKEN, client=client)

    plaintext = service.decrypt_entity(entity_id, actor="admin", session_user="alice")

    assert plaintext == b"13812345678"
    assert seen["entity_id"] == entity_id
    assert seen["actor"] == "admin"
    assert seen["session_user"] == "alice"
    assert seen["auth"] == f"Bearer {SERVICE_TOKEN}"
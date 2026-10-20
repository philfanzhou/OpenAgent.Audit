"""Restore workflow: RBAC, four-eyes approval, reveal TTL, audit trail."""

from __future__ import annotations

import pytest

from openagent_audit.services.decrypt_client import InProcessDecryptService
from openagent_audit.services.restore_service import RestoreError, RestoreService
from openagent_audit.vault.models import OBJECT_ENTITY, OBJECT_MEDIA

pytestmark = pytest.mark.usefixtures("db")


@pytest.fixture()
def seeded_entity(db, cipher):
    db.insert_entities([
        {"entity_id": "e" * 16, "entity_type": "PHONE_NUMBER",
         "ciphertext": cipher.seal("13812345678", aad=("e" * 16).encode()),
         "trace_id": "t1", "session_id": "s1"},
    ])
    return "e" * 16


@pytest.fixture()
def svc(db, audit, cipher, object_store, seeded_entity) -> RestoreService:
    decrypt = InProcessDecryptService(
        cipher=cipher, key_provider=None, vault=db, object_store=object_store, audit=audit
    )
    return RestoreService(db, audit, decrypt, reveal_ttl_minutes=10)


@pytest.fixture()
def object_store(tmp_path):
    from openagent_audit.media.objectstore import LocalObjectStore

    return LocalObjectStore(tmp_path / "objects")


def test_auditor_cannot_request(svc, seeded_entity):
    with pytest.raises(RestoreError, match="compliance") as exc:
        svc.request(actor="alice", role="auditor", object_type=OBJECT_ENTITY,
                    object_id=seeded_entity, reason="抽查")
    assert exc.value.status_code == 403


def test_unknown_entity_rejected(svc):
    with pytest.raises(RestoreError, match="not in vault") as exc:
        svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                    object_id="f" * 16, reason="争议")
    assert exc.value.status_code == 404


def test_reason_required(svc, seeded_entity):
    with pytest.raises(RestoreError, match="reason"):
        svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                    object_id=seeded_entity, reason="  ")


def test_full_happy_path(svc, db, audit, seeded_entity):
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="争议处理", trace_id="t1", session_id="s1")
    assert req.status.value == "pending"

    with pytest.raises(RestoreError) as exc:
        svc.decide(req.id, approver="bob", role="compliance_lead", approve=True)
    assert exc.value.code == "four_eyes"

    with pytest.raises(RestoreError) as exc:
        svc.decide(req.id, approver="dan", role="developer", approve=True)
    assert exc.value.status_code == 403

    approved = svc.decide(req.id, approver="carol", role="compliance_lead", approve=True)
    assert approved.status.value == "approved"

    result = svc.reveal(req.id, actor="carol", role="compliance_lead")
    assert result["plaintext"] == "13812345678"
    assert db.get_restore_request(req.id).status.value == "fulfilled"
    assert db.get_restore_request(req.id).reveal_expires_at is not None

    # every step landed in the audit log
    actions = [e.action for e in audit.list_entries(limit=100)]
    for expected in ("RESTORE_REQUESTED", "RESTORE_APPROVED", "RESTORE_DECRYPTED", "RESTORE_VIEWED"):
        assert expected in actions


def test_second_reveal_inside_ttl_ok_and_logged(svc, audit, seeded_entity):
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="调查")
    svc.decide(req.id, approver="carol", role="compliance_lead", approve=True)
    svc.reveal(req.id, actor="bob", role="compliance_lead")
    again = svc.reveal(req.id, actor="bob", role="compliance_lead")
    assert again["plaintext"] == "13812345678"
    assert [e.action for e in audit.list_entries(100)].count("RESTORE_VIEWED") == 2


def test_reveal_requires_compliance_role(svc, seeded_entity):
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="调查")
    svc.decide(req.id, approver="carol", role="compliance_lead", approve=True)
    with pytest.raises(RestoreError) as exc:
        svc.reveal(req.id, actor="alice", role="auditor")
    assert exc.value.status_code == 403


def test_reveal_not_approved(svc, seeded_entity):
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="调查")
    with pytest.raises(RestoreError) as exc:
        svc.reveal(req.id, actor="carol", role="compliance_lead")
    assert exc.value.code == "not_approved"


def test_reveal_expired(svc, db, audit, cipher, clock, seeded_entity):
    decrypt = InProcessDecryptService(cipher=cipher, key_provider=None, vault=db, audit=audit)
    svc = RestoreService(db, audit, decrypt, reveal_ttl_minutes=10, clock=clock)
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="调查")
    svc.decide(req.id, approver="carol", role="compliance_lead", approve=True)
    svc.reveal(req.id, actor="bob", role="compliance_lead")
    clock.advance(minutes=11)
    with pytest.raises(RestoreError) as exc:
        svc.reveal(req.id, actor="bob", role="compliance_lead")
    assert exc.value.code == "reveal_expired"
    assert exc.value.status_code == 410


def test_reject_flow(svc, seeded_entity):
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="调查")
    rejected = svc.decide(req.id, approver="carol", role="compliance_lead",
                          approve=False, comment="证据不足")
    assert rejected.status.value == "rejected"
    with pytest.raises(RestoreError) as exc:
        svc.reveal(req.id, actor="bob", role="compliance_lead")
    assert exc.value.code == "not_approved"


def test_double_decision_conflict(svc, seeded_entity):
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="调查")
    svc.decide(req.id, approver="carol", role="compliance_lead", approve=True)
    with pytest.raises(RestoreError) as exc:
        svc.decide(req.id, approver="dave", role="compliance_lead", approve=True)
    assert exc.value.code == "not_pending"


def test_tampered_ciphertext_fails_safely(svc, db, audit, seeded_entity):
    # corrupt the stored ciphertext (simulated DB write by a privileged actor)
    import sqlite3

    row = db.get_entity(seeded_entity)
    conn = sqlite3.connect(db._path)
    conn.execute("UPDATE entity_ciphertext SET ciphertext=? WHERE entity_id=?",
                 (row.ciphertext[:-4] + "AAAA", seeded_entity))
    conn.commit()

    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_ENTITY,
                      object_id=seeded_entity, reason="调查")
    svc.decide(req.id, approver="carol", role="compliance_lead", approve=True)
    with pytest.raises(RestoreError) as exc:
        svc.reveal(req.id, actor="bob", role="compliance_lead")
    assert exc.value.code == "decrypt_failed"
    assert "DECRYPT_FAILED" in [e.action for e in audit.list_entries(100)]


def test_media_restore_flow(svc, media_fixture, audit):
    key, original = media_fixture
    req = svc.request(actor="bob", role="compliance_lead", object_type=OBJECT_MEDIA,
                      object_id=key, reason="核查截图")
    svc.decide(req.id, approver="carol", role="compliance_lead", approve=True)
    result = svc.reveal(req.id, actor="bob", role="compliance_lead")
    import base64

    assert base64.b64decode(result["content_b64"]) == original
    assert "MEDIA_DECRYPTED" in [e.action for e in audit.list_entries(100)]


@pytest.fixture()
def media_fixture(object_store, cipher):
    from openagent_audit.media.service import MediaService

    service = MediaService(cipher, object_store, bucket="agent-media")
    payload = b"\x89PNG-fake-photo-bytes-1234567890"
    ref = service.encrypt_and_upload(payload, "image/png")
    return ref.key, payload

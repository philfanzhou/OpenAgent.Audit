"""Hash chain + audit log + vault repository semantics."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from openagent_audit.vault.hashchain import GENESIS_HASH, canonical_entry, entry_hash, verify_chain
from openagent_audit.vault.models import EntityCiphertextRow, RestoreRequest, RestoreStatus
from openagent_audit.vault.store import SQLiteAuditDatabase

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def rows_for_chain(entries):
    return [
        {
            "seq": e.seq, "ts": e.ts, "actor": e.actor, "role": e.role,
            "action": e.action, "object_type": e.object_type,
            "object_id": e.object_id, "detail": e.detail,
            "prev_hash": e.prev_hash, "entry_hash": e.entry_hash,
        }
        for e in entries
    ]


def test_genesis_prev_hash():
    db = SQLiteAuditDatabase(":memory:")
    entry = db.append_audit(ts=NOW, actor="sys", role="service", action="BOOT")
    assert entry.prev_hash == GENESIS_HASH


def test_chain_links_forward(db):
    e1 = db.append_audit(ts=NOW, actor="a", role="auditor", action="VIEW")
    e2 = db.append_audit(ts=NOW, actor="b", role="auditor", action="VIEW")
    e3 = db.append_audit(ts=NOW, actor="c", role="auditor", action="DECRYPT")
    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash
    ok, bad = verify_chain(rows_for_chain(db.iter_audit()))
    assert ok and bad is None


def test_tamper_detected_at_right_seq(db):
    db.append_audit(ts=NOW, actor="a", role="auditor", action="VIEW")
    db.append_audit(ts=NOW, actor="b", role="auditor", action="VIEW")
    db.append_audit(ts=NOW, actor="c", role="auditor", action="DECRYPT")
    # simulate in-place edit (the DB account has no UPDATE grant in prod)
    import sqlite3

    conn = sqlite3.connect(db._path)
    conn.execute("UPDATE audit_log SET actor='mallory' WHERE seq=2")
    conn.commit()
    ok, bad = verify_chain(rows_for_chain(db.iter_audit()))
    assert not ok and bad == 2


def test_deletion_detected(db):
    for i in range(3):
        db.append_audit(ts=NOW, actor=f"u{i}", role="auditor", action="VIEW")
    import sqlite3

    conn = sqlite3.connect(db._path)
    conn.execute("DELETE FROM audit_log WHERE seq=2")
    conn.commit()
    ok, _ = verify_chain(rows_for_chain(db.iter_audit()))
    assert not ok


def test_canonical_entry_is_stable_and_sorted():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    a = canonical_entry(ts=ts, actor="u", role="auditor", action="VIEW",
                        object_type="entity", object_id="e1", detail={"k": 1})
    b = canonical_entry(ts=ts, actor="u", role="auditor", action="VIEW",
                        object_type="entity", object_id="e1", detail={"k": 1})
    assert a == b
    assert a.index('"action"') < a.index('"ts"')  # sort_keys ordering


def test_entry_hash_differs_by_prev():
    canonical = canonical_entry(ts=NOW, actor="u", role="auditor", action="VIEW",
                                object_type=None, object_id=None, detail={})
    h1 = entry_hash("0" * 64, canonical)
    h2 = entry_hash("1" * 64, canonical)
    assert h1 != h2


# -- vault --------------------------------------------------------------------


def test_insert_and_get_entities(db):
    rows = [
        {"entity_id": "e" * 16, "entity_type": "PHONE_NUMBER", "ciphertext": "CT1",
         "trace_id": "t1", "session_id": "s1"},
        {"entity_id": "f" * 16, "entity_type": "ID_CARD", "ciphertext": "CT2",
         "trace_id": "t1", "session_id": "s1"},
    ]
    db.insert_entities(rows)
    row = db.get_entity("e" * 16)
    assert row is not None and row.ciphertext == "CT1" and row.entity_type == "PHONE_NUMBER"
    assert db.get_entity("missing") is None


def test_delete_for_traces(db):
    db.insert_entities([
        {"entity_id": "a" * 16, "entity_type": "PHONE_NUMBER", "ciphertext": "C",
         "trace_id": "t-old", "session_id": "s"},
        {"entity_id": "b" * 16, "entity_type": "PHONE_NUMBER", "ciphertext": "C",
         "trace_id": "t-new", "session_id": "s"},
    ])
    deleted = db.delete_for_traces(["t-old"])
    assert deleted == 1
    assert db.get_entity("a" * 16) is None
    assert db.get_entity("b" * 16) is not None
    assert db.delete_for_traces([]) == 0


def test_delete_older_than(db):
    old = NOW - timedelta(days=100)
    recent = NOW - timedelta(days=1)
    db.insert_entities([])  # no-op sanity
    with db._lock, db._connect() as conn:
        conn.execute(
            "INSERT INTO entity_ciphertext VALUES (?, 'T', 'C', 't', 's', ?)",
            ("1" * 16, old.isoformat()),
        )
        conn.execute(
            "INSERT INTO entity_ciphertext VALUES (?, 'T', 'C', 't', 's', ?)",
            ("2" * 16, recent.isoformat()),
        )
    assert db.delete_older_than(NOW - timedelta(days=90)) == 1
    assert db.get_entity("1" * 16) is None
    assert db.get_entity("2" * 16) is not None


# -- restore requests -------------------------------------------------------------


def test_restore_request_lifecycle_rows(db):
    req = RestoreRequest(
        id="r1", object_type="entity", object_id="e" * 16, reason="争议处理",
        requested_by="bob", status=RestoreStatus.PENDING, created_at=NOW,
    )
    db.insert_restore_request(req)
    got = db.get_restore_request("r1")
    assert got is not None and got.status is RestoreStatus.PENDING
    updated = db.update_restore_request("r1", status=RestoreStatus.APPROVED, approver="carol", decided_at=NOW)
    assert updated.status is RestoreStatus.APPROVED and updated.approver == "carol"
    assert db.get_restore_request("missing") is None
    assert len(db.list_restore_requests(RestoreStatus.APPROVED)) == 1


# -- concurrency ---------------------------------------------------------------------


def test_concurrent_audit_appends_keep_chain_intact(db):
    def worker(i):
        for j in range(5):
            db.append_audit(ts=NOW, actor=f"u{i}-{j}", role="auditor", action="VIEW")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    entries = db.iter_audit()
    assert len(entries) == 20
    ok, bad = verify_chain(rows_for_chain(entries))
    assert ok and bad is None
    assert [e.seq for e in entries] == list(range(1, 21))

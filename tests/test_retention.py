"""Retention job: purge expired traces + vault rows, archive audit entries."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from openagent_audit.media.objectstore import LocalObjectStore
from openagent_audit.services.retention import RetentionJob
from openagent_audit.tracing.trace_store import LocalTraceStore
from openagent_audit.vault.store import FrozenClock

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def seed(db, trace_store, pipeline, *, trace_id, age_days):
    from openagent_audit.tracing.trace_store import ObservationRecord, TraceRecord

    ts = NOW - timedelta(days=age_days)
    result = pipeline.protect(f"电话1381234567{age_days:02d}", trace_id=trace_id, session_id="s")
    # overwrite vault timestamps to simulate age
    for e in result.entities:
        import sqlite3

        conn = sqlite3.connect(db._path)
        conn.execute("UPDATE entity_ciphertext SET created_at=? WHERE entity_id=?",
                     (ts.isoformat(), e.entity_id))
        conn.commit()
    trace_store.upsert_trace(TraceRecord(
        trace_id=trace_id, session_id="s", user_id="u", agent_tag="a:1",
        name="n", timestamp=ts,
        observations=(ObservationRecord(id="o", type="span", name="x", input=result.masked_text),),
    ))


def test_retention_purges_old_only(db, pipeline, tmp_path):
    from openagent_audit.services.audit_log_service import AuditLogService

    trace_store = LocalTraceStore()
    seed(db, trace_store, pipeline, trace_id="old", age_days=120)
    seed(db, trace_store, pipeline, trace_id="new", age_days=10)
    store = LocalObjectStore(tmp_path / "objects")
    audit = AuditLogService(db)

    job = RetentionJob(
        trace_store=trace_store, db=db, audit=audit, object_store=store,
        trace_retention_days=90, audit_archive_after_days=10000,
        clock=lambda: NOW,
    )
    summary = job.run()
    assert summary["traces_deleted"] == 1
    assert trace_store.get_trace("old") is None
    assert trace_store.get_trace("new") is not None
    # vault rows for the expired trace are gone too
    import sqlite3

    conn = sqlite3.connect(db._path)
    remaining = conn.execute("SELECT COUNT(*) FROM entity_ciphertext WHERE trace_id='old'").fetchone()[0]
    conn.close()
    assert remaining == 0
    assert "RETENTION_RUN" in [e.action for e in db.iter_audit()]


def test_retention_archives_old_entries(db, pipeline, tmp_path):
    from openagent_audit.services.audit_log_service import AuditLogService

    trace_store = LocalTraceStore()
    store = LocalObjectStore(tmp_path / "objects")
    audit = AuditLogService(db)
    # old audit entries exist before the run
    old_ts = NOW - timedelta(days=40)
    audit.append(actor="bob", role="compliance_lead", action="RESTORE_REQUESTED",
                 object_type="entity", object_id="x" * 16, ts=old_ts)
    audit.append(actor="carol", role="compliance_lead", action="RESTORE_APPROVED",
                 object_type="entity", object_id="x" * 16, ts=old_ts)
    seed(db, trace_store, pipeline, trace_id="t1", age_days=1)

    job = RetentionJob(
        trace_store=trace_store, db=db, audit=audit, object_store=store,
        trace_retention_days=90, audit_archive_after_days=30,
        clock=lambda: NOW,
    )
    summary = job.run()
    assert summary["audit_entries_archived"] == 2
    # archived file is JSONL and re-verifiable
    import json as jsonlib
    from pathlib import Path

    files = list(Path(tmp_path / "objects" / "audit-archive").rglob("*.jsonl"))
    assert files, "archive file missing"
    lines = [jsonlib.loads(l) for l in files[0].read_text(encoding="utf-8").splitlines()]
    assert all("entry_hash" in l for l in lines)
    # second run archives only new entries since none remain beyond cutoff
    again = job.run()
    assert again["audit_entries_archived"] == 0


def test_retention_without_object_store(db, pipeline):
    from openagent_audit.services.audit_log_service import AuditLogService

    audit = AuditLogService(db)
    job = RetentionJob(
        trace_store=LocalTraceStore(), db=db, audit=audit, object_store=None,
        trace_retention_days=90, audit_archive_after_days=30, clock=lambda: NOW,
    )
    summary = job.run()
    assert summary["audit_entries_archived"] == 0

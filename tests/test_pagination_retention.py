"""Pagination, retention consistency and archive-watermark regressions.

All four reported defects were "the code silently did less than it claimed":
only the first API page was processed, the two stores ended up disagreeing
about what still expired, the archive went to the wrong bucket, and a
non-monotonic watermark skipped entries forever.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from openagent_audit.media.objectstore import LocalObjectStore
from openagent_audit.services.retention import RetentionJob
from openagent_audit.tracing.trace_store import LangfuseTraceStore

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def _client(handler) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://lf.example",
        auth=("pk", "sk"),
    )


class _PagedLangfuse:
    """Minimal Langfuse v2 mock with real cursor-pagination semantics.

    Each row is one observation; the store groups them by ``traceId`` on the
    client side. We model the cursor as an integer offset into the row list so
    the test can assert how many requests were issued.
    """

    def __init__(self, total: int, page_limit: int = 50):
        # One observation per trace (good enough for the pagination tests,
        # which only care about counts and that every page is consumed).
        self.rows = [
            {"id": f"obs-{i:04d}", "traceId": f"t-{i:04d}", "sessionId": f"s-{i}",
             "userId": "u", "startTime": None}
            for i in range(total)
        ]
        self.page_limit = page_limit
        self.page_requests = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            target = request.url.path.rsplit("/", 1)[-1]
            self.rows = [r for r in self.rows if r["traceId"] != target]
            return httpx.Response(204)

        # v2 observations endpoint only.
        if request.url.path.rstrip("/") != "/api/public/v2/observations":
            return httpx.Response(404)

        self.page_requests += 1
        requested = int(request.url.params.get("limit", str(self.page_limit)))
        size = min(requested, self.page_limit)
        # Cursor is the offset into the row list (encoded as "off-<n>"); the
        # initial request has no cursor.
        cursor = request.url.params.get("cursor")
        offset = 0 if not cursor else int(cursor.split("-")[-1])
        data = self.rows[offset : offset + size]
        next_offset = offset + len(data)
        # Return a cursor only when more rows remain. An empty data page with
        # no cursor is the unambiguous end signal.
        meta: dict = {}
        if next_offset < len(self.rows):
            meta["cursor"] = f"off-{next_offset}"
        return httpx.Response(200, json={"data": data, "meta": meta})


class TestTracePagination:
    def test_list_pages_past_the_first_page(self):
        mock = _PagedLangfuse(total=125, page_limit=50)
        store = LangfuseTraceStore("https://x", "pk", "sk", client=_client(mock.handler))

        rows = store.list_trace_dicts(max_pages=None)

        assert len(rows) == 125, f"only retrieved {len(rows)} rows"
        # 50+50+25 rows across 3 requests; the last page returns no cursor.
        assert mock.page_requests == 3

    def test_list_traces_includes_every_page(self):
        mock = _PagedLangfuse(total=125, page_limit=50)
        # give the rows timestamps, otherwise they are not renderable as traces
        for i, row in enumerate(mock.rows):
            row["startTime"] = f"2026-10-20T10:{i // 60:02d}:{i % 60:02d}Z"
        store = LangfuseTraceStore("https://x", "pk", "sk", client=_client(mock.handler))

        records = store.list_traces(with_observations=False)

        assert len(records) == 125

    def test_delete_older_than_clears_every_page(self):
        mock = _PagedLangfuse(total=125, page_limit=50)
        store = LangfuseTraceStore("https://x", "pk", "sk", client=_client(mock.handler))

        deleted = store.delete_older_than(NOW)

        assert len(deleted) == 125, f"only deleted {len(deleted)} traces"
        assert mock.rows == [], f"{len(mock.rows)} traces left behind"

    def test_empty_result_stops_immediately(self):
        mock = _PagedLangfuse(total=0)
        store = LangfuseTraceStore("https://x", "pk", "sk", client=_client(mock.handler))

        assert store.list_trace_dicts() == []
        assert mock.page_requests == 1

    def test_session_crawl_is_not_silently_capped_at_10k(self):
        """A hard page cap used to hide sessions beyond it. v2 cursor
        pagination must follow the cursor to the end."""
        mock = _PagedLangfuse(total=10_050, page_limit=100)
        store = LangfuseTraceStore("https://x", "pk", "sk", client=_client(mock.handler))

        sessions = store.list_sessions()

        assert len(sessions) == 10_050, f"only {len(sessions)} sessions visible"


class TestObservationContract:
    def test_v2_returns_observation_bodies_inline(self):
        """v2 returns observation bodies inline (io/model/usage fields), so
        ``with_observations=True`` needs no per-trace detail round trip."""

        def handler(request: httpx.Request) -> httpx.Response:
            data = [
                {"id": "obs-1", "traceId": "t-1", "sessionId": "s-1", "userId": "u",
                 "startTime": "2026-10-20T10:00:00Z", "type": "span", "name": "接收请求",
                 "input": {"text": "⟦PHONE_NUMBER#ab|138****5678⟧"}},
                {"id": "obs-2", "traceId": "t-1", "sessionId": "s-1", "userId": "u",
                 "startTime": "2026-10-20T10:00:01Z", "type": "GENERATION", "name": "LLM",
                 "output": {"text": "好的"}},
            ]
            return httpx.Response(200, json={"data": data, "meta": {}})

        store = LangfuseTraceStore("https://x", "pk", "sk", client=_client(handler))
        (record,) = store.list_traces(with_observations=True)

        assert len(record.observations) == 2
        assert record.observations[0].id == "obs-1"
        assert "⟦PHONE_NUMBER#ab|138****5678⟧" in str(record.observations[0].input)

    def test_detail_failure_does_not_blank_the_page(self):
        """If the v2 endpoint errors mid-crawl, the store surfaces the error
        rather than silently returning partial data."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        store = LangfuseTraceStore("https://x", "pk", "sk", client=_client(handler))
        with pytest.raises(Exception):
            store.list_traces(with_observations=True)


# ---------------------------------------------------------------------------
# Retention consistency
# ---------------------------------------------------------------------------


class _FakeTraceStore:
    def __init__(self, total: int, *, fail: bool = False):
        self.deleted: list[str] = []
        self._remaining = [f"t-{i}" for i in range(total)]
        self.fail = fail

    def delete_older_than(self, cutoff):
        if self.fail:
            raise RuntimeError("langfuse unavailable")
        batch, self._remaining = list(self._remaining), []
        self.deleted.extend(batch)
        return batch


def _job(tmp_path, trace_store, db, audit):
    return RetentionJob(
        trace_store=trace_store,
        db=db,
        audit=audit,
        object_store=LocalObjectStore(tmp_path / "archive"),
        trace_retention_days=90,
        audit_archive_after_days=30,
        clock=lambda: NOW,
    )


def test_retention_reports_partial_when_trace_deletion_fails(db, tmp_path):
    from openagent_audit.services.audit_log_service import AuditLogService

    audit = AuditLogService(db)
    summary = _job(tmp_path, _FakeTraceStore(10, fail=True), db, audit).run()

    assert summary["status"] == "partial"
    assert summary["incomplete"]["trace_deletion"] is True
    # the failure is recorded in the audit log, not swallowed
    entry = db.iter_audit()[-1]
    assert entry.action == "RETENTION_RUN"
    assert entry.detail["status"] == "partial"


def test_retention_status_is_ok_when_everything_succeeds(db, tmp_path):
    from openagent_audit.services.audit_log_service import AuditLogService

    audit = AuditLogService(db)
    summary = _job(tmp_path, _FakeTraceStore(3), db, audit).run()

    assert summary["status"] == "ok"
    assert summary["traces_deleted"] == 3


# ---------------------------------------------------------------------------
# Archive watermark must not skip out-of-order entries
# ---------------------------------------------------------------------------


class _RecordingStore(LocalObjectStore):
    def __init__(self, root):
        super().__init__(root)
        self.retentions: list[int | None] = []

    def put(self, key, data, *, retention_days=None):
        self.retentions.append(retention_days)
        super().put(key, data, retention_days=retention_days)


def test_archive_requests_object_lock_retention(tmp_path, db):
    from openagent_audit.services.audit_log_service import AuditLogService

    audit = AuditLogService(db)
    store = _RecordingStore(tmp_path / "archive")
    old = NOW - timedelta(days=40)
    for i in range(3):
        audit.append(actor="bob", role="auditor", action="VIEW",
                     object_type="session", object_id=f"o-{i}", ts=old)

    job = RetentionJob(
        trace_store=None, db=db, audit=audit, object_store=store,
        trace_retention_days=90, audit_archive_after_days=30, clock=lambda: NOW,
        archive_retention_days=3650,
    )
    summary = job.run()

    assert summary["audit_entries_archived"] == 3
    # every archived object carries an Object-Lock retention request
    archived_puts = [r for r in store.retentions if r is not None]
    assert archived_puts and all(r == 3650 for r in archived_puts)


def test_watermark_does_not_advance_past_unarchived_entries(tmp_path, db):
    """Entries whose ``seq`` and ``ts`` disagree must still each be archived.

    The old code took ``entries[-1].seq`` of the *due* set. With a high-seq
    entry expiring before a low-seq one, the watermark jumped ahead and the
    later-expiring entry was skipped forever.
    """
    from openagent_audit.services.audit_log_service import AuditLogService

    audit = AuditLogService(db)
    store = _RecordingStore(tmp_path / "archive")

    # seq 1: recent (not yet due); seq 2: old (due)
    audit.append(actor="a", role="auditor", action="EARLY", object_type="session",
                 object_id="o1", ts=NOW - timedelta(days=1))
    audit.append(actor="a", role="auditor", action="LATE", object_type="session",
                 object_id="o2", ts=NOW - timedelta(days=40))

    job = RetentionJob(
        trace_store=None, db=db, audit=audit, object_store=store,
        trace_retention_days=90, audit_archive_after_days=30, clock=lambda: NOW,
    )
    first = job.run()
    assert first["audit_entries_archived"] == 1

    # now seq 1 also becomes due; it must still be archived despite the
    # watermark having already advanced past it conceptually
    job_later = RetentionJob(
        trace_store=None, db=db, audit=audit, object_store=store,
        trace_retention_days=90, audit_archive_after_days=30,
        clock=lambda: NOW + timedelta(days=60),
    )
    second = job_later.run()
    assert second["audit_entries_archived"] >= 1, "entry was skipped by the watermark"

    archived_actions = set()
    import pathlib

    for f in pathlib.Path(tmp_path / "archive").rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            archived_actions.add(json.loads(line)["action"])
    assert "EARLY" in archived_actions, f"EARLY never archived: {archived_actions}"

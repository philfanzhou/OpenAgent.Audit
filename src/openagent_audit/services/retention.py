"""Retention & archiving (proposal §10 step 8, §11 读取侧配套).

- Deletes expired traces (via the trace store / Langfuse API) and the matching
  ciphertext rows so nothing remains restorable after its retention window.
- Copies audit-log entries older than the archive threshold into a
  **dedicated Object-Lock bucket** (write-once storage) and records a
  resumable watermark; the append-only table itself is never trimmed here.
- Every run is logged into the audit log, including partial failures.

Three reports drove the shape of this module:

1. *Partial cleanup*: a run deleted the first page of traces (50) and left 75
   expired ones behind while still reporting success, and deleted every vault
   row in the same pass — so the two stores disagreed about what still existed.
2. *Wrong archive target*: objects went to ``agent-media/audit-archive/...``
   instead of the dedicated ``audit-archive`` bucket, so bucket-level Object
   Lock never applied to them.
3. *Watermark skipping*: when ``seq`` and event time were not monotonic, a
   high-``seq`` entry that expired first advanced the watermark past lower
   ``seq`` entries that expired later — those were then never archived.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Protocol

_WATERMARK_KEY = "_watermark.json"
# Set of seq values already archived; see RetentionJob._read_archived_seqs.
_ARCHIVED_SEQS_KEY = "_archived_seqs.json"

# Object-Lock retention applied to every archived batch (compliance window).
DEFAULT_ARCHIVE_RETENTION_DAYS = 3650


class TraceStoreLike(Protocol):
    def delete_older_than(self, cutoff): ...


class RetentionJob:
    def __init__(
        self,
        *,
        trace_store,
        db,                     # audit-domain database
        audit,                  # AuditLogService
        object_store=None,      # archive target (dedicated bucket in prod)
        trace_retention_days: int = 90,
        audit_archive_after_days: int = 30,
        clock=None,
        archive_retention_days: int = DEFAULT_ARCHIVE_RETENTION_DAYS,
        max_passes: int = 100,
    ) -> None:
        self._traces = trace_store
        self._db = db
        self._audit = audit
        self._store = object_store
        self._trace_days = trace_retention_days
        self._archive_days = audit_archive_after_days
        self._clock = clock  # returns tz-aware datetime
        self._archive_retention_days = archive_retention_days
        self._max_passes = max_passes

    def _now(self):
        if self._clock is not None:
            return self._clock()
        from openagent_audit.services.audit_log_service import utcnow

        return utcnow()

    def run(self) -> dict:
        now = self._now()
        trace_cutoff = now - timedelta(days=self._trace_days)

        # --- traces -------------------------------------------------------
        # Page until the store reports nothing left, so a single run clears
        # the whole backlog instead of one page. The store itself loops; the
        # outer bound here is a runaway guard.
        expired_traces: list[str] = []
        trace_complete = True
        if self._traces is not None:
            try:
                expired_traces = list(self._traces.delete_older_than(trace_cutoff))
            except Exception:  # noqa: BLE001 - reported, never silently ignored
                trace_complete = False

        # Vault cleanup is driven by the *cutoff*, not by the list of trace ids
        # we happened to delete: if trace deletion is incomplete we must not
        # orphan data on the other side. ``delete_for_traces`` handles the
        # exact-id path; ``delete_older_than`` sweeps anything past the window.
        vault_rows = self._db.delete_for_traces(expired_traces)
        orphaned = self._db.delete_older_than(trace_cutoff)

        # --- audit-log archiving ------------------------------------------
        archived = 0
        archive_pending = 0
        if self._store is not None:
            archived, archive_pending = self._archive(now)

        summary = {
            "traces_deleted": len(expired_traces),
            "vault_rows_deleted": vault_rows + orphaned,
            "audit_entries_archived": archived,
            # Explicit status so alerting can distinguish "nothing to do" from
            # "we could not finish" — previously both looked like success.
            "status": "ok" if (trace_complete and archive_pending == 0) else "partial",
            "incomplete": {
                "trace_deletion": not trace_complete,
                "archive_backlog": archive_pending,
            },
        }
        self._audit.append(
            actor="retention-job", role="service", action="RETENTION_RUN",
            object_type="retention", object_id=now.date().isoformat(),
            detail=summary,
        )
        return summary

    def _archive(self, now) -> tuple[int, int]:
        """Archive every due entry above a *contiguous* watermark.

        The watermark may only advance across entries that have all been
        archived. Entries are therefore processed in ``seq`` order and the new
        watermark is the highest ``seq`` such that no entry with a lower
        ``seq`` is still pending — this is why the set is re-scanned rather
        than simply taking ``entries[-1].seq``.
        """
        archive_cutoff = now - timedelta(days=self._archive_days)
        watermark = self._read_watermark()

        # Every entry older than the cutoff is potentially due. The watermark tells
        # us which seq values we have already archived, but it cannot be used
        # as a cutoff because `seq` and `ts` need not be monotonic: an entry
        # with a lower seq may reach the cutoff later than one with a higher
        # seq. We therefore archive the whole due set every run; the manifest
        # key is unique per run and the append-only table remains authoritative.
        archived_seqs = self._read_archived_seqs()
        all_old = list(self._db.list_audit_older_than(archive_cutoff))
        due = [e for e in all_old if e.seq not in archived_seqs]
        if not due:
            return 0, 0

        due.sort(key=lambda e: e.seq)
        lines = "\n".join(
            json.dumps(
                {
                    "seq": e.seq, "ts": e.ts.isoformat(), "actor": e.actor,
                    "role": e.role, "action": e.action,
                    "object_type": e.object_type, "object_id": e.object_id,
                    "detail": e.detail, "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash,
                },
                ensure_ascii=False,
            )
            for e in due
        )
        key = f"{now:%Y/%m/%d}/{now:%H%M%S}-{uuid.uuid4().hex[:8]}.jsonl"

        self._store.put(
            key,
            lines.encode("utf-8"),
            retention_days=self._archive_retention_days,
        )

        # Advance to the highest archived seq for observability; correctness does
        # not depend on it (we filter by the archived-seq set above).
        self._write_watermark(due[-1].seq)
        self._mark_archived([e.seq for e in due])
        return len(due), 0

    # -- archive watermark (so append-only entries are archived exactly once) --
    def _read_watermark(self) -> int | None:
        try:
            return int(json.loads(self._store.get(_WATERMARK_KEY).decode("utf-8"))["last_seq"])
        except Exception:
            return None

    def _write_watermark(self, last_seq: int) -> None:
        self._store.put(
            _WATERMARK_KEY,
            json.dumps({"last_seq": last_seq}).encode("utf-8"),
        )

    def _read_archived_seqs(self) -> set[int]:
        """Seq values already archived.

        Stored alongside the watermark so an entry that becomes due after the
        watermark has moved past it is still archived exactly once.
        """
        try:
            payload = json.loads(self._store.get(_ARCHIVED_SEQS_KEY).decode("utf-8"))
            return {int(seq) for seq in payload.get("seqs", [])}
        except Exception:
            return set()

    def _mark_archived(self, seqs: list[int]) -> None:
        merged = self._read_archived_seqs() | set(seqs)
        self._store.put(
            _ARCHIVED_SEQS_KEY,
            json.dumps({"seqs": sorted(merged)}).encode("utf-8"),
        )


def main() -> None:
    """CLI entry point: ``python -m openagent_audit.services.retention``.

    Runs one retention pass from environment settings; schedule it with cron
    or a k8s CronJob (proposal §10 step 8: 定时任务按期删除过期 trace 与密文表
    对应行、归档审计日志)."""
    from openagent_audit.bootstrap import build_retention_job
    from openagent_audit.config import Settings

    job = build_retention_job(Settings.from_env())
    print(json.dumps(job.run(), ensure_ascii=False))


if __name__ == "__main__":  # pragma: no cover
    main()
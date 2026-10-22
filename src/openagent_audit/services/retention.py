"""Retention & archiving (proposal §10 step 8, §11 读取侧配套).

- Deletes expired traces (via the trace store / Langfuse API) and the matching
  ciphertext rows so nothing remains restorable after its retention window.
- Copies audit-log entries older than the archive threshold into the object
  store (deployment target: an Object-Lock bucket — write-once storage); the
  append-only table itself is never trimmed here.
- Every run is logged into the audit log.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Protocol

_WATERMARK_KEY = "audit-archive/_watermark.json"


class TraceStoreLike(Protocol):
    def delete_older_than(self, cutoff): ...


class RetentionJob:
    def __init__(
        self,
        *,
        trace_store,
        db,                     # audit-domain database
        audit,                  # AuditLogService
        object_store=None,      # archive target (Object-Lock bucket in prod)
        trace_retention_days: int = 90,
        audit_archive_after_days: int = 30,
        clock=None,
    ) -> None:
        self._traces = trace_store
        self._db = db
        self._audit = audit
        self._store = object_store
        self._trace_days = trace_retention_days
        self._archive_days = audit_archive_after_days
        self._clock = clock  # returns tz-aware datetime

    def _now(self):
        if self._clock is not None:
            return self._clock()
        from openagent_audit.services.audit_log_service import utcnow

        return utcnow()

    def run(self) -> dict:
        now = self._now()
        trace_cutoff = now - timedelta(days=self._trace_days)

        expired_traces: list[str] = []
        if self._traces is not None:
            expired_traces = list(self._traces.delete_older_than(trace_cutoff))
        vault_rows = self._db.delete_for_traces(expired_traces)
        orphaned = self._db.delete_older_than(trace_cutoff)

        archived = 0
        if self._store is not None:
            archive_cutoff = now - timedelta(days=self._archive_days)
            watermark = self._read_watermark()
            entries = [
                e for e in self._db.list_audit_older_than(archive_cutoff)
                if watermark is None or e.seq > watermark
            ]
            if entries:
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
                    for e in entries
                )
                key = f"audit-archive/{now:%Y/%m/%d}/{now:%H%M%S}-{uuid.uuid4().hex[:8]}.jsonl"
                self._store.put(key, lines.encode("utf-8"))
                self._write_watermark(entries[-1].seq)
                archived = len(entries)

        summary = {
            "traces_deleted": len(expired_traces),
            "vault_rows_deleted": vault_rows + orphaned,
            "audit_entries_archived": archived,
        }
        self._audit.append(
            actor="retention-job", role="service", action="RETENTION_RUN",
            object_type="retention", object_id=now.date().isoformat(),
            detail=summary,
        )
        return summary

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

"""Audit log service: hash-chained append + best-effort Loki copy.

Every browsing, restore, decryption, and retention action lands here first —
the Loki copy exists purely for real-time alerting (e.g. decrypt bursts).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping

from openagent_audit.alerts.loki import NullLokiClient
from openagent_audit.vault.models import AuditEntry


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLogService:
    def __init__(self, db, loki=None) -> None:
        self._db = db
        self._loki = loki if loki is not None else NullLokiClient()

    def append(
        self,
        *,
        actor: str,
        role: str,
        action: str,
        object_type: str | None = None,
        object_id: str | None = None,
        detail: Mapping[str, object] | None = None,
        ts: datetime | None = None,
    ) -> AuditEntry:
        entry = self._db.append_audit(
            ts=ts or utcnow(),
            actor=actor,
            role=role,
            action=action,
            object_type=object_type,
            object_id=object_id,
            detail=dict(detail or {}),
        )
        # Alerting copy: ids and action only — never values.
        self._loki.push_event(
            {
                "ts": entry.ts.isoformat(),
                "actor": entry.actor,
                "role": entry.role,
                "action": entry.action,
                "object_type": entry.object_type,
                "object_id": entry.object_id,
            },
            category=_category(entry.action),
        )
        return entry

    def list_entries(self, limit: int = 200, before_seq: int | None = None) -> list[AuditEntry]:
        return self._db.list_audit(limit=limit, before_seq=before_seq)

    def verify(self) -> dict:
        from openagent_audit.vault.hashchain import verify_chain

        entries = self._db.iter_audit()
        ok, bad_seq = verify_chain(
            [
                {
                    "seq": e.seq, "ts": e.ts, "actor": e.actor, "role": e.role,
                    "action": e.action, "object_type": e.object_type,
                    "object_id": e.object_id, "detail": e.detail,
                    "prev_hash": e.prev_hash, "entry_hash": e.entry_hash,
                }
                for e in entries
            ]
        )
        return {"ok": ok, "first_bad_seq": bad_seq, "entries": len(entries)}


def _category(action: str) -> str:
    if "DECRYPT" in action or "REVEAL" in action or "VIEW" in action:
        return "decrypt"
    if "RESTORE" in action:
        return "restore"
    return "audit"

"""Audit-domain repositories: ciphertext vault + append-only audit log +
restore requests. The SQLite implementation backs dev and the full test
suite; :mod:`openagent_audit.vault.postgres_store` is the deployment twin
with identical semantics (see ``deploy/audit_db_init.sql`` for grants — the
Agent account gets INSERT-only on ``entity_ciphertext``).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from openagent_audit.vault.hashchain import GENESIS_HASH, canonical_entry, entry_hash
from openagent_audit.vault.models import (
    AuditEntry,
    EntityCiphertextRow,
    RestoreRequest,
    RestoreStatus,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


class SQLiteAuditDatabase:
    """Single-file implementation of the three audit-domain tables."""

    def __init__(self, path: str | Path, *, now=None) -> None:
        self._memory = str(path) == ":memory:"
        if not self._memory:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._path = ":memory:" if self._memory else str(path)
        self._now = now or _utcnow
        self._lock = threading.RLock()
        self._mem_conn: sqlite3.Connection | None = None
        if self._memory:
            self._mem_conn = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self.init_schema()

    # -- plumbing ----------------------------------------------------------
    @contextmanager
    def _connect(self):
        if self._mem_conn is not None:
            yield self._mem_conn
            self._mem_conn.commit()
            return
        conn = sqlite3.connect(self._path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entity_ciphertext (
                    entity_id   TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    ciphertext  TEXT NOT NULL,
                    trace_id    TEXT,
                    session_id  TEXT,
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_entity_session ON entity_ciphertext(session_id);
                CREATE INDEX IF NOT EXISTS ix_entity_trace ON entity_ciphertext(trace_id);
                CREATE INDEX IF NOT EXISTS ix_entity_created ON entity_ciphertext(created_at);

                CREATE TABLE IF NOT EXISTS audit_log (
                    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT NOT NULL,
                    actor       TEXT NOT NULL,
                    role        TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    object_type TEXT,
                    object_id   TEXT,
                    detail      TEXT NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    entry_hash  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS restore_request (
                    id                TEXT PRIMARY KEY,
                    object_type       TEXT NOT NULL,
                    object_id         TEXT NOT NULL,
                    reason            TEXT NOT NULL,
                    requested_by      TEXT NOT NULL,
                    trace_id          TEXT,
                    session_id        TEXT,
                    status            TEXT NOT NULL,
                    approver          TEXT,
                    decision_comment  TEXT,
                    created_at        TEXT NOT NULL,
                    decided_at        TEXT,
                    reveal_expires_at TEXT
                );
                """
            )

    # -- ciphertext vault ---------------------------------------------------
    def insert_entities(self, rows: Sequence[Mapping[str, object]]) -> None:
        now = _iso(self._now())
        with self._lock, self._connect() as conn:
            conn.executemany(
                "INSERT INTO entity_ciphertext "
                "(entity_id, entity_type, ciphertext, trace_id, session_id, created_at) "
                "VALUES (:entity_id, :entity_type, :ciphertext, :trace_id, :session_id, :created_at)",
                [
                    {
                        "entity_id": r["entity_id"],
                        "entity_type": r["entity_type"],
                        "ciphertext": r["ciphertext"],
                        "trace_id": r.get("trace_id"),
                        "session_id": r.get("session_id"),
                        "created_at": now,
                    }
                    for r in rows
                ],
            )

    def get_entity(self, entity_id: str) -> EntityCiphertextRow | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM entity_ciphertext WHERE entity_id = ?", (entity_id,)
            ).fetchone()
        return self._entity_row(row)

    @staticmethod
    def _entity_row(row: sqlite3.Row | None) -> EntityCiphertextRow | None:
        if row is None:
            return None
        return EntityCiphertextRow(
            entity_id=row["entity_id"],
            entity_type=row["entity_type"],
            ciphertext=row["ciphertext"],
            trace_id=row["trace_id"],
            session_id=row["session_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def delete_for_traces(self, trace_ids: Iterable[str]) -> int:
        ids = list(trace_ids)
        if not ids:
            return 0
        with self._lock, self._connect() as conn:
            marks = ",".join("?" for _ in ids)
            cur = conn.execute(
                f"DELETE FROM entity_ciphertext WHERE trace_id IN ({marks})", ids
            )
            return cur.rowcount

    def delete_older_than(self, cutoff: datetime) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM entity_ciphertext WHERE created_at < ?", (cutoff.isoformat(),)
            )
            return cur.rowcount

    # -- audit log (append-only + hash chain) --------------------------------
    def append_audit(
        self,
        *,
        ts: datetime,
        actor: str,
        role: str,
        action: str,
        object_type: str | None = None,
        object_id: str | None = None,
        detail: Mapping[str, object] | None = None,
    ) -> AuditEntry:
        detail = dict(detail or {})
        with self._lock, self._connect() as conn:
            last = conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = last["entry_hash"] if last else GENESIS_HASH
            canonical = canonical_entry(
                ts=ts, actor=actor, role=role, action=action,
                object_type=object_type, object_id=object_id, detail=detail,
            )
            eh = entry_hash(prev_hash, canonical)
            cur = conn.execute(
                "INSERT INTO audit_log (ts, actor, role, action, object_type, object_id, "
                "detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                (ts.isoformat(), actor, role, action, object_type, object_id,
                 json.dumps(detail, ensure_ascii=False), prev_hash, eh),
            )
            seq = cur.lastrowid
        return AuditEntry(
            seq=seq, ts=ts, actor=actor, role=role, action=action,
            object_type=object_type, object_id=object_id, detail=detail,
            prev_hash=prev_hash, entry_hash=eh,
        )

    def list_audit(
        self,
        limit: int = 200,
        before_seq: int | None = None,
        q: str | None = None,
        offset: int = 0,
    ) -> list[AuditEntry]:
        query = "SELECT * FROM audit_log"
        params: list[object] = []
        clauses: list[str] = []
        if before_seq is not None:
            clauses.append("seq < ?")
            params.append(before_seq)
        if q:
            clauses.append(
                "(actor LIKE ? OR action LIKE ? OR object_type LIKE ? OR object_id LIKE ? OR role LIKE ?)"
            )
            like = f"%{q}%"
            params += [like, like, like, like, like]
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY seq DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._audit_row(r) for r in rows]

    def iter_audit(self) -> list[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
        return [self._audit_row(r) for r in rows]

    def count_entities(self) -> int:
        with self._connect() as conn:
            (n,) = conn.execute("SELECT COUNT(*) FROM entity_ciphertext").fetchone()
        return int(n)

    def count_audit_entries(self, q: str | None = None) -> int:
        query = "SELECT COUNT(*) FROM audit_log"
        params: list[object] = []
        if q:
            query += (
                " WHERE actor LIKE ? OR action LIKE ? OR object_type LIKE ?"
                " OR object_id LIKE ? OR role LIKE ?"
            )
            like = f"%{q}%"
            params = [like, like, like, like, like]
        with self._connect() as conn:
            (n,) = conn.execute(query, params).fetchone()
        return int(n)

    def list_audit_older_than(self, cutoff: datetime) -> list[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE ts < ? ORDER BY seq ASC", (cutoff.isoformat(),)
            ).fetchall()
        return [self._audit_row(r) for r in rows]

    @staticmethod
    def _audit_row(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            seq=row["seq"],
            ts=datetime.fromisoformat(row["ts"]),
            actor=row["actor"],
            role=row["role"],
            action=row["action"],
            object_type=row["object_type"],
            object_id=row["object_id"],
            detail=json.loads(row["detail"]),
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    # -- restore requests ----------------------------------------------------
    def insert_restore_request(self, req: RestoreRequest) -> RestoreRequest:
        created_at = _iso(req.created_at) or _iso(self._now())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO restore_request (id, object_type, object_id, reason, requested_by, "
                "trace_id, session_id, status, approver, decision_comment, created_at, decided_at, "
                "reveal_expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (req.id, req.object_type, req.object_id, req.reason, req.requested_by,
                 req.trace_id, req.session_id, req.status.value, req.approver,
                 req.decision_comment, created_at, _iso(req.decided_at),
                 _iso(req.reveal_expires_at)),
            )
        return req

    def update_restore_request(
        self,
        request_id: str,
        *,
        status: RestoreStatus,
        approver: str | None = None,
        decision_comment: str | None = None,
        decided_at: datetime | None = None,
        reveal_expires_at: datetime | None = None,
    ) -> RestoreRequest | None:
        current = self.get_restore_request(request_id)
        if current is None:
            return None
        updated = RestoreRequest(
            id=current.id,
            object_type=current.object_type,
            object_id=current.object_id,
            reason=current.reason,
            requested_by=current.requested_by,
            trace_id=current.trace_id,
            session_id=current.session_id,
            status=status,
            approver=approver if approver is not None else current.approver,
            decision_comment=decision_comment if decision_comment is not None else current.decision_comment,
            created_at=current.created_at,
            decided_at=decided_at if decided_at is not None else current.decided_at,
            reveal_expires_at=reveal_expires_at if reveal_expires_at is not None else current.reveal_expires_at,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE restore_request SET status=?, approver=?, decision_comment=?, decided_at=?, "
                "reveal_expires_at=? WHERE id=?",
                (updated.status.value, updated.approver, updated.decision_comment,
                 _iso(updated.decided_at), _iso(updated.reveal_expires_at), request_id),
            )
        return updated

    def get_restore_request(self, request_id: str) -> RestoreRequest | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM restore_request WHERE id = ?", (request_id,)
            ).fetchone()
        return self._restore_row(row)

    def list_restore_requests(
        self,
        status: RestoreStatus | None = None,
        q: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[RestoreRequest]:
        query = "SELECT * FROM restore_request"
        params: list[object] = []
        clauses: list[str] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        if q:
            clauses.append(
                "(object_id LIKE ? OR reason LIKE ? OR requested_by LIKE ? OR approver LIKE ? OR id LIKE ?)"
            )
            like = f"%{q}%"
            params += [like, like, like, like, like]
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params += [limit, offset]
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._restore_row(r) for r in rows]

    def count_restore_requests(
        self, status: RestoreStatus | None = None, q: str | None = None
    ) -> int:
        query = "SELECT COUNT(*) FROM restore_request"
        params: list[object] = []
        clauses: list[str] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        if q:
            clauses.append(
                "(object_id LIKE ? OR reason LIKE ? OR requested_by LIKE ? OR approver LIKE ? OR id LIKE ?)"
            )
            like = f"%{q}%"
            params += [like, like, like, like, like]
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            (n,) = conn.execute(query, params).fetchone()
        return int(n)

    @staticmethod
    def _restore_row(row: sqlite3.Row | None) -> RestoreRequest | None:
        if row is None:
            return None
        return RestoreRequest(
            id=row["id"],
            object_type=row["object_type"],
            object_id=row["object_id"],
            reason=row["reason"],
            requested_by=row["requested_by"],
            trace_id=row["trace_id"],
            session_id=row["session_id"],
            status=RestoreStatus(row["status"]),
            approver=row["approver"],
            decision_comment=row["decision_comment"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            decided_at=datetime.fromisoformat(row["decided_at"]) if row["decided_at"] else None,
            reveal_expires_at=datetime.fromisoformat(row["reveal_expires_at"])
            if row["reveal_expires_at"]
            else None,
        )


class FrozenClock:
    """Test helper: a clock that only moves when you advance it."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or _utcnow()

    def __call__(self) -> datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now = self._now + timedelta(**kwargs)

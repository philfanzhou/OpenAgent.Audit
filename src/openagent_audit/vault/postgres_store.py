"""Postgres twin of :class:`openagent_audit.vault.store.SQLiteAuditDatabase`.

Deployment target for the audit domain (``audit-db`` in docker-compose).
Grants in ``deploy/audit_db_init.sql`` enforce the proposal's privilege
split: the Agent account holds INSERT-only on ``entity_ciphertext``;
audit-api holds no SELECT on ``entity_ciphertext`` at all; decrypt-svc is
the only role that reads ciphertext.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Mapping, Sequence

from openagent_audit.vault.hashchain import GENESIS_HASH, canonical_entry, entry_hash
from openagent_audit.vault.models import (
    AuditEntry,
    EntityCiphertextRow,
    RestoreRequest,
    RestoreStatus,
)


class PostgresAuditDatabase:
    def __init__(self, dsn: str, *, now=None) -> None:
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise RuntimeError(
                "psycopg is not installed; pip install 'openagent-audit[postgres]'"
            ) from exc
        self._dsn = dsn
        self._now = now or (lambda: datetime.now().astimezone())
        self.init_schema()

    def _connect(self):
        import psycopg

        return psycopg.connect(self._dsn)

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entity_ciphertext (
                    entity_id   TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    ciphertext  TEXT NOT NULL,
                    trace_id    TEXT,
                    session_id  TEXT,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                CREATE INDEX IF NOT EXISTS ix_entity_session ON entity_ciphertext(session_id);
                CREATE INDEX IF NOT EXISTS ix_entity_trace ON entity_ciphertext(trace_id);
                CREATE INDEX IF NOT EXISTS ix_entity_created ON entity_ciphertext(created_at);

                CREATE TABLE IF NOT EXISTS audit_log (
                    seq         BIGSERIAL PRIMARY KEY,
                    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
                    actor       TEXT NOT NULL,
                    role        TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    object_type TEXT,
                    object_id   TEXT,
                    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
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
                    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
                    decided_at        TIMESTAMPTZ,
                    reveal_expires_at TIMESTAMPTZ
                );
                """
            )

    # -- ciphertext vault ---------------------------------------------------
    def insert_entities(self, rows: Sequence[Mapping[str, object]]) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO entity_ciphertext "
                    "(entity_id, entity_type, ciphertext, trace_id, session_id) "
                    "VALUES (%(entity_id)s, %(entity_type)s, %(ciphertext)s, %(trace_id)s, %(session_id)s)",
                    [
                        {
                            "entity_id": r["entity_id"],
                            "entity_type": r["entity_type"],
                            "ciphertext": r["ciphertext"],
                            "trace_id": r.get("trace_id"),
                            "session_id": r.get("session_id"),
                        }
                        for r in rows
                    ],
                )

    def get_entity(self, entity_id: str) -> EntityCiphertextRow | None:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT entity_id, entity_type, ciphertext, trace_id, session_id, created_at "
                "FROM entity_ciphertext WHERE entity_id = %s",
                (entity_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return EntityCiphertextRow(
            entity_id=row[0], entity_type=row[1], ciphertext=row[2],
            trace_id=row[3], session_id=row[4], created_at=row[5],
        )

    def delete_for_traces(self, trace_ids) -> int:
        ids = list(trace_ids)
        if not ids:
            return 0
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM entity_ciphertext WHERE trace_id = ANY(%s)", (ids,)
            )
            return cur.rowcount

    def delete_older_than(self, cutoff: datetime) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM entity_ciphertext WHERE created_at < %s", (cutoff,)
            )
            return cur.rowcount

    # -- audit log ------------------------------------------------------------
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
        with self._connect() as conn:
            # Serialize writers so the hash chain is race-free (proposal §08:
            # append-only; deletion/edit must be detectable).
            conn.execute("SELECT pg_advisory_xact_lock(hashtext('openagent_audit_log'))")
            last = conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = last[0] if last else GENESIS_HASH
            canonical = canonical_entry(
                ts=ts, actor=actor, role=role, action=action,
                object_type=object_type, object_id=object_id, detail=detail,
            )
            eh = entry_hash(prev_hash, canonical)
            cur = conn.execute(
                "INSERT INTO audit_log (ts, actor, role, action, object_type, object_id, detail, "
                "prev_hash, entry_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING seq",
                (ts, actor, role, action, object_type, object_id,
                 json.dumps(detail, ensure_ascii=False), prev_hash, eh),
            )
            seq = cur.fetchone()[0]
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
        query = (
            "SELECT seq, ts, actor, role, action, object_type, object_id, detail, "
            "prev_hash, entry_hash FROM audit_log"
        )
        params: list[object] = []
        if before_seq is not None:
            query += " WHERE seq < %s"
            params.append(before_seq)
        if q:
            clauses = "(actor LIKE %s OR action LIKE %s OR object_type LIKE %s OR object_id LIKE %s OR role LIKE %s)"
            like = f"%{q}%"
            query += (" WHERE " if before_seq is None else " AND ") + clauses
            params += [like, like, like, like, like]
        query += " ORDER BY seq DESC LIMIT %s OFFSET %s"
        params += [limit, offset]
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            AuditEntry(
                seq=r[0], ts=r[1], actor=r[2], role=r[3], action=r[4],
                object_type=r[5], object_id=r[6], detail=r[7] if isinstance(r[7], dict) else json.loads(r[7]),
                prev_hash=r[8], entry_hash=r[9],
            )
            for r in rows
        ]

    def iter_audit(self) -> list[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, ts, actor, role, action, object_type, object_id, detail, "
                "prev_hash, entry_hash FROM audit_log ORDER BY seq ASC"
            ).fetchall()
        return [
            AuditEntry(
                seq=r[0], ts=r[1], actor=r[2], role=r[3], action=r[4],
                object_type=r[5], object_id=r[6], detail=r[7] if isinstance(r[7], dict) else json.loads(r[7]),
                prev_hash=r[8], entry_hash=r[9],
            )
            for r in rows
        ]

    def count_entities(self, q: str | None = None) -> int:
        query = "SELECT COUNT(*) FROM entity_ciphertext"
        params: list[object] = []
        if q:
            query += (
                " WHERE entity_id LIKE %s OR entity_type LIKE %s"
                " OR trace_id LIKE %s OR session_id LIKE %s"
            )
            like = f"%{q}%"
            params = [like, like, like, like]
        with self._connect() as conn:
            (n,) = conn.execute(query, params).fetchone()
        return int(n)

    def count_audit_entries(self, q: str | None = None) -> int:
        query = "SELECT COUNT(*) FROM audit_log"
        params: list[object] = []
        if q:
            query += (
                " WHERE actor LIKE %s OR action LIKE %s OR object_type LIKE %s"
                " OR object_id LIKE %s OR role LIKE %s"
            )
            like = f"%{q}%"
            params = [like, like, like, like, like]
        with self._connect() as conn:
            (n,) = conn.execute(query, params).fetchone()
        return int(n)

    def list_audit_older_than(self, cutoff: datetime) -> list[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, ts, actor, role, action, object_type, object_id, detail, "
                "prev_hash, entry_hash FROM audit_log WHERE ts < %s ORDER BY seq ASC",
                (cutoff,),
            ).fetchall()
        return [
            AuditEntry(
                seq=r[0], ts=r[1], actor=r[2], role=r[3], action=r[4],
                object_type=r[5], object_id=r[6], detail=r[7] if isinstance(r[7], dict) else json.loads(r[7]),
                prev_hash=r[8], entry_hash=r[9],
            )
            for r in rows
        ]

    # -- restore requests -------------------------------------------------------
    def insert_restore_request(self, req: RestoreRequest) -> RestoreRequest:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO restore_request (id, object_type, object_id, reason, requested_by, "
                "trace_id, session_id, status, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (req.id, req.object_type, req.object_id, req.reason, req.requested_by,
                 req.trace_id, req.session_id, req.status.value, req.created_at),
            )
        return req

    def update_restore_request(self, request_id: str, **fields) -> RestoreRequest | None:
        sets, params = [], []
        column_map = {
            "status": "status",
            "approver": "approver",
            "decision_comment": "decision_comment",
            "decided_at": "decided_at",
            "reveal_expires_at": "reveal_expires_at",
        }
        for key, value in fields.items():
            col = column_map.get(key)
            if col is None:
                raise KeyError(key)
            if isinstance(value, RestoreStatus):
                value = value.value
            sets.append(f"{col} = %s")
            params.append(value)
        if not sets:
            # nothing to update — do not emit invalid SQL ("UPDATE ... SET WHERE")
            return self.get_restore_request(request_id)
        params.append(request_id)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE restore_request SET {', '.join(sets)} WHERE id = %s", params
            )
        return self.get_restore_request(request_id)

    def get_restore_request(self, request_id: str) -> RestoreRequest | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, object_type, object_id, reason, requested_by, trace_id, session_id, "
                "status, approver, decision_comment, created_at, decided_at, reveal_expires_at "
                "FROM restore_request WHERE id = %s",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        return RestoreRequest(
            id=row[0], object_type=row[1], object_id=row[2], reason=row[3],
            requested_by=row[4], trace_id=row[5], session_id=row[6],
            status=RestoreStatus(row[7]), approver=row[8], decision_comment=row[9],
            created_at=row[10], decided_at=row[11], reveal_expires_at=row[12],
        )

    def list_restore_requests(
        self,
        status: RestoreStatus | None = None,
        q: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[RestoreRequest]:
        query = (
            "SELECT id, object_type, object_id, reason, requested_by, trace_id, session_id, "
            "status, approver, decision_comment, created_at, decided_at, reveal_expires_at "
            "FROM restore_request"
        )
        params: list[object] = []
        clauses: list[str] = []
        if status is not None:
            clauses.append("status = %s")
            params.append(status.value)
        if q:
            clauses.append(
                "(object_id LIKE %s OR reason LIKE %s OR requested_by LIKE %s"
                " OR approver LIKE %s OR id LIKE %s)"
            )
            like = f"%{q}%"
            params += [like, like, like, like, like]
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += " LIMIT %s OFFSET %s"
            params += [limit, offset]
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            RestoreRequest(
                id=r[0], object_type=r[1], object_id=r[2], reason=r[3],
                requested_by=r[4], trace_id=r[5], session_id=r[6],
                status=RestoreStatus(r[7]), approver=r[8], decision_comment=r[9],
                created_at=r[10], decided_at=r[11], reveal_expires_at=r[12],
            )
            for r in rows
        ]

    def count_restore_requests(
        self, status: RestoreStatus | None = None, q: str | None = None
    ) -> int:
        query = "SELECT COUNT(*) FROM restore_request"
        params: list[object] = []
        clauses: list[str] = []
        if status is not None:
            clauses.append("status = %s")
            params.append(status.value)
        if q:
            clauses.append(
                "(object_id LIKE %s OR reason LIKE %s OR requested_by LIKE %s"
                " OR approver LIKE %s OR id LIKE %s)"
            )
            like = f"%{q}%"
            params += [like, like, like, like, like]
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            (n,) = conn.execute(query, params).fetchone()
        return int(n)

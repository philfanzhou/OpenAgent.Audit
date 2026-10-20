"""Integration test against a real Postgres (proposal §01 audit lane).

Requires a disposable container::

    docker run -d --name openagent-audit-pg-test \\
      -e POSTGRES_USER=audit_owner -e POSTGRES_PASSWORD=testpw \\
      -e POSTGRES_DB=openagent_audit -p 15432:5432 \\
      -v "$(pwd)/deploy/audit_db_init.sql:/docker-entrypoint-initdb.d/10_init.sql:ro" \\
      postgres:17

Skipped automatically when the database is unreachable. Verifies:
- PostgresAuditDatabase parity with the SQLite implementation
- the deployment privilege split from deploy/audit_db_init.sql
  (agent INSERT-only, audit-api no ciphertext read, decrypt-svc sole reader)
"""

from __future__ import annotations

import os

import pytest

PG_DSN = os.environ.get(
    "AUDIT_TEST_PG_DSN",
    "postgresql://audit_owner:testpw@localhost:15432/openagent_audit",
)


def _postgres_available() -> bool:
    try:
        import psycopg

        with psycopg.connect(PG_DSN, connect_timeout=3):
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_available(), reason="postgres test container not reachable on :15432"
)


@pytest.fixture()
def pg_db():
    from openagent_audit.vault.postgres_store import PostgresAuditDatabase

    db = PostgresAuditDatabase(PG_DSN)
    # clean slate between tests
    with db._connect() as conn:
        conn.execute("TRUNCATE entity_ciphertext, audit_log, restore_request")
    return db


def _role_dsn(role: str, password: str) -> str:
    return f"postgresql://{role}:{password}@localhost:15432/openagent_audit"


def test_vault_and_audit_flow(pg_db):
    from openagent_audit.vault.hashchain import verify_chain

    pg_db.insert_entities([
        {"entity_id": "e" * 16, "entity_type": "PHONE_NUMBER", "ciphertext": "CT",
         "trace_id": "t1", "session_id": "s1"},
    ])
    assert pg_db.get_entity("e" * 16).ciphertext == "CT"

    from datetime import datetime, timezone

    e1 = pg_db.append_audit(ts=datetime.now(timezone.utc), actor="bob", role="compliance_lead",
                            action="RESTORE_REQUESTED", object_type="entity", object_id="e" * 16,
                            detail={"request_id": "r1"})
    e2 = pg_db.append_audit(ts=datetime.now(timezone.utc), actor="carol", role="compliance_lead",
                            action="RESTORE_APPROVED", object_type="entity", object_id="e" * 16,
                            detail={"request_id": "r1"})
    assert e2.prev_hash == e1.entry_hash
    rows = [
        {"seq": e.seq, "ts": e.ts, "actor": e.actor, "role": e.role, "action": e.action,
         "object_type": e.object_type, "object_id": e.object_id, "detail": e.detail,
         "prev_hash": e.prev_hash, "entry_hash": e.entry_hash}
        for e in pg_db.iter_audit()
    ]
    ok, bad = verify_chain(rows)
    assert ok and bad is None

    assert pg_db.delete_for_traces(["t1"]) == 1
    assert pg_db.get_entity("e" * 16) is None


def test_restore_request_roundtrip(pg_db):
    from datetime import datetime, timedelta, timezone

    from openagent_audit.vault.models import RestoreRequest, RestoreStatus

    now = datetime.now(timezone.utc)
    req = RestoreRequest(id="r" * 16, object_type="entity", object_id="e" * 16,
                         reason="争议处理", requested_by="bob",
                         status=RestoreStatus.PENDING, created_at=now)
    pg_db.insert_restore_request(req)
    got = pg_db.get_restore_request("r" * 16)
    assert got is not None and got.status is RestoreStatus.PENDING
    updated = pg_db.update_restore_request(
        "r" * 16, status=RestoreStatus.APPROVED, approver="carol",
        decided_at=now, reveal_expires_at=now + timedelta(minutes=10))
    assert updated.status is RestoreStatus.APPROVED
    assert len(pg_db.list_restore_requests(RestoreStatus.PENDING)) == 0


def test_privilege_split(pg_db):
    """The grant matrix from deploy/audit_db_init.sql, verified live."""
    import psycopg

    # agent_writer: INSERT-only on entity_ciphertext
    with psycopg.connect(_role_dsn("agent_writer", "change-me-agent")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO entity_ciphertext (entity_id, entity_type, ciphertext) "
                "VALUES (%s, %s, %s)",
                ("a" * 16, "PHONE_NUMBER", "CT-AGENT"),
            )
        conn.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM entity_ciphertext").fetchall()
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("INSERT INTO audit_log (actor, role, action) VALUES ('x','y','z')")
        conn.rollback()

    # audit_api: no ciphertext access whatsoever (structural no-bypass)
    with psycopg.connect(_role_dsn("audit_api", "change-me-api")) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM entity_ciphertext").fetchall()
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("INSERT INTO entity_ciphertext VALUES ('b','T','C')")
        conn.rollback()
        # restore workflow + audit appends work
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO restore_request (id, object_type, object_id, reason, requested_by, status) "
                "VALUES (%s, 'entity', 'e', 'r', 'bob', 'pending')",
                ("c" * 16,),
            )
            cur.execute(
                "INSERT INTO audit_log (actor, role, action, prev_hash, entry_hash) "
                "VALUES ('api','service','BOOT', %s, %s)",
                ("0" * 64, "f" * 64),
            )
        conn.commit()

    # decrypt_svc: the only role that reads ciphertext
    with psycopg.connect(_role_dsn("decrypt_svc", "change-me-decrypt")) as conn:
        with conn.cursor() as cur:
            assert cur.execute("SELECT ciphertext FROM entity_ciphertext LIMIT 1").fetchone() is not None
            cur.execute(
                "INSERT INTO audit_log (actor, role, action, prev_hash, entry_hash) "
                "VALUES ('svc','service','BOOT', %s, %s)",
                ("0" * 64, "e" * 64),
            )
        conn.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("INSERT INTO entity_ciphertext VALUES ('d','T','C')")
        conn.rollback()

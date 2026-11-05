"""Batch atomicity: a dropped batch must leave no ciphertext behind.

Reported: when field 1 of a batch was sealed and written but field 2 failed,
the batch was correctly withheld from Langfuse (fail-closed) — yet field 1's
ciphertext stayed in the vault permanently as an orphan row.

All entities in a payload are now collected by one ``protect_batch`` and
written in a single vault call, so either the whole batch persists or nothing
does.
"""

from __future__ import annotations

import sqlite3

import pytest

from openagent_audit.gateway.otlp import process_otlp_payload
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter

PHONE = "13812345678"


def _payload(texts: list[str]) -> dict:
    return {
        "resourceSpans": [{
            "resource": {"attributes": []},
            "scopeSpans": [{
                "scope": {"name": "OpenAgent.Engine"},
                "spans": [{
                    "traceId": "a" * 32,
                    "spanId": "1" * 16,
                    "name": "chat",
                    "attributes": [
                        {"key": f"gen_ai.prompt.{i}.content", "value": {"stringValue": t}}
                        for i, t in enumerate(texts)
                    ],
                }],
            }],
        }]
    }


def _run(payload, pipeline):
    return process_otlp_payload(
        payload,
        pipeline=pipeline,
        content_prefixes=("gen_ai.",),
        session_attrs=("openagent.conversation_id",),
        user_attrs=("openagent.user_id",),
        agent_attrs=("agent.id",),
    )


class _FailingVault:
    """Accepts the first write, then fails — simulating a partial batch."""

    def __init__(self, db_path, fail_after: int = 1):
        self._db_path = db_path
        self._fail_after = fail_after
        self.calls = 0

    def insert_entities(self, rows):
        self.calls += 1
        if self.calls > self._fail_after:
            raise RuntimeError("db down mid-batch")
        conn = sqlite3.connect(self._db_path)
        try:
            conn.executemany(
                "INSERT INTO entity_ciphertext "
                "(entity_id, entity_type, ciphertext, trace_id, session_id, created_at) "
                "VALUES (?,?,?,?,?,?)",
                [
                    (r["entity_id"], r["entity_type"], r["ciphertext"],
                     r.get("trace_id"), r.get("session_id"), "2026-10-20T00:00:00+00:00")
                    for r in rows
                ],
            )
            conn.commit()
        finally:
            conn.close()


def _row_count(db_path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM entity_ciphertext").fetchone()[0]
    finally:
        conn.close()


def test_single_write_per_batch(db, cipher):
    """Two PII fields in one payload produce exactly one vault write."""
    writes: list[list] = []

    class Counting:
        def insert_entities(self, rows):
            writes.append(list(rows))
            db.insert_entities(rows)

    pipeline = MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(Counting(), attempts=1))
    _run(_payload([f"call {PHONE}", "also 13900001111"]), pipeline)

    assert len(writes) == 1, f"expected one atomic write, got {len(writes)}"
    assert len(writes[0]) == 2, writes[0]


def test_failed_batch_leaves_no_ciphertext(tmp_path, keypair):
    """A batch that fails after its first field must persist nothing at all."""
    import pathlib

    from openagent_audit.crypto.envelope import RsaEnvelopeCipher
    from openagent_audit.crypto.keys import LocalKeyProvider, load_public_key
    from openagent_audit.vault.store import SQLiteAuditDatabase

    public_pem, private_pem = keypair
    cipher = RsaEnvelopeCipher(load_public_key(public_pem))
    db_path = tmp_path / "audit.db"
    # the schema comes from the real store so the vault table exists
    real = SQLiteAuditDatabase(db_path)

    vault = _FailingVault(db_path, fail_after=0)  # every write fails
    pipeline = MaskingPipeline(
        cipher=cipher, vault_writer=VaultWriter(vault, attempts=1)
    )

    with pytest.raises(RuntimeError):
        _run(_payload([f"call {PHONE}", "also 13900001111"]), pipeline)

    assert _row_count(db_path) == 0, "orphan ciphertext survived a failed batch"
    assert vault.calls == 1


def test_successful_batch_persists_every_entity(tmp_path, keypair):
    from openagent_audit.crypto.envelope import RsaEnvelopeCipher
    from openagent_audit.crypto.keys import load_public_key
    from openagent_audit.vault.store import SQLiteAuditDatabase

    public_pem, _ = keypair
    cipher = RsaEnvelopeCipher(load_public_key(public_pem))
    db_path = tmp_path / "audit.db"
    SQLiteAuditDatabase(db_path)

    pipeline = MaskingPipeline(
        cipher=cipher, vault_writer=VaultWriter(SQLiteAuditDatabase(db_path), attempts=1)
    )
    _run(_payload([f"call {PHONE}", "also 13900001111"]), pipeline)

    assert _row_count(db_path) == 2


def test_batch_failure_marks_nothing_partial(db, cipher):
    """If the write raises, the pipeline must not report success upward."""
    class Exploding:
        def insert_entities(self, rows):
            raise RuntimeError("boom")

    pipeline = MaskingPipeline(
        cipher=cipher, vault_writer=VaultWriter(Exploding(), attempts=1)
    )
    with pytest.raises(RuntimeError):
        _run(_payload([f"call {PHONE}"]), pipeline)


def test_protect_batch_context_skips_write_on_exception(db, cipher):
    """A caller that raises inside the batch writes nothing."""
    writes: list = []

    class Recording:
        def insert_entities(self, rows):
            writes.append(list(rows))

    pipeline = MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(Recording(), attempts=1))

    with pytest.raises(ValueError):
        with pipeline.batch(trace_id="t", session_id="s") as batch:
            batch.protect(f"call {PHONE}")
            raise ValueError("detector exploded")

    assert writes == [], writes
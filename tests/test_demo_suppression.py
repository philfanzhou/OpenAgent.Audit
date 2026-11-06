"""Demo-data auto-suppression: real data always wins over synthetic rows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from openagent_audit.config import Settings, UserEntry
from openagent_audit.services.audit_api import build_container
from openagent_audit.services.demo_seed import DEMO_SESSION_PREFIX, is_demo_session
from openagent_audit.tracing.trace_store import TraceRecord

PASSPHRASE = b"unit-test-passphrase"


def _settings(tmp_path, keypair):
    public_pem, private_pem = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir(exist_ok=True)
    (key_dir / "audit_private_key.pem").write_bytes(private_pem)
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    return Settings(
        audit_db_url=f"sqlite:///{(tmp_path / 'audit.db')}",
        service_token="svc-token-123",
        users=(UserEntry("tok-a", "alice", "auditor"),),
        local_private_key_path=str(key_dir / "audit_private_key.pem"),
        local_private_key_passphrase=PASSPHRASE.decode(),
        public_key_path=str(key_dir / "audit_public_key.pem"),
        trace_store="local",
        demo_seed=True,
    )


def _add_real_trace(store, trace_id="tr-real-1", session_id="sess-real-1"):
    store.upsert_trace(TraceRecord(
        trace_id=trace_id, session_id=session_id, user_id="usr_real",
        agent_tag="agent:prod", name="POST /agent/run",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
    ))


def test_is_demo_session():
    assert is_demo_session("sess-demo-1001")
    assert not is_demo_session("sess-real-1")


def test_all_demo_visible_when_no_real_data(tmp_path, keypair):
    container = build_container(_settings(tmp_path, keypair))
    sessions = container.trace_store.list_sessions()
    assert sessions and all(is_demo_session(s["session_id"]) for s in sessions)


def test_real_data_purges_demo(tmp_path, keypair):
    """Once OpenAgent delivers a real conversation the samples are deleted.

    Filtering alone left the demo rows in the store, where a stale page, a log
    archive or a later query could surface them again. After connecting to the
    platform the console must hold platform data only.
    """
    from fastapi.testclient import TestClient

    from openagent_audit.services.audit_api import create_audit_app

    settings = _settings(tmp_path, keypair)
    container = build_container(settings)  # seeds 26 demo sessions
    assert len(container.trace_store.list_sessions()) == 26

    # OpenAgent connects: a real conversation arrives
    _add_real_trace(container.trace_store)

    client = TestClient(create_audit_app(container))
    token = {"Authorization": "Bearer tok-a"}
    body = client.get("/v1/sessions", headers=token).json()

    assert body["total"] == 1
    assert body["sessions"][0]["session_id"] == "sess-real-1"

    # Physically gone, not merely hidden: nothing remains to resurface.
    remaining = container.trace_store.list_sessions()
    assert all(not is_demo_session(s["session_id"]) for s in remaining)
    assert len(remaining) == 1


def test_demo_is_kept_while_store_has_no_real_data(tmp_path, keypair):
    """A local demo store stays useful: samples are only purged once real data
    exists, otherwise the console would be empty for no reason."""
    settings = _settings(tmp_path, keypair)
    container = build_container(settings)

    assert len(container.trace_store.list_sessions()) == 26
    assert len(container.trace_store.list_traces()) == 26


def test_purge_is_idempotent_and_safe():
    from openagent_audit.services.demo_seed import purge_demo_data

    class Empty:
        def list_traces(self):
            return []

    # No store / empty store are no-ops rather than errors.
    assert purge_demo_data(Empty()) == 0
    assert purge_demo_data(object()) == 0


def test_seeding_skipped_when_only_real_data(tmp_path, keypair):
    from openagent_audit.services.demo_seed import seed_demo_data
    from openagent_audit.tracing.trace_store import LocalTraceStore
    from openagent_audit.vault.store import SQLiteAuditDatabase

    settings = _settings(tmp_path, keypair)
    store = LocalTraceStore()
    db = SQLiteAuditDatabase(tmp_path / "audit.db")
    _add_real_trace(store)
    assert seed_demo_data(settings, store, db) == 0
    assert not any(is_demo_session(t.session_id) for t in store.list_traces())

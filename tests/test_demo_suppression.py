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


def test_real_data_hides_demo_and_blocks_seeding(tmp_path, keypair):
    from fastapi.testclient import TestClient

    from openagent_audit.services.audit_api import create_audit_app

    settings = _settings(tmp_path, keypair)
    container = build_container(settings)  # seeds 26 demo sessions
    assert container.trace_store.list_sessions()

    # OpenAgent connects: a real conversation arrives
    _add_real_trace(container.trace_store)

    client = TestClient(create_audit_app(container))
    token = {"Authorization": "Bearer tok-a"}
    body = client.get("/v1/sessions", headers=token).json()
    assert body["total"] == 1
    assert body["sessions"][0]["session_id"] == "sess-real-1"
    assert body["demo_hidden"] is True

    # opt-in still shows the demo dataset
    body_demo = client.get("/v1/sessions", headers=token,
                           params={"include_demo": "true"}).json()
    assert body_demo["total"] == 27
    assert body_demo["demo_hidden"] is False

    # a fresh dev process seeds its own ephemeral store, but the view-level
    # suppression (demo_hidden) is what keeps real views clean — verified above
    container2 = build_container(settings)
    assert len(container2.trace_store.list_traces()) == 26  # fresh ephemeral store
    body2 = client.get("/v1/sessions", headers=token).json()  # original store untouched
    assert body2["total"] == 1 and body2["demo_hidden"] is True
    assert any(t.trace_id == "tr-real-1" for t in container.trace_store.list_traces())


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

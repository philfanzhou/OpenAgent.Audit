"""Demo-data auto-suppression: real data always wins over synthetic rows."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import httpx

from openagent_audit.config import Settings, UserEntry
from openagent_audit.services.audit_api import build_container
from openagent_audit.services.demo_seed import is_demo_session
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

    # Flipping pages afterwards must not touch the trace store's crawl path
    # again: the purge only runs when the index really holds demo rows.
    traces_calls = {"n": 0}
    real_list_traces = container.trace_store.list_traces

    def counting_list_traces(*a, **kw):
        traces_calls["n"] += 1
        return real_list_traces(*a, **kw)

    container.trace_store.list_traces = counting_list_traces  # type: ignore[method-assign]
    for page in (1, 2):
        assert client.get(f"/v1/sessions?page={page}", headers=token).status_code == 200
    assert traces_calls["n"] == 0, "demo purge re-scanned the store on a page flip"


def _langfuse_container(tmp_path, keypair, handler):
    """A production-shaped container: Langfuse-backed trace store behind a
    mocked v2 observations endpoint (counting every upstream call)."""
    import httpx

    from openagent_audit.services.audit_api import create_audit_app
    from openagent_audit.tracing.trace_store import LangfuseTraceStore

    calls = {"n": 0}

    def counting(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(counting), base_url="https://lf", auth=("pk", "sk"))
    store = LangfuseTraceStore("https://lf", "pk", "sk", client=client)
    # demo_seed only ever writes into a LocalTraceStore; swap it for Langfuse.
    settings = dataclasses.replace(_settings(tmp_path, keypair), demo_seed=False)
    container = build_container(settings)
    container.trace_store = store
    api = TestClient(create_audit_app(container))
    api.post("/ui/login", data={"token": "tok-a"}, follow_redirects=False)
    return api, store, calls


def test_langfuse_backed_page_flips_never_recrawl(tmp_path, keypair):
    """Production (Langfuse) mode: building the session index pages through
    every observation, so each page flip must be served from the cache.

    The demo purge used to run an *uncached* ``list_traces`` scan on every
    request — on a real Langfuse that is a multi-second full crawl for every
    paging click, which is exactly what the console felt like."""

    def handler(request: httpx.Request) -> httpx.Response:
        # No cursor -> one page is the whole deployment. Real OpenAgent
        # conversation, so there is nothing demo to purge.
        data = [
            {"id": "obs-1", "traceId": "t-1", "sessionId": "sess-real-1", "userId": "usr_real",
             "startTime": "2026-11-25T10:00:00Z", "tags": ["agent:prod"]},
        ]
        return httpx.Response(200, json={"data": data, "meta": {}})

    api, _, calls = _langfuse_container(tmp_path, keypair, handler)

    for query in ("?page=1", "", "?page=1"):  # page flips + a browser refresh
        body = api.get(f"/v1/sessions{query}").json()
        assert body["total"] == 1 and body["sessions"][0]["session_id"] == "sess-real-1"
    assert calls["n"] == 1, "each page flip must be served from the cached index"


def test_langfuse_demo_rows_are_purged_once_and_index_invalidated(tmp_path, keypair):
    """If demo rows ever reach a Langfuse-backed store next to real ones they
    are deleted, and the cached index is dropped so the next page flip does
    not keep serving the rows that were just deleted."""
    import httpx

    rows = [
        {"id": "obs-demo", "traceId": "tr-demo", "sessionId": "sess-demo-1001",
         "startTime": "2026-11-25T09:00:00Z", "tags": []},
        {"id": "obs-real", "traceId": "tr-real", "sessionId": "sess-real-1",
         "startTime": "2026-11-25T10:00:00Z", "tags": []},
    ]
    deletes: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            deleted = request.url.path.rsplit("/", 1)[-1]
            deletes.append(deleted)
            rows[:] = [r for r in rows if r["traceId"] != deleted]
            return httpx.Response(204)
        return httpx.Response(200, json={"data": list(rows), "meta": {}})

    api, _, _ = _langfuse_container(tmp_path, keypair, handler)

    body = api.get("/v1/sessions").json()
    assert deletes == ["tr-demo"], "demo trace must be deleted from Langfuse"
    assert [s["session_id"] for s in body["sessions"]] == ["sess-real-1"]

    # Second page flip: nothing left to purge, index rebuilt after the purge.
    assert api.get("/v1/sessions").json()["total"] == 1
    assert deletes == ["tr-demo"], "the purge must not repeat"


def test_gzip_compresses_large_responses(container):
    """The ~1 MB SPA bundle and the static CSS are gzipped; tiny replies are
    left alone. (The test client decompresses transparently, so only the
    header proves the encoding happened.)"""
    from fastapi.testclient import TestClient

    from openagent_audit.services.audit_api import create_audit_app

    client = TestClient(create_audit_app(container), headers={"Accept-Encoding": "gzip"})

    css = client.get("/static/bootstrap.min.css")
    assert css.status_code == 200
    assert css.headers.get("content-encoding") == "gzip"
    assert len(css.content) > 100_000

    small = client.get("/healthz")
    assert small.status_code == 200
    assert "content-encoding" not in small.headers


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

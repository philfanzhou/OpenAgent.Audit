"""Server-side pagination & search for sessions and the audit log.

All requests go through a real browser session: sign in as a platform user,
then step up to administrator where admin-only data (the audit log) is needed.
"""

from __future__ import annotations

import pytest

from openagent_audit.tracing.trace_store import ObservationRecord, TraceRecord
from datetime import datetime, timezone


@pytest.fixture()
def admin_client(api_client):
    api_client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)
    api_client.post(
        "/ui/admin/login",
        data={"username": "admin", "password": "admin@123456"},
        follow_redirects=False,
    )
    return api_client


@pytest.fixture()
def many_audits(admin_client, container):
    for i in range(25):
        container.audit.append(
            actor=f"user{i:02d}",
            role="service",
            action=f"ACTION_{i:02d}",
            object_type="thing",
            object_id=f"obj-{i:03d}",
        )
    return admin_client


def test_audit_log_paged(many_audits):
    body = many_audits.get("/v1/audit-log", params={"page": 1, "page_size": 10}).json()
    assert body["total"] >= 25
    assert len(body["entries"]) == 10
    assert body["page"] == 1 and body["page_size"] == 10

    page3 = many_audits.get("/v1/audit-log", params={"page": 3, "page_size": 10}).json()
    assert len(page3["entries"]) >= 5

    seqs1 = {e["seq"] for e in body["entries"]}
    seqs3 = {e["seq"] for e in page3["entries"]}
    assert not (seqs1 & seqs3)


def test_audit_log_search(many_audits):
    body = many_audits.get("/v1/audit-log", params={"q": "user07"}).json()
    assert body["total"] == 1
    assert body["entries"][0]["actor"] == "user07"

    wider = many_audits.get("/v1/audit-log", params={"q": "ACTION_1"}).json()
    assert wider["total"] == 10  # ACTION_10 .. ACTION_19


def test_audit_log_page_size_capped(many_audits):
    body = many_audits.get("/v1/audit-log", params={"page_size": 10000, "page": 0}).json()
    assert body["page_size"] <= 100


@pytest.fixture()
def many_sessions(container):
    for i in range(30):
        container.trace_store.upsert_trace(
            TraceRecord(
                trace_id=f"t-{i:03d}",
                session_id=f"sess-{i:03d}",
                user_id=f"usr_{i:03d}",
                agent_tag="agent:cs-bot" if i % 2 == 0 else "agent:other",
                name="POST /agent/run",
                timestamp=datetime(2026, 10, 20, tzinfo=timezone.utc),
                observations=(ObservationRecord(id="o", type="span", name="x"),),
            )
        )
    return container


def test_sessions_paged_and_searched(api_client, many_sessions):
    api_client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)

    first = api_client.get("/v1/sessions", params={"page": 1, "page_size": 10}).json()
    assert first["total"] == 30
    assert len(first["sessions"]) == 10

    second = api_client.get("/v1/sessions", params={"page": 2, "page_size": 10}).json()
    ids1 = {s["session_id"] for s in first["sessions"]}
    ids2 = {s["session_id"] for s in second["sessions"]}
    assert not (ids1 & ids2)

    found = api_client.get("/v1/sessions", params={"q": "sess-007"}).json()
    assert found["total"] == 1
    assert found["sessions"][0]["session_id"] == "sess-007"

    by_agent = api_client.get("/v1/sessions", params={"agent": "other"}).json()
    assert by_agent["total"] == 15


def test_sessions_browse_blocked_over_threshold(api_client, container):
    """Beyond the threshold, unconditional browsing demands a search."""
    from openagent_audit.services.audit_api import BROWSE_THRESHOLD, MAX_PAGES, MAX_VISIBLE

    # Start from an empty store so demo rows cannot mask the rule.
    store = container.trace_store
    if hasattr(store, "clear"):
        store.clear()
    else:
        for existing in list(store.list_traces()):
            store.delete_trace(existing.trace_id)

    for i in range(BROWSE_THRESHOLD + 5):
        container.trace_store.upsert_trace(
            TraceRecord(
                trace_id=f"t-{i:04d}",
                session_id=f"sess-{i:04d}",
                user_id="usr",
                agent_tag="agent:x",
                name="n",
                timestamp=datetime(2026, 10, 20, tzinfo=timezone.utc),
            )
        )

    api_client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)
    body = api_client.get("/v1/sessions").json()

    # Beyond the visible cap the console flags that a search is required, and
    # still serves the newest page rather than an empty one.
    assert body["browse_blocked"] is True
    assert len(body["sessions"]) == 10
    assert body["truncated"] is True
    assert body["max_visible"] == MAX_VISIBLE
    assert body["total_pages"] == MAX_PAGES

    # an explicit search is still served
    searched = api_client.get("/v1/sessions", params={"q": "sess-0001"}).json()
    assert searched["browse_blocked"] is False
    assert searched["total"] == 1


def test_paging_is_capped_at_ten_per_page_twenty_pages():
    """The paging policy is uniform: 10 rows, at most 20 pages."""
    from openagent_audit.services.audit_api import MAX_PAGES, MAX_VISIBLE, PAGE_SIZE

    assert PAGE_SIZE == 10
    assert MAX_PAGES == 20
    assert MAX_VISIBLE == 200
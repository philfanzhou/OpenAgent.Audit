"""Server-side pagination & search for sessions / restore requests / audit log."""

from __future__ import annotations

import pytest

from tests.test_audit_api import AUD, DEV, LEAD


@pytest.fixture()
def many_audits(api_client, container):
    audit = container.audit
    for i in range(25):
        audit.append(actor=f"user{i:02d}", role="service", action=f"ACTION_{i:02d}",
                     object_type="thing", object_id=f"obj-{i:03d}")
    return api_client


def test_audit_log_paged(many_audits):
    r = many_audits.get("/v1/audit-log", headers=AUD, params={"page": 1, "page_size": 10})
    body = r.json()
    assert r.status_code == 200
    assert body["total"] >= 25
    assert len(body["entries"]) == 10
    assert body["page"] == 1 and body["page_size"] == 10
    r2 = many_audits.get("/v1/audit-log", headers=AUD, params={"page": 3, "page_size": 10})
    assert len(r2.json()["entries"]) >= 5
    # pages do not overlap
    seqs1 = {e["seq"] for e in body["entries"]}
    seqs3 = {e["seq"] for e in r2.json()["entries"]}
    assert not (seqs1 & seqs3)


def test_audit_log_search(many_audits):
    r = many_audits.get("/v1/audit-log", headers=AUD, params={"q": "user07"})
    body = r.json()
    assert body["total"] == 1
    assert body["entries"][0]["actor"] == "user07"
    r2 = many_audits.get("/v1/audit-log", headers=AUD, params={"q": "ACTION_1"})
    assert r2.json()["total"] == 10  # LIKE %ACTION_1% matches ACTION_10..ACTION_19


def test_audit_log_page_size_capped(many_audits):
    r = many_audits.get("/v1/audit-log", headers=AUD, params={"page_size": 10000, "page": 0})
    assert r.json()["page_size"] <= 100
    assert r.json()["page"] == 1


@pytest.fixture()
def many_requests(api_client, container, pipeline):
    for i in range(12):
        entity_id = f"{i:016x}"
        container.db.insert_entities([
            {"entity_id": entity_id, "entity_type": "PHONE_NUMBER",
             "ciphertext": "ct", "trace_id": f"t{i}", "session_id": f"s{i}"},
        ])
        container.restore.request(
            actor="bob", role="compliance_lead", object_type="entity",
            object_id=entity_id, reason=f"调查 {i:02d} 号案件",
        )
    return api_client


def test_restore_requests_paged_and_searched(many_requests):
    r = many_requests.get("/v1/restore-requests", headers=AUD, params={"page": 2, "page_size": 10})
    body = r.json()
    assert body["total"] >= 12
    assert len(body["requests"]) == body["total"] - 10
    assert body["page"] == 2

    r2 = many_requests.get("/v1/restore-requests", headers=AUD, params={"q": "调查 07"})
    body2 = r2.json()
    assert body2["total"] == 1
    assert "07" in body2["requests"][0]["reason"]

    r3 = many_requests.get("/v1/restore-requests", headers=AUD,
                           params={"q": "不存在的理由xyz"})
    assert r3.json()["total"] == 0 and r3.json()["requests"] == []


def test_sessions_paged_and_searched(api_client, container, pipeline, trace_store):
    from datetime import datetime, timedelta, timezone
    from tests.conftest import seed_masked_conversation
    from openagent_audit.tracing.trace_store import TraceRecord

    container.trace_store = trace_store
    seed_masked_conversation(trace_store=trace_store, pipeline=pipeline,
                             trace_id="tr-p1", session_id="sess-alpha", user_id="usr_alpha")
    seed_masked_conversation(trace_store=trace_store, pipeline=pipeline,
                             trace_id="tr-p2", session_id="sess-beta", user_id="usr_beta")
    for i in range(12):
        trace_store.upsert_trace(TraceRecord(
            trace_id=f"tr-bulk-{i}", session_id=f"sess-bulk-{i:02d}", user_id="usr_bulk",
            agent_tag="agent:bulk", name="POST /agent/run",
            timestamp=datetime.now(timezone.utc) + timedelta(seconds=i),
        ))

    r = api_client.get("/v1/sessions", headers=DEV, params={"page": 1, "page_size": 10})
    body = r.json()
    assert body["total"] == 14
    assert len(body["sessions"]) == 10
    # ordered by most recent activity first (B: 最近活跃倒序)
    assert body["sessions"][0]["session_id"] == "sess-bulk-11"

    r2 = api_client.get("/v1/sessions", headers=DEV, params={"q": "alpha"})
    body2 = r2.json()
    assert body2["total"] == 1 and body2["sessions"][0]["session_id"] == "sess-alpha"

    r3 = api_client.get("/v1/sessions", headers=DEV, params={"q": "agent:bulk", "page": 2, "page_size": 10})
    body3 = r3.json()
    assert body3["total"] == 12 and len(body3["sessions"]) == 2


def test_sessions_browse_blocked_over_threshold(api_client, container, pipeline, trace_store):
    """A: beyond the browse threshold, unconditional listing is blocked until
    the caller narrows with q / from_ts / agent."""
    from datetime import datetime, timedelta, timezone
    from openagent_audit.tracing.trace_store import TraceRecord
    from openagent_audit.services.audit_api import BROWSE_THRESHOLD

    container.trace_store = trace_store
    now = datetime.now(timezone.utc)
    for i in range(BROWSE_THRESHOLD + 1):
        trace_store.upsert_trace(TraceRecord(
            trace_id=f"tr-{i:04d}", session_id=f"sess-{i:04d}", user_id="usr_x",
            agent_tag="agent:bulk", name="POST /agent/run",
            timestamp=now - timedelta(minutes=BROWSE_THRESHOLD + 1 - i),
        ))

    # unconditional browse is blocked
    r = api_client.get("/v1/sessions", headers=DEV)
    body = r.json()
    assert body["browse_blocked"] is True
    assert body["total"] == BROWSE_THRESHOLD + 1
    assert body["sessions"] == []

    # any filter unlocks results
    r2 = api_client.get("/v1/sessions", headers=DEV, params={"q": "sess-0001"})
    assert r2.json()["browse_blocked"] is False
    assert r2.json()["total"] == 1

    r3 = api_client.get("/v1/sessions", headers=DEV,
                        params={"from_ts": (now - timedelta(minutes=2)).isoformat()})
    assert r3.json()["browse_blocked"] is False
    assert r3.json()["total"] == 2  # the two most recent sessions

    r4 = api_client.get("/v1/sessions", headers=DEV, params={"agent": "bulk"})
    assert r4.json()["browse_blocked"] is False
    assert r4.json()["total"] == BROWSE_THRESHOLD + 1

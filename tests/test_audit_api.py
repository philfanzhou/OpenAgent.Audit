"""audit-api: auth, RBAC, endpoints, web UI."""

from __future__ import annotations

import pytest

from openagent_audit.services.audit_api import create_audit_app
from tests.conftest import VALID_BANK, seed_masked_conversation

AUD = {"Authorization": "Bearer tok-auditor"}
LEAD = {"Authorization": "Bearer tok-lead"}
LEAD2 = {"Authorization": "Bearer tok-lead2"}
DEV = {"Authorization": "Bearer tok-dev"}


@pytest.fixture()
def seeded(api_client, container, pipeline, trace_store):
    raw = seed_masked_conversation(trace_store=trace_store, pipeline=pipeline)
    container.trace_store = trace_store
    # api_client's app holds the container; rebuild routes read the same object
    return raw


def test_session_view_audited(api_client, seeded):
    """Every session view (API and UI) lands in the audit log (proposal §08)."""
    api_client.get("/v1/sessions/sess-1001", headers=AUD)
    api_client.get("/ui/sessions/sess-1001", cookies={"openagent_audit_session": "tok-auditor"})
    log = api_client.get("/v1/audit-log", headers=AUD).json()
    viewed = [e for e in log["entries"] if e["action"] == "SESSION_VIEWED"]
    assert len(viewed) == 2
    assert all(e["object_id"] == "sess-1001" for e in viewed)
    assert {e["actor"] for e in viewed} == {"alice"}


def test_trace_search_time_range_and_user(api_client, seeded):
    ok = api_client.get(
        "/v1/traces", headers=AUD,
        params={"user_id": "usr_10086342"},
    )
    assert ok.status_code == 200 and len(ok.json()["traces"]) == 1
    none = api_client.get("/v1/traces", headers=AUD, params={"user_id": "usr_other"})
    assert none.json()["traces"] == []
    bad = api_client.get("/v1/traces", headers=AUD, params={"from_ts": "not-a-date"})
    assert bad.status_code == 422


def test_metrics_prometheus_exposition(api_client, container):
    container.drop_monitor.record_batch_dropped()
    resp = api_client.get("/internal/metrics/prometheus", headers=AUD)
    assert resp.status_code == 200
    assert "openagent_audit_dropped_batches 1" in resp.text


def test_healthz(api_client):
    resp = api_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_missing_token_401(api_client, seeded):
    assert api_client.get("/v1/sessions").status_code == 401


def test_unknown_token_401(api_client, seeded):
    assert api_client.get("/v1/sessions", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_developer_denied_audit_plane(api_client, seeded):
    # developers use the Langfuse UI, not audit-web (proposal §08 role table)
    resp = api_client.get("/v1/sessions", headers=DEV)
    assert resp.status_code == 403


def test_auditor_views_masked_sessions(api_client, seeded):
    resp = api_client.get("/v1/sessions", headers=AUD)
    assert resp.status_code == 200
    sessions = resp.json()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["user_id"] == "usr_10086342"


def test_masked_trace_has_no_plaintext_or_ciphertext(api_client, container, seeded):
    resp = api_client.get("/v1/sessions/sess-1001", headers=AUD)
    assert resp.status_code == 200
    body = resp.text
    for secret in (seeded, "13812345678", "张伟", "zhangwei@example.com"):
        assert secret not in body
    assert "138****5678" in body
    assert "⟦" in body  # entity chips present
    # no stored ciphertext ever crosses the read side
    import sqlite3

    conn = sqlite3.connect(container.db._path)
    for (ct,) in conn.execute("SELECT ciphertext FROM entity_ciphertext"):
        assert ct not in body
    conn.close()


def test_audit_log_requires_auditor_or_lead(api_client, seeded):
    assert api_client.get("/v1/audit-log", headers=DEV).status_code == 403
    ok = api_client.get("/v1/audit-log?verify=true", headers=AUD)
    assert ok.status_code == 200
    assert ok.json()["verification"]["ok"] is True


def test_restore_flow_via_api(api_client, container, pipeline, seeded):
    result = pipeline.protect("电话13812345678", trace_id="t-api", session_id="sess-1001")
    entity_id = result.entities[0].entity_id

    # auditor cannot request
    r = api_client.post("/v1/restore-requests", headers=AUD, json={
        "object_type": "entity", "object_id": entity_id, "reason": "抽查"})
    assert r.status_code == 403

    # lead requests
    r = api_client.post("/v1/restore-requests", headers=LEAD, json={
        "object_type": "entity", "object_id": entity_id,
        "reason": "用户投诉核验", "trace_id": "t-api", "session_id": "sess-1001"})
    assert r.status_code == 201
    request_id = r.json()["id"]

    # four-eyes: self-approval blocked
    r = api_client.post(f"/v1/restore-requests/{request_id}/approve",
                        headers=LEAD, json={"comment": None})
    assert r.status_code == 403 and r.json()["detail"] == "four_eyes"

    # second lead approves
    r = api_client.post(f"/v1/restore-requests/{request_id}/approve",
                        headers=LEAD2, json={"comment": "同意"})
    assert r.status_code == 200 and r.json()["status"] == "approved"

    # reveal returns the plaintext exactly once-approved
    r = api_client.post(f"/v1/restore-requests/{request_id}/reveal", headers=LEAD2)
    assert r.status_code == 200
    assert r.json()["plaintext"] == "13812345678"

    # audit log records the whole chain
    log = api_client.get("/v1/audit-log?verify=true", headers=AUD).json()
    actions = [e["action"] for e in log["entries"]]
    assert {"RESTORE_REQUESTED", "RESTORE_APPROVED", "RESTORE_DECRYPTED", "RESTORE_VIEWED"} <= set(actions)
    assert log["verification"]["ok"] is True


def test_list_and_filter_restore_requests(api_client, container, pipeline, seeded):
    result = pipeline.protect("邮箱test@example.com", trace_id="t-f", session_id="s-f")
    entity_id = result.entities[0].entity_id
    api_client.post("/v1/restore-requests", headers=LEAD, json={
        "object_type": "entity", "object_id": entity_id, "reason": "r1"})
    listed = api_client.get("/v1/restore-requests", headers=AUD)
    assert listed.status_code == 200
    assert len(listed.json()["requests"]) >= 1
    by_status = api_client.get("/v1/restore-requests?status=pending", headers=AUD)
    assert all(r["status"] == "pending" for r in by_status.json()["requests"])


def test_request_unknown_entity_404(api_client):
    r = api_client.post("/v1/restore-requests", headers=LEAD, json={
        "object_type": "entity", "object_id": "f" * 16, "reason": "不存在"})
    assert r.status_code == 404


def test_metrics_endpoint(api_client, container):
    resp = api_client.get("/internal/metrics", headers=AUD)
    assert resp.status_code == 200
    assert "dropped_batches" in resp.json()["drops"]
    assert api_client.get("/internal/metrics", headers=DEV).status_code == 200


def test_media_content_download(api_client, container, cipher):
    from openagent_audit.media.objectstore import LocalObjectStore
    from openagent_audit.media.service import MediaService

    service = MediaService(cipher, container.object_store, bucket="agent-media")
    payload = b"\x89PNG-audit-photo-0987654321"
    ref = service.encrypt_and_upload(payload, "image/png")

    r = api_client.post("/v1/restore-requests", headers=LEAD, json={
        "object_type": "media", "object_id": ref.key, "reason": "核查截图"})
    request_id = r.json()["id"]
    api_client.post(f"/v1/restore-requests/{request_id}/approve", headers=LEAD2, json={})

    content = api_client.get(f"/v1/restore-requests/{request_id}/content", headers=LEAD)
    assert content.status_code == 200
    assert content.content == payload
    assert content.headers["content-type"].startswith("application/octet-stream")


def test_web_ui_login_and_browse(api_client, seeded):
    # unauthenticated redirect to login
    r = api_client.get("/ui/sessions", follow_redirects=False)
    assert r.status_code in (302, 307)

    r = api_client.post("/ui/login", data={"token": "wrong"}, follow_redirects=False)
    assert r.status_code == 401

    r = api_client.post("/ui/login", data={"token": "tok-auditor"}, follow_redirects=False)
    assert r.status_code == 302 and "/ui/sessions" in r.headers["location"]

    r = api_client.get("/ui/sessions", cookies={"openagent_audit_session": "tok-auditor"})
    assert r.status_code == 200
    assert "usr_10086342" in r.text

    detail = api_client.get("/ui/sessions/sess-1001", cookies={"openagent_audit_session": "tok-auditor"})
    assert detail.status_code == 200
    assert "138****5678" in detail.text and seeded not in detail.text

    log = api_client.get("/ui/audit-log", cookies={"openagent_audit_session": "tok-auditor"})
    assert log.status_code == 200 and "哈希链完整" in log.text

    requests_page = api_client.get("/ui/requests", cookies={"openagent_audit_session": "tok-lead"})
    assert requests_page.status_code == 200


def test_web_ui_approval_flow(api_client, container, pipeline, seeded):
    result = pipeline.protect("电话13900001111", trace_id="t-ui", session_id="s-ui")
    entity_id = result.entities[0].entity_id
    api_client.post("/v1/restore-requests", headers=LEAD, json={
        "object_type": "entity", "object_id": entity_id, "reason": "UI 核验"})

    page = api_client.get("/ui/requests", cookies={"openagent_audit_session": "tok-lead2"})
    # lead2 is not the requester -> approve/reject buttons are offered
    assert "批准" in page.text and "驳回" in page.text

    # self-approval via UI is blocked
    reqs = api_client.get("/v1/restore-requests", headers=LEAD).json()["requests"]
    (pending,) = [r for r in reqs if r["status"] == "pending"]
    r = api_client.post(f"/ui/requests/{pending['id']}/decide",
                        data={"decision": "approve", "comment": ""},
                        cookies={"openagent_audit_session": "tok-lead"}, follow_redirects=False)
    assert r.status_code == 403

    # second lead approves via UI then reveals via API
    r = api_client.post(f"/ui/requests/{pending['id']}/decide",
                        data={"decision": "approve", "comment": ""},
                        cookies={"openagent_audit_session": "tok-lead2"}, follow_redirects=False)
    assert r.status_code == 302
    reveal = api_client.post(f"/ui/requests/{pending['id']}/reveal",
                             cookies={"openagent_audit_session": "tok-lead2"})
    assert reveal.status_code == 200 and reveal.json()["plaintext"] == "13900001111"


def test_ui_reveal_json_payload(api_client, container, pipeline, seeded):
    result = pipeline.protect(f"卡号{VALID_BANK}", trace_id="t-ui2", session_id="s-ui2")
    entity_id = result.entities[0].entity_id
    api_client.post("/v1/restore-requests", headers=LEAD, json={
        "object_type": "entity", "object_id": entity_id, "reason": "UI 核验 2"})
    (pending,) = [r for r in api_client.get("/v1/restore-requests", headers=LEAD).json()["requests"]
                  if r["status"] == "pending"]
    api_client.post(f"/v1/restore-requests/{pending['id']}/approve", headers=LEAD2, json={})
    reveal = api_client.post(f"/ui/requests/{pending['id']}/reveal",
                             cookies={"openagent_audit_session": "tok-lead2"})
    assert reveal.status_code == 200
    assert "plaintext" in reveal.json()

"""Trace stores: local semantics + Langfuse public-API adapter."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from openagent_audit.tracing.trace_store import (
    LangfuseTraceStore,
    LocalTraceStore,
    ObservationRecord,
    TraceRecord,
)

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def trace(tid: str, session: str, user: str, ts: datetime = NOW) -> TraceRecord:
    return TraceRecord(
        trace_id=tid, session_id=session, user_id=user, agent_tag="agent:cs-bot",
        name="POST /agent/run", timestamp=ts,
        observations=(ObservationRecord(id="o1", type="span", name="接收请求", input="⟦PHONE_NUMBER#x|138****5678⟧"),),
    )


class TestLocalTraceStore:
    def test_upsert_get_list(self):
        store = LocalTraceStore()
        store.upsert_trace(trace("t1", "s1", "u1"))
        store.upsert_trace(trace("t2", "s1", "u2"))
        store.upsert_trace(trace("t3", "s2", "u1"))
        assert store.get_trace("t1").trace_id == "t1"
        assert [t.trace_id for t in store.list_traces(session_id="s1")] == ["t1", "t2"]
        assert {t.user_id for t in store.list_traces(user_id="u1")} == {"u1"}
        assert store.get_trace("nope") is None

    def test_sessions_aggregation(self):
        store = LocalTraceStore()
        store.upsert_trace(trace("t1", "s1", "u1"))
        store.upsert_trace(trace("t2", "s1", "u1", NOW + timedelta(minutes=5)))
        sessions = store.list_sessions()
        (s,) = sessions
        assert s["session_id"] == "s1" and s["trace_count"] == 2
        assert s["agent_tags"] == ["agent:cs-bot"]
        assert s["last_ts"] == NOW + timedelta(minutes=5)

    def test_delete_older_than(self):
        store = LocalTraceStore()
        store.upsert_trace(trace("old", "s", "u", NOW - timedelta(days=100)))
        store.upsert_trace(trace("new", "s", "u", NOW - timedelta(days=1)))
        expired = store.delete_older_than(NOW - timedelta(days=90))
        assert expired == ["old"]
        assert store.get_trace("old") is None
        assert store.get_trace("new") is not None

    def test_list_traces_time_range(self):
        store = LocalTraceStore()
        store.upsert_trace(trace("early", "s", "u", NOW - timedelta(days=5)))
        store.upsert_trace(trace("late", "s", "u", NOW + timedelta(days=5)))
        got = store.list_traces(from_ts=NOW - timedelta(days=1), to_ts=NOW + timedelta(days=1))
        assert [t.trace_id for t in got] == []
        got = store.list_traces(from_ts=NOW - timedelta(days=6), to_ts=NOW)
        assert [t.trace_id for t in got] == ["early"]


class TestLangfuseTraceStore:
    def test_list_and_delete_via_mock_api(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            captured["params"] = dict(request.url.params)
            captured["auth"] = request.headers.get("Authorization")
            if request.method == "GET":
                return httpx.Response(200, json={"data": [{"id": "t-1"}, {"id": "t-2"}]})
            return httpx.Response(204)

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport, base_url="https://lf.example", auth=("pk", "sk"))
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client)

        rows = store.list_traces(session_id="s1", user_id="u1")
        assert [r["id"] for r in rows] == ["t-1", "t-2"]
        assert captured["path"] == "/api/public/traces"
        assert captured["params"]["sessionId"] == "s1"
        assert captured["params"]["userId"] == "u1"
        assert captured["auth"].startswith("Basic ")

        deleted = store.delete_older_than(NOW)
        assert deleted == ["t-1", "t-2"]

    def test_time_range_params_forwarded(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json={"data": []})

        client = httpx.Client(
            transport=httpx.MockTransport(handler), base_url="https://lf.example", auth=("pk", "sk")
        )
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client)
        store.list_traces(from_ts=NOW - timedelta(minutes=1), to_ts=NOW)
        assert "fromTimestamp" in captured["params"]
        assert "toTimestamp" in captured["params"]

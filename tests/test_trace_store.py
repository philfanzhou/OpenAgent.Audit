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
        captured: dict = {"get_paths": [], "deletes": []}
        # v2 observations: two traces, one observation each. The store groups
        # them by traceId and reconstructs the legacy trace shape.
        remaining = [
            {"id": "obs-1", "traceId": "t-1", "startTime": "2026-10-20T10:00:00Z"},
            {"id": "obs-2", "traceId": "t-2", "startTime": "2026-10-20T10:01:00Z"},
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                captured["get_paths"].append(request.url.path)
                captured["params"] = dict(request.url.params)
                captured["auth"] = request.headers.get("Authorization")
                # No cursor returned -> terminates the crawl after one page.
                return httpx.Response(200, json={"data": list(remaining), "meta": {}})
            captured["deletes"].append(request.url.path)
            deleted_id = request.url.path.rsplit("/", 1)[-1]
            remaining[:] = [r for r in remaining if r["traceId"] != deleted_id]
            return httpx.Response(204)

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport, base_url="https://lf.example", auth=("pk", "sk"))
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client)

        rows = store.list_traces(session_id="s1", user_id="u1", with_observations=False)
        assert [r.trace_id for r in rows] == ["t-1", "t-2"]
        assert captured["get_paths"][0] == "/api/public/v2/observations"
        assert captured["params"]["sessionId"] == "s1"
        assert captured["params"]["userId"] == "u1"
        assert captured["auth"].startswith("Basic ")

        deleted = store.delete_older_than(NOW)
        assert sorted(deleted) == ["t-1", "t-2"]
        # both traces deleted (paged to exhaustion rather than stopping early)
        assert len(captured["deletes"]) == 2

    def test_list_trace_dicts_returns_raw_rows(self):
        def handler(request: httpx.Request) -> httpx.Response:
            # One observation -> one reconstructed trace dict with id=t-1.
            data = [{"id": "obs-1", "traceId": "t-1"}]
            return httpx.Response(200, json={"data": data, "meta": {}})

        client = httpx.Client(
            transport=httpx.MockTransport(handler), base_url="https://lf.example", auth=("pk", "sk")
        )
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client)
        rows = store.list_trace_dicts()
        assert len(rows) == 1
        assert rows[0]["id"] == "t-1"
        assert rows[0]["traceId"] == "t-1"

    def test_session_detail_renders_through_audit_api(self):
        """Production mode (AUDIT_TRACE_STORE=langfuse) must serve the session
        detail page: v2 observation rows are normalised into TraceRecord, so
        audit_api._trace_dict never meets a raw API dict."""

        def handler(request: httpx.Request) -> httpx.Response:
            # v2 returns the observation inline (io/model/usage fields).
            data = [{
                "id": "obs-1",
                "traceId": "t-1",
                "sessionId": "sess-1",
                "userId": "usr_1",
                "traceName": "POST /api/v1/agent/chat",
                "startTime": "2026-10-20T10:00:00Z",
                "type": "GENERATION",
                "name": "chat",
                "tags": ["agent:cs-bot"],
                "input": {"messages": [{"role": "user",
                                        "content": "电话 ⟦PHONE_NUMBER#ab|138****5678⟧"}]},
                "output": {"choices": [{"message": {"content": "好的"}}]},
                "model": "glm-4",
                "usageDetails": {"input": 10, "output": 5},
            }]
            return httpx.Response(200, json={"data": data, "meta": {}})

        client = httpx.Client(
            transport=httpx.MockTransport(handler), base_url="https://lf.example", auth=("pk", "sk")
        )
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client)

        from openagent_audit.services.audit_api import _trace_dict

        payload = _trace_dict(store.list_traces(session_id="sess-1", with_observations=True)[0])
        assert payload["trace_id"] == "t-1"
        assert payload["session_id"] == "sess-1"
        assert payload["user_id"] == "usr_1"
        assert payload["agent_tag"] == "agent:cs-bot"
        assert payload["timestamp"].startswith("2026-10-20T10:00:00")
        (obs,) = payload["observations"]
        assert obs["id"] == "obs-1" and obs["model"] == "glm-4"
        # structured input/output are flattened to renderable text, masks intact
        assert "⟦PHONE_NUMBER#ab|138****5678⟧" in obs["input"]
        assert "好的" in obs["output"]
        assert isinstance(obs["input"], str)

    def test_missing_fields_normalise_to_empty_strings(self):
        from openagent_audit.tracing.trace_store import normalize_langfuse_trace

        record = normalize_langfuse_trace({})
        assert record.trace_id == "" and record.session_id == ""
        assert record.timestamp is None and record.observations == ()

    def test_time_range_params_forwarded(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json={"data": [], "meta": {}})

        client = httpx.Client(
            transport=httpx.MockTransport(handler), base_url="https://lf.example", auth=("pk", "sk")
        )
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client)
        store.list_traces(from_ts=NOW - timedelta(minutes=1), to_ts=NOW)
        # v2 uses fromStartTime/toStartTime (not fromTimestamp/toTimestamp)
        assert "fromStartTime" in captured["params"]
        assert "toStartTime" in captured["params"]

    def test_list_sessions_aggregates_and_paginates(self):
        """list_sessions aggregates the cursor-paged v2 observations API into
        session rows. v2 keeps returning a cursor until the end, even across
        empty pages, so we must follow the cursor (not terminate on a short
        page)."""
        # page 1: 100 bulk observations (each its own trace/session) + 2 for s1
        page1 = [
            {"id": f"obs-b{i}", "traceId": f"b{i}", "sessionId": f"bulk-{i}",
             "userId": "u0", "startTime": None, "tags": []}
            for i in range(100)
        ] + [
            {"id": "obs-t1", "traceId": "t1", "sessionId": "s1", "userId": "u1",
             "startTime": "2026-10-20T10:00:00Z", "tags": ["agent:cs-bot"]},
            {"id": "obs-t2", "traceId": "t2", "sessionId": "s1", "userId": "u1",
             "startTime": "2026-10-20T10:05:00Z", "tags": "agent:cs-bot"},
        ]
        # page 2: one observation for s2, plus a cursor to page 3
        page2 = [
            {"id": "obs-t3", "traceId": "t3", "sessionId": "s2", "userId": "u2",
             "startTime": "2026-10-20T11:00:00Z", "tags": []},
        ]
        # page 3: empty data but still carries a cursor (v4 can do this); the
        # store must keep paging. page 4: empty, no cursor -> end.
        pages = [
            (page1, "cursor-after-1"),
            (page2, "cursor-after-2"),
            ([], "cursor-after-3"),
            ([], None),
        ]
        seen_cursors: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            cursor = request.url.params.get("cursor")
            seen_cursors.append(cursor)
            idx = 0 if cursor is None else min(int(cursor.split("-")[-1]), len(pages) - 1)
            data, next_cursor = pages[idx]
            return httpx.Response(200, json={"data": data, "meta": {"cursor": next_cursor}})

        client = httpx.Client(
            transport=httpx.MockTransport(handler), base_url="https://lf.example", auth=("pk", "sk")
        )
        store = LangfuseTraceStore("https://lf.example", "pk", "sk", client=client)
        rows = store.list_sessions()
        # 4 requests: initial (no cursor) + 3 follow-ups
        assert len(seen_cursors) == 4
        assert len(rows) == 102  # 100 bulk + s1 + s2
        by_id = {r["session_id"]: r for r in rows}
        assert by_id["s1"]["trace_count"] == 2
        assert by_id["s1"]["first_ts"] == datetime(2026, 10, 20, 10, 0, tzinfo=timezone.utc)
        assert by_id["s1"]["last_ts"] == datetime(2026, 10, 20, 10, 5, tzinfo=timezone.utc)
        assert by_id["s1"]["agent_tags"] == ["agent:cs-bot"]  # string tag coerced
        assert by_id["s2"]["trace_count"] == 1

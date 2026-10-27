"""Trace stores.

The proposal keeps Langfuse as the trace master data. ``LangfuseTraceStore``
proxies the Langfuse public API for audit-side reads and retention deletes;
``LocalTraceStore`` is a self-contained in-memory stand-in so the audit plane
runs (and is fully tested) without a live Langfuse.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, Sequence


@dataclass(frozen=True)
class ObservationRecord:
    id: str
    type: str  # "span" | "generation"
    name: str
    input: object = None
    output: object = None
    metadata: dict = field(default_factory=dict)
    model: str | None = None
    usage: dict = field(default_factory=dict)
    latency_ms: int | None = None


@dataclass(frozen=True)
class TraceRecord:
    trace_id: str
    session_id: str
    user_id: str
    agent_tag: str
    name: str
    timestamp: datetime
    observations: tuple[ObservationRecord, ...] = ()


class TraceStore(Protocol):
    def upsert_trace(self, trace: TraceRecord) -> None: ...
    def get_trace(self, trace_id: str) -> TraceRecord | None: ...
    def list_traces(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
    ) -> list[TraceRecord]: ...
    def delete_trace(self, trace_id: str) -> None: ...
    def delete_older_than(self, cutoff: datetime) -> list[str]: ...
    def list_sessions(self) -> list[dict]: ...


class LocalTraceStore:
    """In-memory trace store standing in for Langfuse in dev/tests."""

    def __init__(self) -> None:
        self._traces: dict[str, TraceRecord] = {}
        self._lock = threading.Lock()

    def upsert_trace(self, trace: TraceRecord) -> None:
        with self._lock:
            self._traces[trace.trace_id] = trace

    def get_trace(self, trace_id: str) -> TraceRecord | None:
        with self._lock:
            return self._traces.get(trace_id)

    def list_traces(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
    ) -> list[TraceRecord]:
        with self._lock:
            traces = list(self._traces.values())
        if session_id is not None:
            traces = [t for t in traces if t.session_id == session_id]
        if user_id is not None:
            traces = [t for t in traces if t.user_id == user_id]
        if from_ts is not None:
            traces = [t for t in traces if t.timestamp >= from_ts]
        if to_ts is not None:
            traces = [t for t in traces if t.timestamp < to_ts]
        return sorted(traces, key=lambda t: t.timestamp)

    def delete_trace(self, trace_id: str) -> None:
        with self._lock:
            self._traces.pop(trace_id, None)

    def delete_older_than(self, cutoff: datetime) -> list[str]:
        with self._lock:
            expired = [t.trace_id for t in self._traces.values() if t.timestamp < cutoff]
            for trace_id in expired:
                del self._traces[trace_id]
        return expired

    def list_sessions(self) -> list[dict]:
        with self._lock:
            traces = list(self._traces.values())
        sessions: dict[str, dict] = {}
        for t in sorted(traces, key=lambda t: t.timestamp):
            entry = sessions.setdefault(
                t.session_id,
                {"session_id": t.session_id, "user_id": t.user_id, "trace_count": 0,
                 "first_ts": t.timestamp, "last_ts": t.timestamp, "agent_tags": set()},
            )
            entry["trace_count"] += 1
            entry["last_ts"] = max(entry["last_ts"], t.timestamp)
            entry["agent_tags"].add(t.agent_tag)
        return [
            {
                "session_id": s["session_id"],
                "user_id": s["user_id"],
                "trace_count": s["trace_count"],
                "first_ts": s["first_ts"],
                "last_ts": s["last_ts"],
                "agent_tags": sorted(s["agent_tags"]),
            }
            for s in sessions.values()
        ]


class LangfuseTraceStore:
    """Langfuse public-API adapter (reads + retention deletes only).

    Audit-side reads never touch raw prompt storage beyond what Langfuse
    already exposes — and thanks to the export hook, that data only ever
    contained ``⟦TYPE#id|mask⟧`` placeholders in the first place.
    """

    def __init__(self, base_url: str, public_key: str, secret_key: str, client=None) -> None:
        if client is not None:
            self._client = client
        else:
            import httpx

            self._client = httpx.Client(
                base_url=base_url.rstrip("/"),
                auth=(public_key, secret_key),
                timeout=15.0,
            )

    def list_traces(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
    ) -> list[dict]:
        """Langfuse API is the source of truth; retrieval stays limited to
        userId / sessionId / time range (proposal §08 检索范围 — no reverse
        lookup by phone number or ID card)."""
        from datetime import timezone

        params: dict[str, str] = {}
        if session_id:
            params["sessionId"] = session_id
        if user_id:
            params["userId"] = user_id
        if from_ts is not None:
            params["fromTimestamp"] = from_ts.astimezone(timezone.utc).isoformat()
        if to_ts is not None:
            params["toTimestamp"] = to_ts.astimezone(timezone.utc).isoformat()
        resp = self._client.get("/api/public/traces", params=params)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def list_sessions(self, from_ts: datetime | None = None, to_ts: datetime | None = None) -> list[dict]:
        """Aggregate sessions from the Langfuse traces API (paged). Mirrors
        ``LocalTraceStore.list_sessions`` so the audit-web session list works
        in production mode too."""
        from datetime import timezone

        sessions: dict[str, dict] = {}
        page, page_size = 1, 100
        while True:
            params: dict[str, object] = {"page": page, "limit": page_size}
            if from_ts is not None:
                params["fromTimestamp"] = from_ts.astimezone(timezone.utc).isoformat()
            if to_ts is not None:
                params["toTimestamp"] = to_ts.astimezone(timezone.utc).isoformat()
            resp = self._client.get("/api/public/traces", params=params)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            for t in data:
                sid = t.get("sessionId") or ""
                entry = sessions.setdefault(
                    sid,
                    {"session_id": sid, "user_id": t.get("userId") or "", "trace_count": 0,
                     "first_ts": None, "last_ts": None, "agent_tags": set()},
                )
                entry["trace_count"] += 1
                raw_ts = t.get("timestamp")
                if raw_ts:
                    try:
                        parsed = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                    except ValueError:
                        parsed = None
                    if parsed is not None:
                        entry["first_ts"] = min(entry["first_ts"] or parsed, parsed)
                        entry["last_ts"] = max(entry["last_ts"] or parsed, parsed)
                tags = t.get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                entry["agent_tags"].update(tags)
            if len(data) < page_size or page >= 100:  # hard cap: 10k traces
                break
            page += 1
        return [
            {
                "session_id": s["session_id"],
                "user_id": s["user_id"],
                "trace_count": s["trace_count"],
                "first_ts": s["first_ts"],
                "last_ts": s["last_ts"],
                "agent_tags": sorted(s["agent_tags"]),
            }
            for s in sessions.values()
        ]

    def delete_trace(self, trace_id: str) -> None:
        resp = self._client.delete(f"/api/public/traces/{trace_id}")
        resp.raise_for_status()

    def delete_older_than(self, cutoff: datetime) -> list[str]:
        from datetime import timezone

        resp = self._client.get(
            "/api/public/traces",
            params={"toTimestamp": cutoff.astimezone(timezone.utc).isoformat()},
        )
        resp.raise_for_status()
        ids = [t["id"] for t in resp.json().get("data", [])]
        for trace_id in ids:
            self.delete_trace(trace_id)
        return ids

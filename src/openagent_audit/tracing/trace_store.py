"""Trace stores.

The proposal keeps Langfuse as the trace master data. ``LangfuseTraceStore``
proxies the Langfuse public API for audit-side reads and retention deletes;
``LocalTraceStore`` is a self-contained in-memory stand-in so the audit plane
runs (and is fully tested) without a live Langfuse.
"""

from __future__ import annotations

import json
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
    timestamp: datetime | None
    observations: tuple[ObservationRecord, ...] = ()


def _parse_timestamp(raw) -> datetime | None:
    if isinstance(raw, datetime):
        return raw
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _stringify_io(value, depth: int = 0):
    """Flatten a Langfuse ``input``/``output`` value into something a Jinja
    template can render, without ever inventing text that was not stored.

    Langfuse returns the observed input/output as JSON objects; the audit-web
    templates (and the JSON API) expect a scalar. Objects are re-serialised as
    pretty JSON, base64 media placeholders are kept verbatim, and deeply
    nested structures are truncated rather than blowing up the page.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if depth >= 8:
        return "…"
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, default=str)
    except (TypeError, ValueError):
        return str(value)


def normalize_langfuse_trace(row: dict) -> TraceRecord:
    """Map one Langfuse public-API trace row onto :class:`TraceRecord`.

    Langfuse field names (``id``/``sessionId``/``userId``/``tags``) differ from
    the audit-domain ones, and ids may arrive base64-encoded depending on the
    API version. Normalising here keeps every caller — audit-api, the web UI,
    retention — on one shape.
    """
    tags = row.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    tags = [t for t in tags if isinstance(t, str)]
    agent_tag = next((t for t in tags if t.startswith("agent:")), tags[0] if tags else "")

    observations: list[ObservationRecord] = []
    for obs in row.get("observations") or []:
        if isinstance(obs, dict):
            observations.append(_observation_from_dict(obs))
        # A bare string is an observation *id*: the trace-list endpoint does not
        # embed observation bodies, only ids. Callers that need content must
        # fetch detail per trace (see LangfuseTraceStore.get_trace_detail);
        # skipping bare ids silently produced empty session pages.

    return TraceRecord(
        trace_id=str(row.get("traceId") or row.get("id") or ""),
        session_id=str(row.get("sessionId") or ""),
        user_id=str(row.get("userId") or ""),
        agent_tag=agent_tag,
        name=str(row.get("name") or ""),
        timestamp=_parse_timestamp(row.get("timestamp")),
        observations=tuple(observations),
    )


def _observation_from_dict(obs: dict) -> ObservationRecord:
    return ObservationRecord(
        id=str(obs.get("id") or ""),
        type=str(obs.get("type") or "span"),
        name=str(obs.get("name") or ""),
        input=_stringify_io(obs.get("input")),
        output=_stringify_io(obs.get("output")),
        metadata=obs.get("metadata") if isinstance(obs.get("metadata"), dict) else {},
        model=obs.get("model"),
        usage=obs.get("usage") if isinstance(obs.get("usage"), dict) else {},
        latency_ms=obs.get("latency") if isinstance(obs.get("latency"), (int, float)) else None,
    )


class TraceStore(Protocol):
    def upsert_trace(self, trace: TraceRecord) -> None: ...
    def get_trace(self, trace_id: str) -> TraceRecord | None: ...
    def list_traces(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        *,
        with_observations: bool = False,
        max_detail_fetches: int = 50,
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
        *,
        with_observations: bool = False,
        max_detail_fetches: int = 50,
    ) -> list[TraceRecord]:
        # The local store holds complete records, so `with_observations` and
        # `max_detail_fetches` are accepted for parity with the Langfuse store
        # (no detail round trips exist here) and ignored.
        del with_observations, max_detail_fetches
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

    ``list_traces`` returns :class:`TraceRecord` objects (never the raw API
    dicts) so audit-api renders identically regardless of which store backs
    it; the raw Langfuse rows stay available through ``list_trace_dicts`` for
    callers that need fields the normalised record drops.
    """

    def __init__(
        self, base_url: str, public_key: str, secret_key: str,
        client=None, tls: dict | None = None,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            import httpx

            self._client = httpx.Client(
                base_url=base_url.rstrip("/"),
                auth=(public_key, secret_key),
                timeout=15.0,
                **(tls or {}),
            )

    def list_trace_dicts(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        *,
        page_size: int = 100,
        max_pages: int | None = None,
    ) -> list[dict]:
        """Langfuse API is the source of truth; retrieval stays limited to
        userId / sessionId / time range (proposal §08 检索范围 — no reverse
        lookup by phone number or ID card).

        Pages until the API returns a short page. Previously only the first
        page was fetched, so any deployment with more than ``limit`` traces in
        range silently served a truncated view (and retention deleted only the
        first page). ``max_pages`` bounds the work for callers that only need
        a sample; ``None`` means "page to the end".
        """
        from datetime import timezone

        rows: list[dict] = []
        page = 1
        while True:
            params: dict[str, object] = {"page": page, "limit": page_size}
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
            data = resp.json().get("data", []) or []
            rows.extend(data)

            # Terminate on an empty page, not on "shorter than what we asked
            # for": a Langfuse build with a server-side page cap returns fewer
            # rows than requested while more pages remain, which would
            # silently truncate the result (and the retention sweep).
            if not data:
                break
            if max_pages is not None and page >= max_pages:
                break
            page += 1

        return rows

    def list_traces(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        *,
        with_observations: bool = False,
        max_detail_fetches: int = 50,
    ) -> list[TraceRecord]:
        """List traces, optionally filling in observation bodies.

        ``with_observations`` defaults to **False**: the list endpoint returns
        bare observation ids, so fetching bodies costs one detail request per
        trace. Audit search results are a summary view; only the session-detail
        page needs bodies, and it passes ``with_observations=True`` with a bound
        (``max_detail_fetches``) so a 1000-trace session cannot issue 1000
        sequential round trips.
        """
        rows = self.list_trace_dicts(
            session_id=session_id, user_id=user_id, from_ts=from_ts, to_ts=to_ts
        )
        records = [normalize_langfuse_trace(row) for row in rows]

        if with_observations:
            budget = max_detail_fetches
            enriched: list[TraceRecord] = []
            for record in records:
                if record.observations or budget <= 0:
                    enriched.append(record)
                    continue
                budget -= 1
                enriched.append(self._with_observations(record))
            records = enriched

        return sorted(
            (r for r in records if r.timestamp is not None),
            key=lambda r: r.timestamp,
        )

    def _with_observations(self, record: TraceRecord) -> TraceRecord:
        if record.observations:
            return record
        try:
            detail = self.get_trace_detail(record.trace_id)
        except Exception:  # noqa: BLE001 - one bad trace must not break the page
            return record
        if not detail or not detail.observations:
            return record
        return TraceRecord(
            trace_id=record.trace_id,
            session_id=record.session_id,
            user_id=record.user_id,
            agent_tag=record.agent_tag,
            name=record.name,
            timestamp=record.timestamp,
            observations=detail.observations,
        )

    def get_trace_detail(self, trace_id: str) -> TraceRecord | None:
        """Fetch one trace with its observation bodies from the detail API."""
        resp = self._client.get(f"/api/public/traces/{trace_id}")
        resp.raise_for_status()
        try:
            row = resp.json()
        except ValueError:
            return None
        if not isinstance(row, dict):
            return None
        return normalize_langfuse_trace(row)

    def list_sessions(
        self,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        *,
        max_pages: int = 1000,
    ) -> list[dict]:
        """Aggregate sessions from the Langfuse traces API (paged).

        Time filtering is pushed down to the API (``fromTimestamp`` /
        ``toTimestamp``) so the server does the work; previously it was applied
        client-side after a capped crawl, which made ``total`` wrong.

        ``max_pages`` is a safety valve, not a silent truncation: the previous
        hard cap of 100 pages (10k traces) meant sessions beyond it were
        unreachable by search. Raise it deliberately for large deployments.
        """
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
            data = resp.json().get("data", []) or []
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
            # Empty page = done; a short-but-non-empty page may still have more.
            if not data or page >= max_pages:
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
        """Delete every trace older than *cutoff*, paging until exhausted.

        Deleting while iterating by page is unsafe because the page contents
        shift as rows disappear; this re-queries from page 1 after each batch
        instead, and stops when a page comes back empty.
        """
        from datetime import timezone

        deleted: list[str] = []
        cutoff_iso = cutoff.astimezone(timezone.utc).isoformat()
        while True:
            resp = self._client.get(
                "/api/public/traces",
                params={"toTimestamp": cutoff_iso, "page": 1, "limit": 100},
            )
            resp.raise_for_status()
            batch = resp.json().get("data", []) or []
            if not batch:
                break
            for row in batch:
                trace_id = row.get("id")
                if trace_id:
                    self.delete_trace(trace_id)
                    deleted.append(trace_id)
        return deleted

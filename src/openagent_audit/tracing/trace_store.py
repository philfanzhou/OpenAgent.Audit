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

    ---

    **Langfuse v4 compatibility.** Langfuse v4 (``events_only`` mode) removed
    the legacy ``GET /api/public/traces`` and ``GET /api/public/traces/{id}``
    read endpoints — they now return ``404`` with an "events_only mode"
    message. Reads go through the Observations API v2
    (``GET /api/public/v2/observations``), which returns *observation* rows
    (cursor-paginated) that this adapter groups by ``traceId`` on the client
    side to reconstruct the legacy trace shape. Trace deletion
    (``DELETE /api/public/traces/{id}``) is still supported on v4 and is
    unchanged. See the Langfuse v4 migration guide.
    """

    # Field groups requested from the v2 Observations API. ``core`` and
    # ``basic`` give id/traceId/sessionId/userId/type/name/startTime; ``io``
    # adds input/output; ``model``/``usage``/``metrics`` add the generation
    # fields; ``trace_context`` adds trace-level tags/name/release.
    _V2_FIELDS_LIST = "core,basic,trace_context"
    _V2_FIELDS_DETAIL = "core,basic,io,model,usage,metrics,trace_context"

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

    # -- v2 Observations API helpers --------------------------------------

    def _v2_fetch_observations(
        self,
        *,
        session_id: str | None = None,
        user_id: str | None = None,
        trace_id: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        fields: str = _V2_FIELDS_LIST,
        page_size: int = 100,
        max_pages: int | None = None,
    ) -> list[dict]:
        """Page through ``GET /api/public/v2/observations`` following the
        cursor, until the cursor is absent or ``max_pages`` is hit.

        v2 uses cursor-based pagination (``meta.cursor``), not page numbers.
        An empty ``data`` array can still carry a cursor, so we must keep
        paging until the cursor is *absent* — terminating on an empty page
        would silently truncate large result sets.
        """
        from datetime import timezone

        rows: list[dict] = []
        cursor: str | None = None
        pages = 0
        while True:
            params: dict[str, object] = {"limit": page_size, "fields": fields}
            if session_id:
                params["sessionId"] = session_id
            if user_id:
                params["userId"] = user_id
            if trace_id:
                params["traceId"] = trace_id
            if from_ts is not None:
                params["fromStartTime"] = from_ts.astimezone(timezone.utc).isoformat()
            if to_ts is not None:
                params["toStartTime"] = to_ts.astimezone(timezone.utc).isoformat()
            if cursor:
                params["cursor"] = cursor

            resp = self._client.get("/api/public/v2/observations", params=params)
            resp.raise_for_status()
            payload = resp.json() or {}
            data = payload.get("data", []) or []
            rows.extend(data)
            pages += 1

            next_cursor = (payload.get("meta") or {}).get("cursor")
            # No cursor = end of results. An empty data array with a cursor
            # is still not the end: keep paging.
            if not next_cursor:
                break
            if max_pages is not None and pages >= max_pages:
                break
            cursor = next_cursor

        return rows

    @staticmethod
    def _observations_to_trace_dicts(observations: list[dict]) -> list[dict]:
        """Group v2 observation rows by ``traceId`` and rebuild the legacy
        trace dict shape that :func:`normalize_langfuse_trace` expects.

        v4 has no trace-level entity; a "trace" is the set of observations
        sharing a ``traceId``. Trace-level fields (``sessionId``, ``userId``,
        ``tags``, ``traceName``) are denormalised onto every observation row
        by the v2 API, so we take them from the first row of each group. The
        trace ``timestamp`` is the earliest observation ``startTime``. The
        trace ``id`` is the ``traceId``. Observation bodies are embedded
        directly (v2 returns them inline, unlike the legacy list endpoint
        which returned bare observation ids).
        """
        by_trace: dict[str, dict] = {}
        for obs in observations:
            if not isinstance(obs, dict):
                continue
            trace_id = str(obs.get("traceId") or "")
            if not trace_id:
                continue
            entry = by_trace.get(trace_id)
            if entry is None:
                # Reconstruct a legacy-shaped trace dict.
                tags = obs.get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                entry = {
                    "id": trace_id,
                    "traceId": trace_id,
                    "sessionId": obs.get("sessionId") or "",
                    "userId": obs.get("userId") or "",
                    "name": obs.get("traceName") or "",
                    "tags": tags,
                    "timestamp": obs.get("startTime"),
                    "observations": [],
                }
                by_trace[trace_id] = entry
            # Append the observation in the legacy dict shape so
            # _observation_from_dict keeps working.
            entry["observations"].append({
                "id": obs.get("id") or "",
                "type": obs.get("type") or "span",
                "name": obs.get("name") or "",
                "input": obs.get("input"),
                "output": obs.get("output"),
                "metadata": obs.get("metadata") or {},
                "model": obs.get("model"),
                "usage": obs.get("usageDetails") or obs.get("usage") or {},
                "latency": obs.get("latency"),
            })
            # Trace timestamp = earliest observation startTime.
            raw_ts = obs.get("startTime")
            if raw_ts:
                try:
                    parsed = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                except ValueError:
                    parsed = None
                if parsed is not None:
                    cur = entry["timestamp"]
                    if cur:
                        try:
                            cur_parsed = datetime.fromisoformat(str(cur).replace("Z", "+00:00"))
                        except ValueError:
                            cur_parsed = None
                    else:
                        cur_parsed = None
                    if cur_parsed is None or parsed < cur_parsed:
                        entry["timestamp"] = raw_ts
        return list(by_trace.values())

    # -- public read API --------------------------------------------------

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
        """List traces as legacy-shaped dicts (grouped from v2 observations).

        Retrieval stays limited to userId / sessionId / time range
        (proposal §08 检索范围 — no reverse lookup by phone number or ID
        card). ``max_pages`` bounds the work for callers that only need a
        sample; ``None`` means "page to the end".
        """
        observations = self._v2_fetch_observations(
            session_id=session_id, user_id=user_id,
            from_ts=from_ts, to_ts=to_ts,
            fields=self._V2_FIELDS_LIST,
            page_size=page_size, max_pages=max_pages,
        )
        return self._observations_to_trace_dicts(observations)

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
        """List traces, optionally with observation bodies.

        On Langfuse v4 the v2 Observations API returns observation bodies
        inline, so ``with_observations`` is satisfied by requesting the
        ``io``/``model``/``usage``/``metrics`` field groups up front — there
        is no per-trace detail round trip. ``max_detail_fetches`` is kept for
        API parity with :class:`LocalTraceStore` and ignored.
        """
        del max_detail_fetches
        fields = self._V2_FIELDS_DETAIL if with_observations else self._V2_FIELDS_LIST
        observations = self._v2_fetch_observations(
            session_id=session_id, user_id=user_id,
            from_ts=from_ts, to_ts=to_ts,
            fields=fields,
        )
        rows = self._observations_to_trace_dicts(observations)
        records = [normalize_langfuse_trace(row) for row in rows]
        return sorted(
            (r for r in records if r.timestamp is not None),
            key=lambda r: r.timestamp,
        )

    def get_trace_detail(self, trace_id: str) -> TraceRecord | None:
        """Fetch one trace with its observation bodies via the v2 API.

        v2 has no get-by-id route; we filter the observations endpoint by
        ``traceId``. A trace with no observations returns ``None``.
        """
        observations = self._v2_fetch_observations(
            trace_id=trace_id, fields=self._V2_FIELDS_DETAIL,
        )
        if not observations:
            return None
        rows = self._observations_to_trace_dicts(observations)
        if not rows:
            return None
        return normalize_langfuse_trace(rows[0])

    def list_sessions(
        self,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        *,
        max_pages: int = 1000,
    ) -> list[dict]:
        """Aggregate sessions from the v2 observations API.

        Time filtering is pushed down to the API (``fromStartTime`` /
        ``toStartTime``) so the server does the work. Sessions are grouped
        client-side by ``sessionId`` (a high-cardinality dimension in v4).
        ``max_pages`` is a safety valve against unbounded crawls.
        """
        observations = self._v2_fetch_observations(
            from_ts=from_ts, to_ts=to_ts,
            fields="core,basic,trace_context",
            page_size=100, max_pages=max_pages,
        )

        sessions: dict[str, dict] = {}
        for obs in observations:
            if not isinstance(obs, dict):
                continue
            sid = str(obs.get("sessionId") or "")
            if not sid:
                continue
            entry = sessions.setdefault(
                sid,
                {"session_id": sid, "user_id": str(obs.get("userId") or ""),
                 "trace_ids": set(), "first_ts": None, "last_ts": None,
                 "agent_tags": set()},
            )
            tid = obs.get("traceId")
            if tid:
                entry["trace_ids"].add(str(tid))
            raw_ts = obs.get("startTime")
            if raw_ts:
                try:
                    parsed = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                except ValueError:
                    parsed = None
                if parsed is not None:
                    entry["first_ts"] = min(entry["first_ts"] or parsed, parsed)
                    entry["last_ts"] = max(entry["last_ts"] or parsed, parsed)
            tags = obs.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            entry["agent_tags"].update(t for t in tags if isinstance(t, str))
        return [
            {
                "session_id": s["session_id"],
                "user_id": s["user_id"],
                "trace_count": len(s["trace_ids"]),
                "first_ts": s["first_ts"],
                "last_ts": s["last_ts"],
                "agent_tags": sorted(s["agent_tags"]),
            }
            for s in sessions.values()
        ]

    # -- deletes (v4 still supports DELETE /api/public/traces/{id}) -------

    def delete_trace(self, trace_id: str) -> None:
        resp = self._client.delete(f"/api/public/traces/{trace_id}")
        resp.raise_for_status()

    def delete_older_than(self, cutoff: datetime) -> list[str]:
        """Delete every trace whose earliest observation started before
        *cutoff*, paging until exhausted.

        Deleting while iterating by cursor is unsafe because the result set
        shifts as rows disappear; this re-queries from the start after each
        batch instead, and stops when a full crawl returns no traces. A trace
        whose deletion fails is skipped (and retried on the next sweep) so
        one bad trace cannot abort retention.
        """
        deleted: list[str] = []
        seen_failing: set[str] = set()
        while True:
            observations = self._v2_fetch_observations(
                to_ts=cutoff, fields="core,basic", page_size=100,
            )
            rows = self._observations_to_trace_dicts(observations)
            if not rows:
                break
            progressed = False
            for row in rows:
                trace_id = str(row.get("id") or "")
                if not trace_id or trace_id in seen_failing:
                    continue
                try:
                    self.delete_trace(trace_id)
                except Exception:  # noqa: BLE001 - skip and retry next sweep
                    seen_failing.add(trace_id)
                    continue
                deleted.append(trace_id)
                progressed = True
            if not progressed:
                break
        return deleted

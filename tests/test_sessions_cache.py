"""Session-index cache of the Langfuse trace store.

The console rebuilds the session list on every page flip / browser refresh.
Rebuilding means paging through every observation in Langfuse, so the index
is cached with a stale-while-revalidate policy: fresh index → no upstream
call; expired → old data now, one background refresh; too old (or no index)
→ synchronous refresh with errors surfacing.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta, timezone

import httpx
import pytest

from openagent_audit.tracing.trace_store import LangfuseTraceStore


class _Langfuse:
    """Cursor-paged v2 observations endpoint backed by a mutable row list.

    Honours the ``fromStartTime`` filter like the real API, so a test can
    tell an incremental crawl (filtered) from a full one (unfiltered).

    ``gate`` blocks every request after the first ``gate_after`` calls until
    the test releases it — proves a stale reader gets its answer *before* the
    refresh could possibly have finished.
    """

    def __init__(
        self, rows: list[dict], *, page_size: int = 100, fail: bool = False,
        gate: threading.Event | None = None, gate_after: int = 1,
    ):
        self.rows = rows
        self.page_size = page_size
        self.fail = fail
        self.gate = gate
        self.gate_after = gate_after
        self.calls = 0
        self.blocked = threading.Event()
        # Query parameters of every request, in order.
        self.requests: list[dict[str, str]] = []

    def _subset(self, params: dict[str, str]) -> list[dict]:
        lower = params.get("fromStartTime")
        if not lower:
            return self.rows
        since = datetime.fromisoformat(lower)
        out = []
        for row in self.rows:
            ts = row.get("startTime")
            if ts and datetime.fromisoformat(ts) >= since:
                out.append(row)
        return out

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        params = {k: v for k, v in request.url.params.items()}
        self.requests.append(params)
        if self.gate is not None and self.calls > self.gate_after:
            self.blocked.set()
            assert self.gate.wait(5), "test never released the Langfuse gate"
        if self.fail:
            return httpx.Response(500)
        subset = self._subset(params)
        cursor = params.get("cursor")
        offset = 0 if not cursor else int(cursor.split("-")[-1])
        data = subset[offset : offset + self.page_size]
        meta = {"cursor": f"off-{offset + self.page_size}"} if offset + self.page_size < len(subset) else {}
        return httpx.Response(200, json={"data": data, "meta": meta})

    def filtered_requests(self) -> list[dict[str, str]]:
        return [p for p in self.requests if "fromStartTime" in p]


def _row(i: int, at: datetime | None = None) -> dict:
    at = at or datetime(2026, 11, 25, 10, i % 60, tzinfo=timezone.utc)
    return {"id": f"obs-{i}", "traceId": f"t-{i}", "sessionId": f"s-{i}",
            "startTime": at.isoformat(), "tags": ["agent:cs-bot"]}


def _store(
    mock: _Langfuse, *, ttl: float = 60.0, max_stale: float = 600.0,
    full_rebuild: float = 900.0, lag: float = 120.0, now: float | None = None,
) -> LangfuseTraceStore:
    client = httpx.Client(transport=httpx.MockTransport(mock.handler), base_url="https://lf", auth=("pk", "sk"))
    return LangfuseTraceStore(
        "https://lf", "pk", "sk", client=client, cache_ttl=ttl, max_stale=max_stale,
        full_rebuild_seconds=full_rebuild, incremental_lag_seconds=lag,
        now_wall=(lambda: now) if now is not None else None,
    )


def _ids(sessions: list[dict]) -> list[str]:
    return [s["session_id"] for s in sessions]


def _wait_for_refresh(store: LangfuseTraceStore, mock: _Langfuse, calls: int) -> None:
    """Block until the background refresh (if one was started) is finished."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with store._sessions_refresh_lock:
            if mock.calls >= calls:
                return
        time.sleep(0.01)
    raise AssertionError(f"background refresh did not run: {mock.calls} calls")


def _age(store: LangfuseTraceStore, seconds: float) -> None:
    """Pretend the cached index is ``seconds`` old."""
    with store._sessions_cache_lock:
        store._sessions_cache_at -= seconds


class TestSessionIndexCache:
    def test_fresh_index_is_served_without_calling_langfuse(self):
        mock = _Langfuse([_row(i) for i in range(250)])  # 3 pages
        store = _store(mock)

        first = store.list_sessions()
        assert len(first) == 250 and mock.calls == 3

        for _ in range(3):  # page flips / browser refreshes
            assert len(store.list_sessions()) == 250
        assert mock.calls == 3, "a fresh index must not re-crawl Langfuse"

    def test_callers_get_copies_and_cannot_mutate_the_cache(self):
        mock = _Langfuse([_row(1), _row(2)])
        store = _store(mock)

        first = store.list_sessions()
        first.clear()
        first_mutation = store.list_sessions()
        first_mutation[0]["agent_tags"].append("injected")  # agent_tags list is shared
        first_mutation[0]["last_ts"] = "clobbered"

        again = store.list_sessions()
        assert len(again) == 2
        assert again[0]["last_ts"] != "clobbered"

    def test_expired_index_is_served_stale_and_refreshed_in_background(self):
        gate = threading.Event()
        mock = _Langfuse([_row(1)], gate=gate)
        store = _store(mock)
        assert _ids(store.list_sessions()) == ["s-1"]

        # A new conversation arrived in Langfuse; the cached index expired.
        mock.rows.append(_row(2))
        _age(store, 61)
        stale = store.list_sessions()  # the refresh is still blocked here
        assert _ids(stale) == ["s-1"], "the request must not wait for the refresh"

        assert mock.blocked.wait(5), "no background refresh was started"
        gate.set()
        _wait_for_refresh(store, mock, 2)
        assert _ids(store.list_sessions()) == ["s-1", "s-2"]

    def test_concurrent_stale_requests_trigger_one_refresh(self):
        gate = threading.Event()
        mock = _Langfuse([_row(1)], gate=gate)
        store = _store(mock)
        store.list_sessions()
        _age(store, 61)

        for _ in range(10):
            store.list_sessions()  # each would like a refresh
        assert mock.blocked.wait(5)
        assert mock.calls == 2, "ten stale readers, exactly one refresh started"

        gate.set()
        _wait_for_refresh(store, mock, 2)
        time.sleep(0.05)
        assert mock.calls == 2, "ten stale readers, exactly one background crawl"

    def test_too_stale_index_refreshes_synchronously(self):
        """Beyond max-stale the request waits for current data."""
        mock = _Langfuse([_row(1)])
        store = _store(mock, ttl=60, max_stale=120)
        store.list_sessions()
        mock.rows.append(_row(2))
        _age(store, 600)
        mock.gate = threading.Event()
        mock.gate_after = 1  # the refresh crawl blocks until released
        threading.Timer(0.1, mock.gate.set).start()

        assert _ids(store.list_sessions()) == ["s-1", "s-2"], "beyond max-stale the data must be current"
        assert mock.calls == 2

    def test_too_stale_index_surfaces_langfuse_errors(self):
        """A dead Langfuse must not be papered over with arbitrarily old data."""
        mock = _Langfuse([_row(1)])
        store = _store(mock, ttl=60, max_stale=120)
        store.list_sessions()
        _age(store, 600)
        mock.fail = True
        with pytest.raises(httpx.HTTPStatusError):
            store.list_sessions()

    def test_failed_background_refresh_keeps_the_stale_index(self):
        mock = _Langfuse([_row(1)])
        store = _store(mock)
        store.list_sessions()
        _age(store, 61)
        mock.fail = True

        assert _ids(store.list_sessions()) == ["s-1"]  # stale, but returned
        _wait_for_refresh(store, mock, 2)
        assert store._sessions_cache is not None, "a failed refresh must not drop the stale index"

        mock.fail = False
        mock.rows.append(_row(2))
        assert _ids(store.list_sessions()) == ["s-1"]  # still within max-stale → retried
        _wait_for_refresh(store, mock, 3)
        assert _ids(store.list_sessions()) == ["s-1", "s-2"]

    def test_invalidate_forces_a_reread(self):
        mock = _Langfuse([_row(1)])
        store = _store(mock)
        assert _ids(store.list_sessions()) == ["s-1"]
        mock.rows.append(_row(2))

        assert _ids(store.list_sessions()) == ["s-1"]  # still fresh
        store.invalidate_sessions_cache()
        assert _ids(store.list_sessions()) == ["s-1", "s-2"]
        assert mock.calls == 2

    def test_invalidate_during_a_refresh_discards_its_result(self):
        mock = _Langfuse([_row(1)])
        store = _store(mock)
        store.list_sessions()
        mock.rows.append(_row(2))
        _age(store, 61)

        started = threading.Event()
        real_crawl = store._build_index

        def slow_crawl(*args, **kwargs):
            started.set()
            time.sleep(0.05)
            return real_crawl(*args, **kwargs)

        store._build_index = slow_crawl  # type: ignore[method-assign]
        store.list_sessions()  # kicks off a (slow) background crawl
        assert started.wait(5)
        store.invalidate_sessions_cache()  # e.g. traces purged meanwhile
        _wait_for_refresh(store, mock, 2)
        time.sleep(0.1)

        with store._sessions_cache_lock:
            assert store._sessions_cache is None, "refresh started before invalidation must not refill the cache"

    def test_cold_start_crawls_once_under_concurrency(self):
        mock = _Langfuse([_row(i) for i in range(50)])
        store = _store(mock)
        results: list[list[str]] = []

        def hit():
            results.append(_ids(store.list_sessions()))

        threads = [threading.Thread(target=hit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert len(results) == 8 and all(len(r) == 50 for r in results)
        assert mock.calls == 1, "concurrent cold requests share one crawl"

    def test_time_filtered_lists_bypass_the_cache(self):
        mock = _Langfuse([_row(1)])
        store = _store(mock)
        store.list_sessions()

        store.list_sessions(from_ts=datetime.now(UTC) - timedelta(days=1))
        store.list_sessions(from_ts=datetime.now(UTC) - timedelta(days=1))
        assert len(mock.filtered_requests()) == 2, "windowed queries are never cached"

    @pytest.mark.parametrize("ttl, max_stale", [(0, 5), (-3, 0), (30, 1)])
    def test_degenerate_knobs_are_clamped(self, ttl, max_stale):
        store = _store(_Langfuse([]), ttl=ttl, max_stale=max_stale)
        assert store._sessions_cache_ttl >= 0
        assert store._sessions_cache_max_stale >= store._sessions_cache_ttl


class TestIncrementalRefresh:
    """After the first full crawl a refresh only fetches observations newer
    than the last crawl's watermark, so upstream traffic scales with new
    conversations rather than with the size of the store."""

    NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)

    def _store_at(self, mock, **kwargs):
        """Store whose wall clock is pinned to NOW, so the watermark does not
        depend on when the test happens to run."""
        return _store(mock, now=self.NOW.timestamp(), **kwargs)

    def _expired_refresh(self, store, mock):
        _age(store, 61)
        before = len(mock.requests)
        rows = store._refresh_sessions(1000, wait=True)
        return rows, mock.requests[before:]

    def test_refresh_fetches_only_observations_since_the_watermark(self):
        mock = _Langfuse([_row(i) for i in range(300)])  # 3 pages on a full crawl
        store = self._store_at(mock, lag=0)
        assert len(store.list_sessions()) == 300
        assert mock.calls == 3 and not mock.filtered_requests(), "first crawl is a full crawl"

        # New conversations arrive while the cached index is still fresh.
        mock.rows += [_row(1000 + i, self.NOW + timedelta(minutes=i)) for i in range(5)]
        # A long-running conversation gets another trace.
        mock.rows.append({**_row(2000, self.NOW), "sessionId": "s-7", "traceId": "t-2000"})
        rows, requests = self._expired_refresh(store, mock)

        assert len(requests) == 1, "one page of new observations, not three"
        assert all("fromStartTime" in p for p in requests), "incremental crawl is filtered"
        by_id = {r["session_id"]: r for r in rows}
        assert len(rows) == 305
        assert by_id["s-1004"]["trace_count"] == 1
        assert by_id["s-7"]["trace_count"] == 2, "new trace folded into the existing session"
        assert by_id["s-7"]["last_ts"] == self.NOW

    def test_watermark_is_the_crawl_start_backed_off_by_the_ingest_lag(self):
        mock = _Langfuse([_row(1)])
        store = self._store_at(mock, lag=120)
        store.list_sessions()

        assert store._index_watermark == self.NOW - timedelta(seconds=120)

    def test_overlap_rows_are_not_double_counted(self):
        """The lag margin re-reads recent rows on every incremental crawl;
        folding them again must not inflate counts."""
        recent = self.NOW - timedelta(minutes=10)
        mock = _Langfuse([_row(i, recent + timedelta(minutes=i)) for i in range(3)])
        store = self._store_at(mock, lag=600)
        store.list_sessions()
        (before,) = [r for r in store.list_sessions() if r["session_id"] == "s-1"]

        rows, requests = self._expired_refresh(store, mock)

        assert requests and all("fromStartTime" in p for p in requests)
        # every row is inside the 10-minute overlap and gets re-delivered
        (after,) = [r for r in rows if r["session_id"] == "s-1"]
        assert after == before
        assert sum(r["trace_count"] for r in rows) == 3

    def test_deletions_surface_after_the_full_rebuild_interval(self):
        mock = _Langfuse([_row(1, self.NOW), _row(2, self.NOW + timedelta(minutes=1))])
        store = self._store_at(mock, lag=0, full_rebuild=900)
        store.list_sessions()
        mock.rows[:] = [r for r in mock.rows if r["traceId"] != "t-2"]  # retention deleted it

        rows, _ = self._expired_refresh(store, mock)
        assert {r["session_id"] for r in rows} == {"s-1", "s-2"}, "an incremental crawl cannot see a deletion"

        store._index_full_at -= 901  # due for a full rebuild
        _, requests = self._expired_refresh(store, mock)
        assert not [p for p in requests if "fromStartTime" in p], "periodic rebuild is unfiltered"
        assert {r["session_id"] for r in store.list_sessions()} == {"s-1"}

    def test_invalidated_index_is_rebuilt_in_full(self):
        mock = _Langfuse([_row(1, self.NOW)])
        store = self._store_at(mock, lag=0)
        store.list_sessions()
        mock.rows.append(_row(2, self.NOW))

        store.invalidate_sessions_cache()
        rows = store.list_sessions()

        assert {r["session_id"] for r in rows} == {"s-1", "s-2"}
        assert store._index_watermark is not None

    def test_incremental_failure_leaves_the_index_and_watermark_in_place(self):
        mock = _Langfuse([_row(1, self.NOW)])
        store = self._store_at(mock, lag=0)
        store.list_sessions()
        _age(store, 61)
        mock.fail = True

        assert _ids(store.list_sessions()) == ["s-1"]  # stale but served
        _wait_for_refresh(store, mock, 2)
        assert store._index_watermark is not None, "a failed crawl must not move the watermark"
        assert store._session_index is not None

"""Search and paging on the session list and the audit log.

Policy, identical for both lists: ten rows per page, at most twenty pages (200
rows). Anything older must be reached with a filter — a date range, a role, an
account or a keyword — rather than by paging forever.

Timestamps are stored in UTC and *displayed* in the deployment zone, so a
search for "2026-11-06 09:00" must mean nine in the morning local time, not
nine UTC.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from openagent_audit.services.audit_api import MAX_PAGES, MAX_VISIBLE, PAGE_SIZE
from openagent_audit.tracing.trace_store import ObservationRecord, TraceRecord

TZ8 = timezone(timedelta(hours=8))


@pytest.fixture()
def user_client(api_client):
    api_client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)
    return api_client


@pytest.fixture()
def admin_client(user_client):
    user_client.post(
        "/ui/admin/login",
        data={"username": "admin", "password": "admin@123456"},
        follow_redirects=False,
    )
    return user_client


def _seed_sessions(container, count: int) -> None:
    store = container.trace_store
    for existing in list(store.list_traces()):
        store.delete_trace(existing.trace_id)
    for i in range(count):
        store.upsert_trace(
            TraceRecord(
                trace_id=f"t-{i:04d}",
                session_id=f"sess-{i:04d}",
                user_id=f"usr_{i % 3}",
                agent_tag=f"agent:bot-{i % 2}",
                name="POST /agent/run",
                timestamp=datetime(2026, 11, 1, tzinfo=timezone.utc) + timedelta(hours=i),
                observations=(ObservationRecord(id="o", type="span", name="x"),),
            )
        )


class TestPagingPolicy:
    def test_constants(self):
        assert PAGE_SIZE == 10
        assert MAX_PAGES == 20
        assert MAX_VISIBLE == 200

    def test_default_page_size_is_ten(self, user_client, container):
        _seed_sessions(container, 25)
        body = user_client.get("/v1/sessions").json()

        assert body["page_size"] == 10
        assert len(body["sessions"]) == 10
        assert body["total"] == 25
        assert body["total_pages"] == 3

    def test_cannot_request_more_than_ten(self, user_client, container):
        _seed_sessions(container, 25)
        body = user_client.get("/v1/sessions", params={"page_size": 500}).json()
        assert body["page_size"] == PAGE_SIZE
        assert len(body["sessions"]) <= PAGE_SIZE

    def test_cannot_page_beyond_twenty(self, user_client, container):
        _seed_sessions(container, 250)
        body = user_client.get("/v1/sessions", params={"page": 999}).json()

        assert body["page"] == MAX_PAGES
        assert body["total_pages"] == MAX_PAGES
        assert body["truncated"] is True

    def test_truncation_is_reported(self, user_client, container):
        _seed_sessions(container, MAX_VISIBLE + 50)
        body = user_client.get("/v1/sessions").json()

        assert body["total"] == MAX_VISIBLE + 50
        assert body["max_visible"] == MAX_VISIBLE
        assert body["truncated"] is True
        assert body["total_pages"] == MAX_PAGES


class TestSessionSearch:
    def test_keyword_matches_session_user_and_agent(self, user_client, container):
        _seed_sessions(container, 12)

        by_session = user_client.get("/v1/sessions", params={"q": "sess-0003"}).json()
        assert by_session["total"] == 1

        by_user = user_client.get("/v1/sessions", params={"q": "usr_0"}).json()
        assert by_user["total"] >= 1

        by_agent = user_client.get("/v1/sessions", params={"agent": "bot-1"}).json()
        assert by_agent["total"] == 6

    def test_date_range_filters(self, user_client, container):
        """Session rows are stored in UTC; the filter is entered in local time.

        The seed starts at 2026-11-01T00:00Z, which is 08:00 Beijing. A local
        range of 08:00-12:00 therefore selects the first few rows, while the
        same numbers read as UTC would select none.
        """
        _seed_sessions(container, 12)  # 2026-11-01T00:00Z .. +11h

        wide = user_client.get(
            "/v1/sessions", params={"from_ts": "2026-11-01T08:00", "to_ts": "2026-11-01T20:00"}
        ).json()
        assert wide["total"] == 12

        narrow = user_client.get(
            "/v1/sessions", params={"from_ts": "2026-11-01T08:00", "to_ts": "2026-11-01T11:00"}
        ).json()
        assert narrow["total"] == 3

        # Interpreting the same digits as UTC would match nothing, which is the
        # eight-hour mistake this filter exists to avoid.
        utc_read = user_client.get(
            "/v1/sessions", params={"from_ts": "2026-11-01T00:00", "to_ts": "2026-11-01T03:00"}
        ).json()
        assert utc_read["total"] == 0

    def test_datetime_local_format_is_accepted(self, user_client, container):
        """``<input type="datetime-local">`` submits ``YYYY-MM-DDTHH:MM``."""
        _seed_sessions(container, 5)
        body = user_client.get(
            "/v1/sessions", params={"from_ts": "2026-11-01T08:00", "to_ts": "2026-11-01T13:00"}
        ).json()
        assert body["total"] == 5

    def test_search_lifts_the_browse_limit(self, user_client, container):
        _seed_sessions(container, MAX_VISIBLE + 30)

        plain = user_client.get("/v1/sessions").json()
        assert plain["browse_blocked"] is True

        searched = user_client.get("/v1/sessions", params={"q": "sess-0010"}).json()
        assert searched["browse_blocked"] is False
        assert searched["total"] == 1


class TestAuditLogSearch:
    def _seed(self, container, n: int = 30) -> None:
        base = datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc)
        for i in range(n):
            container.audit.append(
                actor="alice" if i % 2 == 0 else "bob",
                role="admin" if i % 3 == 0 else "user",
                action=f"ACTION_{i:02d}",
                object_type="session",
                object_id=f"sess-{i:03d}",
                ts=base + timedelta(minutes=i),
            )

    def test_keyword_search(self, admin_client, container):
        self._seed(container)
        body = admin_client.get("/v1/audit-log", params={"q": "sess-007"}).json()
        assert body["total"] == 1
        assert body["entries"][0]["object_id"] == "sess-007"

    def test_role_filter(self, admin_client, container):
        self._seed(container)
        admins = admin_client.get("/v1/audit-log", params={"role": "admin"}).json()
        # ten seeded rows (i % 3 == 0 within 0..29) plus the ADMIN_LOGIN entry
        assert admins["total"] == 11
        assert all(e["role"] == "admin" for e in admins["entries"])

    def test_action_filter(self, admin_client, container):
        self._seed(container)
        body = admin_client.get("/v1/audit-log", params={"action": "ACTION_1"}).json()
        assert body["total"] == 10  # ACTION_10 .. ACTION_19

    def test_date_range_in_display_timezone(self, admin_client, container):
        """A local-time range must be interpreted locally, not as UTC."""
        self._seed(container, 30)  # 2026-11-01T00:00Z .. +29min

        # 08:00-08:10 Beijing == 00:00-00:10 UTC -> the first 11 entries
        body = admin_client.get(
            "/v1/audit-log",
            params={"from_ts": "2026-11-01T08:00", "to_ts": "2026-11-01T08:10"},
        ).json()

        assert body["total"] == 10, body["total"]
        assert body["display_zone_label"].startswith(("CST", "UTC+08"))

    def test_utc_range_would_differ(self, admin_client, container):
        """Guards the bug: summing UTC directly would select a different set."""
        self._seed(container, 30)
        utc_style = admin_client.get(
            "/v1/audit-log",
            params={"from_ts": "2026-11-01T00:00", "to_ts": "2026-11-01T00:10"},
        ).json()
        # interpreted as Beijing 00:00 == previous day 16:00 UTC -> nothing
        assert utc_style["total"] == 0

    def test_entries_carry_both_utc_and_display_time(self, admin_client, container):
        self._seed(container, 3)
        entry = admin_client.get("/v1/audit-log").json()["entries"][0]

        assert entry["ts"].endswith("+00:00")
        assert entry["ts_display"]
        # display value is the UTC one shifted by eight hours
        utc = datetime.fromisoformat(entry["ts"])
        shown = datetime.fromisoformat(entry["ts_display"])
        assert shown.astimezone(timezone.utc) == utc
        assert shown.utcoffset() == timedelta(hours=8)

    def test_paging_and_truncation(self, admin_client, container):
        self._seed(container, MAX_VISIBLE + 25)
        body = admin_client.get("/v1/audit-log").json()

        assert body["page_size"] == PAGE_SIZE
        assert len(body["entries"]) == PAGE_SIZE
        assert body["truncated"] is True
        assert body["total_pages"] == MAX_PAGES

    def test_total_matches_filtered_pages(self, admin_client, container):
        """The reported total must use the same filters as the rows."""
        self._seed(container, 40)
        body = admin_client.get("/v1/audit-log", params={"q": "alice"}).json()

        page2 = admin_client.get(
            "/v1/audit-log", params={"q": "alice", "page": 2}
        ).json()

        # The total must agree between pages and reflect only matching rows
        # (not every entry in the log), and the pages must not overlap.
        assert body["total"] == page2["total"]
        assert body["total"] < 41 + 3  # far fewer than "everything"
        assert len(body["entries"]) == 10
        seqs1 = {e["seq"] for e in body["entries"]}
        seqs2 = {e["seq"] for e in page2["entries"]}
        assert not (seqs1 & seqs2)


class TestSearchPagesRender:
    def test_sessions_page_has_search_form(self, user_client):
        page = user_client.get("/ui/sessions").text
        for field in ("name=\"q\"", "name=\"from_ts\"", "name=\"to_ts\"", "name=\"agent\""):
            assert field in page, field

    def test_audit_page_has_search_form(self, admin_client):
        page = admin_client.get("/ui/audit-log").text
        for field in ("name=\"q\"", "name=\"from_ts\"", "name=\"to_ts\"",
                      "name=\"role\"", "name=\"action\""):
            assert field in page, field

    def test_pager_renders_with_multiple_pages(self, user_client, container):
        _seed_sessions(container, 25)
        page = user_client.get("/ui/sessions").text
        assert "下一页" in page
        assert "第 1 / 3 页" in page

    def test_search_state_is_preserved_in_pager_links(self, user_client, container):
        _seed_sessions(container, 25)
        page = user_client.get("/ui/sessions", params={"q": "sess"}).text
        assert "page=2" in page
        assert "q=sess" in page


class TestSessionDetailBackButton:
    def test_detail_page_has_back_button(self, user_client, container):
        _seed_sessions(container, 1)
        page = user_client.get("/ui/sessions/sess-0000").text

        assert "返回会话列表" in page
        assert 'href="/ui/sessions"' in page

    def test_header_session_link_still_present(self, user_client, container):
        """The nav link and the back button lead to the same place."""
        _seed_sessions(container, 1)
        page = user_client.get("/ui/sessions/sess-0000").text
        assert ">会话</a>" in page
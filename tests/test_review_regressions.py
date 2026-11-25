"""Regression tests for defects found in the pre-deployment code review.

Each test pins a bug that the suite let through: a privilege invariant that
could be bypassed, 500s on plausible input, an eight-hour time-window
mismatch, and silent truncation of the session index.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from openagent_audit.config import Settings
from openagent_audit.services.audit_api import build_container, create_audit_app
from openagent_audit.services.auth import (
    ROLE_USER,
    Principal,
    SessionStore,
    hash_admin_password,
    verify_password_hash,
)
from openagent_audit.services.sso import SsoClient, SsoError
from openagent_audit.tracing.trace_store import LangfuseTraceStore
from tests.test_sessions_cache import _Langfuse, _store
from tests.test_sso_login import BASE, MockSso
from tests.test_sso_login import _client as sso_client


def _test_account_settings(settings):
    """The fixture settings with the local test account switched on."""
    return dataclasses.replace(
        settings, test_username="test", test_password="test@123456", admin_password="admin@123456"
    )


class _App:
    """A test client that also exposes its container."""

    def __init__(self, settings):
        self.container = build_container(settings)
        self.client = TestClient(create_audit_app(self.container))

    def login_test_account(self):
        resp = self.client.post(
            "/console/api/login/test", json={"username": "test", "password": "test@123456"}
        )
        assert resp.status_code == 200, resp.text
        return self


# ---------------------------------------------------------------------------
# Privilege invariant: the test account can never become administrator
# ---------------------------------------------------------------------------


class TestRevokeAdminKeepsTheTestAccountEphemeral:
    def test_revoke_preserves_ephemeral_and_still_refuses_grant(self):
        store = SessionStore()
        session = store.create(Principal("test", ROLE_USER, ephemeral=True))

        assert store.revoke_admin(session.token) is False, "not an admin: nothing to revoke"
        current = store.get(session.token)
        assert current.principal.ephemeral is True, "downgrade must not erase the marker"
        assert store.grant_admin(session.token) is None
        assert store.get(session.token).principal.role == ROLE_USER

    def test_revoke_of_a_real_admin_session_reports_true_and_keeps_identity(self):
        store = SessionStore()
        session = store.create(Principal("alice", ROLE_USER))
        assert store.grant_admin(session.token) is not None

        assert store.revoke_admin(session.token) is True

        current = store.get(session.token)
        assert current.principal.username == "alice"
        assert current.principal.role == ROLE_USER
        assert current.principal.ephemeral is False

    def test_test_account_keeps_its_one_hour_lifetime_after_revoke(self):
        store = SessionStore(idle_seconds=8 * 3600, test_session_seconds=3600)
        session = store.create(Principal("test", ROLE_USER, ephemeral=True))
        store.revoke_admin(session.token)
        with store._lock:
            store._sessions[session.token] = dataclasses.replace(
                store._sessions[session.token], created_at=time.time() - 3700
            )

        # Without the marker it would live on the 8h idle window instead.
        assert store.get(session.token) is None, "must still expire after the test-account hour"


class TestTestAccountCannotStepUpOverHttp:
    def test_logout_then_login_does_not_unlock_the_test_account(self, settings):
        """Used to succeed: ``/v1/admin/logout`` rebuilt the session without
        ``ephemeral``, after which ``/v1/admin/login`` accepted the test
        account as a real one."""
        app = _App(_test_account_settings(settings)).login_test_account()
        body = {"username": "admin", "password": "admin@123456"}
        assert app.client.post("/v1/admin/login", json=body).status_code == 403

        assert app.client.post("/v1/admin/logout").status_code == 200

        refused = app.client.post("/v1/admin/login", json=body)
        assert refused.status_code == 403, refused.text
        assert app.client.get("/v1/audit-log").status_code == 403

    def test_admin_logout_of_a_non_admin_session_writes_no_audit_record(self, settings):
        app = _App(_test_account_settings(settings)).login_test_account()
        before = [e for e in app.container.db.iter_audit() if e.action == "ADMIN_LOGOUT"]

        app.client.post("/v1/admin/logout")

        after = [e for e in app.container.db.iter_audit() if e.action == "ADMIN_LOGOUT"]
        assert after == before, "logout of a non-admin session is not an audit event"


# ---------------------------------------------------------------------------
# Non-ASCII input must be a wrong login, never a 500
# ---------------------------------------------------------------------------


class TestNonAsciiInput:
    def test_test_account_login_with_a_chinese_username_is_401(self, settings):
        client = TestClient(create_audit_app(build_container(_test_account_settings(settings))))
        resp = client.post(
            "/console/api/login/test", json={"username": "测试员", "password": "test@123456"}
        )
        assert resp.status_code == 401

    def test_form_login_with_a_chinese_username_is_401(self, settings):
        client = TestClient(create_audit_app(build_container(_test_account_settings(settings))))
        resp = client.post(
            "/ui/login", data={"username": "测试员", "password": "x"}, follow_redirects=False
        )
        assert resp.status_code == 401

    def test_admin_login_with_a_chinese_username_is_401(self, api_client, as_user):
        as_user()
        resp = api_client.post(
            "/ui/admin/login", data={"username": "管理员", "password": "admin@123456"},
            follow_redirects=False,
        )
        assert resp.status_code == 401
        resp = api_client.post("/v1/admin/login", json={"username": "管理员", "password": "wrong"})
        assert resp.status_code == 401

    def test_failed_admin_login_records_the_configured_account(self, api_client, as_user, container):
        as_user()
        api_client.post("/v1/admin/login", json={"username": "whatever", "password": "wrong"})

        (entry,) = [e for e in container.db.iter_audit() if e.action == "ADMIN_LOGIN_FAILED"]
        assert entry.object_id == container.settings.admin_username


class TestMalformedPasswordHash:
    @pytest.mark.parametrize(
        "stored",
        [
            "pbkdf2_sha256$-5$AAAA$AAAA",
            "pbkdf2_sha256$99999999999999999999$AAAA$AAAA",
            "pbkdf2_sha256$abc$AAAA$AAAA",
            "pbkdf2_sha256$210000$AAAA",
        ],
    )
    def test_malformed_hash_fails_closed(self, stored):
        assert verify_password_hash(stored, "admin@123456") is False

    def test_valid_hash_still_verifies(self):
        assert verify_password_hash(hash_admin_password("s3cret"), "s3cret") is True
        assert verify_password_hash(hash_admin_password("s3cret"), "wrong") is False

    def test_admin_login_with_a_broken_configured_hash_is_401_not_500(self, settings):
        settings = dataclasses.replace(
            settings, admin_password="", admin_password_hash="pbkdf2_sha256$-5$AAAA$AAAA"
        )
        client = TestClient(create_audit_app(build_container(settings)))
        client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)

        resp = client.post("/v1/admin/login", json={"username": "admin", "password": "x"})

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Time windows use the console's display zone everywhere
# ---------------------------------------------------------------------------


def _recording_langfuse():
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append({k: v for k, v in request.url.params.items()})
        return httpx.Response(200, json={"data": [], "meta": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://lf", auth=("pk", "sk"))
    return LangfuseTraceStore("https://lf", "pk", "sk", client=client), seen


class TestTimeWindowUsesDisplayZone:
    def test_traces_and_session_detail_interpret_naive_times_in_display_zone(
        self, container, api_client, as_user
    ):
        as_user()
        store, seen = _recording_langfuse()
        container.trace_store = store

        assert api_client.get("/v1/traces?from_ts=2026-11-06T09:00:00").status_code == 200
        assert api_client.get("/v1/sessions/abc?to_ts=2026-11-06T09:00:00").status_code == 404

        lowers = [p["fromStartTime"] for p in seen if "fromStartTime" in p]
        uppers = [p["toStartTime"] for p in seen if "toStartTime" in p]
        assert lowers == ["2026-11-06T01:00:00+00:00"], "09:00 Asia/Shanghai is 01:00 UTC"
        assert uppers == ["2026-11-06T01:00:00+00:00"]

    def test_explicit_offset_is_respected(self, container, api_client, as_user):
        as_user()
        store, seen = _recording_langfuse()
        container.trace_store = store

        # The "+" of an offset is a space unless percent-encoded (browsers do it).
        api_client.get("/v1/traces?from_ts=2026-11-06T09:00:00%2B08:00")

        (lower,) = [p["fromStartTime"] for p in seen if "fromStartTime" in p]
        assert lower == "2026-11-06T01:00:00+00:00"


# ---------------------------------------------------------------------------
# Upstream failures and truncation are visible, not silent
# ---------------------------------------------------------------------------


class TestUpstreamFailure:
    def test_langfuse_outage_is_a_503_with_retry_after(self, container, api_client, as_user):
        as_user()

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        container.trace_store = LangfuseTraceStore(
            "https://lf", "pk", "sk",
            client=httpx.Client(
                transport=httpx.MockTransport(handler), base_url="https://lf", auth=("pk", "sk")
            ),
        )
        resp = api_client.get("/v1/sessions")

        assert resp.status_code == 503
        assert resp.headers.get("retry-after") == "30"
        assert "暂时不可用" in resp.json()["detail"]


def _obs(i: int, session: str, at: str) -> dict:
    return {"id": f"o{i}-{session}", "traceId": f"t{i}-{session}", "sessionId": session, "startTime": at}


class TestIndexTruncation:
    OLD, NEW = "2026-11-25T10:00:00Z", "2026-11-25T12:30:00Z"

    def _store(self, mock):
        return _store(mock, now=datetime(2026, 11, 25, 12, 0, tzinfo=UTC).timestamp(), lag=0)

    def _expire(self, store):
        with store._sessions_cache_lock:
            store._sessions_cache_at -= 61

    def test_full_crawl_hitting_max_pages_is_flagged(self):
        mock = _Langfuse([_obs(i, f"s{i}", self.OLD) for i in range(250)])
        store = self._store(mock)
        rows = store.list_sessions(max_pages=2)

        assert mock.calls == 2, "stopped at max_pages"
        assert len(rows) == 200
        assert store.sessions_index_truncated is True

    def test_untruncated_crawl_is_not_flagged(self):
        store = self._store(_Langfuse([_obs(1, "s1", self.OLD)]))
        store.list_sessions()
        assert store.sessions_index_truncated is False

    def test_truncated_incremental_crawl_does_not_advance_the_watermark(self):
        mock = _Langfuse([_obs(i, f"s{i}", self.OLD) for i in range(3)])
        store = self._store(mock)
        store.list_sessions()
        watermark = store._index_watermark
        assert watermark is not None

        mock.rows += [_obs(i, f"new{i}", self.NEW) for i in range(250)]
        self._expire(store)
        rows = store._refresh_sessions(2, wait=True)  # 2 pages of the 250 new rows

        assert len(rows) == 3 + 200, "only the rows actually read were folded in"
        assert store._index_watermark == watermark, "unread rows must still be read next time"
        assert store.sessions_index_truncated is True

        # The next crawl reads the rest and clears the flag.
        self._expire(store)
        store._refresh_sessions(1000, wait=True)
        assert store.sessions_index_truncated is False
        assert len(store.list_sessions()) == 253

    def test_sessions_api_reports_truncation(self, container, api_client, as_user):
        as_user()
        store = self._store(_Langfuse([_obs(1, "s1", self.OLD)]))
        container.trace_store = store
        assert api_client.get("/v1/sessions").json()["index_truncated"] is False

        with store._sessions_cache_lock:
            store._index_truncated = True
        assert api_client.get("/v1/sessions").json()["index_truncated"] is True


# ---------------------------------------------------------------------------
# SSO failure handling
# ---------------------------------------------------------------------------


class TestSsoFailureHandling:
    def test_non_dict_userinfo_is_an_sso_error(self):
        mock = MockSso()
        mock.userinfo = ["not", "an", "object"]
        client = sso_client(mock)

        with pytest.raises(SsoError, match="格式异常"):
            asyncio.run(client.exchange_and_identify(BASE, "code", "verifier"))

    def test_oauth_client_is_closed_when_the_exchange_fails(self, monkeypatch):
        import openagent_audit.services.sso as sso_module

        closed = {"n": 0}

        class FakeOAuth:
            def __init__(self, **kwargs):
                pass

            async def fetch_token(self, *a, **kw):
                raise httpx.ConnectError("boom")

            async def aclose(self):
                closed["n"] += 1

        monkeypatch.setattr(sso_module, "AsyncOAuth2Client", FakeOAuth)
        discovery = MockSso().discovery()
        client = SsoClient(
            Settings(sso_authority="https://sso.example", sso_client_id="cid", sso_client_secret="sec")
        )
        assert client._client is None, "must build its own client for this test"

        async def fake_fetch(url):
            return discovery

        monkeypatch.setattr(client, "_fetch_json", fake_fetch)

        with pytest.raises(SsoError):
            asyncio.run(client.exchange_and_identify("http://audit", "code", "verifier"))
        assert closed["n"] == 1, "the failed login must not leak the HTTP client"

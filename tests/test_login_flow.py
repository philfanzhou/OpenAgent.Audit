"""Getting into the console: enterprise SSO, test account, error handling.

Three paths:

* **Enterprise SSO** — the primary path. The console redirects to the company
  SSO (OIDC Authorization Code + PKCE) and signs the user in as themselves.
* **Manual token** — pasting a platform token (still accepted for API clients).
* **Test account** — the fallback, always an ordinary user, one-hour session.

A earlier design nested the test-account fields inside a collapsed block of a
single shared form; a collapsed block can omit its inputs from the submission,
so a correct test login arrived empty. The forms are independent now, and the
collapsed section hides the form without touching the submission.
"""

from __future__ import annotations

import urllib.parse

import httpx
import pytest
from authlib.integrations.httpx_client import AsyncOAuth2Client

from openagent_audit.config import Settings, UserEntry
from openagent_audit.services.audit_api import build_container, create_audit_app
from tests.test_sso_login import MockSso
from tests.conftest import PASSPHRASE


def _make_app(tmp_path, keypair, **overrides):
    public_pem, private_pem = keypair
    (tmp_path / "pub.pem").write_bytes(public_pem)
    (tmp_path / "priv.pem").write_bytes(private_pem)

    base = dict(
        audit_db_url=f"sqlite:///{tmp_path / 'login.db'}",
        users=(UserEntry("tok-alice", "alice", "user"),),
        admin_username="admin",
        admin_password="admin@123456",
        test_username="test",
        test_password="test@123456",
        test_session_minutes=60,
        public_key_path=str(tmp_path / "pub.pem"),
        local_private_key_path=str(tmp_path / "priv.pem"),
        local_private_key_passphrase=PASSPHRASE.decode(),
        object_store="local",
        object_store_root=str(tmp_path / "obj"),
    )
    base.update(overrides)
    return build_container(Settings(**base))


@pytest.fixture()
def sso_app(tmp_path, keypair):
    container = _make_app(
        tmp_path, keypair,
        sso_authority="https://sso.example.com",
        sso_client_id="openagent-audit",
        sso_client_secret="s3cret",
    )
    mock = MockSso()
    from openagent_audit.services.sso import SsoClient

    container.sso = SsoClient(container.settings)
    # discovery reads go through the mock; the token/userinfo exchanges
    # run on a real AsyncOAuth2Client over the mock transport.
    async def _mock_discovery(url):
        return mock.discovery()
    container.sso._fetch_json = _mock_discovery
    container.sso._client = mock.oauth_client()
    container.sso._client = mock.oauth_client()
    return container, mock


class TestLoginPageStructure:
    def test_sso_button_and_test_form(self, tmp_path, keypair):
        container = _make_app(
            tmp_path, keypair,
            sso_authority="https://sso.example.com",
            sso_client_id="openagent-audit",
            sso_client_secret="s3cret",
        )
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        page = client.get("/ui/login").text

        assert "用企业账号登录" in page
        assert 'href="/ui/login/sso/start"' in page
        # the test form is a separate <form> inside its own <details>
        assert 'name="username"' in page
        assert 'name="password"' in page

    def test_test_section_collapsed_by_default(self, tmp_path, keypair):
        container = _make_app(
            tmp_path, keypair,
            sso_authority="https://sso.example.com",
            sso_client_id="openagent-audit",
            sso_client_secret="s3cret",
        )
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))
        page = client.get("/ui/login").text

        assert '<details id="test-login">' in page
        assert '<details id="test-login" open>' not in page

    def test_test_section_opens_after_an_error(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        page = client.post(
            "/ui/login", data={"username": "test", "password": "nope"}
        ).text

        assert '<details id="test-login" open>' in page

    def test_sso_disabled_hides_the_button(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair, sso_client_id="")
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))
        page = client.get("/ui/login").text

        assert "用企业账号登录" not in page
        assert "用测试账号登录" in page


class TestTestAccountLogin:
    def test_correct_credentials_sign_in(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        resp = client.post(
            "/ui/login",
            data={"token": "", "username": "test", "password": "test@123456"},
            follow_redirects=False,
        )

        assert resp.status_code == 302
        assert resp.headers["location"] == "/ui/sessions"
        me = client.get("/v1/me").json()
        assert me["username"] == "test"
        assert me["is_admin"] is False

    def test_missing_password_says_so(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        page = client.post("/ui/login", data={"username": "test", "password": ""})

        assert page.status_code == 401
        assert "密码" in page.text
        assert "请输入 OpenAgent 令牌，或测试账号与密码" not in page.text

    def test_wrong_password_says_so(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        page = client.post("/ui/login", data={"username": "test", "password": "nope"})

        assert page.status_code == 401
        assert "测试账号或密码不正确" in page.text

    def test_disabled_test_account_explains_itself(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair, test_username="", test_password="")
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        page = client.post(
            "/ui/login", data={"username": "test", "password": "test@123456"}
        )

        assert page.status_code == 401
        assert "测试账号未启用" in page.text

    def test_nothing_entered_keeps_the_generic_hint(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        page = client.post(
            "/ui/login", data={"token": "", "username": "", "password": ""}
        )

        assert page.status_code == 401
        assert "请使用企业账号登录，或使用测试账号" in page.text

    def test_test_account_cannot_reach_admin(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))
        client.post(
            "/ui/login",
            data={"username": "test", "password": "test@123456"},
            follow_redirects=False,
        )

        assert (
            client.post(
                "/ui/admin/login",
                data={"username": "admin", "password": "admin@123456"},
                follow_redirects=False,
            ).status_code
            == 403
        )
        assert client.post("/v1/reveal/deadbeefdeadbeef").status_code == 403


class TestManualTokenLogin:
    def test_valid_token_signs_in(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        resp = client.post(
            "/ui/login", data={"token": "tok-alice"}, follow_redirects=False
        )

        assert resp.status_code == 302
        assert client.get("/v1/me").json()["username"] == "alice"


class TestSsoRoundTrip:
    def test_start_redirects_to_sso_with_pkce(self, sso_app):
        container, _ = sso_app
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        resp = client.get("/ui/login/sso/start", follow_redirects=False)

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("https://sso.example.com/authorize")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        assert query["client_id"] == ["openagent-audit"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == [
            "http://testserver/ui/login/sso/callback"
        ]
        # the state cookie is set for the callback to verify
        assert "openagent_audit_sso_state" in resp.headers["set-cookie"]

    def test_callback_signs_in_as_the_sso_user(self, sso_app):
        container, mock = sso_app
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        start = client.get("/ui/login/sso/start", follow_redirects=False)
        authorize_url = start.headers["location"]
        # the SSO would redirect back with the code; extract the state like the browser does
        query = urllib.parse.parse_qs(urllib.parse.urlparse(authorize_url).query)
        state = query["state"][0]

        callback = f"/ui/login/sso/callback?code=auth-code&state={urllib.parse.quote(state)}"
        resp = client.get(callback, follow_redirects=False)

        assert resp.status_code == 302
        assert resp.headers["location"] == "/ui/sessions"
        me = client.get("/v1/me").json()
        assert me["username"] == "zhang.san"  # the mock SSO answers with this identity
        assert me["is_admin"] is False

    def test_callback_is_audited(self, sso_app):
        container, mock = sso_app
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        start = client.get("/ui/login/sso/start", follow_redirects=False)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(start.headers["location"]).query)
        state = query["state"][0]
        client.get(
            f"/ui/login/sso/callback?code=auth-code&state={urllib.parse.quote(state)}",
            follow_redirects=False,
        )

        entry = [e for e in container.db.iter_audit() if e.action == "LOGIN"][-1]
        assert entry.actor == "zhang.san"
        assert entry.detail["via"] == "sso"

    def test_tampered_state_is_rejected(self, sso_app):
        container, mock = sso_app
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))
        client.get("/ui/login/sso/start", follow_redirects=False)

        page = client.get(
            "/ui/login/sso/callback?code=auth-code&state=forged", follow_redirects=False
        )

        assert page.status_code == 400
        assert "state 不匹配" in page.text

    def test_sso_failure_lands_on_the_login_page(self, tmp_path, keypair):
        container = _make_app(tmp_path, keypair)
        # point the client at an unreachable SSO (no mocked transport)
        from openagent_audit.services.sso import SsoClient

        container.sso = SsoClient(container.settings)  # authority is example.com
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        page = client.get("/ui/login/sso/start")

        # discovery fails; the page explains and keeps the test form available
        assert page.status_code in (200, 502)
        assert "name=\"username\"" in page.text

    def test_automatic_login_grants_no_admin(self, sso_app):
        container, mock = sso_app
        from fastapi.testclient import TestClient

        client = TestClient(create_audit_app(container))

        start = client.get("/ui/login/sso/start", follow_redirects=False)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(start.headers["location"]).query)
        state = query["state"][0]
        client.get(
            f"/ui/login/sso/callback?code=auth-code&state={urllib.parse.quote(state)}",
            follow_redirects=False,
        )

        assert client.get("/v1/audit-log").status_code == 403
        assert client.post("/v1/reveal/deadbeefdeadbeef").status_code == 403
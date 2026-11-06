"""Getting into the console: automatic platform login, test account, errors.

Three paths must work and must not be confused with each other:

* **Automatic** — OpenAgent redirects with ``?token=...``; the browser is
  signed in immediately as itself. This is the normal way in.
* **Manual token** — the user pastes a token into the first form.
* **Test account** — the fallback form, always an ordinary user.

The test-account form used to live inside a collapsed ``<details>`` element
alongside the token field. A collapsed block can omit its inputs from the
submission, so a correctly typed test login arrived with an empty username and
the page answered "请输入 OpenAgent 令牌，或测试账号与密码" — the user was told to
type what they had just typed. The forms are now independent, and these tests
pin that structure so it cannot regress.
"""

from __future__ import annotations

import httpx
import pytest

from openagent_audit.config import Settings, UserEntry
from openagent_audit.services.audit_api import build_container, create_audit_app
from tests.conftest import PASSPHRASE


def _client(tmp_path, keypair, **overrides):
    from fastapi.testclient import TestClient

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
    container = build_container(Settings(**base))
    return TestClient(create_audit_app(container)), container


class TestLoginPageStructure:
    def test_two_independent_forms(self, api_client):
        """Token form and test-account form must be separate, and the test one
        collapsed by default.

        Collapsing is fine *because* the test account has its own ``<form>``:
        hiding the section hides the form, it never strips fields from a
        submission. The earlier bug was a single form whose test fields lived
        inside a collapsed block.
        """
        page = api_client.get("/ui/login").text

        assert page.count('<form action="/ui/login"') >= 2
        assert 'name="token"' in page
        assert 'name="username"' in page
        assert 'name="password"' in page

        # Collapsed on a first visit...
        assert '<details id="test-login"' in page
        assert '<details id="test-login" open>' not in page

    def test_test_section_opens_after_a_failed_attempt(self, tmp_path, keypair):
        """A failed login must reveal the form instead of hiding the error."""
        client, _ = _client(tmp_path, keypair)

        page = client.post("/ui/login", data={"username": "test", "password": "nope"})

        assert page.status_code == 401
        assert '<details id="test-login" open>' in page.text

    def test_test_username_is_prefilled(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)
        page = client.get("/ui/login").text
        assert 'value="test"' in page


class TestTestAccountLogin:
    def test_correct_credentials_sign_in(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)

        resp = client.post(
            "/ui/login",
            data={"token": "", "username": "test", "password": "test@123456"},
            follow_redirects=False,
        )

        assert resp.status_code == 302
        assert resp.headers["location"] == "/ui/sessions"
        me = client.get("/v1/me").json()
        assert me["username"] == "test"
        assert me["role"] == "user"
        assert me["is_admin"] is False

    def test_empty_token_field_does_not_block_the_test_login(self, tmp_path, keypair):
        """This is the exact shape a browser submits from the second form."""
        client, _ = _client(tmp_path, keypair)

        resp = client.post(
            "/ui/login",
            data={"token": "", "username": "test", "password": "test@123456"},
            follow_redirects=False,
        )

        assert resp.status_code == 302, resp.text

    def test_missing_password_says_so(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)

        page = client.post("/ui/login", data={"username": "test", "password": ""})

        assert page.status_code == 401
        assert "密码" in page.text
        # must not claim nothing was entered
        assert "请输入 OpenAgent 令牌，或测试账号与密码" not in page.text

    def test_wrong_password_says_so(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)

        page = client.post("/ui/login", data={"username": "test", "password": "nope"})

        assert page.status_code == 401
        assert "测试账号或密码不正确" in page.text

    def test_disabled_test_account_explains_itself(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair, test_username="", test_password="")

        page = client.post("/ui/login", data={"username": "test", "password": "test@123456"})

        assert page.status_code == 401
        assert "测试账号未启用" in page.text

    def test_nothing_entered_keeps_the_generic_hint(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)

        page = client.post("/ui/login", data={"token": "", "username": "", "password": ""})

        assert page.status_code == 401
        assert "请输入 OpenAgent 令牌，或测试账号与密码" in page.text


class TestAutomaticPlatformLogin:
    """``/ui/login?token=...`` is how OpenAgent hands a signed-in user over."""

    def test_url_token_signs_in_without_typing(self, tmp_path, keypair):
        client, container = _client(tmp_path, keypair)

        resp = client.get("/ui/login?token=tok-alice", follow_redirects=False)

        assert resp.status_code == 302
        assert resp.headers["location"] == "/ui/sessions"
        me = client.get("/v1/me").json()
        assert me["username"] == "alice"

    def test_automatic_login_is_recorded(self, tmp_path, keypair):
        client, container = _client(tmp_path, keypair)

        client.get("/ui/login?token=tok-alice", follow_redirects=False)

        entry = [e for e in container.db.iter_audit() if e.action == "LOGIN"][-1]
        assert entry.actor == "alice"
        assert entry.detail["via"] == "url-token"

    def test_token_is_not_rendered_into_the_page(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)
        client.get("/ui/login?token=tok-alice", follow_redirects=False)

        page = client.get("/ui/sessions").text

        assert "tok-alice" not in page

    def test_invalid_url_token_falls_back_to_the_forms(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)

        page = client.get("/ui/login?token=bogus")

        assert page.status_code == 401
        assert "令牌无效" in page.text
        # the manual forms are still offered, no redirect loop
        assert 'name="username"' in page.text

    def test_no_token_renders_the_plain_page(self, tmp_path, keypair):
        client, _ = _client(tmp_path, keypair)
        page = client.get("/ui/login")
        assert page.status_code == 200

    def test_platform_identity_resolves_through_me_endpoint(self, tmp_path, keypair):
        """The real integration path: OpenAgent's /me answers who the caller is."""
        from openagent_audit.services.auth import IdentityResolver

        settings = Settings(
            auth_provider="http",
            auth_introspect_url="http://engine:8083/api/v1/agent/me",
        )

        class FakeMe:
            def get(self, url, headers):
                assert headers["Authorization"] == "Bearer api-key-token"
                return httpx.Response(
                    200,
                    json={
                        "userId": "u-12345",
                        "username": "zhang.san",
                        "email": "zhang.san@corp.com",
                        "tenantId": "corp",
                        "roles": ["user"],
                        "isAuthenticated": True,
                    },
                )

        principal = IdentityResolver(settings, client=FakeMe()).resolve("api-key-token")

        assert principal is not None
        assert principal.username == "zhang.san"
        assert principal.role == "user"
        assert principal.can("reveal") is False

    def test_automatic_login_grants_no_admin(self, tmp_path, keypair):
        """Being signed in automatically must not skip the admin step-up."""
        client, _ = _client(tmp_path, keypair)
        client.get("/ui/login?token=tok-alice", follow_redirects=False)

        assert client.get("/v1/audit-log").status_code == 403
        assert client.post("/v1/reveal/deadbeefdeadbeef").status_code == 403

        page = client.get("/ui/sessions").text
        assert "登录管理员" in page  # the ordinary user may still step up
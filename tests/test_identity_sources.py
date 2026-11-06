"""Identity sources: OpenAgent platform, and the local test account fallback.

The console normally learns who you are from OpenAgent: the browser carries a
platform token and the platform's ``/me`` endpoint answers with the account.
Every such identity is an ordinary ``user``.

When the platform is not forwarding an identity, a local test account keeps the
console usable — but only for browsing. It cannot reach the administrator role,
and its session expires after one hour.
"""

from __future__ import annotations

import time

import httpx
import pytest

from openagent_audit.config import Settings, UserEntry
from tests.conftest import PASSPHRASE
from openagent_audit.services.audit_api import build_container
from openagent_audit.services.auth import (
    ROLE_ADMIN,
    ROLE_USER,
    IdentityResolver,
    Principal,
    SessionStore,
    _platform_username,
)


class TestPlatformIdentity:
    def test_openagent_me_shape_is_understood(self):
        """``/api/v1/agent/me`` answers with a user object, not just a name."""
        body = {
            "userId": "u-123",
            "username": "zhang.san",
            "email": "zhang.san@example.com",
            "tenantId": "corp",
            "roles": ["user"],
        }
        assert _platform_username(body) == "zhang.san"

    def test_falls_back_to_user_id(self):
        assert _platform_username({"userId": "u-123"}) == "u-123"
        assert _platform_username({"sub": "sub-9"}) == "sub-9"

    def test_prefers_username_over_id(self):
        assert _platform_username({"username": "li.si", "userId": "u-9"}) == "li.si"

    def test_rejects_blank(self):
        assert _platform_username({}) is None
        assert _platform_username({"username": "   "}) is None
        assert _platform_username(None) is None
        assert _platform_username("not-a-dict") is None

    def test_platform_role_claim_is_ignored(self):
        """A platform token never confers the administrator role."""
        settings = Settings(
            auth_provider="http",
            auth_introspect_url="https://openagent/api/v1/agent/me",
        )

        class ClaimsAdmin:
            def get(self, url, headers):
                return httpx.Response(
                    200, json={"username": "eve", "roles": ["admin"], "role": "admin"}
                )

        principal = IdentityResolver(settings, client=ClaimsAdmin()).resolve("tok")

        assert principal is not None
        assert principal.role == ROLE_USER
        assert principal.can("reveal") is False

    def test_rejects_when_platform_says_no(self):
        settings = Settings(
            auth_provider="http", auth_introspect_url="https://openagent/api/v1/agent/me"
        )

        class Unauthorized:
            def get(self, url, headers):
                return httpx.Response(401)

        assert IdentityResolver(settings, client=Unauthorized()).resolve("tok") is None

    def test_missing_config_fails_closed(self):
        resolver = IdentityResolver(Settings(auth_provider="http", auth_introspect_url=""))
        assert resolver.resolve("anything") is None


class TestLocalTestAccount:
    def _settings(self, **overrides) -> Settings:
        base = dict(test_username="test", test_password="test@1233456")
        base.update(overrides)
        return Settings(**base)

    def test_valid_credentials_produce_an_ephemeral_user(self):
        resolver = IdentityResolver(self._settings())

        principal = resolver.resolve_test_account("test", "test@1233456")

        assert principal is not None
        assert principal.username == "test"
        assert principal.role == ROLE_USER
        assert principal.ephemeral is True
        assert principal.can("reveal") is False

    def test_wrong_password_is_rejected(self):
        resolver = IdentityResolver(self._settings())
        assert resolver.resolve_test_account("test", "nope") is None

    def test_wrong_username_is_rejected(self):
        resolver = IdentityResolver(self._settings())
        assert resolver.resolve_test_account("admin", "test@1233456") is None

    def test_disabled_when_not_configured(self):
        resolver = IdentityResolver(Settings())
        assert resolver.resolve_test_account("test", "test@1233456") is None

    def test_refuses_to_shadow_the_admin_account(self):
        """A test account with the admin's name would be a back door."""
        resolver = IdentityResolver(
            self._settings(test_username="admin", admin_username="admin")
        )
        assert resolver.resolve_test_account("admin", "test@1233456") is None

    def test_cannot_step_up(self):
        assert Principal("test", ROLE_USER, ephemeral=True).can_step_up_to_admin is False
        assert Principal("alice", ROLE_USER).can_step_up_to_admin is True

    def test_session_store_refuses_to_promote(self):
        store = SessionStore()
        session = store.create(Principal("test", ROLE_USER, ephemeral=True))

        assert store.grant_admin(session.token) is None
        assert store.get(session.token).principal.role == ROLE_USER

    def test_session_expires_after_one_hour(self):
        store = SessionStore(test_session_seconds=3600)
        session = store.create(Principal("test", ROLE_USER, ephemeral=True))

        assert store.get(session.token) is not None

        # rewind creation time to just past the hour
        store._sessions[session.token] = type(session)(
            token=session.token,
            principal=session.principal,
            created_at=time.time() - 3601,
        )
        assert store.get(session.token) is None

    def test_platform_session_uses_the_idle_window(self):
        """The hourly limit belongs to the test account only."""
        store = SessionStore(test_session_seconds=3600, idle_seconds=8 * 3600)
        session = store.create(Principal("alice", ROLE_USER))

        store._sessions[session.token] = type(session)(
            token=session.token,
            principal=session.principal,
            created_at=time.time() - 7200,
        )
        assert store.get(session.token) is not None


class TestTestAccountOverHttp:
    @pytest.fixture()
    def client(self, api_client, settings):
        # enable the test account for this deployment profile
        container = api_client.app
        return api_client

    def _enable_test_account(self, container):
        container.identities._settings = type(container.settings)(
            **{
                **container.settings.__dict__,
                "test_username": "test",
                "test_password": "test@1233456",
            }
        )

    def test_test_login_works_and_hides_admin_entry(self, api_client, container):
        self._enable_test_account(container)

        resp = api_client.post(
            "/ui/login",
            data={"username": "test", "password": "test@1233456"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        page = api_client.get("/ui/sessions").text
        assert "普通用户" in page
        assert "登录管理员" not in page

    def test_test_account_login_is_audited(self, api_client, container):
        self._enable_test_account(container)
        api_client.post(
            "/ui/login",
            data={"username": "test", "password": "test@1233456"},
            follow_redirects=False,
        )

        entry = [e for e in container.db.iter_audit() if e.action == "LOGIN"][-1]
        assert entry.actor == "test"
        assert entry.detail["via"] == "test-account"
        assert entry.detail["ephemeral"] is True

    def test_test_account_cannot_reach_admin(self, api_client, container):
        self._enable_test_account(container)
        api_client.post(
            "/ui/login",
            data={"username": "test", "password": "test@1233456"},
            follow_redirects=False,
        )

        # the form is refused
        resp = api_client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert "测试账号" in resp.text

        # and the privileged page is refused too
        page = api_client.get("/ui/admin/login", follow_redirects=False)
        assert page.status_code == 403

        # the JSON endpoint agrees
        resp = api_client.post(
            "/v1/admin/login", json={"username": "admin", "password": "admin@123456"}
        )
        assert resp.status_code == 403

    def test_refusal_is_recorded(self, api_client, container):
        self._enable_test_account(container)
        api_client.post(
            "/ui/login",
            data={"username": "test", "password": "test@1233456"},
            follow_redirects=False,
        )
        api_client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )

        actions = [e.action for e in container.db.iter_audit()]
        assert "ADMIN_LOGIN_REFUSED" in actions

    def test_test_account_still_cannot_reveal(self, api_client, container):
        self._enable_test_account(container)
        api_client.post(
            "/ui/login",
            data={"username": "test", "password": "test@1233456"},
            follow_redirects=False,
        )
        assert api_client.post("/v1/reveal/deadbeefdeadbeef").status_code == 403


class TestPasswordHash:
    def test_hash_roundtrip(self):
        from openagent_audit.services.auth import hash_admin_password, verify_password_hash

        stored = hash_admin_password("admin@123456", iterations=1000)

        assert verify_password_hash(stored, "admin@123456") is True
        assert verify_password_hash(stored, "wrong") is False

    def test_hash_does_not_contain_the_password(self):
        from openagent_audit.services.auth import hash_admin_password

        stored = hash_admin_password("admin@123456", iterations=1000)

        assert "admin@123456" not in stored
        assert stored.startswith("pbkdf2_sha256$")

    def test_malformed_hash_is_rejected(self):
        from openagent_audit.services.auth import verify_password_hash

        assert verify_password_hash("not-a-hash", "admin@123456") is False
        assert verify_password_hash("", "admin@123456") is False

    def test_hash_takes_precedence_over_plaintext(self, tmp_path, keypair):
        """A configured hash wins, so a stale plaintext cannot weaken auth."""
        from fastapi.testclient import TestClient

        from openagent_audit.services.audit_api import create_audit_app
        from openagent_audit.services.auth import hash_admin_password

        public_pem, private_pem = keypair
        (tmp_path / "pub.pem").write_bytes(public_pem)
        (tmp_path / "priv.pem").write_bytes(private_pem)

        settings = Settings(
            audit_db_url=f"sqlite:///{tmp_path / 'a.db'}",
            users=(UserEntry("tok-alice", "alice", "user"),),
            admin_username="admin",
            admin_password="admin@123456",
            admin_password_hash=hash_admin_password("real-secret", iterations=1000),
            public_key_path=str(tmp_path / "pub.pem"),
            local_private_key_path=str(tmp_path / "priv.pem"),
            local_private_key_passphrase=PASSPHRASE.decode(),
            object_store="local",
            object_store_root=str(tmp_path / "obj"),
        )
        container = build_container(settings)
        client = TestClient(create_audit_app(container))

        client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)

        # the plaintext path no longer works
        wrong = client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )
        assert wrong.status_code == 401

        # the hashed password does
        right = client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "real-secret"},
            follow_redirects=False,
        )
        assert right.status_code == 302
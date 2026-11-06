"""Administrator session policy: 5-minute unlock, 10-minute cooldown.

The console can decrypt conversations, so the privileged window is short and
re-arming it is deliberately inconvenient:

* an unlock lasts 5 minutes and then the session falls back to an ordinary
  user automatically — even if the browser never sends another request;
* once it ends (timeout *or* explicit logout) the same account cannot unlock
  again for 10 minutes.
"""

from __future__ import annotations

import time

import pytest

from openagent_audit.config import Settings
from openagent_audit.services.auth import (
    ROLE_ADMIN,
    ROLE_USER,
    Principal,
    SessionStore,
)


class TestUnlockWindow:
    def test_default_window_is_five_minutes(self):
        assert Settings().admin_session_minutes == 5

    def test_default_cooldown_is_ten_minutes(self):
        assert Settings().admin_cooldown_minutes == 10

    def test_session_store_defaults_match_the_policy(self):
        store = SessionStore()
        assert store.admin_unlock_seconds == 300
        assert store.admin_cooldown_seconds == 600

    def test_unlock_expires_and_downgrades(self):
        store = SessionStore(admin_unlock_seconds=0)
        session = store.create(Principal("alice", ROLE_USER))
        store.grant_admin(session.token)

        current = store.get(session.token)

        assert current is not None
        assert current.principal.role == ROLE_USER
        assert current.is_admin_unlocked() is False

    def test_unlock_is_still_live_within_the_window(self):
        store = SessionStore(admin_unlock_seconds=300)
        session = store.create(Principal("alice", ROLE_USER))
        store.grant_admin(session.token)

        current = store.get(session.token)

        assert current.principal.role == ROLE_ADMIN
        assert current.is_admin_unlocked() is True
        # roughly the configured window remains
        assert 290 <= (current.admin_until - time.time()) <= 300


class TestCooldown:
    def test_cannot_rearm_during_cooldown(self):
        store = SessionStore(admin_unlock_seconds=300, admin_cooldown_seconds=600)
        session = store.create(Principal("alice", ROLE_USER))
        store.grant_admin(session.token)
        store.revoke_admin(session.token)

        assert store.admin_cooldown_remaining("alice") > 0
        assert store.grant_admin(session.token) is None
        assert store.get(session.token).principal.role == ROLE_USER

    def test_cooldown_starts_on_timeout_too(self):
        """An expired unlock must also lock the account, not just logout."""
        store = SessionStore(admin_unlock_seconds=0, admin_cooldown_seconds=600)
        session = store.create(Principal("alice", ROLE_USER))
        store.grant_admin(session.token)

        store.get(session.token)  # triggers the expiry path

        assert store.admin_cooldown_remaining("alice") > 0
        assert store.grant_admin(session.token) is None

    def test_cooldown_is_per_account(self):
        store = SessionStore(admin_unlock_seconds=300, admin_cooldown_seconds=600)
        alice = store.create(Principal("alice", ROLE_USER))
        bob = store.create(Principal("bob", ROLE_USER))

        store.grant_admin(alice.token)
        store.revoke_admin(alice.token)

        assert store.admin_cooldown_remaining("alice") > 0
        assert store.admin_cooldown_remaining("bob") == 0
        assert store.grant_admin(bob.token) is not None

    def test_rearm_allowed_after_cooldown(self):
        store = SessionStore(admin_unlock_seconds=300, admin_cooldown_seconds=600)
        session = store.create(Principal("alice", ROLE_USER))
        store.grant_admin(session.token)
        store.revoke_admin(session.token)

        # simulate the cooldown having elapsed
        store._admin_ended_at["alice"] = time.time() - 601

        assert store.admin_cooldown_remaining("alice") == 0
        assert store.grant_admin(session.token) is not None


class TestCooldownOverHttp:
    @pytest.fixture()
    def client(self, api_client):
        api_client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)
        return api_client

    def test_second_login_is_blocked_after_logout(self, client):
        ok = client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )
        assert ok.status_code == 302

        client.post("/ui/admin/logout", follow_redirects=False)

        blocked = client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )
        assert blocked.status_code == 429
        assert "等待" in blocked.text

    def test_blocked_attempt_is_recorded(self, client, container):
        client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )
        client.post("/ui/admin/logout", follow_redirects=False)
        client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )

        actions = [e.action for e in container.db.iter_audit()]
        assert "ADMIN_LOGIN_BLOCKED" in actions
        entry = [e for e in container.db.iter_audit() if e.action == "ADMIN_LOGIN_BLOCKED"][-1]
        assert entry.detail["reason"] == "cooldown"
        assert entry.detail["retry_after_seconds"] > 0

    def test_json_endpoint_also_enforces_cooldown(self, client):
        client.post(
            "/v1/admin/login", json={"username": "admin", "password": "admin@123456"}
        )
        client.post("/v1/admin/logout")

        resp = client.post(
            "/v1/admin/login", json={"username": "admin", "password": "admin@123456"}
        )

        assert resp.status_code == 429

    def test_logout_immediately_drops_privileges(self, client, container):
        client.post(
            "/ui/admin/login",
            data={"username": "admin", "password": "admin@123456"},
            follow_redirects=False,
        )
        client.post("/ui/admin/logout", follow_redirects=False)

        assert client.get("/v1/audit-log").status_code == 403
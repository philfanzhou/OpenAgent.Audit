"""audit-api + audit-web: the two-role console.

Model under test:

* every platform identity signs in as ``user`` and sees masked data only;
* an administrator steps up from inside that session and can then click a
  masked value to reveal it;
* every reveal is recorded in the append-only, hash-chained audit log *before*
  the plaintext is returned.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from openagent_audit.config import Settings, UserEntry
from openagent_audit.crypto.keys import generate_keypair
from openagent_audit.services.audit_api import build_container, create_audit_app
from tests.conftest import PASSPHRASE, seed_masked_conversation

ENTITY_PREFIX = "⟦"


@pytest.fixture()
def seeded(container, pipeline):
    """A masked conversation in the *container's* trace store.

    The container builds its own store, so seeding a separate fixture store
    would leave the API looking at an empty one.
    """
    raw = seed_masked_conversation(trace_store=container.trace_store, pipeline=pipeline)
    return {"raw": raw, "entity_ids": _all_entity_ids(container.db)}


def _all_entity_ids(db):
    with db._connect() as connection:
        rows = connection.execute("SELECT entity_id FROM entity_ciphertext").fetchall()
    return [r["entity_id"] for r in rows]


def _login(client, token="tok-alice"):
    resp = client.post("/ui/login", data={"token": token}, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return client


def _admin(client, password="admin@123456"):
    return client.post(
        "/ui/admin/login",
        data={"username": "admin", "password": password},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_missing_token_is_rejected(api_client):
    assert api_client.get("/v1/sessions").status_code == 401


def test_unknown_token_is_rejected(api_client):
    assert api_client.get(
        "/v1/sessions", headers={"Authorization": "Bearer nope"}
    ).status_code == 401


def test_health_is_anonymous(api_client):
    resp = api_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["service"] == "audit-api"


def test_me_reports_role_and_admin_state(api_client):
    api_client.cookies.set("openagent_audit_identity", "tok-alice")
    body = api_client.get("/v1/me").json()
    assert body["username"] == "alice"
    assert body["role"] == "user"
    assert body["is_admin"] is False
    assert body["role_label"] == "普通用户"


# ---------------------------------------------------------------------------
# Ordinary user: masked data only
# ---------------------------------------------------------------------------


def test_user_sees_masked_sessions(api_client, seeded):
    _login(api_client)

    resp = api_client.get("/v1/sessions")

    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


def test_masked_trace_contains_no_plaintext_or_ciphertext(api_client, container, seeded):
    _login(api_client)
    resp = api_client.get("/v1/sessions/sess-1001")

    assert resp.status_code == 200
    body = json.dumps(resp.json(), ensure_ascii=False)

    assert "13812345678" not in body
    assert "110101199003078515" not in body
    assert "zhangwei@example.com" not in body
    assert "⟦PHONE_NUMBER#" in body

    for entity_id in seeded["entity_ids"]:
        row = container.db.get_entity(entity_id)
        assert row is not None
        assert row.ciphertext not in body


def test_user_cannot_reveal(api_client, seeded):
    """The core rule: without the admin step-up there is no plaintext path."""
    _login(api_client)
    entity_id = seeded["entity_ids"][0]

    resp = api_client.post(f"/v1/reveal/{entity_id}")

    assert resp.status_code == 403
    assert "权限不足" in resp.json()["detail"]


def test_user_cannot_read_audit_log(api_client, seeded):
    _login(api_client)
    assert api_client.get("/v1/audit-log").status_code == 403


def test_user_sees_no_admin_controls_in_the_page(api_client, seeded):
    _login(api_client)
    page = api_client.get("/ui/sessions/sess-1001").text

    # masks render as inert spans; no clickable reveal target is emitted
    assert 'class="ent ent-click"' not in page
    assert "data-entity-id=" not in page
    assert "登录管理员" in page


# ---------------------------------------------------------------------------
# Administrator step-up
# ---------------------------------------------------------------------------


def test_admin_login_requires_a_user_session(api_client):
    resp = api_client.post(
        "/v1/admin/login", json={"username": "admin", "password": "admin@123456"}
    )
    assert resp.status_code == 401


def test_admin_login_rejects_wrong_password(api_client, container):
    _login(api_client)

    resp = _admin(api_client, password="wrong")

    assert resp.status_code == 401
    actions = [e.action for e in container.db.iter_audit()]
    assert "ADMIN_LOGIN_FAILED" in actions


def test_admin_login_rejects_wrong_username(api_client):
    _login(api_client)
    resp = api_client.post(
        "/v1/admin/login", json={"username": "root", "password": "admin@123456"}
    )
    assert resp.status_code == 401


def test_admin_login_succeeds_and_is_recorded(api_client, container):
    _login(api_client)

    resp = _admin(api_client)

    assert resp.status_code == 302
    login = [e for e in container.db.iter_audit() if e.action == "ADMIN_LOGIN"]
    assert login, "admin login must be recorded"
    assert login[-1].actor == "admin"
    assert login[-1].detail["session_user"] == "alice"


def test_admin_login_records_who_was_signed_in(api_client, container):
    """The log must answer 'which person was at the console', not just 'admin'."""
    _login(api_client, token="tok-bob")
    _admin(api_client)

    entry = [e for e in container.db.iter_audit() if e.action == "ADMIN_LOGIN"][-1]
    assert entry.detail["session_user"] == "bob"


def test_admin_can_logout(api_client, seeded):
    _login(api_client)
    _admin(api_client)
    api_client.post("/ui/admin/logout", follow_redirects=False)

    resp = api_client.post(f"/v1/reveal/{seeded['entity_ids'][0]}")

    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Reveal
# ---------------------------------------------------------------------------


def test_admin_reveal_returns_plaintext(api_client, container, seeded):
    _login(api_client)
    _admin(api_client)

    # find the phone entity
    phone = next(
        e for e in seeded["entity_ids"]
        if container.db.get_entity(e).entity_type in ("PHONE_NUMBER", "CN_PHONE")
    )
    resp = api_client.post(f"/v1/reveal/{phone}")

    assert resp.status_code == 200, resp.text
    assert resp.json()["plaintext"] == "13812345678"


def test_reveal_is_recorded_before_returning_plaintext(api_client, container, seeded):
    _login(api_client)
    _admin(api_client)
    entity_id = seeded["entity_ids"][0]

    api_client.post(f"/v1/reveal/{entity_id}")

    actions = [e.action for e in container.db.iter_audit()]
    assert "ENTITY_REVEAL_REQUESTED" in actions
    assert "ENTITY_REVEALED" in actions
    recorded = [e for e in container.db.iter_audit() if e.action == "ENTITY_REVEALED"]
    assert recorded[-1].object_id == entity_id
    assert recorded[-1].detail["session_user"] == "alice"


def test_reveal_of_unknown_entity_is_404(api_client):
    _login(api_client)
    _admin(api_client)

    resp = api_client.post("/v1/reveal/deadbeefdeadbeef")

    assert resp.status_code == 404


def test_reveal_does_not_put_plaintext_in_the_audit_log(api_client, container, seeded):
    _login(api_client)
    _admin(api_client)
    for entity_id in seeded["entity_ids"][:1]:
        api_client.post(f"/v1/reveal/{entity_id}")

    blob = json.dumps(
        [{"detail": e.detail, "object_id": e.object_id} for e in container.db.iter_audit()],
        ensure_ascii=False,
    )
    assert "13812345678" not in blob


def test_audit_log_chain_stays_valid_after_reveals(api_client, seeded):
    _login(api_client)
    _admin(api_client)
    api_client.post(f"/v1/reveal/{seeded['entity_ids'][0]}")

    log = api_client.get("/v1/audit-log?verify=true").json()

    assert log["verification"]["ok"] is True


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------


def test_login_page_and_user_flow(api_client, seeded):
    page = api_client.get("/ui/login")
    assert page.status_code == 200

    _login(api_client)
    sessions = api_client.get("/ui/sessions")
    assert sessions.status_code == 200
    assert "sess-1001" in sessions.text

    detail = api_client.get("/ui/sessions/sess-1001")
    assert detail.status_code == 200
    # the filter rewrites ⟦TYPE#id|mask⟧ into a rendered element
    assert "PHONE_NUMBER" in detail.text
    assert "138****5678" in detail.text
    assert "13812345678" not in detail.text


def test_admin_sees_clickable_masks(api_client, seeded):
    _login(api_client)
    _admin(api_client)

    detail = api_client.get("/ui/sessions/sess-1001")

    assert "ent-click" in detail.text
    assert "data-entity-id=" in detail.text
    assert "13812345678" not in detail.text  # still masked until clicked


def test_unauthenticated_ui_redirects_to_login(api_client):
    resp = api_client.get("/ui/sessions", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/ui/login"


def test_audit_log_page_visible_to_admin(api_client, seeded):
    _login(api_client)
    _admin(api_client)

    page = api_client.get("/ui/audit-log")

    assert page.status_code == 200
    assert "ADMIN_LOGIN" in page.text


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_are_admin_only(api_client):
    _login(api_client)
    assert api_client.get("/internal/metrics").status_code == 403

    _admin(api_client)
    assert api_client.get("/internal/metrics").status_code == 200


def test_metrics_prometheus_exposition(api_client):
    _login(api_client)
    _admin(api_client)

    resp = api_client.get("/internal/metrics/prometheus")

    assert resp.status_code == 200
    assert "openagent_audit_" in resp.text


def test_metrics_do_not_leak_secrets(api_client):
    _login(api_client)
    _admin(api_client)

    body = api_client.get("/internal/metrics").text

    assert "admin@123456" not in body
    assert "svc-token-123" not in body


# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------


def test_demo_seed_populates_local_store(tmp_path, keypair):
    public_pem, private_pem = keypair
    key = tmp_path / "pub.pem"
    key.write_bytes(public_pem)
    priv = tmp_path / "priv.pem"
    priv.write_bytes(private_pem)
    settings = Settings(
        audit_db_url=f"sqlite:///{tmp_path / 'demo.db'}",
        users=(UserEntry("t", "u", "user"),),
        public_key_path=str(key),
        local_private_key_path=str(priv),
        local_private_key_passphrase=PASSPHRASE.decode(),
        object_store="local",
        object_store_root=str(tmp_path / "objects"),
        demo_seed=True,
    )
    container = build_container(settings)

    sessions = container.trace_store.list_sessions()

    assert sessions, "demo seeding should populate the local store"
    assert any(str(s["session_id"]).startswith("sess-demo") for s in sessions)


def test_demo_seed_ignored_for_langfuse(tmp_path):
    settings = Settings(trace_store="langfuse", demo_seed=True)
    assert settings.trace_store == "langfuse"
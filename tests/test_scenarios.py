"""Cross-cutting scenario suite.

Every case here corresponds to a probe run against the real code paths; the
ones that originally failed are marked with the defect they caught. Kept as
pytest so the behaviours cannot regress silently.
"""

from __future__ import annotations

import concurrent.futures
import json
import pathlib
import tempfile
import threading

import pytest
from fastapi.testclient import TestClient

from openagent_audit.bootstrap import build_cipher, build_db, build_key_provider, build_write_cipher
from openagent_audit.config import Settings, UserEntry
from openagent_audit.crypto.envelope import RsaEnvelopeCipher
from openagent_audit.crypto.keys import (
    LocalKeyProvider,
    generate_keypair,
    load_public_key,
)
from openagent_audit.gateway.app import GatewayCounters, GatewayDeps, create_gateway_app
from openagent_audit.pii.engine import RuleBasedEngine
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
from openagent_audit.pii.recognizers import _name_recognizer, _phone_recognizer
from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.services.audit_api import build_container, create_audit_app
from openagent_audit.services.retention import RetentionJob
from openagent_audit.tracing.trace_store import LocalTraceStore, ObservationRecord, TraceRecord
from openagent_audit.vault.store import SQLiteAuditDatabase
from tests.conftest import VALID_ID, VALID_PHONE, make_valid_bank_card

PASSPHRASE = b"scenario-pass"
PHONE = "13812345678"


@pytest.fixture()
def keys(tmp_path):
    pub, priv = generate_keypair(PASSPHRASE)
    (tmp_path / "pub.pem").write_bytes(pub)
    (tmp_path / "priv.pem").write_bytes(priv)
    return tmp_path


# ---------------------------------------------------------------------------
# A. PII recall  (defects: adjacent numbers and X-checksum IDs leaked)
# ---------------------------------------------------------------------------


class TestPhoneBoundaries:
    @pytest.mark.parametrize(
        "text",
        [
            PHONE,
            f"电话{PHONE}",
            f"电话：{PHONE}",
            "138 1234 5678",
            "138-1234-5678",
            "１３８１２３４５６７８",
            f"（{PHONE}）",
            f'"{PHONE}"',
            f"联系{PHONE}。",
            f"电话\n{PHONE}",
            f"电话\t{PHONE}",
        ],
    )
    def test_variants_are_detected(self, text):
        assert _phone_recognizer(text), text

    def test_two_adjacent_numbers_are_both_detected(self):
        """DEFECT: a 22-digit blob matched nothing, leaking both numbers."""
        spans = _phone_recognizer(PHONE + "13900001111")
        assert len(spans) == 2, [(s.start, s.end) for s in spans]

    def test_phone_glued_to_id_card_is_detected(self):
        """DEFECT: the 29-digit run hid the phone number entirely."""
        assert _phone_recognizer(PHONE + VALID_ID)

    def test_repeated_numbers_are_detected(self):
        """DEFECT: 50 repetitions produced zero matches."""
        spans = _phone_recognizer(PHONE * 20)
        assert len(spans) >= 20, len(spans)

    @pytest.mark.parametrize("text", ["113812345678", "138123456789", "12345678901"])
    def test_longer_or_invalid_runs_are_not_phones(self, text):
        assert _phone_recognizer(text) == [], text


class TestPersonNamePrecision:
    def test_business_nouns_are_not_names(self):
        """DEFECT: "联系电话" produced PERSON='电话', which consumed a vault row
        and masked the word instead of the number."""
        for text in (
            "联系电话13812345678",
            "联系地址北京市",
            "联系公司人事部",
            "这是系统问题",
            "我是客服",
            "听说客户投诉",
            "交给财务处理",
            "咨询产品价格",
            "询问订单状态",
        ):
            assert _name_recognizer(text) == [], text

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("帮我联系下张伟", "张伟"),
            ("请联系李娜", "李娜"),
            ("询问王小明", "王小明"),
            ("张伟先生", "张伟"),
            ("王强经理", "王强"),
        ],
    )
    def test_real_names_still_detected(self, text, expected):
        values = [s.value for s in _name_recognizer(text)]
        assert expected in values, values


class TestMaskingLeavesNoPlaintext:
    def test_entity_types_do_not_overlap(self):
        engine = RuleBasedEngine()
        spans = engine.detect(VALID_ID)
        types = {s.entity_type for s in spans}
        assert "ID_CARD" in types
        assert "PHONE_NUMBER" not in types or len(types) == 1


# ---------------------------------------------------------------------------
# B. Authorization matrix
# ---------------------------------------------------------------------------


@pytest.fixture()
def api(keys):
    """Two-role console: platform identities are users; admin logs in on top."""
    settings = Settings(
        audit_db_url=f"sqlite:///{keys}/api.db",
        users=(
            UserEntry("tok-alice", "alice", "user"),
            UserEntry("tok-bob", "bob", "user"),
        ),
        admin_username="admin",
        admin_password="admin@123456",
        admin_session_minutes=30,
        public_key_path=str(keys / "pub.pem"),
        local_private_key_path=str(keys / "priv.pem"),
        local_private_key_passphrase=PASSPHRASE.decode(),
        object_store="local",
        object_store_root=str(keys / "obj"),
    )
    container = build_container(settings)
    return TestClient(create_audit_app(container)), container


def _sign_in(client, token="tok-alice"):
    client.post("/ui/login", data={"token": token}, follow_redirects=False)
    return client


def _admin(client, password="admin@123456"):
    return client.post(
        "/ui/admin/login",
        data={"username": "admin", "password": password},
        follow_redirects=False,
    )


class TestBadTokens:
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer nope"},
            {"Authorization": "Basic dG9rLWFsaWNlOng="},
            {"Authorization": "Bearer tok-alic"},
        ],
    )
    def test_rejected(self, api, headers):
        client, _ = api
        assert client.get("/v1/sessions", headers=headers).status_code == 401


class TestTwoRoleModel:
    @pytest.mark.parametrize(
        "endpoint,expected",
        [
            ("/v1/sessions", 200),
            ("/v1/traces", 200),
            ("/v1/audit-log", 403),
            ("/internal/metrics", 403),
        ],
    )
    def test_ordinary_user_permissions(self, api, endpoint, expected):
        client, _ = api
        _sign_in(client)
        assert client.get(endpoint).status_code == expected

    @pytest.mark.parametrize(
        "endpoint",
        ["/v1/sessions", "/v1/traces", "/v1/audit-log", "/internal/metrics"],
    )
    def test_administrator_permissions(self, api, endpoint):
        client, _ = api
        _sign_in(client)
        _admin(client)
        assert client.get(endpoint).status_code == 200

    def test_forbidden_message_is_readable_and_leak_free(self, api):
        client, _ = api
        _sign_in(client)
        detail = client.get("/v1/audit-log").json()["detail"]
        assert "权限不足" in detail
        assert "Traceback" not in detail and ".py" not in detail

    def test_platform_role_claim_cannot_grant_admin(self, keys):
        """Even if the platform says 'admin', the audit plane decides."""
        resolver_settings = Settings(
            auth_provider="http",
            auth_introspect_url="https://platform/introspect",
        )
        from openagent_audit.services.auth import ROLE_USER, IdentityResolver

        class ClaimAdmin:
            def get(self, url, headers):
                import httpx

                return httpx.Response(200, json={"username": "eve", "role": "admin"})

        resolver = IdentityResolver(resolver_settings, client=ClaimAdmin())
        principal = resolver.resolve("tok")

        assert principal is not None
        assert principal.role == ROLE_USER
        assert not principal.can("reveal")


class TestAdminStepUp:
    def test_requires_signed_in_session(self, api):
        """Without a session the console sends the browser to sign-in first."""
        client, _ = api
        resp = _admin(client)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/ui/login"

    def test_rejects_wrong_password(self, api):
        client, _ = api
        _sign_in(client)
        assert _admin(client, password="nope").status_code == 401

    def test_unlock_is_time_bounded(self, keys):
        """An unlock expires on its own so an idle tab cannot decrypt forever."""
        from openagent_audit.services.auth import Principal, SessionStore

        store = SessionStore(admin_unlock_seconds=0)
        session = store.create(Principal("alice", "user"))
        store.grant_admin(session.token)

        unlocked = store.get(session.token)

        assert unlocked is not None
        assert not unlocked.is_admin_unlocked()


class TestRevealModel:
    @pytest.fixture()
    def seeded(self, api):
        client, container = api
        import openagent_audit.bootstrap as bootstrap
        from openagent_audit.pii.masking import MaskingPipeline, VaultWriter

        pipeline = MaskingPipeline(
            cipher=bootstrap.build_cipher(container.settings, bootstrap.build_key_provider(container.settings)),
            vault_writer=VaultWriter(container.db),
        )
        result = pipeline.protect(f"电话{PHONE}", trace_id="t1", session_id="s1")
        return client, result.entities[0].entity_id, container

    def test_user_cannot_reveal(self, seeded):
        client, entity_id, _ = seeded
        _sign_in(client)

        assert client.post(f"/v1/reveal/{entity_id}").status_code == 403

    def test_admin_reveals_and_is_logged(self, seeded):
        client, entity_id, container = seeded
        _sign_in(client)
        _admin(client)

        resp = client.post(f"/v1/reveal/{entity_id}")

        assert resp.status_code == 200, resp.text
        assert resp.json()["plaintext"] == PHONE

        actions = [e.action for e in container.db.iter_audit()]
        assert "ENTITY_REVEALED" in actions
        entry = [e for e in container.db.iter_audit() if e.action == "ENTITY_REVEALED"][-1]
        assert entry.detail["session_user"] == "alice"

    def test_reveal_records_precede_the_plaintext(self, seeded):
        """The request entry is written before decryption is attempted."""
        client, entity_id, container = seeded
        _sign_in(client)
        _admin(client)

        client.post(f"/v1/reveal/{entity_id}")

        actions = [e.action for e in container.db.iter_audit()]
        assert actions.index("ENTITY_REVEAL_REQUESTED") < actions.index("ENTITY_REVEALED")

    def test_chain_remains_valid(self, seeded):
        client, entity_id, container = seeded
        _sign_in(client)
        _admin(client)
        client.post(f"/v1/reveal/{entity_id}")

        assert container.audit.verify()["ok"] is True

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
    settings = Settings(
        audit_db_url=f"sqlite:///{keys}/api.db",
        users=(
            UserEntry("tok-auditor", "alice", "auditor"),
            UserEntry("tok-lead", "bob", "compliance_lead"),
            UserEntry("tok-lead2", "carol", "compliance_lead"),
            UserEntry("tok-dev", "dan", "developer"),
        ),
        public_key_path=str(keys / "pub.pem"),
        local_private_key_path=str(keys / "priv.pem"),
        local_private_key_passphrase=PASSPHRASE.decode(),
        object_store="local",
        object_store_root=str(keys / "obj"),
        reveal_ttl_minutes=5,
    )
    container = build_container(settings)
    return TestClient(create_audit_app(container)), container


class TestBadTokens:
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer nope"},
            {"Authorization": "Basic dG9rLWF1ZGl0b3I6eA=="},
            {"Authorization": "Bearer tok-audito"},
            {"Authorization": "bearer TOK-AUDITOR"},
        ],
    )
    def test_rejected(self, api, headers):
        client, _ = api
        assert client.get("/v1/sessions", headers=headers).status_code == 401


class TestRoleMatrix:
    @pytest.mark.parametrize(
        "token,endpoint,expected",
        [
            ("tok-auditor", "/v1/sessions", 200),
            ("tok-auditor", "/internal/metrics", 403),
            ("tok-dev", "/v1/sessions", 200),
            ("tok-dev", "/internal/metrics", 200),
            ("tok-lead", "/v1/sessions", 200),
            ("tok-lead", "/internal/metrics", 403),
        ],
    )
    def test_visibility(self, api, token, endpoint, expected):
        client, _ = api
        r = client.get(endpoint, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == expected, r.text[:120]

    @pytest.mark.parametrize("token", ["tok-auditor", "tok-dev"])
    def test_non_leads_cannot_request_restore(self, api, token):
        client, _ = api
        r = client.post("/v1/restore-requests",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"object_type": "entity", "object_id": "x", "reason": "r"})
        assert r.status_code == 403

    def test_forbidden_message_is_readable_and_leak_free(self, api):
        client, _ = api
        detail = client.post(
            "/v1/restore-requests",
            headers={"Authorization": "Bearer tok-dev"},
            json={"object_type": "entity", "object_id": "x", "reason": "r"},
        ).json()["detail"]
        assert "权限不足" in detail
        assert "Traceback" not in detail and ".py" not in detail
        assert "SELECT" not in detail.upper()


# ---------------------------------------------------------------------------
# C. Four-eyes workflow
# ---------------------------------------------------------------------------


class TestFourEyes:
    @pytest.fixture()
    def seeded(self, api):
        client, container = api
        pipeline = MaskingPipeline(
            cipher=build_cipher(container.settings, build_key_provider(container.settings)),
            vault_writer=VaultWriter(container.db),
        )
        result = pipeline.protect(f"电话{PHONE}", trace_id="t1", session_id="s1")
        return client, result.entities[0].entity_id

    def test_requester_cannot_self_approve(self, seeded):
        client, entity = seeded
        rid = client.post("/v1/restore-requests", headers={"Authorization": "Bearer tok-lead"},
                          json={"object_type": "entity", "object_id": entity, "reason": "x"}).json()["id"]
        r = client.post(f"/v1/restore-requests/{rid}/approve",
                        headers={"Authorization": "Bearer tok-lead"}, json={})
        assert r.status_code == 403
        assert r.json()["detail"] == "four_eyes"

    def test_second_lead_can_approve_and_reveal(self, seeded):
        client, entity = seeded
        rid = client.post("/v1/restore-requests", headers={"Authorization": "Bearer tok-lead"},
                          json={"object_type": "entity", "object_id": entity, "reason": "x"}).json()["id"]
        assert client.post(f"/v1/restore-requests/{rid}/approve",
                           headers={"Authorization": "Bearer tok-lead2"}, json={}).status_code == 200
        body = client.post(f"/v1/restore-requests/{rid}/reveal",
                           headers={"Authorization": "Bearer tok-lead2"}).json()
        assert body["plaintext"] == PHONE

    def test_reason_is_required(self, seeded):
        client, entity = seeded
        for payload in (
            {"object_type": "entity", "object_id": entity},
            {"object_type": "entity", "object_id": entity, "reason": "   "},
            {"object_type": "bogus", "object_id": entity, "reason": "x"},
        ):
            assert client.post("/v1/restore-requests",
                               headers={"Authorization": "Bearer tok-lead"},
                               json=payload).status_code == 422

    def test_audit_log_records_every_step_without_plaintext(self, seeded):
        client, entity = seeded
        rid = client.post("/v1/restore-requests", headers={"Authorization": "Bearer tok-lead"},
                          json={"object_type": "entity", "object_id": entity, "reason": "x"}).json()["id"]
        client.post(f"/v1/restore-requests/{rid}/reject",
                    headers={"Authorization": "Bearer tok-lead2"}, json={})
        log = client.get("/v1/audit-log?page_size=100",
                         headers={"Authorization": "Bearer tok-auditor"}).json()
        actions = {e["action"] for e in log["entries"]}
        assert {"RESTORE_REQUESTED", "RESTORE_REJECTED"} <= actions
        blob = json.dumps(log["entries"], ensure_ascii=False)
        assert PHONE not in blob
        assert client.get("/v1/audit-log?verify=true",
                          headers={"Authorization": "Bearer tok-auditor"}).json()["verification"]["ok"]


# ---------------------------------------------------------------------------
# D. Crypto invariants
# ---------------------------------------------------------------------------


class TestCrypto:
    def test_write_cipher_cannot_open(self):
        pub, priv = generate_keypair(PASSPHRASE)
        write = RsaEnvelopeCipher(load_public_key(pub))
        sealed = write.seal(b"secret", aad=b"e1")
        with pytest.raises(Exception):
            write.open(sealed, aad=b"e1")

    def test_aad_binding(self):
        pub, priv = generate_keypair(PASSPHRASE)
        read = RsaEnvelopeCipher(load_public_key(pub))
        read.bind_key_provider(LocalKeyProvider(priv, PASSPHRASE))
        sealed = RsaEnvelopeCipher(load_public_key(pub)).seal(b"secret", aad=b"e1")
        assert read.open(sealed, aad=b"e1") == b"secret"
        with pytest.raises(Exception):
            read.open(sealed, aad=b"e2")

    def test_ciphertext_is_randomised(self):
        pub, _ = generate_keypair(PASSPHRASE)
        c = RsaEnvelopeCipher(load_public_key(pub))
        assert c.seal(b"same", aad=b"e") != c.seal(b"same", aad=b"e")

    def test_wrong_passphrase_is_rejected(self, tmp_path):
        _, priv = generate_keypair(PASSPHRASE)
        (tmp_path / "k.pem").write_bytes(priv)
        with pytest.raises(Exception):
            LocalKeyProvider.from_file(str(tmp_path / "k.pem"), "wrong")


# ---------------------------------------------------------------------------
# E. Gateway robustness  (defects: malformed trees 500'd; nested values leaked)
# ---------------------------------------------------------------------------


@pytest.fixture()
def gateway(keys):
    settings = Settings(
        audit_db_url=f"sqlite:///{keys}/gw.db",
        public_key_path=str(keys / "pub.pem"),
        gateway_ingest_token="tok",
        gateway_max_body_bytes=1_000_000,
        gateway_max_spans=100,
    )
    db = build_db(settings)
    forwarded: list[bytes] = []
    deps = GatewayDeps(
        settings=settings,
        pipeline=MaskingPipeline(cipher=build_write_cipher(settings), vault_writer=VaultWriter(db)),
        forwarder=lambda p: forwarded.append(p),
    )
    return TestClient(create_gateway_app(deps)), forwarded, deps


AUTH = {"Authorization": "Bearer tok"}


class TestGatewayHostileInput:
    @pytest.mark.parametrize(
        "body",
        [b"", b"hello", b'{"resourceSpans": [', b"[1,2,3]", b"null"],
    )
    def test_malformed_body_is_4xx(self, gateway, body):
        client, forwarded, _ = gateway
        r = client.post("/v1/traces", content=body, headers={**AUTH, "content-type": "application/json"})
        assert 400 <= r.status_code < 500, r.status_code
        assert forwarded == []

    @pytest.mark.parametrize(
        "payload",
        [
            {"resourceSpans": [{"scopeSpans": [{"spans": None}]}]},
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": None}]}]}]},
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [{"key": "gen_ai.prompt"}]}]}]}]},
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [{"key": 1, "value": {"stringValue": "x"}}]}]}]}]},
            {"resourceSpans": [{"resource": None, "scopeSpans": []}]},
            {"resourceSpans": [{}]},
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"events": "boom"}]}]}]},
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"status": "ok"}]}]}]},
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": 42}]}]}]},
            {"resourceSpans": {"a": 1}},
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": {"k": "v"}}]}]}]},
        ],
    )
    def test_type_hostile_tree_never_500s(self, gateway, payload):
        """DEFECT: a non-string attribute key raised AttributeError -> 500."""
        client, _, _ = gateway
        r = client.post("/v1/traces", json=payload, headers=AUTH)
        assert r.status_code < 500, r.text[:200]


class TestNestedValueMasking:
    def test_array_and_kvlist_values_are_masked(self, gateway):
        """DEFECT: arrayValue/kvlistValue strings were forwarded in the clear."""
        client, forwarded, _ = gateway
        payload = {"resourceSpans": [{"scopeSpans": [{"scope": {"name": "svc"}, "spans": [{
            "traceId": "a" * 32,
            "name": "ok",
            "attributes": [
                {"key": "gen_ai.prompt.0.content", "value": {"stringValue": f"call {PHONE}"}},
                {"key": "gen_ai.prompt.1.content",
                 "value": {"arrayValue": {"values": [{"stringValue": "13900001111"}]}}},
                {"key": "gen_ai.prompt.2.content",
                 "value": {"kvlistValue": {"values": [
                     {"key": "note", "value": {"stringValue": "13800008888"}}]}}},
            ],
        }]}]}]}

        r = client.post("/v1/traces", json=payload, headers=AUTH)
        assert r.status_code == 200, r.text[:200]
        blob = forwarded[-1].decode()
        for number in (PHONE, "13900001111", "13800008888"):
            assert number not in blob, f"{number} leaked"

    def test_identifiers_survive_nested_values(self, gateway):
        client, forwarded, _ = gateway
        payload = {"resourceSpans": [{"scopeSpans": [{"spans": [{
            "traceId": "b" * 32,
            "attributes": [{"key": "openagent.conversation_id", "value": {"stringValue": "conv-7"}}],
        }]}]}]}
        client.post("/v1/traces", json=payload, headers=AUTH)
        assert "conv-7" in forwarded[-1].decode()


class TestGatewayConcurrency:
    def test_no_cross_request_contamination(self, gateway):
        client, forwarded, _ = gateway
        forwarded.clear()

        def one(i: int) -> int:
            body = {"resourceSpans": [{"scopeSpans": [{"spans": [{
                "traceId": f"{i:032x}",
                "attributes": [
                    {"key": "openagent.conversation_id", "value": {"stringValue": f"conv-{i}"}},
                    {"key": "gen_ai.prompt.0.content",
                     "value": {"stringValue": f"phone 1381234567{i % 10}"}},
                ],
            }]}]}]}
            return client.post("/v1/traces", json=body, headers=AUTH).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(one, range(20)))

        assert set(codes) == {200}
        assert len(forwarded) == 20
        for blob in forwarded:
            text = blob.decode()
            span = json.loads(text)["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
            conv = span["attributes"][0]["value"]["stringValue"]
            idx = int(conv.split("-")[1])
            assert conv in text
            assert f"1381234567{idx % 10}" not in text, "own plaintext not masked"


class TestGatewayCounters:
    def test_exact_under_concurrency(self):
        counters = GatewayCounters()
        per_thread, threads = 300, 8

        def hammer():
            for _ in range(per_thread):
                counters.record_batch_received()
                counters.record_spans_masked(2)

        workers = [threading.Thread(target=hammer) for _ in range(threads)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        snap = counters.snapshot()
        assert snap["batches_received"] == per_thread * threads
        assert snap["spans_masked"] == per_thread * threads * 2

    def test_unauthorized_is_not_counted_as_masked(self, gateway):
        client, _, deps = gateway
        before = deps.counters.snapshot()
        client.post("/v1/traces", json={"resourceSpans": [{"scopeSpans": [{"spans": [
            {"traceId": "c" * 32, "attributes": []}]}]}]})
        after = deps.counters.snapshot()
        assert after["spans_masked"] == before["spans_masked"]
        assert after["batches_unauthorized"] == before["batches_unauthorized"] + 1


# ---------------------------------------------------------------------------
# F. Lifecycle consistency
# ---------------------------------------------------------------------------


class TestRetentionConsistency:
    def test_expired_trace_and_vault_removed_together(self, tmp_path):
        from datetime import datetime, timedelta, timezone

        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        db = SQLiteAuditDatabase(tmp_path / "r.db")
        audit = AuditLogService(db)
        traces = LocalTraceStore()
        old = now - timedelta(days=100)
        for i in range(3):
            traces.upsert_trace(TraceRecord(
                trace_id=f"old-{i}", session_id="s", user_id="u", agent_tag="a",
                name="n", timestamp=old,
                observations=(ObservationRecord(id="o", type="span", name="x"),)))
        db.insert_entities([
            {"entity_id": f"e{i}", "entity_type": "PHONE_NUMBER", "ciphertext": "c",
             "trace_id": f"old-{i}", "session_id": "s"} for i in range(3)])

        job = RetentionJob(
            trace_store=traces, db=db, audit=audit, object_store=None,
            trace_retention_days=90, audit_archive_after_days=30, clock=lambda: now)
        summary = job.run()

        assert summary["traces_deleted"] == 3
        assert summary["vault_rows_deleted"] == 3
        assert summary["status"] == "ok"
        assert traces.list_traces() == []
        assert db.count_entities() == 0

    def test_archive_uses_dedicated_store_with_retention(self, tmp_path):
        from datetime import datetime, timedelta, timezone

        from openagent_audit.media.objectstore import LocalObjectStore

        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        db = SQLiteAuditDatabase(tmp_path / "a.db")
        audit = AuditLogService(db)
        for i in range(3):
            audit.append(actor="a", role="auditor", action="VIEW", object_type="s",
                         object_id=f"o{i}", ts=now - timedelta(days=40))

        puts: list[tuple[str, int | None]] = []

        class Recording(LocalObjectStore):
            def put(self, key, data, *, retention_days=None):
                puts.append((key, retention_days))
                super().put(key, data, retention_days=retention_days)

        store = Recording(tmp_path / "archive")
        job = RetentionJob(
            trace_store=None, db=db, audit=audit, object_store=store,
            trace_retention_days=90, audit_archive_after_days=30, clock=lambda: now,
            archive_retention_days=3650)
        summary = job.run()

        assert summary["audit_entries_archived"] == 3
        data_puts = [r for k, r in puts if k.endswith(".jsonl")]
        assert data_puts and all(r == 3650 for r in data_puts)
        assert all("agent-media" not in key for key, _ in puts)
        assert list((tmp_path / "archive").rglob("*.jsonl"))


# ---------------------------------------------------------------------------
# I. Configuration redaction
# ---------------------------------------------------------------------------


class TestConfigDoesNotLeakSecrets:
    def test_repr_redacts_every_secret(self):
        """DEFECT: the dataclass repr printed DB passwords, the private-key
        passphrase and the gateway token."""
        settings = Settings(
            audit_db_url="postgresql://u:SECRETPW@h/db",
            local_private_key_passphrase="SECRETPASS",
            gateway_ingest_token="SECRETTOK",
            users=(UserEntry("TOKSECRET", "bob", "auditor"),),
        )
        rendered = repr(settings)
        for secret in ("SECRETPW", "SECRETPASS", "SECRETTOK", "TOKSECRET"):
            assert secret not in rendered, f"{secret} leaked in repr"

    def test_repr_keeps_useful_context(self):
        settings = Settings(env="prod", pii_backend="rules")
        rendered = repr(settings)
        assert "prod" in rendered and "rules" in rendered

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"reveal_ttl_minutes": 0},
            {"reveal_ttl_minutes": 99999},
            {"trace_retention_days": 0},
            {"audit_archive_after_days": 200, "trace_retention_days": 90},
        ],
    )
    def test_out_of_range_knobs_fail(self, kwargs):
        with pytest.raises(ValueError):
            Settings(**kwargs)
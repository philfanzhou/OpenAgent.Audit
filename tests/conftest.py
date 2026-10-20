"""Shared fixtures: keys, cipher, vault, masking pipeline, API apps."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from openagent_audit.config import Settings, UserEntry
from openagent_audit.crypto.envelope import RsaEnvelopeCipher
from openagent_audit.crypto.keys import LocalKeyProvider, generate_keypair, load_public_key
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
from openagent_audit.pii.recognizers import _ID_CHECK, _ID_WEIGHTS, is_valid_luhn
from openagent_audit.services.audit_api import AppContainer, build_container, create_audit_app
from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.tracing.trace_store import LocalTraceStore
from openagent_audit.vault.store import FrozenClock, SQLiteAuditDatabase

PASSPHRASE = b"unit-test-passphrase"


# ---------------------------------------------------------------------------
# Valid sample PII (computed, never real data)
# ---------------------------------------------------------------------------


def make_valid_id_card(body17: str = "11010119900307851") -> str:
    total = sum(int(ch) * w for ch, w in zip(body17, _ID_WEIGHTS))
    return body17 + _ID_CHECK[total % 11]


def make_valid_bank_card(body: str = "62220202000000000") -> str:
    digits = body
    total = 0
    for i, ch in enumerate(reversed(digits + "0")):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    check = (10 - total % 10) % 10
    candidate = digits + str(check)
    assert is_valid_luhn(candidate)
    return candidate


VALID_PHONE = "13812345678"
VALID_ID = make_valid_id_card()
VALID_BANK = make_valid_bank_card()
VALID_EMAIL = "zhangwei@example.com"
VALID_NAME_TEXT = "帮我联系下张伟，尽快回复。"


@pytest.fixture(scope="session")
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair(PASSPHRASE)


@pytest.fixture()
def key_provider(keypair) -> LocalKeyProvider:
    return LocalKeyProvider(keypair[1], PASSPHRASE)


@pytest.fixture()
def cipher(keypair, key_provider) -> RsaEnvelopeCipher:
    c = RsaEnvelopeCipher(load_public_key(keypair[0]))
    c.bind_key_provider(key_provider)
    return c


@pytest.fixture()
def db(tmp_path) -> SQLiteAuditDatabase:
    return SQLiteAuditDatabase(tmp_path / "audit.db")


@pytest.fixture()
def pipeline(cipher, db) -> MaskingPipeline:
    return MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(db))


@pytest.fixture()
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture()
def audit(db) -> AuditLogService:
    return AuditLogService(db)


@pytest.fixture()
def settings(tmp_path, keypair) -> Settings:
    public_pem, private_pem = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "audit_private_key.pem").write_bytes(private_pem)
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    return Settings(
        audit_db_url=f"sqlite:///{(tmp_path / 'audit.db')}",
        service_token="svc-token-123",
        users=(
            UserEntry("tok-auditor", "alice", "auditor"),
            UserEntry("tok-lead", "bob", "compliance_lead"),
            UserEntry("tok-lead2", "carol", "compliance_lead"),
            UserEntry("tok-dev", "dan", "developer"),
        ),
        key_provider="local",
        local_private_key_path=str(key_dir / "audit_private_key.pem"),
        local_private_key_passphrase=PASSPHRASE.decode(),
        public_key_path=str(key_dir / "audit_public_key.pem"),
        object_store="local",
        object_store_root=str(tmp_path / "objects"),
    )


@pytest.fixture()
def container(settings) -> AppContainer:
    return build_container(settings)


@pytest.fixture()
def api_client(container):
    from fastapi.testclient import TestClient

    return TestClient(create_audit_app(container))


@pytest.fixture()
def trace_store() -> LocalTraceStore:
    return LocalTraceStore()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def seed_masked_conversation(
    *,
    trace_store: LocalTraceStore,
    pipeline: MaskingPipeline,
    trace_id: str = "tr-e2e-0001",
    session_id: str = "sess-1001",
    user_id: str = "usr_10086342",
    agent_tag: str = "agent:cs-bot",
) -> str:
    """Simulate the write side: raw in-process spans -> export hook masks ->
    masked trace lands in the store. Returns the raw user text for later
    plaintext assertions."""
    from datetime import datetime, timezone

    from openagent_audit.tracing.hook import mask_attribute_map
    from openagent_audit.tracing.trace_store import ObservationRecord, TraceRecord

    raw_input = (
        f"帮我联系下张伟，电话 {VALID_PHONE}，身份证 {VALID_ID}，"
        f"邮箱 {VALID_EMAIL}，卡号 {VALID_BANK}。"
    )
    raw_output = "好的，已联系张伟本人，邮箱 zhangwei@example.com。"

    # export-thread masking (exactly what the hook does to span attributes)
    masked_input = mask_attribute_map({"langfuse.observation.input": raw_input}, pipeline, ("langfuse.observation.input",))
    masked_output = mask_attribute_map({"langfuse.observation.output": raw_output}, pipeline, ("langfuse.observation.output",))

    trace_store.upsert_trace(
        TraceRecord(
            trace_id=trace_id,
            session_id=session_id,
            user_id=user_id,
            agent_tag=agent_tag,
            name="POST /agent/run",
            timestamp=datetime.now(timezone.utc),
            observations=(
                ObservationRecord(id="o1", type="span", name="接收请求",
                                  input=masked_input["langfuse.observation.input"]),
                ObservationRecord(id="o2", type="generation", name="LLM 调用 #1",
                                  model="glm-4.7", input=masked_input["langfuse.observation.input"],
                                  output=masked_output["langfuse.observation.output"],
                                  usage={"input": 1248, "output": 356}, latency_ms=1100),
            ),
        )
    )
    return raw_input


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

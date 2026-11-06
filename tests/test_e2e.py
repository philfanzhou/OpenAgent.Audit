"""Flagship end-to-end: one conversation through the whole plane.

User message with PII + a photo -> Agent encrypts media & records the trace ->
export hook masks text and seals entities into the vault -> auditor browses
only masks -> compliance lead restores a single record after four-eyes
approval -> every step lands in the hash-chained audit log with a Loki copy.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime, timezone

import pytest

from openagent_audit.agent.instrument import AgentInstrument, LocalTraceSink
from openagent_audit.media.objectstore import LocalObjectStore
from openagent_audit.media.service import MediaService
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
from openagent_audit.services.audit_api import build_container, create_audit_app
from openagent_audit.tracing.hook import mask_attribute_map
from openagent_audit.tracing.trace_store import (
    LocalTraceStore,
    ObservationRecord,
    TraceRecord,
)
from fastapi.testclient import TestClient

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)
RAW_TEXT = "帮我联系下张伟，电话 13812345678，邮箱 zhangwei@example.com，这是银行卡照片"


class FakeLoki:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def push_event(self, event: dict, *, category: str) -> bool:
        self.events.append({**event, "category": category})
        return True


@pytest.fixture()
def world(tmp_path, cipher, settings):
    """The complete write side + read side in one process."""
    container = build_container(settings)
    loki = FakeLoki()
    container.audit._loki = loki  # observe the alerting fan-out

    pipeline = MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(container.db))
    trace_store = LocalTraceStore()
    # the agent uploads to the same object store the audit plane is configured
    # with (one bucket per deployment)
    media = MediaService(cipher, container.object_store)
    instrument = AgentInstrument(LocalTraceSink(trace_store), media=media)

    container.trace_store = trace_store
    client = TestClient(create_audit_app(container))
    return {
        "container": container, "pipeline": pipeline, "instrument": instrument,
        "trace_store": trace_store, "media": media, "client": client, "loki": loki,
        "cipher": cipher,
    }


def _ingest(world) -> list:
    """Simulate one full request: report -> export-thread masking -> store."""
    messages = [
        {"role": "user", "content": [
            {"type": "text", "text": RAW_TEXT},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64.b64encode(PNG).decode()}"}},
        ]},
    ]
    prepared, refs = world["instrument"].report_request(
        trace_id="tr-e2e-42", conversation_id="conv-9000", internal_user_id="usr_10086342",
        agent_id="cs-bot", name="POST /agent/run", messages=messages,
        llm_calls=[{"name": "LLM 调用 #1", "model": "glm-4.7",
                    "input": "帮我联系下张伟，电话 13812345678",
                    "output": "好的，已记录", "usage": {"input": 120}, "latency_ms": 900}],
    )
    record = world["trace_store"].get_trace("tr-e2e-42")
    masked_observations = []
    for obs in record.observations:
        # mirror the SDK: non-scalar input/output are serialized to string
        # attributes before export, then masked by the hook
        fields = {}
        for field_name in ("input", "output"):
            value = getattr(obs, field_name)
            if value is None:
                continue
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            masked = mask_attribute_map({"k": text}, world["pipeline"], ("k",))
            fields[field_name] = masked.get("k", text)
        masked_observations.append(ObservationRecord(**{**obs.__dict__, **fields}))
    world["trace_store"].upsert_trace(
        TraceRecord(trace_id=record.trace_id, session_id=record.session_id,
                    user_id=record.user_id, agent_tag=record.agent_tag, name=record.name,
                    timestamp=record.timestamp, observations=tuple(masked_observations))
    )
    return refs


def _find_entity_by_plaintext(world, plaintext: str) -> str:
    """The test holds the private key: decrypt vault rows to locate the entity.
    Production audit-api can do neither (no key, no ciphertext grants)."""
    conn = sqlite3.connect(world["container"].db._path)
    rows = conn.execute("SELECT entity_id, ciphertext FROM entity_ciphertext").fetchall()
    conn.close()
    for entity_id, ciphertext in rows:
        try:
            if world["cipher"].open(ciphertext, aad=entity_id.encode()) == plaintext.encode():
                return entity_id
        except Exception:
            continue
    raise AssertionError(f"vault row for {plaintext!r} not found")


def test_full_plane(world):
    client, container = world["client"], world["container"]
    refs = _ingest(world)
    assert len(refs) == 1

    # 1. an ordinary user browses: masks only, no plaintext, no ciphertext
    client.post("/ui/login", data={"token": "tok-alice"}, follow_redirects=False)
    assert client.get("/v1/sessions").status_code == 200
    body = client.get("/v1/sessions/conv-9000").text
    assert "13812345678" not in body
    assert "张伟" not in body
    assert "zhangwei@example.com" not in body
    assert base64.b64encode(PNG).decode() not in body
    assert "138****5678" in body

    # 2. a plain user has no plaintext path at all
    phone_entity = _find_entity_by_plaintext(world, "13812345678")
    assert client.post(f"/v1/reveal/{phone_entity}").status_code == 403
    assert client.get("/v1/audit-log").status_code == 403

    # 3. the administrator steps up, then a click reveals exactly one value
    assert client.post(
        "/ui/admin/login",
        data={"username": "admin", "password": "admin@123456"},
        follow_redirects=False,
    ).status_code == 302

    revealed = client.post(f"/v1/reveal/{phone_entity}")
    assert revealed.status_code == 200, revealed.text
    assert revealed.json()["plaintext"] == "13812345678"

    # 4. the audit log records the step-up and the reveal, chain intact
    log = client.get("/v1/audit-log?verify=true").json()
    assert log["verification"]["ok"] is True
    actions = [e["action"] for e in log["entries"]]
    for expected in ("LOGIN", "ADMIN_LOGIN", "ENTITY_REVEAL_REQUESTED", "ENTITY_REVEALED"):
        assert expected in actions, actions

    reveal_entry = next(e for e in log["entries"] if e["action"] == "ENTITY_REVEALED")
    assert reveal_entry["detail"]["session_user"] == "alice"

    # alerting copies never carry values
    for event in world["loki"].events:
        assert "13812345678" not in json.dumps(event, ensure_ascii=False)

    # 5. metrics are administrator-only and show no drops
    metrics = client.get("/internal/metrics").json()
    assert metrics["drops"]["dropped_batches"] == 0


def test_e2e_vault_rows_never_hold_plaintext(world):
    _ingest(world)
    conn = sqlite3.connect(world["container"].db._path)
    blob = " ".join(
        r[0] for r in conn.execute("SELECT ciphertext || ' ' || entity_id FROM entity_ciphertext")
    )
    conn.close()
    for secret in ("13812345678", "zhangwei@example.com", "张伟", RAW_TEXT):
        assert secret not in blob

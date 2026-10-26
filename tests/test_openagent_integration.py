"""Reserved OpenAgent integration surface: HTTP introspection auth + agent
attachment helper."""

from __future__ import annotations

import httpx
import pytest

from openagent_audit.config import Settings, UserEntry
from openagent_audit.services.auth import (
    HttpIntrospectionAuthenticator,
    load_authenticator,
)


class MockIntrospection:
    """httpx.Client stand-in counting calls (for cache assertions)."""

    def __init__(self, payloads: dict[str, object], status_for_missing: int = 401):
        self.payloads = payloads
        self.status_for_missing = status_for_missing
        self.calls = 0

    def get(self, url, headers):
        self.calls += 1
        token = headers["Authorization"].removeprefix("Bearer ")
        payload = self.payloads.get(token)
        if payload is None:
            return httpx.Response(self.status_for_missing)
        return httpx.Response(200, json=payload)


def test_static_provider_loads_env_users():
    auth = load_authenticator(
        Settings(users=(UserEntry("tok", "alice", "auditor"),))
    )
    assert auth.resolve("tok").username == "alice"
    assert auth.resolve("nope") is None


def test_http_provider_requires_introspect_url():
    with pytest.raises(ValueError):
        load_authenticator(
            Settings(auth_provider="http", auth_introspect_url="")
        )


def test_http_introspection_resolves_principal():
    mock = MockIntrospection({
        "tok-bob": {"username": "bob", "role": "compliance_lead"},
    })
    auth = HttpIntrospectionAuthenticator(
        "https://openagent.internal/auth/introspect", client=mock, cache_seconds=60
    )
    principal = auth.resolve("tok-bob")
    assert principal.username == "bob" and principal.role == "compliance_lead"
    assert principal.can("manage_restore")


def test_http_introspection_rejects_unknown_and_bad_roles():
    mock = MockIntrospection({
        "tok-bad": {"username": "eve", "role": "superadmin"},
    })
    auth = HttpIntrospectionAuthenticator("https://x", client=mock)
    assert auth.resolve("tok-unknown") is None
    assert auth.resolve("tok-bad") is None  # role not one of the three


def test_http_introspection_unreachable_fails_closed():
    class Boom:
        def get(self, url, headers):
            raise httpx.ConnectError("down")

    auth = HttpIntrospectionAuthenticator("https://x", client=Boom())
    assert auth.resolve("tok") is None


def test_http_introspection_caches(monkeypatch):
    mock = MockIntrospection({
        "tok-bob": {"username": "bob", "role": "auditor"},
    })
    auth = HttpIntrospectionAuthenticator(
        "https://x", client=mock, cache_seconds=3600
    )
    auth.resolve("tok-bob")
    auth.resolve("tok-bob")
    auth.resolve("tok-bob")
    assert mock.calls == 1  # served from cache


def test_load_authenticator_selects_http(monkeypatch):
    # no network access happens until resolve(); construction must succeed
    auth = load_authenticator(
        Settings(auth_provider="http", auth_introspect_url="https://openagent/auth")
    )
    assert isinstance(auth, HttpIntrospectionAuthenticator)


def test_attach_openagent_builds_instrument(tmp_path, keypair):
    """One-call agent attachment: masked write path end-to-end with a local
    sink + store (no langfuse needed)."""
    from openagent_audit.agent.instrument import AgentInstrument, LocalTraceSink
    from openagent_audit.integrations.openagent import attach_openagent
    from openagent_audit.tracing.trace_store import LocalTraceStore
    from openagent_audit.vault.store import SQLiteAuditDatabase

    public_pem, private_pem = keypair
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "audit_public_key.pem").write_bytes(public_pem)
    settings = Settings(
        public_key_path=str(key_dir / "audit_public_key.pem"),
        object_store="local",
        object_store_root=str(tmp_path / "objects"),
    )
    store = LocalTraceStore()
    db = SQLiteAuditDatabase(tmp_path / "audit.db")
    instrument = attach_openagent(
        settings, sink=LocalTraceSink(store), db=db,
        media=None,  # no media in this path
    )
    assert isinstance(instrument, AgentInstrument)
    prepared, refs = instrument.report_request(
        trace_id="tr-int-1",
        conversation_id="sess-int-1",
        internal_user_id="usr_int_1",
        agent_id="cs-bot",
        name="POST /agent/run",
        messages=[{"role": "user", "content": "联系电话 13812345678"}],
    )
    trace = store.get_trace("tr-int-1")
    assert trace is not None and trace.session_id == "sess-int-1"

    # Masking happens in the Langfuse export thread, not in the local sink —
    # simulate the export hook on the recorded input to prove the pipeline is
    # wired to the vault (same call the hook makes, incl. trace/session ids).
    from openagent_audit.integrations.openagent import build_masking_pipeline
    from openagent_audit.tracing.hook import mask_attribute_map

    pipeline = build_masking_pipeline(settings, db)
    masked = mask_attribute_map(
        {"langfuse.observation.input": "13812345678"},
        pipeline, ("langfuse.observation.input",),
        trace_id="tr-int-1", session_id="sess-int-1",
    )
    assert "13812345678" not in masked["langfuse.observation.input"]
    assert "⟦PHONE_NUMBER#" in masked["langfuse.observation.input"]
    # the ciphertext landed in the audit-domain vault with trace ownership
    import sqlite3

    conn = sqlite3.connect(db._path)
    try:
        rows = conn.execute(
            "SELECT trace_id, session_id FROM entity_ciphertext"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [("tr-int-1", "sess-int-1")]

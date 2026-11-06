"""OpenAgent platform integration: identity resolution + agent attachment.

The platform tells the audit plane *who* a caller is. It does not, and must
not, tell it what that person may do: every platform identity becomes an
ordinary ``user``, and the administrator capability is unlocked separately by
a step-up login.
"""

from __future__ import annotations

import httpx
import pytest

from openagent_audit.config import Settings, UserEntry
from openagent_audit.services.auth import (
    ROLE_ADMIN,
    ROLE_USER,
    IdentityResolver,
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


def _static_settings(*users: UserEntry) -> Settings:
    return Settings(users=users)


def _http_settings(url: str = "https://openagent.internal/auth/introspect") -> Settings:
    return Settings(auth_provider="http", auth_introspect_url=url, auth_cache_seconds=60)


def test_static_provider_resolves_platform_users():
    resolver = IdentityResolver(_static_settings(UserEntry("tok", "alice", "user")))

    principal = resolver.resolve("tok")

    assert principal is not None
    assert principal.username == "alice"
    assert resolver.resolve("nope") is None


def test_platform_identities_are_always_ordinary_users():
    """A platform token can never carry the administrator role.

    The role is granted only by the step-up login, so even a token whose entry
    claims otherwise cannot decrypt.
    """
    with pytest.raises(ValueError, match="always 'user'"):
        UserEntry("tok", "eve", "admin").validate()


def test_http_introspection_resolves_principal():
    mock = MockIntrospection({"tok-bob": {"username": "bob", "role": "compliance_lead"}})
    resolver = IdentityResolver(_http_settings(), client=mock)

    principal = resolver.resolve("tok-bob")

    assert principal is not None
    assert principal.username == "bob"
    # A role claimed by the platform is ignored: the audit plane decides.
    assert principal.role == ROLE_USER
    assert not principal.can("reveal")


def test_http_introspection_rejects_unknown_tokens():
    mock = MockIntrospection({})
    resolver = IdentityResolver(_http_settings(), client=mock)

    assert resolver.resolve("tok-unknown") is None


def test_http_introspection_ignores_any_role_claim():
    """Even an admin claim from the platform does not confer admin here."""
    mock = MockIntrospection({"tok-x": {"username": "eve", "role": "admin"}})
    resolver = IdentityResolver(_http_settings(), client=mock)

    principal = resolver.resolve("tok-x")

    assert principal is not None
    assert principal.role == ROLE_USER
    assert principal.role != ROLE_ADMIN


def test_http_introspection_unreachable_fails_closed():
    class Boom:
        def get(self, url, headers):
            raise httpx.ConnectError("down")

    resolver = IdentityResolver(_http_settings(), client=Boom())

    assert resolver.resolve("tok") is None


def test_http_introspection_caches():
    mock = MockIntrospection({"tok-bob": {"username": "bob"}})
    resolver = IdentityResolver(_http_settings(), client=mock)

    resolver.resolve("tok-bob")
    resolver.resolve("tok-bob")
    resolver.resolve("tok-bob")

    assert mock.calls == 1


def test_http_introspection_without_url_fails_closed():
    """Misconfiguration must not silently accept every token."""
    resolver = IdentityResolver(Settings(auth_provider="http", auth_introspect_url=""))

    assert resolver.resolve("anything") is None


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

    # Masking happens in the export thread, not in the local sink — simulate
    # the export hook on the recorded input to prove the pipeline is wired to
    # the vault (same call the hook makes, incl. trace/session ids).
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

    import sqlite3

    conn = sqlite3.connect(db._path)
    try:
        rows = conn.execute(
            "SELECT trace_id, session_id FROM entity_ciphertext"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [("tr-int-1", "sess-int-1")]
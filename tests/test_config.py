"""Settings parsing."""

from __future__ import annotations

import pytest

from openagent_audit.config import Settings


def test_parse_users_roundtrip():
    s = Settings.from_env({"AUDIT_USERS": "tok1:alice:auditor,tok2:bob:compliance_lead"})
    assert len(s.users) == 2
    assert s.user_for_token("tok1").username == "alice"
    assert s.user_for_token("tok1").role == "auditor"
    assert s.user_for_token("tok2").role == "compliance_lead"
    assert s.user_for_token("nope") is None


def test_parse_users_rejects_bad_entries():
    with pytest.raises(ValueError):
        Settings.from_env({"AUDIT_USERS": "tok1:alice:hacker"})
    with pytest.raises(ValueError):
        Settings.from_env({"AUDIT_USERS": "tok1-alice"})


def test_defaults_are_conservative():
    s = Settings.from_env({})
    assert s.trace_retention_days == 90
    assert s.reveal_ttl_minutes == 60
    assert s.auth_provider == "static"
    assert s.auth_introspect_url == ""
    assert s.pii_backend == "rules"
    assert s.loki_url == ""  # fan-out disabled unless configured
    assert s.decrypt_svc_url == ""


def test_env_overrides():
    s = Settings.from_env({
        "AUDIT_ENV": "production",
        "AUDIT_DECRYPT_SVC_URL": "http://decrypt:8101",
        "LOKI_URL": "http://loki:3100",
        "AUDIT_TRACE_RETENTION_DAYS": "180",
        "AUDIT_REVEAL_TTL_MINUTES": "5",
    })
    assert s.env == "production"
    assert s.decrypt_svc_url == "http://decrypt:8101"
    assert s.loki_url == "http://loki:3100"
    assert s.trace_retention_days == 180
    assert s.reveal_ttl_minutes == 5


def test_sqlite_path_resolution(tmp_path):
    from openagent_audit.config import sqlite_path_from_url

    path = sqlite_path_from_url(f"sqlite:///{tmp_path}/x/audit.db")
    assert path == tmp_path / "x" / "audit.db"
    assert path.parent.exists()
    with pytest.raises(ValueError):
        sqlite_path_from_url("postgresql://host/db")

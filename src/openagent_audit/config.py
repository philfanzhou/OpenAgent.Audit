"""Application settings, resolved from environment variables.

Everything that the proposal marks as “待合规确认” (mask depth, retention, reveal
TTL) is a configuration knob here with a conservative default — the code never
hard-codes a compliance decision.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


ROLES = ("auditor", "compliance_lead", "developer")


@dataclass(frozen=True)
class UserEntry:
    """One audit-plane user: bearer token -> (username, role)."""

    token: str
    username: str
    role: str

    def validate(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role!r}; expected one of {ROLES}")


@dataclass(frozen=True)
class Settings:
    env: str = "dev"

    # Audit domain storage. sqlite for dev/tests, postgres for deployment
    # (see deploy/audit_db_init.sql for the production schema and grants).
    audit_db_url: str = "sqlite:///./data/audit.db"

    # Shared secret between audit-api and decrypt-svc (bearer token).
    service_token: str = "dev-service-token"

    # Audit-plane users: AUDIT_USERS="token:alice:auditor,token2:bob:compliance_lead"
    users: tuple[UserEntry, ...] = ()

    # Identity source (reserved for the OpenAgent platform integration):
    # "static" uses AUDIT_USERS above; "http" resolves tokens against the
    # platform's introspection endpoint (docs/openagent-integration.md).
    auth_provider: str = "static"
    auth_introspect_url: str = ""
    auth_cache_seconds: float = 60.0

    # Key custody: "local" (PEM file held only by decrypt-svc) or "kms" (AWS KMS).
    key_provider: str = "local"
    local_private_key_path: str = ""
    local_private_key_passphrase: str = ""
    aws_region: str = ""
    kms_key_id: str = ""
    # Public key used by Agents to seal payloads (only the public key leaves
    # the KMS/admin boundary — Agents can encrypt, never decrypt).
    public_key_path: str = ""

    # Media object storage: "local" (dev) or "s3" (SeaweedFS / MinIO).
    object_store: str = "local"
    object_store_root: str = "./data/objects"
    media_bucket: str = "agent-media"
    s3_endpoint: str = ""
    s3_access_key: str = ""
    s3_secret_key: str = ""

    # Trace store: "local" (dev/tests, stands in for Langfuse queries) or
    # "langfuse" (proxy the Langfuse public API).
    trace_store: str = "local"
    langfuse_host: str = "http://localhost:3000"
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""

    # Separate decrypt-svc deployment; empty = in-process decrypt (dev only).
    decrypt_svc_url: str = ""

    # Loki copy for real-time alerting; empty disables the fan-out.
    loki_url: str = ""

    # Retention / compliance knobs (proposal §10-11; confirm with compliance).
    trace_retention_days: int = 90
    audit_archive_after_days: int = 30
    reveal_ttl_minutes: int = 5

    # PII detection backend: "rules" (built-in, no external model) or
    # "presidio" (Microsoft Presidio + Chinese spaCy model, proposal §11.3).
    pii_backend: str = "rules"

    # Demo seeding: with AUDIT_TRACE_STORE=local, pre-fill sample masked
    # conversations at startup (local manual testing only — never production).
    demo_seed: bool = False

    # Which agent processes export through this process (used by tooling).
    masking_prefixes: tuple[str, ...] = field(
        default=(
            "langfuse.observation.input",
            "langfuse.observation.output",
            "gen_ai.prompt",
            "gen_ai.completion",
        )
    )

    # ------------------------------------------------------------------
    @staticmethod
    def from_env(env: Mapping[str, str] | None = None) -> "Settings":
        e = os.environ if env is None else env
        return Settings(
            env=e.get("AUDIT_ENV", "dev"),
            audit_db_url=e.get("AUDIT_DB_URL", "sqlite:///./data/audit.db"),
            service_token=e.get("AUDIT_SERVICE_TOKEN", "dev-service-token"),
            users=_parse_users(e.get("AUDIT_USERS", "")),
            auth_provider=e.get("AUDIT_AUTH_PROVIDER", "static"),
            auth_introspect_url=e.get("AUDIT_AUTH_INTROSPECT_URL", ""),
            auth_cache_seconds=float(e.get("AUDIT_AUTH_CACHE_SECONDS", "60")),
            key_provider=e.get("AUDIT_KEY_PROVIDER", "local"),
            local_private_key_path=e.get("AUDIT_PRIVATE_KEY_PATH", ""),
            local_private_key_passphrase=e.get("AUDIT_PRIVATE_KEY_PASSPHRASE", ""),
            aws_region=e.get("AWS_REGION", ""),
            kms_key_id=e.get("AUDIT_KMS_KEY_ID", ""),
            public_key_path=e.get("AUDIT_PUBLIC_KEY_PATH", ""),
            object_store=e.get("AUDIT_OBJECT_STORE", "local"),
            object_store_root=e.get("AUDIT_OBJECT_STORE_ROOT", "./data/objects"),
            media_bucket=e.get("AUDIT_MEDIA_BUCKET", "agent-media"),
            s3_endpoint=e.get("AUDIT_S3_ENDPOINT", ""),
            s3_access_key=e.get("AUDIT_S3_ACCESS_KEY", ""),
            s3_secret_key=e.get("AUDIT_S3_SECRET_KEY", ""),
            trace_store=e.get("AUDIT_TRACE_STORE", "local"),
            langfuse_host=e.get("LANGFUSE_HOST", "http://localhost:3000"),
            langfuse_public_key=e.get("LANGFUSE_PUBLIC_KEY", ""),
            langfuse_secret_key=e.get("LANGFUSE_SECRET_KEY", ""),
            decrypt_svc_url=e.get("AUDIT_DECRYPT_SVC_URL", ""),
            loki_url=e.get("LOKI_URL", ""),
            trace_retention_days=int(e.get("AUDIT_TRACE_RETENTION_DAYS", "90")),
            audit_archive_after_days=int(e.get("AUDIT_ARCHIVE_AFTER_DAYS", "30")),
            reveal_ttl_minutes=int(e.get("AUDIT_REVEAL_TTL_MINUTES", "5")),
            pii_backend=e.get("AUDIT_PII_BACKEND", "rules"),
            demo_seed=e.get("AUDIT_DEMO_SEED", "").lower() in ("1", "true", "yes", "on"),
        )

    def user_for_token(self, token: str) -> UserEntry | None:
        for u in self.users:
            if u.token == token:
                return u
        return None


def _parse_users(raw: str) -> tuple[UserEntry, ...]:
    users: list[UserEntry] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(":")
        if len(parts) != 3:
            raise ValueError(f"AUDIT_USERS entry {chunk!r} must be token:username:role")
        entry = UserEntry(token=parts[0].strip(), username=parts[1].strip(), role=parts[2].strip())
        entry.validate()
        users.append(entry)
    return tuple(users)


def sqlite_path_from_url(url: str) -> Path:
    """``sqlite:///./data/audit.db`` -> ``Path("data/audit.db")``."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        raise ValueError(f"not a sqlite url: {url!r}")
    path = Path(url[len(prefix) :])
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

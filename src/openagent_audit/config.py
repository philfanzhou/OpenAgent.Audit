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


# The audit plane has exactly two roles: ordinary staff (masked data only) and
# an administrator who can reveal originals after a step-up login.
ROLES = ("user", "admin")

# Masking Gateway defaults (overridable via AUDIT_GATEWAY_* env vars).
DEFAULT_CONTENT_PREFIXES = (
    "gen_ai.", "langfuse.observation", "llm.", "prompt", "completion",
    "content", "message", "input", "output",
)
DEFAULT_SESSION_ATTRS = (
    "langfuse.session.id", "session.id", "conversation.id",
    "openagent.conversation_id", "conversation_id",
)
DEFAULT_USER_ATTRS = (
    "langfuse.user.id", "user.id", "enduser.id",
    "openagent.user_id", "user_id",
)
DEFAULT_AGENT_ATTRS = (
    "agent.id", "openagent.agent_id", "agent_id", "gen_ai.agent",
)


def _csv_or_default(raw: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if not raw:
        return default
    items = tuple(p.strip() for p in raw.split(",") if p.strip())
    return items or default


@dataclass(frozen=True)
class UserEntry:
    """One audit-plane user: bearer token -> (username, role)."""

    token: str
    username: str
    role: str

    def validate(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role!r}; expected one of {ROLES}")
        # Entries in AUDIT_USERS describe platform identities. They are always
        # ordinary users: the administrator role is granted only by the
        # step-up login, never carried by a token, so declaring it here is a
        # configuration mistake that would quietly hand out decryption.
        if self.role != "user":
            raise ValueError(
                f"AUDIT_USERS entry for {self.username!r} declares role {self.role!r}; "
                "platform identities are always 'user'. The administrator role is "
                "granted by the admin login, not by a token."
            )

    def __repr__(self) -> str:
        # The token authenticates the user; never render it.
        return f"UserEntry(username={self.username!r}, role={self.role!r}, token='***')"


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

    # Administrator step-up login. The console is used by ordinary staff; the
    # administrator capability is unlocked by typing these credentials inside a
    # signed-in session. Store a hash (scripts/hash_admin_password.py) so a
    # leaked .env does not hand out decryption capability; a plain password is
    # accepted for local runs and hashed on load.
    admin_username: str = "admin"
    admin_password: str = ""
    admin_password_hash: str = ""
    # How long an unlock lasts before the session drops back to a normal user.
    # The console is a decrypt-capable surface, so the window is deliberately
    # short: 5 minutes.
    admin_session_minutes: int = 5

    # Display timezone for the console. Audit entries are always stored in UTC
    # (that is the only unambiguous record), but rendering raw UTC makes a
    # 13:37 Beijing event look like 05:37. This shifts for display and is
    # recorded in each page's footer so a reviewer knows what they are reading.
    display_timezone: str = "Asia/Shanghai"

    # Local test account. Deliberately a fallback for when the platform is not
    # forwarding an identity: it proves the console renders, and it can never
    # step up to administrator. Sessions expire after one hour.
    # Leave either value empty to disable the test login entirely.
    test_username: str = ""
    test_password: str = ""
    test_session_minutes: int = 60

    # After the unlock ends (by timeout or explicit logout) the same account
    # must wait this long before it may unlock again: 10 minutes.
    admin_cooldown_minutes: int = 10

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
    # Dedicated Object-Lock bucket for the audit-log archive (never the media bucket).
    archive_bucket: str = "audit-archive"
    archive_retention_days: int = 3650
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

    # Outbound TLS trust for every HTTP client this process creates
    # (Langfuse, Loki, decrypt-svc, the optional introspection endpoint).
    # Empty = the system CA bundle. Point this at an internal CA bundle when
    # those targets use certificates the container does not already trust;
    # ``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE`` are honoured as fallbacks, and
    # a deployment can opt out of verification entirely with
    # AUDIT_TLS_VERIFY=false (documented as a last resort).
    ca_bundle_path: str = ""
    tls_verify: bool = True

    # Retention / compliance knobs (proposal §10-11; confirm with compliance).
    trace_retention_days: int = 90
    audit_archive_after_days: int = 30
    reveal_ttl_minutes: int = 60

    # PII detection backend: "rules" (built-in, no external model) or
    # "presidio" (Microsoft Presidio + Chinese spaCy model, proposal §11.3).
    pii_backend: str = "rules"

    # Demo seeding: with AUDIT_TRACE_STORE=local, pre-fill sample masked
    # conversations at startup (local manual testing only — never production).
    demo_seed: bool = False

    # --- Masking Gateway (OTLP ingest for non-Python agents, e.g. OpenAgent .NET)
    # Bearer token required on POST /v1/traces; empty disables auth (dev only).
    gateway_ingest_token: str = ""
    # When true, an empty token is a configuration error rather than "auth
    # disabled" — set this in every real deployment so a missing token can
    # never silently open the gateway to unauthenticated plaintext ingress.
    gateway_require_auth: bool = False
    # Ingest limits: a single OTLP export larger than this is rejected with
    # 413 before it is buffered, and a batch with more spans than the cap is
    # rejected as well. Both bound the work one POST can force on the process
    # that holds the masking and key duties.
    gateway_max_body_bytes: int = 16 * 1024 * 1024
    gateway_max_spans: int = 5000
    # Mask string span attributes whose key starts with any of these prefixes.
    gateway_content_prefixes: tuple[str, ...] = (
        "gen_ai.", "langfuse.observation", "llm.", "prompt", "completion",
        "content", "message", "input", "output",
    )
    # Candidate span-attribute keys to map identifiers from (first hit wins).
    gateway_session_attrs: tuple[str, ...] = (
        "langfuse.session.id", "session.id", "conversation.id",
        "openagent.conversation_id", "conversation_id",
    )
    gateway_user_attrs: tuple[str, ...] = (
        "langfuse.user.id", "user.id", "enduser.id",
        "openagent.user_id", "user_id",
    )
    gateway_agent_attrs: tuple[str, ...] = (
        "agent.id", "openagent.agent_id", "agent_id", "gen_ai.agent",
    )

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
            admin_username=e.get("AUDIT_ADMIN_USERNAME", "admin"),
            admin_password=e.get("AUDIT_ADMIN_PASSWORD", ""),
            admin_password_hash=e.get("AUDIT_ADMIN_PASSWORD_HASH", ""),
            admin_session_minutes=int(e.get("AUDIT_ADMIN_SESSION_MINUTES", "5")),
            admin_cooldown_minutes=int(e.get("AUDIT_ADMIN_COOLDOWN_MINUTES", "10")),
            test_username=e.get("AUDIT_TEST_USERNAME", ""),
            test_password=e.get("AUDIT_TEST_PASSWORD", ""),
            test_session_minutes=int(e.get("AUDIT_TEST_SESSION_MINUTES", "60")),
            display_timezone=e.get("AUDIT_DISPLAY_TIMEZONE", "Asia/Shanghai"),
            key_provider=e.get("AUDIT_KEY_PROVIDER", "local"),
            local_private_key_path=e.get("AUDIT_PRIVATE_KEY_PATH", ""),
            local_private_key_passphrase=e.get("AUDIT_PRIVATE_KEY_PASSPHRASE", ""),
            aws_region=e.get("AWS_REGION", ""),
            kms_key_id=e.get("AUDIT_KMS_KEY_ID", ""),
            public_key_path=e.get("AUDIT_PUBLIC_KEY_PATH", ""),
            object_store=e.get("AUDIT_OBJECT_STORE", "local"),
            object_store_root=e.get("AUDIT_OBJECT_STORE_ROOT", "./data/objects"),
            media_bucket=e.get("AUDIT_MEDIA_BUCKET", "agent-media"),
            archive_bucket=e.get("AUDIT_ARCHIVE_BUCKET", "audit-archive"),
            archive_retention_days=int(e.get("AUDIT_ARCHIVE_RETENTION_DAYS", "3650")),
            s3_endpoint=e.get("AUDIT_S3_ENDPOINT", ""),
            s3_access_key=e.get("AUDIT_S3_ACCESS_KEY", ""),
            s3_secret_key=e.get("AUDIT_S3_SECRET_KEY", ""),
            trace_store=e.get("AUDIT_TRACE_STORE", "local"),
            langfuse_host=e.get("LANGFUSE_HOST", "http://localhost:3000"),
            langfuse_public_key=e.get("LANGFUSE_PUBLIC_KEY", ""),
            langfuse_secret_key=e.get("LANGFUSE_SECRET_KEY", ""),
            decrypt_svc_url=e.get("AUDIT_DECRYPT_SVC_URL", ""),
            loki_url=e.get("LOKI_URL", ""),
            ca_bundle_path=_first_non_empty(
                e.get("AUDIT_CA_BUNDLE"),
                e.get("REQUESTS_CA_BUNDLE"),
                e.get("SSL_CERT_FILE"),
            ),
            tls_verify=e.get("AUDIT_TLS_VERIFY", "true").strip().lower()
            not in ("0", "false", "no", "off"),
            trace_retention_days=int(e.get("AUDIT_TRACE_RETENTION_DAYS", "90")),
            audit_archive_after_days=int(e.get("AUDIT_ARCHIVE_AFTER_DAYS", "30")),
            reveal_ttl_minutes=int(e.get("AUDIT_REVEAL_TTL_MINUTES", "60")),
            pii_backend=e.get("AUDIT_PII_BACKEND", "rules"),
            demo_seed=e.get("AUDIT_DEMO_SEED", "").lower() in ("1", "true", "yes", "on"),
            gateway_ingest_token=e.get("AUDIT_GATEWAY_TOKEN", ""),
            gateway_max_body_bytes=int(e.get("AUDIT_GATEWAY_MAX_BODY_BYTES", str(16 * 1024 * 1024))),
            gateway_max_spans=int(e.get("AUDIT_GATEWAY_MAX_SPANS", "5000")),
            gateway_require_auth=e.get("AUDIT_GATEWAY_REQUIRE_AUTH", "").lower()
            in ("1", "true", "yes", "on"),
            gateway_content_prefixes=_csv_or_default(
                e.get("AUDIT_GATEWAY_CONTENT_PREFIXES"), DEFAULT_CONTENT_PREFIXES),
            gateway_session_attrs=_csv_or_default(
                e.get("AUDIT_GATEWAY_SESSION_ATTRS"), DEFAULT_SESSION_ATTRS),
            gateway_user_attrs=_csv_or_default(
                e.get("AUDIT_GATEWAY_USER_ATTRS"), DEFAULT_USER_ATTRS),
            gateway_agent_attrs=_csv_or_default(
                e.get("AUDIT_GATEWAY_AGENT_ATTRS"), DEFAULT_AGENT_ATTRS),
        )

    def user_for_token(self, token: str) -> UserEntry | None:
        for u in self.users:
            if u.token == token:
                return u
        return None

    def __repr__(self) -> str:
        """Redacted representation.

        ``Settings`` holds the audit DB credentials, the private-key
        passphrase and the gateway bearer token. The dataclass default repr
        would print all of them, and a single ``logger.debug(settings)`` or
        an exception traceback rendering the object would leak every secret
        into logs and crash dumps.
        """
        def secret(value: str) -> str:
            return "***" if value else ""

        return (
            f"Settings(env={self.env!r}, audit_db_url={self._redact_url(self.audit_db_url)!r}, "
            f"service_token={secret(self.service_token)!r}, "
            f"users={len(self.users)} entries, auth_provider={self.auth_provider!r}, "
            f"key_provider={self.key_provider!r}, "
            f"private_key_passphrase={secret(self.local_private_key_passphrase)!r}, "
            f"gateway_ingest_token={secret(self.gateway_ingest_token)!r}, "
            f"trace_store={self.trace_store!r}, pii_backend={self.pii_backend!r})"
        )

    @staticmethod
    def _redact_url(url: str) -> str:
        """Hide the password inside ``scheme://user:password@host/db``."""
        if "://" not in url:
            return url
        scheme, _, rest = url.partition("://")
        if "@" not in rest:
            return url
        credentials, _, host = rest.rpartition("@")
        user, sep, _password = credentials.partition(":")
        return f"{scheme}://{user}{sep}***@{host}" if sep else url

    def __post_init__(self) -> None:
        """Reject compliance knobs outside their safe operating range.

        These values gate how long plaintext stays revealable (``reveal_ttl``)
        and how long evidence is kept (``retention``). A typo such as
        ``AUDIT_REVEAL_TTL_MINUTES=100000`` would silently hold a decryption
        window open for weeks, so it fails at construction instead.
        """
        if not 1 <= self.reveal_ttl_minutes <= 1440:
            raise ValueError(
                f"AUDIT_REVEAL_TTL_MINUTES must be between 1 and 1440, got {self.reveal_ttl_minutes}"
            )
        if not 1 <= self.trace_retention_days <= 3650:
            raise ValueError(
                f"AUDIT_TRACE_RETENTION_DAYS must be between 1 and 3650, got {self.trace_retention_days}"
            )
        if not 1 <= self.audit_archive_after_days <= self.trace_retention_days:
            raise ValueError(
                "AUDIT_ARCHIVE_AFTER_DAYS must be >= 1 and <= AUDIT_TRACE_RETENTION_DAYS "
                f"(got {self.audit_archive_after_days} vs {self.trace_retention_days})"
            )


def _first_non_empty(*values: str | None) -> str:
    for value in values:
        if value and value.strip():
            return value.strip()
    return ""


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

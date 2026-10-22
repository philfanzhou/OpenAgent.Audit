"""Wiring helpers shared by the audit-api and decrypt-svc entry points."""

from __future__ import annotations

from openagent_audit.config import Settings, sqlite_path_from_url
from openagent_audit.crypto.envelope import RsaEnvelopeCipher
from openagent_audit.crypto.keys import KeyProvider, KmsKeyProvider, LocalKeyProvider, load_public_key


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def build_key_provider(settings: Settings) -> KeyProvider:
    """Private-key custody: local PEM (decrypt-svc host) or AWS KMS."""
    if settings.key_provider == "kms":
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise RuntimeError("boto3 is not installed; pip install 'openagent-audit[s3]'") from exc
        kms = boto3.client("kms", region_name=settings.aws_region or None)
        return KmsKeyProvider(kms, settings.kms_key_id)
    return LocalKeyProvider.from_file(
        settings.local_private_key_path,
        settings.local_private_key_passphrase or None,
    )


def build_write_cipher(settings: Settings) -> RsaEnvelopeCipher:
    """Write-side (Agent) cipher: public key only, structurally unable to open
    ciphertext — no key provider is ever bound, so ``cipher.open`` raises
    regardless of which env vars are present (proposal §01: Agent 只持公钥)."""
    if not settings.public_key_path:
        raise RuntimeError(
            "AUDIT_PUBLIC_KEY_PATH is required for the write-side cipher; "
            "agents must never receive the private key"
        )
    public_key = load_public_key(read_bytes(settings.public_key_path))
    return RsaEnvelopeCipher(public_key)  # deliberately unbound


def build_cipher(settings: Settings, key_provider: KeyProvider | None = None) -> RsaEnvelopeCipher:
    """Read-side cipher (decrypt-svc host / dev in-process variant): the
    public key seals, the bound provider opens."""
    provider = key_provider if key_provider is not None else build_key_provider(settings)
    if settings.public_key_path:
        public_key = load_public_key(read_bytes(settings.public_key_path))
    else:
        local = provider if isinstance(provider, LocalKeyProvider) else None
        if local is None:
            raise RuntimeError(
                "AUDIT_PUBLIC_KEY_PATH is required when the key provider cannot derive it"
            )
        public_key = local.public_key()
    cipher = RsaEnvelopeCipher(public_key)
    cipher.bind_key_provider(provider)
    return cipher


def build_object_store(settings: Settings):
    if settings.object_store == "s3":
        from openagent_audit.media.objectstore import S3ObjectStore

        return S3ObjectStore(
            settings.media_bucket,
            endpoint_url=settings.s3_endpoint or None,
            access_key=settings.s3_access_key or None,
            secret_key=settings.s3_secret_key or None,
            region=settings.aws_region or None,
        )
    from openagent_audit.media.objectstore import LocalObjectStore

    return LocalObjectStore(settings.object_store_root)


def build_db(settings: Settings):
    if settings.audit_db_url.startswith("sqlite"):
        from openagent_audit.vault.store import SQLiteAuditDatabase

        return SQLiteAuditDatabase(sqlite_path_from_url(settings.audit_db_url))
    from openagent_audit.vault.postgres_store import PostgresAuditDatabase

    return PostgresAuditDatabase(settings.audit_db_url)


def build_trace_store(settings: Settings):
    """Read/delete side of the trace master data. ``langfuse`` requires the
    public/secret key pair; ``local`` stands in for dev/tests only."""
    if settings.trace_store == "langfuse":
        from openagent_audit.tracing.trace_store import LangfuseTraceStore

        return LangfuseTraceStore(
            settings.langfuse_host,
            settings.langfuse_public_key,
            settings.langfuse_secret_key,
        )
    from openagent_audit.tracing.trace_store import LocalTraceStore

    return LocalTraceStore()


def build_retention_job(settings: Settings):
    """Assemble the retention job from settings (used by the CLI entry point
    ``python -m openagent_audit.services.retention`` — schedule it with cron /
    k8s CronJob under the ``audit_retention`` DB role, see
    deploy/audit_db_init.sql)."""
    from openagent_audit.services.audit_log_service import AuditLogService
    from openagent_audit.services.retention import RetentionJob

    db = build_db(settings)
    return RetentionJob(
        trace_store=build_trace_store(settings),
        db=db,
        audit=AuditLogService(db, build_loki(settings)),
        object_store=build_object_store(settings),
        trace_retention_days=settings.trace_retention_days,
        audit_archive_after_days=settings.audit_archive_after_days,
    )


def build_loki(settings: Settings):
    if settings.loki_url:
        from openagent_audit.alerts.loki import LokiPushClient

        return LokiPushClient(settings.loki_url)
    from openagent_audit.alerts.loki import NullLokiClient

    return NullLokiClient()

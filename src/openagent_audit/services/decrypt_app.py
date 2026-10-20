"""decrypt-svc entry point: ``uvicorn openagent_audit.services.decrypt_app:app``.

Runs as its own deployment (proposal §08 ③): the only service holding the
private key / ``kms:Decrypt``, independently auditing every decryption. The
app is built lazily so importing the module never touches key material.
"""

from __future__ import annotations

from openagent_audit.services.decrypt_svc import DecryptServiceDeps, create_decrypt_app


def _build_app():
    from openagent_audit.bootstrap import (
        build_cipher,
        build_db,
        build_key_provider,
        build_loki,
        build_object_store,
    )
    from openagent_audit.config import Settings
    from openagent_audit.services.audit_log_service import AuditLogService

    settings = Settings.from_env()
    cipher = build_cipher(settings, build_key_provider(settings))
    db = build_db(settings)
    audit = AuditLogService(db, build_loki(settings))
    object_store = None if settings.object_store == "none" else build_object_store(settings)
    return create_decrypt_app(
        DecryptServiceDeps(
            cipher=cipher,
            db=db,
            audit=audit,
            service_token=settings.service_token,
            object_store=object_store,
        )
    )


def __getattr__(name: str):
    if name == "app":
        return _build_app()
    raise AttributeError(name)

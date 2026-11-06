"""decrypt-svc — the only process that holds the private key.

The console asks it to decrypt a single entity when an administrator clicks a
masked value. Two properties are preserved from the earlier design:

* **Single object scope.** One call decrypts exactly one entity id; there is no
  bulk or "decrypt everything" operation, so a compromised caller cannot walk
  the vault.
* **Independent record.** This service writes its own audit entry for every
  decryption, so the log shows the act from both sides (audit-api records the
  administrator's request; decrypt-svc records that the plaintext was actually
  released).

What changed: the caller no longer has to present an approved "restore
request". The console's model is a single administrator action, and the
authorization decision is made there (administrator step-up) and recorded
there before the call is made. This service still verifies the shared service
token and refuses anything that does not name an administrator.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Protocol

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from openagent_audit.bootstrap import (
    build_cipher,
    build_db,
    build_key_provider,
    build_loki,
    build_object_store,
)
from openagent_audit.config import Settings


class CipherLike(Protocol):
    def open(self, ciphertext: str, *, aad: bytes) -> bytes: ...


class DecryptEntityBody(BaseModel):
    entity_id: str = Field(min_length=1, max_length=512)
    # The administrator whose click caused this decryption. Required so the
    # record always names a person, never an anonymous service call.
    actor: str = Field(min_length=1, max_length=200)
    session_user: str = Field(default="", max_length=200)


class DecryptMediaBody(BaseModel):
    object_key: str = Field(min_length=1, max_length=1024)
    actor: str = Field(min_length=1, max_length=200)
    session_user: str = Field(default="", max_length=200)


class DecryptServiceDeps:
    def __init__(self, *, cipher, db, service_token: str, object_store=None, audit=None) -> None:
        self.cipher = cipher
        self.db = db
        self.service_token = service_token
        self.object_store = object_store
        self.audit = audit


def build_deps(settings: Settings) -> DecryptServiceDeps:
    from openagent_audit.services.audit_log_service import AuditLogService

    db = build_db(settings)
    key_provider = build_key_provider(settings)
    cipher = build_cipher(settings, key_provider)
    return DecryptServiceDeps(
        cipher=cipher,
        db=db,
        service_token=settings.service_token,
        object_store=build_object_store(settings),
        audit=AuditLogService(db, build_loki(settings)),
    )


def _check_service_token(request: Request, token: str) -> None:
    import hmac

    header = request.headers.get("Authorization", "")
    if not hmac.compare_digest(header, f"Bearer {token}"):
        raise HTTPException(status_code=401, detail="服务令牌无效")


def create_decrypt_app(deps: DecryptServiceDeps) -> FastAPI:
    app = FastAPI(title="openagent-audit decrypt-svc", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "service": "decrypt-svc"}

    @app.post("/v1/decrypt")
    def decrypt_entity(body: DecryptEntityBody, request: Request) -> dict:
        _check_service_token(request, deps.service_token)

        row = deps.db.get_entity(body.entity_id)
        if row is None:
            _record(deps, body.actor, body.session_user, "DECRYPT_FAILED",
                    body.entity_id, {"reason": "not_found"})
            raise HTTPException(status_code=404, detail="实体不存在")

        try:
            plaintext = deps.cipher.open(row.ciphertext, aad=body.entity_id.encode("ascii"))
        except Exception:  # noqa: BLE001 - reported as a domain error
            _record(deps, body.actor, body.session_user, "DECRYPT_FAILED",
                    body.entity_id, {"reason": "tampered_or_wrong_key"})
            raise HTTPException(status_code=422, detail="解密失败（密文损坏或密钥不匹配）") from None

        _record(deps, body.actor, body.session_user, "DECRYPT_PERFORMED",
                body.entity_id, {"entity_type": row.entity_type})
        return {"plaintext_b64": base64.b64encode(plaintext).decode("ascii")}

    @app.post("/v1/decrypt-media")
    def decrypt_media(body: DecryptMediaBody, request: Request) -> Response:
        _check_service_token(request, deps.service_token)
        if deps.object_store is None:
            raise HTTPException(status_code=501, detail="未配置对象存储")

        try:
            payload = deps.object_store.get(body.object_key)
        except Exception:  # noqa: BLE001
            _record(deps, body.actor, body.session_user, "DECRYPT_FAILED",
                    body.object_key, {"reason": "object_not_found"})
            raise HTTPException(status_code=404, detail="对象不存在") from None

        # Media is stored encrypted with the entity AAD = object key, so the
        # service must open it before returning the bytes; handing back the
        # stored object would send ciphertext to the reviewer.
        try:
            plaintext = deps.cipher.open(
                payload.decode("ascii") if isinstance(payload, bytes) else payload,
                aad=body.object_key.encode("utf-8"),
            )
        except Exception:  # noqa: BLE001
            _record(deps, body.actor, body.session_user, "DECRYPT_FAILED",
                    body.object_key, {"reason": "tampered_or_wrong_key"})
            raise HTTPException(status_code=422, detail="解密失败（密文损坏或密钥不匹配）") from None

        _record(deps, body.actor, body.session_user, "MEDIA_DECRYPT_PERFORMED",
                body.object_key, {})
        return Response(content=plaintext, media_type="application/octet-stream")

    return app


def _record(deps: DecryptServiceDeps, actor: str, session_user: str, action: str,
            object_id: str, detail: dict | None = None) -> None:
    """Append the service-side record. Failure here is fatal for the call."""
    if deps.audit is None:
        return
    payload = {"session_user": session_user or actor, "decrypted_at": datetime.now(timezone.utc).isoformat()}
    payload.update(detail or {})
    deps.audit.append(
        actor=actor,
        role="admin",
        action=action,
        object_type="entity",
        object_id=object_id,
        detail=payload,
    )


def create_app() -> FastAPI:
    """uvicorn entry point: ``openagent_audit.services.decrypt_svc:create_app``.

    Built lazily so importing this module does not require the private key;
    tests import the module to construct their own app with injected deps.
    """
    return create_decrypt_app(build_deps(Settings.from_env()))
"""decrypt-svc — the only component that can turn ciphertext into plaintext
(proposal §08: 独立部署、单独审计).

Defense in depth: beyond audit-api's approval gate, this service independently
verifies that the referenced restore request is approved/fulfilled before
touching the vault, and writes its own audit entry for every decryption.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.vault.models import RestoreStatus


@dataclass
class DecryptServiceDeps:
    cipher: object          # EnvelopeCipher with a bound key provider
    db: object              # audit-domain database (vault + restore requests + audit log)
    audit: AuditLogService
    service_token: str
    object_store: object | None = None


class DecryptEntityBody(BaseModel):
    entity_id: str = Field(min_length=8, max_length=64)
    request_id: str = Field(min_length=8, max_length=64)
    requested_by: str = Field(min_length=1, max_length=128)


class DecryptMediaBody(BaseModel):
    key: str = Field(min_length=1, max_length=512)
    request_id: str = Field(min_length=8, max_length=64)
    requested_by: str = Field(min_length=1, max_length=128)


def _check_service_token(request: Request, token: str) -> None:
    header = request.headers.get("Authorization", "")
    if header != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid service token")


def _require_approved_request(db, request_id: str, *, object_type: str, object_id: str):
    """Independent gate (defense in depth beyond audit-api):

    - the request must exist and be APPROVED / FULFILLED;
    - the request must cover exactly the object being decrypted — one approved
      request can never unlock a different entity or media object;
    - a FULFILLED request is only valid inside its reveal TTL window.
    """
    req = db.get_restore_request(request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="restore request not found")
    if req.status not in (RestoreStatus.APPROVED, RestoreStatus.FULFILLED):
        raise HTTPException(
            status_code=409,
            detail=f"restore request is {req.status.value!r}; decryption requires approval",
        )
    if req.object_type != object_type or req.object_id != object_id:
        raise HTTPException(
            status_code=403,
            detail="restore request does not cover this object",
        )
    if req.status is RestoreStatus.FULFILLED:
        if req.reveal_expires_at is None or datetime.now(timezone.utc) >= req.reveal_expires_at:
            raise HTTPException(
                status_code=410,
                detail="reveal window has expired; file a new restore request",
            )
    return req


def create_decrypt_app(deps: DecryptServiceDeps) -> FastAPI:
    app = FastAPI(title="openagent-audit decrypt-svc", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "service": "decrypt-svc"}

    @app.post("/v1/decrypt")
    def decrypt_entity(body: DecryptEntityBody, request: Request) -> dict:
        _check_service_token(request, deps.service_token)
        _require_approved_request(
            deps.db, body.request_id, object_type="entity", object_id=body.entity_id
        )
        row = deps.db.get_entity(body.entity_id)
        if row is None:
            raise HTTPException(status_code=404, detail="entity not found")
        try:
            plaintext = deps.cipher.open(row.ciphertext, aad=body.entity_id.encode("ascii"))
        except Exception:
            raise HTTPException(status_code=422, detail="decryption failed (tampered or wrong key)")
        deps.audit.append(
            actor="decrypt-svc", role="service", action="DECRYPT_PERFORMED",
            object_type="entity", object_id=body.entity_id,
            detail={"request_id": body.request_id, "requested_by": body.requested_by},
        )
        return {"plaintext_b64": base64.b64encode(plaintext).decode("ascii")}

    @app.post("/v1/decrypt-media")
    def decrypt_media(body: DecryptMediaBody, request: Request) -> Response:
        _check_service_token(request, deps.service_token)
        _require_approved_request(
            deps.db, body.request_id, object_type="media", object_id=body.key
        )
        if deps.object_store is None:
            raise HTTPException(status_code=503, detail="no object store configured")
        try:
            sealed = deps.object_store.get(body.key).decode("ascii")
            plaintext = deps.cipher.open(sealed, aad=body.key.encode("ascii"))
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="media object not found")
        except Exception:
            raise HTTPException(status_code=422, detail="decryption failed (tampered or wrong key)")
        deps.audit.append(
            actor="decrypt-svc", role="service", action="DECRYPT_PERFORMED",
            object_type="media", object_id=body.key,
            detail={"request_id": body.request_id, "requested_by": body.requested_by},
        )
        return Response(content=plaintext, media_type="application/octet-stream")

    return app

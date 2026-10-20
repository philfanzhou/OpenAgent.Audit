"""Restore workflow (proposal §08 flow ③ “核验”).

Request (compliance_lead) -> approval (another compliance_lead, four-eyes) ->
reveal via decrypt-svc, single record, fully logged. Plaintext is returned to
the caller only; it is never persisted, never logged, and expires after the
reveal TTL.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Protocol

from openagent_audit.services.audit_log_service import AuditLogService, utcnow
from openagent_audit.vault.models import (
    OBJECT_ENTITY,
    OBJECT_MEDIA,
    RestoreRequest,
    RestoreStatus,
)


class RestoreError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class DecryptGateway(Protocol):
    """What audit-api uses to reach decrypt-svc (HTTP in prod, in-process in dev)."""

    def decrypt_entity(self, entity_id: str, *, request_id: str, requested_by: str) -> bytes: ...

    def decrypt_media(self, key: str, *, request_id: str, requested_by: str) -> bytes: ...


class RestoreService:
    def __init__(
        self,
        db,
        audit: AuditLogService,
        decrypt: DecryptGateway,
        *,
        reveal_ttl_minutes: int = 10,
        clock=utcnow,
    ) -> None:
        self._db = db
        self._audit = audit
        self._decrypt = decrypt
        self._ttl = timedelta(minutes=reveal_ttl_minutes)
        self._clock = clock

    # -- request -------------------------------------------------------------
    def request(
        self,
        *,
        actor: str,
        role: str,
        object_type: str,
        object_id: str,
        reason: str,
        trace_id: str | None = None,
        session_id: str | None = None,
    ) -> RestoreRequest:
        if role != "compliance_lead":
            raise RestoreError("forbidden", "only compliance leads may request restores", 403)
        if not reason or not reason.strip():
            raise RestoreError("reason_required", "a written reason is required", 422)
        if object_type not in (OBJECT_ENTITY, OBJECT_MEDIA):
            raise RestoreError("bad_object_type", f"object_type must be '{OBJECT_ENTITY}' or '{OBJECT_MEDIA}'", 422)
        if object_type == OBJECT_ENTITY and self._db.get_entity(object_id) is None:
            raise RestoreError("entity_not_found", f"entity {object_id!r} not in vault", 404)

        req = RestoreRequest(
            id=uuid.uuid4().hex,
            object_type=object_type,
            object_id=object_id,
            reason=reason.strip(),
            requested_by=actor,
            trace_id=trace_id,
            session_id=session_id,
            status=RestoreStatus.PENDING,
            created_at=self._clock(),
        )
        self._db.insert_restore_request(req)
        self._audit.append(
            actor=actor, role=role, action="RESTORE_REQUESTED",
            object_type=object_type, object_id=object_id,
            detail={"request_id": req.id, "trace_id": trace_id, "session_id": session_id},
        )
        return req

    # -- approval --------------------------------------------------------------
    def decide(
        self,
        request_id: str,
        *,
        approver: str,
        role: str,
        approve: bool,
        comment: str | None = None,
    ) -> RestoreRequest:
        if role != "compliance_lead":
            raise RestoreError("forbidden", "only compliance leads may decide restores", 403)
        req = self._db.get_restore_request(request_id)
        if req is None:
            raise RestoreError("request_not_found", f"restore request {request_id!r} not found", 404)
        if req.status is not RestoreStatus.PENDING:
            raise RestoreError("not_pending", f"request is {req.status.value}, not pending", 409)
        if req.requested_by == approver:
            raise RestoreError(
                "four_eyes", "the requester cannot approve their own request", 403
            )
        now = self._clock()
        status = RestoreStatus.APPROVED if approve else RestoreStatus.REJECTED
        updated = self._db.update_restore_request(
            request_id,
            status=status,
            approver=approver,
            decision_comment=comment,
            decided_at=now,
        )
        assert updated is not None
        self._audit.append(
            actor=approver, role=role,
            action="RESTORE_APPROVED" if approve else "RESTORE_REJECTED",
            object_type=req.object_type, object_id=req.object_id,
            detail={"request_id": req.id},
        )
        return updated

    # -- reveal ------------------------------------------------------------------
    def reveal(self, request_id: str, *, actor: str, role: str) -> dict:
        if role != "compliance_lead":
            raise RestoreError("forbidden", "only compliance leads may reveal restores", 403)
        req = self._db.get_restore_request(request_id)
        if req is None:
            raise RestoreError("request_not_found", f"restore request {request_id!r} not found", 404)
        now = self._clock()

        if req.status is RestoreStatus.APPROVED or req.status is RestoreStatus.FULFILLED:
            # APPROVED: first reveal performs the decryption via decrypt-svc.
            # FULFILLED: re-view inside the TTL window — still logged.
            if req.status is RestoreStatus.FULFILLED:
                if req.reveal_expires_at is None or now >= req.reveal_expires_at:
                    raise RestoreError(
                        "reveal_expired", "reveal window has expired; file a new restore request", 410
                    )
            try:
                if req.object_type == OBJECT_ENTITY:
                    plaintext = self._decrypt.decrypt_entity(
                        req.object_id, request_id=req.id, requested_by=actor
                    )
                else:
                    plaintext = self._decrypt.decrypt_media(
                        req.object_id, request_id=req.id, requested_by=actor
                    )
            except KeyError:
                raise RestoreError("not_found", "ciphertext not found in vault", 404) from None
            except Exception as exc:
                self._audit.append(
                    actor=actor, role=role, action="DECRYPT_FAILED",
                    object_type=req.object_type, object_id=req.object_id,
                    detail={"request_id": req.id},
                )
                raise RestoreError(
                    "decrypt_failed", "decryption failed (tampered, wrong key, or undecodable)", 422
                ) from exc
            if req.status is RestoreStatus.APPROVED:
                self._audit.append(
                    actor=actor, role=role,
                    action="RESTORE_DECRYPTED" if req.object_type == OBJECT_ENTITY else "MEDIA_DECRYPTED",
                    object_type=req.object_type, object_id=req.object_id,
                    detail={"request_id": req.id},
                )
                self._db.update_restore_request(
                    req.id,
                    status=RestoreStatus.FULFILLED,
                    reveal_expires_at=now + self._ttl,
                )
        else:
            raise RestoreError(
                "not_approved", f"request status is {req.status.value!r}; decryption not allowed", 409
            )

        # Every view is logged (proposal §08: 浏览与解密 100% 进入审计日志).
        self._audit.append(
            actor=actor, role=role, action="RESTORE_VIEWED",
            object_type=req.object_type, object_id=req.object_id,
            detail={"request_id": req.id},
        )
        result = {
            "request_id": req.id,
            "object_type": req.object_type,
            "object_id": req.object_id,
            "reveal_expires_at": (req.reveal_expires_at or now + self._ttl).isoformat(),
        }
        if req.object_type == OBJECT_ENTITY:
            result["plaintext"] = plaintext.decode("utf-8")
        else:
            result["content_b64"] = base64.b64encode(plaintext).decode("ascii")
        return result

    def get(self, request_id: str) -> RestoreRequest | None:
        return self._db.get_restore_request(request_id)

    def list(self, status: RestoreStatus | None = None) -> list[RestoreRequest]:
        return self._db.list_restore_requests(status)

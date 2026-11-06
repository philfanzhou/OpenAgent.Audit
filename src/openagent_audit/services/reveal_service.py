"""Reveal service: turn one masked placeholder back into its original text.

This replaces the old approve-then-reveal workflow. The audit plane has two
kinds of people: staff who read masked conversations, and an administrator who
— from inside their own signed-in session — can click a masked value to see
the original.

Two guarantees matter and are enforced here, not in the UI:

1. **Nothing is revealed without a record.** The audit entry is appended
   *before* the plaintext is returned. If the append fails, no plaintext is
   returned at all (fail-closed): an unlogged reveal is a compliance failure,
   so it must not be possible.
2. **The record cannot be altered afterwards.** Entries go to the append-only,
   hash-chained audit_log table; the chain makes edits and deletions
   detectable (vault/hashchain.py), and no application role holds UPDATE or
   DELETE on it (deploy/10_audit_schema.sql).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass


class RevealError(Exception):
    """Raised when a reveal cannot proceed; carries an operator-safe message."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class RevealResult:
    object_id: str
    entity_type: str
    plaintext: str


class RevealService:
    """Decrypts single entities on behalf of an authenticated administrator."""

    def __init__(self, *, decrypt, vault, audit) -> None:
        self._decrypt = decrypt
        self._vault = vault
        self._audit = audit

    def reveal_entity(
        self,
        entity_id: str,
        *,
        actor: str,
        role: str,
        session_user: str,
        trace_id: str | None = None,
        session_id: str | None = None,
    ) -> RevealResult:
        """Decrypt one entity and record the reveal.

        ``actor``/``role`` describe the effective identity (an administrator);
        ``session_user`` is who the browser session belongs to, which is what
        makes the log answer the question that actually matters during a
        investigation: *which person was sitting at the console*.
        """
        if not entity_id or len(entity_id) > 512:
            raise RevealError("invalid_entity", "实体编号无效。", 400)

        row = self._lookup(entity_id)
        entity_type = getattr(row, "entity_type", "UNKNOWN")

        # Record first, decrypt second. A failed append must not hand out
        # plaintext, otherwise the guarantee above is only nominal.
        self._record(
            action="ENTITY_REVEAL_REQUESTED",
            actor=actor,
            role=role,
            session_user=session_user,
            entity_id=entity_id,
            entity_type=entity_type,
            trace_id=trace_id,
            session_id=session_id,
        )

        try:
            plaintext = self._decrypt.decrypt_entity(
                entity_id,
                actor=actor,
                session_user=session_user,
            )
        except KeyError:
            self._record(
                action="ENTITY_REVEAL_FAILED",
                actor=actor,
                role=role,
                session_user=session_user,
                entity_id=entity_id,
                entity_type=entity_type,
                trace_id=trace_id,
                session_id=session_id,
                extra={"reason": "not_found"},
            )
            raise RevealError("not_found", "密文中不存在该实体编号。", 404) from None
        except Exception as exc:  # noqa: BLE001 - reported, then re-raised as a reveal error
            self._record(
                action="ENTITY_REVEAL_FAILED",
                actor=actor,
                role=role,
                session_user=session_user,
                entity_id=entity_id,
                entity_type=entity_type,
                trace_id=trace_id,
                session_id=session_id,
                extra={"reason": type(exc).__name__},
            )
            raise RevealError(
                "decrypt_failed", "解密失败（密文损坏或密钥不匹配）。", 422
            ) from exc

        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = base64.b64encode(plaintext).decode("ascii")

        self._record(
            action="ENTITY_REVEALED",
            actor=actor,
            role=role,
            session_user=session_user,
            entity_id=entity_id,
            entity_type=entity_type,
            trace_id=trace_id,
            session_id=session_id,
        )
        return RevealResult(object_id=entity_id, entity_type=entity_type, plaintext=text)

    # -- helpers ------------------------------------------------------------

    def _lookup(self, entity_id: str):
        """Best-effort metadata lookup; the plaintext path does not depend on it."""
        try:
            return self._vault.get_entity(entity_id)
        except Exception:  # noqa: BLE001 - metadata is informative only
            return None

    def _record(
        self,
        *,
        action: str,
        actor: str,
        role: str,
        session_user: str,
        entity_id: str,
        entity_type: str,
        trace_id: str | None,
        session_id: str | None,
        extra: dict | None = None,
    ) -> None:
        detail = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            # Who signed in to the console, as distinct from the effective
            # identity that performed the reveal.
            "session_user": session_user,
        }
        if trace_id:
            detail["trace_id"] = trace_id
        if session_id:
            detail["session_id"] = session_id
        if extra:
            detail.update(extra)

        # No try/except: an append failure aborts the reveal.
        self._audit.append(
            actor=actor,
            role=role,
            action=action,
            object_type="entity",
            object_id=entity_id,
            detail=detail,
        )
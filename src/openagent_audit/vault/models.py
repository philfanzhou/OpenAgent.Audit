"""Audit-domain row types (ciphertext vault, audit log, restore requests)."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class RestoreStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    FULFILLED = "fulfilled"


OBJECT_ENTITY = "entity"
OBJECT_MEDIA = "media"


@dataclass(frozen=True)
class EntityCiphertextRow:
    entity_id: str
    entity_type: str
    ciphertext: str
    trace_id: str | None = None
    session_id: str | None = None
    created_at: datetime | None = None


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: datetime
    actor: str
    role: str
    action: str
    object_type: str | None
    object_id: str | None
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""


@dataclass(frozen=True)
class RestoreRequest:
    id: str
    object_type: str
    object_id: str
    reason: str
    requested_by: str
    trace_id: str | None = None
    session_id: str | None = None
    status: RestoreStatus = RestoreStatus.PENDING
    approver: str | None = None
    decision_comment: str | None = None
    created_at: datetime | None = None
    decided_at: datetime | None = None
    reveal_expires_at: datetime | None = None

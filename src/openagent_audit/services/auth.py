"""Audit-plane roles and permissions (proposal §08 role table).

- ``auditor``         — audit-web masked views; never sees plaintext
- ``compliance_lead`` — masked views + request/approve/reveal restores
                        (four-eyes: an approver can never approve their own
                        request)
- ``developer``       — Langfuse UI only; the audit plane denies access so
                        troubleshooting data stays in Langfuse
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from openagent_audit.config import Settings, UserEntry

VIEW_MASKED = "view_masked"
MANAGE_RESTORE = "manage_restore"
VIEW_AUDIT_LOG = "view_audit_log"
VIEW_METRICS = "view_metrics"

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "auditor": frozenset({VIEW_MASKED, VIEW_AUDIT_LOG, VIEW_METRICS}),
    "compliance_lead": frozenset({VIEW_MASKED, MANAGE_RESTORE, VIEW_AUDIT_LOG, VIEW_METRICS}),
    "developer": frozenset({VIEW_METRICS}),
}


@dataclass(frozen=True)
class Principal:
    username: str
    role: str

    def can(self, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, frozenset())


class AuthenticationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


class Authenticator:
    def __init__(self, users: tuple[UserEntry, ...]) -> None:
        self._by_token = {u.token: u for u in users}

    def resolve(self, token: str | None) -> Principal | None:
        if not token:
            return None
        entry = self._by_token.get(token)
        if entry is None:
            return None
        return Principal(username=entry.username, role=entry.role)

    def require(self, token: str | None, permission: str) -> Principal:
        principal = self.resolve(token)
        if principal is None:
            raise AuthenticationError("missing or unknown bearer token")
        if not principal.can(permission):
            raise AuthorizationError(
                f"role {principal.role!r} lacks permission {permission!r}"
            )
        return principal


def load_authenticator(settings: Settings) -> Authenticator:
    return Authenticator(settings.users)

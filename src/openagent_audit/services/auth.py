"""Audit-plane roles and permissions.

- ``auditor``         — audit-web masked views + audit log; never sees plaintext
- ``compliance_lead`` — masked views + request/approve/reveal restores
                        (four-eyes: an approver can never approve their own
                        request)
- ``developer``       — read-only admin: can view everything (sessions,
                        restore requests, audit log) plus the operational
                        metrics, but has NO write/approve/reveal capability —
                        decryption stays exclusively behind the compliance
                        four-eyes flow
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Protocol

from openagent_audit.config import Settings, UserEntry

VIEW_MASKED = "view_masked"
MANAGE_RESTORE = "manage_restore"
VIEW_AUDIT_LOG = "view_audit_log"
VIEW_METRICS = "view_metrics"

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "auditor": frozenset({VIEW_MASKED, VIEW_AUDIT_LOG}),
    "compliance_lead": frozenset({VIEW_MASKED, MANAGE_RESTORE, VIEW_AUDIT_LOG}),
    # Read-only admin: full visibility + operational metrics, zero mutation —
    # the audit plane only ever holds masks, so this does not cross the
    # proposal §07 threat model; restores still require compliance four-eyes.
    "developer": frozenset({VIEW_MASKED, VIEW_AUDIT_LOG, VIEW_METRICS}),
}

# Human-readable names used in professional denial messages.
PERMISSION_LABELS: dict[str, str] = {
    VIEW_MASKED: "审计会话查看（掩码视图）",
    MANAGE_RESTORE: "还原申请与审批（查看原文）",
    VIEW_AUDIT_LOG: "审计日志查看",
    VIEW_METRICS: "运行指标查看",
}

ROLE_LABELS: dict[str, str] = {
    "auditor": "审计员",
    "compliance_lead": "合规主管",
    "developer": "开发者（只读管理员）",
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
            raise AuthenticationError(
                "认证失败：访问令牌缺失或无效（missing or invalid bearer token），请重新登录。"
            )
        if not principal.can(permission):
            raise AuthorizationError(
                f"权限不足：当前角色「{ROLE_LABELS.get(principal.role, principal.role)}」"
                f"（{principal.role}）未被授予「{PERMISSION_LABELS.get(permission, permission)}」"
                f"权限（{permission}）。如需相应访问能力，请联系系统管理员调整角色授权。"
            )
        return principal


def load_authenticator(settings: Settings) -> Authenticator:
    """Choose the auth source (reserved interface for the OpenAgent platform).

    - ``static`` (default): tokens come from ``AUDIT_USERS`` — dev / demo.
    - ``http``: tokens are resolved against the OpenAgent platform's token
      introspection endpoint (``AUDIT_AUTH_INTROSPECT_URL``). The platform
      implements the contract in docs/openagent-integration.md §身份认证:
      ``GET <url>`` with ``Authorization: Bearer <audit token>`` →
      ``200 {"username": "...", "role": "auditor|compliance_lead|developer"}``
      or 401 for unknown/invalid tokens.
    """
    if settings.auth_provider == "http":
        return HttpIntrospectionAuthenticator(
            settings.auth_introspect_url,
            cache_seconds=settings.auth_cache_seconds,
        )
    return Authenticator(settings.users)


class IntrospectionClient(Protocol):
    """Minimal HTTP surface (httpx.Client compatible) for testing."""

    def get(self, url: str, headers: dict) -> object: ...


class HttpIntrospectionAuthenticator(Authenticator):
    """Resolves tokens against an external identity provider (OpenAgent).

    Roles stay local: the platform maps its users onto the three audit roles,
    so permission checks never change with the identity source. Responses are
    cached for ``cache_seconds`` to keep the platform out of the hot path.
    """

    def __init__(self, introspect_url: str, *, cache_seconds: float = 60.0, client: IntrospectionClient | None = None) -> None:
        super().__init__(())
        if not introspect_url:
            raise ValueError(
                "AUDIT_AUTH_INTROSPECT_URL is required when AUDIT_AUTH_PROVIDER=http"
            )
        self._url = introspect_url
        self._cache_ttl = cache_seconds
        self._client = client
        self._cache: dict[str, tuple[float, Principal]] = {}
        self._lock = threading.Lock()

    def _http_get(self, token: str):
        if self._client is not None:
            return self._client.get(self._url, headers={"Authorization": f"Bearer {token}"})
        import httpx

        with httpx.Client(timeout=5.0) as client:
            return client.get(self._url, headers={"Authorization": f"Bearer {token}"})

    def resolve(self, token: str | None) -> Principal | None:
        if not token:
            return None
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(token)
            if cached is not None and cached[0] > now:
                return cached[1]
        try:
            resp = self._http_get(token)
        except Exception:
            return None  # identity provider unreachable -> treat as unauthenticated
        if getattr(resp, "status_code", 0) != 200:
            return None
        try:
            body = resp.json()
        except Exception:
            return None
        username = body.get("username")
        role = body.get("role")
        if not username or role not in ROLE_PERMISSIONS:
            return None
        principal = Principal(username=username, role=role)
        with self._lock:
            self._cache[token] = (now + self._cache_ttl, principal)
        return principal

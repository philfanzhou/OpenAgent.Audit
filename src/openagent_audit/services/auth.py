"""Audit-plane identity and authorization (two roles only).

The audit plane is an internal IT tool: the people who use it are staff who
occasionally need to inspect a conversation. That shape needs exactly two
roles, not a workflow system:

``user``
    Anyone the OpenAgent platform vouches for. Can open the console and read
    masked conversations. Cannot see plaintext, ever.

``admin``
    Reached by typing the administrator credentials *from inside* a signed-in
    user session, not by holding a privileged token. An admin can click a
    masked value to reveal its original text. Every reveal is written to the
    append-only audit log before the plaintext is returned.

Why admin is a step-up and not a token
--------------------------------------
The platform hands out tokens for ordinary staff. If an admin token existed,
holding it would be enough to decrypt production conversations — and
distributing such a token defeats the point of masking. A step-up password
means the privileged capability lives behind something the operator must know
and type, inside a session that is already attributed to a real user, and the
unlock is bounded in time.

The plaintext path
------------------
Reveal does not create a "restore request" that another person must approve.
It is a single action: the admin clicks the placeholder, the server logs
``ENTITY_REVEALED`` (actor, time, entity) and then returns the decrypted value.
The audit log is append-only and hash-chained (see vault/hashchain.py), so the
record cannot be silently altered or removed afterwards.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from openagent_audit.config import Settings, UserEntry

ROLE_USER = "user"
ROLE_ADMIN = "admin"

# The only two roles. Kept as a tuple so tests and callers can iterate it.
ROLES = (ROLE_USER, ROLE_ADMIN)

# Permission names are intentionally few: the model has two levels of access.
VIEW_MASKED = "view_masked"       # read masked conversations
REVEAL_PLAINTEXT = "reveal"       # click a mask to see the original
VIEW_AUDIT_LOG = "view_audit_log"
VIEW_METRICS = "view_metrics"

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    # Ordinary staff: masked data only.
    ROLE_USER: frozenset({VIEW_MASKED}),
    # IT administrators: everything, including reveal.
    ROLE_ADMIN: frozenset({VIEW_MASKED, REVEAL_PLAINTEXT, VIEW_AUDIT_LOG, VIEW_METRICS}),
}

PERMISSION_LABELS: dict[str, str] = {
    VIEW_MASKED: "审计会话查看（掩码视图）",
    REVEAL_PLAINTEXT: "查看原文（解密）",
    VIEW_AUDIT_LOG: "审计日志查看",
    VIEW_METRICS: "运行指标查看",
}

ROLE_LABELS: dict[str, str] = {
    ROLE_USER: "普通用户",
    ROLE_ADMIN: "管理员",
}


@dataclass(frozen=True)
class Principal:
    """An authenticated caller.

    ``username`` is who they are — from the OpenAgent platform, or the local
    test account. ``role`` is what they may do. ``via_admin_login`` records
    that the role was granted by an explicit administrator login rather than
    carried by the incoming identity, so the audit log can distinguish
    "staff browsing" from "administrator stepped up".

    ``ephemeral`` marks the local test account. It exists only so the console
    can be exercised when the platform is not forwarding an identity, and it
    is deliberately unable to escalate: see :meth:`can_step_up_to_admin`.
    """

    username: str
    role: str
    via_admin_login: bool = False
    ephemeral: bool = False

    def can(self, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, frozenset())

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def can_step_up_to_admin(self) -> bool:
        """Whether this identity may unlock the administrator role.

        The test account never can. It exists so somebody can confirm the
        console renders; handing it the decryption path would turn a
        convenience login into a back door, especially because its password is
        documented in the deployment guide.
        """
        return not self.ephemeral


class AuthenticationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


def check(principal: Principal | None, permission: str) -> Principal:
    """Raise unless *principal* holds *permission*.

    Messages are written for an operator reading a browser, not a developer
    reading a stack trace, and deliberately carry no internal detail.
    """
    if principal is None:
        raise AuthenticationError(
            "认证失败：请先进入审计系统（访问令牌缺失或无效）。"
        )
    if not principal.can(permission):
        raise AuthorizationError(
            f"权限不足：当前身份「{ROLE_LABELS.get(principal.role, principal.role)}」"
            f"没有「{PERMISSION_LABELS.get(permission, permission)}」权限。"
            "查看原文需要管理员登录。"
        )
    return principal


# ---------------------------------------------------------------------------
# Password verification for the administrator account
# ---------------------------------------------------------------------------


def _constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def verify_admin_password(settings: Settings, username: str, password: str) -> bool:
    """Check the administrator credentials.

    Both fields are compared in constant time, and an unknown username is
    still compared against the configured one so the response time does not
    reveal whether the account exists.
    """
    expected_user = settings.admin_username
    expected_password = settings.admin_password
    if not expected_password:
        # Refuse rather than allow an empty password to unlock decryption.
        return False

    user_ok = _constant_time_equals(username or "", expected_user)
    password_ok = _constant_time_equals(password or "", expected_password)
    return user_ok and password_ok


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------


_SCHEME = "pbkdf2_sha256"


def _hash_password(password: str, *, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def hash_admin_password(password: str, *, iterations: int = 210_000) -> str:
    """Return a self-describing hash string suitable for AUDIT_ADMIN_PASSWORD_HASH.

    Format: ``pbkdf2_sha256$<iterations>$<salt-b64>$<hash-b64>``. Storing the
    hash instead of the password means a leaked environment file does not hand
    over decryption capability directly.
    """
    salt = secrets.token_bytes(16)
    digest = _hash_password(password, salt=salt, iterations=iterations)
    import base64

    return "$".join(
        (
            _SCHEME,
            str(iterations),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def verify_password_hash(stored: str, password: str) -> bool:
    """Check *password* against a hash produced by :func:`hash_admin_password`."""
    import base64

    try:
        scheme, iterations_text, salt_b64, digest_b64 = stored.split("$")
        if scheme != _SCHEME:
            return False
        iterations = int(iterations_text)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False

    candidate = _hash_password(password, salt=salt, iterations=iterations)
    return hmac.compare_digest(candidate, expected)


@dataclass(frozen=True)
class Session:
    """A browser session bound to a platform identity.

    ``admin_until`` is a monotonic deadline: the administrator unlock expires
    on its own so a forgotten browser tab cannot decrypt indefinitely.
    """

    token: str
    principal: Principal
    created_at: float
    admin_until: float | None = None

    def is_admin_unlocked(self, now: float | None = None) -> bool:
        if self.admin_until is None:
            return False
        return (now if now is not None else time.time()) < self.admin_until


class SessionStore:
    """In-memory session table.

    Sessions are intentionally ephemeral: a restart signs everyone out, which
    is the safe default for a console that can decrypt conversations. The
    authoritative record of who did what lives in the hash-chained audit log,
    not here.
    """

    def __init__(
        self,
        *,
        admin_unlock_seconds: int = 300,
        admin_cooldown_seconds: int = 600,
        idle_seconds: int = 8 * 3600,
        test_session_seconds: int = 3600,
    ) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._admin_unlock_seconds = admin_unlock_seconds
        self._admin_cooldown_seconds = admin_cooldown_seconds
        self._idle_seconds = idle_seconds
        self._test_session_seconds = test_session_seconds
        # username -> monotonic instant when the administrator unlock ended.
        # Drives the cooldown that prevents immediate re-arming.
        self._admin_ended_at: dict[str, float] = {}

    @property
    def admin_unlock_seconds(self) -> int:
        return self._admin_unlock_seconds

    @property
    def admin_cooldown_seconds(self) -> int:
        return self._admin_cooldown_seconds

    @property
    def test_session_seconds(self) -> int:
        return self._test_session_seconds

    def create(self, principal: Principal) -> Session:
        token = secrets.token_urlsafe(32)
        session = Session(token=token, principal=principal, created_at=time.time())
        with self._lock:
            self._sessions[token] = session
        return session

    def get(self, token: str | None) -> Session | None:
        """Return the session, expiring its administrator unlock when due.

        The unlock is checked on every access, so a 5-minute window closes even
        if the browser never sends another request. When it closes the end time
        is remembered so the cooldown can start counting.
        """
        if not token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if self._is_expired(session):
                del self._sessions[token]
                return None

            if session.admin_until is not None and now >= session.admin_until:
                # Unlock just expired: fall back to an ordinary user and start
                # the cooldown for this account.
                self._admin_ended_at[session.principal.username] = now
                downgraded = Session(
                    token=session.token,
                    principal=Principal(username=session.principal.username, role=ROLE_USER),
                    created_at=session.created_at,
                )
                self._sessions[token] = downgraded
                return downgraded
            return session

    def _is_expired(self, session: Session) -> bool:
        """Lifetime check.

        The local test account lives exactly one hour; platform-identity
        sessions use the idle window. A restart clears everything regardless.
        """
        lifetime = (
            self._test_session_seconds
            if session.principal.ephemeral
            else self._idle_seconds
        )
        return time.time() - session.created_at > lifetime

    def admin_cooldown_remaining(self, username: str) -> int:
        """Seconds this account must still wait before it may unlock again."""
        with self._lock:
            return self._cooldown_remaining_locked(username)

    def _cooldown_remaining_locked(self, username: str) -> int:
        """Cooldown check that assumes the lock is already held.

        Calling the public helper here would deadlock: ``threading.Lock`` is not
        reentrant, so the same thread cannot acquire it twice.
        """
        ended = self._admin_ended_at.get(username)
        if ended is None:
            return 0
        remaining = int(self._admin_cooldown_seconds - (time.time() - ended))
        return max(remaining, 0)

    def grant_admin(self, token: str) -> Session | None:
        """Arm the administrator unlock, or return None when it cannot be armed.

        Returns None when the account is cooling down *or* when the session
        belongs to the local test account. Callers must treat None as "the
        login did not happen" and say why.
        """
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.principal.ephemeral:
                # The test account exists to confirm the console renders; it is
                # never allowed to reach the decryption path.
                return None
            if self._cooldown_remaining_locked(session.principal.username) > 0:
                # Locked out: leave the session as an ordinary user.
                return None

            self._admin_ended_at.pop(session.principal.username, None)
            upgraded = Session(
                token=session.token,
                principal=Principal(
                    username=session.principal.username,
                    role=ROLE_ADMIN,
                    via_admin_login=True,
                ),
                created_at=session.created_at,
                admin_until=time.time() + self._admin_unlock_seconds,
            )
            self._sessions[token] = upgraded
            return upgraded

    def revoke_admin(self, token: str) -> None:
        """Drop the administrator role immediately and start the cooldown."""
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return
            if session.principal.is_admin:
                self._admin_ended_at[session.principal.username] = time.time()
            self._sessions[token] = Session(
                token=session.token,
                principal=Principal(username=session.principal.username, role=ROLE_USER),
                created_at=session.created_at,
            )

    def drop(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


# ---------------------------------------------------------------------------
# Platform-side identity resolution (what OpenAgent vouches for)
# ---------------------------------------------------------------------------


class IntrospectionClient(Protocol):
    """Minimal HTTP surface (httpx.Client compatible) for testing."""

    def get(self, url: str, headers: dict) -> object: ...


def _platform_username(body: object) -> str | None:
    """Extract a display name from a platform identity response.

    OpenAgent's ``/api/v1/agent/me`` answers
    ``{userId, username, email, tenantId, roles, ...}``; older or
    hand-written introspection endpoints often return just ``{username}``.
    Prefer the human-readable name, fall back to the stable id, and never
    accept a blank value.
    """
    if not isinstance(body, dict):
        return None
    for key in ("username", "userName", "name", "userId", "user_id", "sub", "email"):
        value = body.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


class IdentityResolver:
    """Resolves an incoming credential into an audit ``user`` identity.

    Three sources, in order:

    1. **The local test account** (``AUDIT_TEST_USERNAME``/``AUDIT_TEST_PASSWORD``).
       A deliberate fallback for when the platform is not forwarding an
       identity — enough to confirm the console renders, never enough to
       decrypt. It cannot step up to administrator.
    2. **The OpenAgent platform** (``auth_provider=http``): the incoming bearer
       token is presented to the platform's ``/me`` endpoint, which answers
       who the caller is. That is the normal path.
    3. **``AUDIT_USERS``** (``auth_provider=static``), for local runs where no
       platform is available.

    Every platform identity becomes ``user``. There is no role mapping: the
    administrator capability is granted only by the step-up login, never
    carried by a token's claims.
    """

    def __init__(self, settings: Settings, client: IntrospectionClient | None = None) -> None:
        self._settings = settings
        self._client = client
        self._by_token = {u.token: u for u in settings.users}
        self._cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def resolve(self, token: str | None) -> Principal | None:
        if not token:
            return None
        if self._settings.auth_provider == "static":
            entry: UserEntry | None = self._by_token.get(token)
            if entry is None:
                return None
            return Principal(username=entry.username, role=ROLE_USER)
        return self._resolve_platform(token)

    def resolve_test_account(self, username: str, password: str) -> Principal | None:
        """Validate the local test credentials in constant time.

        Returns an ``ephemeral`` principal, which the session store refuses to
        promote to administrator and which expires after one hour.
        """
        expected_user = self._settings.test_username
        expected_password = self._settings.test_password
        if not expected_user or not expected_password:
            # Test login is closed unless explicitly configured on both sides.
            return None

        # An ephemeral account is pointless if it collides with the real admin
        # name, so treat that misconfiguration as "no test account".
        if expected_user == self._settings.admin_username:
            return None

        user_ok = hmac.compare_digest(username or "", expected_user)
        password_ok = hmac.compare_digest(password or "", expected_password)
        if not (user_ok and password_ok):
            return None
        return Principal(username=expected_user, role=ROLE_USER, ephemeral=True)

    def _resolve_platform(self, token: str) -> Principal | None:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(token)
            if cached is not None and cached[0] > now:
                return Principal(username=cached[1], role=ROLE_USER)

        try:
            response = self._http_get(token)
        except Exception:  # noqa: BLE001 - unreachable provider fails closed
            return None

        if getattr(response, "status_code", 0) != 200:
            return None
        try:
            body = response.json()
        except Exception:  # noqa: BLE001
            return None

        username = _platform_username(body)
        if not username:
            return None

        ttl = float(self._settings.auth_cache_seconds)
        with self._lock:
            self._cache[token] = (now + ttl, username)
        return Principal(username=username, role=ROLE_USER)

    def _http_get(self, token: str):
        if self._client is not None:
            return self._client.get(
                self._settings.auth_introspect_url,
                headers={"Authorization": f"Bearer {token}"},
            )

        import httpx

        from openagent_audit.tls import httpx_tls_kwargs

        with httpx.Client(timeout=5.0, **httpx_tls_kwargs(self._settings)) as client:
            return client.get(
                self._settings.auth_introspect_url,
                headers={"Authorization": f"Bearer {token}"},
            )
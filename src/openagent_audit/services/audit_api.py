"""audit-api + audit-web — the read side (proposal §08 ② 展示 / §11.4).

Two roles, one console:

``user``
    Anyone the OpenAgent platform vouches for. Opens the console, reads masked
    conversations. No plaintext, no admin capabilities.

``admin``
    Unlocked by typing the administrator credentials *inside* a signed-in
    session (the "管理员登录" button). Then a masked placeholder becomes
    clickable: clicking it decrypts that single value and records the act in
    the append-only audit log before returning the text.

The read side never holds the private key: plaintext exists only in the
decrypt service's response, and every access is logged.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from openagent_audit.bootstrap import (
    build_cipher,
    build_db,
    build_key_provider,
    build_loki,
    build_object_store,
)
from openagent_audit.config import Settings
from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.services.auth import (
    ROLE_ADMIN,
    ROLE_LABELS,
    ROLE_USER,
    AuthenticationError,
    AuthorizationError,
    IdentityResolver,
    Principal,
    SessionStore,
    VIEW_AUDIT_LOG,
    VIEW_MASKED,
    VIEW_METRICS,
    check,
    verify_password_hash,
)
from openagent_audit.services.decrypt_client import HttpDecryptService, InProcessDecryptService
from openagent_audit.services.reveal_service import RevealError, RevealService
from openagent_audit.services.sso import SsoClient, SsoError, sign_state_cookie, verify_state_cookie
from openagent_audit.tls import httpx_tls_kwargs, warn_if_verification_disabled
from openagent_audit.timezone_display import resolve_timezone, to_display, zone_label
from openagent_audit.tracing.drop_monitor import DropMonitor
from openagent_audit.tracing.trace_store import LangfuseTraceStore, LocalTraceStore

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_SESSION_COOKIE = "openagent_audit_session"
# Platform token handed to the browser, used to resolve who is signed in.
_IDENTITY_COOKIE = "openagent_audit_identity"
# Signed cookie carrying the OIDC state across the SSO round trip.
_SSO_STATE_COOKIE = "openagent_audit_sso_state"
# Secret for signing that cookie; generated per deployment.
_SSO_STATE_SECRET_ENV = "AUDIT_SSO_STATE_SECRET"

# Search-first: unconditional browsing of the session list is allowed only up
# to this many sessions; beyond it the UI demands a search/filter.
BROWSE_THRESHOLD = 200

# A masked entity as written into a trace: ⟦TYPE#id|mask⟧
_ENTITY_RE = re.compile(r"⟦([^⟧]*?)#([0-9a-fA-F]{8,})[|]([^⟧]*)⟧")

# Paging policy, identical for sessions and the audit log: ten rows per page,
# at most twenty pages. Beyond ~200 entries the console expects a search rather
# than an unbounded scan — that keeps a page load bounded and, for the audit
# log, avoids crawling the whole chain on every click.
PAGE_SIZE = 10
MAX_PAGES = 20
MAX_VISIBLE = PAGE_SIZE * MAX_PAGES


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------


@dataclass
class AppContainer:
    settings: Settings
    db: object
    audit: AuditLogService
    identities: IdentityResolver
    sessions: SessionStore
    reveal: RevealService
    trace_store: object
    object_store: object | None
    drop_monitor: DropMonitor = field(default_factory=DropMonitor)
    sso: SsoClient | None = None
    # Display timezone: entries are stored in UTC and rendered in this zone.
    display_tz: object = field(default_factory=lambda: timezone.utc)


def build_container(settings: Settings) -> AppContainer:
    db = build_db(settings)
    audit = AuditLogService(db, build_loki(settings))
    object_store = build_object_store(settings)

    if settings.decrypt_svc_url:
        decrypt = HttpDecryptService(
            settings.decrypt_svc_url, settings.service_token, tls=httpx_tls_kwargs(settings)
        )
    else:
        key_provider = build_key_provider(settings)
        cipher = build_cipher(settings, key_provider)
        decrypt = InProcessDecryptService(
            cipher=cipher,
            key_provider=key_provider,
            vault=db,
            object_store=object_store,
            audit=audit,
        )

    reveal = RevealService(decrypt=decrypt, vault=db, audit=audit)

    if settings.trace_store == "langfuse":
        trace_store = LangfuseTraceStore(
            settings.langfuse_host,
            settings.langfuse_public_key,
            settings.langfuse_secret_key,
            tls=httpx_tls_kwargs(settings),
        )
    else:
        trace_store = LocalTraceStore()
        if settings.demo_seed:
            from openagent_audit.services.demo_seed import seed_demo_data

            seed_demo_data(settings, trace_store, db)

    warn_if_verification_disabled(settings)

    sso_client = SsoClient(settings)

    return AppContainer(
        settings=settings,
        db=db,
        audit=audit,
        identities=IdentityResolver(settings),
        sessions=SessionStore(
            admin_unlock_seconds=settings.admin_session_minutes * 60,
            admin_cooldown_seconds=settings.admin_cooldown_minutes * 60,
            test_session_seconds=settings.test_session_minutes * 60,
        ),
        reveal=reveal,
        trace_store=trace_store,
        object_store=object_store,
        display_tz=resolve_timezone(settings.display_timezone),
        sso=sso_client,
    )


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class AdminLoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=400)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_https(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        proto = forwarded.split(",")[0].strip().lower()
        if proto:
            return proto == "https"
    return request.url.scheme == "https"


def _cookie_security(request: Request) -> dict:
    return {"httponly": True, "samesite": "lax", "secure": _is_https(request)}


def search_sessions(
    container: AppContainer,
    *,
    q: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
    agent: str | None = None,
    include_demo: bool = False,
) -> tuple[list[dict], int, bool, bool]:
    """Filter sessions for both the JSON API and the console page.

    Returns ``(rows, total, demo_hidden, browse_blocked)``.

    * The demo dataset disappears as soon as a real conversation exists, so a
      seeded environment cannot masquerade as production data.
    * ``browse_blocked`` becomes True when more than ``MAX_VISIBLE`` sessions
      exist and no filter was supplied: the console then asks for a search
      instead of paging through an unbounded list.
    """
    from openagent_audit.services.demo_seed import is_demo_session, purge_demo_data

    # Once real conversations exist the seeded samples are removed from the
    # store, not merely filtered out: after connecting to OpenAgent the console
    # must show platform data only, with nothing left to mistake for it.
    purge_demo_data(container.trace_store)

    sessions = (
        container.trace_store.list_sessions()
        if hasattr(container.trace_store, "list_sessions")
        else []
    )

    has_real = any(not is_demo_session(s.get("session_id", "")) for s in sessions)
    demo_hidden = has_real and not include_demo
    if demo_hidden:
        sessions = [s for s in sessions if not is_demo_session(s.get("session_id", ""))]

    def sort_key(session: dict):
        return session.get("last_ts") or session.get("first_ts") or datetime.min.replace(
            tzinfo=timezone.utc
        )

    sessions = sorted(sessions, key=sort_key, reverse=True)

    def in_scope(session: dict) -> bool:
        moment = sort_key(session)
        if from_ts:
            start, _ = display_range_to_utc(from_ts, None, container.display_tz)
            if start and moment < start:
                return False
        if to_ts:
            _, end = display_range_to_utc(None, to_ts, container.display_tz)
            if end and moment >= end:
                return False
        return True

    filtered_any = False
    if from_ts or to_ts:
        sessions = [s for s in sessions if in_scope(s)]
        filtered_any = True
    if agent:
        needle = agent.lower()
        sessions = [s for s in sessions if any(needle in str(t).lower() for t in s.get("agent_tags", []))]
        filtered_any = True
    if q:
        needle = q.lower()
        sessions = [
            s
            for s in sessions
            if needle in str(s.get("session_id", "")).lower()
            or needle in str(s.get("user_id", "")).lower()
            or any(needle in str(t).lower() for t in s.get("agent_tags", []))
        ]
        filtered_any = True

    total = len(sessions)
    browse_blocked = not filtered_any and total > MAX_VISIBLE
    return sessions, total, demo_hidden, browse_blocked


def _pager_query(**params) -> str:
    """Serialise the active filters for pager links (page is appended later)."""
    from urllib.parse import urlencode

    clean = {k: v for k, v in params.items() if v}
    return ("&" + urlencode(clean)) if clean else ""


def _cooldown_message(seconds: int) -> str:
    """Human-readable wait time for the administrator login form."""
    minutes, secs = divmod(max(seconds, 0), 60)
    if minutes and secs:
        wait = f"{minutes} 分 {secs} 秒"
    elif minutes:
        wait = f"{minutes} 分钟"
    else:
        wait = f"{secs} 秒"
    return f"该账号刚刚结束管理员会话，需等待 {wait} 后才能再次登录。"


def _admin_credentials_match(settings: Settings, username: str, password: str) -> bool:
    """Check the administrator credentials against whichever form is configured.

    A hash (``AUDIT_ADMIN_PASSWORD_HASH``) takes precedence over a plaintext
    password (``AUDIT_ADMIN_PASSWORD``, for local runs). The username is always
    compared in constant time, and an unknown account is still compared so the
    response time does not disclose whether the account exists.
    """
    import hmac

    username_ok = hmac.compare_digest(username or "", settings.admin_username)

    if settings.admin_password_hash:
        password_ok = verify_password_hash(settings.admin_password_hash, password or "")
    elif settings.admin_password:
        password_ok = hmac.compare_digest(password or "", settings.admin_password)
    else:
        # No credential configured: the administrator login is closed rather
        # than open. An empty password must never unlock decryption.
        return False

    return username_ok and password_ok


def display_range_to_utc(
    from_ts: str | None,
    to_ts: str | None,
    tz,
) -> tuple[datetime | None, datetime | None]:
    """Interpret operator-entered times in the display zone, return UTC bounds.

    An operator typing "2026-11-06 09:00" means nine in the morning *their*
    time. Comparing that string directly against stored UTC would silently
    query an eight-hour window in the wrong place, so the naive value is
    attached to the display zone first and then converted.
    """
    def parse(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail="时间格式无效，请使用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM"
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=tz)
        return parsed.astimezone(timezone.utc)

    return parse(from_ts), parse(to_ts)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


def create_audit_app(container: AppContainer) -> FastAPI:
    app = FastAPI(title="openagent-audit audit-api", docs_url=None, redoc_url=None)
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    settings = container.settings
    # Entries are stored in UTC; pages render them in this zone and label it.
    display_tz = resolve_timezone(settings.display_timezone)
    display_zone_label = zone_label(display_tz)

    # -- identity ---------------------------------------------------------

    def resolve_principal(request: Request) -> Principal | None:
        """The effective identity for this request.

        A session cookie is authoritative (it carries any admin unlock); the
        identity cookie lets API clients present a platform token directly.
        """
        session = container.sessions.get(request.cookies.get(_SESSION_COOKIE))
        if session is not None:
            return session.principal

        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header[:7].lower() == "bearer " else None
        if token is None:
            token = request.cookies.get(_IDENTITY_COOKIE)
        return container.identities.resolve(token)

    def require(request: Request, permission: str) -> Principal:
        return check(resolve_principal(request), permission)

    def log_view(principal: Principal, action: str, object_type: str, object_id: str) -> None:
        container.audit.append(
            actor=principal.username,
            role=principal.role,
            action=action,
            object_type=object_type,
            object_id=object_id,
        )

    def page_args(page: int, page_size: int | None = None) -> tuple[int, int]:
        """Clamp paging to the console policy: 10 per page, at most 20 pages.

        ``page_size`` from the caller is accepted for API compatibility but is
        confined to the policy, so a client cannot ask for a 10 000-row page.
        """
        clamped_page = min(max(page, 1), MAX_PAGES)
        clamped_size = min(max(page_size or PAGE_SIZE, 1), PAGE_SIZE)
        return clamped_page, clamped_size

    def paging_meta(total: int, page: int, size: int) -> dict:
        """Paging envelope shared by every list endpoint and page."""
        visible = min(total, MAX_VISIBLE)
        total_pages = max(1, (visible + size - 1) // size)
        return {
            "total": total,
            "page": page,
            "page_size": size,
            "total_pages": total_pages,
            "max_pages": MAX_PAGES,
            "max_visible": MAX_VISIBLE,
            # True when older rows exist but are out of reach without a search.
            "truncated": total > MAX_VISIBLE,
        }

    def time_range(from_ts: str | None, to_ts: str | None):
        def parse(value: str | None, name: str) -> datetime | None:
            if not value:
                return None
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                raise HTTPException(
                    status_code=422, detail=f"{name} 不是合法的 ISO-8601 时间"
                ) from None

        return parse(from_ts, "from_ts"), parse(to_ts, "to_ts")

    def render(request: Request, template: str, **ctx) -> Response:
        ctx.setdefault("principal", resolve_principal(request))
        status_code = ctx.pop("status_code", 200)
        ctx["request"] = request
        ctx["role_labels"] = ROLE_LABELS
        ctx["display_zone_label"] = display_zone_label
        ctx["admin_unlock_minutes"] = settings.admin_session_minutes
        ctx["admin_cooldown_minutes"] = settings.admin_cooldown_minutes
        return templates.TemplateResponse(request, template, ctx, status_code=status_code)

    # -- template filters --------------------------------------------------

    def entmark(value: str, revealable: bool = False) -> str:
        """Render masked entities; when revealable, wrap them in a click target."""
        escaped = html.escape(value or "")
        if not escaped:
            return ""

        def replace(match: re.Match) -> str:
            entity_type, entity_id, mask = match.group(1), match.group(2), match.group(3)
            label = html.escape(f"{entity_type} {mask}".strip())
            if not revealable:
                return f'<span class="ent">{label}</span>'
            return (
                f'<button type="button" class="ent ent-click" '
                f'data-entity-id="{html.escape(entity_id)}" '
                f'data-entity-type="{html.escape(entity_type)}" '
                f'title="点击查看原文（将记录到审计日志）">{label}</button>'
            )

        return _ENTITY_RE.sub(replace, escaped)

    templates.env.filters["entmark"] = entmark

    def tsformat(value, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Render a stored (UTC) timestamp in the deployment's display zone.

        Storage stays UTC; only the rendering shifts. Leaving this as raw UTC
        would show a 13:37 Beijing event as 05:37, an eight-hour error that is
        hard to notice and easy to misread during an investigation.
        """
        if value is None:
            return "-"
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return value
        try:
            return to_display(value, display_tz).strftime(fmt)
        except (AttributeError, ValueError):
            return str(value)

    templates.env.filters["tsformat"] = tsformat

    # -- health ------------------------------------------------------------

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "service": "audit-api", "env": settings.env}

    # -- identity ----------------------------------------------------------

    @app.get("/v1/me")
    def me(request: Request):
        principal = resolve_principal(request)
        if principal is None:
            raise AuthenticationError("认证失败：请先登录。")
        return {
            "username": principal.username,
            "role": principal.role,
            "is_admin": principal.is_admin,
            "role_label": ROLE_LABELS.get(principal.role, principal.role),
        }

    @app.post("/v1/admin/login")
    def admin_login(body: AdminLoginBody, request: Request):
        """Step up to administrator inside the current session.

        The credentials are checked here, not in the browser, and the unlock is
        bound to this session so the audit log can attribute every reveal to
        the person who was signed in.
        """
        session_token = request.cookies.get(_SESSION_COOKIE)
        session = container.sessions.get(session_token)
        if session is None:
            raise AuthenticationError("认证失败：请先进入审计系统，再登录管理员账号。")

        waiting = container.sessions.admin_cooldown_remaining(session.principal.username)
        if waiting > 0:
            container.audit.append(
                actor=session.principal.username,
                role=session.principal.role,
                action="ADMIN_LOGIN_BLOCKED",
                object_type="admin",
                object_id=body.username[:200],
                detail={
                    "session_user": session.principal.username,
                    "retry_after_seconds": waiting,
                    "reason": "cooldown",
                },
            )
            raise HTTPException(status_code=429, detail=_cooldown_message(waiting))

        if not _admin_credentials_match(settings, body.username, body.password):
            container.audit.append(
                actor=session.principal.username,
                role=session.principal.role,
                action="ADMIN_LOGIN_FAILED",
                object_type="admin",
                object_id=body.username[:200],
                detail={"session_user": session.principal.username},
            )
            raise AuthenticationError("管理员账号或密码错误。")

        upgraded = container.sessions.grant_admin(session_token)  # type: ignore[arg-type]
        if upgraded is None:
            if session.principal.ephemeral:
                container.audit.append(
                    actor=session.principal.username,
                    role=session.principal.role,
                    action="ADMIN_LOGIN_REFUSED",
                    object_type="admin",
                    object_id=body.username[:200],
                    detail={
                        "session_user": session.principal.username,
                        "reason": "test_account",
                    },
                )
                raise HTTPException(
                    status_code=403,
                    detail="测试账号不能登录管理员。请使用 OpenAgent 正常登录的用户。",
                )
            waiting = container.sessions.admin_cooldown_remaining(session.principal.username)
            raise HTTPException(status_code=429, detail=_cooldown_message(waiting))

        container.audit.append(
            actor=settings.admin_username,
            role=ROLE_ADMIN,
            action="ADMIN_LOGIN",
            object_type="admin",
            object_id=settings.admin_username,
            detail={
                "session_user": session.principal.username,
                "unlock_minutes": settings.admin_session_minutes,
                "cooldown_minutes": settings.admin_cooldown_minutes,
            },
        )
        return {
            "username": upgraded.principal.username,
            "role": upgraded.principal.role,
            "is_admin": True,
            "expires_in": container.sessions.admin_unlock_seconds,
        }

    @app.post("/v1/admin/logout")
    def admin_logout(request: Request):
        session_token = request.cookies.get(_SESSION_COOKIE)
        session = container.sessions.get(session_token)
        if session is None:
            raise AuthenticationError("认证失败：请先登录。")
        container.sessions.revoke_admin(session_token)  # type: ignore[arg-type]
        container.audit.append(
            actor=session.principal.username,
            role=session.principal.role,
            action="ADMIN_LOGOUT",
            object_type="admin",
            object_id=settings.admin_username,
            detail={"session_user": session.principal.username},
        )
        return {"role": ROLE_USER}

    # -- reading -----------------------------------------------------------

    @app.get("/v1/sessions")
    def list_sessions(
        request: Request,
        page: int = 1,
        page_size: int = PAGE_SIZE,
        q: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        agent: str | None = None,
        include_demo: bool = False,
    ):
        require(request, VIEW_MASKED)
        page, size = page_args(page, page_size)
        rows, total, demo_hidden, browse_blocked = search_sessions(
            container,
            q=q,
            from_ts=from_ts,
            to_ts=to_ts,
            agent=agent,
            include_demo=include_demo,
        )
        return {
            "sessions": rows[(page - 1) * size : (page - 1) * size + size],
            **paging_meta(total, page, size),
            "browse_blocked": browse_blocked,
            "browse_threshold": MAX_VISIBLE,
            "demo_hidden": demo_hidden,
            "display_zone_label": display_zone_label,
        }

    @app.get("/v1/sessions/{session_id}")
    def get_session(
        session_id: str, request: Request, from_ts: str | None = None, to_ts: str | None = None
    ):
        principal = require(request, VIEW_MASKED)
        start, end = time_range(from_ts, to_ts)
        traces = container.trace_store.list_traces(
            session_id=session_id, from_ts=start, to_ts=end, with_observations=True
        )
        if not traces:
            raise HTTPException(status_code=404, detail="会话不存在")
        log_view(principal, "SESSION_VIEWED", "session", session_id)
        return {"session_id": session_id, "traces": [_trace_dict(t) for t in traces]}

    @app.get("/v1/traces")
    def list_traces(
        request: Request,
        session_id: str | None = None,
        user_id: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
    ):
        require(request, VIEW_MASKED)
        start, end = time_range(from_ts, to_ts)
        traces = container.trace_store.list_traces(
            session_id=session_id, user_id=user_id, from_ts=start, to_ts=end
        )
        return {"traces": [_trace_summary(t) for t in traces]}

    @app.get("/v1/audit-log")
    def audit_log(
        request: Request,
        page: int = 1,
        page_size: int = PAGE_SIZE,
        q: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        role: str | None = None,
        action: str | None = None,
        verify: bool = False,
    ):
        """Searchable audit log.

        Timestamps are filtered in the console's display timezone (what the
        operator typed) and converted to UTC for the query, because that is how
        entries are stored. Entries come back with both the UTC value and the
        display value so a caller never has to guess.
        """
        require(request, VIEW_AUDIT_LOG)
        page, size = page_args(page, page_size)
        start, end = display_range_to_utc(from_ts, to_ts, display_tz)

        entries = container.db.list_audit(
            limit=size,
            q=q,
            offset=(page - 1) * size,
            from_ts=start,
            to_ts=end,
            role=role,
            action=action,
        )
        total = container.db.count_audit_entries(
            q=q, from_ts=start, to_ts=end, role=role, action=action
        )
        payload = {
            "entries": [
                {
                    "seq": e.seq,
                    "ts": e.ts.isoformat(),
                    "ts_display": to_display(e.ts, display_tz).isoformat(),
                    "actor": e.actor,
                    "role": e.role,
                    "action": e.action,
                    "object_type": e.object_type,
                    "object_id": e.object_id,
                    "detail": e.detail,
                }
                for e in entries
            ],
            **paging_meta(total, page, size),
            "display_timezone": settings.display_timezone,
            "display_zone_label": display_zone_label,
        }
        if verify:
            payload["verification"] = container.audit.verify()
        return payload

    # -- reveal ------------------------------------------------------------

    @app.post("/v1/reveal/{entity_id}")
    def reveal_entity(entity_id: str, request: Request):
        """Decrypt one masked value. Administrator only; always logged."""
        principal = require(request, "reveal")
        try:
            result = container.reveal.reveal_entity(
                entity_id,
                actor=principal.username,
                role=principal.role,
                session_user=principal.username,
            )
        except RevealError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
        container.drop_monitor.record_restore_revealed()
        return {
            "entity_id": result.object_id,
            "entity_type": result.entity_type,
            "plaintext": result.plaintext,
        }

    @app.get("/internal/metrics")
    def metrics(request: Request):
        require(request, VIEW_METRICS)
        return {
            "drops": container.drop_monitor.snapshot(),
            "inventory": _build_inventory(container),
            "config": {
                "trace_retention_days": settings.trace_retention_days,
                "audit_archive_after_days": settings.audit_archive_after_days,
                "trace_store": settings.trace_store,
                "pii_backend": settings.pii_backend,
                "admin_session_minutes": settings.admin_session_minutes,
            },
        }

    @app.get("/internal/metrics/prometheus")
    def metrics_prometheus(request: Request):
        require(request, VIEW_METRICS)
        snap = container.drop_monitor.snapshot()
        lines = [
            f"# TYPE openagent_audit_{name} gauge\nopenagent_audit_{name} {value}"
            for name, value in snap.items()
            if isinstance(value, (int, float))
        ]
        return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    # -- web UI ------------------------------------------------------------

    @app.get("/ui", response_class=HTMLResponse)
    def ui_index(request: Request):
        return RedirectResponse("/ui/sessions", status_code=302)

    @app.get("/ui/login", response_class=HTMLResponse)
    async def ui_login(request: Request):
        """Login page: enterprise SSO as the primary path, test account as the fallback."""
        return render(
            request,
            "login.html",
            error=None,
            test_username=settings.test_username,
            show_test_login=False,
            sso_enabled=bool(container.sso and container.sso.is_enabled()),
        )

    # Generated once per process. The start route signs the state and the
    # callback verifies it, so a per-call value would make every login fail.
    # Across restarts an in-flight login fails and the user retries - the
    # safe default. AUDIT_SSO_STATE_SECRET makes it survive restarts.
    _state_secret = os.environ.get(_SSO_STATE_SECRET_ENV) or secrets.token_urlsafe(32)

    def _sso_state_secret() -> str:
        return _state_secret

    @app.get("/ui/login/sso/start")
    async def ui_sso_start(request: Request):
        """Begin the SSO round trip: state cookie + 302 to the authorize URL."""
        if container.sso is None or not container.sso.is_enabled():
            return RedirectResponse("/ui/login", status_code=302)

        base_url = str(request.base_url).rstrip("/")
        state_secret = _sso_state_secret()
        try:
            url, state, verifier = await container.sso.authorization_url(base_url)
        except SsoError as exc:
            return render(
                request,
                "login.html",
                error=str(exc),
                test_username=settings.test_username,
                show_test_login=True,
                status_code=502,
            )

        response = RedirectResponse(url, status_code=302)
        # Signed, short-lived cookies bind the round trip to this browser.
        # The callback verifies the returned state against the signed value,
        # which is the CSRF defence; the verifier completes PKCE.
        response.set_cookie(
            _SSO_STATE_COOKIE,
            sign_state_cookie(state, state_secret),
            max_age=600,
            **_cookie_security(request),
        )
        response.set_cookie(
            "openagent_audit_sso_pkce",
            verifier,
            max_age=600,
            **_cookie_security(request),
        )
        return response

    @app.get("/ui/login/sso/callback")
    async def ui_sso_callback(request: Request):
        """Finish the SSO round trip: verify state, exchange code, sign in."""
        state_cookie = request.cookies.get(_SSO_STATE_COOKIE)
        pkce_verifier = request.cookies.get("openagent_audit_sso_pkce")
        if not state_cookie or not pkce_verifier:
            return render(
                request,
                "login.html",
                error="SSO 登录会话缺失，请重新点击「用企业账号登录」。",
                test_username=settings.test_username,
                show_test_login=True,
                status_code=400,
            )

        query_state = request.query_params.get("state")
        code = request.query_params.get("code")
        if not query_state or not code:
            error = request.query_params.get("error_description") or request.query_params.get("error")
            return render(
                request,
                "login.html",
                error=f"SSO 登录被取消或失败：{error or '未知原因'}。",
                test_username=settings.test_username,
                show_test_login=True,
                status_code=401,
            )

        try:
            expected_state = verify_state_cookie(state_cookie, _sso_state_secret())
        except SsoError as exc:
            return render(
                request,
                "login.html",
                error=str(exc),
                test_username=settings.test_username,
                show_test_login=True,
                status_code=400,
            )

        import hmac as _hmac

        if not _hmac.compare_digest(query_state, expected_state):
            return render(
                request,
                "login.html",
                error="SSO 回调校验失败（state 不匹配），请重新登录。",
                test_username=settings.test_username,
                show_test_login=True,
                status_code=400,
            )

        base_url = str(request.base_url).rstrip("/")
        try:
            identity = await container.sso.exchange_and_identify(
                base_url, code, pkce_verifier)
        except SsoError as exc:
            return render(
                request,
                "login.html",
                error=str(exc),
                test_username=settings.test_username,
                show_test_login=True,
                status_code=502,
            )

        principal = Principal(username=identity.username, role=ROLE_USER)
        session = container.sessions.create(principal)
        container.audit.append(
            actor=principal.username,
            role=principal.role,
            action="LOGIN",
            object_type="session",
            object_id=principal.username,
            detail={"via": "sso", "ephemeral": False},
        )
        response = RedirectResponse("/ui/sessions", status_code=302)
        response.set_cookie(_SESSION_COOKIE, session.token, **_cookie_security(request))
        # The SSO round-trip cookies have served their purpose.
        response.delete_cookie(_SSO_STATE_COOKIE, secure=_is_https(request))
        response.delete_cookie("openagent_audit_sso_pkce", secure=_is_https(request))
        return response

    @app.post("/ui/login")
    async def ui_login_post(
        request: Request,
        token: str = Form(""),
        username: str = Form(""),
        password: str = Form(""),
    ):
        """Manual sign-in paths.

        The primary path is the SSO round trip above. This endpoint handles the
        two manual fallbacks: pasting a platform token, and the local test
        account (an ordinary user that can never reach the admin role).
        """
        principal: Principal | None = None
        via = ""

        if token.strip():
            principal = container.identities.resolve(token.strip())
            via = settings.auth_provider

        if principal is None and username.strip():
            principal = container.identities.resolve_test_account(username.strip(), password)
            if principal is not None:
                via = "test-account"

        if principal is None:
            if username.strip() and not password:
                message = "请输入测试账号的密码。"
            elif username.strip() or password:
                if not settings.test_username or not settings.test_password:
                    message = (
                        "测试账号未启用（AUDIT_TEST_USERNAME/AUDIT_TEST_PASSWORD 为空）。"
                        "请改用企业账号登录。"
                    )
                else:
                    message = "测试账号或密码不正确。"
            elif token.strip():
                message = "OpenAgent 令牌无效，或平台暂时不可达。"
            else:
                message = "请使用企业账号登录，或使用测试账号。"
            return render(
                request,
                "login.html",
                error=message,
                test_username=settings.test_username,
                show_test_login=True,
                sso_enabled=bool(container.sso and container.sso.is_enabled()),
                status_code=401,
            )

        session = container.sessions.create(principal)
        container.audit.append(
            actor=principal.username,
            role=principal.role,
            action="LOGIN",
            object_type="session",
            object_id=principal.username,
            detail={"via": via, "ephemeral": principal.ephemeral},
        )
        secure = _cookie_security(request)
        response = RedirectResponse("/ui/sessions", status_code=302)
        response.set_cookie(_SESSION_COOKIE, session.token, **secure)
        if token.strip():
            # Kept so API clients can reuse the same browser session.
            response.set_cookie(_IDENTITY_COOKIE, token.strip(), **secure)
        return response

    @app.post("/ui/logout")
    def ui_logout(request: Request):
        container.sessions.drop(request.cookies.get(_SESSION_COOKIE))
        response = RedirectResponse("/ui/login", status_code=302)
        response.delete_cookie(_SESSION_COOKIE, secure=_is_https(request))
        response.delete_cookie(_IDENTITY_COOKIE, secure=_is_https(request))
        return response

    def ui_session(request: Request) -> tuple[Principal, str | None]:
        """Like ``require``, but redirects a browser to the login page."""
        try:
            return require(request, VIEW_MASKED), request.cookies.get(_SESSION_COOKIE)
        except AuthenticationError:
            raise HTTPException(status_code=302, headers={"Location": "/ui/login"}) from None
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from None

    @app.post("/ui/admin/login")
    def ui_admin_login(
        request: Request, username: str = Form(...), password: str = Form(...)
    ):
        """Administrator step-up from the console header."""
        session_token = request.cookies.get(_SESSION_COOKIE)
        session = container.sessions.get(session_token)
        if session is None:
            return RedirectResponse("/ui/login", status_code=302)

        # Cooldown is checked before the password so a locked-out account
        # cannot use the form as a credential oracle.
        waiting = container.sessions.admin_cooldown_remaining(session.principal.username)
        if waiting > 0:
            container.audit.append(
                actor=session.principal.username,
                role=session.principal.role,
                action="ADMIN_LOGIN_BLOCKED",
                object_type="admin",
                object_id=username[:200],
                detail={
                    "session_user": session.principal.username,
                    "retry_after_seconds": waiting,
                    "reason": "cooldown",
                },
            )
            return render(
                request,
                "admin_login.html",
                error=_cooldown_message(waiting),
                session_user=session.principal.username,
                wait_seconds=waiting,
                status_code=429,
            )

        if not _admin_credentials_match(settings, username, password):
            container.audit.append(
                actor=session.principal.username,
                role=session.principal.role,
                action="ADMIN_LOGIN_FAILED",
                object_type="admin",
                object_id=username[:200],
                detail={"session_user": session.principal.username},
            )
            return render(
                request,
                "admin_login.html",
                error="管理员账号或密码错误。",
                session_user=session.principal.username,
                status_code=401,
            )

        upgraded = container.sessions.grant_admin(session_token)  # type: ignore[arg-type]
        if upgraded is None:
            if session.principal.ephemeral:
                container.audit.append(
                    actor=session.principal.username,
                    role=session.principal.role,
                    action="ADMIN_LOGIN_REFUSED",
                    object_type="admin",
                    object_id=username[:200],
                    detail={"session_user": session.principal.username, "reason": "test_account"},
                )
                return render(
                    request,
                    "admin_login.html",
                    error="测试账号不能登录管理员。请使用 OpenAgent 正常登录的用户。",
                    session_user=session.principal.username,
                    status_code=403,
                )
            # lost a race with another tab; still cooling down
            waiting = container.sessions.admin_cooldown_remaining(session.principal.username)
            return render(
                request,
                "admin_login.html",
                error=_cooldown_message(waiting),
                session_user=session.principal.username,
                wait_seconds=waiting,
                status_code=429,
            )

        container.audit.append(
            actor=settings.admin_username,
            role=ROLE_ADMIN,
            action="ADMIN_LOGIN",
            object_type="admin",
            object_id=settings.admin_username,
            detail={
                "session_user": session.principal.username,
                "unlock_minutes": settings.admin_session_minutes,
                "cooldown_minutes": settings.admin_cooldown_minutes,
            },
        )
        return RedirectResponse("/ui/sessions", status_code=302)

    @app.get("/ui/admin/login", response_class=HTMLResponse)
    def ui_admin_login_page(request: Request):
        session = container.sessions.get(request.cookies.get(_SESSION_COOKIE))
        if session is None:
            return RedirectResponse("/ui/login", status_code=302)
        if not session.principal.can_step_up_to_admin:
            # The test account has no administrator entry point; do not render
            # a form it could never successfully submit.
            return render(
                request,
                "admin_login.html",
                error="测试账号不能登录管理员。请使用 OpenAgent 正常登录的用户。",
                session_user=session.principal.username,
                status_code=403,
            )
        return render(
            request,
            "admin_login.html",
            error=None,
            session_user=session.principal.username,
        )

    @app.post("/ui/admin/logout")
    def ui_admin_logout(request: Request):
        session_token = request.cookies.get(_SESSION_COOKIE)
        session = container.sessions.get(session_token)
        if session is not None:
            container.sessions.revoke_admin(session_token)  # type: ignore[arg-type]
            container.audit.append(
                actor=session.principal.username,
                role=session.principal.role,
                action="ADMIN_LOGOUT",
                object_type="admin",
                object_id=settings.admin_username,
                detail={"session_user": session.principal.username},
            )
        return RedirectResponse("/ui/sessions", status_code=302)

    @app.get("/ui/sessions", response_class=HTMLResponse)
    def ui_sessions(
        request: Request,
        q: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        agent: str | None = None,
        page: int = 1,
    ):
        principal, _ = ui_session(request)
        page, size = page_args(page)
        rows, total, demo_hidden, browse_blocked = search_sessions(
            container, q=q, from_ts=from_ts, to_ts=to_ts, agent=agent
        )
        paged = rows[(page - 1) * size : (page - 1) * size + size]
        meta = paging_meta(total, page, size)
        return render(
            request,
            "sessions.html",
            principal=principal,
            sessions=paged,
            **meta,
            browse_blocked=browse_blocked,
            demo_hidden=demo_hidden,
            q=q or "",
            from_ts=from_ts or "",
            to_ts=to_ts or "",
            agent=agent or "",
            pager_base="/ui/sessions?",
            pager_query=_pager_query(q=q, from_ts=from_ts, to_ts=to_ts, agent=agent),
        )

    @app.get("/ui/sessions/{session_id}", response_class=HTMLResponse)
    def ui_session_detail(
        session_id: str, request: Request, from_ts: str | None = None, to_ts: str | None = None
    ):
        principal, _ = ui_session(request)
        start, end = time_range(from_ts, to_ts)
        traces = container.trace_store.list_traces(
            session_id=session_id, from_ts=start, to_ts=end, with_observations=True
        )
        if not traces:
            raise HTTPException(status_code=404, detail="会话不存在")
        log_view(principal, "SESSION_VIEWED", "session", session_id)
        return render(
            request,
            "session_detail.html",
            principal=principal,
            session_id=session_id,
            traces=[_trace_dict(t) for t in traces],
            revealable=principal.is_admin,
        )

    @app.get("/ui/audit-log", response_class=HTMLResponse)
    def ui_audit_log(
        request: Request,
        q: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        role: str | None = None,
        action: str | None = None,
        page: int = 1,
        verify: bool = False,
    ):
        principal, _ = ui_session(request)
        check(principal, VIEW_AUDIT_LOG)
        page, size = page_args(page)
        start_utc, end_utc = display_range_to_utc(from_ts, to_ts, display_tz)

        entries = container.db.list_audit(
            limit=size,
            q=q,
            offset=(page - 1) * size,
            from_ts=start_utc,
            to_ts=end_utc,
            role=role,
            action=action,
        )
        total = container.db.count_audit_entries(
            q=q, from_ts=start_utc, to_ts=end_utc, role=role, action=action
        )
        meta = paging_meta(total, page, size)
        return render(
            request,
            "audit_log.html",
            principal=principal,
            entries=entries,
            verification=container.audit.verify() if verify or page == 1 else None,
            role=role or "",
            action=action or "",
            q=q or "",
            from_ts=from_ts or "",
            to_ts=to_ts or "",
            pager_base="/ui/audit-log?",
            pager_query=_pager_query(
                q=q, from_ts=from_ts, to_ts=to_ts, role=role, action=action
            ),
            **meta,
        )

        # -- error mapping -----------------------------------------------------

    @app.exception_handler(AuthenticationError)
    def _auth_error(request: Request, exc: AuthenticationError):
        return JSONResponse({"detail": str(exc)}, status_code=401)

    @app.exception_handler(AuthorizationError)
    def _perm_error(request: Request, exc: AuthorizationError):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    return app


def create_app(settings: Settings | None = None) -> FastAPI:
    """Entry point used by ``uvicorn openagent_audit.services.audit_api:create_app``."""
    return create_audit_app(build_container(settings or Settings.from_env()))


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _trace_summary(t) -> dict:
    return {
        "trace_id": t.trace_id,
        "session_id": t.session_id,
        "user_id": t.user_id,
        "name": t.name,
        "timestamp": str(t.timestamp),
    }


def _build_inventory(container: AppContainer) -> dict:
    inventory: dict = {}
    try:
        inventory["vault_entities"] = container.db.count_entities()
    except Exception:  # noqa: BLE001 - informational only
        inventory["vault_entities"] = None
    try:
        inventory["audit_entries"] = container.db.count_audit_entries()
    except Exception:  # noqa: BLE001
        inventory["audit_entries"] = None
    try:
        sessions = (
            container.trace_store.list_sessions()
            if hasattr(container.trace_store, "list_sessions")
            else []
        )
        inventory["sessions"] = len(sessions)
        inventory["traces"] = sum(s.get("trace_count", 0) for s in sessions)
    except Exception:  # noqa: BLE001
        inventory["sessions"] = None
        inventory["traces"] = None
    return inventory


def _trace_dict(t) -> dict:
    return {
        "trace_id": t.trace_id,
        "session_id": t.session_id,
        "user_id": t.user_id,
        "agent_tag": t.agent_tag,
        "name": t.name,
        "timestamp": t.timestamp.isoformat(),
        "observations": [
            {
                "id": o.id,
                "type": o.type,
                "name": o.name,
                "input": o.input,
                "output": o.output,
                "model": o.model,
                "usage": o.usage,
                "latency_ms": o.latency_ms,
                "metadata": o.metadata,
            }
            for o in t.observations
        ],
    }
"""audit-api + audit-web — the read side (proposal §08 ② 展示 / §11.4).

- ``/v1/*``  : JSON API for the audit plane (bearer-token auth, RBAC)
- ``/ui/*``  : server-rendered audit-web (login, sessions, restore requests,
               audit log)

The read side never holds the private key and never touches ciphertext:
masked trace data comes from the trace store, and plaintext only ever flows
through decrypt-svc after an approved restore request.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from openagent_audit.bootstrap import build_cipher, build_db, build_key_provider, build_loki, build_object_store
from openagent_audit.config import Settings
from openagent_audit.services.auth import (
    AuthenticationError,
    Authenticator,
    AuthorizationError,
    Principal,
    VIEW_AUDIT_LOG,
    VIEW_MASKED,
    VIEW_METRICS,
    MANAGE_RESTORE,
    load_authenticator,
)
from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.services.decrypt_client import HttpDecryptService, InProcessDecryptService
from openagent_audit.services.restore_service import RestoreError, RestoreService
from openagent_audit.tracing.drop_monitor import DropMonitor
from openagent_audit.tracing.trace_store import LangfuseTraceStore, LocalTraceStore

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_COOKIE_NAME = "openagent_audit_session"

# Search-first: unconditional browsing of the session list is allowed only up
# to this many sessions; beyond it the UI demands a search/filter (proposal
# review: 数万条会话下"无条件浏览"不是可用的审计工作流).
BROWSE_THRESHOLD = 200

_ENT_RE = re.compile(r"(⟦[^⟧]*⟧)")


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------


@dataclass
class AppContainer:
    settings: Settings
    db: object
    audit: AuditLogService
    restore: RestoreService
    authenticator: Authenticator
    trace_store: object
    object_store: object | None
    drop_monitor: DropMonitor = field(default_factory=DropMonitor)
    pipeline_stats: dict = field(default_factory=dict)


def build_container(settings: Settings) -> AppContainer:
    db = build_db(settings)
    audit = AuditLogService(db, build_loki(settings))
    object_store = build_object_store(settings)

    # decrypt path: separate decrypt-svc when configured, else in-process
    if settings.decrypt_svc_url:
        decrypt = HttpDecryptService(settings.decrypt_svc_url, settings.service_token)
    else:
        key_provider = build_key_provider(settings)
        cipher = build_cipher(settings, key_provider)
        decrypt = InProcessDecryptService(
            cipher=cipher, key_provider=key_provider, vault=db, object_store=object_store, audit=audit
        )

    restore = RestoreService(
        db,
        audit,
        decrypt,
        reveal_ttl_minutes=settings.reveal_ttl_minutes,
    )

    # trace reads
    if settings.trace_store == "langfuse":
        trace_store = LangfuseTraceStore(
            settings.langfuse_host, settings.langfuse_public_key, settings.langfuse_secret_key
        )
    else:
        trace_store = LocalTraceStore()
        if settings.demo_seed:
            from openagent_audit.services.demo_seed import seed_demo_data

            seed_demo_data(settings, trace_store, db)

    return AppContainer(
        settings=settings,
        db=db,
        audit=audit,
        restore=restore,
        authenticator=load_authenticator(settings),
        trace_store=trace_store,
        object_store=object_store,
    )


# ---------------------------------------------------------------------------
# Request bodies (module level so FastAPI can resolve postponed annotations)
# ---------------------------------------------------------------------------


class RestoreRequestBody(BaseModel):
    object_type: str = Field(pattern="^(entity|media)$")
    object_id: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=2000)
    trace_id: str | None = None
    session_id: str | None = None


class DecisionBody(BaseModel):
    comment: str | None = None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------


def _bearer(request: Request) -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer ") :].strip()
    return request.cookies.get(_COOKIE_NAME)


def create_audit_app(container: AppContainer) -> FastAPI:
    app = FastAPI(title="openagent-audit audit-api", docs_url=None, redoc_url=None)
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    def principal_of(request: Request, permission: str) -> Principal:
        token = _bearer(request)
        return container.authenticator.require(token, permission)

    def log_view(principal: Principal, action: str, object_type: str, object_id: str) -> None:
        """Every audit-plane view lands in the append-only audit log
        (proposal §08: 浏览与解密 100% 进入审计日志)."""
        container.audit.append(
            actor=principal.username, role=principal.role,
            action=action, object_type=object_type, object_id=object_id,
        )

    def page_args(page: int, page_size: int, max_size: int = 100) -> tuple[int, int]:
        page = max(page, 1)
        page_size = min(max(page_size, 1), max_size)
        return page, page_size

    def time_range(from_ts: str | None, to_ts: str | None) -> tuple[datetime | None, datetime | None]:
        def parse(value: str | None, name: str) -> datetime | None:
            if not value:
                return None
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                raise HTTPException(
                    status_code=422, detail=f"invalid {name}; expected ISO-8601 timestamp"
                ) from None

        return parse(from_ts, "from"), parse(to_ts, "to")

    def render(request: Request, template: str, **ctx) -> Response:
        principal = container.authenticator.resolve(request.cookies.get(_COOKIE_NAME))
        ctx.setdefault("principal", principal)
        status_code = ctx.pop("status_code", 200)
        ctx["request"] = request
        return templates.TemplateResponse(request, template, ctx, status_code=status_code)

    # -- templates filters ------------------------------------------------------
    def entmark(value: str) -> str:
        escaped = html.escape(value)
        return _ENT_RE.sub(lambda m: f'<span class="ent">{m.group(1)}</span>', escaped)

    templates.env.filters["entmark"] = entmark

    def tsformat(value, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        if value is None:
            return "-"
        if isinstance(value, str):
            try:
                from datetime import datetime as _dt

                value = _dt.fromisoformat(value)
            except ValueError:
                return value
        return value.strftime(fmt)

    templates.env.filters["tsformat"] = tsformat

    # -- health ---------------------------------------------------------------
    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "service": "audit-api", "env": container.settings.env}

    # -- current principal (SPA session bootstrap) ------------------------------
    @app.get("/v1/me")
    def me(request: Request):
        # Identity resolution only — available to every authenticated principal
        # regardless of role, so the SPA can render the role badge.
        token = _bearer(request)
        principal = container.authenticator.resolve(token)
        if principal is None:
            raise AuthenticationError(
                "认证失败：访问令牌缺失或无效（missing or invalid bearer token），请重新登录。"
            )
        return {"username": principal.username, "role": principal.role}

    # -- JSON API ---------------------------------------------------------------
    @app.get("/v1/sessions")
    def list_sessions(
        request: Request,
        page: int = 1,
        page_size: int = 10,
        q: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        agent: str | None = None,
        include_demo: bool = False,
    ):
        """Paged + searchable session list (session_id / user_id / agent tag).

        Search-first at scale: unconditional browsing is only allowed while
        the session total stays at or below ``BROWSE_THRESHOLD``; beyond that
        callers must narrow with ``q`` / ``from_ts`` / ``to_ts`` / ``agent``.
        Sessions are ordered by most recent activity.
        """
        principal_of(request, VIEW_MASKED)
        page, size = page_args(page, page_size)
        start_ts, end_ts = time_range(from_ts, to_ts)
        sessions = (
            container.trace_store.list_sessions()
            if hasattr(container.trace_store, "list_sessions")
            else []
        )
        from openagent_audit.services.demo_seed import is_demo_session

        has_real = any(not is_demo_session(s["session_id"]) for s in sessions)
        if has_real and not include_demo:
            sessions = [s for s in sessions if not is_demo_session(s["session_id"])]

        # newest activity first (auditors almost always want the latest)
        sessions = sorted(
            sessions, key=lambda s: s.get("last_ts") or s.get("first_ts"), reverse=True
        )

        if start_ts:
            sessions = [s for s in sessions if (s.get("last_ts") or s.get("first_ts")) >= start_ts]
        if end_ts:
            sessions = [s for s in sessions if (s.get("last_ts") or s.get("first_ts")) < end_ts]
        if agent:
            needle = agent.lower()
            sessions = [s for s in sessions if any(needle in t.lower() for t in s.get("agent_tags", []))]
        if q:
            needle = q.lower()
            sessions = [
                s for s in sessions
                if needle in s["session_id"].lower()
                or needle in s["user_id"].lower()
                or any(needle in t.lower() for t in s.get("agent_tags", []))
            ]

        total = len(sessions)
        filtered = bool(q or start_ts or end_ts or agent)
        browse_blocked = not filtered and total > BROWSE_THRESHOLD
        if browse_blocked:
            sessions = []
            start = 0
        else:
            start = (page - 1) * size
        return {"sessions": sessions[start : start + size],
                "total": total, "page": page, "page_size": size,
                "demo_hidden": has_real and not include_demo,
                "browse_blocked": browse_blocked,
                "browse_threshold": BROWSE_THRESHOLD}

    @app.get("/v1/sessions/{session_id}")
    def get_session(session_id: str, request: Request, from_ts: str | None = None, to_ts: str | None = None):
        principal = principal_of(request, VIEW_MASKED)
        start, end = time_range(from_ts, to_ts)
        traces = container.trace_store.list_traces(session_id=session_id, from_ts=start, to_ts=end)
        if not traces:
            raise HTTPException(status_code=404, detail="session not found")
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
        """Audit search scope (proposal §08): userId / sessionId / time range
        only — there is deliberately no reverse lookup by phone number or ID
        card (entity ids are random, ciphertext is randomized)."""
        principal_of(request, VIEW_MASKED)
        start, end = time_range(from_ts, to_ts)
        traces = container.trace_store.list_traces(
            session_id=session_id, user_id=user_id, from_ts=start, to_ts=end
        )
        return {"traces": [_trace_summary(t) for t in traces]}

    @app.get("/v1/audit-log")
    def audit_log(
        request: Request,
        page: int = 1,
        page_size: int = 10,
        q: str | None = None,
        verify: bool = False,
    ):
        """Paged audit-log read (search: actor/action/object/role). ``verify``
        runs the full hash-chain check independent of paging."""
        principal_of(request, VIEW_AUDIT_LOG)
        page, size = page_args(page, page_size)
        entries = container.db.list_audit(
            limit=size, q=q, offset=(page - 1) * size
        )
        payload = {
            "entries": [
                {
                    "seq": e.seq, "ts": e.ts.isoformat(), "actor": e.actor, "role": e.role,
                    "action": e.action, "object_type": e.object_type, "object_id": e.object_id,
                    "detail": e.detail,
                }
                for e in entries
            ],
            "total": container.db.count_audit_entries(q=q),
            "page": page,
            "page_size": size,
        }
        if verify:
            payload["verification"] = container.audit.verify()
        return payload

    @app.post("/v1/restore-requests", status_code=201)
    def create_restore_request(body: RestoreRequestBody, request: Request):
        principal = principal_of(request, MANAGE_RESTORE)
        req = container.restore.request(
            actor=principal.username,
            role=principal.role,
            object_type=body.object_type,
            object_id=body.object_id,
            reason=body.reason,
            trace_id=body.trace_id,
            session_id=body.session_id,
        )
        return _request_dict(req)

    @app.get("/v1/restore-requests")
    def list_restore_requests(
        request: Request,
        status: str | None = None,
        page: int = 1,
        page_size: int = 10,
        q: str | None = None,
    ):
        """Paged + searchable restore requests (id/object/reason/people)."""
        principal_of(request, VIEW_AUDIT_LOG)
        from openagent_audit.vault.models import RestoreStatus

        status_filter = RestoreStatus(status) if status else None
        page, size = page_args(page, page_size)
        requests = container.db.list_restore_requests(
            status=status_filter, q=q, limit=size, offset=(page - 1) * size
        )
        return {
            "requests": [_request_dict(r) for r in requests],
            "total": container.db.count_restore_requests(status=status_filter, q=q),
            "page": page,
            "page_size": size,
        }

    @app.get("/v1/restore-requests/{request_id}")
    def get_restore_request(request_id: str, request: Request):
        principal_of(request, VIEW_AUDIT_LOG)
        req = container.restore.get(request_id)
        if req is None:
            raise HTTPException(status_code=404, detail="restore request not found")
        return _request_dict(req)

    @app.post("/v1/restore-requests/{request_id}/approve")
    def approve(request_id: str, body: DecisionBody, request: Request):
        principal = principal_of(request, MANAGE_RESTORE)
        req = container.restore.decide(
            request_id, approver=principal.username, role=principal.role,
            approve=True, comment=body.comment,
        )
        return _request_dict(req)

    @app.post("/v1/restore-requests/{request_id}/reject")
    def reject(request_id: str, body: DecisionBody, request: Request):
        principal = principal_of(request, MANAGE_RESTORE)
        req = container.restore.decide(
            request_id, approver=principal.username, role=principal.role,
            approve=False, comment=body.comment,
        )
        return _request_dict(req)

    @app.post("/v1/restore-requests/{request_id}/reveal")
    def reveal(request_id: str, request: Request):
        principal = principal_of(request, MANAGE_RESTORE)
        result = container.restore.reveal(request_id, actor=principal.username, role=principal.role)
        container.drop_monitor.record_restore_revealed()
        return result

    @app.get("/v1/restore-requests/{request_id}/content")
    def media_content(request_id: str, request: Request):
        """Stream decrypted media for an approved media restore."""
        principal = principal_of(request, MANAGE_RESTORE)
        result = container.restore.reveal(request_id, actor=principal.username, role=principal.role)
        if result.get("object_type") != "media":
            raise HTTPException(status_code=400, detail="not a media restore request")
        import base64 as _b64

        data = _b64.b64decode(result["content_b64"])
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{request_id}.bin"'},
        )

    @app.get("/internal/metrics")
    def metrics(request: Request):
        principal_of(request, VIEW_METRICS)
        payload = {"drops": container.drop_monitor.snapshot()}
        if container.pipeline_stats:
            payload["pipeline"] = container.pipeline_stats
        payload["inventory"] = _build_inventory(container)
        payload["config"] = {
            "reveal_ttl_minutes": container.settings.reveal_ttl_minutes,
            "trace_retention_days": container.settings.trace_retention_days,
            "audit_archive_after_days": container.settings.audit_archive_after_days,
            "trace_store": container.settings.trace_store,
            "pii_backend": container.settings.pii_backend,
        }
        return payload

    @app.get("/internal/metrics/prometheus")
    def metrics_prometheus(request: Request):
        """Prometheus exposition for the drop counters so ``dropped_batches > 0``
        can alert (proposal §02 通路①: 丢弃数必须监控，大于 0 即告警).
        Scrape config + alert rules: deploy/alerting/."""
        principal_of(request, VIEW_METRICS)
        snap = container.drop_monitor.snapshot()
        lines = []
        for name, value in snap.items():
            if isinstance(value, (int, float)):
                lines.append(f"# TYPE openagent_audit_{name} gauge\nopenagent_audit_{name} {value}")
        return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    # -- web UI -----------------------------------------------------------------
    @app.get("/ui", response_class=HTMLResponse)
    def ui_index(request: Request):
        return RedirectResponse("/ui/sessions", status_code=302)

    @app.get("/ui/login", response_class=HTMLResponse)
    def ui_login(request: Request):
        return render(request, "login.html", error=None)

    @app.post("/ui/login")
    def ui_login_post(request: Request, token: str = Form(...)):
        principal = container.authenticator.resolve(token.strip())
        if principal is None:
            return render(request, "login.html", error="未知令牌", status_code=401)
        resp = RedirectResponse("/ui/sessions", status_code=302)
        resp.set_cookie(_COOKIE_NAME, token.strip(), httponly=True, samesite="lax")
        return resp

    @app.post("/ui/logout")
    def ui_logout(request: Request):
        resp = RedirectResponse("/ui/login", status_code=302)
        resp.delete_cookie(_COOKIE_NAME)
        return resp

    def ui_principal(request: Request, permission: str) -> Principal:
        try:
            return container.authenticator.require(request.cookies.get(_COOKIE_NAME), permission)
        except (AuthenticationError, AuthorizationError):
            raise HTTPException(status_code=302, headers={"Location": "/ui/login"}) from None

    @app.get("/ui/sessions", response_class=HTMLResponse)
    def ui_sessions(request: Request):
        principal = ui_principal(request, VIEW_MASKED)
        return render(
            request, "sessions.html", principal=principal,
            sessions=container.trace_store.list_sessions() if hasattr(container.trace_store, "list_sessions") else [],
        )

    @app.get("/ui/sessions/{session_id}", response_class=HTMLResponse)
    def ui_session_detail(
        session_id: str, request: Request, from_ts: str | None = None, to_ts: str | None = None
    ):
        principal = ui_principal(request, VIEW_MASKED)
        start, end = time_range(from_ts, to_ts)
        traces = container.trace_store.list_traces(session_id=session_id, from_ts=start, to_ts=end)
        if not traces:
            raise HTTPException(status_code=404, detail="session not found")
        log_view(principal, "SESSION_VIEWED", "session", session_id)
        return render(
            request, "session_detail.html", principal=principal,
            session_id=session_id, traces=[_trace_dict(t) for t in traces],
        )

    @app.get("/ui/requests", response_class=HTMLResponse)
    def ui_requests(request: Request):
        principal = ui_principal(request, VIEW_AUDIT_LOG)
        from openagent_audit.vault.models import RestoreStatus

        return render(
            request, "requests.html", principal=principal,
            requests=[_request_dict(r) for r in container.restore.list()],
            statuses=[s.value for s in RestoreStatus],
        )

    @app.post("/ui/requests/{request_id}/decide")
    def ui_decide(request_id: str, request: Request, decision: str = Form(...), comment: str = Form("")):
        principal = ui_principal(request, MANAGE_RESTORE)
        try:
            container.restore.decide(
                request_id, approver=principal.username, role=principal.role,
                approve=(decision == "approve"), comment=comment or None,
            )
        except RestoreError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        return RedirectResponse("/ui/requests", status_code=302)

    @app.post("/ui/requests/{request_id}/reveal")
    def ui_reveal(request_id: str, request: Request):
        principal = ui_principal(request, MANAGE_RESTORE)
        try:
            result = container.restore.reveal(request_id, actor=principal.username, role=principal.role)
        except RestoreError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        payload = {"plaintext": result.get("plaintext")} if result.get("object_type") == "entity" else {"plaintext": "(二进制媒体，请经 API 下载)"}
        return JSONResponse(payload)

    @app.get("/ui/audit-log", response_class=HTMLResponse)
    def ui_audit_log(request: Request):
        principal = ui_principal(request, VIEW_AUDIT_LOG)
        entries = container.audit.list_entries(limit=200)
        verification = container.audit.verify()
        return render(
            request, "audit_log.html", principal=principal,
            entries=entries, verification=verification,
        )

    # -- error mapping ------------------------------------------------------------
    @app.exception_handler(AuthenticationError)
    def _auth_error(request: Request, exc: AuthenticationError):
        return JSONResponse({"detail": str(exc)}, status_code=401)

    @app.exception_handler(AuthorizationError)
    def _perm_error(request: Request, exc: AuthorizationError):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(RestoreError)
    def _restore_error(request: Request, exc: RestoreError):
        return JSONResponse({"detail": exc.code, "message": str(exc)}, status_code=exc.status_code)

    return app


def create_app(settings: Settings | None = None) -> FastAPI:
    """Entry point used by ``uvicorn openagent_audit.services.audit_api:create_app``."""
    return create_audit_app(build_container(settings or Settings.from_env()))


# ---------------------------------------------------------------------------
# serialization helpers
# ---------------------------------------------------------------------------


def _trace_summary(t) -> dict:
    """Accept both TraceRecord (local store) and raw Langfuse API dicts."""
    if isinstance(t, dict):
        return {
            "trace_id": t.get("id"),
            "session_id": t.get("sessionId"),
            "user_id": t.get("userId"),
            "name": t.get("name"),
            "timestamp": str(t.get("timestamp")),
        }
    return {
        "trace_id": t.trace_id,
        "session_id": t.session_id,
        "user_id": t.user_id,
        "name": t.name,
        "timestamp": str(t.timestamp),
    }


def _build_inventory(container: AppContainer) -> dict:
    """Audit-domain stocktaking for the developer/admin metrics view."""
    from openagent_audit.vault.models import RestoreStatus

    inventory: dict = {}
    try:  # vault + audit log (SQLite exposes _path; Postgres path shared below)
        inventory["vault_entities"] = container.db.count_entities()
    except Exception:
        inventory["vault_entities"] = None
    try:
        inventory["audit_entries"] = container.db.count_audit_entries()
    except Exception:
        inventory["audit_entries"] = None
    try:
        by_status: dict[str, int] = {}
        for status in RestoreStatus:
            by_status[status.value] = sum(
                1 for r in container.restore.list(status)
            )
        inventory["restore_requests"] = by_status
    except Exception:
        inventory["restore_requests"] = None
    try:
        if hasattr(container.trace_store, "list_sessions"):
            sessions = container.trace_store.list_sessions()
            inventory["sessions"] = len(sessions)
            inventory["traces"] = sum(s.get("trace_count", 0) for s in sessions)
        else:
            inventory["sessions"] = None
            inventory["traces"] = None
    except Exception:
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


def _request_dict(r) -> dict:
    return {
        "id": r.id,
        "object_type": r.object_type,
        "object_id": r.object_id,
        "reason": r.reason,
        "requested_by": r.requested_by,
        "trace_id": r.trace_id,
        "session_id": r.session_id,
        "status": r.status.value,
        "approver": r.approver,
        "decision_comment": r.decision_comment,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "decided_at": r.decided_at.isoformat() if r.decided_at else None,
        "reveal_expires_at": r.reveal_expires_at.isoformat() if r.reveal_expires_at else None,
    }

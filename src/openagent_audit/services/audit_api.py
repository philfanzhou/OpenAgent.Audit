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
)
from openagent_audit.services.audit_log_service import AuditLogService
from openagent_audit.services.decrypt_client import HttpDecryptService, InProcessDecryptService
from openagent_audit.services.restore_service import RestoreError, RestoreService
from openagent_audit.tracing.drop_monitor import DropMonitor
from openagent_audit.tracing.trace_store import LangfuseTraceStore, LocalTraceStore

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_COOKIE_NAME = "openagent_audit_session"

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

    return AppContainer(
        settings=settings,
        db=db,
        audit=audit,
        restore=restore,
        authenticator=Authenticator(settings.users),
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

    # -- JSON API ---------------------------------------------------------------
    @app.get("/v1/sessions")
    def list_sessions(request: Request):
        principal_of(request, VIEW_MASKED)
        sessions = (
            container.trace_store.list_sessions()
            if hasattr(container.trace_store, "list_sessions")
            else []
        )
        return {"sessions": sessions}

    @app.get("/v1/sessions/{session_id}")
    def get_session(session_id: str, request: Request):
        principal_of(request, VIEW_MASKED)
        traces = container.trace_store.list_traces(session_id=session_id)
        if not traces:
            raise HTTPException(status_code=404, detail="session not found")
        return {"session_id": session_id, "traces": [_trace_dict(t) for t in traces]}

    @app.get("/v1/audit-log")
    def audit_log(request: Request, limit: int = 200, verify: bool = False):
        principal_of(request, VIEW_AUDIT_LOG)
        entries = container.audit.list_entries(limit=min(limit, 1000))
        payload = {
            "entries": [
                {
                    "seq": e.seq, "ts": e.ts.isoformat(), "actor": e.actor, "role": e.role,
                    "action": e.action, "object_type": e.object_type, "object_id": e.object_id,
                    "detail": e.detail,
                }
                for e in entries
            ]
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
    def list_restore_requests(request: Request, status: str | None = None):
        principal_of(request, VIEW_AUDIT_LOG)
        from openagent_audit.vault.models import RestoreStatus

        status_filter = RestoreStatus(status) if status else None
        return {"requests": [_request_dict(r) for r in container.restore.list(status_filter)]}

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
        return payload

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
    def ui_session_detail(session_id: str, request: Request):
        principal = ui_principal(request, VIEW_MASKED)
        traces = container.trace_store.list_traces(session_id=session_id)
        if not traces:
            raise HTTPException(status_code=404, detail="session not found")
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

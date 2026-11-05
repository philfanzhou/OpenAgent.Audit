"""Masking Gateway FastAPI app: OTLP in (from non-Python agents), masked
OTLP out (to Langfuse), fail-closed, with drop counters for alerting.

The gateway is the single ingest point for non-Python agents (the OpenAgent
.NET platform). It accepts both OTLP transports an OpenTelemetry SDK can emit
and tolerates every way the SDK composes the endpoint URL, so the agent side
only has to point ``OTEL_EXPORTER_OTLP_ENDPOINT`` at this service:

======================================  ======================================
Agent exporter setting                  Route reached
======================================  ======================================
``http/protobuf`` (ASP.NET default)     ``POST /v1/traces`` (protobuf body)
``http/json``                           ``POST /v1/traces`` (JSON body)
``http/protobuf`` + ``/v1/traces``      ``POST /v1/traces`` (same URL)
``grpc`` + ``:4317`` base endpoint      ``POST /v1/traces`` (OTLP/gRPC body)
======================================  ======================================

Whichever transport is used, the *masked* payload forwarded downstream is
always OTLP/HTTP JSON to Langfuse's native endpoint, so the masking pipeline
and the ciphertext vault are shared with the Python agent path.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from openagent_audit.bootstrap import build_db, build_write_cipher
from openagent_audit.config import Settings
from openagent_audit.gateway.otlp import (
    GatewayPayloadError,
    decode_otlp_body,
    encode_otlp_json,
    iter_spans,
    process_otlp_payload,
)
from openagent_audit.pii.engine import DetectionEngine, RuleBasedEngine, create_engine, PresidioEngine
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
from openagent_audit.tracing.drop_monitor import DropMonitor


@dataclass
class GatewayCounters:
    """Thread-safe operational counters for the gateway."""

    batches_received: int = 0
    spans_masked: int = 0
    batches_dropped: int = 0          # masking/vault failure (fail-closed)
    forward_failures: int = 0         # Langfuse unreachable after retries
    forwarded_batches: int = 0
    batches_rejected: int = 0         # undecodable body (protobuf/JSON)
    batches_unauthorized: int = 0
    last_forward_error: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # Every mutation goes through these locked helpers: a bare
    # ``threading.Lock()`` in a ``with`` statement creates a throwaway lock
    # (and, worse, raises TypeError under this signature), so it never
    # protected anything.
    def record_batch_received(self) -> None:
        with self._lock:
            self.batches_received += 1

    def record_spans_masked(self, count: int) -> None:
        with self._lock:
            self.spans_masked += count

    def record_batch_dropped(self) -> None:
        with self._lock:
            self.batches_dropped += 1

    def record_batch_rejected(self) -> None:
        with self._lock:
            self.batches_rejected += 1

    def record_unauthorized(self) -> None:
        with self._lock:
            self.batches_unauthorized += 1

    def record_forwarded(self) -> None:
        with self._lock:
            self.forwarded_batches += 1

    def record_forward_failure(self, error: str) -> None:
        with self._lock:
            self.forward_failures += 1
            self.last_forward_error = error

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "batches_received": self.batches_received,
                "spans_masked": self.spans_masked,
                "batches_dropped": self.batches_dropped,
                "forward_failures": self.forward_failures,
                "forwarded_batches": self.forwarded_batches,
                "batches_rejected": self.batches_rejected,
                "batches_unauthorized": self.batches_unauthorized,
                "last_forward_error": self.last_forward_error,
            }

    def has_drops(self) -> bool:
        snap = self.snapshot()
        return snap["batches_dropped"] > 0 or snap["forward_failures"] > 0


@dataclass
class GatewayDeps:
    settings: Settings
    pipeline: MaskingPipeline
    forwarder: object                 # callable(payload_json: bytes) -> None
    counters: GatewayCounters = field(default_factory=GatewayCounters)
    drop_monitor: DropMonitor = field(default_factory=DropMonitor)


def build_gateway_deps(settings: Settings | None = None) -> GatewayDeps:
    """Assemble the gateway from environment settings."""
    settings = settings or Settings.from_env()

    def forwarder(payload: bytes) -> None:
        # Langfuse natively ingests OTLP/HTTP JSON on this endpoint.
        _forward_via_httpx(settings, payload)

    db = build_db(settings)

    # Respect the configured PII backend (rules / presidio) rather than
    # hard-coding RuleBasedEngine. A missing or unusable backend fails at
    # startup so the gateway never silently degrades.
    engine = _build_detection_engine(settings)

    pipeline = MaskingPipeline(
        engine=engine,
        cipher=build_write_cipher(settings),  # gateway only ever seals
        vault_writer=VaultWriter(db),
    )
    return GatewayDeps(settings=settings, pipeline=pipeline, forwarder=forwarder)


def _build_detection_engine(settings: Settings) -> DetectionEngine:
    """Resolve the configured PII backend and fail-fast on misconfiguration.

    ``RuleBasedEngine`` is always available. ``PresidioEngine`` requires the
    ``presidio-analyzer`` package and a Chinese spaCy model; when
    ``AUDIT_PII_BACKEND=presidio`` is chosen but the extra is not installed,
    this function raises immediately rather than silently falling back to the
    rule engine — a deployment running an unsupported backend is a
    configuration error and must never degrade without an alert.
    """
    backend = settings.pii_backend
    if backend == "rules":
        return RuleBasedEngine()
    if backend == "presidio":
        return PresidioEngine()
    raise ValueError(
        f"Unsupported AUDIT_PII_BACKEND={backend!r}. "
        "Expected 'rules' or 'presidio'."
    )


def _forward_via_httpx(settings: Settings, payload: bytes) -> None:
    import time

    import httpx

    url = settings.langfuse_host.rstrip("/") + "/api/public/otel/v1/traces"
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(
                    url,
                    content=payload,
                    headers={"Content-Type": "application/json"},
                    auth=(settings.langfuse_public_key, settings.langfuse_secret_key),
                )
            if resp.status_code < 300:
                return
            last_error = RuntimeError(
                f"langfuse responded {resp.status_code}: {resp.text[:200]}"
            )
        except Exception as exc:  # noqa: BLE001 - retried below
            last_error = exc
        if attempt < 2:
            time.sleep(min(0.5 * (2**attempt), 4.0))
    raise RuntimeError(f"langfuse forward failed after retries: {last_error}") from last_error


def _authorize(settings: Settings, request: Request) -> bool:
    """Bearer token check for OTLP ingest.

    Uses ``hmac.compare_digest`` so the comparison is constant-time, and
    accepts the token either as ``Authorization: Bearer <token>`` (what we
    tell agents to send) or as ``x-api-key: <token>`` (the header form
    OpenTelemetry's stock environment variables write most naturally).
    Authentication is disabled only when no token is configured (dev), and
    ``AUDIT_GATEWAY_REQUIRE_AUTH`` forces it on regardless (production).
    """
    expected = settings.gateway_ingest_token
    if not expected:
        if settings.gateway_require_auth:
            return False
        return True

    import hmac

    candidates: list[str] = []
    header = request.headers.get("Authorization", "")
    if header[:7].lower() == "bearer ":
        candidates.append(header[7:].strip())
    api_key = request.headers.get("x-api-key", "").strip()
    if api_key:
        candidates.append(api_key)
    return any(hmac.compare_digest(token, expected) for token in candidates)


def _count_spans(deps: GatewayDeps) -> Callable[[int], None]:
    def _record(n: int) -> None:
        deps.counters.record_spans_masked(n)
        deps.drop_monitor.record_spans_patched(n)

    return _record


def create_gateway_app(deps: GatewayDeps | None = None) -> FastAPI:
    deps = deps or build_gateway_deps()
    app = FastAPI(title="openagent-audit masking gateway", docs_url=None, redoc_url=None)
    counters = deps.counters
    settings = deps.settings

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "service": "masking-gateway"}

    @app.get("/internal/metrics")
    def metrics() -> dict:
        return {
            "gateway": counters.snapshot(),
            "drops": deps.drop_monitor.snapshot(),
        }

    def _ingest(request: Request, body: bytes, path_style: str):
        if not _authorize(settings, request):
            counters.record_unauthorized()
            return JSONResponse(
                {"detail": "无效的网关访问令牌（Authorization: Bearer / x-api-key）"},
                status_code=401,
            )

        counters.record_batch_received()
        try:
            payload = decode_otlp_body(
                body, content_type=request.headers.get("content-type", "")
            )
        except GatewayPayloadError as exc:
            counters.record_batch_rejected()
            return JSONResponse(
                {"detail": f"请求体无法解析为 OTLP: {exc}"}, status_code=400
            )

        if not any(iter_spans(payload)):
            # Valid but empty export: nothing to mask or forward.
            return {"ok": True, "spans": 0, "transport": path_style}

        try:
            process_otlp_payload(
                payload,
                pipeline=deps.pipeline,
                content_prefixes=settings.gateway_content_prefixes,
                session_attrs=settings.gateway_session_attrs,
                user_attrs=settings.gateway_user_attrs,
                agent_attrs=settings.gateway_agent_attrs,
                on_batch_masked=_count_spans(deps),
            )
        except Exception as exc:  # noqa: BLE001 - fail-closed by design
            # fail-closed: masking/vault failure -> drop the batch, never forward
            counters.record_batch_dropped()
            deps.drop_monitor.record_batch_dropped()
            deps.drop_monitor.record_vault_failure()
            return JSONResponse(
                {
                    "detail": "脱敏处理失败，批次已丢弃（fail-closed），请检查网关与审计库。",
                    "error": type(exc).__name__,
                },
                status_code=500,
            )

        try:
            deps.forwarder(encode_otlp_json(payload))
        except Exception as exc:  # noqa: BLE001 - masked data only, counted
            # masked data only — losing it is an observability loss, not a leak
            counters.record_forward_failure(str(exc))
            return JSONResponse(
                {"detail": "掩码完成，但转发 Langfuse 失败（已计数告警）"},
                status_code=502,
            )
        counters.record_forwarded()
        return {"ok": True, "transport": path_style}

    # The same ingest logic answers every route an OpenTelemetry SDK can end
    # up calling. ``/v1/traces`` is canonical; the others exist because the
    # SDK only appends the signal path when the configured endpoint has no
    # path of its own (so ``.../<host>:<port>/v1/traces`` can become
    # ``.../v1/traces/v1/traces``), and because a ``grpc``-configured endpoint
    # posts OTLP/gRPC framing to the base URL.
    async def ingest_traces(request: Request):
        return _ingest(request, await request.body(), "http")

    for route in (
        "/v1/traces",
        # An SDK given ".../<host>:<port>/v1/traces" with no signal path of its
        # own appends one more segment; answer it instead of 404-ing.
        "/v1/traces/v1/traces",
        # protocol=grpc exporters address the service by its fully qualified
        # name; the framing is unwrapped inside decode_otlp_body.
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        # A grpc-configured exporter posts to the configured endpoint
        # verbatim; only reachable when the agent configured <host>:<port>.
        "/",
    ):
        app.add_api_route(route, ingest_traces, methods=["POST"], response_model=None)

    return app


def create_app() -> FastAPI:
    """uvicorn entry point: openagent_audit.gateway.app:create_app"""
    return create_gateway_app(build_gateway_deps(Settings.from_env()))
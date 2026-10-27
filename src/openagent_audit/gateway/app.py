"""Masking Gateway FastAPI app: OTLP in (from non-Python agents), masked
OTLP out (to Langfuse), fail-closed, with drop counters for alerting."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from openagent_audit.bootstrap import build_db, build_loki, build_write_cipher
from openagent_audit.config import Settings
from openagent_audit.gateway.otlp import process_otlp_payload
from openagent_audit.pii.engine import RuleBasedEngine
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
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "batches_received": self.batches_received,
                "spans_masked": self.spans_masked,
                "batches_dropped": self.batches_dropped,
                "forward_failures": self.forward_failures,
                "forwarded_batches": self.forwarded_batches,
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
        if not _forward_via_httpx(settings, payload):
            raise RuntimeError("langfuse forward failed")

    db = build_db(settings)
    pipeline = MaskingPipeline(
        engine=RuleBasedEngine(),
        cipher=build_write_cipher(settings),  # gateway only ever seals
        vault_writer=VaultWriter(db),
    )
    return GatewayDeps(settings=settings, pipeline=pipeline, forwarder=forwarder)


def _forward_via_httpx(settings: Settings, payload: bytes) -> bool:
    """POST the masked OTLP/JSON payload to Langfuse with bounded retries."""
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
                return True
            last_error = RuntimeError(f"langfuse responded {resp.status_code}")
        except Exception as exc:  # noqa: BLE001 - retried below
            last_error = exc
        time.sleep(min(0.5 * (2**attempt), 4.0))
    raise RuntimeError(f"langfuse forward failed after retries") from last_error


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

    @app.post("/v1/traces")
    async def ingest_traces(request: Request):
        # ingest auth (bearer); disabled only when no token is configured (dev)
        expected = settings.gateway_ingest_token
        if expected:
            header = request.headers.get("Authorization", "")
            if header != f"Bearer {expected}":
                return JSONResponse({"detail": "无效的网关访问令牌"}, status_code=401)
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"detail": "请求体不是合法 JSON"}, status_code=400)

        with threading.Lock():
            counters.batches_received += 1
        def _count_spans(n: int) -> None:
            with threading.Lock():
                counters.spans_masked += n
            deps.drop_monitor.record_spans_patched(n)

        try:
            process_otlp_payload(
                payload,
                pipeline=deps.pipeline,
                content_prefixes=settings.gateway_content_prefixes,
                session_attrs=settings.gateway_session_attrs,
                user_attrs=settings.gateway_user_attrs,
                agent_attrs=settings.gateway_agent_attrs,
                on_batch_masked=_count_spans,
            )
        except Exception:
            # fail-closed: masking/vault failure -> drop the batch, never forward
            with threading.Lock():
                counters.batches_dropped += 1
            deps.drop_monitor.record_batch_dropped()
            deps.drop_monitor.record_vault_failure()
            return JSONResponse(
                {"detail": "脱敏处理失败，批次已丢弃（fail-closed），请检查网关与审计库。"},
                status_code=500,
            )

        try:
            import json

            deps.forwarder(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            with threading.Lock():
                counters.forwarded_batches += 1
        except Exception:
            # masked data only — losing it is an observability loss, not a leak
            with threading.Lock():
                counters.forward_failures += 1
            return JSONResponse(
                {"detail": "掩码完成，但转发 Langfuse 失败（已计数告警）"},
                status_code=502,
            )
        return {"ok": True, "drops": counters.snapshot()}

    return app


def create_app() -> FastAPI:
    """uvicorn entry point: openagent_audit.gateway.app:create_app"""
    return create_gateway_app(build_gateway_deps(Settings.from_env()))

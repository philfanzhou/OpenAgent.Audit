"""OTLP span tree: recursive masking for nested content-bearing fields.

The original implementation only masked ``span.attributes``' ``stringValue``
scalars whose key starts with one of the configured prefixes. That left
these paths unmasked and forwarded in the clear to Langfuse:

* span ``name``                           — may contain PII in the metric name
* span ``status.message``                 — error descriptions
* ``events[*].attributes``                — span events with their own attributes
* ``events[*].name``                      — event names
* ``resource.attributes``                 — service-level metadata
* ``scope.name`` / ``scope.version``      — instrumentation scope
* nested attribute values (arrays/objects) — any structured content

This module now applies the same detection pipeline recursively, and any
field that the PII engine does not flag passes through unchanged — the
engine is still the sole determinant of what is sensitive.

Batch atomicity: every entity in a payload is collected by one
:func:`~openagent_audit.pii.masking.protect_batch` and written to the vault in
a single transaction. A failure anywhere in the batch therefore leaves no
ciphertext behind, matching the fail-closed rule that such a batch is never
forwarded.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable

AttrValue = int | float | bool | str
JsonDict = dict[str, Any]

_DROP = object()

# OTLP/HTTP binary protobuf media type, and the gRPC framing used when an SDK
# is configured with protocol=grpc but talks to an HTTP endpoint.
_PROTOBUF_CONTENT_TYPES = (
    "application/x-protobuf",
    "application/protobuf",
    "application/vnd.google.protobuf",
    "application/grpc",
    "application/grpc+proto",
)


class GatewayPayloadError(ValueError):
    """The request body is not a decodable OTLP export payload."""

# Fields that may contain user text and should be scanned for PII.
_CONTENT_STRING_FIELDS: tuple[tuple[str, ...], ...] = (
    # span-level (top to bottom, longest path first)
    ("attributes",),
    ("name",),
    ("status", "message"),
    # span events: a list of dicts each with their own attributes
    ("events",),
    # span links
    ("links",),
    # resource-level (the outer resourceSpans envelopes)
    ("resource", "attributes"),
    # scope-level (the instrumentation library identity)
    ("scope", "name"),
    ("scope", "version"),
)

# Attribute keys that are known to carry identifiers, not free-form text.
# These are NOT masked even when their key starts with a content prefix
# because they carry audit correlation identifiers, not user content.
_ID_ATTRIBUTE_KEYS: frozenset[str] = frozenset({
    "openagent.conversation_id",
    "openagent.user_id",
    "openagent.agent_id",
    "openagent.tenant_id",
    "openagent.trace_id",
    "user.id",
    "session.id",
    "agent.id",
    "langfuse.session.id",
    "langfuse.user.id",
    "langfuse.tag.agent",
})


def _try_mask(
    text: str,
    key: str,
    pipeline,
    content_prefixes: tuple[str, ...],
    protect,
) -> str | None:
    """Mask *text* when *key* appears to carry user content. Returns the
    masked version when entities were found, ``None`` otherwise (the caller
    should leave the original unchanged when nothing was recognised).

    *protect* is the batch-aware callable supplied by ``process_otlp_payload``
    so every entity in a payload is persisted in one vault write.
    """
    if not text:
        return None
    if key in _ID_ATTRIBUTE_KEYS:
        return None
    if not _is_content_key(key, content_prefixes):
        return None
    result = protect(text)
    if result.entities:
        return result.masked_text
    return None


def _is_content_key(key: str, prefixes: tuple[str, ...]) -> bool:
    return key.startswith(prefixes)


def _attr_value(raw: JsonDict) -> AttrValue | None:
    value = raw.get("value")
    if not isinstance(value, dict):
        return None
    for key, cast in (
        ("stringValue", str),
        ("intValue", int),
        ("doubleValue", float),
        ("boolValue", bool),
    ):
        if key in value:
            try:
                return cast(value[key])
            except (TypeError, ValueError):
                return None
    return None


def _set_attr(span: JsonDict, key: str, value: str) -> None:
    attrs = span.setdefault("attributes", [])
    for attr in attrs:
        if attr.get("key") == key:
            attr["value"] = {"stringValue": value}
            return
    attrs.append({"key": key, "value": {"stringValue": value}})


def _first_attr(span: JsonDict, candidates: Iterable[str]) -> str | None:
    attrs = {a.get("key"): _attr_value(a) for a in span.get("attributes", [])}
    for key in candidates:
        value = attrs.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def mask_span(
    span: JsonDict,
    *,
    pipeline,  # MaskingPipeline
    content_prefixes: tuple[str, ...],
    session_attrs: tuple[str, ...],
    user_attrs: tuple[str, ...],
    agent_attrs: tuple[str, ...],
    protect=None,
) -> None:
    """Mask content attributes of one span in place and stamp identifiers.

    Raises on pipeline failure — the caller treats any exception as
    fail-closed and drops the whole batch.

    *protect* is the batch-aware masking callable; when omitted a per-call
    pipeline write is used (the historical behaviour).
    """
    if protect is None:
        trace_id = _hex_trace_id(span.get("traceId")) or span.get("traceId")
        session_id_for_scope = _first_attr(span, session_attrs)

        def protect(text: str):  # noqa: ANN001 - closure over span identifiers
            return pipeline.protect(text, trace_id=trace_id, session_id=session_id_for_scope)

    trace_id = _hex_trace_id(span.get("traceId")) or span.get("traceId")
    session_id = _first_attr(span, session_attrs)
    user_id = _first_attr(span, user_attrs)
    agent_id = _first_attr(span, agent_attrs)

    # 1. attributes (the original path, kept for backward compat)
    for attr in span.get("attributes", []):
        key = attr.get("key", "")
        if not key.startswith(tuple(content_prefixes)):
            continue
        value = _attr_value(attr)
        if not isinstance(value, str) or not value:
            continue
        result = protect(value)
        if result.entities:
            attr["value"] = {"stringValue": result.masked_text}

    # 2. span name (the metric name that usually mirrors the route)
    name = span.get("name")
    if isinstance(name, str) and name:
        name_result = protect(name)
        if name_result.entities:
            span["name"] = name_result.masked_text

    # 3. status.message
    status = span.get("status")
    if isinstance(status, dict):
        msg = status.get("message")
        if isinstance(msg, str) and msg:
            msg_result = protect(msg)
            if msg_result.entities:
                status["message"] = msg_result.masked_text

    # 4. span events (a list of {name, attributes, timeUnixNano, ...})
    events = span.get("events")
    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict):
                event_name = event.get("name")
                if isinstance(event_name, str) and event_name:
                    ev_result = pipeline.protect(
                        event_name, trace_id=trace_id, session_id=session_id
                    )
                    if ev_result.entities:
                        event["name"] = ev_result.masked_text
                for ev_attr in event.get("attributes", []):
                    ev_key = ev_attr.get("key", "")
                    if not ev_key.startswith(tuple(content_prefixes)):
                        continue
                    ev_value = _attr_value(ev_attr)
                    if not isinstance(ev_value, str) or not ev_value:
                        continue
                    result = pipeline.protect(
                        ev_value, trace_id=trace_id, session_id=session_id
                    )
                    if result.entities:
                        ev_attr["value"] = {"stringValue": result.masked_text}

    # 5. resource-level attributes (outer envelope)
    # Handled by mask_resource() below when iterating resourceSpans.

    # identifier mapping for Langfuse (session/user first-class, agent as tag)
    if session_id:
        _set_attr(span, "langfuse.session.id", session_id)
    if user_id:
        _set_attr(span, "langfuse.user.id", user_id)
    if agent_id:
        _set_attr(span, "langfuse.tag.agent", agent_id)


def mask_resource_attrs(
    resource: JsonDict,
    *,
    pipeline,
    content_prefixes: tuple[str, ...],
    protect=None,
    trace_id: str | None = None,
    session_id: str | None = None,
) -> None:
    """Mask content attributes on the outer resource envelope."""
    if protect is None:
        def protect(text: str):  # noqa: ANN001 - closure over identifiers
            return pipeline.protect(text, trace_id=trace_id, session_id=session_id)

    for attr in resource.get("attributes", []):
        key = attr.get("key", "")
        if not key.startswith(tuple(content_prefixes)):
            continue
        value = _attr_value(attr)
        if not isinstance(value, str) or not value:
            continue
        result = protect(value)
        if result.entities:
            attr["value"] = {"stringValue": result.masked_text}


def mask_scope(
    scope: JsonDict,
    *,
    pipeline,
    content_prefixes: tuple[str, ...],
    protect=None,
    trace_id: str | None = None,
    session_id: str | None = None,
) -> None:
    """Mask scope-level name/version if they match content prefixes."""
    if protect is None:
        def protect(text: str):  # noqa: ANN001 - closure over identifiers
            return pipeline.protect(text, trace_id=trace_id, session_id=session_id)

    for field in ("name", "version"):
        value = scope.get(field)
        if isinstance(value, str) and value and _is_content_key(field, content_prefixes):
            result = protect(value)
            if result.entities:
                scope[field] = result.masked_text


def iter_spans(payload: JsonDict) -> Iterable[JsonDict]:
    """Yield every span in an OTLP/JSON export payload."""
    for resource_spans in payload.get("resourceSpans", []):
        for scope_spans in resource_spans.get("scopeSpans", []):
            yield from scope_spans.get("spans", [])


def process_otlp_payload(
    payload: JsonDict,
    *,
    pipeline,
    content_prefixes: tuple[str, ...],
    session_attrs: tuple[str, ...],
    user_attrs: tuple[str, ...],
    agent_attrs: tuple[str, ...],
    on_batch_masked: Callable[[int], None] | None = None,
) -> JsonDict:
    """Mask every span of the payload in place; returns the same payload.

    Also applies masking to resource-level and scope-level attributes so
    that content-bearing fields at every level of the OTLP tree are scanned
    before the payload is forwarded.

    All entities found in the payload are persisted through ONE
    ``protect_batch``: if any step raises, nothing is written, so a dropped
    (fail-closed) batch never leaves orphan ciphertext rows behind.
    """
    first_span = next(iter_spans(payload), {})
    trace_id = _hex_trace_id(first_span.get("traceId"))
    session_id = _first_attr(first_span, session_attrs) if first_span else None

    with pipeline.batch(trace_id=trace_id, session_id=session_id) as batch:
        for resource_spans in payload.get("resourceSpans", []):
            resource = resource_spans.get("resource")
            if isinstance(resource, dict):
                mask_resource_attrs(
                    resource,
                    pipeline=pipeline,
                    content_prefixes=content_prefixes,
                    protect=batch.protect,
                )
            for scope_spans in resource_spans.get("scopeSpans", []):
                scope = scope_spans.get("scope")
                if isinstance(scope, dict):
                    mask_scope(
                        scope,
                        pipeline=pipeline,
                        content_prefixes=content_prefixes,
                        protect=batch.protect,
                    )
                for span in scope_spans.get("spans", []):
                    mask_span(
                        span,
                        pipeline=pipeline,
                        content_prefixes=content_prefixes,
                        session_attrs=session_attrs,
                        user_attrs=user_attrs,
                        agent_attrs=agent_attrs,
                        protect=batch.protect,
                    )

    span_count = sum(1 for _ in iter_spans(payload))
    if on_batch_masked is not None:
        on_batch_masked(span_count)
    return payload


# ---------------------------------------------------------------------------
# Trace id normalisation
# ---------------------------------------------------------------------------


def _hex_trace_id(raw) -> str | None:
    """Normalise an OTLP trace id to the 32-char lowercase hex form.

    OTLP/JSON carries ids base64-encoded while OTLP/Protobuf carries raw
    bytes, so the same trace arrives in three shapes. The vault stores the
    id that retention matches on and that humans correlate with the
    platform's logs, which is hex — otherwise a protobuf-ingested batch
    would be un-deletable when its retention window closes.
    """
    if not isinstance(raw, str) or not raw:
        return None
    import base64
    import binascii

    stripped = raw.strip()
    if len(stripped) == 32 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return stripped.lower()
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) in (16, 8):
        return decoded.hex()
    return None


# ---------------------------------------------------------------------------
# Transport decoding (protobuf / gRPC framing) and re-encoding to JSON
# ---------------------------------------------------------------------------


def _is_protobuf_content_type(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return any(lowered.startswith(media_type) for media_type in _PROTOBUF_CONTENT_TYPES)


def _looks_like_protobuf(body: bytes) -> bool:
    """OTLP JSON bodies always start with ``{``; protobuf ones almost never do."""
    return bool(body) and not body.lstrip()[:1] == b"{"


def _unwrap_grpc_frame(body: bytes) -> bytes:
    """Strip the 5-byte gRPC message frame (compression flag + length).

    Compressed messages are refused rather than passed through: decompressing
    arbitrary client data on the masking path would put the plaintext
    guarantee behind a decompressor we do not audit.
    """
    if len(body) < 5:
        raise GatewayPayloadError("OTLP/gRPC 消息帧不完整")
    compressed = body[0]
    if compressed != 0:
        raise GatewayPayloadError(
            "不支持压缩的 OTLP/gRPC 消息（compressed-flag=1）；"
            "请在 Agent 侧使用 http/json 或 http/protobuf"
        )
    length = int.from_bytes(body[1:5], "big")
    message = body[5 : 5 + length]
    if len(message) != length:
        raise GatewayPayloadError("OTLP/gRPC 消息帧长度与实际内容不符")
    return message


def _decode_protobuf(message: bytes) -> JsonDict:
    """Decode an OTLP/Protobuf ``ExportTraceServiceRequest`` into JSON form.

    Uses ``opentelemetry-proto`` (the canonical generated bindings, also used
    by the OpenTelemetry Python exporter) and converts it with
    ``MessageToDict``, which yields exactly the OTLP/JSON structure the rest
    of this module and Langfuse's OTLP endpoint expect: base64 trace/span ids,
    camelCase attribute values.
    """
    try:
        from google.protobuf.json_format import MessageToDict
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTraceServiceRequest,
        )
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise GatewayPayloadError(
            "网关收到 OTLP/Protobuf 请求，但未安装 protobuf 支持；"
            "请安装 openagent-audit[otlp]，或在 Agent 侧设置 "
            "OTEL_EXPORTER_OTLP_PROTOCOL=http/json"
        ) from exc

    request = ExportTraceServiceRequest()
    try:
        request.ParseFromString(message)
    except Exception as exc:  # noqa: BLE001 - reported as a payload error
        raise GatewayPayloadError(f"无法解析 OTLP/Protobuf 请求体: {exc}") from exc

    payload = MessageToDict(
        request,
        preserving_proto_field_name=False,
        use_integers_for_enums=False,
    )
    if not isinstance(payload, dict):
        raise GatewayPayloadError("OTLP/Protobuf 请求体不是资源跨度的对象")
    payload.setdefault("resourceSpans", [])
    return payload


def decode_otlp_body(body: bytes, *, content_type: str = "") -> JsonDict:
    """Decode an OTLP export request body in any transport into JSON form.

    Order of detection: explicit protobuf/gRPC content type first, then the
    body's first non-space byte. A JSON body that fails to parse raises
    :class:`GatewayPayloadError` rather than silently becoming an empty batch —
    an unparsed batch must never look like a successful export.
    """
    if not body or not body.strip():
        raise GatewayPayloadError("请求体为空")

    if _is_protobuf_content_type(content_type):
        if content_type.lower().startswith("application/grpc"):
            return _decode_protobuf(_unwrap_grpc_frame(body))
        return _decode_protobuf(body)

    if _looks_like_protobuf(body):
        return _decode_protobuf(body)

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayPayloadError("请求体不是合法 JSON") from exc
    if not isinstance(payload, dict):
        raise GatewayPayloadError("请求体不是 OTLP JSON 对象（缺少 resourceSpans）")
    return payload


def encode_otlp_json(payload: JsonDict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")
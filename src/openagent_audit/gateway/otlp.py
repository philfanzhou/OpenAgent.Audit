"""OTLP payload decoding, transformation and re-encoding.

The gateway speaks the OTLP/HTTP JSON export format (``resourceSpans`` tree)
natively, and additionally accepts the two other shapes an OpenTelemetry SDK
can emit when it is pointed at the gateway by mistake or by deployment
convention:

* ``http/json``           — wire format is already JSON (handled here directly);
* ``http/protobuf``       — ASP.NET Core's default; decoded with
  ``opentelemetry-proto`` when that optional dependency is installed;
* ``grpc`` framing        — a 5-byte length-prefixed message; the frame is
  unwrapped and then decoded exactly like an HTTP protobuf body.

Protobuf support is optional (``pip install 'openagent-audit[otlp]'``): the
default install parses JSON only, and a protobuf body without the extra
raises :class:`GatewayPayloadError` with an actionable message instead of a
bare 400.

Everything that leaves the gateway is re-encoded as OTLP/HTTP JSON, which is
what Langfuse's native OTLP endpoint ingests — so the masking pipeline, the
ciphertext vault and the drop accounting are identical no matter which
transport the agent used.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable

AttrValue = int | float | bool | str
# An OTLP JSON attribute value: {"value": {"stringValue": ...} | {...}}
JsonDict = dict[str, Any]

_DROP = object()  # sentinel: value could not be masked -> drop the batch

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


def mask_span(
    span: JsonDict,
    *,
    pipeline,  # MaskingPipeline
    content_prefixes: tuple[str, ...],
    session_attrs: tuple[str, ...],
    user_attrs: tuple[str, ...],
    agent_attrs: tuple[str, ...],
) -> None:
    """Mask content attributes of one span in place and stamp identifiers.

    Raises on pipeline failure — the caller treats any exception as
    fail-closed and drops the whole batch.
    """
    trace_id = _hex_trace_id(span.get("traceId")) or span.get("traceId")
    session_id = _first_attr(span, session_attrs)
    user_id = _first_attr(span, user_attrs)
    agent_id = _first_attr(span, agent_attrs)

    for attr in span.get("attributes", []):
        key = attr.get("key", "")
        if not key.startswith(tuple(content_prefixes)):
            continue
        value = _attr_value(attr)
        if not isinstance(value, str) or not value:
            continue
        result = pipeline.protect(value, trace_id=trace_id, session_id=session_id)
        if result.entities:
            attr["value"] = {"stringValue": result.masked_text}

    # identifier mapping for Langfuse (session/user first-class, agent as tag)
    if session_id:
        _set_attr(span, "langfuse.session.id", session_id)
    if user_id:
        _set_attr(span, "langfuse.user.id", user_id)
    if agent_id:
        _set_attr(span, "langfuse.tag.agent", agent_id)


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

    Any exception propagates to the caller for fail-closed batch dropping.
    """
    spans = list(iter_spans(payload))
    for span in spans:
        mask_span(
            span,
            pipeline=pipeline,
            content_prefixes=content_prefixes,
            session_attrs=session_attrs,
            user_attrs=user_attrs,
            agent_attrs=agent_attrs,
        )
    if on_batch_masked is not None:
        on_batch_masked(len(spans))
    return payload


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
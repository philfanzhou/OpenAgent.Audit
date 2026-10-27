"""OTLP/HTTP-JSON transformation: mask, seal, and tag spans.

Accepts the OTLP/HTTP JSON export format (``resourceSpans`` tree) that the
OpenTelemetry .NET exporter emits when configured with
``OTEL_EXPORTER_OTLP_PROTOCOL=http/json``. Protobuf input is intentionally not
parsed here: the gateway asks upstream agents to emit JSON, which keeps the
dependency surface (no protobuf compiler/codegen) small while remaining
spec-compliant.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

AttrValue = int | float | bool | str
# An OTLP JSON attribute value: {"value": {"stringValue": ...} | {...}}
JsonDict = dict[str, Any]

_DROP = object()  # sentinel: value could not be masked -> drop the batch


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
) -> None:
    """Mask content attributes of one span in place and stamp identifiers.

    Raises on pipeline failure — the caller treats any exception as
    fail-closed and drops the whole batch.
    """
    trace_id = span.get("traceId")
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

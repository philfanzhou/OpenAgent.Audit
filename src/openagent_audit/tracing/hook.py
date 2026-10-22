"""The ``mask_otel_spans`` export-thread hook (proposal §02 通路① / §11.3).

Runs inside the Langfuse SDK's background export thread — never on the
request thread. If anything raises, the SDK drops the whole batch
(fail-closed: no plaintext ever leaves the process); we count the drop so it
can alert.
"""

from __future__ import annotations

from typing import Callable, Mapping

from openagent_audit.pii.masking import MaskingPipeline
from openagent_audit.tracing.drop_monitor import DropMonitor

MaskHook = Callable[..., object]

SESSION_ATTRIBUTE = "langfuse.session.id"


def _trace_session_ids(span) -> tuple[str | None, str | None]:
    """Best-effort (trace_id, session_id) for one exported span.

    ``trace_id`` comes from the OTel span data; ``session_id`` from the
    Langfuse OTEL attribute the Agent sets via ``propagate_attributes`` /
    ``AgentInstrument``. Vault rows carry both so retention can delete the
    matching ciphertext when a trace expires (proposal §10 step 8).
    """
    trace_id = getattr(span, "trace_id", None)
    attributes = getattr(span, "attributes", None) or {}
    session_id = attributes.get(SESSION_ATTRIBUTE)
    return trace_id, session_id


def mask_attribute_map(
    attributes: Mapping[str, object],
    pipeline: MaskingPipeline,
    prefixes: tuple[str, ...],
    *,
    trace_id: str | None = None,
    session_id: str | None = None,
) -> dict[str, str]:
    """Pure helper: mask the string attributes whose keys match ``prefixes``."""
    masked: dict[str, str] = {}
    for key, value in attributes.items():
        if not isinstance(value, str) or not value:
            continue
        if not key.startswith(tuple(prefixes)):
            continue
        result = pipeline.protect(value, trace_id=trace_id, session_id=session_id)
        if result.entities:
            masked[key] = result.masked_text
    return masked


def build_mask_otel_spans(
    pipeline: MaskingPipeline,
    drop_monitor: DropMonitor | None = None,
    prefixes: tuple[str, ...] = ("langfuse.observation.input", "langfuse.observation.output",
                                "gen_ai.prompt", "gen_ai.completion"),
) -> MaskHook:
    """Build a hook with the exact Langfuse v5 signature::

        def mask_otel_spans(*, params: MaskOtelSpansParams) -> MaskOtelSpansResult

    Attach it at client construction: ``Langfuse(mask_otel_spans=hook)``.
    """
    monitor = drop_monitor if drop_monitor is not None else DropMonitor()

    def mask_otel_spans(*, params):  # noqa: ANN001 - signature fixed by the SDK
        try:
            patches = {}
            for identifier, span in params.spans.items():
                trace_id, session_id = _trace_session_ids(span)
                masked = mask_attribute_map(
                    span.attributes, pipeline, prefixes,
                    trace_id=trace_id, session_id=session_id,
                )
                if masked:
                    patches[identifier] = _span_patch(set_attributes=masked)
        except Exception:
            # fail-closed: re-raise so the SDK discards the batch untouched,
            # after counting the loss for alerting.
            monitor.record_batch_dropped()
            raise
        monitor.record_spans_patched(len(patches))
        return _mask_result(span_patches=patches)

    return mask_otel_spans


def _span_patch(*, set_attributes: dict[str, str]):
    from langfuse.types import OtelSpanPatch

    return OtelSpanPatch(set_attributes=set_attributes)


def _mask_result(*, span_patches: dict):
    from langfuse.types import MaskOtelSpansResult

    return MaskOtelSpansResult(span_patches=span_patches)

"""Glue for constructing a real Langfuse client with the masking hook attached.

Only the Agent process imports this; the audit plane never talks to Langfuse
with plaintext data because the hook runs before export leaves the process.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from openagent_audit.config import Settings
    from openagent_audit.pii.masking import MaskingPipeline
    from openagent_audit.tracing.drop_monitor import DropMonitor


def build_langfuse_client(
    settings: "Settings",
    pipeline: "MaskingPipeline",
    drop_monitor: "DropMonitor | None" = None,
    **client_kwargs,
):
    """``Langfuse(mask_otel_spans=...)`` with our export-thread hook.

    Raises a helpful error when the optional ``langfuse`` extra is missing.
    """
    try:
        from langfuse import Langfuse
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise RuntimeError(
            "langfuse is not installed; pip install 'openagent-audit[langfuse]'"
        ) from exc

    from openagent_audit.tracing.hook import build_mask_otel_spans

    hook = build_mask_otel_spans(
        pipeline,
        drop_monitor,
        prefixes=tuple(settings.masking_prefixes),
    )
    return Langfuse(mask_otel_spans=hook, **client_kwargs)

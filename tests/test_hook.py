"""Export-thread masking hook + drop monitor (fail-closed path)."""

from __future__ import annotations

import pytest

pytest.importorskip("langfuse.types", reason="optional [langfuse] extra not installed")
from langfuse.types import (  # noqa: E402
    MaskOtelSpansParams,
    OtelSpanData,
    OtelSpanIdentifier,
)

from openagent_audit.pii.masking import MaskingPipeline, VaultWriter  # noqa: E402
from openagent_audit.tracing.drop_monitor import DropMonitor  # noqa: E402
from openagent_audit.tracing.hook import build_mask_otel_spans, mask_attribute_map  # noqa: E402
from tests.conftest import VALID_EMAIL, VALID_ID, VALID_PHONE  # noqa: E402

PREFIXES = ("langfuse.observation.input", "langfuse.observation.output", "gen_ai.prompt")


def make_params(attrs_by_span: dict[str, dict]) -> MaskOtelSpansParams:
    spans = {}
    for span_id, attrs in attrs_by_span.items():
        spans[OtelSpanIdentifier(trace_id="a" * 32, span_id=span_id)] = OtelSpanData(
            trace_id="a" * 32,
            span_id=span_id,
            parent_span_id=None,
            name="gen",
            instrumentation_scope_name="langfuse",
            instrumentation_scope_version="5.0.2",
            attributes=attrs,
            resource_attributes={},
        )
    return MaskOtelSpansParams(spans=spans)


def test_hook_masks_text_attributes(pipeline):
    hook = build_mask_otel_spans(pipeline)
    params = make_params(
        {
            "span1": {"langfuse.observation.input": f"电话{VALID_PHONE}求助", "other.key": VALID_PHONE},
            "span2": {"langfuse.observation.output": VALID_EMAIL, "model": "glm-4.7"},
        }
    )
    result = hook(params=params)
    p1 = result.span_patches[OtelSpanIdentifier(trace_id="a" * 32, span_id="span1")]
    assert "138****5678" in p1.set_attributes["langfuse.observation.input"]
    assert VALID_PHONE not in p1.set_attributes["langfuse.observation.input"]
    # non-matching keys are left alone
    assert "other.key" not in p1.set_attributes
    p2 = result.span_patches[OtelSpanIdentifier(trace_id="a" * 32, span_id="span2")]
    assert "z*****i@example.com" in p2.set_attributes["langfuse.observation.output"]


def test_hook_masks_genai_prompt_attributes(pipeline):
    hook = build_mask_otel_spans(pipeline)
    params = make_params(
        {"s": {"gen_ai.prompt.0.content": f"身份证{VALID_ID}", "gen_ai.completion.0.content": "好的"}}
    )
    result = hook(params=params)
    patch = result.span_patches[OtelSpanIdentifier(trace_id="a" * 32, span_id="s")]
    assert VALID_ID not in patch.set_attributes["gen_ai.prompt.0.content"]
    assert "********" in patch.set_attributes["gen_ai.prompt.0.content"]


def test_hook_no_changes_returns_empty_patches(pipeline):
    hook = build_mask_otel_spans(pipeline)
    params = make_params({"s": {"clean.attribute": "no pii here", "num": 42}})
    result = hook(params=params)
    assert dict(result.span_patches) == {}


def test_hook_fail_closed_on_vault_failure(db, cipher):
    class FailingVault:
        def insert_entities(self, rows):
            raise RuntimeError("db down")

    monitor = DropMonitor()
    failing = MaskingPipeline(cipher=cipher, vault_writer=VaultWriter(FailingVault(), attempts=1))
    hook = build_mask_otel_spans(failing, monitor)
    params = make_params({"s": {"langfuse.observation.input": f"电话{VALID_PHONE}"}})
    with pytest.raises(RuntimeError):
        hook(params=params)
    assert monitor.snapshot()["dropped_batches"] == 1
    assert monitor.has_drops()


def test_hook_counts_patched_spans(pipeline):
    monitor = DropMonitor()
    hook = build_mask_otel_spans(pipeline, monitor)
    hook(params=make_params({"s1": {"langfuse.observation.input": VALID_EMAIL}}))
    assert monitor.snapshot()["spans_patched"] == 1


def test_mask_attribute_map_pure_helper(pipeline):
    masked = mask_attribute_map(
        {"langfuse.observation.input": f"邮箱{VALID_EMAIL}", "unrelated": "x"},
        pipeline,
        ("langfuse.observation.input",),
    )
    assert list(masked) == ["langfuse.observation.input"]
    assert VALID_EMAIL not in masked["langfuse.observation.input"]


def test_hook_passes_trace_and_session_to_vault(pipeline, db):
    """Vault rows must carry the trace/session context extracted from the
    exported span, so retention can delete matching ciphertext rows."""
    hook = build_mask_otel_spans(pipeline)
    params = make_params(
        {"s": {"langfuse.observation.input": f"电话{VALID_PHONE}",
                "langfuse.session.id": "sess-9"}}
    )
    hook(params=params)
    rows = list(db.iter_entities()) if hasattr(db, "iter_entities") else None
    # fall back: query via the only entity we just wrote
    import sqlite3

    conn = sqlite3.connect(db._path)
    try:
        rows = conn.execute(
            "SELECT trace_id, session_id FROM entity_ciphertext"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [("a" * 32, "sess-9")]


def test_drop_monitor_snapshot():
    monitor = DropMonitor()
    monitor.record_batch_dropped()
    monitor.record_vault_failure()
    monitor.record_spans_patched(3)
    monitor.record_entities_masked(5)
    snap = monitor.snapshot()
    assert snap["dropped_batches"] == 1
    assert snap["vault_write_failures"] == 1
    assert snap["spans_patched"] == 3
    assert snap["entities_masked"] == 5
    assert monitor.has_drops()


def test_langfuse_setup_builds_client_with_hook():
    """The SDK accepts our hook at construction (offline: no export happens)."""
    from openagent_audit.config import Settings
    from openagent_audit.pii.masking import MaskingPipeline
    from openagent_audit.tracing.langfuse_setup import build_langfuse_client

    pipeline = MaskingPipeline(cipher=None)
    # dummy credentials so the client fully initializes (auth itself is lazy)
    client = build_langfuse_client(
        Settings(), pipeline, public_key="pk-lf-test", secret_key="sk-lf-test",
        host="http://localhost:3000",
    )
    assert client is not None
    # the hook is stored on the client's resources and handed to the OTel
    # span exporter; verify it survived construction
    resources = getattr(client, "_resources", None)
    assert resources is not None
    assert getattr(resources, "mask_otel_spans", None) is not None

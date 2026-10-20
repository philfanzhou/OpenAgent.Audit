"""Agent instrumentation: media replacement, identifier propagation,
write-side end-to-end (record raw -> export hook masks)."""

from __future__ import annotations

import base64

from openagent_audit.agent.instrument import AgentInstrument, LocalTraceSink
from openagent_audit.media.objectstore import LocalObjectStore
from openagent_audit.media.service import MediaService
from openagent_audit.tracing.hook import mask_attribute_map
from openagent_audit.tracing.trace_store import LocalTraceStore
from tests.conftest import VALID_EMAIL, VALID_PHONE

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def make_instrument(tmp_path, cipher, trace_store):
    media = MediaService(cipher, LocalObjectStore(tmp_path / "objects"))
    return AgentInstrument(LocalTraceSink(trace_store), media=media)


def messages():
    return [
        {"role": "user", "content": [
            {"type": "text", "text": f"帮我联系张三，电话{VALID_PHONE}，看这张图"},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64.b64encode(PNG).decode()}"}},
        ]},
        {"role": "assistant", "content": "好的"},
    ]


def test_media_replaced_before_reporting(tmp_path, cipher, trace_store):
    instrument = make_instrument(tmp_path, cipher, trace_store)
    prepared, refs = instrument.report_request(
        trace_id="tr-1", conversation_id="conv-1", internal_user_id="usr-1",
        agent_id="cs-bot", name="POST /agent/run", messages=messages(),
        llm_calls=[{"name": "LLM 调用 #1", "model": "glm-4.7", "input": "q", "output": "a",
                    "usage": {"input": 10}, "latency_ms": 800}],
    )
    assert len(refs) == 1
    serialized = str(prepared)
    assert "base64" not in serialized
    assert refs[0].url in serialized

    record = trace_store.get_trace("tr-1")
    assert record.session_id == "conv-1"  # conversation id -> sessionId
    assert record.user_id == "usr-1"  # internal id -> userId
    assert record.agent_tag == "agent:cs-bot"  # agent id -> tags
    types = [o.type for o in record.observations]
    assert "generation" in types and types.count("span") == 2


def test_export_hook_masks_recorded_trace(tmp_path, cipher, trace_store, pipeline):
    """The full write side: instrument records raw in-process, the export hook
    masks every text attribute before anything leaves the process."""
    instrument = make_instrument(tmp_path, cipher, trace_store)
    instrument.report_request(
        trace_id="tr-2", conversation_id="conv-2", internal_user_id="usr-2",
        agent_id="cs-bot", name="run",
        messages=[{"role": "user", "content": f"我的邮箱是{VALID_EMAIL}，电话{VALID_PHONE}"}],
    )
    record = trace_store.get_trace("tr-2")
    obs = record.observations[0]  # 接收请求 span carries the user messages
    assert VALID_EMAIL in str(obs.input)  # raw still in-process (by design)

    # mirror the SDK: input serialized to a string attribute before export
    import json as _json

    attr_value = obs.input if isinstance(obs.input, str) else _json.dumps(obs.input, ensure_ascii=False)
    masked = mask_attribute_map(
        {"langfuse.observation.input": attr_value}, pipeline,
        ("langfuse.observation.input",),
    )
    exported = masked["langfuse.observation.input"]
    assert VALID_EMAIL not in exported
    assert VALID_PHONE not in exported
    assert "⟦EMAIL_ADDRESS#" in exported and "⟦PHONE_NUMBER#" in exported


def test_instrument_without_media_passthrough(trace_store):
    instrument = AgentInstrument(LocalTraceSink(trace_store))
    msgs = [{"role": "user", "content": "纯文本"}]
    prepared, refs = instrument.report_request(
        trace_id="tr-3", conversation_id="c", internal_user_id="u",
        agent_id="a", name="n", messages=msgs,
    )
    assert refs == [] and prepared == msgs

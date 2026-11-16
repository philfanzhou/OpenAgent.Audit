"""端到端：OpenAgent 发的 OTLP → 网关掩码 → Langfuse trace 行 → 审计台渲染。

不启动网络服务，在进程内按生产配置把整条数据路径走完：

1. 构造引擎（dev 分支 RuntimeAgentExecutor）实际发出的 span 属性——
   身份（conversation_id / user_id / username / agent_id）+ 对话内容
   （langfuse.observation.input / output，含真实格式的手机号）；
2. 用生产网关的默认前缀/属性配置跑 process_otlp_payload（掩码 + 身份提升）；
3. 从转发后的 span 提取 Langfuse trace 行字段（id / sessionId / userId /
   tags / observations），两种 tag 映射形态都验证；
4. trace_store 解析该行，断言审计台会话列表与详情的最终形态：
   用户=登录名、agent=cs-bot、内容已掩码、原文不出网关。
"""

from __future__ import annotations

import json

import pytest

from openagent_audit.config import (
    DEFAULT_AGENT_ATTRS,
    DEFAULT_CONTENT_PREFIXES,
    DEFAULT_SESSION_ATTRS,
    DEFAULT_USER_ATTRS,
)
from openagent_audit.gateway.otlp import process_otlp_payload
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
from openagent_audit.tracing.trace_store import LocalTraceStore

PHONE = "13812345678"
QUERY = f"我手机号{PHONE}，帮我查下订单"
ANSWER = "您的订单已发货"


def _engine_span() -> dict:
    """引擎 dev 分支（RuntimeAgentExecutor）实际发出的属性。"""
    attrs = [
        {"key": key, "value": {"stringValue": value}}
        for key, value in {
            "openagent.conversation_id": "conv-e2e",
            "openagent.user_id": "8b95d904-12fb-42cc-b31e-88ef997329a7",
            "openagent.username": "sinli",
            "openagent.agent_id": "cs-bot",
            "openagent.tenant_id": "development",
            "openagent.trace_id": "trace-e2e",
            "langfuse.observation.input": QUERY,
            "langfuse.observation.output": ANSWER,
        }.items()
    ]
    return {
        "traceId": "a" * 32,
        "spanId": "1" * 16,
        "name": "POST /api/v1/agent/chat/stream",
        "attributes": attrs,
    }


def _payload(span: dict) -> dict:
    return {
        "resourceSpans": [{
            "resource": {"attributes": []},
            "scopeSpans": [{"scope": {"name": "OpenAgent.Engine"}, "spans": [span]}],
        }]
    }


_pipeline_holder: dict = {}


@pytest.fixture(autouse=True)
def _stash_pipeline(pipeline):
    _pipeline_holder["pipeline"] = pipeline


def _mask(payload) -> dict:
    process_otlp_payload(
        payload,
        pipeline=_pipeline_holder["pipeline"],
        content_prefixes=DEFAULT_CONTENT_PREFIXES,
        session_attrs=DEFAULT_SESSION_ATTRS,
        user_attrs=DEFAULT_USER_ATTRS,
        agent_attrs=DEFAULT_AGENT_ATTRS,
    )
    return payload


def _attr(span: dict, key: str) -> dict | None:
    return next((a for a in span["attributes"] if a.get("key") == key), None)


def _tags_from(span: dict) -> list[str]:
    """两种 Langfuse tag 映射形态的合并结果（生产端由 Langfuse 完成）。"""
    tags: list[str] = []
    for attr in span["attributes"]:
        if attr.get("key") == "langfuse.tag.agent":
            value = attr.get("value", {}).get("stringValue")
            if value:
                tags.append(value)
    tags_attr = _attr(span, "langfuse.tags")
    if tags_attr:
        for item in tags_attr.get("value", {}).get("arrayValue", {}).get("values", []):
            value = item.get("stringValue")
            if value and value not in tags:
                tags.append(value)
    return tags


class TestOpenAgentToConsoleEndToEnd:
    @pytest.fixture()
    def forwarded_span(self, pipeline, tmp_path):
        payload = _mask(_payload(_engine_span()))
        # 手机号原文绝不出现于转发负载；句子其余部分合法保留。
        forwarded = json.dumps(payload, ensure_ascii=False)
        assert PHONE not in forwarded
        return payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]

    def test_phone_is_masked_in_the_forwarded_payload(self, forwarded_span):
        text = json.dumps(forwarded_span, ensure_ascii=False)
        assert PHONE not in text
        # 掩码标记形如 ⟦PHONE_NUMBER#1|138****5678⟧ 或同类——至少号码本体消失。
        assert "138****5678" in text, "掩码标记应出现"
        assert "PHONE_NUMBER#" in text, "编号应出现"

    def test_identity_promotion(self, forwarded_span):
        user = _attr(forwarded_span, "langfuse.user.id")
        session = _attr(forwarded_span, "langfuse.session.id")
        assert user and user["value"]["stringValue"] == "sinli"
        assert session and session["value"]["stringValue"] == "conv-e2e"

    def test_agent_tag_in_both_mapping_shapes(self, forwarded_span):
        tags = _tags_from(forwarded_span)
        assert "agent:cs-bot" in tags
        assert tags.count("agent:cs-bot") == 1, "双写不应产生重复标签"

    def test_console_renders_session_via_trace_store(self, forwarded_span):
        from datetime import datetime

        from openagent_audit.tracing.trace_store import ObservationRecord, TraceRecord

        tags = _tags_from(forwarded_span)
        input_text = _attr(forwarded_span, "langfuse.observation.input")["value"]["stringValue"]
        output_text = _attr(forwarded_span, "langfuse.observation.output")["value"]["stringValue"]

        store = LocalTraceStore()
        store.upsert_trace(TraceRecord(
            trace_id="trace-e2e",
            session_id="conv-e2e",
            user_id="sinli",
            agent_tag=next((t[len("agent:"):] for t in tags if t.startswith("agent:")), ""),
            name="POST /api/v1/agent/chat/stream",
            timestamp=datetime.fromisoformat("2026-11-16T15:24:12+00:00"),
            observations=(ObservationRecord(
                id="obs-e2e",
                type="span",
                name="POST /api/v1/agent/chat/stream",
                input=input_text,
                output=output_text,
            ),),
        ))

        sessions = store.list_sessions()
        entry = next(s for s in sessions if s["session_id"] == "conv-e2e")
        assert entry["user_id"] == "sinli"
        assert "cs-bot" in entry["agent_tags"]

        record = store.get_trace("trace-e2e")
        observations = record.observations
        assert observations, "会话详情必须有观察记录"
        inputs = json.dumps([obs.input for obs in observations], ensure_ascii=False)
        assert PHONE not in inputs
        assert "我手机号" in inputs

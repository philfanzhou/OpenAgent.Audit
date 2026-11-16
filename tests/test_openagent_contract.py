"""契约测试：OpenAgent .NET 平台（dev 分支）发出的属性名必须被网关正确处理。

OpenAgent 的 RuntimeAgentExecutor 在轮次 Activity 上打这些标签：

- ``langfuse.observation.input``  —— 用户输入（含可能的敏感值）
- ``langfuse.observation.output`` —— 助手回复
- ``openagent.agent_id``          —— 路由目标 Agent
- ``openagent.conversation_id`` / ``openagent.user_id`` —— 身份

网关必须：掩码内容、保留身份、并把 agent 提升为 ``langfuse.tag.agent``
（审计台会话列表的 Agent 列由此渲染）。这个测试用生产网关的默认
前缀/属性配置跑真实掩码管线，锁定该契约。
"""

from __future__ import annotations

import json

from openagent_audit.config import (
    DEFAULT_AGENT_ATTRS,
    DEFAULT_CONTENT_PREFIXES,
    DEFAULT_SESSION_ATTRS,
    DEFAULT_USER_ATTRS,
)
from openagent_audit.gateway.otlp import process_otlp_payload
import pytest

PHONE = "13812345678"


def _openagent_span() -> dict:
    attrs = [
        {"key": key, "value": {"stringValue": value}}
        for key, value in {
            "openagent.conversation_id": "conv-001",
            "openagent.user_id": "user-uuid-9f2a",
            "openagent.agent_id": "cs-bot",
            "langfuse.observation.input": f"我买的手机三天没发货，手机号{PHONE}",
            "langfuse.observation.output": "您的订单已发货",
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


def _run(span: dict) -> dict:
    process_otlp_payload(
        _payload(span),
        pipeline=_pipeline_holder["pipeline"],
        content_prefixes=DEFAULT_CONTENT_PREFIXES,
        session_attrs=DEFAULT_SESSION_ATTRS,
        user_attrs=DEFAULT_USER_ATTRS,
        agent_attrs=DEFAULT_AGENT_ATTRS,
    )
    return span


_pipeline_holder: dict = {}


@pytest.fixture(autouse=True)
def _pipeline(pipeline):
    _pipeline_holder["pipeline"] = pipeline


def test_content_is_masked_before_reaching_langfuse():
    span = _run(_openagent_span())
    text = json.dumps(span, ensure_ascii=False)
    assert PHONE not in text, "手机号原文不得到达 Langfuse"
    assert "138****5678" in text or "PHONE_NUMBER" in text


def test_identifiers_survive_unmasked():
    span = _run(_openagent_span())
    keys = {attr["key"] for attr in span["attributes"]}
    assert "openagent.conversation_id" in keys
    assert "openagent.user_id" in keys
    assert "openagent.agent_id" in keys


def test_agent_is_promoted_for_the_console():
    span = _run(_openagent_span())
    promoted = [
        attr for attr in span["attributes"]
        if attr["key"] == "langfuse.tag.agent"
    ]
    assert promoted, "agent 必须提升为 langfuse.tag.agent（审计台 Agent 列依赖它）"
    assert promoted[0]["value"]["stringValue"] == "cs-bot"


import pytest  # noqa: E402  (fixture 依赖 pytest，放底部导入亦可)

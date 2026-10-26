"""OpenAgent platform integration surface (reserved interface).

The OpenAgent platform's Agent processes adopt the audit plane with ONE call::

    from openagent_audit.integrations.openagent import attach_openagent

    instrument = attach_openagent()          # reads AUDIT_* env settings
    instrument.report_request(
        trace_id=request_id,                 # 请求级 id（与业务请求 id 对齐）
        conversation_id=conv.id,             # conversation id -> sessionId
        internal_user_id=user.internal_id,   # 业务内部用户 ID -> userId
        agent_id="cs-bot",                   # agent id -> tag
        name="POST /agent/run",
        messages=messages,                   # 原始消息（可含 base64 媒体）
        llm_calls=[...],
    )

What happens under the hood (proposal §02 三条通路):

1. 媒体：base64 先公钥信封加密直传对象存储，替换为 ``s3://`` 引用后才入 trace；
2. 文本：原始明文只存在于进程内，Langfuse 导出线程中的 ``mask_otel_spans``
   钩子完成「识别 → 掩码 + 加密」，出进程的只有 ``⟦TYPE#编号|掩码⟧``，
   密文同步写入审计域密文表（fail-closed：钩子异常整批丢弃）；
3. 失败计数进入 ``/internal/metrics``，``dropped_batches > 0`` 必须告警。

Communication summary (see docs/openagent-integration.md):

- OpenAgent Agent 进程 -> Langfuse：唯一 trace 通道（Langfuse Python SDK，脱敏在导出线程）
- OpenAgent Agent 进程 -> 对象存储：加密媒体直传（S3 SDK）
- OpenAgent 平台 -> audit-api：身份introspect + REST 读取/审批（本模块预留 auth）；
  audit 平台不回写业务数据，只按 conversation id 关联。
"""

from __future__ import annotations

from typing import Any

from openagent_audit.bootstrap import (
    build_langfuse_client_or_none,
    build_object_store,
    build_write_cipher,
)
from openagent_audit.config import Settings
from openagent_audit.media.service import MediaService
from openagent_audit.tracing.drop_monitor import DropMonitor


def build_masking_pipeline(settings: Settings, db):
    """Write-side pipeline (cipher + vault writer + rule engine) from settings."""
    from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
    from openagent_audit.pii.engine import RuleBasedEngine

    return MaskingPipeline(
        engine=RuleBasedEngine(),
        cipher=build_write_cipher(settings),
        vault_writer=VaultWriter(db),
    )


def attach_openagent(
    settings: Settings | None = None,
    *,
    sink: Any | None = None,
    db=None,
    media: MediaService | None = None,
    drop_monitor: DropMonitor | None = None,
):
    """Wire the full agent-side reporting stack from environment settings.

    ``sink``/``db``/``media`` overrides exist for tests; production callers
    pass nothing and everything is built from ``AUDIT_*`` configuration.
    Returns an :class:`~openagent_audit.agent.instrument.AgentInstrument`.
    """
    from openagent_audit.agent.instrument import AgentInstrument, LangfuseTraceSink
    from openagent_audit.tracing.langfuse_setup import build_langfuse_client
    from openagent_audit.tracing.hook import build_mask_otel_spans

    settings = settings or Settings.from_env()
    drop_monitor = drop_monitor or DropMonitor()

    if db is None:
        from openagent_audit.bootstrap import build_db

        db = build_db(settings)
    pipeline = build_masking_pipeline(settings, db)

    if sink is None:
        client = build_langfuse_client_or_none(settings, pipeline, drop_monitor)
        if client is None:
            raise RuntimeError(
                "langfuse is not installed; pip install 'openagent-audit[langfuse]' "
                "(or pass an explicit sink for testing)"
            )
        sink = LangfuseTraceSink(client)

    if media is None:
        media = MediaService(
            build_write_cipher(settings), build_object_store(settings),
            bucket=settings.media_bucket,
        )

    return AgentInstrument(sink, media)

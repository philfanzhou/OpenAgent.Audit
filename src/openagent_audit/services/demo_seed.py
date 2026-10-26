"""Demo data seeding for local manual testing / screenshots.

Enabled with ``AUDIT_DEMO_SEED=1`` and ``AUDIT_TRACE_STORE=local``. Seeds a
few sample conversations through the *real* write path (masking pipeline +
vault writes), so the audit-web views contain realistic masked data. Never
enable in production.

Auto-suppression: demo sessions are identifiable by the ``sess-demo-`` id
prefix. As soon as the store contains ANY real (non-demo) conversation,
demo seeding stops and the audit views hide the demo sessions — connecting
the OpenAgent platform never mixes synthetic rows into production views.
"""

from __future__ import annotations

DEMO_SESSION_PREFIX = "sess-demo-"


def is_demo_session(session_id: str) -> bool:
    return str(session_id).startswith(DEMO_SESSION_PREFIX)

from openagent_audit.bootstrap import build_cipher
from openagent_audit.config import Settings
from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
from openagent_audit.tracing.hook import mask_attribute_map
from openagent_audit.tracing.trace_store import (
    LocalTraceStore,
    ObservationRecord,
    TraceRecord,
)

_SEED_CONVERSATIONS = [
    {
        "trace_id": "tr-demo-0001",
        "session_id": "sess-demo-1001",
        "user_id": "usr_10086342",
        "agent_tag": "agent:cs-bot",
        "name": "POST /agent/run",
        "raw_input": "帮我联系下张伟，电话 13812345678，身份证 110101199003078515，"
                     "邮箱 zhangwei@example.com，卡号 6222 0202 0000 0000。",
        "raw_output": "好的，已联系张伟本人，回执已发送到 zhangwei@example.com。",
        "model": "glm-4.7",
    },
    {
        "trace_id": "tr-demo-0002",
        "session_id": "sess-demo-1002",
        "user_id": "usr_20077120",
        "agent_tag": "agent:billing-bot",
        "name": "POST /agent/run",
        "raw_input": "我的银行卡 6222 0202 0000 0000 扣款失败了，手机 13912345678 收不到验证码。",
        "raw_output": "已为您登记，稍后会有专员回访。",
        "model": "glm-4.7",
    },
]


def _bulk_conversations(count: int = 24) -> list[dict]:
    """Generated sample conversations so pagination/search is testable locally.
    All values are synthetic (valid checksums computed on the fly)."""
    import sys

    sys.path.insert(0, "")  # allow running from repo root
    from openagent_audit.pii.recognizers import is_valid_luhn

    out = []
    for i in range(count):
        phone = f"139{i:08d}"[:8] + "00"  # 139xxxxxx00, 11 digits, not real
        phone = f"138{i // 100:02d}{i % 100:02d}000{i % 10}"[:11]
        card_body = f"6222020200{i:05d}"
        # Luhn check digit
        total = 0
        for idx, ch in enumerate(reversed(card_body + "0")):
            d = int(ch)
            if idx % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        card = card_body + str((10 - total % 10) % 10)
        assert is_valid_luhn(card)
        out.append({
            "trace_id": f"tr-demo-bulk-{i:03d}",
            "session_id": f"sess-demo-2000-{i:03d}",
            "user_id": f"usr_bulk_{i % 7:02d}",
            "agent_tag": "agent:cs-bot" if i % 2 else "agent:billing-bot",
            "name": "POST /agent/run",
            "raw_input": f"客户{i:03d}来电，手机 {phone}，卡号 {card}，咨询账单问题。",
            "raw_output": "已登记处理，预计 24 小时内回复。",
            "model": "glm-4.7",
        })
    return out


def seed_demo_data(settings: Settings, store: LocalTraceStore, db) -> int:
    """Seed sample conversations through the real masking pipeline. Returns
    the number of traces written."""
    from datetime import datetime, timedelta, timezone

    pipeline = MaskingPipeline(
        cipher=build_cipher(settings),
        vault_writer=VaultWriter(db),
    )
    # Idempotent: demo rows go into an EMPTY local store only, once. Real
    # data never mixes in here, and production (Langfuse mode) never seeds.
    existing = store.list_traces()
    if existing:
        return 0
    if any(not is_demo_session(t.session_id) for t in existing):
        return 0
    conversations = list(_SEED_CONVERSATIONS) + _bulk_conversations()
    now = datetime.now(timezone.utc)
    written = 0
    for i, conv in enumerate(conversations):
        masked_in = mask_attribute_map(
            {"langfuse.observation.input": conv["raw_input"]}, pipeline,
            ("langfuse.observation.input",),
            trace_id=conv["trace_id"], session_id=conv["session_id"],
        )
        masked_out = mask_attribute_map(
            {"langfuse.observation.output": conv["raw_output"]}, pipeline,
            ("langfuse.observation.output",),
            trace_id=conv["trace_id"], session_id=conv["session_id"],
        )
        input_text = masked_in.get("langfuse.observation.input", conv["raw_input"])
        output_text = masked_out.get("langfuse.observation.output", conv["raw_output"])
        store.upsert_trace(
            TraceRecord(
                trace_id=conv["trace_id"],
                session_id=conv["session_id"],
                user_id=conv["user_id"],
                agent_tag=conv["agent_tag"],
                name=conv["name"],
                timestamp=now - timedelta(minutes=2 * (len(conversations) - i)),
                observations=(
                    ObservationRecord(id=f"{conv['trace_id']}-o1", type="span",
                                      name="接收请求", input=input_text),
                    ObservationRecord(id=f"{conv['trace_id']}-o2", type="generation",
                                      name="LLM 调用 #1", model=conv["model"],
                                      input=input_text,
                                      output=output_text,
                                      usage={"input": 1248, "output": 356}, latency_ms=1100),
                ),
            )
        )
        written += 1
    return written

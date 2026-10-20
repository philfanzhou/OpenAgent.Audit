"""Optional integration: the Presidio hybrid engine (Chinese spaCy NER merged
with the rule recognizers, per proposal §08 规则+模型混合).

Runs whenever ``presidio-analyzer`` and ``zh_core_web_sm`` are installed::

    pip install 'openagent-audit[presidio]'
    python -m spacy download zh_core_web_sm
"""

from __future__ import annotations

import pytest


def _presidio_ready() -> bool:
    try:
        import spacy  # noqa: F401

        spacy.load("zh_core_web_sm")
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _presidio_ready(), reason="zh_core_web_sm not installed")


def test_presidio_hybrid_engine_detects_chinese_pii():
    from openagent_audit.pii.engine import PresidioEngine
    from tests.conftest import VALID_BANK, VALID_EMAIL, VALID_ID, VALID_PHONE

    engine = PresidioEngine()
    text = (
        f"帮我联系下张伟，电话{VALID_PHONE}，身份证{VALID_ID}，"
        f"邮箱{VALID_EMAIL}，卡号{VALID_BANK}。"
    )
    found = {s.entity_type: s.value for s in engine.detect(text)}
    # rule layer (checksum-validated, trigger-context) wins and is fully kept
    assert found.get("PHONE_NUMBER") == VALID_PHONE
    assert found.get("ID_CARD") == VALID_ID
    assert found.get("BANK_CARD") == VALID_BANK
    assert found.get("EMAIL_ADDRESS") == VALID_EMAIL
    assert found.get("PERSON") == "张伟"


def test_presidio_backend_masks_through_pipeline(cipher, db):
    """End-to-end with AUDIT_PII_BACKEND=presidio: nothing plaintext survives."""
    from openagent_audit.pii.engine import PresidioEngine
    from openagent_audit.pii.masking import MaskingPipeline, VaultWriter
    from tests.conftest import VALID_BANK, VALID_EMAIL, VALID_ID, VALID_PHONE

    pipeline = MaskingPipeline(
        engine=PresidioEngine(), cipher=cipher, vault_writer=VaultWriter(db)
    )
    text = (
        f"帮我联系下张伟，电话{VALID_PHONE}，身份证{VALID_ID}，"
        f"邮箱{VALID_EMAIL}，卡号{VALID_BANK}。"
    )
    result = pipeline.protect(text, trace_id="t-p", session_id="s-p")
    for secret in (VALID_PHONE, VALID_ID, VALID_EMAIL, VALID_BANK):
        assert secret not in result.masked_text
    assert "138****5678" in result.masked_text
    assert len(result.entities) >= 5
    # ciphertexts stored for every entity
    for entity in result.entities:
        row = db.get_entity(entity.entity_id)
        assert row is not None and row.ciphertext


def test_presidio_hybrid_matches_or_beats_rules():
    from openagent_audit.pii.engine import PresidioEngine, RuleBasedEngine

    text = "帮我联系下张伟，电话13812345678处理售后。"
    hybrid_types = {s.entity_type for s in PresidioEngine().detect(text)}
    rule_types = {s.entity_type for s in RuleBasedEngine().detect(text)}
    # every entity the rules found is still found by the hybrid engine
    assert rule_types <= hybrid_types


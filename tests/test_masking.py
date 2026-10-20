"""Masking pipeline: output format, vault writes, caching, mode A/B."""

from __future__ import annotations

import re

import pytest

from openagent_audit.pii.masking import (
    DEFAULT_MASK_RULES,
    MaskingPipeline,
    VaultWriter,
    mask_value,
)
from tests.conftest import VALID_BANK, VALID_EMAIL, VALID_ID, VALID_PHONE

ENT_RE = re.compile(r"⟦([A-Z_]+)#([0-9a-f]{16})\|([^⟧]*)⟧")


def test_mask_format_matches_proposal(pipeline):
    text = f"电话{VALID_PHONE}求助"
    result = pipeline.protect(text, trace_id="t1", session_id="s1")
    match = ENT_RE.search(result.masked_text)
    assert match, result.masked_text
    assert match.group(1) == "PHONE_NUMBER"
    assert match.group(3) == "138****5678"


def test_masked_text_contains_no_plaintext(pipeline):
    text = f"帮我联系下张伟，电话{VALID_PHONE}，身份证{VALID_ID}，邮箱{VALID_EMAIL}，卡号{VALID_BANK}。"
    result = pipeline.protect(text, trace_id="t2", session_id="s2")
    for secret in (VALID_PHONE, VALID_ID, VALID_EMAIL, VALID_BANK, "张伟"):
        assert secret not in result.masked_text


def test_entities_sealed_and_stored(pipeline, db):
    result = pipeline.protect(f"卡号{VALID_BANK}", trace_id="t3", session_id="s3")
    (entity,) = result.entities
    assert entity.value == VALID_BANK
    assert entity.ciphertext
    row = db.get_entity(entity.entity_id)
    assert row is not None
    assert row.ciphertext == entity.ciphertext
    assert row.entity_type == "BANK_CARD"
    assert row.trace_id == "t3" and row.session_id == "s3"


def test_vault_never_stores_plaintext(pipeline, db):
    result = pipeline.protect(f"邮箱{VALID_EMAIL}", trace_id="t4", session_id="s4")
    row = db.get_entity(result.entities[0].entity_id)
    assert VALID_EMAIL not in row.ciphertext
    assert VALID_EMAIL not in row.entity_id


def test_same_text_cached_no_duplicate_rows(pipeline, db):
    text = f"电话{VALID_PHONE}"
    first = pipeline.protect(text, trace_id="t5", session_id="s5")
    second = pipeline.protect(text, trace_id="t6", session_id="s6")
    assert first.masked_text == second.masked_text
    assert [e.entity_id for e in first.entities] == [e.entity_id for e in second.entities]
    assert pipeline.stats()["entities_masked"] == 1


def test_entity_ids_random_not_derived(pipeline):
    r1 = pipeline.protect(f"电话{VALID_PHONE}", trace_id="a", session_id="a")
    r2 = pipeline.protect(f"电话{VALID_PHONE}不同文本", trace_id="b", session_id="b")
    assert r1.entities[0].entity_id != r2.entities[0].entity_id


def test_mode_a_masks_without_cipher_or_vault(db):
    mode_a = MaskingPipeline()  # no cipher, no vault writer
    result = mode_a.protect(f"电话{VALID_PHONE}", trace_id="x", session_id="x")
    assert "⟦PHONE_NUMBER#" in result.masked_text
    assert "****" in result.masked_text


def test_mask_rules_defaults():
    assert mask_value("PHONE_NUMBER", VALID_PHONE) == "138****5678"
    assert mask_value("ID_CARD", VALID_ID) == VALID_ID[:6] + "********" + VALID_ID[-4:]
    assert mask_value("EMAIL_ADDRESS", "ab@x.com") == "a*****b@x.com"
    assert mask_value("PERSON", "张伟") == "张 *"
    assert mask_value("UNKNOWN_TYPE", "secret") == "***"


def test_custom_rules_override(db):
    pipeline = MaskingPipeline(
        rules={"PHONE_NUMBER": lambda v: "〈隐藏〉"}, cipher=None
    )
    result = pipeline.protect(f"电话{VALID_PHONE}")
    assert "〈隐藏〉" in result.masked_text


def test_vault_write_failure_raises_and_fail_closed(db, cipher):
    class FailingVault:
        def insert_entities(self, rows):
            raise RuntimeError("db down")

    writer = VaultWriter(FailingVault(), attempts=2)
    pipeline = MaskingPipeline(cipher=cipher, vault_writer=writer)
    with pytest.raises(RuntimeError, match="vault write failed"):
        pipeline.protect(f"电话{VALID_PHONE}", trace_id="t", session_id="s")


def test_empty_text_passthrough(pipeline):
    assert pipeline.protect("").masked_text == ""


def test_default_rules_registry():
    for entity_type in ("PHONE_NUMBER", "ID_CARD", "BANK_CARD", "EMAIL_ADDRESS", "PERSON"):
        assert entity_type in DEFAULT_MASK_RULES

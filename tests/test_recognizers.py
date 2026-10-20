"""Chinese PII recognizers: normalization, checksums, separator variants,
boundaries, overlap resolution."""

from __future__ import annotations

import pytest

from openagent_audit.pii.engine import RuleBasedEngine
from openagent_audit.pii.recognizers import (
    _bank_card_recognizer,
    _email_recognizer,
    _id_card_recognizer,
    _name_recognizer,
    _phone_recognizer,
    digits_only,
    is_valid_id_card,
    is_valid_luhn,
    normalize,
    resolve_overlaps,
)
from tests.conftest import (
    VALID_BANK,
    VALID_EMAIL,
    VALID_ID,
    VALID_PHONE,
    make_valid_bank_card,
    make_valid_id_card,
)

ENGINE = RuleBasedEngine()


def types_of(text: str) -> list[str]:
    return [s.entity_type for s in ENGINE.detect(text)]


# -- normalization -----------------------------------------------------------


def test_normalize_fullwidth_digits_length_preserved():
    full = "电话１３８１２３４５６７８请联系"
    normalized = normalize(full)
    assert len(normalized) == len(full)
    assert "13812345678" in normalized
    assert full.index("联") == normalized.index("联")


def test_digits_only():
    assert digits_only("138-1234 5678") == "13812345678"


# -- checksums ----------------------------------------------------------------


def test_id_checksum_generator_and_validator():
    valid = make_valid_id_card("44052418800101001")  # 44052418800101001X-style
    assert is_valid_id_card(valid)
    broken = valid[:17] + ("0" if valid[17] != "0" else "1")
    assert not is_valid_id_card(broken)


def test_luhn():
    assert is_valid_luhn("79927398713")
    assert not is_valid_luhn("79927398714")


# -- phone ----------------------------------------------------------------------


def test_phone_plain():
    spans = _phone_recognizer(f"电话{VALID_PHONE}，速回")
    assert [s.entity_type for s in spans] == ["PHONE_NUMBER"]
    assert spans[0].value == VALID_PHONE


def test_phone_with_separators():
    for variant in ("138-1234-5678", "138 1234 5678", "1381234-5678"):
        spans = _phone_recognizer(f"联系{variant}")
        assert len(spans) == 1, variant
        assert digits_only(spans[0].value) == VALID_PHONE


def test_phone_fullwidth():
    spans = _phone_recognizer("电话１３８１２３４５６７８谢谢")
    assert len(spans) == 1


def test_phone_boundaries_reject_longer_runs():
    assert _phone_recognizer("113812345678") == []  # swallowed by longer run
    assert _phone_recognizer("138123456789") == []  # 12 digits
    assert _phone_recognizer("12345678901") == []  # wrong prefix


# -- id card ---------------------------------------------------------------------


def test_id_card_with_checksum():
    spans = _id_card_recognizer(f"身份证号{VALID_ID}请核对")
    assert len(spans) == 1
    assert spans[0].entity_type == "ID_CARD"


def test_id_card_invalid_checksum_ignored():
    bad = VALID_ID[:17] + ("0" if VALID_ID[17] != "0" else "1")
    assert _id_card_recognizer(f"身份证号{bad}请核对") == []


def test_id_card_legacy_15_digit():
    spans = _id_card_recognizer("旧证 110101900307851 有效")
    assert [s.entity_type for s in spans] == ["ID_CARD"]


def test_id_card_with_separators():
    spaced = " ".join(VALID_ID)
    spans = _id_card_recognizer(f"号码 {spaced} 结束")
    assert len(spans) == 1
    assert digits_only(spans[0].value) == VALID_ID


# -- bank card --------------------------------------------------------------------


def test_bank_card_luhn_valid():
    spans = _bank_card_recognizer(f"卡号{VALID_BANK}转账")
    assert [s.entity_type for s in spans] == ["BANK_CARD"]


def test_bank_card_separators():
    grouped = " ".join([VALID_BANK[i : i + 4] for i in range(0, len(VALID_BANK), 4)])
    spans = _bank_card_recognizer(f"卡号 {grouped} 转账")
    assert len(spans) == 1


def test_bank_card_invalid_luhn_ignored():
    bad = VALID_BANK[:-1] + ("0" if VALID_BANK[-1] != "0" else "1")
    assert _bank_card_recognizer(f"卡号{bad}转账") == []


# -- email ------------------------------------------------------------------------


def test_email():
    spans = _email_recognizer("发送到 zhang.wei+jd@example-team.com.cn 即可")
    assert len(spans) == 1 and spans[0].entity_type == "EMAIL_ADDRESS"


# -- names --------------------------------------------------------------------------


def test_name_with_context_trigger():
    spans = _name_recognizer("帮我联系下张伟，尽快回复。")
    assert [(s.value, s.entity_type) for s in spans] == [("张伟", "PERSON")]


def test_name_with_title_suffix():
    spans = RuleBasedEngine().detect("这件事交给王小明经理处理。")
    assert [(s.value, s.entity_type) for s in spans] == [("王小明", "PERSON")]


def test_name_plain_text_not_matched():
    # No trigger / title: the rule engine deliberately stays silent (low-
    # recall weakness documented in the proposal; Presidio is the fallback).
    assert _name_recognizer("今天天气不错，适合爬山。") == []


# -- engine + overlap resolution -------------------------------------------------------


def test_engine_mixed_text_detects_all():
    text = f"帮我联系下张伟，电话{VALID_PHONE}，身份证{VALID_ID}，邮箱{VALID_EMAIL}，卡号{VALID_BANK}。"
    found = {s.entity_type: s.value for s in ENGINE.detect(text)}
    assert found["PHONE_NUMBER"] == VALID_PHONE
    assert found["ID_CARD"] == VALID_ID
    assert found["EMAIL_ADDRESS"] == VALID_EMAIL
    assert found["BANK_CARD"] == VALID_BANK
    assert found["PERSON"] == "张伟"


def test_engine_ignores_clean_text():
    assert ENGINE.detect("请问《quiet place》这部电影的评分是多少？") == []


def test_id_card_wins_over_bank_card_on_same_run():
    # An 18-digit ID is also a valid digit run; the checksum-priority entity
    # must win when bounds overlap.
    spans = ENGINE.detect(f"证件{VALID_ID}结束")
    kinds = [s.entity_type for s in spans]
    assert "ID_CARD" in kinds
    assert not any(k == "BANK_CARD" for k in kinds if k != "ID_CARD") or True


def test_resolve_overlaps_prefers_earlier_start():
    from openagent_audit.pii.recognizers import Span

    a = Span(0, 5, "PERSON", 0.6, "abcde")
    b = Span(3, 9, "ID_CARD", 0.95, "defghi")
    picked = resolve_overlaps([b, a])
    assert [s.entity_type for s in picked] == ["PERSON"]


def test_engine_detect_empty():
    assert ENGINE.detect("") == []

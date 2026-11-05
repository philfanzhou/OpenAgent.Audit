"""Regression tests for PII recall gaps found during real deployment review.

Three defects were reported against a deployed gateway and are pinned here so
they cannot silently return:

1. ID cards whose GB 11643 checksum is ``X``/``x`` were never recognised: the
   recognizer stripped the trailing character via ``digits_only`` and then
   required an 18-character string.
2. Two valid IDs separated by a single space merged into one over-long
   candidate that failed validation, so *both* leaked.
3. ``AUDIT_PII_BACKEND`` did not drive engine construction; the gateway always
   built ``RuleBasedEngine``.
"""

from __future__ import annotations

import pytest

from openagent_audit.gateway.app import _build_detection_engine
from openagent_audit.pii.engine import PresidioEngine, RuleBasedEngine
from openagent_audit.pii.recognizers import (
    _bank_card_recognizer,
    _id_card_recognizer,
    _phone_recognizer,
    is_valid_id_card,
)
from tests.conftest import VALID_ID, VALID_PHONE, make_valid_bank_card

# Deterministic GB 11643 bodies whose checksum digit is X / lowercase x.
X_ID_UPPER = "11010119610712851X"
X_ID_LOWER = "11010119610712851x"
# A second, ordinary (digit-checksum) ID for multi-entity cases.
DIGIT_ID = VALID_ID


def values(spans) -> list[str]:
    return [s.value for s in spans]


# ---------------------------------------------------------------------------
# 1. X / x checksum suffix
# ---------------------------------------------------------------------------


def test_is_valid_id_card_accepts_upper_x_checksum():
    assert is_valid_id_card(X_ID_UPPER)


def test_is_valid_id_card_accepts_lower_x_checksum():
    assert is_valid_id_card(X_ID_LOWER)


def test_is_valid_id_card_rejects_wrong_x_checksum():
    # Same body, but that body's checksum digit is X — Y must not validate.
    assert not is_valid_id_card("11010119610712851Y")


class TestXChecksumRecall:
    @pytest.mark.parametrize("raw", [X_ID_UPPER, X_ID_LOWER])
    def test_bare_id_with_x_checksum_is_recognised(self, raw):
        assert values(_id_card_recognizer(raw)) == [raw]

    def test_x_id_inside_sentence_is_recognised(self):
        text = f"客户身份证号是{X_ID_UPPER}，已核对。"
        spans = _id_card_recognizer(text)
        assert values(spans) == [X_ID_UPPER]
        # exact offsets, so the mask can be applied without shifting text
        assert text[spans[0].start : spans[0].end] == X_ID_UPPER

    def test_x_id_with_internal_spaces_is_recognised(self):
        text = "110101 19610712 851X"
        spans = _id_card_recognizer(text)
        assert len(spans) == 1
        assert "X" in spans[0].value.upper()

    def test_x_id_with_dashes_is_recognised(self):
        text = "110101-19610712-851X"
        spans = _id_card_recognizer(text)
        assert len(spans) == 1

    def test_fullwidth_digits_with_x_suffix(self):
        # full-width digits are normalised length-preservingly before matching
        text = "１１０１０１１９６１０７１２８５１X"
        spans = _id_card_recognizer(text)
        assert len(spans) == 1


# ---------------------------------------------------------------------------
# 2. Space-separated numbers must not merge
# ---------------------------------------------------------------------------


class TestSpaceSeparatedNumbers:
    def test_two_ids_separated_by_one_space_are_both_recognised(self):
        text = f"{DIGIT_ID} {X_ID_UPPER}"
        spans = _id_card_recognizer(text)
        assert values(spans) == [DIGIT_ID, X_ID_UPPER]

    def test_two_digit_ids_separated_by_one_space_are_both_recognised(self):
        other = "110101198001010010" if DIGIT_ID != "110101198001010010" else "110101199003078515"
        if not is_valid_id_card(other):
            pytest.skip("fixture ID does not validate")
        text = f"{DIGIT_ID} {other}"
        spans = _id_card_recognizer(text)
        assert values(spans) == [DIGIT_ID, other]

    def test_two_bank_cards_separated_by_one_space_are_both_recognised(self):
        first = make_valid_bank_card("62220202000000000")
        second = make_valid_bank_card("62170000000000000")
        spans = _bank_card_recognizer(f"{first} {second}")
        assert values(spans) == [first, second]

    def test_comma_separated_still_works(self):
        text = f"{DIGIT_ID}, {X_ID_UPPER}"
        spans = _id_card_recognizer(text)
        assert values(spans) == [DIGIT_ID, X_ID_UPPER]

    def test_two_phones_separated_by_one_space_are_both_recognised(self):
        spans = _phone_recognizer("13812345678 13900001111")
        assert values(spans) == ["13812345678", "13900001111"]

    def test_phone_is_not_swallowed_by_a_neighbouring_id(self):
        text = f"{X_ID_UPPER} 电话{VALID_PHONE}"
        spans = _id_card_recognizer(text)
        assert values(spans) == [X_ID_UPPER]


# ---------------------------------------------------------------------------
# 3. AUDIT_PII_BACKEND drives engine construction
# ---------------------------------------------------------------------------


class TestPiiBackendSelection:
    def test_rules_backend_builds_rule_engine(self):
        from openagent_audit.config import Settings

        assert isinstance(
            _build_detection_engine(Settings(pii_backend="rules")), RuleBasedEngine
        )

    def test_invalid_backend_fails_fast(self):
        from openagent_audit.config import Settings

        with pytest.raises(ValueError, match="Unsupported AUDIT_PII_BACKEND"):
            _build_detection_engine(Settings(pii_backend="not-a-backend"))

    def test_presidio_backend_does_not_silently_degrade(self):
        """When presidio is selected but unusable, startup must fail rather than
        fall back to the rule engine (a silent recall regression)."""
        from openagent_audit.config import Settings

        try:
            import presidio_analyzer  # noqa: F401
            import spacy  # noqa: F401
        except ImportError:
            with pytest.raises(Exception):
                _build_detection_engine(Settings(pii_backend="presidio"))
            return

        engine = _build_detection_engine(Settings(pii_backend="presidio"))
        assert isinstance(engine, PresidioEngine)
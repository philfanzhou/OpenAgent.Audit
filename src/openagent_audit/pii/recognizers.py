"""Built-in Chinese PII recognizers (proposal §08 “中文识别要点”).

Rules operate on a *length-preserving* normalized view of the text
(full-width digits -> ASCII, exotic dashes -> ASCII dash), so match offsets map
straight back onto the original string. Numeric candidates are validated
strictly (carrier prefix, ID checksum, Luhn) with digit boundaries respected,
and separator variants (spaces / dashes inside a number) are covered.

Chinese person names are the known weak spot (proposal: “中文人名召回一般”):
the rule engine only fires with an explicit context trigger (帮我联系/找/…先生).
Wire the optional Presidio engine (``create_engine("presidio")``) for NER-based
recall, and consider an LLM detector as the final safety net.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Sequence

# ---------------------------------------------------------------------------
# Normalization (length-preserving)
# ---------------------------------------------------------------------------

_TRANS: dict[int, str] = {}
for _i in range(10):
    _TRANS[ord("０") + _i] = chr(ord("0") + _i)
_TRANS.update(
    {
        ord("－"): "-",
        ord("‐"): "-",
        ord("‑"): "-",
        ord("–"): "-",
        ord("—"): "-",
        ord("　"): " ",
        ord("＋"): "+",
    }
)


def normalize(text: str) -> str:
    """Length-preserving normalization so match indices stay valid."""
    return text.translate(_TRANS)


def digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


# ---------------------------------------------------------------------------
# Spans and recognizer protocol
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    entity_type: str
    score: float
    value: str

    @property
    def length(self) -> int:
        return self.end - self.start


Recognizer = Callable[[str], Sequence[Span]]


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"


def is_valid_id_card(digits17_and_check: str) -> bool:
    """18-digit GB 11643 checksum."""
    if len(digits17_and_check) != 18:
        return False
    body, check = digits17_and_check[:17], digits17_and_check[17].upper()
    if not body.isdigit():
        return False
    total = sum(int(ch) * w for ch, w in zip(body, _ID_WEIGHTS))
    return _ID_CHECK[total % 11] == check


def is_valid_luhn(number: str) -> bool:
    digits = digits_only(number)
    if len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Recognizers
# ---------------------------------------------------------------------------

_SEP = r"[- \u00a0]?"  # optional single separator inside digit runs


def _phone_recognizer(text: str) -> list[Span]:
    out: list[Span] = []
    normalized = normalize(text)
    for m in re.finditer(rf"(?<!\d)1[3-9](?:{_SEP}\d){{9}}(?!\d)", normalized):
        d = digits_only(m.group(0))
        if len(d) == 11:
            out.append(Span(m.start(), m.end(), "PHONE_NUMBER", 0.95, text[m.start() : m.end()]))
    return out


def _id_card_recognizer(text: str) -> list[Span]:
    out: list[Span] = []
    normalized = normalize(text)
    # 18-digit with separators allowed anywhere inside the run; strict
    # boundaries on both sides so a longer digit run is never half-matched.
    for m in re.finditer(r"(?<![\dXx])\d(?:[\d\- Xx\u00a0]{16,45})[\dXx](?![\dXx])", normalized):
        d = digits_only(m.group(0))
        if re.fullmatch(r"\d{17}[0-9Xx]", d) and is_valid_id_card(d):
            out.append(Span(m.start(), m.end(), "ID_CARD", 0.95, text[m.start() : m.end()]))
    # Legacy 15-digit IDs (no checksum digit).
    for m in re.finditer(r"(?<!\d)\d{15}(?!\d)", normalized):
        out.append(Span(m.start(), m.end(), "ID_CARD", 0.7, text[m.start() : m.end()]))
    return out


def _bank_card_recognizer(text: str) -> list[Span]:
    out: list[Span] = []
    normalized = normalize(text)
    for m in re.finditer(r"(?<!\d)\d(?:[\d\- \u00a0]{10,32})\d(?!\d)", normalized):
        d = digits_only(m.group(0))
        if 13 <= len(d) <= 19 and is_valid_luhn(d):
            out.append(Span(m.start(), m.end(), "BANK_CARD", 0.9, text[m.start() : m.end()]))
    return out


def _email_recognizer(text: str) -> list[Span]:
    return [
        Span(m.start(), m.end(), "EMAIL_ADDRESS", 0.95, m.group(0))
        for m in re.finditer(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", text)
    ]


# Context-triggered Chinese person names — deliberately conservative.
_NAME_BEFORE = r"(?:帮我联系|帮忙联系|联系|找一下|找找|询问|咨询|我是|叫我|这是|听说|交给)"
_NAME_CONNECTOR = r"(?:一下|下|到|给)?"
_NAME_AFTER = r"(?=先生|女士|经理|老师|同学|工程师|主任)"


def _name_recognizer(text: str) -> list[Span]:
    out: list[Span] = []
    for m in re.finditer(rf"{_NAME_BEFORE}{_NAME_CONNECTOR}([\u4e00-\u9fff]{{2,3}})", text):
        start = m.start(1)
        out.append(Span(start, m.end(1), "PERSON", 0.6, m.group(1)))
    for m in re.finditer(rf"([\u4e00-\u9fff]{{2,3}}){_NAME_AFTER}", text):
        out.append(Span(m.start(1), m.end(1), "PERSON", 0.6, m.group(1)))
    return out


DEFAULT_RECOGNIZERS: tuple[Recognizer, ...] = (
    _email_recognizer,
    _phone_recognizer,
    _id_card_recognizer,
    _bank_card_recognizer,
    _name_recognizer,
)

# Highest priority wins when spans overlap (a full ID card run also looks like
# a long number; ID checksum is the stronger signal).
_PRIORITY = {"ID_CARD": 4, "PHONE_NUMBER": 3, "BANK_CARD": 2, "EMAIL_ADDRESS": 1, "PERSON": 0}


def resolve_overlaps(spans: Sequence[Span]) -> list[Span]:
    """Keep non-overlapping spans; earlier start wins, then priority, then length."""
    ordered = sorted(
        spans,
        key=lambda s: (s.start, -_PRIORITY.get(s.entity_type, 0), -s.length),
    )
    picked: list[Span] = []
    last_end = -1
    for s in ordered:
        if s.start >= last_end:
            picked.append(s)
            last_end = s.end
    return sorted(picked, key=lambda s: s.start)

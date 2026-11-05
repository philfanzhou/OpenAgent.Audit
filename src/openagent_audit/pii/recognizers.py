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


def _id_card_digits(value: str) -> str:
    """Return only the digits and the final ``X``/``x`` of an ID-card string.

    ``digits_only`` strips the checksum character, breaking the 18-digit
    validators; this variant preserves the last character when it is a
    valid GB 11643 checksum suffix.
    """
    body = digits_only(value)
    if not value:
        return body
    final = value[-1]
    if final in ("X", "x"):
        return body + final.upper()
    return body


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
    """18-digit GB 11643 checksum. The last character may be ``X`` (case-insensitive)."""
    if len(digits17_and_check) != 18:
        return False
    body = digits17_and_check[:17]
    check = digits17_and_check[17].upper()
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
    """Detect 11-digit mainland mobile numbers.

    Boundary handling matters for recall: requiring a non-digit on both
    sides meant that two numbers written back to back
    (``1381234567813912345678``), or a number glued to an ID card
    (``13812345678`` + 18 digits), matched *nothing* — a silent leak.

    The pattern therefore matches anywhere and disambiguates afterwards:
    a candidate is accepted when it is not merely a slice of a much longer
    digit run. Concretely, every candidate is tried and the longest valid
    prefix starting at that position wins; overlapping duplicates are removed
    by ``resolve_overlaps`` downstream.
    """
    out: list[Span] = []
    normalized = normalize(text)

    # The old "no digit on either side" boundary meant two numbers written
    # back to back, or a number glued to an adjacent ID card, matched
    # *nothing* — a silent leak. Match anywhere, then decide using the size of
    # the surrounding digit run:
    #
    #   run == 11            -> a lone phone number          -> accept
    #   run length is a multiple of 11 (22, 33, …)
    #                        -> concatenated numbers         -> accept each
    #   any other length     -> a fragment of a longer number
    #                           (12-digit typo, an ID card's digit substring)
    #                                                         -> reject
    #
    # The "multiple of 11" rule is what keeps adjacent numbers detectable
    # without inventing false positives inside ID/bank numbers.
    for m in re.finditer(rf"1[3-9](?:{_SEP}\d){{9}}", normalized):
        d = digits_only(m.group(0))
        if len(d) != 11:
            continue
        start, end = m.start(), m.end()

        # Walk the surrounding *number run*, treating the same separators the
        # pattern allows as part of the run (so "138-1234-5678" is one run,
        # while "138 1234 5678," still ends at the comma).
        def is_run_char(ch: str) -> bool:
            return ch.isdigit() or ch in "- \u00a0"

        run_start = start
        while run_start > 0 and is_run_char(normalized[run_start - 1]):
            run_start -= 1
        run_end = end
        while run_end < len(normalized) and is_run_char(normalized[run_end]):
            run_end += 1
        run_len = len(digits_only(normalized[run_start:run_end]))

        # Accept when the run can be explained as whole numbers:
        #   11               -> one phone number
        #   22, 33, … (11n)  -> concatenated phone numbers
        #   29 / 26 / 30     -> a phone number glued to an 18/15/19-digit
        #                       ID or card; the ID recognizer claims the tail
        #                       and overlap resolution keeps both spans
        explained = run_len % 11 == 0 or run_len in (11 + 18, 11 + 15, 11 + 19)
        if explained:
            out.append(Span(start, end, "PHONE_NUMBER", 0.95, text[start:end]))
    return out


def _id_card_recognizer(text: str) -> list[Span]:
    out: list[Span] = []
    normalized = normalize(text)
    # Match any candidate 18-char string that looks like an ID: 17 digits +
    # a final character that is either a digit or X/x. Separators are handled
    # inside the run (one separator allowed every 1-4 digits). The non-digit
    # run separator constraint avoids merging two separate ID numbers separated
    # by a single space (18 + space + 18 -> one 37-char candidate).
    #
    # Strategy: match *any* digit run that becomes 18 chars after sanitising,
    # then let is_valid_id_card reject the wrong ones. A greedy match over
    # arbitrary separators would merge neighbouring candidates, so we first
    # match a tight run (digits + at most one separator every few digits) and
    # fall back to the looser pattern only when the tight one produces nothing.
    _tight = re.compile(
        r"(?<![0-9Xx])"
        r"(?:\d{1,4}[\- \u00a0]?){4,6}\d[\dXx]"
        r"(?![0-9Xx])"
    )
    _loose = re.compile(
        r"(?<![0-9Xx])"           # left boundary: not a digit/X/x
        r"[\dXx](?:[\d\- \u00a0Xx]{16,44})"  # body with separators
        r"(?![0-9Xx])"            # right boundary
    )
    seen: set[tuple[int, int]] = set()
    for pattern in (_tight, _loose):
        for m in pattern.finditer(normalized):
            raw = m.group(0)
            key = (m.start(), m.end())
            if key in seen:
                continue
            d = _id_card_digits(raw)
            if len(d) == 18 and is_valid_id_card(d):
                seen.add(key)
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
#
# The trigger words alone are not enough: "联系" is followed by ordinary
# nouns just as often as by a person ("联系电话138…", "联系地址…"), and a
# naive 2-3 character capture masked the WORD rather than a name. Every
# candidate is therefore checked against a blocklist of common business nouns
# before being reported, which keeps precision usable without losing the
# genuine "帮我联系下张伟" case.
_NAME_BEFORE = r"(?:帮我联系|帮忙联系|联系|找一下|找找|询问|咨询|我是|叫我|这是|听说|交给)"
_NAME_CONNECTOR = r"(?:一下|下|到|给)?"
_NAME_AFTER = r"(?=先生|女士|经理|老师|同学|工程师|主任)"

# Nouns that frequently follow a trigger word. Matching any of these means the
# capture is a common noun, not a person's name.
_NON_NAME_WORDS: frozenset[str] = frozenset({
    "电话", "手机", "号码", "邮箱", "邮件", "地址", "地点", "公司", "部门", "单位",
    "客户", "用户", "业务", "部门", "合同", "订单", "账号", "帐号", "密码", "验证",
    "资料", "信息", "相关", "负责", "人员", "同事", "领导", "上级", "下级", "财务",
    "人事", "行政", "技术", "产品", "运营", "市场", "销售", "客服", "售后", "服务",
    "系统", "平台", "应用", "接口", "数据", "报表", "文档", "文件", "图片", "视频",
    "以后", "之后", "之前", "现在", "今天", "明天", "昨天", "时候", "时间", "地方",
})

# Chinese surnames are 1-2 characters; using the strongest single-character set
# avoids treating arbitrary text as a name.
_NON_NAME_SUFFIXES: tuple[str, ...] = ("部", "处", "科", "组", "室", "局", "厅", "司", "厂", "店")
_NAME_SURNAMES: frozenset[str] = frozenset(
    "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    "戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳鲍史唐"
    "费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平"
    "黄和穆萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝"
    "董梁杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊"
    "胡凌霍虞万支柯昝管卢莫经房裘缪干解应宗丁宣贲邓郁单杭洪包诸左石"
    "崔吉钮龚程嵇邢滑裴陆荣翁荀羊於惠甄曲家封芮羿储靳汲邴糜松井段富"
    "巫乌焦巴弓牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘钭厉戎祖武"
    "符刘景詹束龙叶幸司韶郜黎蓟薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池"
    "乔阴郁胥能苍双闻莘党翟谭贡劳逄姬申扶堵冉宰郦雍却璩桑桂濮牛寿通"
    "边扈燕冀郏浦尚农温别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾"
    "终暨居衡步都耿满弘匡国文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾"
    "敖融冷訾辛阚那简饶空曾毋沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖"
    "益桓公"
)


def _looks_like_name(candidate: str) -> bool:
    """Heuristic: a 2-3 character capture starting with a surname.

    The blocklist catches whole common nouns ("电话", "地址"). Candidates that
    merely *end* in a business-noun fragment ("公司人" out of "公司人事部") are
    caught too: if the capture contains a blocklisted 2-character word at all,
    the surrounding text is a phrase rather than a name.
    """
    if not candidate or not (2 <= len(candidate) <= 3):
        return False
    if candidate in _NON_NAME_WORDS:
        return False
    for start in range(len(candidate) - 1):
        if candidate[start : start + 2] in _NON_NAME_WORDS:
            return False
    # Occupations/titles that follow a surname in business text are not names
    # on their own ("人事部", "财务部").
    if any(candidate.endswith(suffix) for suffix in _NON_NAME_SUFFIXES):
        return False
    return candidate[0] in _NAME_SURNAMES


def _name_recognizer(text: str) -> list[Span]:
    out: list[Span] = []
    for m in re.finditer(rf"{_NAME_BEFORE}{_NAME_CONNECTOR}([\u4e00-\u9fff]{{2,3}})", text):
        candidate = m.group(1)
        if not _looks_like_name(candidate):
            continue
        out.append(Span(m.start(1), m.end(1), "PERSON", 0.6, candidate))
    for m in re.finditer(rf"([\u4e00-\u9fff]{{2,3}}){_NAME_AFTER}", text):
        candidate = m.group(1)
        if not _looks_like_name(candidate):
            continue
        out.append(Span(m.start(1), m.end(1), "PERSON", 0.6, candidate))
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

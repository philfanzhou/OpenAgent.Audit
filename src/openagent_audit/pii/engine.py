"""Detection engines: the built-in rule engine, plus an optional Presidio
engine wired exactly as the proposal prescribes (Chinese spaCy model via
``NlpEngineProvider``; custom numeric recognizers with checksum validation).
"""

from __future__ import annotations

from typing import Protocol, Sequence

from openagent_audit.pii.recognizers import (
    DEFAULT_RECOGNIZERS,
    Span,
    resolve_overlaps,
)


class DetectionEngine(Protocol):
    def detect(self, text: str) -> Sequence[Span]: ...


class RuleBasedEngine:
    """Built-in recognizers, no external model required."""

    def __init__(self, recognizers: Sequence[Recognizer] | None = None) -> None:
        self._recognizers = tuple(recognizers) if recognizers is not None else DEFAULT_RECOGNIZERS

    def detect(self, text: str) -> list[Span]:
        if not text:
            return []
        spans: list[Span] = []
        for recognizer in self._recognizers:
            spans.extend(recognizer(text))
        return resolve_overlaps(spans)


class PresidioEngine:
    """Hybrid engine per the proposal §08 “中文识别要点”: Presidio (Chinese
    spaCy NER + its recognizer registry, including our checksum-validated
    CN_PHONE) **merged with** the built-in rule recognizers — 规则 + 模型混合.
    Overlaps resolve in favor of the typed rule entities (higher priority),
    and the NER layer adds recall the rules cannot (or vice versa when the
    model improves).

    Requires the ``presidio-analyzer`` extra and a Chinese spaCy model
    (``zh_core_web_sm``).
    """

    def __init__(self, language: str = "zh") -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise RuntimeError(
                "presidio-analyzer is not installed; "
                "pip install 'openagent-audit[presidio]' and a zh spaCy model"
            ) from exc

        nlp = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": "zh_core_web_sm"}],
            }
        )
        self._analyzer = AnalyzerEngine(nlp_engine=nlp.create_engine(), supported_languages=[language])
        self._language = language
        self._rules = RuleBasedEngine()
        self._register_custom_recognizers()

    def _register_custom_recognizers(self) -> None:
        from presidio_analyzer import Pattern, PatternRecognizer

        self._analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="CN_PHONE",
                supported_language=self._language,
                patterns=[Pattern("cn-mobile", r"(?<!\d)1[3-9]\d{9}(?!\d)", 0.95)],
            )
        )

    def detect(self, text: str) -> list[Span]:
        # layer 1: our typed rules (checksum numerics + trigger-context names);
        # they always win overlaps — they are checksum/structure validated
        rule_spans = self._rules.detect(text)
        spans: list[Span] = list(rule_spans)
        # layer 2: Presidio (zh spaCy NER + registry recognizers) adds the
        # entities the rules do not cover
        for r in self._analyzer.analyze(text=text, language=self._language):
            candidate = Span(r.start, r.end, r.entity_type, float(r.score), text[r.start : r.end])
            overlaps_rules = any(
                candidate.start < s.end and s.start < candidate.end for s in rule_spans
            )
            if not overlaps_rules:
                spans.append(candidate)
        return resolve_overlaps(spans)


def create_engine(backend: str = "rules") -> DetectionEngine:
    if backend == "rules":
        return RuleBasedEngine()
    if backend == "presidio":
        return PresidioEngine()
    raise ValueError(f"unknown PII backend {backend!r}; expected 'rules' or 'presidio'")

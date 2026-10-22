"""The masking pipeline (proposal §08 flow ①“入库”).

``protect(text)`` detects sensitive entities and rewrites the text so that
every entity becomes ``⟦TYPE#entity_id|mask⟧`` — the *only* form that ever
leaves the Agent process. In mode B each entity is simultaneously sealed with
the envelope cipher and batch-inserted into the audit-domain ciphertext vault.
Results are cached per text hash because multi-turn conversations resend the
same history on every LLM call (proposal §11 “性能提示”).
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

from openagent_audit.crypto.envelope import EnvelopeCipher
from openagent_audit.pii.engine import DetectionEngine, RuleBasedEngine
from openagent_audit.pii.recognizers import digits_only

MaskFn = Callable[[str], str]

# ---------------------------------------------------------------------------
# Mask rules (defaults follow the proposal §08 demo; each is a compliance
# decision — override per entity type when compliance signs off other depths).
# ---------------------------------------------------------------------------


def _mask_phone(value: str) -> str:
    d = digits_only(value)
    return f"{d[:3]}****{d[-4:]}" if len(d) == 11 else "*" * len(d)


def _mask_id_card(value: str) -> str:
    v = value.upper()
    return f"{v[:6]}********{v[-4:]}"


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if len(local) >= 2:
        return f"{local[0]}*****{local[-1]}@{domain}"
    return f"*****@{domain}"


def _mask_bank_card(value: str) -> str:
    d = digits_only(value)
    return f"{d[:4]} **** **** {d[-4:]}" if len(d) >= 8 else "*" * len(d)


def _mask_person(value: str) -> str:
    return f"{value[0]} *"


def _mask_default(value: str) -> str:
    return "***"


DEFAULT_MASK_RULES: dict[str, MaskFn] = {
    "PHONE_NUMBER": _mask_phone,
    "CN_PHONE": _mask_phone,
    "ID_CARD": _mask_id_card,
    "BANK_CARD": _mask_bank_card,
    "EMAIL_ADDRESS": _mask_email,
    "PERSON": _mask_person,
}


def mask_value(entity_type: str, value: str, rules: Mapping[str, MaskFn] | None = None) -> str:
    active = rules if rules is not None else DEFAULT_MASK_RULES
    fn = active.get(entity_type, _mask_default)
    return fn(value)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EntityRecord:
    """One detected entity. ``value`` (raw plaintext) exists only in memory
    during ingest and is never persisted or logged."""

    entity_id: str
    entity_type: str
    value: str
    mask: str
    ciphertext: str
    start: int
    end: int

    def redacted(self) -> "EntityRecord":
        """Copy safe to hand to anything that might be logged or serialized."""
        return EntityRecord(self.entity_id, self.entity_type, "", self.mask, "", self.start, self.end)


@dataclass(frozen=True)
class ProtectResult:
    masked_text: str
    entities: tuple[EntityRecord, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class _Detection:
    """Cached detection outcome. Only positions, type and mask are cached —
    ``entity_id`` and ciphertext are regenerated on every call so each trace
    gets fresh random identifiers and fresh randomized ciphertext (proposal
    §08: 编号随机生成、同一实体每次加密结果都不同)."""

    start: int
    end: int
    entity_type: str
    raw: str
    mask: str


class _MaskingCache:
    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._data: OrderedDict[str, tuple[_Detection, ...]] = OrderedDict()

    def get(self, key: str) -> tuple[_Detection, ...] | None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                return self._data[key]
            return None

    def put(self, key: str, value: tuple[_Detection, ...]) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)


class VaultWriter:
    """Batch insert with bounded retries (proposal §02 通路① “密文写入可靠性”)."""

    def __init__(self, vault, attempts: int = 3) -> None:
        self._vault = vault
        self._attempts = attempts

    def write(self, rows: Sequence[Mapping[str, object]]) -> None:
        last_error: Exception | None = None
        for attempt in range(self._attempts):
            try:
                self._vault.insert_entities(list(rows))
                return
            except Exception as exc:  # noqa: BLE001 - retried below
                last_error = exc
                if attempt + 1 < self._attempts:
                    time.sleep(min(0.5 * (2**attempt), 4.0))  # bounded backoff
        raise RuntimeError(f"vault write failed after {self._attempts} attempts") from last_error


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class MaskingPipeline:
    def __init__(
        self,
        engine: DetectionEngine | None = None,
        cipher: EnvelopeCipher | None = None,
        vault_writer: VaultWriter | None = None,
        rules: Mapping[str, MaskFn] | None = None,
        cache_size: int = 512,
    ) -> None:
        self._engine = engine if engine is not None else RuleBasedEngine()
        self._cipher = cipher
        self._vault_writer = vault_writer
        self._rules = rules
        self._cache = _MaskingCache(cache_size)
        self.entities_masked = 0
        self._count_lock = threading.Lock()

    def protect(
        self,
        text: str,
        *,
        trace_id: str | None = None,
        session_id: str | None = None,
    ) -> ProtectResult:
        if not text:
            return ProtectResult(masked_text=text, entities=())
        key = hashlib.sha256(text.encode("utf-8")).hexdigest()
        detections = self._cache.get(key)
        if detections is None:
            # Expensive part (regex / Presidio NER) — cached per text hash
            # (proposal §11 性能提示). Sealing stays per-call.
            detections = tuple(
                _Detection(
                    start=span.start,
                    end=span.end,
                    entity_type=span.entity_type,
                    raw=text[span.start : span.end],
                    mask=mask_value(span.entity_type, text[span.start : span.end], self._rules),
                )
                for span in self._engine.detect(text)
            )
            self._cache.put(key, detections)

        pieces: list[str] = []
        records: list[EntityRecord] = []
        last = 0
        for det in detections:
            entity_id = secrets.token_hex(8)  # random, never derived from the value
            ciphertext = ""
            if self._cipher is not None:
                ciphertext = self._cipher.seal(det.raw.encode("utf-8"), aad=entity_id.encode("ascii"))
            pieces.append(text[last : det.start])
            pieces.append(f"⟦{det.entity_type}#{entity_id}|{det.mask}⟧")
            records.append(
                EntityRecord(
                    entity_id=entity_id,
                    entity_type=det.entity_type,
                    value=det.raw,
                    mask=det.mask,
                    ciphertext=ciphertext,
                    start=det.start,
                    end=det.end,
                )
            )
            last = det.end
        pieces.append(text[last:])
        result = ProtectResult(masked_text="".join(pieces), entities=tuple(records))

        if records and self._vault_writer is not None and self._cipher is not None:
            self._vault_writer.write(
                [
                    {
                        "entity_id": r.entity_id,
                        "entity_type": r.entity_type,
                        "ciphertext": r.ciphertext,
                        "trace_id": trace_id,
                        "session_id": session_id,
                    }
                    for r in records
                ]
            )
        with self._count_lock:
            self.entities_masked += len(records)
        return result

    def stats(self) -> dict[str, int]:
        with self._count_lock:
            return {"entities_masked": self.entities_masked}

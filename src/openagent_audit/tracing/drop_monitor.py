"""Drop monitoring (proposal §02: “必须监控丢弃数，大于 0 即告警”)."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class DropMonitor:
    """Thread-safe counters for the export-thread masking path.

    The Langfuse SDK itself drops the whole export batch when
    ``mask_otel_spans`` raises (fail-closed); we count that here so operators
    can alert on ``dropped_batches > 0`` — a drop is a *loss of observability*,
    never a plaintext leak.
    """

    dropped_batches: int = 0
    hook_failures: int = 0
    vault_write_failures: int = 0
    spans_patched: int = 0
    entities_masked: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_batch_dropped(self, spans: int = 0) -> None:
        with self._lock:
            self.dropped_batches += 1
            self.hook_failures += 1

    def record_spans_patched(self, count: int) -> None:
        with self._lock:
            self.spans_patched += count

    def record_entities_masked(self, count: int) -> None:
        with self._lock:
            self.entities_masked += count

    def record_vault_failure(self) -> None:
        with self._lock:
            self.vault_write_failures += 1

    def has_drops(self) -> bool:
        with self._lock:
            return self.dropped_batches > 0 or self.vault_write_failures > 0

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "dropped_batches": self.dropped_batches,
                "hook_failures": self.hook_failures,
                "vault_write_failures": self.vault_write_failures,
                "spans_patched": self.spans_patched,
                "entities_masked": self.entities_masked,
            }

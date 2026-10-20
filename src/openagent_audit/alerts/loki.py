"""Best-effort Loki fan-out: audit-event copies for real-time alerting only.

Loki never receives prompt storage (proposal §05). Only low-cardinality
labels go into the label set; the JSON line carries ids and action metadata —
never entity values, never ciphertext.
"""

from __future__ import annotations

import json
import time


class LokiPushClient:
    def __init__(self, url: str, labels: dict[str, str] | None = None, client=None, timeout: float = 5.0) -> None:
        if client is not None:
            self._client = client
        else:
            import httpx

            self._client = httpx.Client(timeout=timeout)
        self._url = url.rstrip("/")
        self._labels = labels or {}
        self.push_failures = 0

    def push_event(self, event: dict, *, category: str) -> bool:
        """Push one audit-event copy. Returns True on success; failures are
        counted, never raised — the append-only table is the system of record."""
        ts_ns = str(time.time_ns())
        stream = {"job": "openagent-audit", "category": category, **self._labels}
        payload = {
            "streams": [
                {
                    "stream": stream,
                    "values": [[ts_ns, json.dumps(event, ensure_ascii=False)]],
                }
            ]
        }
        try:
            resp = self._client.post(f"{self._url}/loki/api/v1/push", json=payload)
            resp.raise_for_status()
            return True
        except Exception:
            self.push_failures += 1
            return False


class NullLokiClient:
    """Disabled fan-out (LOKI_URL unset)."""

    push_failures = 0

    def push_event(self, event: dict, *, category: str) -> bool:
        return False

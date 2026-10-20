"""Hash chain over the append-only audit log (proposal §08 “审计日志”).

Each entry commits to the previous entry's hash over a canonical JSON
rendering, so any deletion or in-place edit breaks verification. Entry hashes
are computed over every field *except* ``entry_hash`` itself.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable, Mapping

GENESIS_HASH = "0" * 64


def canonical_entry(
    *,
    ts: datetime,
    actor: str,
    role: str,
    action: str,
    object_type: str | None,
    object_id: str | None,
    detail: Mapping[str, Any],
) -> str:
    payload = {
        "actor": actor,
        "action": action,
        "detail": detail,
        "object_id": object_id,
        "object_type": object_type,
        "role": role,
        "ts": ts.isoformat(),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def entry_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def verify_chain(rows: Iterable[Mapping[str, Any]]) -> tuple[bool, int | None]:
    """Verify a hash chain over rows ordered by ``seq``.

    Rows need ``seq, ts, actor, role, action, object_type, object_id, detail,
    prev_hash, entry_hash``. Returns ``(ok, first_bad_seq)``.
    """
    prev = GENESIS_HASH
    for row in sorted(rows, key=lambda r: r["seq"]):
        ts = row["ts"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        canonical = canonical_entry(
            ts=ts,
            actor=row["actor"],
            role=row["role"],
            action=row["action"],
            object_type=row["object_type"],
            object_id=row["object_id"],
            detail=row["detail"],
        )
        expected = entry_hash(prev, canonical)
        if row["prev_hash"] != prev or row["entry_hash"] != expected:
            return False, row["seq"]
        prev = row["entry_hash"]
    return True, None

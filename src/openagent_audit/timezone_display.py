"""Display-time timezone handling.

Audit entries are always **stored in UTC**. That is the only unambiguous
record: it survives a DST change, a host relabelling itself, and a reviewer in
another country. But rendering raw UTC in a Beijing console makes a 13:37
event look like 05:37, which is exactly the kind of off-by-eight-hours mistake
that undermines an investigation.

So storage stays UTC and *display* shifts into the deployment's zone. The zone
name is shown next to the times so nobody has to guess which clock they are
reading.

A missing ``tzdata`` package (common in slim containers and on Windows) must
not break the console, so the lookup degrades to a fixed offset derived from
the configured name and finally to UTC.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo

# Fallback offsets for the zones we can reasonably guess from a name such as
# "Asia/Shanghai" or "UTC+8" when no tz database is available.
_KNOWN_OFFSETS: dict[str, int] = {
    "asia/shanghai": 8,
    "asia/chongqing": 8,
    "asia/hong_kong": 8,
    "asia/taipei": 8,
    "asia/singapore": 8,
    "asia/tokyo": 9,
    "asia/seoul": 9,
    "utc": 0,
    "etc/utc": 0,
    "gmt": 0,
}

_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?$", re.IGNORECASE)


def resolve_timezone(name: str | None) -> tzinfo:
    """Return a tzinfo for *name*, degrading gracefully.

    Resolution order: the IANA database, a built-in offset table for the zones
    we ship with, a literal ``UTC+8`` style name, then UTC.
    """
    if not name:
        return timezone.utc

    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - package missing or unknown zone
        pass

    key = name.strip().lower()
    if key in _KNOWN_OFFSETS:
        return timezone(timedelta(hours=_KNOWN_OFFSETS[key]), name=name)

    match = _OFFSET_RE.match(name.strip())
    if match:
        sign = 1 if match.group(1) == "+" else -1
        hours = int(match.group(2))
        minutes = int(match.group(3) or 0)
        return timezone(sign * timedelta(hours=hours, minutes=minutes), name=name)

    return timezone.utc


def to_display(value: datetime | None, tz: tzinfo) -> datetime | None:
    """Convert a stored UTC timestamp into the display timezone.

    A naive datetime is assumed to be UTC (that is how entries are written).
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(tz)


def zone_label(tz: tzinfo) -> str:
    """Short, stable label for the zone, e.g. ``CST+08:00``."""
    now = datetime.now(tz)
    offset = now.utcoffset() or timedelta(0)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    hours, minutes = divmod(abs(total_minutes), 60)
    name = now.tzname() or ""
    return f"{name}+{hours:02d}:{minutes:02d}" if name else f"UTC{sign}{hours:02d}:{minutes:02d}"
"""Canonical JSON, hashing and time helpers.

All hashes in this project are derived deterministically from canonical JSON so
that an auditor can recompute them from ``cases.json`` and ``result.json``
alone.  Times are fixed-width UTC ISO-8601 strings, which makes plain string
comparison a valid chronological comparison.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    """Serialize ``value`` with sorted keys and no gratuitous whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_of(value: Any) -> str:
    """Digest of an arbitrary JSON value under the canonical encoding."""
    return sha256_text(canonical_json(value))


def is_digest(value: object) -> bool:
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))


def parse_ts(value: str) -> datetime:
    """Parse a ``...Z`` timestamp into an aware UTC datetime."""
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_ts(value: object) -> bool:
    if not isinstance(value, str) or not _TS_RE.match(value):
        return False
    try:
        parse_ts(value)
    except ValueError:
        return False
    return True


def normalize_ts(value: str) -> str:
    """Re-emit a timestamp in the fixed ``YYYY-MM-DDTHH:MM:SSZ`` form.

    Sub-second precision is rejected upstream so that lexicographic ordering is
    always identical to chronological ordering.
    """
    return parse_ts(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def bump_ts(value: str, seconds: int) -> str:
    return (parse_ts(value) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_stamp(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

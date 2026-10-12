"""JSON coercion shared by evidence hashing and persistence (so stored content hashes to the stored sha256)."""
from __future__ import annotations

import hashlib
import json
from datetime import date, datetime


def _default(o):
    if hasattr(o, "item") and callable(o.item):          # numpy scalars (imagehash, numpy distances)
        return o.item()
    if isinstance(o, (set, frozenset, tuple)):
        return list(o)
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, bytes):
        return o.decode("utf-8", errors="replace")
    return str(o)


def jsonable(obj):
    """A plain-JSON copy of obj (dict/list/str/int/float/bool/None only)."""
    return json.loads(json.dumps(obj, default=_default, ensure_ascii=False))


def canonical_sha256(obj) -> str:
    data = json.dumps(jsonable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

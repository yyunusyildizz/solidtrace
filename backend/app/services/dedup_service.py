"""
app.services.dedup_service
==========================
In-memory event deduplication for ingest pipeline.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Dict, Optional

_EVENT_DEDUP_CACHE: dict[str, float] = {}
_EVENT_DEDUP_WINDOW_SECONDS = 20
_EVENT_DEDUP_MAX_ITEMS = 10000
_LOCK = threading.Lock()


def configure_dedup(window_seconds: int = 20, max_items: int = 10000) -> None:
    global _EVENT_DEDUP_WINDOW_SECONDS, _EVENT_DEDUP_MAX_ITEMS
    _EVENT_DEDUP_WINDOW_SECONDS = max(1, int(window_seconds))
    _EVENT_DEDUP_MAX_ITEMS = max(100, int(max_items))


def _cleanup_event_dedup_cache() -> None:
    now = time.time()
    expired = [k for k, v in _EVENT_DEDUP_CACHE.items() if v <= now]
    for k in expired:
        _EVENT_DEDUP_CACHE.pop(k, None)

    if len(_EVENT_DEDUP_CACHE) > _EVENT_DEDUP_MAX_ITEMS:
        overflow = len(_EVENT_DEDUP_CACHE) - _EVENT_DEDUP_MAX_ITEMS
        for key in list(_EVENT_DEDUP_CACHE.keys())[:overflow]:
            _EVENT_DEDUP_CACHE.pop(key, None)


def event_fingerprint(event_data: Dict[str, Any], tenant_id: Optional[str]) -> str:
    raw = "|".join(
        [
            str(tenant_id or ""),
            str(event_data.get("hostname") or "").strip().lower(),
            str(event_data.get("type") or "").strip().lower(),
            str(event_data.get("user") or "").strip().lower(),
            str(event_data.get("pid") or ""),
            str(event_data.get("command_line") or "").strip().lower()[:200],
            str(event_data.get("serial") or "").strip().lower(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_duplicate_event(event_data: Dict[str, Any], tenant_id: Optional[str]) -> bool:
    with _LOCK:
        _cleanup_event_dedup_cache()

        fp = event_fingerprint(event_data, tenant_id)
        now = time.time()
        exp = _EVENT_DEDUP_CACHE.get(fp)

        if exp and exp > now:
            return True

        _EVENT_DEDUP_CACHE[fp] = now + _EVENT_DEDUP_WINDOW_SECONDS
        return False


def cache_size() -> int:
    with _LOCK:
        _cleanup_event_dedup_cache()
        return len(_EVENT_DEDUP_CACHE)


def clear_cache() -> None:
    with _LOCK:
        _EVENT_DEDUP_CACHE.clear()

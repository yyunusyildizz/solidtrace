"""
app.services.threat_intel
=========================

Dış tehdit istihbaratı entegrasyonları:
  - AlienVault OTX
  - MalwareBazaar (abuse.ch)

Tasarım hedefleri:
- FastAPI / DB bağımsız kalsın
- Tek kaynak implementasyon olsun
- Async background çalışma desteklensin
- Connection pooling ile HTTP client reuse edilsin
- TTL cache ile tekrar sorgular azaltılsın
- Concurrency limiti ile kaynak tüketimi kontrol edilsin
- Benign / gürültülü dosyalar için gereksiz intel sorguları baskılansın
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Awaitable, Callable, Dict, Optional

import httpx

logger = logging.getLogger("SolidTrace.ThreatIntel")

BroadcastFn = Callable[[dict], Awaitable[None]]

OTX_API_KEY = os.getenv("OTX_API_KEY")
BAZAAR_API_KEY = os.getenv("BAZAAR_API_KEY")

CACHE_TTL_SECONDS = 3600.0
MAX_CONCURRENT_TASKS = 20

INTEL_CACHE: Dict[str, float] = {}
SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
_http_client: Optional[httpx.AsyncClient] = None

BENIGN_PATH_MARKERS = [
    ".vscode",
    "codeium",
    "python-env",
    "node_modules",
    "language_server_windows_x64.exe",
    "pet.exe",
    "solidtrace_agent.exe",
    "audiodg.exe",
    "explorer.exe",
    "mscopilot_proxy.exe",
    "microsoftedgeupdate.exe",
    "7zfm.exe",
    "git-remote-https.exe",
    "notepad.exe",
    "smartscreen.exe",
    "python.exe",
    "uvicorn.exe",
    "rtkbtmanserv.exe",
    "updater.exe",
    "easyduplicatefinder.exe",
]


def get_client() -> httpx.AsyncClient:
    """Global AsyncClient döndürür. Connection pooling için tek client kullanılır."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=10.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
            follow_redirects=True,
        )
    return _http_client


async def close_client() -> None:
    """Uygulama shutdown sırasında çağrılabilir."""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


def _cleanup_cache() -> None:
    now = time.time()
    expired = [k for k, expiry in list(INTEL_CACHE.items()) if expiry < now]
    for key in expired:
        INTEL_CACHE.pop(key, None)


def _normalize_path(path: Optional[str]) -> str:
    return str(path or "").strip().lower().replace("/", "\\")


def _should_skip_file_path(file_path: Optional[str]) -> bool:
    normalized = _normalize_path(file_path)
    if not normalized:
        return False
    return any(marker in normalized for marker in BENIGN_PATH_MARKERS)


def _cache_hit(file_hash: str) -> bool:
    now = time.time()
    return file_hash in INTEL_CACHE and INTEL_CACHE[file_hash] > now


def _cache_store(file_hash: str) -> None:
    INTEL_CACHE[file_hash] = time.time() + CACHE_TTL_SECONDS


async def check_otx(file_hash: str) -> Optional[str]:
    if not OTX_API_KEY:
        return None

    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"

    try:
        client = get_client()
        res = await client.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=5.0)
        if res.status_code != 200:
            logger.debug("OTX non-200 status=%s hash=%s", res.status_code, file_hash)
            return None

        count = res.json().get("pulse_info", {}).get("count", 0)
        if count > 0:
            return f"OTX: {count} tehdit kaydı"

    except Exception as exc:
        logger.warning("OTX sorgu hatası hash=%s error=%s", file_hash, exc)

    return None


async def check_malware_bazaar(file_hash: str) -> Optional[str]:
    if not BAZAAR_API_KEY:
        return None

    try:
        client = get_client()
        res = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash},
            headers={"Auth-Key": BAZAAR_API_KEY},
            timeout=15.0,
        )

        if res.status_code == 403:
            logger.info("MalwareBazaar 403 hash=%s", file_hash)
            return None

        if res.status_code != 200:
            logger.debug("MalwareBazaar non-200 status=%s hash=%s", res.status_code, file_hash)
            return None

        payload = res.json()
        if payload.get("query_status") == "ok":
            signature = payload["data"][0].get("signature", "Malware")
            return f"Bazaar: {signature} tespit"

    except Exception as exc:
        logger.warning("MalwareBazaar sorgu hatası hash=%s error=%s", file_hash, exc)

    return None


async def _broadcast_message(
    broadcast_fn: Optional[BroadcastFn],
    *,
    label: str,
    intel_message: str,
    file_path: str,
) -> None:
    if not broadcast_fn:
        return

    try:
        await broadcast_fn(
            {
                "type": "ACTION_LOG",
                "message": f"🚨 [{label}] {intel_message} → {file_path}",
            }
        )
    except Exception as exc:
        logger.warning("Threat intel broadcast hatası label=%s path=%s error=%s", label, file_path, exc)


async def _background_intel(report, broadcast_fn: Optional[BroadcastFn]) -> None:
    file_hash = str(getattr(report, "file_hash", "") or "").strip()
    file_path = str(getattr(report, "file_path", "") or "").strip()

    if not file_hash:
        return

    try:
        async with SEMAPHORE:
            otx_res, bazaar_res = await asyncio.gather(
                check_otx(file_hash),
                check_malware_bazaar(file_hash),
                return_exceptions=True,
            )

        for label, result in (("OTX", otx_res), ("Bazaar", bazaar_res)):
            if isinstance(result, Exception):
                logger.warning("Threat intel provider exception label=%s hash=%s error=%s", label, file_hash, result)
                continue

            if not result:
                continue

            await _broadcast_message(
                broadcast_fn,
                label=label,
                intel_message=result,
                file_path=file_path,
            )
            logger.warning("🚨 [%s] %s → %s", label, result, file_path)

    except Exception as exc:
        logger.error("Background threat intel critical error hash=%s error=%s", file_hash, exc, exc_info=True)


async def process_threat_intel(
    report,
    broadcast_fn: Optional[BroadcastFn] = None,
) -> None:
    """
    Ana giriş noktası.

    Beklenen report alanları:
    - report.file_hash
    - report.file_path

    Davranış:
    - benign path ise sorgu atlaması
    - TTL cache varsa sorgu atlaması
    - uygun ise fire-and-forget background task
    """
    file_hash = str(getattr(report, "file_hash", "") or "").strip()
    file_path = str(getattr(report, "file_path", "") or "").strip()

    if not file_hash:
        return

    _cleanup_cache()

    if _should_skip_file_path(file_path):
        logger.info("Threat intel skipped for benign path path=%s", file_path)
        return

    if _cache_hit(file_hash):
        logger.debug("Threat intel cache hit hash=%s", file_hash)
        return

    _cache_store(file_hash)
    asyncio.create_task(_background_intel(report, broadcast_fn))

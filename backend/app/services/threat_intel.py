"""
app.services.threat_intel
=========================
Dış tehdit istihbaratı entegrasyonları:
  - AlienVault OTX
  - MalwareBazaar (abuse.ch)

Hiçbir DB veya FastAPI bağımlılığı içermez.
broadcast fonksiyonu dışarıdan enjekte edilir (bağımlılık tersine çevirme).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional, Callable, Dict

import httpx

logger = logging.getLogger("SolidTrace.ThreatIntel")

OTX_API_KEY    = os.getenv("OTX_API_KEY")
BAZAAR_API_KEY = os.getenv("BAZAAR_API_KEY")

# Basit in-memory cache — tekrar sorgulama önleme
INTEL_CACHE: Dict[str, bool] = {}


async def check_otx(file_hash: str) -> Optional[str]:
    """AlienVault OTX'te hash sorgula."""
    if not OTX_API_KEY:
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
            if res.status_code == 200:
                count = res.json().get("pulse_info", {}).get("count", 0)
                if count > 0:
                    return f"OTX: {count} Tehdit Kaydı!"
    except Exception as e:
        logger.error(f"OTX Hatası: {e}")
    return None


async def check_malware_bazaar(file_hash: str) -> Optional[str]:
    """MalwareBazaar'da hash sorgula."""
    if not BAZAAR_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash},
                headers={"Auth-Key": BAZAAR_API_KEY},
            )
            if res.status_code == 200:
                j = res.json()
                if j.get("query_status") == "ok":
                    sig = j["data"][0].get("signature", "Malware")
                    return f"Bazaar: {sig} Tespit!"
    except Exception as e:
        logger.error(f"Bazaar Hatası: {e}")
    return None


async def process_threat_intel(
    report,                              # HashReport schema
    broadcast_fn: Optional[Callable] = None,
) -> None:
    """
    OTX + Bazaar paralel sorgulama.
    broadcast_fn: sonuçları WebSocket'e iletmek için enjekte edilir.
    """
    if report.file_hash in INTEL_CACHE:
        return

    otx_res, bazaar_res = await asyncio.gather(
        check_otx(report.file_hash),
        check_malware_bazaar(report.file_hash),
        return_exceptions=True,
    )

    for label, result in [("OTX", otx_res), ("Bazaar", bazaar_res)]:
        if result and not isinstance(result, Exception):
            if broadcast_fn:
                await broadcast_fn({
                    "type":    "ACTION_LOG",
                    "message": f"🚨 [{label}] {result} → {report.file_path}",
                })
            logger.warning(f"🚨 [{label}] {result} → {report.file_path}")

    INTEL_CACHE[report.file_hash] = True

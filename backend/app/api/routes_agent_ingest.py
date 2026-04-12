from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.core.security import get_current_tenant_id
from app.database.db_manager import SessionLocal
from app.services.detection_queue import DetectionQueueService

logger = logging.getLogger("SolidTrace.AgentIngest")
router = APIRouter(tags=["agent_ingest"])

_QUEUE = DetectionQueueService(worker_name="api-enqueue", batch_size=1, poll_interval=1.0)


@dataclass
class FileHashReport:
    hostname: str
    file_path: str
    file_hash: str
    pid: int = 0
    tenant_id: Optional[str] = None


def _resolve_tenant(header_tenant: Optional[str], fallback_tenant: Optional[str]) -> Optional[str]:
    return (header_tenant or fallback_tenant or "default_tenant").strip()


def _require_agent_key(agent_key: Optional[str]) -> None:
    if not agent_key:
        raise HTTPException(status_code=401, detail="Kimlik doğrulama başarısız")


@router.post("/api/v1/ingest")
async def ingest_events(
    payload: Any,
    request: Request,
    x_agent_key: Optional[str] = Header(default=None, alias="X-Agent-Key"),
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    _require_agent_key(x_agent_key)
    resolved_tenant = _resolve_tenant(x_tenant_id, tenant_id)

    if not isinstance(payload, list):
        raise HTTPException(status_code=400, detail="Payload liste olmalı")

    items = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        normalized = dict(item)
        normalized["tenant_id"] = normalized.get("tenant_id") or resolved_tenant
        items.append(normalized)

    if not items:
        return {"status": "ok", "enqueued": 0}

    count = _QUEUE.enqueue_many(resolved_tenant, items)
    logger.info(
        "agent_ingest_enqueued ip=%s tenant=%s count=%s",
        request.client.host if request.client else "n/a",
        resolved_tenant,
        count,
    )
    return {"status": "ok", "enqueued": count}


@router.post("/api/v1/report_hash")
async def report_hash(
    payload: dict,
    request: Request,
    x_agent_key: Optional[str] = Header(default=None, alias="X-Agent-Key"),
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    _require_agent_key(x_agent_key)
    resolved_tenant = _resolve_tenant(x_tenant_id, tenant_id)

    report = FileHashReport(
        hostname=str(payload.get("hostname") or "unknown"),
        file_path=str(payload.get("file_path") or ""),
        file_hash=str(payload.get("file_hash") or ""),
        pid=int(payload.get("pid") or 0),
        tenant_id=resolved_tenant,
    )

    try:
        from app.services.threat_intel import process_threat_intel
        await process_threat_intel(report)
    except Exception as exc:
        logger.warning("threat_intel_process_failed tenant=%s error=%s", resolved_tenant, exc)

    logger.info(
        "agent_hash_received ip=%s tenant=%s host=%s path=%s",
        request.client.host if request.client else "n/a",
        resolved_tenant,
        report.hostname,
        report.file_path,
    )
    return {"status": "ok"}

"""
app.api.routes_assets
=====================
Asset inventory ve agent görünürlüğü endpoint'leri.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc

from app.core.security import get_current_tenant_id, require_role
from app.database.db_manager import AgentModel, AlertModel, SessionLocal
from app.schemas.models import AssetDetailResponse, AssetListItemResponse

logger = logging.getLogger("SolidTrace.Assets")
router = APIRouter(tags=["assets"])


ONLINE_THRESHOLD_MINUTES = 5


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _agent_online_status(last_seen: Optional[str]) -> str:
    dt = _parse_dt(last_seen)
    if not dt:
        return "unknown"

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    if utcnow() - dt <= timedelta(minutes=ONLINE_THRESHOLD_MINUTES):
        return "online"
    return "offline"


def _alert_risk_summary(db, tenant_id: Optional[str], hostname: str) -> dict:
    query = db.query(AlertModel).filter(AlertModel.hostname == hostname)

    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)

    alerts = query.order_by(desc(AlertModel.created_at)).limit(100).all()

    total_alerts = len(alerts)
    critical_count = sum(1 for a in alerts if (a.severity or "").upper() == "CRITICAL")
    high_count = sum(1 for a in alerts if (a.severity or "").upper() == "HIGH")
    max_risk_score = max((a.risk_score or 0 for a in alerts), default=0)

    latest_alert = alerts[0].created_at if alerts else None

    return {
        "total_alerts": total_alerts,
        "critical_count": critical_count,
        "high_count": high_count,
        "max_risk_score": max_risk_score,
        "latest_alert_at": latest_alert,
    }


@router.get("/api/v1/assets", response_model=list[AssetListItemResponse])
async def list_assets(
    request: Request,
    q: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None, pattern="^(online|offline|unknown)$"),
    active_only: bool = Query(default=True),
    limit: int = Query(default=200, ge=1, le=1000),
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = db.query(AgentModel)

        if tenant_id and hasattr(AgentModel, "tenant_id"):
            query = query.filter(AgentModel.tenant_id == tenant_id)

        if active_only:
            query = query.filter(AgentModel.is_active == True)  # noqa: E712

        rows = query.order_by(desc(AgentModel.last_seen), desc(AgentModel.enrolled_at)).limit(limit).all()

        items: list[AssetListItemResponse] = []
        q_norm = q.strip().lower() if q and q.strip() else None

        for row in rows:
            online_status = _agent_online_status(row.last_seen)

            if status and online_status != status:
                continue

            searchable = " ".join(
                [
                    row.hostname or "",
                    row.os_name or "",
                    row.agent_version or "",
                    row.last_ip or "",
                    row.last_user or "",
                ]
            ).lower()

            if q_norm and q_norm not in searchable:
                continue

            risk = _alert_risk_summary(db, tenant_id, row.hostname)

            items.append(
                AssetListItemResponse(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    hostname=row.hostname,
                    os_name=row.os_name,
                    agent_version=row.agent_version,
                    enrolled_at=row.enrolled_at,
                    last_seen=row.last_seen,
                    online_status=online_status,
                    is_active=bool(row.is_active),
                    revoked_at=row.revoked_at,
                    last_ip=row.last_ip,
                    last_user=row.last_user,
                    total_alerts=risk["total_alerts"],
                    critical_count=risk["critical_count"],
                    high_count=risk["high_count"],
                    max_risk_score=risk["max_risk_score"],
                )
            )

        logger.info(
            "asset_list_requested request_id=%s tenant=%s user=%s result_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            len(items),
        )

        return items
    finally:
        db.close()


@router.get("/api/v1/assets/{agent_id}", response_model=AssetDetailResponse)
async def get_asset_detail(
    agent_id: str,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = db.query(AgentModel).filter(AgentModel.id == agent_id)

        if tenant_id and hasattr(AgentModel, "tenant_id"):
            query = query.filter(AgentModel.tenant_id == tenant_id)

        agent = query.first()
        if not agent:
            raise HTTPException(status_code=404, detail="Asset bulunamadı")

        risk = _alert_risk_summary(db, tenant_id, agent.hostname)

        recent_query = db.query(AlertModel).filter(AlertModel.hostname == agent.hostname)
        if tenant_id and hasattr(AlertModel, "tenant_id"):
            recent_query = recent_query.filter(AlertModel.tenant_id == tenant_id)

        recent_alerts = recent_query.order_by(desc(AlertModel.created_at)).limit(10).all()

        logger.info(
            "asset_detail_requested request_id=%s tenant=%s user=%s agent_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            agent_id,
        )

        return AssetDetailResponse(
            id=agent.id,
            tenant_id=agent.tenant_id,
            hostname=agent.hostname,
            device_fingerprint=agent.device_fingerprint,
            os_name=agent.os_name,
            agent_version=agent.agent_version,
            enrolled_at=agent.enrolled_at,
            last_seen=agent.last_seen,
            online_status=_agent_online_status(agent.last_seen),
            is_active=bool(agent.is_active),
            revoked_at=agent.revoked_at,
            last_ip=agent.last_ip,
            last_user=agent.last_user,
            total_alerts=risk["total_alerts"],
            critical_count=risk["critical_count"],
            high_count=risk["high_count"],
            max_risk_score=risk["max_risk_score"],
            latest_alert_at=risk["latest_alert_at"],
            recent_alerts=[a.to_dict() for a in recent_alerts],
        )
    finally:
        db.close()
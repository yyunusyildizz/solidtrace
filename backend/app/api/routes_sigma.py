"""
app.api.routes_sigma
====================
Sigma istatistik endpoint'leri.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy import desc

from app.core.security import get_current_tenant_id, require_role
from app.database.db_manager import AlertModel, SessionLocal
from app.schemas.models import SigmaStatsResponse

logger = logging.getLogger("SolidTrace.Sigma")
router = APIRouter(tags=["sigma"])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")


def _alert_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AlertModel)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)
    return query


def _is_sigma_like(alert: AlertModel) -> bool:
    text = f"{alert.rule or ''} {alert.type or ''}".lower()
    sigma_keywords = (
        "sigma",
        "credential dumping",
        "lsass",
        "mimikatz",
        "psexec",
        "ransomware",
    )
    return any(keyword in text for keyword in sigma_keywords)


@router.get("/api/v1/sigma/stats", response_model=SigmaStatsResponse)
async def sigma_stats(
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = _alert_query_for_tenant(db, tenant_id).order_by(desc(AlertModel.created_at)).limit(1000).all()
        sigma_alerts = [alert for alert in alerts if _is_sigma_like(alert)]

        last_24h_cutoff = (utcnow() - timedelta(hours=24)).isoformat()

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        rule_counts: dict[str, int] = {}

        for alert in sigma_alerts:
            sev = (alert.severity or "INFO").upper()
            if sev not in severity_counts:
                sev = "INFO"
            severity_counts[sev] += 1

            key = alert.rule or alert.type or "Unknown Rule"
            rule_counts[key] = rule_counts.get(key, 0) + 1

        top_rules = [
            {"name": name, "count": count}
            for name, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        detections_last_24h = sum(1 for alert in sigma_alerts if (alert.created_at or "") >= last_24h_cutoff)

        logger.info(
            "sigma_stats_requested request_id=%s tenant=%s user=%s sigma_alert_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            len(sigma_alerts),
        )

        return SigmaStatsResponse(
            total_matches=len(sigma_alerts),
            matches_last_24h=detections_last_24h,
            severity_distribution=severity_counts,
            top_rules=top_rules,
            engine_status="degraded" if len(sigma_alerts) > 0 else "idle",
            note="Sigma engine tam entegre değilse bu istatistikler alert verisinden türetilir.",
        )
    finally:
        db.close()
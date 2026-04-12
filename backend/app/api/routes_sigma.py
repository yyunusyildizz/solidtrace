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

NOISY_RULES = {
    "SIGMA:HackTool - Mimikatz Execution",
    "SIGMA:PowerShell Download and Execution Cradles",
    "SIGMA:WMIC Remote Command Execution",
    "SIGMA:New User Created Via Net.EXE",
}
NOISY_DETAILS_MARKERS = [".vscode", "codeium", "python-env", "language_server_windows_x64.exe", "pet.exe", "solidtrace_agent.exe"]

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
    return any(k in text for k in ("sigma", "credential dumping", "lsass", "mimikatz", "psexec", "ransomware"))

def _is_noisy_sigma(alert: AlertModel) -> bool:
    rule = str(alert.rule or "")
    text = " ".join([str(alert.details or ""), str(alert.command_line or "")]).lower()
    return rule in NOISY_RULES and any(marker in text for marker in NOISY_DETAILS_MARKERS)

@router.get("/api/v1/sigma/stats", response_model=SigmaStatsResponse)
async def sigma_stats(
    request: Request,
    include_noise: bool = False,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = _alert_query_for_tenant(db, tenant_id).order_by(desc(AlertModel.created_at)).limit(1000).all()
        sigma_alerts = [alert for alert in alerts if _is_sigma_like(alert)]
        if not include_noise:
            sigma_alerts = [alert for alert in sigma_alerts if not _is_noisy_sigma(alert)]

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

        top_rules = [{"name": name, "count": count} for name, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
        detections_last_24h = sum(1 for alert in sigma_alerts if (alert.created_at or "") >= last_24h_cutoff)

        logger.info(
            "sigma_stats_requested request_id=%s tenant=%s user=%s sigma_alert_count=%s include_noise=%s",
            _get_request_id(request), tenant_id, current_user, len(sigma_alerts), include_noise,
        )

        return SigmaStatsResponse(
            total_matches=len(sigma_alerts),
            matches_last_24h=detections_last_24h,
            severity_distribution=severity_counts,
            top_rules=top_rules,
        )
    finally:
        db.close()

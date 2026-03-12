"""
app.api.routes_dashboard
========================
Dashboard summary ve recent activity endpoint'leri.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy import desc

from app.core.security import get_current_tenant_id, require_role
from app.database.db_manager import AlertModel, AuditLogModel, AgentModel, SessionLocal
from app.schemas.models import DashboardRecentActivityItem, DashboardSummaryResponse

logger = logging.getLogger("SolidTrace.Dashboard")
router = APIRouter(tags=["dashboard"])


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
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _online_status(last_seen: Optional[str], threshold_minutes: int = 5) -> bool:
    dt = _parse_dt(last_seen)
    if not dt:
        return False
    return utcnow() - dt <= timedelta(minutes=threshold_minutes)


def _alert_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AlertModel)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)
    return query


def _agent_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AgentModel)
    if tenant_id and hasattr(AgentModel, "tenant_id"):
        query = query.filter(AgentModel.tenant_id == tenant_id)
    return query


def _audit_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AuditLogModel)
    if tenant_id and hasattr(AuditLogModel, "tenant_id"):
        query = query.filter(AuditLogModel.tenant_id == tenant_id)
    return query


@router.get("/api/dashboard/summary", response_model=DashboardSummaryResponse)
async def dashboard_summary(
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert_query = _alert_query_for_tenant(db, tenant_id)
        agent_query = _agent_query_for_tenant(db, tenant_id)

        alerts_last_24h_cutoff = (utcnow() - timedelta(hours=24)).isoformat()

        total_alerts = alert_query.count()
        critical_alerts = alert_query.filter(AlertModel.severity == "CRITICAL").count()
        high_alerts = alert_query.filter(AlertModel.severity == "HIGH").count()
        alerts_last_24h = alert_query.filter(AlertModel.created_at >= alerts_last_24h_cutoff).count()
        open_alerts = alert_query.filter(AlertModel.status == "open").count()
        acknowledged_alerts = alert_query.filter(AlertModel.status == "acknowledged").count()
        resolved_alerts = alert_query.filter(AlertModel.status == "resolved").count()

        agents = agent_query.order_by(desc(AgentModel.last_seen)).all()
        total_assets = len(agents)
        online_assets = sum(1 for agent in agents if _online_status(agent.last_seen))
        offline_assets = sum(1 for agent in agents if agent.last_seen and not _online_status(agent.last_seen))
        revoked_assets = sum(1 for agent in agents if bool(agent.revoked_at))

        top_hosts_raw = (
            alert_query.order_by(desc(AlertModel.created_at))
            .limit(500)
            .all()
        )

        host_counts: dict[str, int] = {}
        rule_counts: dict[str, int] = {}
        latest_alerts = []

        for row in top_hosts_raw:
            host = row.hostname or "unknown"
            rule = row.rule or row.type or "unknown"

            host_counts[host] = host_counts.get(host, 0) + 1
            rule_counts[rule] = rule_counts.get(rule, 0) + 1

        latest_rows = alert_query.order_by(desc(AlertModel.created_at)).limit(10).all()
        for row in latest_rows:
            latest_alerts.append(
                {
                    "id": row.id,
                    "created_at": row.created_at,
                    "hostname": row.hostname,
                    "severity": row.severity,
                    "rule": row.rule,
                    "status": row.status,
                    "risk_score": row.risk_score,
                }
            )

        top_hosts = [
            {"name": host, "count": count}
            for host, count in sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        top_rules = [
            {"name": rule, "count": count}
            for rule, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        logger.info(
            "dashboard_summary_requested request_id=%s tenant=%s user=%s total_alerts=%s total_assets=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            total_alerts,
            total_assets,
        )

        return DashboardSummaryResponse(
            generated_at=utcnow_iso(),
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            alerts_last_24h=alerts_last_24h,
            open_alerts=open_alerts,
            acknowledged_alerts=acknowledged_alerts,
            resolved_alerts=resolved_alerts,
            total_assets=total_assets,
            online_assets=online_assets,
            offline_assets=offline_assets,
            revoked_assets=revoked_assets,
            top_hosts=top_hosts,
            top_rules=top_rules,
            latest_alerts=latest_alerts,
        )
    finally:
        db.close()


@router.get("/api/dashboard/recent-activity", response_model=list[DashboardRecentActivityItem])
async def dashboard_recent_activity(
    request: Request,
    limit: int = 50,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        limit = max(1, min(limit, 200))

        alerts = _alert_query_for_tenant(db, tenant_id).order_by(desc(AlertModel.created_at)).limit(limit).all()
        audits = _audit_query_for_tenant(db, tenant_id).order_by(desc(AuditLogModel.timestamp)).limit(limit).all()

        activity: list[DashboardRecentActivityItem] = []

        for row in alerts:
            activity.append(
                DashboardRecentActivityItem(
                    timestamp=row.created_at,
                    activity_type="alert",
                    title=row.rule or row.type or "Alert",
                    description=row.details or "",
                    severity=row.severity or "INFO",
                    hostname=row.hostname,
                    username=row.username,
                    status=row.status,
                    source_id=row.id,
                )
            )

        for row in audits:
            activity.append(
                DashboardRecentActivityItem(
                    timestamp=row.timestamp,
                    activity_type="audit",
                    title=row.action or "Audit Event",
                    description=row.detail or "",
                    severity="INFO",
                    hostname=None,
                    username=row.username,
                    status=row.result,
                    source_id=row.id,
                )
            )

        activity.sort(key=lambda item: item.timestamp or "", reverse=True)
        activity = activity[:limit]

        logger.info(
            "dashboard_recent_activity_requested request_id=%s tenant=%s user=%s result_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            len(activity),
        )

        return activity
    finally:
        db.close()
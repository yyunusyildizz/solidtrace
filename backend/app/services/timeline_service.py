from __future__ import annotations

from typing import List, Dict, Optional
from sqlalchemy import desc

from app.database.db_manager import (
    AlertModel,
    AuditLogModel,
    CaseAlertLinkModel,
    CaseModel,
)


def build_timeline(db, hostname: str, tenant_id: Optional[str]) -> List[Dict]:
    timeline = []

    query = db.query(AlertModel).filter(AlertModel.hostname == hostname)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)

    alerts = query.order_by(desc(AlertModel.created_at)).limit(50).all()

    for alert in alerts:
        timeline.append(
            {
                "timestamp": alert.created_at,
                "type": "alert",
                "title": alert.rule or alert.type or "Alert",
                "severity": alert.severity,
                "status": alert.status,
                "details": alert.details,
                "source_id": alert.id,
            }
        )

    query = db.query(AuditLogModel).filter(AuditLogModel.target == hostname)
    if tenant_id and hasattr(AuditLogModel, "tenant_id"):
        query = query.filter(AuditLogModel.tenant_id == tenant_id)

    audits = query.order_by(desc(AuditLogModel.timestamp)).limit(50).all()

    for audit in audits:
        timeline.append(
            {
                "timestamp": audit.timestamp,
                "type": "audit",
                "title": audit.action,
                "severity": "INFO",
                "status": audit.result,
                "details": audit.detail,
                "source_id": audit.id,
            }
        )

    timeline.sort(key=lambda x: x["timestamp"], reverse=True)
    return timeline


def build_host_detail(db, hostname: str, tenant_id: Optional[str]) -> Dict:
    query = db.query(AlertModel).filter(AlertModel.hostname == hostname)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)

    alerts = query.order_by(desc(AlertModel.created_at)).limit(100).all()

    total = len(alerts)
    critical = sum(1 for a in alerts if a.severity == "CRITICAL")
    high = sum(1 for a in alerts if a.severity == "HIGH")
    max_risk = max([a.risk_score for a in alerts], default=0)

    return {
        "hostname": hostname,
        "total_alerts": total,
        "critical_count": critical,
        "high_count": high,
        "max_risk_score": max_risk,
        "recent_alerts": [a.to_dict() for a in alerts[:10]],
    }


def build_case_timeline(db, case_id: str, tenant_id: Optional[str]) -> List[Dict]:
    timeline: list[dict] = []

    case_query = db.query(CaseModel).filter(CaseModel.id == case_id)
    if tenant_id and hasattr(CaseModel, "tenant_id"):
        case_query = case_query.filter(CaseModel.tenant_id == tenant_id)

    case_row = case_query.first()
    if not case_row:
        return []

    timeline.append(
        {
            "timestamp": case_row.created_at,
            "type": "case",
            "title": case_row.title,
            "severity": case_row.severity,
            "status": case_row.status,
            "details": case_row.description or case_row.analyst_note,
            "source_id": case_row.id,
        }
    )

    links = (
        db.query(CaseAlertLinkModel)
        .filter(CaseAlertLinkModel.case_id == case_id)
        .order_by(desc(CaseAlertLinkModel.linked_at))
        .all()
    )

    alert_ids = [link.alert_id for link in links]
    if alert_ids:
        alert_query = db.query(AlertModel).filter(AlertModel.id.in_(alert_ids))
        if tenant_id and hasattr(AlertModel, "tenant_id"):
            alert_query = alert_query.filter(AlertModel.tenant_id == tenant_id)

        alerts = alert_query.order_by(desc(AlertModel.created_at)).all()

        for alert in alerts:
            timeline.append(
                {
                    "timestamp": alert.created_at,
                    "type": "alert",
                    "title": alert.rule or alert.type or "Alert",
                    "severity": alert.severity,
                    "status": alert.status,
                    "details": alert.details,
                    "source_id": alert.id,
                }
            )

    audit_query = db.query(AuditLogModel).filter(AuditLogModel.target == case_id)
    if tenant_id and hasattr(AuditLogModel, "tenant_id"):
        audit_query = audit_query.filter(AuditLogModel.tenant_id == tenant_id)

    audits = audit_query.order_by(desc(AuditLogModel.timestamp)).limit(100).all()

    for audit in audits:
        timeline.append(
            {
                "timestamp": audit.timestamp,
                "type": "audit",
                "title": audit.action,
                "severity": "INFO",
                "status": audit.result,
                "details": audit.detail,
                "source_id": audit.id,
            }
        )

    timeline.sort(key=lambda x: x["timestamp"], reverse=True)
    return timeline
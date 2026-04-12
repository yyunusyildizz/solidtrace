from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict

from sqlalchemy import desc

from app.database.db_manager import (
    AlertModel,
    CaseAlertLinkModel,
    CaseModel,
    utcnow_iso,
)
from app.services.timeline_service import build_case_timeline


def _derive_case_severity(alerts: list[AlertModel], fallback: str = "INFO") -> str:
    if not alerts:
        return fallback

    max_risk = max((a.risk_score or 0) for a in alerts)

    if max_risk >= 90:
        return "CRITICAL"
    if max_risk >= 70:
        return "HIGH"
    if max_risk >= 40:
        return "WARNING"
    return "INFO"


def _case_to_response(case: CaseModel, related_alerts: Optional[list[dict]] = None) -> dict:
    related_alerts = related_alerts or []
    return {
        "id": case.id,
        "tenant_id": case.tenant_id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity": case.severity,
        "owner": case.owner,
        "analyst_note": case.analyst_note,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "closed_at": case.closed_at,
        "related_alert_count": len(related_alerts),
        "related_alerts": related_alerts,
    }


def create_case(
    db,
    *,
    tenant_id: Optional[str],
    title: str,
    description: Optional[str] = None,
    severity: str = "INFO",
    owner: Optional[str] = None,
) -> CaseModel:
    now = utcnow_iso()
    row = CaseModel(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        title=title,
        description=description,
        status="open",
        severity=severity,
        owner=owner,
        analyst_note=None,
        created_at=now,
        updated_at=now,
        closed_at=None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_cases(db, tenant_id: Optional[str], limit: int = 100) -> List[Dict]:
    query = db.query(CaseModel)

    if tenant_id and hasattr(CaseModel, "tenant_id"):
        query = query.filter(CaseModel.tenant_id == tenant_id)

    rows = (
        query.order_by(desc(CaseModel.created_at))
        .limit(max(1, min(limit, 500)))
        .all()
    )

    results: list[dict] = []
    for row in rows:
        related_count = (
            db.query(CaseAlertLinkModel)
            .filter(CaseAlertLinkModel.case_id == row.id)
            .count()
        )
        payload = _case_to_response(row, related_alerts=[])
        payload["related_alert_count"] = related_count
        results.append(payload)

    return results


def get_case_detail(db, case_id: str, tenant_id: Optional[str]) -> Optional[Dict]:
    query = db.query(CaseModel).filter(CaseModel.id == case_id)

    if tenant_id and hasattr(CaseModel, "tenant_id"):
        query = query.filter(CaseModel.tenant_id == tenant_id)

    row = query.first()
    if not row:
        return None

    links = (
        db.query(CaseAlertLinkModel)
        .filter(CaseAlertLinkModel.case_id == row.id)
        .all()
    )

    alert_ids = [link.alert_id for link in links]
    related_alerts: list[dict] = []
    linked_hosts: list[str] = []
    linked_users: list[str] = []
    max_risk_score = 0
    avg_risk_score = 0.0
    critical_alert_count = 0
    high_alert_count = 0
    derived_severity = row.severity or "INFO"

    if alert_ids:
        alert_query = db.query(AlertModel).filter(AlertModel.id.in_(alert_ids))
        if tenant_id and hasattr(AlertModel, "tenant_id"):
            alert_query = alert_query.filter(AlertModel.tenant_id == tenant_id)

        alerts = alert_query.order_by(desc(AlertModel.created_at)).all()
        related_alerts = [a.to_dict() for a in alerts]

        linked_hosts = sorted({a.hostname for a in alerts if getattr(a, "hostname", None)})
        linked_users = sorted({a.username for a in alerts if getattr(a, "username", None)})

        risk_scores = [(a.risk_score or 0) for a in alerts]
        max_risk_score = max(risk_scores) if risk_scores else 0
        avg_risk_score = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0

        critical_alert_count = sum(1 for a in alerts if (a.severity or "").upper() == "CRITICAL")
        high_alert_count = sum(1 for a in alerts if (a.severity or "").upper() == "HIGH")

        derived_severity = _derive_case_severity(alerts, fallback=row.severity or "INFO")

    timeline = build_case_timeline(db, row.id, tenant_id)

    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "title": row.title,
        "description": row.description,
        "status": row.status,
        "severity": derived_severity,
        "owner": row.owner,
        "analyst_note": row.analyst_note,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "closed_at": row.closed_at,
        "related_alert_count": len(related_alerts),
        "related_alerts": related_alerts,
        "timeline": timeline,
        "linked_hosts": linked_hosts,
        "linked_users": linked_users,
        "max_risk_score": max_risk_score,
        "avg_risk_score": avg_risk_score,
        "critical_alert_count": critical_alert_count,
        "high_alert_count": high_alert_count,
    }


def assign_case(db, case_id: str, owner: str, tenant_id: Optional[str]) -> Optional[CaseModel]:
    query = db.query(CaseModel).filter(CaseModel.id == case_id)

    if tenant_id and hasattr(CaseModel, "tenant_id"):
        query = query.filter(CaseModel.tenant_id == tenant_id)

    row = query.first()
    if not row:
        return None

    row.owner = owner
    if row.status == "open":
        row.status = "acknowledged"
    row.updated_at = utcnow_iso()

    db.commit()
    db.refresh(row)
    return row


def update_case_status(db, case_id: str, status: str, tenant_id: Optional[str]) -> Optional[CaseModel]:
    query = db.query(CaseModel).filter(CaseModel.id == case_id)

    if tenant_id and hasattr(CaseModel, "tenant_id"):
        query = query.filter(CaseModel.tenant_id == tenant_id)

    row = query.first()
    if not row:
        return None

    row.status = status
    row.updated_at = utcnow_iso()
    if status == "resolved":
        row.closed_at = utcnow_iso()
    elif status in {"open", "acknowledged"}:
        row.closed_at = None

    db.commit()
    db.refresh(row)
    return row


def update_case_note(db, case_id: str, note: str, tenant_id: Optional[str]) -> Optional[CaseModel]:
    query = db.query(CaseModel).filter(CaseModel.id == case_id)

    if tenant_id and hasattr(CaseModel, "tenant_id"):
        query = query.filter(CaseModel.tenant_id == tenant_id)

    row = query.first()
    if not row:
        return None

    row.analyst_note = note
    row.updated_at = utcnow_iso()

    db.commit()
    db.refresh(row)
    return row


def link_alert_to_case(db, case_id: str, alert_id: str, tenant_id: Optional[str]) -> Optional[CaseAlertLinkModel]:
    case_query = db.query(CaseModel).filter(CaseModel.id == case_id)
    if tenant_id and hasattr(CaseModel, "tenant_id"):
        case_query = case_query.filter(CaseModel.tenant_id == tenant_id)

    case_row = case_query.first()
    if not case_row:
        return None

    alert_query = db.query(AlertModel).filter(AlertModel.id == alert_id)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        alert_query = alert_query.filter(AlertModel.tenant_id == tenant_id)

    alert_row = alert_query.first()
    if not alert_row:
        return None

    existing = (
        db.query(CaseAlertLinkModel)
        .filter(
            CaseAlertLinkModel.case_id == case_id,
            CaseAlertLinkModel.alert_id == alert_id,
        )
        .first()
    )
    if existing:
        return existing

    link = CaseAlertLinkModel(
        id=str(uuid.uuid4()),
        case_id=case_id,
        alert_id=alert_id,
        linked_at=utcnow_iso(),
    )
    db.add(link)

    case_row.updated_at = utcnow_iso()
    db.add(case_row)

    db.commit()
    db.refresh(link)
    return link


def find_open_case_for_host(
    db,
    *,
    hostname: Optional[str],
    tenant_id: Optional[str],
    lookback_minutes: int = 120,
) -> Optional[CaseModel]:
    if not hostname:
        return None

    since = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()

    query = (
        db.query(CaseModel)
        .filter(
            CaseModel.status.in_(["open", "acknowledged"]),
            CaseModel.created_at >= since,
        )
        .order_by(desc(CaseModel.created_at))
    )

    if tenant_id and hasattr(CaseModel, "tenant_id"):
        query = query.filter(CaseModel.tenant_id == tenant_id)

    rows = query.all()
    for case_row in rows:
        links = db.query(CaseAlertLinkModel).filter(CaseAlertLinkModel.case_id == case_row.id).all()
        if not links:
            continue

        alert_ids = [link.alert_id for link in links]
        alert_query = db.query(AlertModel).filter(AlertModel.id.in_(alert_ids))
        if tenant_id and hasattr(AlertModel, "tenant_id"):
            alert_query = alert_query.filter(AlertModel.tenant_id == tenant_id)

        alerts = alert_query.all()
        if any((a.hostname or "").strip().lower() == hostname.strip().lower() for a in alerts):
            return case_row

    return None


def ensure_case_for_alert(
    db,
    *,
    alert: AlertModel,
    auto_create_threshold: int = 90,
) -> Optional[CaseModel]:
    if not alert:
        return None

    existing_case = find_open_case_for_host(
        db,
        hostname=alert.hostname,
        tenant_id=getattr(alert, "tenant_id", None),
    )

    if existing_case:
        link_alert_to_case(
            db,
            case_id=existing_case.id,
            alert_id=alert.id,
            tenant_id=getattr(alert, "tenant_id", None),
        )
        return existing_case

    if (alert.risk_score or 0) < auto_create_threshold and (alert.severity or "").upper() != "CRITICAL":
        return None

    case_row = create_case(
        db,
        tenant_id=getattr(alert, "tenant_id", None),
        title=alert.rule or alert.type or "Auto-created Case",
        description=alert.details,
        severity=alert.severity or "HIGH",
        owner=None,
    )
    link_alert_to_case(
        db,
        case_id=case_row.id,
        alert_id=alert.id,
        tenant_id=getattr(alert, "tenant_id", None),
    )
    return case_row

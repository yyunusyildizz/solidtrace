"""
app.api.routes_investigations
=============================
Alert-driven investigations endpoints.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, or_

from app.core.security import get_current_user, get_current_tenant_id
from app.database.db_manager import SessionLocal, AlertModel

router = APIRouter(tags=["investigations"])


def _query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AlertModel)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)
    return query


def _normalize_status(status: Optional[str]) -> str:
    value = (status or "open").strip().lower()

    if value in {"open", "new", "created"}:
        return "open"
    if value in {"acknowledged", "ack", "investigating", "in_progress"}:
        return "in_progress"
    if value in {"contained"}:
        return "contained"
    if value in {"resolved", "closed"}:
        return "closed"
    return "open"


def _normalize_severity(severity: Optional[str]) -> str:
    value = (severity or "INFO").strip().upper()

    if value in {"CRITICAL", "HIGH", "WARNING", "INFO"}:
        return value
    if value == "MEDIUM":
        return "WARNING"
    if value == "LOW":
        return "INFO"
    return "INFO"


def _safe_str(value: object | None, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value)


def _process_label(command_line: Optional[str]) -> str:
    if not command_line:
        return "unknown-process"

    first = command_line.strip().split(" ")[0].strip()
    if "\\" in first:
        first = first.split("\\")[-1]
    if "/" in first:
        first = first.split("/")[-1]

    return first or "unknown-process"


def _related_alert_count(db, tenant_id: Optional[str], alert) -> int:
    hostname = getattr(alert, "hostname", None)
    username = getattr(alert, "username", None)
    rule = getattr(alert, "rule", None)

    query = _query_for_tenant(db, tenant_id)
    conditions = []

    if hostname:
        conditions.append(AlertModel.hostname == hostname)
    if username:
        conditions.append(AlertModel.username == username)
    if rule:
        conditions.append(AlertModel.rule == rule)

    if not conditions:
        return 1

    return query.filter(or_(*conditions)).count()


def _build_tags(alert) -> list[str]:
    tags: list[str] = []

    hostname = _safe_str(getattr(alert, "hostname", None), "")
    username = _safe_str(getattr(alert, "username", None), "")
    rule = _safe_str(getattr(alert, "rule", None), "")
    command_line = _safe_str(getattr(alert, "command_line", None), "")
    severity = _normalize_severity(getattr(alert, "severity", None))

    if severity:
        tags.append(f"severity:{severity.lower()}")
    if rule:
        tags.append(rule.lower().replace(" ", "-"))
    if hostname:
        tags.append(f"host:{hostname}")
    if username and username != "unknown-user":
        tags.append(f"user:{username}")
    if command_line:
        tags.append("process-execution")

    # sıra koruyarak uniq
    seen = set()
    result = []
    for tag in tags:
        if tag not in seen:
            seen.add(tag)
            result.append(tag)

    return result[:6]


def _queue_item(db, tenant_id: Optional[str], alert) -> dict:
    alert_id = _safe_str(getattr(alert, "id", ""))
    hostname = _safe_str(getattr(alert, "hostname", None), "unknown-host")
    username = _safe_str(getattr(alert, "username", None), "unknown-user")
    rule = _safe_str(getattr(alert, "rule", None), "")
    alert_type = _safe_str(getattr(alert, "type", None), "Alert")
    severity = _normalize_severity(getattr(alert, "severity", None))
    status = _normalize_status(getattr(alert, "status", None))
    assigned_to = _safe_str(getattr(alert, "assigned_to", None), "Unassigned")
    created_at = _safe_str(getattr(alert, "created_at", None), "")
    updated_at = _safe_str(
        getattr(alert, "assigned_at", None)
        or getattr(alert, "resolved_at", None)
        or getattr(alert, "created_at", None),
        "",
    )
    details = _safe_str(getattr(alert, "details", None), "")

    title = rule or f"{alert_type} on {hostname}"
    summary = details or f"Investigation candidate for host {hostname} and user {username}."

    return {
        "id": f"INV-{alert_id}",
        "alert_id": alert_id,
        "title": title,
        "status": status,
        "severity": severity,
        "owner": assigned_to,
        "created_at": created_at,
        "updated_at": updated_at or created_at,
        "related_alerts": _related_alert_count(db, tenant_id, alert),
        "affected_host": hostname,
        "summary": summary,
        "tags": _build_tags(alert),
    }


@router.get("/api/investigations")
async def get_investigations(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _query_for_tenant(db, tenant_id)
        alerts = (
            query.order_by(
                desc(AlertModel.risk_score),
                desc(AlertModel.created_at),
            )
            .limit(limit)
            .all()
        )

        return [_queue_item(db, tenant_id, alert) for alert in alerts]
    finally:
        db.close()


@router.get("/api/investigations/{investigation_id}")
async def get_investigation_detail(
    investigation_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    alert_id = investigation_id.removeprefix("INV-")

    db = SessionLocal()
    try:
        alert = _query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Investigation not found")

        return _queue_item(db, tenant_id, alert)
    finally:
        db.close()


@router.get("/api/investigations/graph/{alert_id}")
async def get_investigation_graph(
    alert_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert = _query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        hostname = _safe_str(getattr(alert, "hostname", None), "unknown-host")
        username = _safe_str(getattr(alert, "username", None), "unknown-user")
        rule = _safe_str(getattr(alert, "rule", None), "Detection Rule")
        command_line = _safe_str(getattr(alert, "command_line", None), "")
        process_name = _process_label(command_line)
        severity = _normalize_severity(getattr(alert, "severity", None))
        status = _normalize_status(getattr(alert, "status", None))
        risk_score = int(getattr(alert, "risk_score", 0) or 0)
        details = _safe_str(getattr(alert, "details", None), "")
        title = rule or f"Alert {alert_id}"

        rule_slug = rule.lower().replace(" ", "-") if rule else f"rule-{alert_id}"

        related_count = _related_alert_count(db, tenant_id, alert)

        nodes = [
            {
                "id": f"alert-{alert_id}",
                "label": f"ALERT-{alert_id}",
                "type": "alert",
                "risk": risk_score,
                "meta": f"{status} / {severity}",
            },
            {
                "id": f"host-{hostname}",
                "label": hostname,
                "type": "host",
                "risk": max(risk_score - 10, 0),
                "meta": "Affected host",
            },
            {
                "id": f"user-{username}",
                "label": username,
                "type": "user",
                "risk": max(risk_score - 20, 0),
                "meta": "Related user",
            },
            {
                "id": f"proc-{process_name}",
                "label": process_name,
                "type": "process",
                "risk": max(risk_score - 5, 0),
                "meta": command_line or "Observed process execution",
            },
            {
                "id": f"rule-{rule_slug}",
                "label": rule,
                "type": "rule",
                "risk": risk_score,
                "meta": details or "Detection rule match",
            },
        ]

        edges = [
            {"from": f"user-{username}", "to": f"proc-{process_name}", "label": "executed"},
            {"from": f"proc-{process_name}", "to": f"host-{hostname}", "label": "ran on"},
            {"from": f"proc-{process_name}", "to": f"rule-{rule_slug}", "label": "matched"},
            {"from": f"rule-{rule_slug}", "to": f"alert-{alert_id}", "label": "generated"},
            {"from": f"host-{hostname}", "to": f"alert-{alert_id}", "label": "affected"},
        ]

        if username != "unknown-user":
            edges.append(
                {"from": f"user-{username}", "to": f"host-{hostname}", "label": "accessed"}
            )

        return {
            "alert_id": alert_id,
            "title": title,
            "nodes": nodes,
            "edges": edges,
            "meta": {
                "summary": details or f"Alert-driven graph for {hostname}",
                "related_alerts": related_count,
                "severity": severity,
                "status": status,
            },
        }
    finally:
        db.close()
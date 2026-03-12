"""
app.api.routes_alerts
=====================
Alert sorgulama, lifecycle, assignment, analytics, istatistik ve aylık rapor endpoint'leri.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, or_

from app.core.security import get_current_user, get_current_tenant_id, require_role
from app.database.db_manager import SessionLocal, AlertModel, AuditLogModel, write_audit
from app.schemas.models import (
    AlertActionResponse,
    AlertAssignRequest,
    AlertNoteUpdateRequest,
    AlertResolveRequest,
    AlertResponse,
    AlertStatusUpdateRequest,
)

logger = logging.getLogger("SolidTrace.Alerts")
router = APIRouter(tags=["alerts"])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")


def _alert_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AlertModel)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)
    return query


def _audit_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AuditLogModel)
    if tenant_id and hasattr(AuditLogModel, "tenant_id"):
        query = query.filter(AuditLogModel.tenant_id == tenant_id)
    return query


async def _write_alert_audit(
    current_user: str,
    action: str,
    target: str,
    detail: str = "",
    tenant_id: Optional[str] = None,
) -> None:
    db = SessionLocal()
    try:
        await write_audit(
            db,
            current_user,
            action,
            target=target,
            detail=detail[:1000],
            tenant_id=tenant_id,
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ALERT LİSTESİ
# ---------------------------------------------------------------------------

@router.get("/api/alerts", response_model=list[AlertResponse])
async def get_alerts(
    request: Request,
    q: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    assigned_to: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id)

        if severity and severity.strip():
            query = query.filter(AlertModel.severity == severity.strip())

        if status_filter and status_filter.strip():
            query = query.filter(AlertModel.status == status_filter.strip())

        if assigned_to and assigned_to.strip():
            query = query.filter(AlertModel.assigned_to == assigned_to.strip())

        if q and q.strip():
            term = f"%{q.strip()}%"
            query = query.filter(
                or_(
                    AlertModel.hostname.ilike(term),
                    AlertModel.rule.ilike(term),
                    AlertModel.details.ilike(term),
                    AlertModel.username.ilike(term),
                    AlertModel.type.ilike(term),
                )
            )

        rows = query.order_by(desc(AlertModel.created_at)).limit(limit).all()

        logger.info(
            "alert_list_requested request_id=%s tenant=%s user=%s limit=%s result_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            limit,
            len(rows),
        )

        return [AlertResponse(**row.to_dict()) for row in rows]
    except Exception as exc:
        logger.exception(
            "alert_list_failed request_id=%s tenant=%s user=%s error=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            exc,
        )
        raise HTTPException(status_code=500, detail="Alert listesi alınamadı")
    finally:
        db.close()


@router.get("/api/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert_detail(
    alert_id: str,
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        logger.info(
            "alert_detail_requested request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
        )

        return AlertResponse(**alert.to_dict())
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ALERT LIFECYCLE
# ---------------------------------------------------------------------------

@router.patch("/api/alerts/{alert_id}/status", response_model=AlertActionResponse)
async def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdateRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.status = payload.status

        if payload.status == "resolved":
            alert.resolved_at = utcnow_iso()
            alert.resolved_by = current_user
        else:
            alert.resolved_at = None
            if payload.status == "open":
                alert.resolved_by = None

        db.commit()

        logger.info(
            "alert_status_updated request_id=%s tenant=%s user=%s alert_id=%s status=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
            payload.status,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERT_STATUS_UPDATE",
            target=alert_id,
            detail=f"status={payload.status}",
            tenant_id=tenant_id,
        )

        return AlertActionResponse(
            status=payload.status,
            alert_id=alert_id,
            assigned_to=alert.assigned_to,
            assigned_at=alert.assigned_at,
        )
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/ack", response_model=AlertActionResponse)
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.status = "acknowledged"
        db.commit()

        logger.info(
            "alert_acknowledged request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERT_ACKNOWLEDGE",
            target=alert_id,
            detail="Alert acknowledged",
            tenant_id=tenant_id,
        )

        return AlertActionResponse(
            status="acknowledged",
            alert_id=alert_id,
            assigned_to=alert.assigned_to,
            assigned_at=alert.assigned_at,
        )
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/resolve", response_model=AlertActionResponse)
async def resolve_alert(
    alert_id: str,
    payload: AlertResolveRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.status = "resolved"
        alert.resolved_at = utcnow_iso()
        alert.resolved_by = current_user

        if payload.note:
            alert.analyst_note = payload.note

        db.commit()

        logger.info(
            "alert_resolved request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERT_RESOLVE",
            target=alert_id,
            detail=(payload.note or "Alert resolved")[:1000],
            tenant_id=tenant_id,
        )

        return AlertActionResponse(
            status="resolved",
            alert_id=alert_id,
            analyst_note=alert.analyst_note,
            assigned_to=alert.assigned_to,
            assigned_at=alert.assigned_at,
        )
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/reopen", response_model=AlertActionResponse)
async def reopen_alert(
    alert_id: str,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.status = "open"
        alert.resolved_at = None
        alert.resolved_by = None

        db.commit()

        logger.info(
            "alert_reopened request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERT_REOPEN",
            target=alert_id,
            detail="Alert reopened",
            tenant_id=tenant_id,
        )

        return AlertActionResponse(
            status="open",
            alert_id=alert_id,
            assigned_to=alert.assigned_to,
            assigned_at=alert.assigned_at,
        )
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/note", response_model=AlertActionResponse)
async def update_alert_note(
    alert_id: str,
    payload: AlertNoteUpdateRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.analyst_note = payload.note
        db.commit()

        logger.info(
            "alert_note_updated request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERT_NOTE_UPDATE",
            target=alert_id,
            detail=payload.note[:1000],
            tenant_id=tenant_id,
        )

        return AlertActionResponse(
            status="updated",
            alert_id=alert_id,
            analyst_note=alert.analyst_note,
            assigned_to=alert.assigned_to,
            assigned_at=alert.assigned_at,
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ALERT ASSIGNMENT
# ---------------------------------------------------------------------------

@router.patch("/api/alerts/{alert_id}/assign", response_model=AlertActionResponse)
async def assign_alert(
    alert_id: str,
    payload: AlertAssignRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.assigned_to = payload.assigned_to
        alert.assigned_at = utcnow_iso()

        if alert.status == "open":
            alert.status = "acknowledged"

        db.commit()

        logger.info(
            "alert_assigned request_id=%s tenant=%s user=%s alert_id=%s assigned_to=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
            payload.assigned_to,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERT_ASSIGN",
            target=alert_id,
            detail=f"assigned_to={payload.assigned_to}",
            tenant_id=tenant_id,
        )

        return AlertActionResponse(
            status=alert.status,
            alert_id=alert_id,
            analyst_note=alert.analyst_note,
            assigned_to=alert.assigned_to,
            assigned_at=alert.assigned_at,
        )
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/unassign", response_model=AlertActionResponse)
async def unassign_alert(
    alert_id: str,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id)
        alert = query.first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.assigned_to = None
        alert.assigned_at = None
        db.commit()

        logger.info(
            "alert_unassigned request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            alert_id,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERT_UNASSIGN",
            target=alert_id,
            detail="assignment cleared",
            tenant_id=tenant_id,
        )

        return AlertActionResponse(
            status=alert.status,
            alert_id=alert_id,
            analyst_note=alert.analyst_note,
            assigned_to=None,
            assigned_at=None,
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ANALİTİK & İSTATİSTİK
# ---------------------------------------------------------------------------

@router.get("/api/analytics")
async def get_analytics(
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id)
        alerts = query.order_by(desc(AlertModel.created_at)).limit(500).all()

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        timeline: dict[str, int] = {}

        for alert in alerts:
            sev = alert.severity if alert.severity in severity_counts else "INFO"
            severity_counts[sev] += 1
            try:
                if alert.created_at:
                    key = datetime.fromisoformat(alert.created_at).strftime("%H:00")
                    timeline[key] = timeline.get(key, 0) + 1
            except Exception:
                pass

        logger.info(
            "analytics_requested request_id=%s tenant=%s user=%s alert_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            len(alerts),
        )

        return {
            "severity_distribution": [
                {"name": key, "value": value}
                for key, value in severity_counts.items()
                if value > 0
            ],
            "activity_trend": [
                {"time": key, "count": value}
                for key, value in sorted(timeline.items())
            ],
        }
    finally:
        db.close()


@router.get("/api/stats")
async def get_stats(
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id)

        total = query.count()
        critical = query.filter(AlertModel.risk_score >= 70).count()
        yesterday = (utcnow() - timedelta(days=1)).isoformat()
        recent = query.filter(AlertModel.created_at >= yesterday).count()

        logger.info(
            "stats_requested request_id=%s tenant=%s user=%s total=%s critical=%s recent_24h=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            total,
            critical,
            recent,
        )

        return {
            "total_logs": total,
            "critical_count": critical,
            "last_24h": recent,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ALERT TEMİZLE
# ---------------------------------------------------------------------------

@router.delete("/api/alerts/clear")
async def clear_alerts(
    request: Request,
    current_user: str = Depends(require_role("admin")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    from app.api.websockets import broadcast

    db = SessionLocal()
    try:
        query = _alert_query_for_tenant(db, tenant_id)
        count = query.count()
        query.delete()
        db.commit()

        await broadcast(
            {
                "type": "ACTION_LOG",
                "message": f"🧹 {count} alarm temizlendi (by {current_user})",
            }
        )

        logger.warning(
            "alerts_cleared request_id=%s tenant=%s user=%s cleared_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            count,
        )

        await _write_alert_audit(
            current_user=current_user,
            action="ALERTS_CLEAR",
            target="alerts",
            detail=f"{count} alerts cleared",
            tenant_id=tenant_id,
        )

        return {"status": "cleared", "count": count}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------

@router.get("/api/audit-log")
async def get_audit_log(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    username: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    current_user: str = Depends(require_role("admin")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = _audit_query_for_tenant(db, tenant_id).order_by(desc(AuditLogModel.timestamp))

        if username:
            query = query.filter(AuditLogModel.username == username)
        if action:
            query = query.filter(AuditLogModel.action == action)

        rows = query.limit(limit).all()

        logger.info(
            "audit_log_requested request_id=%s tenant=%s user=%s limit=%s result_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            limit,
            len(rows),
        )

        return [
            {
                "timestamp": row.timestamp,
                "username": row.username,
                "action": row.action,
                "target": row.target,
                "detail": row.detail,
                "ip_address": row.ip_address,
                "result": row.result,
                "tenant_id": row.tenant_id,
            }
            for row in rows
        ]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AYLIK RAPOR
# ---------------------------------------------------------------------------

@router.get("/api/report/monthly")
async def monthly_report(
    request: Request,
    month: Optional[str] = Query(default=None, description="YYYY-MM formatı"),
    format: str = Query(default="json", pattern="^(json|pdf)$"),
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    import io

    if month:
        try:
            report_dt = datetime.strptime(month, "%Y-%m")
        except ValueError:
            raise HTTPException(status_code=400, detail="Tarih formatı: YYYY-MM")
    else:
        report_dt = utcnow().replace(day=1)

    month_start = report_dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    month_end = (
        report_dt.replace(year=report_dt.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        if report_dt.month == 12
        else report_dt.replace(month=report_dt.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
    ).isoformat()
    month_label = report_dt.strftime("%B %Y")

    db = SessionLocal()
    try:
        alert_query = _alert_query_for_tenant(db, tenant_id).filter(
            AlertModel.created_at >= month_start,
            AlertModel.created_at < month_end,
        )
        alerts = alert_query.all()

        total = len(alerts)
        critical_count = sum(1 for alert in alerts if alert.severity == "CRITICAL")
        high_count = sum(1 for alert in alerts if alert.severity == "HIGH")
        warning_count = sum(1 for alert in alerts if alert.severity == "WARNING")
        unique_hosts = len(set(alert.hostname for alert in alerts if alert.hostname))
        avg_risk = round(sum(alert.risk_score for alert in alerts) / total, 1) if total else 0

        top_rules: dict[str, int] = {}
        for alert in alerts:
            key = alert.rule or "Unknown Rule"
            top_rules[key] = top_rules.get(key, 0) + 1
        top_rules_sorted = sorted(top_rules.items(), key=lambda item: item[1], reverse=True)[:5]

        audit_count = _audit_query_for_tenant(db, tenant_id).filter(
            AuditLogModel.timestamp >= month_start,
            AuditLogModel.timestamp < month_end,
        ).count()

        report_data = {
            "report_type": "Aylık Güvenlik Raporu",
            "period": month_label,
            "generated_at": utcnow_iso(),
            "generated_by": current_user,
            "tenant_id": tenant_id,
            "summary": {
                "total_alerts": total,
                "critical": critical_count,
                "high": high_count,
                "warning": warning_count,
                "unique_endpoints": unique_hosts,
                "avg_risk_score": avg_risk,
                "actions_taken": audit_count,
                "risk_level": (
                    "KRİTİK" if critical_count > 10 else
                    "YÜKSEK" if critical_count > 3 else
                    "ORTA" if high_count > 10 else
                    "DÜŞÜK"
                ),
            },
            "top_threats": [{"rule": rule, "count": count} for rule, count in top_rules_sorted],
            "kvkk_note": (
                "Bu dönemde veri ihlali riski taşıyan kritik alarm tespit edilmiştir. "
                "KVKK Madde 12 kapsamında gerekli teknik tedbirler alınmıştır."
                if critical_count > 0 else
                "Bu dönemde veri ihlali riski taşıyan kritik alarm tespit edilmemiştir."
            ),
            "recommendations": _build_recommendations(critical_count, high_count, top_rules_sorted),
        }

        logger.info(
            "monthly_report_requested request_id=%s tenant=%s user=%s month=%s format=%s alert_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            month_label,
            format,
            total,
        )

        if format == "json":
            return report_data

        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                HRFlowable,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )

            buf = io.BytesIO()
            doc = SimpleDocTemplate(
                buf,
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm,
            )
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                "title",
                parent=styles["Title"],
                fontSize=20,
                textColor=colors.HexColor("#1a1a2e"),
                spaceAfter=6,
            )
            sub_style = ParagraphStyle(
                "sub",
                parent=styles["Normal"],
                fontSize=11,
                textColor=colors.HexColor("#444"),
                spaceAfter=4,
            )
            label_style = ParagraphStyle(
                "label",
                parent=styles["Normal"],
                fontSize=9,
                textColor=colors.HexColor("#888"),
                spaceAfter=2,
            )
            body_style = ParagraphStyle(
                "body",
                parent=styles["Normal"],
                fontSize=10,
                spaceAfter=6,
                leading=14,
            )

            story.append(Paragraph("🛡 SolidTrace", title_style))
            story.append(Paragraph(f"Aylık Güvenlik Raporu — {month_label}", sub_style))
            story.append(
                Paragraph(
                    f"Oluşturulma: {utcnow().strftime('%d.%m.%Y %H:%M')} | Hazırlayan: {current_user}",
                    label_style,
                )
            )
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#ddd"), spaceAfter=12))

            risk_level = report_data["summary"]["risk_level"]
            risk_color = {
                "KRİTİK": "#e74c3c",
                "YÜKSEK": "#e67e22",
                "ORTA": "#f39c12",
                "DÜŞÜK": "#27ae60",
            }

            summary_data = [
                ["Toplam Alarm", "Kritik", "Yüksek", "Risk Ort.", "Genel Risk"],
                [str(total), str(critical_count), str(high_count), str(avg_risk), risk_level],
            ]
            table = Table(summary_data, colWidths=[3.2 * cm] * 5)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, 0), 9),
                        ("FONTSIZE", (0, 1), (-1, 1), 13),
                        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                        ("BACKGROUND", (4, 1), (4, 1), colors.HexColor(risk_color.get(risk_level, "#888"))),
                        ("TEXTCOLOR", (4, 1), (4, 1), colors.white),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [colors.HexColor("#f8f9fa")]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 0.5 * cm))

            story.append(Paragraph("En Çok Tetiklenen Tehdit Kuralları", styles["Heading2"]))
            if top_rules_sorted:
                threat_data = [["#", "Kural Adı", "Tetiklenme"]]
                for idx, (rule, count) in enumerate(top_rules_sorted, 1):
                    threat_data.append([str(idx), rule[:60], str(count)])

                threat_table = Table(threat_data, colWidths=[1 * cm, 12 * cm, 3 * cm])
                threat_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                             [colors.HexColor("#ffffff"), colors.HexColor("#f2f2f2")]),
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccc")),
                            ("TOPPADDING", (0, 0), (-1, -1), 5),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                story.append(threat_table)

            story.append(Spacer(1, 0.4 * cm))
            story.append(Paragraph("KVKK Uyum Notu", styles["Heading2"]))
            story.append(Paragraph(report_data["kvkk_note"], body_style))
            story.append(Spacer(1, 0.3 * cm))

            story.append(Paragraph("Öneriler ve Aksiyonlar", styles["Heading2"]))
            for rec in report_data["recommendations"]:
                story.append(Paragraph(f"• {rec}", body_style))

            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ccc")))
            story.append(
                Paragraph(
                    "Bu rapor SolidTrace Siber Güvenlik İzleme Platformu tarafından otomatik oluşturulmuştur.",
                    ParagraphStyle(
                        "footer",
                        parent=styles["Normal"],
                        fontSize=8,
                        textColor=colors.HexColor("#999"),
                    ),
                )
            )

            doc.build(story)
            buf.seek(0)

            filename = f"solidtrace-rapor-{report_dt.strftime('%Y-%m')}.pdf"
            return StreamingResponse(
                buf,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        except ImportError:
            raise HTTPException(
                status_code=503,
                detail="PDF için 'reportlab' paketi gerekli: pip install reportlab",
            )
    finally:
        db.close()


def _build_recommendations(critical: int, high: int, top_rules: list[tuple[str, int]]) -> list[str]:
    recs: list[str] = []
    if critical > 0:
        recs.append(f"{critical} kritik alarm tespit edildi. Etkilenen endpoint'ler incelenmeli.")
    if high > 5:
        recs.append("Yüksek riskli alarm sayısı fazla — endpoint güvenlik politikaları güçlendirilmeli.")
    if top_rules:
        recs.append(f"En sık kural: '{top_rules[0][0]}' — kullanıcı farkındalık eğitimi önerilir.")
    recs.append("Tüm kullanıcı parolalarının 90 günde bir değiştirilmesi önerilir.")
    recs.append("Agent'ların güncel sürümde çalıştığından emin olunuz.")
    if not recs:
        recs.append("Bu dönemde önemli bir tehdit tespit edilmedi. İzleme sürdürülmeli.")
    return recs
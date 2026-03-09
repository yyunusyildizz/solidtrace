"""
app.api.routes_alerts
=====================
Alert sorgulama, analytics, istatistik, aylık rapor endpoint'leri.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, or_

from app.core.security import get_current_user, get_current_tenant_id, require_role
from app.database.db_manager import SessionLocal, AlertModel, AuditLogModel

logger = logging.getLogger("SolidTrace.Alerts")
router = APIRouter(tags=["alerts"])


# ---------------------------------------------------------------------------
# ALERT LİSTESİ
# ---------------------------------------------------------------------------

@router.get("/api/alerts")
async def get_alerts(
    q:            Optional[str] = None,
    severity:     Optional[str] = None,
    limit:        int           = Query(default=100, ge=1, le=1000),
    current_user: str           = Depends(get_current_user),
    tenant_id:    Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = db.query(AlertModel)
        if tenant_id:
            query = query.filter(AlertModel.tenant_id == tenant_id)
        if severity and severity.strip():
            query = query.filter(AlertModel.severity == severity)
        if q and q.strip():
            term  = f"%{q}%"
            query = query.filter(or_(
                AlertModel.hostname.ilike(term),
                AlertModel.rule.ilike(term),
                AlertModel.details.ilike(term),
                AlertModel.username.ilike(term),
            ))
        return [a.to_dict() for a in query.order_by(desc(AlertModel.created_at)).limit(limit).all()]
    except Exception as e:
        logger.error(f"Alerts Hatası: {e}")
        return []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ANALİTİK & İSTATİSTİK
# ---------------------------------------------------------------------------

@router.get("/api/analytics")
async def get_analytics(
    current_user: str           = Depends(get_current_user),
    tenant_id:    Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        q = db.query(AlertModel)
        if tenant_id:
            q = q.filter(AlertModel.tenant_id == tenant_id)
        alerts          = q.order_by(desc(AlertModel.created_at)).limit(500).all()
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        timeline: dict  = {}
        for a in alerts:
            sev = a.severity if a.severity in severity_counts else "INFO"
            severity_counts[sev] += 1
            try:
                if a.created_at:
                    key = datetime.fromisoformat(a.created_at).strftime("%H:00")
                    timeline[key] = timeline.get(key, 0) + 1
            except Exception:
                pass
        return {
            "severity_distribution": [{"name": k, "value": v} for k, v in severity_counts.items() if v > 0],
            "activity_trend":        [{"time": k, "count": v} for k, v in sorted(timeline.items())],
        }
    finally:
        db.close()


@router.get("/api/stats")
async def get_stats(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        total     = db.query(AlertModel).count()
        critical  = db.query(AlertModel).filter(AlertModel.risk_score >= 70).count()
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        recent    = db.query(AlertModel).filter(AlertModel.created_at >= yesterday).count()
        return {"total_logs": total, "critical_count": critical, "last_24h": recent}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ALERT TEMİZLE
# ---------------------------------------------------------------------------

@router.delete("/api/alerts/clear")
async def clear_alerts(current_user: str = Depends(require_role("admin"))):
    from app.api.websockets import broadcast
    db = SessionLocal()
    try:
        count = db.query(AlertModel).count()
        db.query(AlertModel).delete()
        db.commit()
        await broadcast({"type": "ACTION_LOG", "message": f"🧹 {count} alarm temizlendi (by {current_user})"})
        logger.warning(f"⚠️  {count} alarm silindi (by {current_user})")
        return {"status": "cleared", "count": count}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------

@router.get("/api/audit-log")
async def get_audit_log(
    limit:        int           = Query(default=100, ge=1, le=1000),
    username:     Optional[str] = Query(default=None),
    action:       Optional[str] = Query(default=None),
    current_user: str           = Depends(require_role("admin")),
):
    db = SessionLocal()
    try:
        q = db.query(AuditLogModel).order_by(desc(AuditLogModel.timestamp))
        if username:
            q = q.filter(AuditLogModel.username == username)
        if action:
            q = q.filter(AuditLogModel.action == action)
        return [
            {"timestamp": e.timestamp, "username": e.username, "action": e.action,
             "target": e.target, "detail": e.detail,
             "ip_address": e.ip_address, "result": e.result}
            for e in q.limit(limit).all()
        ]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AYLIK RAPOR
# ---------------------------------------------------------------------------

@router.get("/api/report/monthly")
async def monthly_report(
    month:        Optional[str] = Query(default=None, description="YYYY-MM formatı"),
    format:       str           = Query(default="json", pattern="^(json|pdf)$"),
    current_user: str           = Depends(get_current_user),
):
    import io

    if month:
        try:
            report_dt = datetime.strptime(month, "%Y-%m")
        except ValueError:
            raise HTTPException(status_code=400, detail="Tarih formatı: YYYY-MM")
    else:
        report_dt = datetime.now().replace(day=1)

    month_start = report_dt.replace(day=1, hour=0, minute=0, second=0).isoformat()
    month_end   = (
        report_dt.replace(year=report_dt.year + 1, month=1, day=1)
        if report_dt.month == 12
        else report_dt.replace(month=report_dt.month + 1, day=1)
    ).isoformat()
    month_label = report_dt.strftime("%B %Y")

    db = SessionLocal()
    try:
        alerts = db.query(AlertModel).filter(
            AlertModel.created_at >= month_start,
            AlertModel.created_at <  month_end,
        ).all()

        total          = len(alerts)
        critical_count = sum(1 for a in alerts if a.severity == "CRITICAL")
        high_count     = sum(1 for a in alerts if a.severity == "HIGH")
        warning_count  = sum(1 for a in alerts if a.severity == "WARNING")
        unique_hosts   = len(set(a.hostname for a in alerts))
        avg_risk       = round(sum(a.risk_score for a in alerts) / total, 1) if total else 0

        top_rules: dict = {}
        for a in alerts:
            top_rules[a.rule] = top_rules.get(a.rule, 0) + 1
        top_rules_sorted = sorted(top_rules.items(), key=lambda x: x[1], reverse=True)[:5]

        audit_count = db.query(AuditLogModel).filter(
            AuditLogModel.timestamp >= month_start,
            AuditLogModel.timestamp <  month_end,
        ).count()

        report_data = {
            "report_type":  "Aylık Güvenlik Raporu",
            "period":       month_label,
            "generated_at": datetime.now().isoformat(),
            "generated_by": current_user,
            "summary": {
                "total_alerts":      total,
                "critical":          critical_count,
                "high":              high_count,
                "warning":           warning_count,
                "unique_endpoints":  unique_hosts,
                "avg_risk_score":    avg_risk,
                "actions_taken":     audit_count,
                "risk_level": (
                    "KRİTİK" if critical_count > 10 else
                    "YÜKSEK" if critical_count > 3  else
                    "ORTA"   if high_count > 10     else "DÜŞÜK"
                ),
            },
            "top_threats": [{"rule": r, "count": c} for r, c in top_rules_sorted],
            "kvkk_note": (
                "Bu dönemde veri ihlali riski taşıyan kritik alarm tespit edilmiştir. "
                "KVKK Madde 12 kapsamında gerekli teknik tedbirler alınmıştır."
                if critical_count > 0 else
                "Bu dönemde veri ihlali riski taşıyan kritik alarm tespit edilmemiştir."
            ),
            "recommendations": _build_recommendations(critical_count, high_count, top_rules_sorted),
        }

        if format == "json":
            return report_data

        # PDF
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                            Spacer, Table, TableStyle, HRFlowable)
            from reportlab.lib.units import cm

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4,
                                    rightMargin=2 * cm, leftMargin=2 * cm,
                                    topMargin=2 * cm, bottomMargin=2 * cm)
            styles = getSampleStyleSheet()
            story  = []

            title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=20,
                                         textColor=colors.HexColor("#1a1a2e"), spaceAfter=6)
            sub_style   = ParagraphStyle("sub",   parent=styles["Normal"], fontSize=11,
                                         textColor=colors.HexColor("#444"), spaceAfter=4)
            label_style = ParagraphStyle("label", parent=styles["Normal"], fontSize=9,
                                         textColor=colors.HexColor("#888"), spaceAfter=2)
            body_style  = ParagraphStyle("body",  parent=styles["Normal"],
                                         fontSize=10, spaceAfter=6, leading=14)

            story.append(Paragraph("🛡 SolidTrace", title_style))
            story.append(Paragraph(f"Aylık Güvenlik Raporu — {month_label}", sub_style))
            story.append(Paragraph(
                f"Oluşturulma: {datetime.now().strftime('%d.%m.%Y %H:%M')} | Hazırlayan: {current_user}",
                label_style))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=colors.HexColor("#ddd"), spaceAfter=12))

            rl = report_data["summary"]["risk_level"]
            risk_color = {"KRİTİK": "#e74c3c", "YÜKSEK": "#e67e22",
                          "ORTA": "#f39c12", "DÜŞÜK": "#27ae60"}
            summary_data = [
                ["Toplam Alarm", "Kritik", "Yüksek", "Risk Ort.", "Genel Risk"],
                [str(total), str(critical_count), str(high_count), str(avg_risk), rl],
            ]
            t = Table(summary_data, colWidths=[3.2 * cm] * 5)
            t.setStyle(TableStyle([
                ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
                ("FONTSIZE",       (0, 0), (-1, 0), 9),
                ("FONTSIZE",       (0, 1), (-1, 1), 13),
                ("FONTNAME",       (0, 1), (-1, 1), "Helvetica-Bold"),
                ("BACKGROUND",     (4, 1), (4, 1), colors.HexColor(risk_color.get(rl, "#888"))),
                ("TEXTCOLOR",      (4, 1), (4, 1), colors.white),
                ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, 1), [colors.HexColor("#f8f9fa")]),
                ("GRID",           (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                ("TOPPADDING",     (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING",  (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.5 * cm))

            story.append(Paragraph("En Çok Tetiklenen Tehdit Kuralları", styles["Heading2"]))
            if top_rules_sorted:
                threat_data = [["#", "Kural Adı", "Tetiklenme"]]
                for i, (rule, cnt) in enumerate(top_rules_sorted, 1):
                    threat_data.append([str(i), rule[:60], str(cnt)])
                tt = Table(threat_data, colWidths=[1 * cm, 12 * cm, 3 * cm])
                tt.setStyle(TableStyle([
                    ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE",       (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#ffffff"), colors.HexColor("#f2f2f2")]),
                    ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#ccc")),
                    ("TOPPADDING",     (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
                ]))
                story.append(tt)
            story.append(Spacer(1, 0.4 * cm))

            story.append(Paragraph("KVKK Uyum Notu", styles["Heading2"]))
            story.append(Paragraph(report_data["kvkk_note"], body_style))
            story.append(Spacer(1, 0.3 * cm))

            story.append(Paragraph("Öneriler ve Aksiyonlar", styles["Heading2"]))
            for rec in report_data["recommendations"]:
                story.append(Paragraph(f"• {rec}", body_style))

            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ccc")))
            story.append(Paragraph(
                "Bu rapor SolidTrace Siber Güvenlik İzleme Platformu tarafından otomatik oluşturulmuştur.",
                ParagraphStyle("footer", parent=styles["Normal"],
                               fontSize=8, textColor=colors.HexColor("#999"))))

            doc.build(story)
            buf.seek(0)
            filename = f"solidtrace-rapor-{report_dt.strftime('%Y-%m')}.pdf"
            return StreamingResponse(buf, media_type="application/pdf",
                                     headers={"Content-Disposition": f'attachment; filename="{filename}"'})

        except ImportError:
            raise HTTPException(status_code=503,
                                detail="PDF için 'reportlab' paketi gerekli: pip install reportlab")
    finally:
        db.close()


def _build_recommendations(critical: int, high: int, top_rules: list) -> list:
    recs = []
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

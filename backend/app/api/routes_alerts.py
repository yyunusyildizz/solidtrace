from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc, or_

from app.core.security import get_current_user, get_current_tenant_id
from app.database.db_manager import SessionLocal, AlertModel, write_audit
from app.schemas.models import (
    AlertResponse,
    AlertActionResponse,
    AlertAssignRequest,
    AlertNoteUpdateRequest,
    AlertResolveRequest,
)

logger = logging.getLogger("SolidTrace.Alerts")
router = APIRouter(tags=["alerts"])

NOISY_RULES = {
    "SIGMA:HackTool - Mimikatz Execution",
    "SIGMA:PowerShell Download and Execution Cradles",
    "SIGMA:WMIC Remote Command Execution",
    "SIGMA:New User Created Via Net.EXE",
    "PROCESS_ANOMALY_STORM",
    "PERSISTENCE_STORM",
    "LOGON_THEN_PERSISTENCE",
}
NOISY_DETAILS_MARKERS = [
    ".vscode", "codeium", "python-env",
    "language_server_windows_x64.exe", "pet.exe", "solidtrace_agent.exe",
]

def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")

def _alert_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AlertModel)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)
    return query

def _is_low_value_historical_alert(alert: AlertModel) -> bool:
    rule = str(getattr(alert, "rule", "") or "")
    details = str(getattr(alert, "details", "") or "").lower()
    command_line = str(getattr(alert, "command_line", "") or "").lower()
    text = " ".join([details, command_line])
    if rule in NOISY_RULES and any(marker in text for marker in NOISY_DETAILS_MARKERS):
        return True
    if rule in {"PROCESS_ANOMALY_STORM", "PERSISTENCE_STORM", "LOGON_THEN_PERSISTENCE"}:
        return True
    return False

@router.get("/api/alerts", response_model=list[AlertResponse])
async def get_alerts(
    request: Request,
    q: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    assigned_to: Optional[str] = Query(default=None),
    include_noise: bool = Query(default=False),
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
            query = query.filter(or_(
                AlertModel.hostname.ilike(term),
                AlertModel.rule.ilike(term),
                AlertModel.details.ilike(term),
                AlertModel.username.ilike(term),
                AlertModel.type.ilike(term),
            ))
        rows = query.order_by(desc(AlertModel.created_at)).limit(limit * 5 if not include_noise else limit).all()
        if not include_noise:
            rows = [row for row in rows if not _is_low_value_historical_alert(row)][:limit]
        logger.info(
            "alert_list_requested request_id=%s tenant=%s user=%s limit=%s result_count=%s include_noise=%s",
            _get_request_id(request), tenant_id, current_user, limit, len(rows), include_noise,
        )
        return [AlertResponse(**row.to_dict()) for row in rows]
    except Exception as exc:
        logger.exception(
            "alert_list_failed request_id=%s tenant=%s user=%s error=%s",
            _get_request_id(request), tenant_id, current_user, exc,
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
# ALERT WORKFLOW ENDPOINTS
# ---------------------------------------------------------------------------


def _build_action_response(alert: AlertModel) -> AlertActionResponse:
    return AlertActionResponse(
        status=alert.status or "open",
        alert_id=alert.id,
        analyst_note=alert.analyst_note,
        assigned_to=alert.assigned_to,
        assigned_at=alert.assigned_at,
    )


@router.patch("/api/alerts/{alert_id}/assign", response_model=AlertActionResponse)
async def assign_alert(
    alert_id: str,
    body: AlertAssignRequest,
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.assigned_to = body.assigned_to
        alert.assigned_at = datetime.now(timezone.utc).isoformat()
        db.commit()
        db.refresh(alert)

        await write_audit(
            db, current_user, "ALERT_ASSIGN",
            target=alert_id,
            detail=f"assigned_to={body.assigned_to}",
            tenant_id=tenant_id,
        )

        logger.info(
            "alert_assigned request_id=%s tenant=%s user=%s alert_id=%s assigned_to=%s",
            _get_request_id(request), tenant_id, current_user, alert_id, body.assigned_to,
        )
        return _build_action_response(alert)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("alert_assign_failed alert_id=%s error=%s", alert_id, exc)
        raise HTTPException(status_code=500, detail="Alert assign başarısız")
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/unassign", response_model=AlertActionResponse)
async def unassign_alert(
    alert_id: str,
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.assigned_to = None
        alert.assigned_at = None
        db.commit()
        db.refresh(alert)

        await write_audit(
            db, current_user, "ALERT_UNASSIGN",
            target=alert_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "alert_unassigned request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request), tenant_id, current_user, alert_id,
        )
        return _build_action_response(alert)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("alert_unassign_failed alert_id=%s error=%s", alert_id, exc)
        raise HTTPException(status_code=500, detail="Alert unassign başarısız")
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/note", response_model=AlertActionResponse)
async def update_alert_note(
    alert_id: str,
    body: AlertNoteUpdateRequest,
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.analyst_note = body.note
        db.commit()
        db.refresh(alert)

        await write_audit(
            db, current_user, "ALERT_NOTE_UPDATE",
            target=alert_id,
            detail=f"note_length={len(body.note)}",
            tenant_id=tenant_id,
        )

        logger.info(
            "alert_note_updated request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request), tenant_id, current_user, alert_id,
        )
        return _build_action_response(alert)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("alert_note_update_failed alert_id=%s error=%s", alert_id, exc)
        raise HTTPException(status_code=500, detail="Alert not güncelleme başarısız")
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/resolve", response_model=AlertActionResponse)
async def resolve_alert(
    alert_id: str,
    body: AlertResolveRequest,
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.status = "resolved"
        alert.resolved_at = datetime.now(timezone.utc).isoformat()
        alert.resolved_by = current_user
        if body.note is not None:
            alert.analyst_note = body.note
        db.commit()
        db.refresh(alert)

        await write_audit(
            db, current_user, "ALERT_RESOLVE",
            target=alert_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "alert_resolved request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request), tenant_id, current_user, alert_id,
        )
        return _build_action_response(alert)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("alert_resolve_failed alert_id=%s error=%s", alert_id, exc)
        raise HTTPException(status_code=500, detail="Alert resolve başarısız")
    finally:
        db.close()


@router.patch("/api/alerts/{alert_id}/reopen", response_model=AlertActionResponse)
async def reopen_alert(
    alert_id: str,
    request: Request,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert = _alert_query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert bulunamadı")

        alert.status = "open"
        alert.resolved_at = None
        alert.resolved_by = None
        db.commit()
        db.refresh(alert)

        await write_audit(
            db, current_user, "ALERT_REOPEN",
            target=alert_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "alert_reopened request_id=%s tenant=%s user=%s alert_id=%s",
            _get_request_id(request), tenant_id, current_user, alert_id,
        )
        return _build_action_response(alert)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("alert_reopen_failed alert_id=%s error=%s", alert_id, exc)
        raise HTTPException(status_code=500, detail="Alert reopen başarısız")
    finally:
        db.close()

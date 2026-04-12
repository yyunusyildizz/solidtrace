"""
app.api.routes_cases
====================
Case management endpoints.

Bu router:
- case listeleme
- case detay
- manuel case oluşturma
- owner atama
- status güncelleme
- analyst note güncelleme
- alert'i case'e bağlama
işlevlerini sağlar.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.security import get_current_tenant_id, require_role
from app.database.db_manager import SessionLocal
from app.schemas.models import (
    CaseAssignRequest,
    CaseCreateRequest,
    CaseDetailResponse,
    CaseNoteUpdateRequest,
    CaseResponse,
    CaseStatusUpdateRequest,
)
from app.services.case_service import (
    assign_case,
    create_case,
    get_case_detail,
    link_alert_to_case,
    list_cases,
    update_case_note,
    update_case_status,
)

logger = logging.getLogger("SolidTrace.Cases")
router = APIRouter(tags=["cases"])


def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")


@router.get("/api/cases", response_model=list[CaseResponse])
async def api_list_cases(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        rows = list_cases(db, tenant_id=tenant_id, limit=limit)
        logger.info(
            "case_list_requested request_id=%s tenant=%s user=%s result_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            len(rows),
        )
        return rows
    finally:
        db.close()


@router.get("/api/cases/{case_id}", response_model=CaseDetailResponse)
async def api_get_case_detail(
    case_id: str,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = get_case_detail(db, case_id=case_id, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Case bulunamadı")

        logger.info(
            "case_detail_requested request_id=%s tenant=%s user=%s case_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            case_id,
        )
        return row
    finally:
        db.close()


@router.post("/api/cases", response_model=CaseResponse)
async def api_create_case(
    body: CaseCreateRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = create_case(
            db,
            tenant_id=tenant_id,
            title=body.title,
            description=body.description,
            severity=(body.severity or "INFO").upper(),
            owner=body.owner or current_user,
        )

        payload = get_case_detail(db, case_id=row.id, tenant_id=tenant_id)
        logger.info(
            "case_created request_id=%s tenant=%s user=%s case_id=%s title=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            row.id,
            row.title,
        )
        return payload
    finally:
        db.close()


@router.post("/api/cases/{case_id}/assign", response_model=CaseResponse)
async def api_assign_case(
    case_id: str,
    body: CaseAssignRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = assign_case(db, case_id=case_id, owner=body.owner, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Case bulunamadı")

        payload = get_case_detail(db, case_id=case_id, tenant_id=tenant_id)
        logger.info(
            "case_assigned request_id=%s tenant=%s actor=%s case_id=%s owner=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            case_id,
            body.owner,
        )
        return payload
    finally:
        db.close()


@router.post("/api/cases/{case_id}/status", response_model=CaseResponse)
async def api_update_case_status(
    case_id: str,
    body: CaseStatusUpdateRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = update_case_status(db, case_id=case_id, status=body.status, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Case bulunamadı")

        payload = get_case_detail(db, case_id=case_id, tenant_id=tenant_id)
        logger.info(
            "case_status_updated request_id=%s tenant=%s actor=%s case_id=%s status=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            case_id,
            body.status,
        )
        return payload
    finally:
        db.close()


@router.post("/api/cases/{case_id}/note", response_model=CaseResponse)
async def api_update_case_note(
    case_id: str,
    body: CaseNoteUpdateRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = update_case_note(db, case_id=case_id, note=body.note, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Case bulunamadı")

        payload = get_case_detail(db, case_id=case_id, tenant_id=tenant_id)
        logger.info(
            "case_note_updated request_id=%s tenant=%s actor=%s case_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            case_id,
        )
        return payload
    finally:
        db.close()


@router.post("/api/cases/{case_id}/link-alert/{alert_id}", response_model=CaseResponse)
async def api_link_alert_to_case(
    case_id: str,
    alert_id: str,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        link = link_alert_to_case(
            db,
            case_id=case_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
        )
        if not link:
            raise HTTPException(status_code=404, detail="Case veya alert bulunamadı")

        payload = get_case_detail(db, case_id=case_id, tenant_id=tenant_id)
        logger.info(
            "case_alert_linked request_id=%s tenant=%s actor=%s case_id=%s alert_id=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            case_id,
            alert_id,
        )
        return payload
    finally:
        db.close()

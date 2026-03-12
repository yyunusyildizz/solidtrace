"""
app.api.routes_agents
=====================
Agent enrollment / register / heartbeat / revoke endpoint'leri
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from app.core.security import (
    encrypt_agent_secret,
    get_current_tenant_id,
    hash_secret,
    hash_token,
    require_role,
    verify_agent_request,
)
from app.database.db_manager import (
    AgentEnrollmentTokenModel,
    AgentModel,
    SessionLocal,
)
from app.schemas.models import (
    AgentEnrollmentTokenCreateRequest,
    AgentEnrollmentTokenCreateResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentListResponse,
    AgentRegisterRequest,
    AgentRegisterResponse,
)

logger = logging.getLogger("SolidTrace.Agents")

router = APIRouter(tags=["agents"])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")


@router.post(
    "/api/agents/enrollment-token",
    response_model=AgentEnrollmentTokenCreateResponse,
)
async def create_enrollment_token(
    body: AgentEnrollmentTokenCreateRequest,
    request: Request,
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    if body.expires_in_minutes < 1 or body.expires_in_minutes > 1440:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expires_in_minutes 1 ile 1440 arasında olmalı",
        )

    db = SessionLocal()
    try:
        if current_tenant_id and body.tenant_id != current_tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bu tenant için işlem yetkiniz yok",
            )

        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_token(raw_token)
        expires_at = (utcnow() + timedelta(minutes=body.expires_in_minutes)).isoformat()

        token_rec = AgentEnrollmentTokenModel(
            id=str(uuid.uuid4()),
            tenant_id=body.tenant_id,
            token_hash=token_hash,
            created_by=current_user,
            created_at=utcnow_iso(),
            expires_at=expires_at,
            used_at=None,
            revoked_at=None,
        )

        db.add(token_rec)
        db.commit()

        logger.info(
            "agent_enrollment_token_created request_id=%s tenant=%s user=%s expires_at=%s",
            _get_request_id(request),
            body.tenant_id,
            current_user,
            expires_at,
        )

        return AgentEnrollmentTokenCreateResponse(
            enrollment_token=raw_token,
            expires_at=expires_at,
            tenant_id=body.tenant_id,
        )
    finally:
        db.close()


@router.post(
    "/api/agents/register",
    response_model=AgentRegisterResponse,
)
async def register_agent(
    body: AgentRegisterRequest,
    request: Request,
):
    hostname = (body.hostname or "").strip()[:255]
    device_fingerprint = (body.device_fingerprint or "").strip()[:255]
    os_name = (body.os_name or "").strip()[:128] or None
    agent_version = (body.agent_version or "").strip()[:64] or None

    if not hostname:
        raise HTTPException(status_code=400, detail="hostname gerekli")

    if not device_fingerprint:
        raise HTTPException(status_code=400, detail="device_fingerprint gerekli")

    db = SessionLocal()
    try:
        token_hash = hash_token(body.enrollment_token)

        token_rec = (
            db.query(AgentEnrollmentTokenModel)
            .filter(AgentEnrollmentTokenModel.token_hash == token_hash)
            .first()
        )

        if not token_rec:
            raise HTTPException(status_code=401, detail="Geçersiz enrollment token")

        if token_rec.revoked_at:
            raise HTTPException(status_code=401, detail="Enrollment token iptal edilmiş")

        if token_rec.used_at:
            raise HTTPException(status_code=401, detail="Enrollment token zaten kullanılmış")

        token_exp = datetime.fromisoformat(token_rec.expires_at)
        if token_exp < utcnow():
            raise HTTPException(status_code=401, detail="Enrollment token süresi dolmuş")

        existing_agent = (
            db.query(AgentModel)
            .filter(
                AgentModel.tenant_id == token_rec.tenant_id,
                AgentModel.device_fingerprint == device_fingerprint,
                AgentModel.revoked_at.is_(None),
            )
            .first()
        )

        if existing_agent and existing_agent.is_active:
            raise HTTPException(
                status_code=409,
                detail="Bu cihaz zaten kayıtlı. Gerekirse önce revoke edin.",
            )

        agent_id = str(uuid.uuid4())
        agent_secret = secrets.token_urlsafe(48)

        agent = AgentModel(
            id=agent_id,
            tenant_id=token_rec.tenant_id,
            hostname=hostname,
            device_fingerprint=device_fingerprint,
            os_name=os_name,
            agent_version=agent_version,
            secret_hash=hash_secret(agent_secret),
            secret_enc=encrypt_agent_secret(agent_secret),
            enrolled_at=utcnow_iso(),
            last_seen=utcnow_iso(),
            is_active=True,
            revoked_at=None,
            secret_rotated_at=None,
            secret_version=1,
            last_ip=request.client.host if request.client else None,
            last_user=None,
        )

        token_rec.used_at = utcnow_iso()

        db.add(agent)
        db.commit()

        logger.info(
            "agent_registered request_id=%s tenant=%s agent_id=%s host=%s ip=%s",
            _get_request_id(request),
            token_rec.tenant_id,
            agent_id,
            hostname,
            request.client.host if request.client else None,
        )

        return AgentRegisterResponse(
            agent_id=agent_id,
            agent_secret=agent_secret,
            tenant_id=token_rec.tenant_id,
        )
    finally:
        db.close()


@router.post(
    "/api/v1/agent/heartbeat",
    response_model=AgentHeartbeatResponse,
)
async def agent_heartbeat(
    body: AgentHeartbeatRequest,
    request: Request,
    tenant_id: str = Depends(verify_agent_request),
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
):
    if not x_agent_id:
        raise HTTPException(status_code=401, detail="X-Agent-Id gerekli")

    db = SessionLocal()
    try:
        agent = (
            db.query(AgentModel)
            .filter(
                AgentModel.id == x_agent_id,
                AgentModel.tenant_id == tenant_id,
                AgentModel.revoked_at.is_(None),
                AgentModel.is_active == True,
            )
            .first()
        )

        if not agent:
            raise HTTPException(status_code=404, detail="Agent bulunamadı")

        agent.last_seen = utcnow_iso()

        if body.agent_version:
            agent.agent_version = body.agent_version.strip()[:64]

        if body.os_name:
            agent.os_name = body.os_name.strip()[:128]

        if getattr(body, "user", None):
            agent.last_user = body.user.strip()[:128]

        observed_ip = request.client.host if request.client else None
        if observed_ip:
            agent.last_ip = observed_ip

        db.commit()

        logger.info(
            "agent_heartbeat_received request_id=%s tenant=%s agent_id=%s host=%s ip=%s",
            _get_request_id(request),
            tenant_id,
            x_agent_id,
            agent.hostname,
            observed_ip,
        )

        return AgentHeartbeatResponse(
            status="ok",
            server_time=utcnow_iso(),
        )
    finally:
        db.close()


@router.get(
    "/api/agents",
    response_model=list[AgentListResponse],
)
async def list_agents(
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = db.query(AgentModel)

        if current_tenant_id and hasattr(AgentModel, "tenant_id"):
            query = query.filter(AgentModel.tenant_id == current_tenant_id)

        rows = query.order_by(AgentModel.enrolled_at.desc()).all()

        result = []
        for row in rows:
            result.append(
                AgentListResponse(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    hostname=row.hostname,
                    device_fingerprint=row.device_fingerprint,
                    os_name=row.os_name,
                    agent_version=row.agent_version,
                    enrolled_at=row.enrolled_at,
                    last_seen=row.last_seen,
                    is_active=bool(row.is_active),
                    revoked_at=row.revoked_at,
                    last_ip=getattr(row, "last_ip", None),
                    last_user=getattr(row, "last_user", None),
                )
            )

        logger.info(
            "agent_list_requested request_id=%s tenant=%s user=%s agent_count=%s",
            _get_request_id(request),
            current_tenant_id,
            current_user,
            len(result),
        )

        return result
    finally:
        db.close()


@router.post("/api/agents/{agent_id}/revoke")
async def revoke_agent(
    agent_id: str,
    request: Request,
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = db.query(AgentModel).filter(AgentModel.id == agent_id)

        if current_tenant_id and hasattr(AgentModel, "tenant_id"):
            query = query.filter(AgentModel.tenant_id == current_tenant_id)

        agent = query.first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent bulunamadı")

        if agent.revoked_at:
            logger.info(
                "agent_already_revoked request_id=%s tenant=%s agent_id=%s user=%s",
                _get_request_id(request),
                getattr(agent, "tenant_id", None),
                agent.id,
                current_user,
            )
            return {"status": "already_revoked", "agent_id": agent.id}

        agent.is_active = False
        agent.revoked_at = utcnow_iso()
        db.commit()

        logger.warning(
            "agent_revoked request_id=%s tenant=%s agent_id=%s user=%s",
            _get_request_id(request),
            getattr(agent, "tenant_id", None),
            agent.id,
            current_user,
        )

        return {"status": "revoked", "agent_id": agent.id}
    finally:
        db.close()
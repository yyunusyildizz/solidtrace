"""
app.api.routes_agents
=====================
Agent enrollment / registration / lifecycle endpoint'leri

Bu dosya şunları sağlar:
- POST /api/agents/enrollment-token
- POST /api/agents/register
- GET  /api/agents
- POST /api/agents/{agent_id}/revoke
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.security import (
    encrypt_agent_secret,
    get_current_tenant_id,
    hash_secret,
    hash_token,
    require_role,
    tenant_filter,
    verify_agent_request,
)
from app.database.db_manager import (
    AgentEnrollmentTokenModel,
    AgentModel,
    SessionLocal,
    TenantModel,
    write_audit,
)
from app.schemas.models import (
    AgentEnrollmentTokenCreateRequest,
    AgentEnrollmentTokenCreateResponse,
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
)
from app.api.routes_auth import utcnow, utcnow_iso, parse_utc

logger = logging.getLogger("SolidTrace.Agents")
router = APIRouter(tags=["agents"])


@router.post("/api/agents/enrollment-token", response_model=AgentEnrollmentTokenCreateResponse)
async def create_enrollment_token(
    body: AgentEnrollmentTokenCreateRequest,
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    if current_tenant_id is not None and body.tenant_id != current_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sadece kendi tenant'ınız için enrollment token üretebilirsiniz",
        )

    raw_token = secrets.token_urlsafe(32)
    expires_at = (utcnow() + timedelta(minutes=body.expires_in_minutes)).isoformat()

    db = SessionLocal()
    try:
        rec = AgentEnrollmentTokenModel(
            id=str(uuid.uuid4()),
            tenant_id=body.tenant_id,
            token_hash=hash_token(raw_token),
            created_by=current_user,
            created_at=utcnow_iso(),
            expires_at=expires_at,
        )
        db.add(rec)
        db.commit()

        await write_audit(
            db,
            current_user,
            "AGENT_ENROLLMENT_TOKEN_CREATE",
            detail=f"tenant_id={body.tenant_id} expires_at={expires_at}",
            tenant_id=body.tenant_id,
        )

        logger.info(f"🔑 Enrollment token üretildi | tenant={body.tenant_id} | by={current_user}")

        return AgentEnrollmentTokenCreateResponse(
            enrollment_token=raw_token,
            expires_at=expires_at,
            tenant_id=body.tenant_id,
        )
    finally:
        db.close()


@router.post("/api/agents/register", response_model=AgentRegisterResponse)
async def register_agent(body: AgentRegisterRequest, request: Request):
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
        if token_rec.revoked_at is not None:
            raise HTTPException(status_code=401, detail="Enrollment token iptal edilmiş")
        if token_rec.used_at is not None:
            raise HTTPException(status_code=401, detail="Enrollment token zaten kullanılmış")
        if parse_utc(token_rec.expires_at) < utcnow():
            raise HTTPException(status_code=401, detail="Enrollment token süresi dolmuş")

        tenant = (
            db.query(TenantModel)
            .filter(TenantModel.id == token_rec.tenant_id)
            .first()
        )
        if not tenant or not tenant.is_active:
            raise HTTPException(status_code=403, detail="Tenant aktif değil veya bulunamadı")

        tenant_agent_count = (
            db.query(AgentModel)
            .filter(
                AgentModel.tenant_id == token_rec.tenant_id,
                AgentModel.revoked_at.is_(None),
                AgentModel.is_active == True,
            )
            .count()
        )

        if tenant_agent_count >= (tenant.max_agents or 10):
            raise HTTPException(
                status_code=403,
                detail="Tenant agent limiti aşıldı",
            )

        existing = (
            db.query(AgentModel)
            .filter(
                AgentModel.tenant_id == token_rec.tenant_id,
                AgentModel.device_fingerprint == body.device_fingerprint,
            )
            .first()
        )
        if existing and existing.revoked_at is None and existing.is_active:
            raise HTTPException(status_code=409, detail="Bu cihaz zaten kayıtlı")

        agent_id = str(uuid.uuid4())
        agent_secret = secrets.token_urlsafe(48)

        agent = AgentModel(
            id=agent_id,
            tenant_id=token_rec.tenant_id,
            hostname=body.hostname,
            device_fingerprint=body.device_fingerprint,
            os_name=body.os_name,
            agent_version=body.agent_version,
            secret_hash=hash_secret(agent_secret),
            secret_enc=encrypt_agent_secret(agent_secret),
            enrolled_at=utcnow_iso(),
            last_seen=utcnow_iso(),
            last_ip=request.client.host if request.client else None,
            is_active=True,
            revoked_at=None,
        )
        db.add(agent)

        token_rec.used_at = utcnow_iso()
        db.flush()
        db.commit()

        await write_audit(
            db,
            username=f"agent:{agent_id}",
            action="AGENT_REGISTER",
            target=agent_id,
            detail=f"hostname={body.hostname} tenant_id={token_rec.tenant_id}",
            ip=request.client.host if request.client else "",
            tenant_id=token_rec.tenant_id,
        )

        logger.info(
            f"🤖 Agent kayıt oldu | id={agent_id} | tenant={token_rec.tenant_id} | host={body.hostname}"
        )

        return AgentRegisterResponse(
            agent_id=agent_id,
            agent_secret=agent_secret,
            tenant_id=token_rec.tenant_id,
        )
    finally:
        db.close()


@router.get("/api/agents")
async def list_agents(
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        q = db.query(AgentModel)
        q = tenant_filter(q, AgentModel, current_tenant_id)
        agents = q.order_by(AgentModel.enrolled_at.desc()).all()
        return {"agents": [a.to_dict() for a in agents]}
    finally:
        db.close()


@router.post("/api/agents/{agent_id}/revoke")
async def revoke_agent(
    agent_id: str,
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        q = db.query(AgentModel).filter(AgentModel.id == agent_id)
        q = tenant_filter(q, AgentModel, current_tenant_id)
        agent = q.first()

        if not agent:
            raise HTTPException(status_code=404, detail="Agent bulunamadı")

        if agent.revoked_at is None:
            agent.revoked_at = utcnow_iso()
            agent.is_active = False
            db.commit()

        await write_audit(
            db,
            current_user,
            "AGENT_REVOKE",
            target=agent_id,
            detail=f"hostname={agent.hostname}",
            tenant_id=agent.tenant_id,
        )

        logger.warning(f"⛔ Agent revoke edildi | id={agent_id} | host={agent.hostname}")

        return {"status": "revoked", "agent_id": agent_id}
    finally:
        db.close()

# ---------------------------------------------------------------------------
# AGENT HEARTBEAT
# ---------------------------------------------------------------------------

@router.post("/api/v1/agent/heartbeat", response_model=AgentHeartbeatResponse)
async def agent_heartbeat(
    body: AgentHeartbeatRequest,
    request: Request,
    tenant_id: str = Depends(verify_agent_request),
):
    db = SessionLocal()

    try:
        agent_id = request.headers.get("X-Agent-Id")

        agent = (
            db.query(AgentModel)
            .filter(AgentModel.id == agent_id)
            .first()
        )

        if not agent:
            raise HTTPException(status_code=404, detail="Agent bulunamadı")

        agent.last_seen = utcnow_iso()

        if body.agent_version:
            agent.agent_version = body.agent_version

        if body.os_name:
            agent.os_name = body.os_name

        if body.user:
            agent.last_user = body.user

        if body.ip:
            agent.last_ip = body.ip

        db.commit()

        return AgentHeartbeatResponse(
            status="ok",
            server_time=utcnow_iso(),
        )

    finally:
        db.close()
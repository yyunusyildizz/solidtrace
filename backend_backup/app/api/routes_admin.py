"""
app.api.routes_admin
====================
Yönetim endpoint'leri:
  /api/tenants/*, /api/rules/*, /api/agent/*, /api/system/status, /health
"""

from __future__ import annotations

import hashlib
import logging
import os
import time as _time
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import desc

from app.core.security import get_current_user, get_current_tenant_id, require_role
from app.database.db_manager import (
    SessionLocal, TenantModel, UserModel, AlertModel,
    RuleModel, write_audit,
)
from app.schemas.models import DetectionRuleSchema, TenantCreateRequest, UserCreateRequest
from app.core.security import pwd_context

logger      = logging.getLogger("SolidTrace.Admin")
router      = APIRouter(tags=["admin"])
_START_TIME = _time.time()

AGENT_VERSION    = os.getenv("AGENT_VERSION", "1.0.0")
AGENT_BUILD_DATE = os.getenv("AGENT_BUILD_DATE", datetime.now().strftime("%Y-%m-%d"))
AGENT_BINARY_DIR = os.getenv("AGENT_BINARY_DIR", "releases")


# ---------------------------------------------------------------------------
# KURAL YÖNETİMİ
# ---------------------------------------------------------------------------

@router.post("/api/rules")
async def add_rule(
    rule:         DetectionRuleSchema,
    current_user: str = Depends(require_role("analyst")),
):
    db = SessionLocal()
    try:
        new_rule = RuleModel(
            id=str(uuid.uuid4()), name=rule.name, keyword=rule.keyword,
            risk_score=rule.risk_score, severity=rule.severity,
            created_at=datetime.now().isoformat(), created_by=current_user,
        )
        db.add(new_rule)
        db.commit()
        logger.info(f"✅ Kural oluşturuldu: {rule.name} (by {current_user})")
        return {"status": "ok", "rule": new_rule.to_dict()}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/api/rules")
async def get_rules(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return [r.to_dict() for r in
                db.query(RuleModel).order_by(desc(RuleModel.created_at)).all()]
    finally:
        db.close()


@router.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str, current_user: str = Depends(require_role("admin"))):
    db = SessionLocal()
    try:
        deleted = db.query(RuleModel).filter(RuleModel.id == rule_id).delete()
        db.commit()
        if deleted:
            logger.info(f"🗑️  Kural silindi: {rule_id} (by {current_user})")
            return {"status": "deleted"}
        raise HTTPException(status_code=404, detail="Kural bulunamadı")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# TENANT YÖNETİMİ
# ---------------------------------------------------------------------------

@router.get("/api/tenants")
async def list_tenants(current_user: str = Depends(require_role("admin"))):
    db = SessionLocal()
    try:
        me = db.query(UserModel).filter(UserModel.username == current_user).first()
        if me and me.tenant_id:
            raise HTTPException(status_code=403, detail="Sadece süper admin erişebilir")
        tenants = db.query(TenantModel).all()
        result  = []
        for t in tenants:
            agent_count = (
                db.query(AlertModel)
                .filter(AlertModel.tenant_id == t.id)
                .distinct(AlertModel.hostname)
                .count()
            )
            result.append({
                "id": t.id, "name": t.name, "slug": t.slug,
                "plan": t.plan, "max_agents": t.max_agents,
                "active_agents": agent_count, "is_active": t.is_active,
                "created_at": t.created_at, "contact_email": t.contact_email,
                "agent_key": t.agent_key,
            })
        return result
    finally:
        db.close()


@router.post("/api/tenants")
async def create_tenant(
    req:          TenantCreateRequest,
    current_user: str = Depends(require_role("admin")),
):
    import re
    import secrets as _s
    db = SessionLocal()
    try:
        me = db.query(UserModel).filter(UserModel.username == current_user).first()
        if me and me.tenant_id:
            raise HTTPException(status_code=403, detail="Sadece süper admin tenant oluşturabilir")

        slug = re.sub(r"[^a-z0-9]+", "-", req.name.lower()).strip("-")
        if db.query(TenantModel).filter(TenantModel.slug == slug).first():
            slug = f"{slug}-{_s.token_hex(3)}"

        tenant = TenantModel(
            id=str(uuid.uuid4()), name=req.name, slug=slug,
            agent_key=f"st-{_s.token_urlsafe(24)}",
            max_agents=req.max_agents, plan=req.plan,
            is_active=True, created_at=datetime.now().isoformat(),
            contact_email=req.contact_email,
        )
        db.add(tenant)
        db.commit()
        await write_audit(db, current_user, "TENANT_CREATE",
                          target=req.name, detail=f"plan={req.plan}")
        logger.info(f"🏢 Yeni tenant: {req.name}")
        return {"id": tenant.id, "name": tenant.name, "slug": tenant.slug,
                "agent_key": tenant.agent_key, "plan": tenant.plan}
    finally:
        db.close()


@router.delete("/api/tenants/{tenant_id}")
async def delete_tenant(tenant_id: str, current_user: str = Depends(require_role("admin"))):
    db = SessionLocal()
    try:
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant bulunamadı")
        db.query(AlertModel).filter(AlertModel.tenant_id == tenant_id).delete()
        db.query(UserModel).filter(UserModel.tenant_id == tenant_id).delete()
        db.delete(tenant)
        db.commit()
        await write_audit(db, current_user, "TENANT_DELETE", target=tenant.name)
        return {"status": "deleted", "name": tenant.name}
    finally:
        db.close()


@router.get("/api/tenants/{tenant_id}/stats")
async def tenant_stats(tenant_id: str, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant bulunamadı")
        total_alerts  = db.query(AlertModel).filter(AlertModel.tenant_id == tenant_id).count()
        critical      = db.query(AlertModel).filter(
            AlertModel.tenant_id == tenant_id, AlertModel.severity == "CRITICAL").count()
        cutoff        = (datetime.now() - timedelta(minutes=5)).isoformat()
        active_agents = db.query(AlertModel.hostname).filter(
            AlertModel.tenant_id == tenant_id,
            AlertModel.created_at >= cutoff,
        ).distinct().count()
        return {
            "tenant": tenant.name, "plan": tenant.plan,
            "max_agents": tenant.max_agents, "active_agents": active_agents,
            "license_ok": active_agents <= tenant.max_agents,
            "total_alerts": total_alerts, "critical": critical,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AGENT İNDİRME & SİSTEM DURUMU
# ---------------------------------------------------------------------------

@router.get("/api/agent/info")
async def agent_info():
    binary_path = os.path.join(AGENT_BINARY_DIR, "solidtrace-agent.zip")
    size_mb     = round(os.path.getsize(binary_path) / 1024 / 1024, 1) if os.path.exists(binary_path) else 0.0
    sha256      = "—"
    if os.path.exists(binary_path):
        h = hashlib.sha256()
        with open(binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        sha256 = h.hexdigest()
    return {
        "version": AGENT_VERSION, "build_date": AGENT_BUILD_DATE,
        "platform": "windows-x86_64", "size_mb": size_mb, "sha256": sha256,
        "changelog": [
            "Rust tabanlı hafif agent mimarisi",
            "Windows Event Log izleme",
            "Process, dosya, USB, registry monitörü",
            "Gerçek zamanlı SOC panel entegrasyonu",
            "Sigma kural motoru desteği",
            "Otomatik yeniden bağlanma",
        ],
    }


@router.get("/api/agent/download")
async def agent_download():
    binary_path = os.path.join(AGENT_BINARY_DIR, "solidtrace-agent.zip")
    if not os.path.exists(binary_path):
        os.makedirs(AGENT_BINARY_DIR, exist_ok=True)
        readme = os.path.join(AGENT_BINARY_DIR, "README.txt")
        if not os.path.exists(readme):
            with open(readme, "w") as f:
                f.write("cargo build --release → solidtrace-agent.zip olarak koyun.\n")
        raise HTTPException(status_code=404,
                            detail="Agent binary hazır değil. releases/solidtrace-agent.zip oluşturun.")
    return FileResponse(
        path=binary_path,
        filename=f"solidtrace-agent-v{AGENT_VERSION}.zip",
        media_type="application/zip",
    )


@router.get("/api/system/status")
async def system_status():
    db_ok = False
    total_alerts = agents_online = 0
    try:
        db = SessionLocal()
        total_alerts  = db.query(AlertModel).count()
        cutoff        = (datetime.now() - timedelta(hours=24)).isoformat()
        agents_online = (
            db.query(AlertModel)
            .filter(AlertModel.type == "ASSET_HEARTBEAT",
                    AlertModel.created_at >= cutoff)
            .distinct(AlertModel.hostname)
            .count()
        )
        db.close()
        db_ok = True
    except Exception:
        pass
    return {
        "backend": True, "db": db_ok,
        "agents_online": agents_online, "total_alerts": total_alerts,
        "uptime_seconds": int(_time.time() - _START_TIME),
    }


@router.get("/health")
async def health_check():
    from app.api.websockets import ACTIVE_CONNECTIONS
    return {
        "status":             "healthy",
        "version":            "6.1.0",
        "timestamp":          datetime.now().isoformat(),
        "active_connections": len(ACTIVE_CONNECTIONS),
    }

"""
app.core.security
=================
Kimlik doğrulama ve yetkilendirme katmanı.
JWT oluşturma/doğrulama, RBAC, şifre hash, 2FA, agent key doğrulama.

FastAPI endpoint'i içermez — sadece bağımlılık (Depends) fonksiyonları.
"""

from __future__ import annotations

import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict

from fastapi import Depends, HTTPException, Header, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger("SolidTrace.Security")

# ---------------------------------------------------------------------------
# 1. AYARLAR
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    env = os.getenv("ENV", "development").lower()
    if env == "production":
        logger.critical("❌ JWT_SECRET_KEY tanımlı değil! Üretim ortamında başlatılamaz.")
        sys.exit(1)
    else:
        SECRET_KEY = "DEV-ONLY-NOT-FOR-PRODUCTION"
        logger.warning("⚠️  JWT_SECRET_KEY eksik — development modu")

ALGORITHM                    = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = 480   # 8 saat

MAX_LOGIN_ATTEMPTS           = 5
LOGIN_WINDOW_SECONDS         = 300   # 5 dakika

# Agent API key — global (geriye dönük uyumluluk)
import secrets as _secrets
_raw_agent_key = os.getenv("AGENT_API_KEY", "")
if not _raw_agent_key:
    AGENT_API_KEY = _secrets.token_urlsafe(32)
    logger.warning(f"⚠️  AGENT_API_KEY tanımlı değil — oturum key: {AGENT_API_KEY}")
else:
    AGENT_API_KEY = _raw_agent_key

# ---------------------------------------------------------------------------
# 2. PAROLA HASH
# ---------------------------------------------------------------------------

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ---------------------------------------------------------------------------
# 3. JWT
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire    = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """FastAPI Depends — JWT'den kullanıcı adını çıkarır."""
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Kimlik doğrulama başarısız",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise exc
    except JWTError:
        raise exc
    return username


# ---------------------------------------------------------------------------
# 4. RBAC
# ---------------------------------------------------------------------------

ROLE_HIERARCHY: Dict[str, int] = {"viewer": 0, "analyst": 1, "admin": 2}


def require_role(required_role: str):
    """
    FastAPI Depends — rol tabanlı erişim kontrolü.
    Kullanım: current_user: str = Depends(require_role("admin"))
    """
    async def _check(current_user: str = Depends(get_current_user)) -> str:
        # Lazy import — döngüsel bağımlılığı önler
        from app.database.db_manager import SessionLocal, UserModel
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.username == current_user).first()
            if not user:
                raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
            if ROLE_HIERARCHY.get(user.role, 0) < ROLE_HIERARCHY.get(required_role, 99):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Bu işlem için '{required_role}' rolü gerekli",
                )
            return current_user
        finally:
            db.close()
    return _check


async def get_current_tenant_id(
    current_user: str = Depends(get_current_user),
) -> Optional[str]:
    """Mevcut kullanıcının tenant_id'sini döner. Süper admin → None."""
    from app.database.db_manager import SessionLocal, UserModel
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        return user.tenant_id if user else None
    finally:
        db.close()


def tenant_filter(query, model, tenant_id: Optional[str]):
    """
    Süper admin (tenant_id=None) → filtre yok.
    Normal kullanıcı → sadece kendi tenant'ı.
    """
    if tenant_id is not None:
        query = query.filter(model.tenant_id == tenant_id)
    return query


# ---------------------------------------------------------------------------
# 5. AGENT KEY DOĞRULAMA
# ---------------------------------------------------------------------------

def verify_agent_key(x_agent_key: Optional[str] = Header(None)) -> bool:
    """Global agent key doğrulama — /api/v1/report_hash için."""
    if not x_agent_key or x_agent_key != AGENT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz Agent API Key",
        )
    return True


def verify_tenant_agent_key(x_agent_key: Optional[str] = Header(None)) -> dict:
    """
    Tenant'a özel agent key doğrulama — /api/v1/ingest için.
    Global key VEYA tenant key kabul edilir.
    """
    if not x_agent_key:
        raise HTTPException(status_code=401, detail="Agent key eksik")

    # Global key (geriye dönük uyumluluk)
    if x_agent_key == AGENT_API_KEY:
        return {"tenant_id": None, "tenant_name": "global"}

    from app.database.db_manager import SessionLocal, TenantModel, AlertModel
    db = SessionLocal()
    try:
        tenant = db.query(TenantModel).filter(
            TenantModel.agent_key == x_agent_key,
            TenantModel.is_active == True,
        ).first()
        if not tenant:
            raise HTTPException(status_code=401, detail="Geçersiz agent key")

        # Agent limit kontrolü
        cutoff = (datetime.now() - timedelta(minutes=10)).isoformat()
        active = db.query(AlertModel.hostname).filter(
            AlertModel.tenant_id == tenant.id,
            AlertModel.created_at >= cutoff,
        ).distinct().count()

        if active > tenant.max_agents:
            raise HTTPException(
                status_code=429,
                detail=f"Agent limit aşıldı ({active}/{tenant.max_agents}). Planınızı yükseltiniz.",
            )
        return {"tenant_id": tenant.id, "tenant_name": tenant.name}
    finally:
        db.close()

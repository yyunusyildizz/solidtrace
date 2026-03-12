"""
app.core.security
=================
Kimlik doğrulama / yetkilendirme / güvenlik yardımcıları

Bu revizyonda:
- JWT access / refresh / pending_2fa token desteği
- password hashing
- RBAC / tenant helper'ları
- agent secret encryption / decryption
- HMAC signing helper'ları
eklendi.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger("SolidTrace.Security")


# ---------------------------------------------------------------------------
# JWT / AUTH CONFIG
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    logger.critical("JWT_SECRET_KEY tanımlı değil")
    raise RuntimeError("JWT_SECRET_KEY tanımlı değil")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
PENDING_2FA_EXPIRE_MINUTES = int(os.getenv("PENDING_2FA_EXPIRE_MINUTES", "3"))

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))

ISSUER = os.getenv("JWT_ISSUER", "solidtrace")
AUDIENCE = os.getenv("JWT_AUDIENCE", "solidtrace-panel")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


# ---------------------------------------------------------------------------
# AGENT AUTH CONFIG
# ---------------------------------------------------------------------------

AGENT_MAX_SKEW_SECONDS = int(os.getenv("AGENT_MAX_SKEW_SECONDS", "300"))

# Bu değer urlsafe base64-encoded 32-byte olmalı (Fernet key formatı)
# Üretmek için:
# python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
AGENT_SECRET_KEK = os.getenv("AGENT_SECRET_KEK")
if not AGENT_SECRET_KEK:
    logger.warning("AGENT_SECRET_KEK tanımlı değil. Agent auth aktif edilmeden önce set edilmeli.")

# Ticari dağıtım için güvenli default: false
LEGACY_AGENT_AUTH = os.getenv("LEGACY_AGENT_AUTH", "false").lower() == "true"

AGENT_NONCE_TTL_SECONDS = int(os.getenv("AGENT_NONCE_TTL_SECONDS", "300"))
AGENT_RATE_LIMIT_PER_MINUTE = int(os.getenv("AGENT_RATE_LIMIT_PER_MINUTE", "120"))
AGENT_IP_RATE_LIMIT_PER_MINUTE = int(os.getenv("AGENT_IP_RATE_LIMIT_PER_MINUTE", "60"))


# ---------------------------------------------------------------------------
# PASSWORD HELPERS
# ---------------------------------------------------------------------------

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ---------------------------------------------------------------------------
# JWT HELPERS
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _build_token_payload(data: Dict[str, Any], expires_delta: timedelta, token_type: str) -> Dict[str, Any]:
    now = _utcnow()
    return {
        **data,
        "type": token_type,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": str(uuid.uuid4()),
    }


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = _build_token_payload(
        data=data,
        expires_delta=expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    payload = _build_token_payload(
        data=data,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_pending_2fa_token(username: str) -> str:
    payload = _build_token_payload(
        data={"sub": username, "stage": "2fa_pending"},
        expires_delta=timedelta(minutes=PENDING_2FA_EXPIRE_MINUTES),
        token_type="pending_2fa",
    )
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
        audience=AUDIENCE,
        issuer=ISSUER,
    )


# ---------------------------------------------------------------------------
# CURRENT USER / RBAC
# ---------------------------------------------------------------------------

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Kimlik doğrulama başarısız",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise exc

        username = payload.get("sub")
        if not username:
            raise exc

        from app.database.db_manager import SessionLocal, UserModel

        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.username == username).first()
            if not user or not user.is_active:
                raise exc

            token_version = payload.get("tv", 0)
            if token_version != (user.token_version or 0):
                raise exc
        finally:
            db.close()

        return username
    except JWTError:
        raise exc


def require_role(required_role: str):
    role_order = {"viewer": 1, "analyst": 2, "admin": 3}

    async def _checker(
        current_user: str = Depends(get_current_user),
        token: str = Depends(oauth2_scheme),
    ) -> str:
        exc = HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Yetkiniz yok",
        )

        try:
            payload = decode_token(token)
            username = payload.get("sub")
            if not username or username != current_user:
                raise exc

            from app.database.db_manager import SessionLocal, UserModel

            db = SessionLocal()
            try:
                user = db.query(UserModel).filter(UserModel.username == username).first()
                if not user or not user.is_active:
                    raise exc

                current_role = user.role or "viewer"
                if role_order.get(current_role, 0) < role_order.get(required_role, 999):
                    raise exc
            finally:
                db.close()

            return current_user
        except JWTError:
            raise exc

    return _checker


# ---------------------------------------------------------------------------
# TENANT HELPERS
# ---------------------------------------------------------------------------

async def get_current_tenant_id(token: str = Depends(oauth2_scheme)) -> Optional[str]:
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if not username:
            return None

        from app.database.db_manager import SessionLocal, UserModel

        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.username == username).first()
            return user.tenant_id if user else None
        finally:
            db.close()
    except Exception:
        return None


def tenant_filter(query, model, tenant_id: Optional[str]):
    if tenant_id is None:
        return query
    if hasattr(model, "tenant_id"):
        return query.filter(model.tenant_id == tenant_id)
    return query


# ---------------------------------------------------------------------------
# GENERIC TOKEN / SECRET HELPERS
# ---------------------------------------------------------------------------

def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_secret_hash(plain_value: str, stored_hash: str) -> bool:
    candidate = hashlib.sha256(plain_value.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, stored_hash)


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# AGENT SECRET ENCRYPTION
# ---------------------------------------------------------------------------

def _get_fernet() -> Fernet:
    if not AGENT_SECRET_KEK:
        raise RuntimeError("AGENT_SECRET_KEK tanımlı değil")
    try:
        return Fernet(AGENT_SECRET_KEK.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("AGENT_SECRET_KEK geçersiz; Fernet key formatında olmalı") from exc


def encrypt_agent_secret(secret: str) -> str:
    f = _get_fernet()
    return f.encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_agent_secret(secret_enc: str) -> str:
    f = _get_fernet()
    try:
        return f.decrypt(secret_enc.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Agent secret decrypt edilemedi") from exc


# ---------------------------------------------------------------------------
# AGENT SIGNING / HMAC
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_agent_signing_message(
    method: str,
    path: str,
    body_hash: str,
    timestamp: str,
    nonce: str,
    agent_id: str,
) -> str:
    return "\n".join(
        [
            method.upper(),
            path,
            body_hash,
            timestamp,
            nonce,
            agent_id,
        ]
    )


def sign_agent_message(secret: str, message: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_agent_signature(secret: str, message: str, provided_signature: str) -> bool:
    expected = sign_agent_message(secret, message)
    return secure_compare(expected, provided_signature)


def parse_unix_timestamp(ts: str) -> int:
    try:
        return int(ts)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Geçersiz agent timestamp") from exc


def ensure_agent_timestamp_fresh(ts: str) -> int:
    client_ts = parse_unix_timestamp(ts)
    now_ts = int(_utcnow().timestamp())
    skew = abs(now_ts - client_ts)
    if skew > AGENT_MAX_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Agent isteği zaman penceresi dışında")
    return client_ts


# ---------------------------------------------------------------------------
# LEGACY AGENT KEY SUPPORT
# ---------------------------------------------------------------------------

async def verify_tenant_agent_key(
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> Optional[str]:
    """
    Geçici legacy doğrulama.
    Yeni model signed agent request olacak.
    """
    if not LEGACY_AGENT_AUTH:
        raise HTTPException(status_code=401, detail="Legacy agent auth devre dışı")

    if not x_agent_key:
        raise HTTPException(status_code=401, detail="X-Agent-Key gerekli")

    from app.database.db_manager import SessionLocal, TenantModel

    db = SessionLocal()
    try:
        if x_tenant_id:
            tenant = db.query(TenantModel).filter(TenantModel.id == x_tenant_id).first()
            if tenant and tenant.is_active and tenant.agent_key and secure_compare(tenant.agent_key, x_agent_key):
                logger.warning("Legacy agent auth kullanıldı (tenant-scoped)")
                return tenant.id

        tenant = db.query(TenantModel).filter(TenantModel.agent_key == x_agent_key).first()
        if tenant and tenant.is_active:
            logger.warning("Legacy agent auth kullanıldı")
            return tenant.id

        raise HTTPException(status_code=401, detail="Geçersiz agent key")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# IN-MEMORY FALLBACK STORES
# ---------------------------------------------------------------------------

class NonceStore:
    """
    Redis yoksa geçici in-memory replay koruması.
    Sadece tek process dev/test ortamı için uygundur.
    Production'da Redis-backed nonce store zorunlu olmalıdır.
    """

    def __init__(self, ttl_seconds: int = 300, max_items: int = 50000):
        self.ttl_seconds = ttl_seconds
        self.max_items = max_items
        self._store: "OrderedDict[str, float]" = OrderedDict()

    def _cleanup(self) -> None:
        now = time.time()
        expired = []
        for key, exp in self._store.items():
            if exp <= now:
                expired.append(key)
            else:
                break

        for key in expired:
            self._store.pop(key, None)

        while len(self._store) > self.max_items:
            self._store.popitem(last=False)

    def check_and_set(self, key: str) -> bool:
        """
        True => yeni nonce
        False => replay
        """
        self._cleanup()
        if key in self._store:
            return False
        self._store[key] = time.time() + self.ttl_seconds
        return True


class RateLimiterStore:
    """
    Hafif sliding-window rate limit store.
    Sadece tek process dev/test fallback çözümüdür.
    Production'da Redis-backed rate limiting kullanılmalıdır.
    """

    def __init__(self, window_seconds: int = 60, max_items: int = 50000):
        self.window_seconds = window_seconds
        self.max_items = max_items
        self._store: dict[str, list[float]] = {}

    def hit(self, key: str, limit: int) -> bool:
        """
        True => izin ver
        False => limit aşıldı
        """
        now = time.time()
        window_start = now - self.window_seconds

        bucket = self._store.get(key, [])
        bucket = [ts for ts in bucket if ts >= window_start]
        bucket.append(now)

        if len(bucket) > limit:
            self._store[key] = bucket
            return False

        self._store[key] = bucket

        if len(self._store) > self.max_items:
            oldest_keys = list(self._store.keys())[:1000]
            for key in oldest_keys:
                if not self._store.get(key):
                    self._store.pop(key, None)

        return True


_nonce_store = NonceStore(ttl_seconds=AGENT_NONCE_TTL_SECONDS)
_rate_store = RateLimiterStore(window_seconds=60)


# ---------------------------------------------------------------------------
# AGENT REQUEST HELPERS
# ---------------------------------------------------------------------------

async def get_agent_auth_headers(
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
    x_agent_timestamp: Optional[str] = Header(None, alias="X-Agent-Timestamp"),
    x_agent_nonce: Optional[str] = Header(None, alias="X-Agent-Nonce"),
    x_agent_signature: Optional[str] = Header(None, alias="X-Agent-Signature"),
) -> dict:
    return {
        "agent_id": x_agent_id,
        "timestamp": x_agent_timestamp,
        "nonce": x_agent_nonce,
        "signature": x_agent_signature,
    }


async def verify_agent_key(
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> Optional[str]:
    """
    Geriye dönük uyumluluk alias'ı.
    Eski route'lar verify_agent_key import etmeye devam edebilir.
    Yeni isim: verify_tenant_agent_key
    """
    return await verify_tenant_agent_key(
        x_agent_key=x_agent_key,
        x_tenant_id=x_tenant_id,
    )


def enforce_agent_nonce(agent_id: str, nonce: str) -> None:
    key = f"{agent_id}:{nonce}"
    if not _nonce_store.check_and_set(key):
        raise HTTPException(status_code=401, detail="Replay attack tespit edildi")


def enforce_agent_rate_limit(agent_key: str) -> None:
    if not _rate_store.hit(agent_key, AGENT_RATE_LIMIT_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Agent rate limit aşıldı")


def enforce_ip_rate_limit(client_ip: str) -> None:
    if not _rate_store.hit(f"ip:{client_ip}", AGENT_IP_RATE_LIMIT_PER_MINUTE):
        raise HTTPException(status_code=429, detail="IP rate limit aşıldı")


def get_client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


# ---------------------------------------------------------------------------
# SIGNED AGENT REQUEST VERIFY
# ---------------------------------------------------------------------------

async def verify_agent_request(
    request: Request,
    headers: dict = Depends(get_agent_auth_headers),
) -> str:
    """
    Signed agent request doğrulaması.
    Başarılıysa tenant_id döndürür.
    """

    agent_id = headers.get("agent_id")
    timestamp = headers.get("timestamp")
    nonce = headers.get("nonce")
    signature = headers.get("signature")

    if not agent_id or not timestamp or not nonce or not signature:
        raise HTTPException(status_code=401, detail="Agent auth header eksik")

    ensure_agent_timestamp_fresh(timestamp)
    client_ip = get_client_ip(request)

    from app.database.db_manager import SessionLocal, AgentModel

    db = SessionLocal()
    try:
        agent = db.query(AgentModel).filter(AgentModel.id == agent_id).first()

        if not agent or not agent.is_active or agent.revoked_at:
            enforce_ip_rate_limit(client_ip)
            raise HTTPException(status_code=401, detail="Agent geçersiz")

        enforce_agent_rate_limit(f"{client_ip}:{agent_id}")

        secret = decrypt_agent_secret(agent.secret_enc)

        body = await request.body()
        body_hash = sha256_hex(body)

        message = build_agent_signing_message(
            method=request.method,
            path=request.url.path,
            body_hash=body_hash,
            timestamp=timestamp,
            nonce=nonce,
            agent_id=agent_id,
        )

        if not verify_agent_signature(secret, message, signature):
            raise HTTPException(status_code=401, detail="Agent signature geçersiz")

        enforce_agent_nonce(agent_id, nonce)

        agent.last_seen = datetime.now(timezone.utc)
        db.commit()

        return agent.tenant_id
    finally:
        db.close()
"""
app.api.routes_auth — güvenlik revizyonu
Login (brute-force korumalı), 2FA (pending token), refresh token rotation,
invite flow (şifresiz), setup-password, change-password, admin reset.
"""

import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import (
    MAX_LOGIN_ATTEMPTS,
    LOGIN_WINDOW_SECONDS,
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    create_pending_2fa_token,
    decode_token,
    get_current_user,
    require_role,
    hash_token,
    get_current_tenant_id,
    tenant_filter,
)
from app.database.db_manager import (
    SessionLocal,
    UserModel,
    RefreshTokenModel,
    write_audit,
)
from app.schemas.models import (
    LoginResponse,
    UserInviteRequest,
    InviteSetupRequest,
    PasswordChangeRequest,
    AdminPasswordResetRequest,
    RefreshTokenRequest,
    TwoFALoginRequest,
    TwoFAVerifyRequest,
    TwoFADisableRequest,
)
from app.services.notification import EmailNotifier

logger = logging.getLogger("SolidTrace.Auth")
router = APIRouter(tags=["auth"])

# /api/login için özel limiter — global limiter'dan bağımsız
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    _limiter = Limiter(key_func=get_remote_address)
    _login_limit = _limiter.limit("5/minute")
except ImportError:
    def _login_limit(f):
        return f


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def parse_utc(dt_str: str) -> datetime:
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def persist_refresh_token(db, refresh_token: str, username: str, token_version: int) -> None:
    payload = decode_token(refresh_token)
    db.add(
        RefreshTokenModel(
            id=payload["jti"],
            username=username,
            token_version=token_version,
            issued_at=utcnow_iso(),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat(),
        )
    )
    db.commit()


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Şifre en az 12 karakter olmalı")

    weak = {"admin123", "password", "12345678", "qwerty123", "solidtrace123"}
    if password.lower() in weak:
        raise HTTPException(status_code=400, detail="Zayıf parola kullanılamaz")


# ---------------------------------------------------------------------------
# GİRİŞ
# ---------------------------------------------------------------------------

@router.post("/api/login", response_model=LoginResponse)
@_login_limit
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host if request.client else ""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == form_data.username).first()

        # Kilit kontrolü
        if user and user.locked_until:
            lock_aware = parse_utc(user.locked_until)
            if utcnow() < lock_aware:
                remaining = max(1, int((lock_aware - utcnow()).total_seconds() / 60))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Hesap kilitli. {remaining} dakika sonra tekrar deneyin.",
                )
            user.failed_attempts = 0
            user.locked_until = None
            db.commit()

        # Kullanıcı/şifre kontrolü
        if not user or not user.is_active or not verify_password(form_data.password, user.hashed_password):
            attempted_user = form_data.username
            tenant_id = user.tenant_id if user else None

            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.locked_until = (utcnow() + timedelta(seconds=LOGIN_WINDOW_SECONDS)).isoformat()
                    logger.warning(f"🔒 Hesap kilitlendi: {form_data.username}")
                db.commit()

            await write_audit(
                db,
                attempted_user,
                "LOGIN_FAILED",
                detail="invalid_credentials_or_inactive",
                ip=client_ip,
                result="FAILURE",
                tenant_id=tenant_id,
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kullanıcı adı veya şifre hatalı",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = utcnow_iso()
        db.commit()

        # 2FA aktifse → pending token döndür
        if user.totp_enabled:
            pending_token = create_pending_2fa_token(user.username)
            await write_audit(
                db,
                user.username,
                "LOGIN_PASSWORD_OK_2FA_PENDING",
                detail=f"role={user.role}",
                ip=client_ip,
                tenant_id=user.tenant_id,
            )
            return LoginResponse(
                two_fa_required=True,
                pending_2fa_token=pending_token,
                password_change_required=bool(user.password_change_required),
                role=user.role,
                username=user.username,
            )

        tv = user.token_version or 0
        access_token = create_access_token(data={"sub": user.username, "role": user.role, "tv": tv})
        refresh_token = create_refresh_token(data={"sub": user.username, "role": user.role, "tv": tv})
        persist_refresh_token(db, refresh_token, user.username, tv)

        await write_audit(
            db,
            user.username,
            "LOGIN",
            detail=f"role={user.role}",
            ip=client_ip,
            tenant_id=user.tenant_id,
        )

        logger.info(f"✅ Giriş: {user.username} ({user.role})")
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            password_change_required=bool(user.password_change_required),
            role=user.role,
            username=user.username,
            two_fa_required=False,
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 2FA DOĞRULAMA
# ---------------------------------------------------------------------------

@router.post("/api/login/2fa", response_model=LoginResponse)
async def login_2fa(request: Request, body: TwoFALoginRequest):
    client_ip = request.client.host if request.client else ""

    try:
        import pyotp
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    try:
        payload = decode_token(body.pending_2fa_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş 2FA token")

    if payload.get("type") != "pending_2fa" or payload.get("stage") != "2fa_pending":
        raise HTTPException(status_code=401, detail="Geçersiz 2FA aşaması")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Geçersiz token")

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user or not user.is_active or not user.totp_enabled or not user.totp_secret:
            raise HTTPException(status_code=400, detail="2FA aktif değil veya kullanıcı bulunamadı")

        if not pyotp.TOTP(user.totp_secret).verify(body.totp_code.strip(), valid_window=1):
            await write_audit(
                db,
                username,
                "2FA_LOGIN_FAIL",
                result="FAILURE",
                ip=client_ip,
                tenant_id=user.tenant_id,
            )
            raise HTTPException(status_code=401, detail="2FA kodu hatalı")

        tv = user.token_version or 0
        access_token = create_access_token(data={"sub": user.username, "role": user.role, "tv": tv})
        refresh_token = create_refresh_token(data={"sub": user.username, "role": user.role, "tv": tv})
        persist_refresh_token(db, refresh_token, user.username, tv)

        await write_audit(
            db,
            username,
            "2FA_LOGIN_SUCCESS",
            ip=client_ip,
            tenant_id=user.tenant_id,
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            password_change_required=bool(user.password_change_required),
            role=user.role,
            username=user.username,
            two_fa_required=False,
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# REFRESH TOKEN
# ---------------------------------------------------------------------------

@router.post("/api/token/refresh", response_model=LoginResponse)
async def refresh_access_token(body: RefreshTokenRequest):
    try:
        payload = decode_token(body.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Geçersiz refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Geçersiz refresh token türü")

    username = payload.get("sub")
    jti = payload.get("jti")
    if not username or not jti:
        raise HTTPException(status_code=401, detail="Eksik refresh token claim")

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")

        if payload.get("tv", 0) != (user.token_version or 0):
            raise HTTPException(status_code=401, detail="Refresh token geçersiz kılınmış")

        stored = db.query(RefreshTokenModel).filter(RefreshTokenModel.id == jti).first()
        if not stored or stored.revoked_at is not None:
            raise HTTPException(status_code=401, detail="Refresh token geçersiz veya tekrar kullanılmış")
        if stored.username != user.username or stored.token_version != (user.token_version or 0):
            raise HTTPException(status_code=401, detail="Refresh token eşleşmiyor")
        if parse_utc(stored.expires_at) < utcnow():
            raise HTTPException(status_code=401, detail="Refresh token süresi dolmuş")

        tv = user.token_version or 0
        access_token = create_access_token(data={"sub": user.username, "role": user.role, "tv": tv})
        refresh_token = create_refresh_token(data={"sub": user.username, "role": user.role, "tv": tv})

        new_payload = decode_token(refresh_token)
        stored.revoked_at = utcnow_iso()
        stored.replaced_by = new_payload["jti"]
        db.commit()

        persist_refresh_token(db, refresh_token, user.username, tv)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            password_change_required=bool(user.password_change_required),
            role=user.role,
            username=user.username,
            two_fa_required=False,
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# MEVCUT KULLANICI
# ---------------------------------------------------------------------------

@router.get("/api/me")
async def get_me(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

        return {
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at,
            "last_login": user.last_login,
        }
    finally:
        db.close()


@router.get("/api/me/2fa-status")
async def get_2fa_status(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        return {
            "totp_enabled": bool(user.totp_enabled) if user else False,
            "username": current_user,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 2FA KURULUM
# ---------------------------------------------------------------------------

@router.post("/api/users/2fa/setup")
async def setup_2fa(current_user: str = Depends(get_current_user)):
    try:
        import pyotp
        import base64
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        if user.totp_enabled:
            raise HTTPException(status_code=400, detail="2FA zaten aktif")

        secret = pyotp.random_base32()
        user.totp_secret = secret
        db.commit()

        uri = pyotp.TOTP(secret).provisioning_uri(name=current_user, issuer_name="SolidTrace")
        qr_data_url = None

        try:
            import qrcode
            import io

            qr = qrcode.make(uri)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")
            qr_data_url = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"
        except ImportError:
            pass

        return {
            "secret": secret,
            "uri": uri,
            "qr_data_url": qr_data_url,
            "message": "QR kodu tarayın, /api/users/2fa/verify ile doğrulayın",
        }
    finally:
        db.close()


@router.post("/api/users/2fa/verify")
async def verify_2fa_setup(
    body: TwoFAVerifyRequest,
    current_user: str = Depends(get_current_user),
):
    try:
        import pyotp
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not user.totp_secret:
            raise HTTPException(status_code=400, detail="Önce /api/users/2fa/setup çağrılmalı")

        if not pyotp.TOTP(user.totp_secret).verify(body.code.strip(), valid_window=1):
            raise HTTPException(status_code=400, detail="Kod hatalı veya süresi geçmiş")

        user.totp_enabled = True
        db.commit()

        await write_audit(db, current_user, "2FA_ENABLED", tenant_id=user.tenant_id)
        return {"status": "enabled"}
    finally:
        db.close()


@router.post("/api/users/2fa/disable")
async def disable_2fa(
    body: TwoFADisableRequest,
    current_user: str = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not verify_password(body.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Şifre hatalı")

        user.totp_enabled = False
        user.totp_secret = None
        db.commit()

        await write_audit(db, current_user, "2FA_DISABLED", tenant_id=user.tenant_id)
        return {"status": "disabled"}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# KULLANICI YÖNETİMİ
# ---------------------------------------------------------------------------

@router.get("/api/users")
async def list_users(
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        q = tenant_filter(db.query(UserModel), UserModel, current_tenant_id)
        return [u.to_dict() for u in q.all()]
    finally:
        db.close()


@router.post("/api/users/invite")
async def invite_user(
    req: UserInviteRequest,
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    normalized_email = str(req.email).strip().lower()

    if req.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")

    if current_tenant_id is not None and req.tenant_id != current_tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Sadece kendi tenant'ınıza kullanıcı davet edebilirsiniz",
        )

    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == req.username).first():
            raise HTTPException(status_code=409, detail="Kullanıcı adı zaten mevcut")

        invite_token = secrets.token_urlsafe(32)
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        setup_url = f"{frontend_url}/setup-password?token={invite_token}"

        user = UserModel(
            id=str(uuid.uuid4()),
            username=req.username,
            hashed_password=get_password_hash(secrets.token_urlsafe(24)),
            role=req.role,
            email=normalized_email,
            tenant_id=req.tenant_id,
            created_at=utcnow_iso(),
            password_change_required=True,
            is_active=True,
            must_setup_password=True,
            invite_token_hash=hash_token(invite_token),
            invite_expires_at=(utcnow() + timedelta(hours=24)).isoformat(),
        )
        db.add(user)
        db.commit()

        email_sent = False
        if os.getenv("SMTP_USER"):
            email_sent = EmailNotifier().send_invite_link(
                normalized_email,
                req.username,
                setup_url,
            )

        await write_audit(
            db,
            current_user,
            "USER_INVITE",
            target=req.username,
            detail=f"email={normalized_email} role={req.role} email_sent={email_sent}",
            tenant_id=req.tenant_id,
        )

        return {
            "status": "invited",
            "username": req.username,
            "email_sent": email_sent,
        }
    finally:
        db.close()


@router.post("/api/users/setup-password")
async def setup_password(req: InviteSetupRequest):
    validate_password_strength(req.new_password)
    token_hash = hash_token(req.token)

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.invite_token_hash == token_hash).first()
        if not user:
            raise HTTPException(status_code=400, detail="Geçersiz davet tokenı")

        expires = user.invite_expires_at
        if not expires or parse_utc(expires) < utcnow():
            raise HTTPException(status_code=400, detail="Davet token süresi dolmuş")

        if verify_password(req.new_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Yeni parola mevcut parola ile aynı olamaz")

        user.hashed_password = get_password_hash(req.new_password)
        user.password_change_required = False
        user.must_setup_password = False
        user.invite_token_hash = None
        user.invite_expires_at = None
        user.password_changed_at = utcnow_iso()
        user.token_version = (user.token_version or 0) + 1
        db.commit()

        await write_audit(db, user.username, "PASSWORD_SETUP", tenant_id=user.tenant_id)
        return {"status": "password_set"}
    finally:
        db.close()


@router.delete("/api/users/{username}")
async def delete_user(
    username: str,
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    if username == current_user:
        raise HTTPException(status_code=400, detail="Kendi hesabınızı silemezsiniz")
    if username == "admin":
        raise HTTPException(status_code=400, detail="Ana admin silinemez")

    db = SessionLocal()
    try:
        q = db.query(UserModel).filter(UserModel.username == username)
        q = tenant_filter(q, UserModel, current_tenant_id)
        user = q.first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

        db.delete(user)
        db.commit()

        await write_audit(
            db,
            current_user,
            "USER_DELETE",
            target=username,
            tenant_id=user.tenant_id,
        )
        return {"status": "deleted", "username": username}
    finally:
        db.close()


@router.put("/api/users/{username}/role")
async def update_user_role(
    username: str,
    body: dict,
    current_user: str = Depends(require_role("admin")),
    current_tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    new_role = body.get("role")
    if new_role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")

    db = SessionLocal()
    try:
        q = db.query(UserModel).filter(UserModel.username == username)
        q = tenant_filter(q, UserModel, current_tenant_id)
        user = q.first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

        old_role = user.role
        user.role = new_role
        db.commit()

        await write_audit(
            db,
            current_user,
            "USER_ROLE_CHANGE",
            target=username,
            detail=f"{old_role} → {new_role}",
            tenant_id=user.tenant_id,
        )
        return {"status": "updated", "username": username, "role": new_role}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ŞİFRE İŞLEMLERİ
# ---------------------------------------------------------------------------

@router.post("/api/users/change-password")
async def change_password(
    req: PasswordChangeRequest,
    current_user: str = Depends(get_current_user),
):
    validate_password_strength(req.new_password)

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not verify_password(req.current_password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Mevcut şifre hatalı")

        if verify_password(req.new_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Yeni parola mevcut parola ile aynı olamaz")

        user.hashed_password = get_password_hash(req.new_password)
        user.password_change_required = False
        user.password_changed_at = utcnow_iso()
        user.token_version = (user.token_version or 0) + 1
        db.commit()

        await write_audit(db, current_user, "PASSWORD_CHANGE", tenant_id=user.tenant_id)
        return {"status": "changed"}
    finally:
        db.close()


@router.post("/api/admin/reset-password")
async def admin_reset_password(
    req: AdminPasswordResetRequest,
    current_user: str = Depends(require_role("admin")),
):
    validate_password_strength(req.new_password)

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == req.username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

        if verify_password(req.new_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Yeni parola mevcut parola ile aynı olamaz")

        user.hashed_password = get_password_hash(req.new_password)
        user.password_change_required = True
        user.password_changed_at = utcnow_iso()
        user.token_version = (user.token_version or 0) + 1
        db.commit()

        await write_audit(
            db,
            current_user,
            "ADMIN_PASSWORD_RESET",
            target=req.username,
            tenant_id=user.tenant_id,
        )

        return {"status": "reset", "username": req.username}
    finally:
        db.close()
"""
app.api.routes_auth
===================
Kimlik doğrulama ve kullanıcı yönetimi endpoint'leri:
  /api/login, /api/login/2fa, /api/me, /api/me/2fa-status
  /api/users/*, /api/admin/reset-password, /api/users/change-password
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES, MAX_LOGIN_ATTEMPTS, LOGIN_WINDOW_SECONDS,
    verify_password, get_password_hash, create_access_token,
    get_current_user, require_role, pwd_context,
)
from app.database.db_manager import SessionLocal, UserModel, write_audit
from app.schemas.models import (
    Token, UserCreateRequest, PasswordChangeRequest,
    AdminPasswordResetRequest,
)
from app.services.notification import EmailNotifier

logger = logging.getLogger("SolidTrace.Auth")
router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# GİRİŞ
# ---------------------------------------------------------------------------

@router.post("/api/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """Brute-force korumalı giriş — 5 başarısız denemede 5 dk kilit."""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == form_data.username).first()

        if user and user.locked_until:
            lock_time = datetime.fromisoformat(user.locked_until)
            if datetime.now() < lock_time:
                remaining = int((lock_time - datetime.now()).total_seconds() / 60)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Hesap kilitli. {remaining} dakika sonra tekrar deneyin.",
                )
            else:
                user.failed_attempts = 0
                user.locked_until    = None

        if not user or not verify_password(form_data.password, user.hashed_password):
            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.locked_until = (
                        datetime.now() + timedelta(seconds=LOGIN_WINDOW_SECONDS)
                    ).isoformat()
                    logger.warning(f"🔒 Hesap kilitlendi: {form_data.username}")
                db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kullanıcı adı veya şifre hatalı",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user.failed_attempts = 0
        user.locked_until    = None
        user.last_login      = datetime.now().isoformat()
        db.commit()

        token = create_access_token(data={"sub": user.username, "role": user.role})
        logger.info(f"✅ Giriş: {user.username} ({user.role})")
        await write_audit(db, user.username, "LOGIN", detail=f"role={user.role}")
        return {
            "access_token":             token,
            "token_type":               "bearer",
            "password_change_required": bool(user.password_change_required),
            "role":                     user.role,
            "username":                 user.username,
        }
    finally:
        db.close()


@router.post("/api/login/2fa")
async def login_2fa(body: dict):
    """2FA doğrulama — normal login'den sonra çağrılır."""
    try:
        import pyotp
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    username  = body.get("username", "")
    totp_code = body.get("totp_code", "").strip()
    db        = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user or not user.totp_enabled or not user.totp_secret:
            raise HTTPException(status_code=400, detail="2FA aktif değil veya kullanıcı bulunamadı")
        if not pyotp.TOTP(user.totp_secret).verify(totp_code, valid_window=1):
            await write_audit(db, username, "2FA_LOGIN_FAIL", result="FAILURE")
            raise HTTPException(status_code=401, detail="2FA kodu hatalı")
        token = create_access_token(data={"sub": user.username, "role": user.role})
        await write_audit(db, username, "2FA_LOGIN_SUCCESS")
        return {
            "access_token":             token,
            "token_type":               "bearer",
            "password_change_required": bool(user.password_change_required),
            "role":                     user.role,
            "username":                 user.username,
        }
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
            "username":   user.username,
            "role":       user.role,
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
        return {"totp_enabled": bool(user.totp_enabled) if user else False, "username": current_user}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 2FA KURULUM
# ---------------------------------------------------------------------------

@router.post("/api/users/2fa/setup")
async def setup_2fa(current_user: str = Depends(get_current_user)):
    try:
        import pyotp, base64
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        if user.totp_enabled:
            raise HTTPException(status_code=400, detail="2FA zaten aktif")

        secret         = pyotp.random_base32()
        user.totp_secret = secret
        db.commit()

        uri = pyotp.TOTP(secret).provisioning_uri(name=current_user, issuer_name="SolidTrace")
        qr_data_url = None
        try:
            import qrcode, io
            qr  = qrcode.make(uri)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")
            qr_data_url = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"
        except ImportError:
            pass

        return {"secret": secret, "uri": uri, "qr_data_url": qr_data_url,
                "message": "QR kodu tarayın, /api/users/2fa/verify ile doğrulayın"}
    finally:
        db.close()


@router.post("/api/users/2fa/verify")
async def verify_2fa_setup(body: dict, current_user: str = Depends(get_current_user)):
    try:
        import pyotp
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not user.totp_secret:
            raise HTTPException(status_code=400, detail="Önce /api/users/2fa/setup çağrılmalı")
        if not pyotp.TOTP(user.totp_secret).verify(body.get("code", "").strip(), valid_window=1):
            raise HTTPException(status_code=400, detail="Kod hatalı veya süresi geçmiş")
        user.totp_enabled = True
        db.commit()
        await write_audit(db, current_user, "2FA_ENABLED")
        return {"status": "enabled", "message": "2FA başarıyla aktifleştirildi"}
    finally:
        db.close()


@router.post("/api/users/2fa/disable")
async def disable_2fa(body: dict, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not verify_password(body.get("password", ""), user.hashed_password):
            raise HTTPException(status_code=401, detail="Şifre hatalı")
        user.totp_enabled = False
        user.totp_secret  = None
        db.commit()
        await write_audit(db, current_user, "2FA_DISABLED")
        return {"status": "disabled"}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# KULLANICI YÖNETİMİ
# ---------------------------------------------------------------------------

@router.get("/api/users")
async def list_users(current_user: str = Depends(require_role("admin"))):
    db = SessionLocal()
    try:
        return [
            {"username": u.username, "role": u.role, "email": u.email,
             "is_active": u.is_active, "last_login": u.last_login,
             "created_at": u.created_at,
             "password_change_required": u.password_change_required}
            for u in db.query(UserModel).all()
        ]
    finally:
        db.close()


@router.post("/api/users")
async def create_user(req: UserCreateRequest, current_user: str = Depends(require_role("admin"))):
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı")
    if req.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")
    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == req.username).first():
            raise HTTPException(status_code=409, detail="Kullanıcı adı zaten mevcut")
        db.add(UserModel(
            id=str(uuid.uuid4()), username=req.username,
            hashed_password=pwd_context.hash(req.password),
            role=req.role, email=req.email,
            created_at=datetime.now().isoformat(),
            password_change_required=True, is_active=True,
        ))
        db.commit()
        await write_audit(db, current_user, "USER_CREATE",
                          target=req.username, detail=f"role={req.role}")
        return {"status": "created", "username": req.username}
    finally:
        db.close()


@router.post("/api/users/invite")
async def invite_user(req: UserCreateRequest, current_user: str = Depends(require_role("admin"))):
    """Kullanıcı oluştur + davet e-postası gönder."""
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı")
    if req.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")
    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == req.username).first():
            raise HTTPException(status_code=409, detail="Kullanıcı adı zaten mevcut")
        db.add(UserModel(
            id=str(uuid.uuid4()), username=req.username,
            hashed_password=pwd_context.hash(req.password),
            role=req.role, email=req.email, tenant_id=req.tenant_id,
            created_at=datetime.now().isoformat(),
            password_change_required=True, is_active=True,
        ))
        db.commit()
        await write_audit(db, current_user, "USER_INVITE",
                          target=req.username, detail=f"email={req.email} role={req.role}")

        email_sent = False
        if req.email and __import__("os").getenv("SMTP_USER"):
            email_sent = EmailNotifier().send_invite(req.email, req.username, req.password)

        return {"status": "invited", "username": req.username, "email_sent": email_sent}
    finally:
        db.close()


@router.delete("/api/users/{username}")
async def delete_user(username: str, current_user: str = Depends(require_role("admin"))):
    if username == current_user:
        raise HTTPException(status_code=400, detail="Kendi hesabınızı silemezsiniz")
    if username == "admin":
        raise HTTPException(status_code=400, detail="Ana admin silinemez")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        db.delete(user)
        db.commit()
        await write_audit(db, current_user, "USER_DELETE", target=username)
        return {"status": "deleted", "username": username}
    finally:
        db.close()


@router.put("/api/users/{username}/role")
async def update_user_role(username: str, body: dict,
                           current_user: str = Depends(require_role("admin"))):
    new_role = body.get("role")
    if new_role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        old_role   = user.role
        user.role  = new_role
        db.commit()
        await write_audit(db, current_user, "USER_ROLE_CHANGE",
                          target=username, detail=f"{old_role} → {new_role}")
        return {"status": "updated", "username": username, "role": new_role}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ŞİFRE İŞLEMLERİ
# ---------------------------------------------------------------------------

@router.post("/api/users/change-password")
async def change_password(req: PasswordChangeRequest,
                          current_user: str = Depends(get_current_user)):
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Yeni şifre en az 8 karakter olmalı")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not verify_password(req.current_password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Mevcut şifre hatalı")
        user.hashed_password          = get_password_hash(req.new_password)
        user.password_change_required = False
        db.commit()
        await write_audit(db, current_user, "PASSWORD_CHANGE")
        return {"status": "changed"}
    finally:
        db.close()


@router.post("/api/admin/reset-password")
async def admin_reset_password(req: AdminPasswordResetRequest,
                               current_user: str = Depends(require_role("admin"))):
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == req.username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        user.hashed_password          = get_password_hash(req.new_password)
        user.password_change_required = True
        db.commit()
        await write_audit(db, current_user, "ADMIN_PASSWORD_RESET", target=req.username)
        return {"status": "reset", "username": req.username}
    finally:
        db.close()

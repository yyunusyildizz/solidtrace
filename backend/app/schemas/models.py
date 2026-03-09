"""
app.schemas.models
==================
Pydantic şemaları
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    role: Optional[str] = None
    username: Optional[str] = None
    password_change_required: Optional[bool] = False
    two_fa_required: bool = False
    pending_2fa_token: Optional[str] = None


Token = LoginResponse


class LoginRequest(BaseModel):
    username: str
    password: str


class TwoFALoginRequest(BaseModel):
    pending_2fa_token: str
    totp_code: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TwoFAVerifyRequest(BaseModel):
    code: str


class TwoFADisableRequest(BaseModel):
    password: str


class UserCreateRequest(BaseModel):
    username: str
    password: Optional[str] = None
    role: str = "analyst"
    email: Optional[EmailStr] = None
    tenant_id: Optional[str] = None


class UserInviteRequest(BaseModel):
    username: str
    role: str = "analyst"
    email: EmailStr
    tenant_id: Optional[str] = None


class InviteSetupRequest(BaseModel):
    token: str
    new_password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class AdminPasswordResetRequest(BaseModel):
    username: str
    new_password: str


class TenantCreateRequest(BaseModel):
    name: str
    contact_email: Optional[str] = None
    max_agents: int = 10
    plan: str = "starter"


class AgentEnrollmentTokenCreateRequest(BaseModel):
    tenant_id: str
    expires_in_minutes: int = 30

    @field_validator("expires_in_minutes")
    @classmethod
    def validate_expiry(cls, v: int) -> int:
        if v < 5 or v > 1440:
            raise ValueError("expires_in_minutes 5 ile 1440 arasında olmalı")
        return v


class AgentEnrollmentTokenCreateResponse(BaseModel):
    enrollment_token: str
    expires_at: str
    tenant_id: str


class AgentRegisterRequest(BaseModel):
    enrollment_token: str
    hostname: str
    device_fingerprint: str
    os_name: Optional[str] = None
    agent_version: Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("hostname boş olamaz")
        return v.strip()

    @field_validator("device_fingerprint")
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("device_fingerprint boş olamaz")
        cleaned = v.strip()
        if len(cleaned) < 8:
            raise ValueError("device_fingerprint çok kısa")
        return cleaned


class AgentRegisterResponse(BaseModel):
    agent_id: str
    agent_secret: str
    tenant_id: str


class AgentListResponse(BaseModel):
    id: str
    tenant_id: str
    hostname: str
    device_fingerprint: str
    os_name: Optional[str] = None
    agent_version: Optional[str] = None
    enrolled_at: str
    last_seen: Optional[str] = None
    is_active: bool
    revoked_at: Optional[str] = None


class AgentHeartbeatRequest(BaseModel):
    hostname: str
    agent_version: Optional[str] = None
    os_name: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    uptime_seconds: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None

    @field_validator("hostname")
    @classmethod
    def hostname_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("hostname boş olamaz")
        return v.strip()


class AgentHeartbeatResponse(BaseModel):
    status: str = "ok"
    server_time: str


class DetectionRuleSchema(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    keyword: str = Field(..., min_length=1, max_length=200)
    risk_score: int = Field(..., ge=0, le=100)
    severity: str = Field(..., pattern="^(INFO|WARNING|HIGH|CRITICAL)$")


class EventBase(BaseModel):
    type: str
    hostname: str
    user: Optional[str] = "SYSTEM"
    pid: Optional[int] = 0
    details: Optional[str] = ""
    command_line: Optional[str] = ""
    serial: Optional[str] = None
    severity: Optional[str] = "INFO"
    timestamp: Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def hostname_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("hostname boş olamaz")
        cleaned = v.strip()
        fake = {"localhost", "unknown", "unknown-host", "sys_internal", "none", "null", "(none)", "computer"}
        if cleaned.lower() in fake:
            raise ValueError(f"Geçersiz hostname: '{cleaned}'.")
        return cleaned

    @field_validator("details", "command_line")
    @classmethod
    def truncate_long_fields(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 10_000:
            return v[:10_000] + "...[truncated]"
        return v


class ActionRequest(BaseModel):
    hostname: str
    pid: Optional[int] = 0
    rule: Optional[str] = None
    severity: Optional[str] = None
    details: Optional[str] = None
    serial: Optional[str] = None
    risk_score: Optional[int] = 0
    command_line: Optional[str] = None
    description: Optional[str] = None


class HashReport(BaseModel):
    hostname: str
    file_path: str
    file_hash: str
    pid: int

    @field_validator("file_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) not in (32, 64) or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("Geçersiz hash formatı (MD5 veya SHA256 bekleniyor)")
        return v
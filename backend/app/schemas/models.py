"""
app.schemas.models
==================
Tüm Pydantic şemaları — ECS uyumlu.
Request/Response modelleri ve validation kuralları.
İş mantığı veya DB kodu içermez.
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------

class Token(BaseModel):
    access_token:             str
    token_type:               str
    role:                     Optional[str] = None
    username:                 Optional[str] = None
    password_change_required: Optional[bool] = False


class LoginRequest(BaseModel):
    username: str
    password: str


class TwoFALoginRequest(BaseModel):
    username:  str
    totp_code: str


# ---------------------------------------------------------------------------
# KULLANICI & KİRACI YÖNETİMİ
# ---------------------------------------------------------------------------

class TenantCreateRequest(BaseModel):
    name:          str
    contact_email: Optional[str] = None
    max_agents:    int = 10
    plan:          str = "starter"


class UserCreateRequest(BaseModel):
    username:  str
    password:  str
    role:      str           = "analyst"
    email:     Optional[str] = None
    tenant_id: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password:     str


class AdminPasswordResetRequest(BaseModel):
    username:     str
    new_password: str


# ---------------------------------------------------------------------------
# KURAL YÖNETİMİ
# ---------------------------------------------------------------------------

class DetectionRuleSchema(BaseModel):
    name:       str = Field(..., min_length=3, max_length=100)
    keyword:    str = Field(..., min_length=1, max_length=200)
    risk_score: int = Field(..., ge=0, le=100)
    severity:   str = Field(..., pattern="^(INFO|WARNING|HIGH|CRITICAL)$")


# ---------------------------------------------------------------------------
# EVENT (AGENT → BACKEND)
# ECS: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
# ---------------------------------------------------------------------------

class EventBase(BaseModel):
    # ECS: event.kind / event.type
    type:         str
    # ECS: host.hostname
    hostname:     str
    # ECS: user.name
    user:         Optional[str] = "SYSTEM"
    # ECS: process.pid
    pid:          Optional[int] = 0
    # ECS: event.original
    details:      Optional[str] = ""
    # ECS: process.command_line
    command_line: Optional[str] = ""
    # USB seri numarası (özel alan)
    serial:       Optional[str] = None
    # ECS: event.severity
    severity:     Optional[str] = "INFO"
    # ECS: @timestamp
    timestamp:    Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def hostname_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("hostname boş olamaz")
        cleaned = v.strip()
        fake_values = {"localhost", "unknown", "unknown-host", "sys_internal",
                       "none", "null", "(none)", "computer"}
        if cleaned.lower() in fake_values:
            raise ValueError(f"Geçersiz hostname: '{cleaned}'.")
        return cleaned

    @field_validator("details", "command_line")
    @classmethod
    def truncate_long_fields(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 10_000:
            return v[:10_000] + "...[truncated]"
        return v


# ---------------------------------------------------------------------------
# AKSİYON İSTEKLERİ
# ---------------------------------------------------------------------------

class ActionRequest(BaseModel):
    hostname:   str
    pid:        Optional[int] = 0
    rule:       Optional[str] = None
    severity:   Optional[str] = None
    details:    Optional[str] = None
    serial:     Optional[str] = None
    risk_score: Optional[int] = 0
    # Komut/açıklama alanları — AI analizi için
    command_line: Optional[str] = None
    description:  Optional[str] = None


class HashReport(BaseModel):
    hostname:  str
    file_path: str
    file_hash: str
    pid:       int

    @field_validator("file_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) not in (32, 64) or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("Geçersiz hash formatı (MD5 veya SHA256 bekleniyor)")
        return v

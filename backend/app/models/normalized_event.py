"""
app.models.normalized_event
============================
NormalizedSecurityEvent — SolidTrace'in ortak güvenlik olayı formatı.

Farklı kaynaklardan gelen event, alert ve response result verilerini
tek bir standart yapıya dönüştürmek için kullanılır.

Gelecekte Correlation Engine, Attack Story Engine, Investigation Graph
ve Case Engine bu modeli ortak veri kaynağı olarak kullanacak.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

EVENT_TYPES: List[str] = [
    "process_execution",
    "sigma_match",
    "alert_created",
    "response_result",
    "user_login",
    "network_connection",
]

SEVERITY_LEVELS: List[str] = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _generate_uuid() -> str:
    """UUID v4 üretir."""
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    """UTC ISO 8601 timestamp üretir."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# NormalizedSecurityEvent
# ---------------------------------------------------------------------------

class NormalizedSecurityEvent(BaseModel):
    """
    Tüm SolidTrace güvenlik olaylarının ortak normalize formatı.

    Alanlar:
        id:               Benzersiz olay kimliği (UUID v4, otomatik üretilir)
        tenant_id:        Kiracı kimliği
        event_type:       Olay türü (EVENT_TYPES listesinden biri)
        hostname:         Hedef/kaynak makine adı
        username:         İlgili kullanıcı adı
        process_name:     Süreç adı (command_line'dan çıkarılır)
        command_line:     Tam komut satırı
        source_ip:        Kaynak IP adresi
        destination_ip:   Hedef IP adresi
        risk_score:       Risk puanı (0-100)
        severity:         Ciddiyet seviyesi (INFO/LOW/MEDIUM/HIGH/CRITICAL)
        mitre_tactic:     MITRE ATT&CK taktiği
        mitre_technique:  MITRE ATT&CK tekniği
        source:           Olay kaynağı (raw_event/sigma_engine/alert_service/response_action)
        raw_ref_id:       Orijinal kayıt referans ID'si
        timestamp:        Zaman damgası (UTC ISO 8601, otomatik üretilir)
        attributes:       Serbest ek alanlar
    """

    id: str = Field(default_factory=_generate_uuid)
    tenant_id: Optional[str] = None
    event_type: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    risk_score: int = 0
    severity: str = "INFO"
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    source: str = "raw_event"
    raw_ref_id: Optional[str] = None
    timestamp: str = Field(default_factory=_utcnow_iso)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "from_attributes": True,
    }

    # -- Validators ----------------------------------------------------------

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in EVENT_TYPES:
            raise ValueError(
                f"Geçersiz event_type: '{value}'. "
                f"İzin verilen değerler: {EVENT_TYPES}"
            )
        return cleaned

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, value: int) -> int:
        if value < 0 or value > 100:
            raise ValueError(
                f"risk_score 0-100 arasında olmalı, verilen: {value}"
            )
        return value

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if cleaned not in SEVERITY_LEVELS:
            raise ValueError(
                f"Geçersiz severity: '{value}'. "
                f"İzin verilen değerler: {SEVERITY_LEVELS}"
            )
        return cleaned

    # -- Serialize -----------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Model verilerini sözlük olarak döndürür."""
        return self.model_dump()

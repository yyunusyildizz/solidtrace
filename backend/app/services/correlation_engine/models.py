"""
app.services.correlation_engine.models
=======================================
CorrelationGroup domain modeli.

NormalizedSecurityEvent'lerin ilişkilendirilmiş grubunu temsil eder.
Pure in-memory Pydantic model — DB persistence yok.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CONFIDENCE_LEVELS: List[str] = ["low", "medium", "high"]


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# CorrelationGroup
# ---------------------------------------------------------------------------

class CorrelationGroup(BaseModel):
    """
    İlişkilendirilmiş güvenlik olaylarının grubu.

    Alanlar:
        id:           Benzersiz grup kimliği (UUID v4, otomatik üretilir)
        tenant_id:    Kiracı kimliği
        title:        Grubun başlığı (rule tarafından belirlenir)
        description:  Açıklama
        severity:     Ciddiyet seviyesi (INFO/LOW/MEDIUM/HIGH/CRITICAL)
        confidence:   Güven seviyesi (low/medium/high)
        risk_score:   Aggregated risk puanı (0-100)
        status:       Grup durumu (default: "open")
        event_ids:    İlişkili NormalizedSecurityEvent ID'leri
        alert_ids:    İlişkili alert raw_ref_id'leri
        entities:     Varlık listeleri (hostname, username, ip)
        tactics:      MITRE ATT&CK tactic'leri
        techniques:   MITRE ATT&CK technique'leri
        reason:       Korelasyon nedeni
        created_at:   Oluşturulma zamanı (UTC ISO 8601)
        updated_at:   Güncellenme zamanı (UTC ISO 8601)
        attributes:   Serbest ek metadata
    """

    id: str = Field(default_factory=_generate_uuid)
    tenant_id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: str = "INFO"
    confidence: str = "medium"
    risk_score: int = 0
    status: str = "open"
    event_ids: List[str] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)
    entities: Dict[str, List[str]] = Field(
        default_factory=lambda: {"hostnames": [], "usernames": [], "ips": []}
    )
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    reason: str = ""
    created_at: str = Field(default_factory=_utcnow_iso)
    updated_at: str = Field(default_factory=_utcnow_iso)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "from_attributes": True,
    }

    # -- Validators ----------------------------------------------------------

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, value: int) -> int:
        return max(0, min(100, value))

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if cleaned not in SEVERITY_ORDER:
            raise ValueError(
                f"Geçersiz severity: '{value}'. "
                f"İzin verilen değerler: {list(SEVERITY_ORDER.keys())}"
            )
        return cleaned

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in CONFIDENCE_LEVELS:
            raise ValueError(
                f"Geçersiz confidence: '{value}'. "
                f"İzin verilen değerler: {CONFIDENCE_LEVELS}"
            )
        return cleaned

    # -- Helpers -------------------------------------------------------------

    def add_event(self, event: Any) -> None:
        """
        NormalizedSecurityEvent'i gruba ekler.
        Event ID, entity, tactic ve technique bilgilerini toplar.

        Args:
            event: NormalizedSecurityEvent instance
        """
        # Event ID
        if event.id and event.id not in self.event_ids:
            self.event_ids.append(event.id)

        # Alert raw_ref_id
        if event.raw_ref_id and event.raw_ref_id not in self.alert_ids:
            self.alert_ids.append(event.raw_ref_id)

        # Entities
        if event.hostname and event.hostname not in self.entities["hostnames"]:
            self.entities["hostnames"].append(event.hostname)
        if event.username and event.username not in self.entities["usernames"]:
            self.entities["usernames"].append(event.username)
        for ip_field in (event.source_ip, event.destination_ip):
            if ip_field and ip_field not in self.entities["ips"]:
                self.entities["ips"].append(ip_field)

        # MITRE
        if event.mitre_tactic and event.mitre_tactic not in self.tactics:
            self.tactics.append(event.mitre_tactic)
        if event.mitre_technique and event.mitre_technique not in self.techniques:
            self.techniques.append(event.mitre_technique)

        # Updated timestamp
        self.updated_at = _utcnow_iso()

    def to_dict(self) -> Dict[str, Any]:
        """Model verilerini sözlük olarak döndürür."""
        return self.model_dump()

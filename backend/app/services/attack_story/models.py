"""
app.services.attack_story.models
==================================
AttackStory ve RecommendedAction domain modelleri.

CorrelationGroup'tan üretilen, analyst tarafından okunabilir
saldırı hikayesi formatı. Pure in-memory — DB persistence yok.
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

ACTION_TYPES = {
    "isolate_host",
    "review_process_tree",
    "collect_artifacts",
    "reset_credentials",
    "disable_usb",
    "monitor_host",
    "create_case",
}

PRIORITY_LEVELS: List[str] = ["immediate", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# RecommendedAction
# ---------------------------------------------------------------------------

class RecommendedAction(BaseModel):
    """
    Story'ye bağlı önerilen aksiyon.

    Attributes:
        action_type:  Aksiyon türü (ACTION_TYPES setinden)
        title:        Okunabilir başlık
        description:  Açıklama
        priority:     Öncelik (immediate/high/medium/low)
        target:       Hedef hostname veya kullanıcı (opsiyonel)
    """

    action_type: str
    title: str = ""
    description: str = ""
    priority: str = "medium"
    target: Optional[str] = None

    @field_validator("action_type")
    @classmethod
    def validate_action_type(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in ACTION_TYPES:
            raise ValueError(
                f"Geçersiz action_type: '{value}'. "
                f"İzin verilen değerler: {sorted(ACTION_TYPES)}"
            )
        return cleaned

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in PRIORITY_LEVELS:
            raise ValueError(
                f"Geçersiz priority: '{value}'. "
                f"İzin verilen değerler: {PRIORITY_LEVELS}"
            )
        return cleaned


# ---------------------------------------------------------------------------
# AttackStory
# ---------------------------------------------------------------------------

class AttackStory(BaseModel):
    """
    Analyst tarafından okunabilir saldırı hikayesi.

    Attributes:
        id:                    Benzersiz story kimliği (UUID v4)
        tenant_id:             Kiracı kimliği
        correlation_group_id:  İlişkili CorrelationGroup ID
        title:                 Story başlığı
        executive_summary:     Yönetici özeti (teknik olmayan)
        technical_summary:     Teknik detay özeti
        severity:              Ciddiyet seviyesi
        confidence:            Güven seviyesi
        risk_score:            Risk puanı (0-100)
        affected_hosts:        Etkilenen hostlar
        affected_users:        Etkilenen kullanıcılar
        source_ips:            Kaynak IP'ler
        destination_ips:       Hedef IP'ler
        tactics:               MITRE ATT&CK tactic'leri
        techniques:            MITRE ATT&CK technique'leri
        timeline:              Olay zaman çizelgesi
        key_findings:          Önemli bulgular
        recommended_actions:   Önerilen aksiyonlar
        analyst_questions:     Analist için sorular
        created_at:            Oluşturulma zamanı (UTC ISO 8601)
        attributes:            Serbest ek metadata
    """

    id: str = Field(default_factory=_generate_uuid)
    tenant_id: Optional[str] = None
    correlation_group_id: str = ""
    title: str = ""
    executive_summary: str = ""
    technical_summary: str = ""
    severity: str = "INFO"
    confidence: str = "medium"
    risk_score: int = 0
    affected_hosts: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    key_findings: List[str] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    analyst_questions: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=_utcnow_iso)
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

    def to_dict(self) -> Dict[str, Any]:
        """Model verilerini sözlük olarak döndürür."""
        return self.model_dump()

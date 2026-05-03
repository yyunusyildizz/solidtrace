"""
app.services.case_engine.models
==================================
CaseDraft, EvidenceItem, TimelineItem domain modelleri.

AttackStory + StoryGraph verilerinden üretilen vaka taslağı formatı.
Pure in-memory — DB persistence yok.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from app.services.attack_story.models import RecommendedAction


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

PRIORITY_LEVELS: List[str] = ["immediate", "high", "medium", "low"]

CONFIDENCE_LEVELS: List[str] = ["low", "medium", "high"]

STATUS_VALUES: List[str] = ["new", "open", "in_progress", "resolved", "closed"]

EVIDENCE_TYPES = {
    "alert",
    "story_timeline",
    "graph_summary",
    "mitre_mapping",
}


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# EvidenceItem
# ---------------------------------------------------------------------------

class EvidenceItem(BaseModel):
    """
    Kanıt öğesi.

    Attributes:
        evidence_type:  Kanıt türü (alert, story_timeline, graph_summary, mitre_mapping)
        source_id:      Kaynak ID
        description:    Okunabilir açıklama
        data:           Ham veri
    """

    evidence_type: str
    source_id: str = ""
    description: str = ""
    data: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "from_attributes": True,
    }

    @field_validator("evidence_type")
    @classmethod
    def validate_evidence_type(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in EVIDENCE_TYPES:
            raise ValueError(
                f"Geçersiz evidence_type: '{value}'. "
                f"İzin verilen değerler: {sorted(EVIDENCE_TYPES)}"
            )
        return cleaned


# ---------------------------------------------------------------------------
# TimelineItem
# ---------------------------------------------------------------------------

class TimelineItem(BaseModel):
    """
    Zaman çizelgesi öğesi.

    Attributes:
        order:           Sıra numarası (1-indexed)
        timestamp:       ISO 8601 veya boş string
        event_id:        Kaynak event ID
        description:     Okunabilir açıklama
        source_story_id: Hangi story'den geldi
    """

    order: int = 1
    timestamp: str = ""
    event_id: str = ""
    description: str = ""
    source_story_id: str = ""

    model_config = {
        "from_attributes": True,
    }

    @field_validator("order")
    @classmethod
    def validate_order(cls, value: int) -> int:
        return max(1, value)


# ---------------------------------------------------------------------------
# CaseDraft
# ---------------------------------------------------------------------------

class CaseDraft(BaseModel):
    """
    AttackStory + StoryGraph verilerinden üretilen vaka taslağı.

    Attributes:
        id:                    Benzersiz case kimliği (UUID v4)
        tenant_id:             Kiracı kimliği
        title:                 Case başlığı
        severity:              Ciddiyet seviyesi
        risk_score:            Risk puanı (0-100)
        status:                Vaka durumu (default: new)
        priority:              Öncelik (immediate/high/medium/low)
        confidence:            Güven seviyesi
        summary:               Yönetici özeti
        affected_hosts:        Etkilenen hostlar
        affected_users:        Etkilenen kullanıcılar
        tactics:               MITRE ATT&CK taktikleri
        techniques:            MITRE ATT&CK teknikleri
        related_alert_ids:     İlişkili alert ID'leri
        related_story_ids:     Kaynak AttackStory ID'leri
        graph_ids:             İlişkili StoryGraph ID'leri
        evidence_items:        Kanıt öğeleri
        timeline_items:        Zaman çizelgesi
        recommended_actions:   Önerilen aksiyonlar
        analyst_questions:     Analist soruları
        tags:                  Etiketler
        attributes:            Serbest metadata
        created_at:            Oluşturulma zamanı (UTC ISO 8601)
    """

    id: str = Field(default_factory=_generate_uuid)
    tenant_id: Optional[str] = None
    title: str = ""
    severity: str = "INFO"
    risk_score: int = 0
    status: str = "new"
    priority: str = "low"
    confidence: str = "medium"
    summary: str = ""
    affected_hosts: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    related_alert_ids: List[str] = Field(default_factory=list)
    related_story_ids: List[str] = Field(default_factory=list)
    graph_ids: List[str] = Field(default_factory=list)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    timeline_items: List[TimelineItem] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    analyst_questions: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utcnow_iso)

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

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in STATUS_VALUES:
            raise ValueError(
                f"Geçersiz status: '{value}'. "
                f"İzin verilen değerler: {STATUS_VALUES}"
            )
        return cleaned

    # -- Helpers -------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Model verilerini sözlük olarak döndürür."""
        return self.model_dump()

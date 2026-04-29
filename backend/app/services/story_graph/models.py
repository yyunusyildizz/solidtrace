"""
app.services.story_graph.models
==================================
StoryGraph, GraphNode, GraphEdge domain modelleri.

AttackStory'den üretilen investigation graph formatı.
Pure in-memory — DB persistence yok.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

NODE_TYPES = {
    "story",
    "host",
    "user",
    "source_ip",
    "destination_ip",
    "tactic",
    "technique",
    "action",
}

EDGE_TYPES = {
    "affects",
    "uses",
    "communicates_with",
    "maps_to",
    "recommends",
    "related_to",
}

SEVERITY_ORDER: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# GraphNode
# ---------------------------------------------------------------------------

class GraphNode(BaseModel):
    """
    Graph düğümü.

    Attributes:
        id:          Benzersiz node kimliği (UUID v4)
        node_type:   Düğüm tipi (story, host, user, source_ip, destination_ip,
                     tactic, technique, action)
        label:       Okunabilir etiket
        severity:    Ciddiyet seviyesi
        risk_score:  Risk puanı (0-100)
        attributes:  Serbest ek metadata
    """

    id: str = Field(default_factory=_generate_uuid)
    node_type: str
    label: str = ""
    severity: str = "INFO"
    risk_score: int = 0
    attributes: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "from_attributes": True,
    }

    @field_validator("node_type")
    @classmethod
    def validate_node_type(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in NODE_TYPES:
            raise ValueError(
                f"Geçersiz node_type: '{value}'. "
                f"İzin verilen değerler: {sorted(NODE_TYPES)}"
            )
        return cleaned

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

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, value: int) -> int:
        return max(0, min(100, value))


# ---------------------------------------------------------------------------
# GraphEdge
# ---------------------------------------------------------------------------

class GraphEdge(BaseModel):
    """
    Graph kenarı.

    Attributes:
        id:         Benzersiz edge kimliği (UUID v4)
        source:     Kaynak node ID
        target:     Hedef node ID
        edge_type:  Kenar tipi (affects, uses, communicates_with, maps_to,
                    recommends, related_to)
        label:      Okunabilir etiket
        attributes: Serbest ek metadata
    """

    id: str = Field(default_factory=_generate_uuid)
    source: str
    target: str
    edge_type: str
    label: str = ""
    attributes: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "from_attributes": True,
    }

    @field_validator("edge_type")
    @classmethod
    def validate_edge_type(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in EDGE_TYPES:
            raise ValueError(
                f"Geçersiz edge_type: '{value}'. "
                f"İzin verilen değerler: {sorted(EDGE_TYPES)}"
            )
        return cleaned


# ---------------------------------------------------------------------------
# StoryGraph
# ---------------------------------------------------------------------------

class StoryGraph(BaseModel):
    """
    AttackStory'den üretilen investigation graph.

    Attributes:
        id:         Benzersiz graph kimliği (UUID v4)
        story_id:   İlişkili AttackStory ID
        tenant_id:  Kiracı kimliği
        title:      Graph başlığı
        severity:   Ciddiyet seviyesi
        risk_score: Risk puanı (0-100)
        nodes:      Graph düğümleri
        edges:      Graph kenarları
        summary:    Özet istatistikler
        created_at: Oluşturulma zamanı (UTC ISO 8601)
        attributes: Serbest ek metadata
    """

    id: str = Field(default_factory=_generate_uuid)
    story_id: str = ""
    tenant_id: Optional[str] = None
    title: str = ""
    severity: str = "INFO"
    risk_score: int = 0
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utcnow_iso)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "from_attributes": True,
    }

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

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, value: int) -> int:
        return max(0, min(100, value))

    def to_dict(self) -> Dict[str, Any]:
        """Model verilerini sözlük olarak döndürür."""
        return self.model_dump()

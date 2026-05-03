"""
app.schemas.case_from_preview
================================
POST /api/cases/from-preview endpoint request / response şemaları.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from app.schemas.models import CaseResponse


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class CaseFromPreviewRequest(BaseModel):
    """Case-from-preview endpoint request body.

    Preview endpoint ile aynı payload yapısı — client aynı body'yi
    /preview veya /from-preview'a gönderebilir.
    """

    source_type: str
    items: List[Dict[str, Any]] = []
    include_graph: bool = True
    consolidate: bool = True


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class CaseFromPreviewSummary(BaseModel):
    """Response summary istatistikleri."""

    total_items: int = 0
    total_case_drafts: int = 0
    total_created_cases: int = 0
    total_linked_alerts: int = 0
    highest_severity: str = "INFO"
    max_risk_score: int = 0


class CaseFromPreviewResponse(BaseModel):
    """POST /api/cases/from-preview response body."""

    created_cases: List[CaseResponse] = []
    case_drafts: List[Dict[str, Any]] = []
    linked_alert_count: int = 0
    summary: CaseFromPreviewSummary = CaseFromPreviewSummary()
    warnings: List[str] = []

"""
app.api.routes_case_preview
==============================
Case Engine Preview API endpoint.

POST /api/cases/preview — CaseDraft preview

StoryPipeline + StoryGraphBuilder + CaseEngine pipeline'ını çalıştırarak
raw event / alert / command result / normalized event listelerinden
CaseDraft üretir. DB persistence yok — tamamen in-memory preview.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.security import get_current_tenant_id, require_role
from app.models.normalized_event import NormalizedSecurityEvent
from app.services.story_pipeline.pipeline import StoryPipeline
from app.services.story_graph.builder import StoryGraphBuilder
from app.services.case_engine.engine import CaseEngine
from app.services.story_graph.models import StoryGraph

logger = logging.getLogger("SolidTrace.CasePreviewAPI")
router = APIRouter(tags=["case_preview"])


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

SUPPORTED_SOURCE_TYPES = {
    "raw_events",
    "alerts",
    "command_results",
    "normalized_events",
}


# ---------------------------------------------------------------------------
# Request Schema
# ---------------------------------------------------------------------------

class CasePreviewRequest(BaseModel):
    """Case preview endpoint request body."""
    source_type: str
    items: List[Dict[str, Any]] = []
    include_graph: bool = True
    consolidate: bool = True


# ---------------------------------------------------------------------------
# Auth dependency (test override için modül seviyesinde)
# ---------------------------------------------------------------------------

_case_preview_auth = require_role("analyst")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/cases/preview")
async def case_preview(
    body: CasePreviewRequest,
    request: Request,
    current_user: str = Depends(_case_preview_auth),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    """
    Case Engine Preview endpoint.

    StoryPipeline ile AttackStory üretir, isteğe bağlı StoryGraph oluşturur,
    CaseEngine ile CaseDraft üretir. DB persistence yok.

    Args:
        body: CasePreviewRequest (source_type + items + include_graph + consolidate)
        request: FastAPI Request
        current_user: JWT'den (require_role analyst)
        tenant_id: JWT'den (get_current_tenant_id)

    Returns:
        case_drafts, attack_stories, story_graphs, summary, warnings
    """
    request_id = getattr(request.state, "request_id", "n/a")

    # Validate source_type
    if body.source_type not in SUPPORTED_SOURCE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Desteklenmeyen source_type: '{body.source_type}'. "
                f"İzin verilen değerler: {sorted(SUPPORTED_SOURCE_TYPES)}"
            ),
        )

    # Boş items → boş result
    if not body.items:
        logger.info(
            "case_preview empty_items request_id=%s user=%s tenant=%s source_type=%s",
            request_id, current_user, tenant_id, body.source_type,
        )
        return _empty_response()

    # Tenant fallback
    resolved_tenant = tenant_id if tenant_id else None

    # -----------------------------------------------------------------------
    # 1. StoryPipeline → AttackStory
    # -----------------------------------------------------------------------
    pipeline = StoryPipeline()
    warnings: List[str] = []

    if body.source_type == "raw_events":
        result = pipeline.build_from_raw_events(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "alerts":
        result = pipeline.build_from_alerts(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "command_results":
        result = pipeline.build_from_command_results(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "normalized_events":
        events, parse_warnings = _parse_normalized_events(body.items)
        result = pipeline.build_from_normalized_events(events)
        result.warnings = parse_warnings + result.warnings

    else:
        raise HTTPException(status_code=400, detail="Geçersiz source_type")

    warnings.extend(result.warnings)
    stories = result.attack_stories

    # -----------------------------------------------------------------------
    # 2. StoryGraphBuilder → StoryGraph (opsiyonel)
    # -----------------------------------------------------------------------
    story_graphs: List[StoryGraph] = []
    story_graph_dicts: List[Dict[str, Any]] = []

    if body.include_graph and stories:
        graph_builder = StoryGraphBuilder()
        for story in stories:
            try:
                graph = graph_builder.build(story)
                story_graphs.append(graph)
                story_graph_dicts.append(graph.to_dict())
            except Exception as exc:
                msg = f"Graph build hatası (story_id={story.id}): {exc}"
                warnings.append(msg)
                logger.warning("graph_build_error %s", msg)

    # -----------------------------------------------------------------------
    # 3. CaseEngine → CaseDraft
    # -----------------------------------------------------------------------
    engine = CaseEngine()
    case_draft_dicts: List[Dict[str, Any]] = []

    if stories:
        if body.consolidate:
            # build_batch: ilişkili story'leri gruplayıp consolidated case üretir
            case_drafts = engine.build_batch(
                stories,
                graphs=story_graphs if story_graphs else None,
            )
        else:
            # Her story → ayrı CaseDraft
            graph_map: Dict[str, StoryGraph] = {}
            for g in story_graphs:
                if g.story_id:
                    graph_map[g.story_id] = g

            case_drafts = []
            for story in stories:
                g = graph_map.get(story.id)
                case_drafts.append(engine.build_single(story, g))

        case_draft_dicts = [cd.to_dict() for cd in case_drafts]

    # -----------------------------------------------------------------------
    # 4. Response
    # -----------------------------------------------------------------------
    attack_story_dicts = [s.to_dict() for s in stories]

    # Summary
    all_hosts: List[str] = []
    all_users: List[str] = []
    max_risk = 0
    highest_severity = "INFO"
    severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for cd in case_draft_dicts:
        for h in cd.get("affected_hosts", []):
            if h not in all_hosts:
                all_hosts.append(h)
        for u in cd.get("affected_users", []):
            if u not in all_users:
                all_users.append(u)
        rs = cd.get("risk_score", 0)
        if rs > max_risk:
            max_risk = rs
        sev = cd.get("severity", "INFO")
        if severity_rank.get(sev, 0) > severity_rank.get(highest_severity, 0):
            highest_severity = sev

    summary = {
        "total_items": len(body.items),
        "total_stories": len(stories),
        "total_graphs": len(story_graph_dicts),
        "total_case_drafts": len(case_draft_dicts),
        "highest_severity": highest_severity,
        "max_risk_score": max_risk,
        "affected_hosts": all_hosts,
        "affected_users": all_users,
    }

    logger.info(
        "case_preview_complete request_id=%s user=%s tenant=%s "
        "source_type=%s stories=%d graphs=%d case_drafts=%d warnings=%d",
        request_id, current_user, tenant_id,
        body.source_type,
        len(stories), len(story_graph_dicts),
        len(case_draft_dicts), len(warnings),
    )

    return {
        "case_drafts": case_draft_dicts,
        "attack_stories": attack_story_dicts,
        "story_graphs": story_graph_dicts,
        "summary": summary,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_response() -> Dict[str, Any]:
    """Boş input için güvenli boş response."""
    return {
        "case_drafts": [],
        "attack_stories": [],
        "story_graphs": [],
        "summary": {
            "total_items": 0,
            "total_stories": 0,
            "total_graphs": 0,
            "total_case_drafts": 0,
            "highest_severity": "INFO",
            "max_risk_score": 0,
            "affected_hosts": [],
            "affected_users": [],
        },
        "warnings": [],
    }


def _parse_normalized_events(
    items: List[Dict[str, Any]],
) -> tuple:
    """
    Dict listesinden NormalizedSecurityEvent oluşturur.
    Hatalı item'lar warning listesine eklenir, atlanır.
    """
    events: List[NormalizedSecurityEvent] = []
    warnings: List[str] = []

    for idx, item in enumerate(items):
        try:
            event = NormalizedSecurityEvent(**item)
            events.append(event)
        except Exception as exc:
            msg = f"NormalizedSecurityEvent parse hatası (index={idx}): {exc}"
            warnings.append(msg)
            logger.warning("normalized_event_parse_error %s", msg)

    return events, warnings

"""
app.api.routes_story
======================
Story Preview API endpoints.

POST /api/story/preview       — AttackStory preview
POST /api/story/graph-preview — AttackStory + StoryGraph preview

StoryPipeline servisini çağırarak raw event / alert / command result /
normalized event listelerinden AttackStory (ve opsiyonel StoryGraph)
üretir. DB persistence yok — tamamen in-memory preview.
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

logger = logging.getLogger("SolidTrace.StoryAPI")
router = APIRouter(tags=["story"])


# ---------------------------------------------------------------------------
# Request Schema
# ---------------------------------------------------------------------------

SUPPORTED_SOURCE_TYPES = {
    "raw_events",
    "alerts",
    "command_results",
    "normalized_events",
}


class StoryPreviewRequest(BaseModel):
    """Story preview endpoint request body."""
    source_type: str
    items: List[Dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Auth dependency referansları (test override için modül seviyesinde)
# ---------------------------------------------------------------------------

_auth_dependency = require_role("analyst")
_graph_auth_dependency = require_role("analyst")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/story/preview")
async def story_preview(
    body: StoryPreviewRequest,
    request: Request,
    current_user: str = Depends(_auth_dependency),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    """
    Story Pipeline preview endpoint.

    source_type'a göre StoryPipeline metodunu çağırır ve
    StoryPipelineResult döndürür. DB persistence yok.

    Args:
        body: StoryPreviewRequest (source_type + items)
        request: FastAPI Request
        current_user: JWT'den (require_role analyst)
        tenant_id: JWT'den (get_current_tenant_id)

    Returns:
        StoryPipelineResult dict
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
            "story_preview empty_items request_id=%s user=%s tenant=%s source_type=%s",
            request_id, current_user, tenant_id, body.source_type,
        )
        pipeline = StoryPipeline()
        empty_result = pipeline._empty_result()
        return empty_result.model_dump()

    # Tenant fallback
    resolved_tenant = tenant_id if tenant_id else None

    pipeline = StoryPipeline()

    # Dispatch
    if body.source_type == "raw_events":
        result = pipeline.build_from_raw_events(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "alerts":
        result = pipeline.build_from_alerts(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "command_results":
        result = pipeline.build_from_command_results(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "normalized_events":
        events, warnings = _parse_normalized_events(body.items)
        result = pipeline.build_from_normalized_events(events)
        # Parsing warning'lerini ekle
        result.warnings = warnings + result.warnings

    else:
        # Bu noktaya ulaşılmamalı ama güvenlik için
        raise HTTPException(status_code=400, detail="Geçersiz source_type")

    logger.info(
        "story_preview_complete request_id=%s user=%s tenant=%s "
        "source_type=%s events=%d groups=%d stories=%d warnings=%d",
        request_id, current_user, tenant_id,
        body.source_type,
        len(result.normalized_events),
        len(result.correlation_groups),
        len(result.attack_stories),
        len(result.warnings),
    )

    return result.model_dump()


# ---------------------------------------------------------------------------
# Graph Preview Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/story/graph-preview")
async def story_graph_preview(
    body: StoryPreviewRequest,
    request: Request,
    current_user: str = Depends(_graph_auth_dependency),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    """
    Story Pipeline + Graph Builder preview endpoint.

    StoryPipeline ile AttackStory üretir, ardından her story için
    StoryGraphBuilder ile investigation graph oluşturur.
    DB persistence yok.

    Args:
        body: StoryPreviewRequest (source_type + items)
        request: FastAPI Request
        current_user: JWT'den (require_role analyst)
        tenant_id: JWT'den (get_current_tenant_id)

    Returns:
        StoryPipelineResult + story_graphs dict
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
            "story_graph_preview empty_items request_id=%s user=%s tenant=%s source_type=%s",
            request_id, current_user, tenant_id, body.source_type,
        )
        pipeline = StoryPipeline()
        empty_result = pipeline._empty_result()
        response = empty_result.model_dump()
        response["story_graphs"] = []
        response["summary"]["graph_count"] = 0
        response["summary"]["total_nodes"] = 0
        response["summary"]["total_edges"] = 0
        return response

    # Tenant fallback
    resolved_tenant = tenant_id if tenant_id else None

    pipeline = StoryPipeline()

    # Dispatch
    if body.source_type == "raw_events":
        result = pipeline.build_from_raw_events(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "alerts":
        result = pipeline.build_from_alerts(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "command_results":
        result = pipeline.build_from_command_results(body.items, tenant_id=resolved_tenant)

    elif body.source_type == "normalized_events":
        events, warnings = _parse_normalized_events(body.items)
        result = pipeline.build_from_normalized_events(events)
        result.warnings = warnings + result.warnings

    else:
        raise HTTPException(status_code=400, detail="Geçersiz source_type")

    # Graph build
    graph_builder = StoryGraphBuilder()
    story_graphs: List[Dict[str, Any]] = []

    for story in result.attack_stories:
        try:
            graph = graph_builder.build(story)
            story_graphs.append(graph.to_dict())
        except Exception as exc:
            msg = f"Graph build hatası (story_id={story.id}): {exc}"
            result.warnings.append(msg)
            logger.warning("graph_build_error %s", msg)

    # Response oluştur
    response = result.model_dump()
    response["story_graphs"] = story_graphs

    # Summary zenginleştirme
    response["summary"]["graph_count"] = len(story_graphs)
    response["summary"]["total_nodes"] = sum(
        g.get("summary", {}).get("node_count", 0) for g in story_graphs
    )
    response["summary"]["total_edges"] = sum(
        g.get("summary", {}).get("edge_count", 0) for g in story_graphs
    )

    logger.info(
        "story_graph_preview_complete request_id=%s user=%s tenant=%s "
        "source_type=%s events=%d groups=%d stories=%d graphs=%d warnings=%d",
        request_id, current_user, tenant_id,
        body.source_type,
        len(result.normalized_events),
        len(result.correlation_groups),
        len(result.attack_stories),
        len(story_graphs),
        len(result.warnings),
    )

    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

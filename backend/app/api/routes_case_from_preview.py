"""
app.api.routes_case_from_preview
===================================
Case Persistence MVP endpoint.

POST /api/cases/from-preview

Preview pipeline'ı (StoryPipeline + StoryGraphBuilder + CaseEngine)
çalıştırıp üretilen CaseDraft'ları gerçek DB-backed Case kayıtlarına
dönüştürür.

İş akışı:
  1. Request validation (source_type + items)
  2. StoryPipeline → AttackStory
  3. StoryGraphBuilder → StoryGraph (opsiyonel)
  4. CaseEngine.build_batch → CaseDraft listesi
  5. Her CaseDraft → case_service.create_case (DB persist)
  6. related_alert_ids → link_alert_to_case (DB link)
  7. Audit log (best-effort)
  8. Response döndür
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.security import get_current_tenant_id, require_role
from app.database.db_manager import SessionLocal, write_audit
from app.models.normalized_event import NormalizedSecurityEvent
from app.schemas.case_from_preview import (
    CaseFromPreviewRequest,
    CaseFromPreviewResponse,
    CaseFromPreviewSummary,
)
from app.services.case_engine.engine import CaseEngine
from app.services.case_engine.models import CaseDraft, SEVERITY_ORDER
from app.services.case_service import create_case, get_case_detail, link_alert_to_case
from app.services.story_graph.builder import StoryGraphBuilder
from app.services.story_graph.models import StoryGraph
from app.services.story_pipeline.pipeline import StoryPipeline

logger = logging.getLogger("SolidTrace.CaseFromPreviewAPI")
router = APIRouter(tags=["case_from_preview"])


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
# Auth dependency (test override için modül seviyesinde)
# ---------------------------------------------------------------------------

_from_preview_auth = require_role("analyst")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/cases/from-preview", response_model=CaseFromPreviewResponse)
async def case_from_preview(
    body: CaseFromPreviewRequest,
    request: Request,
    current_user: str = Depends(_from_preview_auth),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    """
    Case Persistence MVP endpoint.

    Preview pipeline'ı çalıştırır, CaseDraft'ları DB'ye kaydeder,
    related_alert_ids'i linkler, audit log yazar.

    Args:
        body: CaseFromPreviewRequest (source_type + items + include_graph + consolidate)
        request: FastAPI Request
        current_user: JWT'den (require_role analyst)
        tenant_id: JWT'den (get_current_tenant_id)

    Returns:
        CaseFromPreviewResponse: created_cases, case_drafts, linked_alert_count, summary, warnings
    """
    request_id = getattr(request.state, "request_id", "n/a")

    # -- 1. Validation -------------------------------------------------------

    if body.source_type not in SUPPORTED_SOURCE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Desteklenmeyen source_type: '{body.source_type}'. "
                f"İzin verilen değerler: {sorted(SUPPORTED_SOURCE_TYPES)}"
            ),
        )

    if not body.items:
        raise HTTPException(
            status_code=400,
            detail="Case oluşturmak için en az bir item gerekli",
        )

    resolved_tenant = tenant_id if tenant_id else None

    # -- 2. StoryPipeline → AttackStory ---------------------------------------

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

    # -- 3. StoryGraphBuilder → StoryGraph (opsiyonel) ------------------------

    story_graphs: List[StoryGraph] = []

    if body.include_graph and stories:
        graph_builder = StoryGraphBuilder()
        for story in stories:
            try:
                graph = graph_builder.build(story)
                story_graphs.append(graph)
            except Exception as exc:
                msg = f"Graph build hatası (story_id={story.id}): {exc}"
                warnings.append(msg)
                logger.warning("graph_build_error %s", msg)

    # -- 4. CaseEngine → CaseDraft -------------------------------------------

    engine = CaseEngine()
    case_drafts: List[CaseDraft] = []

    if stories:
        if body.consolidate:
            case_drafts = engine.build_batch(
                stories,
                graphs=story_graphs if story_graphs else None,
            )
        else:
            graph_map: Dict[str, StoryGraph] = {}
            for g in story_graphs:
                if g.story_id:
                    graph_map[g.story_id] = g

            for story in stories:
                g = graph_map.get(story.id)
                case_drafts.append(engine.build_single(story, g))

    case_draft_dicts = [cd.to_dict() for cd in case_drafts]

    if not case_drafts:
        raise HTTPException(
            status_code=422,
            detail="CaseDraft üretilemedi: pipeline sonucu boş",
        )

    # -- 5. DB Persistence ----------------------------------------------------

    db = SessionLocal()
    created_cases: List[Dict[str, Any]] = []
    total_linked_alerts = 0

    try:
        for cd in case_drafts:
            # 5a. Case oluştur
            new_case = create_case(
                db,
                tenant_id=resolved_tenant,
                title=cd.title or "Security Case",
                description=cd.summary or None,
                severity=(cd.severity or "INFO").upper(),
                owner=current_user,
            )

            # 5b. Alert linkleme
            linked_count = 0
            for alert_id in cd.related_alert_ids:
                try:
                    link_result = link_alert_to_case(
                        db,
                        case_id=new_case.id,
                        alert_id=alert_id,
                        tenant_id=resolved_tenant,
                    )
                    if link_result:
                        linked_count += 1
                    else:
                        warnings.append(
                            f"Alert linklenemedi: {alert_id} (DB'de bulunamadı)"
                        )
                except Exception as exc:
                    warnings.append(
                        f"Alert linkleme hatası ({alert_id}): {exc}"
                    )
                    logger.warning("alert_link_error alert_id=%s: %s", alert_id, exc)

            total_linked_alerts += linked_count

            # Case detail formatında response'a ekle
            case_payload = get_case_detail(
                db, case_id=new_case.id, tenant_id=resolved_tenant
            )
            if case_payload:
                created_cases.append(case_payload)
            else:
                # Fallback: minimal response
                created_cases.append({
                    "id": new_case.id,
                    "tenant_id": new_case.tenant_id,
                    "title": new_case.title,
                    "description": new_case.description,
                    "status": new_case.status,
                    "severity": new_case.severity,
                    "owner": new_case.owner,
                    "analyst_note": new_case.analyst_note,
                    "created_at": new_case.created_at,
                    "updated_at": new_case.updated_at,
                    "closed_at": new_case.closed_at,
                    "related_alert_count": linked_count,
                    "related_alerts": [],
                })

            logger.info(
                "case_created_from_preview request_id=%s user=%s tenant=%s "
                "case_id=%s draft_id=%s linked_alerts=%d",
                request_id, current_user, resolved_tenant,
                new_case.id, cd.id, linked_count,
            )

    except HTTPException:
        db.close()
        raise
    except Exception as exc:
        logger.error(
            "case_from_preview_db_error request_id=%s: %s",
            request_id, exc,
        )
        try:
            db.rollback()
        except Exception:
            pass
        db.close()
        raise HTTPException(
            status_code=500,
            detail="Case oluşturma sırasında veritabanı hatası",
        )

    # -- 6. Audit log (best-effort) -------------------------------------------

    try:
        for idx, cd in enumerate(case_drafts):
            if idx < len(created_cases):
                case_id = created_cases[idx].get("id", "unknown")
                detail_parts = [
                    f"draft_id={cd.id}",
                    f"severity={cd.severity}",
                    f"risk_score={cd.risk_score}",
                ]
                if cd.affected_hosts:
                    detail_parts.append(f"hosts={','.join(cd.affected_hosts[:5])}")
                if cd.tactics:
                    detail_parts.append(f"tactics={','.join(cd.tactics[:5])}")
                if cd.tags:
                    detail_parts.append(f"tags={','.join(cd.tags[:5])}")

                await write_audit(
                    db,
                    username=current_user,
                    action="create_case_from_preview",
                    target=case_id,
                    detail="; ".join(detail_parts),
                    ip=getattr(request.client, "host", "") if request.client else "",
                    result="SUCCESS",
                    tenant_id=resolved_tenant,
                )
    except Exception as exc:
        logger.warning(
            "audit_log_error request_id=%s: %s (case creation başarılı, audit yazılamadı)",
            request_id, exc,
        )
        warnings.append("Audit log yazılamadı (case oluşturma başarılı)")

    db.close()

    # -- 7. Summary -----------------------------------------------------------

    highest_severity = "INFO"
    max_risk = 0

    for cd_dict in case_draft_dicts:
        sev = cd_dict.get("severity", "INFO")
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(highest_severity, 0):
            highest_severity = sev
        rs = cd_dict.get("risk_score", 0)
        if rs > max_risk:
            max_risk = rs

    summary = CaseFromPreviewSummary(
        total_items=len(body.items),
        total_case_drafts=len(case_draft_dicts),
        total_created_cases=len(created_cases),
        total_linked_alerts=total_linked_alerts,
        highest_severity=highest_severity,
        max_risk_score=max_risk,
    )

    logger.info(
        "case_from_preview_complete request_id=%s user=%s tenant=%s "
        "source_type=%s created_cases=%d linked_alerts=%d warnings=%d",
        request_id, current_user, resolved_tenant,
        body.source_type,
        len(created_cases), total_linked_alerts, len(warnings),
    )

    return CaseFromPreviewResponse(
        created_cases=created_cases,
        case_drafts=case_draft_dicts,
        linked_alert_count=total_linked_alerts,
        summary=summary,
        warnings=warnings,
    )


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

"""
app.api.routes_ueba
===================
UEBA profil ve görünürlük endpoint'leri.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy import desc

from app.core.security import get_current_tenant_id, require_role
from app.database.db_manager import AgentModel, AlertModel, SessionLocal
from app.schemas.models import UEBAProfileItem, UEBAProfilesResponse

logger = logging.getLogger("SolidTrace.UEBA")
router = APIRouter(tags=["ueba"])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")


def _alert_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AlertModel)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)
    return query


def _agent_query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AgentModel)
    if tenant_id and hasattr(AgentModel, "tenant_id"):
        query = query.filter(AgentModel.tenant_id == tenant_id)
    return query


@router.get("/api/v1/ueba/profiles", response_model=UEBAProfilesResponse)
async def ueba_profiles(
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = _alert_query_for_tenant(db, tenant_id).order_by(desc(AlertModel.created_at)).limit(1500).all()
        agents = _agent_query_for_tenant(db, tenant_id).order_by(desc(AgentModel.last_seen)).all()

        user_scores: dict[str, dict] = {}
        host_scores: dict[str, dict] = {}

        for alert in alerts:
            username = (alert.username or "").strip()
            hostname = (alert.hostname or "").strip()
            risk_score = int(alert.risk_score or 0)

            if username:
                item = user_scores.setdefault(
                    username,
                    {"entity_name": username, "entity_type": "user", "risk_score": 0, "alert_count": 0, "last_seen": None},
                )
                item["risk_score"] = max(item["risk_score"], risk_score)
                item["alert_count"] += 1
                item["last_seen"] = max(item["last_seen"] or "", alert.created_at or "")

            if hostname:
                item = host_scores.setdefault(
                    hostname,
                    {"entity_name": hostname, "entity_type": "host", "risk_score": 0, "alert_count": 0, "last_seen": None},
                )
                item["risk_score"] = max(item["risk_score"], risk_score)
                item["alert_count"] += 1
                item["last_seen"] = max(item["last_seen"] or "", alert.created_at or "")

        profiles: list[UEBAProfileItem] = []

        for item in user_scores.values():
            profiles.append(
                UEBAProfileItem(
                    entity_name=item["entity_name"],
                    entity_type="user",
                    risk_score=item["risk_score"],
                    alert_count=item["alert_count"],
                    last_seen=item["last_seen"],
                )
            )

        for item in host_scores.values():
            profiles.append(
                UEBAProfileItem(
                    entity_name=item["entity_name"],
                    entity_type="host",
                    risk_score=item["risk_score"],
                    alert_count=item["alert_count"],
                    last_seen=item["last_seen"],
                )
            )

        profiles.sort(key=lambda x: (x.risk_score, x.alert_count, x.last_seen or ""), reverse=True)
        profiles = profiles[:25]

        risky_profiles = sum(1 for p in profiles if p.risk_score >= 70)
        baseline_ready = len(agents) >= 3 or len(alerts) >= 20

        logger.info(
            "ueba_profiles_requested request_id=%s tenant=%s user=%s profile_count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            len(profiles),
        )

        return UEBAProfilesResponse(
            profile_count=len(profiles),
            risky_profile_count=risky_profiles,
            baseline_ready=baseline_ready,
            last_profile_update_at=utcnow().isoformat(),
            profiles=profiles,
            note="Gerçek UEBA motoru tam entegre değilse profiller mevcut alert/agent verisinden türetilir.",
        )
    finally:
        db.close()
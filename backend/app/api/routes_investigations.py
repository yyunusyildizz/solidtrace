"""
app.api.routes_investigations
=============================
Investigation, campaign, incident and timeline endpoints.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, or_

from app.core.security import get_current_user, get_current_tenant_id
from app.database.db_manager import SessionLocal, AlertModel
from app.schemas.models import (
    AlertResponse,
    InvestigationQueueItem,
    InvestigationGraphResponse,
    InvestigationCampaignListResponse,
    GlobalCampaignListResponse,
    GlobalCampaignEscalationResponse,
    GlobalCampaignResponsePlan,
    IncidentCreateFromCampaignResponse,
    IncidentListResponse,
    IncidentAlertListResponse,
    IncidentResponse,
    IncidentStatusUpdateRequest,
    IncidentAssignRequest,
    IncidentNoteUpdateRequest,
    IncidentTimelineResponse,
    IncidentGraphResponse,
    IncidentAttackChainResponse,
    IncidentResponsePlanResponse,
    IncidentExecutionResult,
)
from app.services.incident_service import (
    upsert_incident_from_campaign,
    list_incidents,
    get_incident_by_id,
    update_incident_status,
    assign_incident,
    update_incident_note,
    list_incident_timeline,
    get_incident_alerts,
    get_incident_graph,
    get_incident_attack_chain,
    get_incident_response_plan,
    execute_incident_response,
    summarize_alert_group,
)

router = APIRouter(tags=["investigations"])


def _query_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(AlertModel)
    if tenant_id and hasattr(AlertModel, "tenant_id"):
        query = query.filter(AlertModel.tenant_id == tenant_id)
    return query


def _to_alert_response(alert: AlertModel) -> AlertResponse:
    return AlertResponse(
        id=str(alert.id),
        created_at=str(alert.created_at or ""),
        hostname=getattr(alert, "hostname", None),
        username=getattr(alert, "username", None),
        type=getattr(alert, "type", None),
        risk_score=int(getattr(alert, "risk_score", 0) or 0),
        rule=getattr(alert, "rule", None),
        severity=getattr(alert, "severity", None),
        details=getattr(alert, "details", None),
        command_line=getattr(alert, "command_line", None),
        pid=getattr(alert, "pid", None),
        serial=getattr(alert, "serial", None),
        tenant_id=getattr(alert, "tenant_id", None),
        status=getattr(alert, "status", "open"),
        analyst_note=getattr(alert, "analyst_note", None),
        resolved_at=getattr(alert, "resolved_at", None),
        resolved_by=getattr(alert, "resolved_by", None),
        assigned_to=getattr(alert, "assigned_to", None),
        assigned_at=getattr(alert, "assigned_at", None),
    )


def _severity_rank(severity: Optional[str]) -> int:
    sev = (severity or "INFO").upper()
    order = {"CRITICAL": 4, "HIGH": 3, "WARNING": 2, "INFO": 1}
    return order.get(sev, 0)


def _severity_max(a: Optional[str], b: Optional[str]) -> str:
    return a if _severity_rank(a) >= _severity_rank(b) else (b or a or "INFO")


def _normalize_campaign_family(rule: str, hostname: str, username: str, alert=None) -> tuple[str, str]:
    hay = " ".join([
        rule or "",
        str(getattr(alert, "details", "") or ""),
        str(getattr(alert, "command_line", "") or ""),
    ]).lower()

    if any(k in hay for k in ["mimikatz", "credential dumping", "credential dump", "sekurlsa", "lsass"]):
        return "credential_access", "high"
    if any(k in hay for k in ["powershell", "invoke-webrequest", "download cradle", "execution cradle"]):
        return "malicious_execution", "medium"
    if any(k in hay for k in ["ransomware", "encrypt", "shadow copy", "vssadmin"]):
        return "impact_ransomware", "high"
    if any(k in hay for k in ["usb", "removable", "mass storage"]):
        return "usb_activity", "medium"
    if any(k in hay for k in ["persistence", "autorun", "run key", "scheduled task", "startup"]):
        return "persistence", "medium"
    return "generic_activity", "low"


def _campaign_confidence_from_score(score: float) -> str:
    if score >= 85:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _build_spread_paths(alerts):
    alerts = sorted(alerts, key=lambda x: getattr(x, "created_at", ""))
    spread_edges = []
    visited_hosts = []
    last_host = None
    for alert in alerts:
        host = str(getattr(alert, "hostname", "") or "").strip()
        if not host or host in {"unknown-host", "string"}:
            continue
        if last_host and host != last_host:
            edge = f"{last_host} → {host}"
            if edge not in spread_edges:
                spread_edges.append(edge)
        last_host = host
        if host not in visited_hosts:
            visited_hosts.append(host)
    return {
        "spread_path": spread_edges,
        "visited_hosts": visited_hosts,
        "spread_depth": len(visited_hosts),
    }


def _escalate_campaign(*, campaign_family: str, total_events: int, spread_depth: int, affected_hosts: list[str]) -> dict:
    reasons: list[str] = []
    score = 0
    host_count = len(affected_hosts)

    if campaign_family == "credential_access":
        score += 45
        reasons.append("credential_access detected")
        if spread_depth >= 3:
            score += 25
            reasons.append(f"spread_depth={spread_depth}")
        if host_count >= 3:
            score += 20
            reasons.append("multi_host_compromise suspected")
        if total_events >= 50:
            score += 10
            reasons.append(f"high_event_volume={total_events}")
    elif campaign_family == "impact_ransomware":
        score += 50
        reasons.append("ransomware-like impact detected")
        if host_count >= 2:
            score += 30
            reasons.append("multiple hosts affected")
        if spread_depth >= 2:
            score += 10
            reasons.append(f"spread_depth={spread_depth}")
    elif campaign_family == "usb_activity":
        score += 20
        reasons.append("usb activity detected")
        if total_events >= 25:
            score += 15
            reasons.append(f"repeated_usb_activity={total_events}")
        if host_count >= 2:
            score += 15
            reasons.append("usb activity across multiple hosts")
    elif campaign_family == "malicious_execution":
        score += 20
        reasons.append("suspicious execution pattern detected")
        if spread_depth >= 2:
            score += 15
            reasons.append(f"spread_depth={spread_depth}")
        if total_events >= 100:
            score += 15
            reasons.append(f"large_execution_volume={total_events}")
    elif campaign_family == "persistence":
        score += 20
        reasons.append("persistence behavior detected")
        if total_events >= 5:
            score += 10
            reasons.append(f"persistent_recurrence={total_events}")
    else:
        score += 5
        reasons.append("generic campaign activity")

    score = min(score, 100)
    if score >= 85:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "WARNING"
    else:
        severity = "INFO"
    return {
        "recommended_severity": severity,
        "incident_priority": score,
        "escalation_reasons": reasons,
    }


def _build_response_plan(*, campaign_family: str, severity: str, spread_depth: int, affected_hosts: list[str], total_events: int, user: str) -> dict:
    actions: list[str] = []
    playbook = None
    auto_incident = severity == "CRITICAL"

    if campaign_family == "credential_access":
        playbook = "credential_access_multi_host"
        actions.extend([
            "isolate affected hosts",
            "disable suspected user account",
            "collect LSASS memory",
            "block suspicious processes",
            "force password reset",
        ])
        if spread_depth >= 5:
            actions.append("investigate lateral movement")
    elif campaign_family == "impact_ransomware":
        playbook = "ransomware_containment"
        actions.extend([
            "isolate all affected hosts immediately",
            "disable network shares",
            "block encryption processes",
            "initiate incident response plan",
        ])
    elif campaign_family == "usb_activity":
        playbook = "usb_exfiltration_investigation"
        actions.extend([
            "audit USB device usage",
            "block unauthorized USB devices",
            "review data transfer logs",
        ])
    elif campaign_family == "malicious_execution":
        playbook = "suspicious_execution_analysis"
        actions.extend([
            "inspect process tree",
            "block suspicious command lines",
            "review execution source",
        ])
    else:
        playbook = "generic_investigation"
        actions.append("review related alerts")

    actions = list(dict.fromkeys(actions))
    return {
        "auto_incident": auto_incident,
        "incident_title": f"{campaign_family} campaign detected for user {user}",
        "playbook": playbook,
        "recommended_actions": actions,
    }


def _extract_attack_path(nodes: list[dict], edges: list[dict]) -> dict:
    incoming = {n["id"]: 0 for n in nodes}
    outgoing = {n["id"]: 0 for n in nodes}
    node_types = {n["id"]: n.get("type") for n in nodes}
    for edge in edges:
        src = edge.get("from")
        dst = edge.get("to")
        if src in outgoing:
            outgoing[src] += 1
        if dst in incoming:
            incoming[dst] += 1
    entry_nodes = [nid for nid, count in incoming.items() if count == 0]
    impact_nodes = [nid for nid, typ in node_types.items() if typ == "alert"]
    pivot_nodes = [nid for nid in incoming.keys() if incoming[nid] > 0 and outgoing[nid] > 0]

    primary_path = []
    current = entry_nodes[0] if entry_nodes else (nodes[0]["id"] if nodes else None)
    visited = set()
    while current and current not in visited:
        visited.add(current)
        primary_path.append(current)
        next_nodes = [e["to"] for e in edges if e.get("from") == current]
        current = next_nodes[0] if next_nodes else None

    return {
        "entry_nodes": entry_nodes[:5],
        "pivot_nodes": pivot_nodes[:10],
        "impact_nodes": impact_nodes[:10],
        "primary_attack_path": primary_path[:20],
    }


def _infer_kill_chain(nodes: list[dict], primary_attack_path: list[str]) -> list[str]:
    node_map = {n["id"]: n for n in nodes}
    phases: list[str] = []
    for node_id in primary_attack_path:
        node = node_map.get(node_id)
        if not node:
            continue
        node_type = node.get("type")
        label = (node.get("label") or "").lower()
        if node_type == "user":
            phase = "Initial Access"
        elif node_type == "process":
            phase = "Execution"
        elif node_type == "rule":
            if any(k in label for k in ["credential", "dumping", "mimikatz"]):
                phase = "Credential Access"
            elif any(k in label for k in ["lateral", "psexec", "remote"]):
                phase = "Lateral Movement"
            elif any(k in label for k in ["ransomware", "encrypt", "impact"]):
                phase = "Impact"
            else:
                phase = "Detection"
        elif node_type == "alert":
            phase = "Detection"
        elif node_type == "host":
            phase = "Impact"
        else:
            phase = "Unknown"
        if phase not in phases:
            phases.append(phase)
    return phases


@router.get("/api/investigations")
async def get_investigations(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        rows = (
            _query_for_tenant(db, tenant_id)
            .order_by(desc(AlertModel.created_at), desc(AlertModel.risk_score))
            .limit(limit)
            .all()
        )
        items = []
        for row in rows:
            items.append(
                InvestigationQueueItem(
                    id=f"INV-{row.id}",
                    alert_id=str(row.id),
                    title=str(getattr(row, "rule", None) or getattr(row, "type", "Investigation")),
                    severity=getattr(row, "severity", None),
                    status=getattr(row, "status", "open"),
                    owner=getattr(row, "assigned_to", None) or "Unassigned",
                    created_at=str(getattr(row, "created_at", "") or ""),
                    updated_at=str(getattr(row, "created_at", "") or ""),
                    related_alerts=1,
                    affected_host=getattr(row, "hostname", None),
                    username=getattr(row, "username", None),
                    rule=getattr(row, "rule", None),
                    risk_score=int(getattr(row, "risk_score", 0) or 0),
                    summary=getattr(row, "details", None),
                    tags=[],
                )
            )
        return items
    finally:
        db.close()


@router.get("/api/investigations/campaigns", response_model=InvestigationCampaignListResponse)
async def get_investigation_campaigns(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = (
            _query_for_tenant(db, tenant_id)
            .order_by(desc(AlertModel.risk_score), desc(AlertModel.created_at))
            .limit(5000)
            .all()
        )
        grouped: dict[str, dict] = {}
        for alert in alerts:
            hostname = str(getattr(alert, "hostname", "") or "")
            username = str(getattr(alert, "username", "") or "").lower() or "unknown-user"
            rule = str(getattr(alert, "rule", "") or "")
            normalized_family, family_confidence = _normalize_campaign_family(rule, hostname, username, alert)
            key = f"{normalized_family}:{username}:{hostname.lower() or 'unknown-host'}"
            severity = str(getattr(alert, "severity", "INFO") or "INFO").upper()
            risk = int(getattr(alert, "risk_score", 0) or 0)
            created_at = str(getattr(alert, "created_at", "") or "")
            if key not in grouped:
                grouped[key] = {
                    "campaign_key": key,
                    "campaign_score": 0.0,
                    "campaign_confidence": "low",
                    "investigation_count": 0,
                    "top_severity": severity,
                    "normalized_family": normalized_family,
                    "family_confidence": family_confidence,
                    "hosts": set(),
                    "users": set(),
                    "rules": set(),
                    "sample_investigation_ids": [],
                    "latest_seen": created_at,
                    "risk_scores": [],
                }
            row = grouped[key]
            if family_confidence == "high":
                row["family_confidence"] = "high"
            elif family_confidence == "medium" and row["family_confidence"] != "high":
                row["family_confidence"] = "medium"
            row["investigation_count"] += 1
            row["top_severity"] = _severity_max(row["top_severity"], severity)
            if hostname:
                row["hosts"].add(hostname)
            if username and username != "unknown-user":
                row["users"].add(username)
            if rule:
                row["rules"].add(rule)
            row["risk_scores"].append(risk)
            if len(row["sample_investigation_ids"]) < 10:
                row["sample_investigation_ids"].append(f"INV-{alert.id}")
            if created_at > (row["latest_seen"] or ""):
                row["latest_seen"] = created_at

        items = []
        for row in grouped.values():
            if row["normalized_family"] == "generic_activity" and row["investigation_count"] > 100:
                continue
            avg_risk = sum(row["risk_scores"]) / len(row["risk_scores"]) if row["risk_scores"] else 0
            count_bonus = 25.0 if row["investigation_count"] >= 100 else 15.0 if row["investigation_count"] >= 25 else 10.0 if row["investigation_count"] >= 10 else 5.0 if row["investigation_count"] >= 3 else 0.0
            sev_bonus = {"CRITICAL": 15.0, "HIGH": 10.0, "WARNING": 5.0, "INFO": 0.0}.get(row["top_severity"], 0.0)
            campaign_score = round(min(avg_risk + count_bonus + sev_bonus, 100.0), 1)
            row["campaign_score"] = campaign_score
            row["campaign_confidence"] = _campaign_confidence_from_score(campaign_score)
            row["hosts"] = [h for h in sorted(row["hosts"]) if h and h != "unknown-host" and h != "string"][:10]
            row["users"] = sorted(row["users"])[:10]
            row["rules"] = sorted(row["rules"])[:10]
            row.pop("risk_scores", None)
            items.append(row)

        items.sort(key=lambda x: (x["campaign_score"], _severity_rank(x["top_severity"]), x["investigation_count"], x["latest_seen"] or ""), reverse=True)
        return {"total_campaigns": len(items[:limit]), "items": items[:limit]}
    finally:
        db.close()


def _global_campaign_key(alert) -> tuple[str, str]:
    rule = str(getattr(alert, "rule", "") or "unknown-rule")
    username = str(getattr(alert, "username", "") or "unknown-user").lower()
    family, _ = _normalize_campaign_family(rule=rule, hostname="", username=username, alert=alert)
    return family, username


@router.get("/api/investigations/campaigns/global", response_model=GlobalCampaignListResponse)
async def get_global_campaigns(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = (
            _query_for_tenant(db, tenant_id)
            .order_by(desc(AlertModel.risk_score), desc(AlertModel.created_at))
            .limit(5000)
            .all()
        )
        grouped: dict[tuple[str, str], dict] = {}
        for alert in alerts:
            family, user = _global_campaign_key(alert)
            key = (family, user)
            severity = str(getattr(alert, "severity", "INFO") or "INFO").upper()
            hostname = str(getattr(alert, "hostname", "") or "")
            risk = int(getattr(alert, "risk_score", 0) or 0)
            created_at = str(getattr(alert, "created_at", "") or "")
            if key not in grouped:
                grouped[key] = {
                    "campaign_family": family,
                    "user": user,
                    "campaign_score": 0.0,
                    "campaign_confidence": "low",
                    "total_events": 0,
                    "affected_hosts": set(),
                    "top_severity": severity,
                    "risk_scores": [],
                    "sample_investigation_ids": [],
                    "latest_seen": created_at,
                }
            row = grouped[key]
            row["total_events"] += 1
            if hostname:
                row["affected_hosts"].add(hostname)
            row["top_severity"] = _severity_max(row["top_severity"], severity)
            row["risk_scores"].append(risk)
            if len(row["sample_investigation_ids"]) < 10:
                row["sample_investigation_ids"].append(f"INV-{alert.id}")
            if created_at > (row["latest_seen"] or ""):
                row["latest_seen"] = created_at

        items = []
        for row in grouped.values():
            if row["campaign_family"] == "generic_activity" and row["total_events"] > 100:
                continue
            avg_risk = sum(row["risk_scores"]) / len(row["risk_scores"]) if row["risk_scores"] else 0
            spread_bonus = min(len(row["affected_hosts"]) * 5, 30)
            score = min(avg_risk + spread_bonus, 100)
            row["campaign_score"] = round(score, 1)
            row["campaign_confidence"] = _campaign_confidence_from_score(score)
            row["affected_hosts"] = [h for h in row["affected_hosts"] if h and h != "unknown-host" and h != "string"][:20]
            row.pop("risk_scores", None)
            items.append(row)

        items.sort(key=lambda x: (x["campaign_score"], _severity_rank(x["top_severity"]), x["total_events"]), reverse=True)
        return {"total_campaigns": len(items[:limit]), "items": items[:limit]}
    finally:
        db.close()


@router.get("/api/investigations/campaigns/global/spread")
async def get_global_campaign_spread(
    campaign_family: str,
    user: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = _query_for_tenant(db, tenant_id).all()
        filtered = []
        for alert in alerts:
            family, username = _global_campaign_key(alert)
            if family == campaign_family and username == user:
                filtered.append(alert)

        if not filtered:
            return {"campaign_family": campaign_family, "user": user, "spread": {}, "message": "no data"}

        spread_info = _build_spread_paths(filtered)
        return {
            "campaign_family": campaign_family,
            "user": user,
            "total_events": len(filtered),
            "spread": spread_info,
        }
    finally:
        db.close()


@router.get("/api/investigations/campaigns/global/escalation", response_model=GlobalCampaignEscalationResponse)
async def get_global_campaign_escalation(
    campaign_family: str,
    user: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = _query_for_tenant(db, tenant_id).all()
        filtered = []
        for alert in alerts:
            family, username = _global_campaign_key(alert)
            if family == campaign_family and username == user:
                filtered.append(alert)
        if not filtered:
            raise HTTPException(status_code=404, detail="Campaign not found")
        spread_info = _build_spread_paths(filtered)
        escalation = _escalate_campaign(
            campaign_family=campaign_family,
            total_events=len(filtered),
            spread_depth=spread_info["spread_depth"],
            affected_hosts=spread_info["visited_hosts"],
        )
        return {
            "campaign_family": campaign_family,
            "user": user,
            "recommended_severity": escalation["recommended_severity"],
            "incident_priority": escalation["incident_priority"],
            "spread_depth": spread_info["spread_depth"],
            "affected_hosts": spread_info["visited_hosts"],
            "total_events": len(filtered),
            "escalation_reasons": escalation["escalation_reasons"],
        }
    finally:
        db.close()


@router.get("/api/investigations/campaigns/global/response", response_model=GlobalCampaignResponsePlan)
async def get_global_campaign_response(
    campaign_family: str,
    user: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = _query_for_tenant(db, tenant_id).all()
        filtered = []
        for alert in alerts:
            family, username = _global_campaign_key(alert)
            if family == campaign_family and username == user:
                filtered.append(alert)
        if not filtered:
            raise HTTPException(status_code=404, detail="Campaign not found")
        spread_info = _build_spread_paths(filtered)
        escalation = _escalate_campaign(
            campaign_family=campaign_family,
            total_events=len(filtered),
            spread_depth=spread_info["spread_depth"],
            affected_hosts=spread_info["visited_hosts"],
        )
        response_plan = _build_response_plan(
            campaign_family=campaign_family,
            severity=escalation["recommended_severity"],
            spread_depth=spread_info["spread_depth"],
            affected_hosts=spread_info["visited_hosts"],
            total_events=len(filtered),
            user=user,
        )
        return {
            "campaign_family": campaign_family,
            "user": user,
            "auto_incident": response_plan["auto_incident"],
            "incident_title": response_plan["incident_title"],
            "playbook": response_plan["playbook"],
            "recommended_actions": response_plan["recommended_actions"],
            "priority": escalation["incident_priority"],
        }
    finally:
        db.close()


@router.post("/api/investigations/campaigns/global/incident", response_model=IncidentCreateFromCampaignResponse)
async def create_incident_from_global_campaign(
    campaign_family: str,
    user: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alerts = _query_for_tenant(db, tenant_id).all()
        filtered = []
        for alert in alerts:
            family, username = _global_campaign_key(alert)
            if family == campaign_family and username == user:
                filtered.append(alert)
        if not filtered:
            raise HTTPException(status_code=404, detail="Campaign not found")

        spread_info = _build_spread_paths(filtered)
        escalation = _escalate_campaign(
            campaign_family=campaign_family,
            total_events=len(filtered),
            spread_depth=spread_info["spread_depth"],
            affected_hosts=spread_info["visited_hosts"],
        )
        response_plan = _build_response_plan(
            campaign_family=campaign_family,
            severity=escalation["recommended_severity"],
            spread_depth=spread_info["spread_depth"],
            affected_hosts=spread_info["visited_hosts"],
            total_events=len(filtered),
            user=user,
        )
        
        # EKLENDİ: Alert grubunu özetle
        summary = summarize_alert_group(filtered)

        status, incident = upsert_incident_from_campaign(
            db,
            tenant_id=tenant_id,
            campaign_family=campaign_family,
            user=user,
            severity=escalation["recommended_severity"],
            priority=escalation["incident_priority"],
            playbook=response_plan["playbook"],
            recommended_actions=response_plan["recommended_actions"],
            attack_story=summary["attack_story"],  # EKLENDİ: Attack story verisi paslanıyor
            affected_hosts=spread_info["visited_hosts"],
            total_events=len(filtered),
            spread_depth=spread_info["spread_depth"],
        )
        return {"status": status, "incident": incident}
    finally:
        db.close()


@router.get("/api/incidents", response_model=IncidentListResponse)
async def get_incidents(
    limit: int = Query(default=100, ge=1, le=500),
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        return list_incidents(db, tenant_id=tenant_id, limit=limit)
    finally:
        db.close()


@router.get("/api/incidents/{incident_id}/timeline", response_model=IncidentTimelineResponse)
async def get_incident_timeline(
    incident_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = get_incident_by_id(db, incident_id, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        return list_incident_timeline(db, incident_id, tenant_id=tenant_id)
    finally:
        db.close()

@router.get("/api/incidents/{incident_id}/alerts", response_model=IncidentAlertListResponse)
async def get_incident_alerts_endpoint(
    incident_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        data = get_incident_alerts(db, incident_id, tenant_id=tenant_id)
        if not data:
            raise HTTPException(status_code=404, detail="Incident not found")
        return data
    finally:
        db.close()

@router.get("/api/incidents/{incident_id}/graph", response_model=IncidentGraphResponse)
async def get_incident_graph_endpoint(
    incident_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        data = get_incident_graph(db, incident_id, tenant_id=tenant_id)
        if not data:
            raise HTTPException(status_code=404, detail="Incident not found")
        return data
    finally:
        db.close()

@router.get("/api/incidents/{incident_id}/attack-chain", response_model=IncidentAttackChainResponse)
async def get_incident_attack_chain_endpoint(
    incident_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        data = get_incident_attack_chain(db, incident_id, tenant_id=tenant_id)
        if not data:
            raise HTTPException(status_code=404, detail="Incident not found")
        return data
    finally:
        db.close()

@router.get("/api/incidents/{incident_id}/response-plan", response_model=IncidentResponsePlanResponse)
async def get_incident_response_plan_endpoint(
    incident_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        data = get_incident_response_plan(db, incident_id, tenant_id=tenant_id)
        if not data:
            raise HTTPException(status_code=404, detail="Incident not found")
        return data
    finally:
        db.close()

@router.post("/api/incidents/{incident_id}/execute-response", response_model=IncidentExecutionResult)
async def execute_incident_response_endpoint(
    incident_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        result = execute_incident_response(db, incident_id, tenant_id=tenant_id)
        if not result:
            raise HTTPException(status_code=404, detail="Incident not found")
        return result
    finally:
        db.close()

@router.get("/api/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident_detail(
    incident_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = get_incident_by_id(db, incident_id, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        return row
    finally:
        db.close()


@router.patch("/api/incidents/{incident_id}/status", response_model=IncidentResponse)
async def patch_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdateRequest,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = update_incident_status(db, incident_id, payload.status, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        return row
    finally:
        db.close()


@router.patch("/api/incidents/{incident_id}/assign", response_model=IncidentResponse)
async def patch_incident_assign(
    incident_id: str,
    payload: IncidentAssignRequest,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = assign_incident(db, incident_id, payload.owner, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        return row
    finally:
        db.close()


@router.patch("/api/incidents/{incident_id}/note", response_model=IncidentResponse)
async def patch_incident_note(
    incident_id: str,
    payload: IncidentNoteUpdateRequest,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        row = update_incident_note(db, incident_id, payload.note, tenant_id=tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        return row
    finally:
        db.close()


@router.get("/api/investigations/graph/{alert_id}", response_model=InvestigationGraphResponse)
async def get_investigation_graph(
    alert_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        alert = _query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Investigation not found")

        hostname = str(getattr(alert, "hostname", "") or "")
        username = str(getattr(alert, "username", "") or "")
        rule = str(getattr(alert, "rule", "") or "")
        command_line = str(getattr(alert, "command_line", "") or "")
        risk_score = int(getattr(alert, "risk_score", 0) or 0)
        severity = str(getattr(alert, "severity", "INFO") or "INFO")
        status = str(getattr(alert, "status", "open") or "open")
        details = str(getattr(alert, "details", "") or "")
        pid = getattr(alert, "pid", None)

        family, confidence = _normalize_campaign_family(rule, hostname, username, alert)
        related_rows = _query_for_tenant(db, tenant_id).filter(
            or_(AlertModel.hostname == hostname, AlertModel.username == username, AlertModel.rule == rule)
        ).limit(10).all()
        related_ids = [f"INV-{row.id}" for row in related_rows if row.id != alert.id]
        related_count = len(related_rows)

        nodes = [
            {"id": f"alert-{alert.id}", "label": f"ALERT-{alert.id}", "type": "alert", "risk": risk_score, "meta": f"{status} / {severity}", "tactic": None, "role": "impact", "score": float(risk_score), "highlighted": True},
            {"id": f"host-{hostname}", "label": hostname or "unknown-host", "type": "host", "risk": max(risk_score - 10, 0), "meta": "Affected host", "tactic": None, "role": "pivot", "score": float(max(risk_score - 10, 0)), "highlighted": True},
            {"id": f"user-{username}", "label": username or "unknown-user", "type": "user", "risk": max(risk_score - 20, 0), "meta": "Related user", "tactic": None, "role": "entry", "score": float(max(risk_score - 20, 0)), "highlighted": True},
            {"id": f"proc-{command_line.split()[0] if command_line else 'unknown'}", "label": command_line.split()[0] if command_line else "unknown", "type": "process", "risk": max(risk_score - 5, 0), "meta": command_line or f"pid={pid}", "tactic": None, "role": "pivot", "score": float(max(risk_score - 5, 0)), "highlighted": True},
            {"id": f"rule-{rule.lower().replace(' ', '-')}", "label": rule or "Unknown Rule", "type": "rule", "risk": risk_score, "meta": details, "tactic": None, "role": "impact", "score": float(risk_score), "highlighted": True},
        ]
        edges = [
            {"from": f"user-{username}", "to": f"proc-{command_line.split()[0] if command_line else 'unknown'}", "label": "executed", "weight": 1.0, "highlighted": True},
            {"from": f"proc-{command_line.split()[0] if command_line else 'unknown'}", "to": f"host-{hostname}", "label": "ran on", "weight": 1.0, "highlighted": True},
            {"from": f"proc-{command_line.split()[0] if command_line else 'unknown'}", "to": f"rule-{rule.lower().replace(' ', '-')}", "label": "matched", "weight": 1.0, "highlighted": True},
            {"from": f"rule-{rule.lower().replace(' ', '-')}", "to": f"alert-{alert.id}", "label": "generated", "weight": 1.0, "highlighted": True},
            {"from": f"host-{hostname}", "to": f"alert-{alert.id}", "label": "affected", "weight": 1.0, "highlighted": True},
        ]
        path_info = _extract_attack_path(nodes, edges)
        kill_chain_phases = _infer_kill_chain(nodes, path_info["primary_attack_path"])

        return {
            "alert_id": str(alert.id),
            "title": rule or "Investigation Graph",
            "nodes": nodes,
            "edges": edges,
            "meta": {
                "summary": details or f"Alert-driven graph for {hostname}",
                "related_alerts": related_count,
                "severity": severity,
                "status": status,
                "entry_nodes": path_info["entry_nodes"],
                "pivot_nodes": path_info["pivot_nodes"],
                "impact_nodes": path_info["impact_nodes"],
                "primary_attack_path": path_info["primary_attack_path"],
                "kill_chain_phases": kill_chain_phases,
                "campaign_confidence": confidence,
                "related_investigation_ids": related_ids,
            },
        }
    finally:
        db.close()


@router.get("/api/investigations/{investigation_id}")
async def get_investigation_detail(
    investigation_id: str,
    current_user: str = Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    alert_id = investigation_id.removeprefix("INV-")
    db = SessionLocal()
    try:
        alert = _query_for_tenant(db, tenant_id).filter(AlertModel.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return _to_alert_response(alert)
    finally:
        db.close()

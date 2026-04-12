from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import desc, or_

from app.api.websockets import broadcast_command
from app.database.db_manager import AlertModel, IncidentModel, IncidentTimelineModel


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _safe_str(value: object | None, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value)


def _incident_scope(query, tenant_id: Optional[str]):
    if tenant_id and hasattr(IncidentModel, "tenant_id"):
        query = query.filter(or_(IncidentModel.tenant_id == tenant_id, IncidentModel.tenant_id.is_(None)))
    return query


def _timeline_scope(query, tenant_id: Optional[str]):
    if tenant_id and hasattr(IncidentTimelineModel, "tenant_id"):
        query = query.filter(or_(IncidentTimelineModel.tenant_id == tenant_id, IncidentTimelineModel.tenant_id.is_(None)))
    return query


def _severity_rank(severity: Optional[str]) -> int:
    sev = (severity or "INFO").upper()
    order = {"CRITICAL": 4, "HIGH": 3, "WARNING": 2, "INFO": 1}
    return order.get(sev, 0)


def _severity_max(a: Optional[str], b: Optional[str]) -> str:
    return a if _severity_rank(a) >= _severity_rank(b) else (b or a or "INFO")


def _incident_to_dict(row: IncidentModel) -> dict:
    return {
        "id": row.id,
        "campaign_family": row.campaign_family,
        "user": row.username,
        "title": row.title,
        "severity": row.severity,
        "priority": int(row.priority or 0),
        "status": row.status or "open",
        "owner": row.owner,
        "analyst_note": row.analyst_note,
        "playbook": row.playbook,
        "recommended_actions": row.recommended_actions(),
        "affected_hosts": row.affected_hosts(),
        "total_events": int(row.total_events or 0),
        "spread_depth": int(row.spread_depth or 0),
        "source_type": row.source_type or "global_campaign",
        "confidence": "high" if int(row.priority or 0) >= 85 else "medium",
        "source_key": row.source_key,
        "attack_story": json.loads(getattr(row, "attack_story_json", "[]") or "[]"),
        "created_at": _to_iso(row.created_at) or "",
        "updated_at": _to_iso(row.updated_at) or "",
    }


def _timeline_to_dict(row: IncidentTimelineModel) -> dict:
    return {
        "id": row.id,
        "incident_id": row.incident_id,
        "event_type": row.event_type,
        "actor": row.actor,
        "title": row.title,
        "details": row.details,
        "created_at": _to_iso(row.created_at) or "",
    }


MITRE_MAP = [
    {"match": ["powershell", "invoke-webrequest", "downloadstring", "frombase64string", " -enc ", " -nop "], "technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
    {"match": ["wmic", "process call create", "/node:"], "technique_id": "T1047", "technique_name": "Windows Management Instrumentation", "tactic": "Execution"},
    {"match": ["mimikatz", "credential dumping", "lsass", "sekurlsa", "procdump lsass", "lsass dump", "logonpasswords"], "technique_id": "T1003", "technique_name": "Credential Dumping", "tactic": "Credential Access"},
    {"match": ["net user", "user created", "new user created via net.exe"], "technique_id": "T1136", "technique_name": "Create Account", "tactic": "Persistence"},
    {"match": ["psexec", "paexec", "wmiexec", "admin$", "remote service", "\\\\", "smbexec"], "technique_id": "T1021", "technique_name": "Remote Services", "tactic": "Lateral Movement"},
    {"match": ["schtasks", "scheduled task", "currentversion\\run", "run key", "autorun"], "technique_id": "T1053", "technique_name": "Scheduled Task/Job", "tactic": "Persistence"},
    {"match": ["vssadmin delete shadows", "wbadmin delete catalog", "ransomware", "encrypt"], "technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
]

NOISE_PROCESS_MARKERS = [
    "audiodg.exe", "trustedinstaller.exe", "tiworker.exe", "explorer.exe", "updater.exe",
    "officesvcmgr.exe", "systemsettings.exe", "rtkbtmanserv.exe", "pet.exe", "python.exe",
    "uvicorn.exe", "cargo.exe", "rustup.exe", "installassistservice.exe", "sppsvc.exe",
    "clipesuconsumer.exe", "language_server_windows_x64.exe", "mscopilot_proxy.exe",
    "microsoftedgeupdate.exe", "notepad.exe", "git-remote-https.exe", "7zfm.exe",
    "smartscreen.exe", "easyduplicatefinder.exe",
]

LOW_VALUE_RULE_MARKERS = ["process_anomaly_storm", "new user created via net.exe", "asset inventory"]

CAMPAIGN_PRECEDENCE = {
    "credential_access": 100,
    "impact_ransomware": 95,
    "lateral_movement": 80,
    "persistence": 70,
    "malicious_execution": 60,
    "usb_activity": 40,
    "generic_activity": 10,
}


def normalize_rule(rule: Optional[str]) -> Optional[str]:
    if not rule:
        return None
    r = rule.strip().lower()
    if "credential dumping" in r or "mimikatz" in r or "lsass access" in r:
        return "Credential Access"
    if "wmic" in r:
        return "WMIC Remote Command Execution"
    if "powershell" in r:
        return "PowerShell Suspicious Execution"
    if "psexec" in r or "remote service" in r or "wmiexec" in r:
        return "Lateral Movement (PsExec)"
    if "scheduled task" in r or "schtasks" in r:
        return "Scheduled Task Persistence"
    if "run key" in r:
        return "Run Key Persistence"
    return rule


def infer_mitre(rule: Optional[str], command_line: Optional[str]):
    text = f"{rule or ''} {command_line or ''}".lower()
    for item in MITRE_MAP:
        if any(keyword in text for keyword in item["match"]):
            return item
    return None


def _alert_text(alert_like: Any) -> str:
    if isinstance(alert_like, dict):
        rule = _safe_str(alert_like.get("rule"), "")
        details = _safe_str(alert_like.get("details"), "")
        cmd = _safe_str(alert_like.get("command_line"), "")
        event_type = _safe_str(alert_like.get("type"), "")
    else:
        rule = _safe_str(getattr(alert_like, "rule", None), "")
        details = _safe_str(getattr(alert_like, "details", None), "")
        cmd = _safe_str(getattr(alert_like, "command_line", None), "")
        event_type = _safe_str(getattr(alert_like, "type", None), "")
    return f"{rule} {details} {cmd} {event_type}".lower()


def _alert_risk(alert_like: Any) -> int:
    if isinstance(alert_like, dict):
        return int(alert_like.get("risk_score", 0) or 0)
    return int(getattr(alert_like, "risk_score", 0) or 0)


def _alert_severity(alert_like: Any) -> str:
    if isinstance(alert_like, dict):
        return _safe_str(alert_like.get("severity"), "INFO").upper()
    return _safe_str(getattr(alert_like, "severity", None), "INFO").upper()


def _alert_username(alert_like: Any) -> str:
    if isinstance(alert_like, dict):
        return _safe_str(alert_like.get("username"), "unknown-user")
    return _safe_str(getattr(alert_like, "username", None), "unknown-user")


def _alert_hostname(alert_like: Any) -> str:
    if isinstance(alert_like, dict):
        return _safe_str(alert_like.get("hostname"), "unknown-host")
    return _safe_str(getattr(alert_like, "hostname", None), "unknown-host")


def _alert_created_at(alert_like: Any) -> Optional[datetime]:
    raw = alert_like.get("created_at") if isinstance(alert_like, dict) else getattr(alert_like, "created_at", None)
    if not raw:
        return None
    try:
        dt = raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _is_recent(alert_like: Any, minutes: int = 45) -> bool:
    dt = _alert_created_at(alert_like)
    return bool(dt and (_now_utc() - dt) <= timedelta(minutes=minutes))


def _incident_dt(row: IncidentModel) -> datetime:
    dt = getattr(row, "updated_at", None) or getattr(row, "created_at", None)
    if dt is None:
        return _now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_incident_recent(row: IncidentModel, minutes: int = 180) -> bool:
    return (_now_utc() - _incident_dt(row)) <= timedelta(minutes=minutes)


def _classify_single_alert(alert_like: Any) -> tuple[str, str]:
    text = _alert_text(alert_like)
    risk = _alert_risk(alert_like)

    if any(k in text for k in ["lsass", "sekurlsa", "mimikatz", "logonpasswords", "procdump.exe -ma lsass", "lsass dump"]):
        return "credential_access", "high"
    if any(k in text for k in ["psexec", "paexec", "wmiexec", "admin$", "remote service", "smbexec"]):
        return "lateral_movement", "high"
    if any(k in text for k in ["wmic", "process call create", "/node:"]):
        return ("malicious_execution", "high") if risk >= 70 else ("malicious_execution", "medium")
    if any(k in text for k in ["powershell", "-enc", "frombase64string", "downloadstring", "invoke-webrequest", "iex ", "iex("]):
        return "malicious_execution", "medium"
    if any(k in text for k in ["schtasks", "scheduled task", "run key", "currentversion\\run", "autorun"]):
        return "persistence", "medium"
    if any(k in text for k in ["ransomware", "encrypt", "vssadmin delete shadows", "wbadmin delete catalog"]):
        return "impact_ransomware", "high"
    if any(k in text for k in ["usb", "removable", "mass storage", "unauthorized usb"]):
        return "usb_activity", "medium"
    return "generic_activity", "low"


def _resolve_campaign_family(alerts: list[Any]) -> tuple[str, str]:
    recent_alerts = [a for a in alerts if _is_recent(a, minutes=45)]
    working_set = recent_alerts or alerts

    text_blob = " || ".join(_alert_text(a) for a in working_set)
    max_risk = max((_alert_risk(a) for a in working_set), default=0)

    has_credential = any(k in text_blob for k in ["lsass", "sekurlsa", "mimikatz", "logonpasswords", "procdump.exe -ma lsass", "lsass dump"])
    has_lateral = any(k in text_blob for k in ["psexec", "paexec", "wmiexec", "admin$", "remote service", "smbexec"])
    has_wmic = any(k in text_blob for k in ["wmic", "process call create", "/node:"])
    has_powershell = any(k in text_blob for k in ["powershell", "-enc", "frombase64string", "downloadstring", "invoke-webrequest", "iex ", "iex("])
    has_persistence = any(k in text_blob for k in ["schtasks", "scheduled task", "run key", "currentversion\\run", "autorun"])
    has_ransom = any(k in text_blob for k in ["ransomware", "encrypt", "vssadmin delete shadows", "wbadmin delete catalog"])

    if has_credential and (has_lateral or has_wmic or has_powershell):
        return "credential_access", "high"
    if has_credential:
        return "credential_access", "high"
    if has_lateral and has_wmic:
        return "lateral_movement", "high"
    if has_lateral:
        return "lateral_movement", "high"
    if has_ransom:
        return "impact_ransomware", "high"
    if has_persistence and (has_wmic or has_powershell):
        return "persistence", "high"
    if has_wmic or has_powershell:
        return ("malicious_execution", "high") if max_risk >= 70 else ("malicious_execution", "medium")
    if has_persistence:
        return "persistence", "medium"

    unique = {_classify_single_alert(a)[0] for a in working_set}
    if "usb_activity" in unique:
        return "usb_activity", "medium"
    if "persistence" in unique:
        return "persistence", "medium"
    return "generic_activity", "low"


def _build_spread_paths(alerts):
    alerts = sorted(alerts, key=lambda x: _alert_created_at(x) or datetime.min.replace(tzinfo=timezone.utc))
    spread_edges = []
    visited_hosts = []
    last_host = None
    for alert in alerts:
        host = _alert_hostname(alert)
        if not host or host == "unknown-host":
            continue
        if last_host and host != last_host:
            edge = f"{last_host} → {host}"
            if edge not in spread_edges:
                spread_edges.append(edge)
        last_host = host
        if host not in visited_hosts:
            visited_hosts.append(host)
    return {"spread_path": spread_edges, "visited_hosts": visited_hosts, "spread_depth": len(visited_hosts)}


def _escalate_campaign(*, campaign_family: str, total_events: int, spread_depth: int, affected_hosts: list[str], max_risk_score: int = 0, top_severity: str = "INFO", recent_event_count: int = 0) -> dict:
    reasons: list[str] = []
    score = 0
    host_count = len(affected_hosts)

    if max_risk_score >= 90:
        score += 40
        reasons.append(f"max_risk_score={max_risk_score}")
    elif max_risk_score >= 70:
        score += 28
        reasons.append(f"max_risk_score={max_risk_score}")
    elif max_risk_score >= 50:
        score += 18
        reasons.append(f"max_risk_score={max_risk_score}")

    if top_severity == "CRITICAL":
        score += 20
        reasons.append("top_severity=CRITICAL")
    elif top_severity == "HIGH":
        score += 10
        reasons.append("top_severity=HIGH")

    if campaign_family == "credential_access":
        score += 50
        reasons.append("credential_access detected")
        if spread_depth >= 2:
            score += 18
            reasons.append(f"spread_depth={spread_depth}")
        if host_count >= 2:
            score += 15
            reasons.append("multiple hosts involved")
        if total_events >= 3:
            score += 10
            reasons.append(f"event_volume={total_events}")
        if recent_event_count >= 2:
            score += 7
            reasons.append(f"recent_event_count={recent_event_count}")
    elif campaign_family == "lateral_movement":
        score += 40
        reasons.append("lateral movement pattern detected")
        if spread_depth >= 2:
            score += 20
            reasons.append(f"spread_depth={spread_depth}")
        if host_count >= 2:
            score += 12
            reasons.append("multiple hosts involved")
        if total_events >= 2:
            score += 8
            reasons.append(f"event_volume={total_events}")
    elif campaign_family == "impact_ransomware":
        score += 50
        reasons.append("ransomware-like impact detected")
        if host_count >= 2:
            score += 20
            reasons.append("multiple hosts affected")
    elif campaign_family == "malicious_execution":
        score += 30
        reasons.append("suspicious execution pattern detected")
        if spread_depth >= 2:
            score += 12
            reasons.append(f"spread_depth={spread_depth}")
        if total_events >= 3:
            score += 8
            reasons.append(f"event_volume={total_events}")
    elif campaign_family == "persistence":
        score += 24
        reasons.append("persistence behavior detected")
        if total_events >= 2:
            score += 8
            reasons.append(f"event_volume={total_events}")
    elif campaign_family == "usb_activity":
        score += 18
        reasons.append("usb activity detected")
    else:
        score += 5
        reasons.append("generic campaign activity")

    score = min(score, 100)

    if campaign_family == "credential_access" and max_risk_score >= 85:
        severity = "CRITICAL"
    elif campaign_family == "lateral_movement" and max_risk_score >= 70:
        severity = "HIGH"
    elif campaign_family == "malicious_execution" and max_risk_score >= 70:
        severity = "HIGH"
    elif score >= 85:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "WARNING"
    else:
        severity = "INFO"

    return {"recommended_severity": severity, "incident_priority": score, "escalation_reasons": reasons}


def _build_response_plan(*, campaign_family: str, severity: str, spread_depth: int, affected_hosts: list[str], total_events: int, user: str) -> dict:
    actions: list[str] = []
    playbook = None
    auto_incident = severity in {"CRITICAL", "HIGH"}

    if campaign_family == "credential_access":
        playbook = "credential_access_multi_host"
        actions.extend(["isolate affected hosts", "disable suspected user account", "collect LSASS memory", "block suspicious processes", "force password reset"])
        if spread_depth >= 2:
            actions.append("investigate lateral movement")
    elif campaign_family == "lateral_movement":
        playbook = "lateral_movement_containment"
        actions.extend(["isolate affected hosts", "block remote execution channels", "review administrative shares", "collect host triage data"])
    elif campaign_family == "impact_ransomware":
        playbook = "ransomware_containment"
        actions.extend(["isolate all affected hosts immediately", "disable network shares", "block encryption processes", "initiate incident response plan"])
    elif campaign_family == "usb_activity":
        playbook = "usb_exfiltration_investigation"
        actions.extend(["audit USB device usage", "block unauthorized USB devices", "review data transfer logs"])
    elif campaign_family == "malicious_execution":
        playbook = "suspicious_execution_analysis"
        actions.extend(["inspect process tree", "block suspicious command lines", "review execution source"])
    elif campaign_family == "persistence":
        playbook = "persistence_eradication"
        actions.extend(["review autoruns and run keys", "inspect scheduled tasks", "remove persistence artifact"])
    else:
        playbook = "generic_investigation"
        actions.append("review related alerts")

    actions = list(dict.fromkeys(actions))
    return {"auto_incident": auto_incident, "incident_title": f"{campaign_family} campaign detected for user {user}", "playbook": playbook, "recommended_actions": actions}


def _confidence_from_summary(summary: dict) -> str:
    score = 0
    if summary["campaign_family"] == "credential_access":
        score += 45
    elif summary["campaign_family"] == "lateral_movement":
        score += 30
    elif summary["campaign_family"] == "malicious_execution":
        score += 20
    score += min(summary["total_events"] * 5, 20)
    score += min(summary["spread_depth"] * 5, 20)
    if summary["severity"] == "CRITICAL":
        score += 20
    elif summary["severity"] == "HIGH":
        score += 10
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"

def build_attack_story(alerts: list[Any]) -> list[str]:
    story: list[str] = []

    for alert in alerts:
        if isinstance(alert, dict):
            rule = _safe_str(alert.get("rule"), "").lower()
            cmd = _safe_str(alert.get("command_line"), "").lower()
            user = _safe_str(alert.get("username"), "unknown-user")
            host = _safe_str(alert.get("hostname"), "unknown-host")
        else:
            rule = _safe_str(getattr(alert, "rule", None), "").lower()
            cmd = _safe_str(getattr(alert, "command_line", None), "").lower()
            user = _safe_str(getattr(alert, "username", None), "unknown-user")
            host = _safe_str(getattr(alert, "hostname", None), "unknown-host")

        if "powershell" in cmd:
            story.append(f"User {user} executed PowerShell on {host}")

        if "wmic" in cmd or "process call create" in cmd:
            story.append(f"Remote WMIC execution observed on {host}")

        if "psexec" in cmd or "paexec" in cmd:
            story.append(f"Remote service execution observed via PsExec-like activity on {host}")

        if "-enc" in cmd or "frombase64string" in cmd or "base64" in cmd:
            story.append("Encoded payload detected (possible obfuscation)")

        if "lsass" in cmd or "mimikatz" in rule or "credential dumping" in rule or "sekurlsa" in cmd:
            story.append("Credential dumping activity detected (LSASS access)")

        if "schtasks" in cmd or "scheduled task" in rule:
            story.append("Persistence attempt detected via scheduled task activity")

        if "run key" in rule or "currentversion\\run" in cmd:
            story.append("Persistence attempt detected via Run Key modification")

        if "ransomware" in rule or "vssadmin delete shadows" in cmd or "wbadmin delete catalog" in cmd:
            story.append("Impact-stage destructive behavior detected")

    return list(dict.fromkeys(story))

def summarize_alert_group(alerts: list[Any]) -> dict:
    if not alerts:
        return {
            "campaign_family": "generic_activity",
            "severity": "INFO",
            "priority": 5,
            "playbook": "generic_investigation",
            "recommended_actions": ["review related alerts"],
            "affected_hosts": [],
            "total_events": 0,
            "spread_depth": 0,
            "title": "generic_activity campaign detected for user unknown-user",
            "user": "unknown-user",
            "confidence": "low",
        }

    campaign_family, _ = _resolve_campaign_family(alerts)
    attack_story = build_attack_story(alerts)
    top_severity = "INFO"
    max_risk_score = 0
    affected_hosts = sorted({_alert_hostname(a) for a in alerts if _alert_hostname(a) and _alert_hostname(a) != "unknown-host"})
    user = _alert_username(alerts[0]).lower()

    for alert in alerts:
        top_severity = _severity_max(top_severity, _alert_severity(alert))
        max_risk_score = max(max_risk_score, _alert_risk(alert))

    spread_info = _build_spread_paths(alerts)
    recent_event_count = len([a for a in alerts if _is_recent(a, minutes=45)])
    escalation = _escalate_campaign(
        campaign_family=campaign_family,
        total_events=len(alerts),
        spread_depth=spread_info["spread_depth"],
        affected_hosts=affected_hosts,
        max_risk_score=max_risk_score,
        top_severity=top_severity,
        recent_event_count=recent_event_count,
    )
    response = _build_response_plan(
        campaign_family=campaign_family,
        severity=escalation["recommended_severity"],
        spread_depth=spread_info["spread_depth"],
        affected_hosts=affected_hosts,
        total_events=len(alerts),
        user=user,
    )
    summary = {
        "campaign_family": campaign_family,
        "severity": escalation["recommended_severity"],
        "priority": int(escalation["incident_priority"]),
        "playbook": response["playbook"],
        "recommended_actions": response["recommended_actions"],
        "affected_hosts": affected_hosts,
        "total_events": len(alerts),
        "spread_depth": spread_info["spread_depth"],
        "attack_story": attack_story,
        "title": response["incident_title"],
        "user": user,
    }
    summary["confidence"] = _confidence_from_summary(summary)
    return summary


def add_incident_timeline_event(db, *, incident_id: str, tenant_id: Optional[str], event_type: str, actor: Optional[str], title: str, details: Optional[str] = None):
    row = IncidentTimelineModel(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        tenant_id=tenant_id,
        event_type=event_type,
        actor=actor,
        title=title,
        details=details,
        created_at=_now_utc(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _timeline_to_dict(row)


def _get_incident_row(db, incident_id: str, tenant_id: Optional[str] = None):
    return _incident_scope(db.query(IncidentModel).filter(IncidentModel.id == incident_id), tenant_id).first()


def get_incident_by_campaign(db, campaign_family: str, user: str, tenant_id: Optional[str] = None):
    query = db.query(IncidentModel).filter(
        IncidentModel.source_type == "global_campaign",
        IncidentModel.source_key == f"{campaign_family}:{user}".lower().strip(),
    )
    query = _incident_scope(query, tenant_id)
    return query.first()


def _mark_child_incident_suppressed(db, *, child: IncidentModel, parent: IncidentModel, tenant_id: Optional[str]):
    child.status = "suppressed"
    child.updated_at = _now_utc()
    db.add(child)
    db.commit()
    db.refresh(child)
    add_incident_timeline_event(
        db,
        incident_id=child.id,
        tenant_id=tenant_id,
        event_type="suppressed",
        actor="system",
        title=f"Suppressed under parent incident {parent.id}",
        details=json.dumps({"parent_incident_id": parent.id, "parent_campaign_family": parent.campaign_family}),
    )


def suppress_stale_child_incidents(db, *, tenant_id: Optional[str], user: str, parent: IncidentModel):
    child_families = {"malicious_execution", "lateral_movement", "persistence"}
    rows = (
        _incident_scope(
            db.query(IncidentModel).filter(
                IncidentModel.username == user,
                IncidentModel.source_type == "global_campaign",
                IncidentModel.status.in_(["open", "acknowledged", "in_progress"]),
                IncidentModel.campaign_family.in_(list(child_families)),
                IncidentModel.id != parent.id,
            ),
            tenant_id,
        )
        .order_by(desc(IncidentModel.updated_at))
        .all()
    )

    suppressed_ids = []
    for row in rows:
        if _is_incident_recent(row, minutes=720):
            _mark_child_incident_suppressed(db, child=row, parent=parent, tenant_id=tenant_id)
            suppressed_ids.append(row.id)

    if suppressed_ids:
        add_incident_timeline_event(
            db,
            incident_id=parent.id,
            tenant_id=tenant_id,
            event_type="child_suppression",
            actor="system",
            title="Suppressed stale child incidents under parent campaign",
            details=json.dumps({"suppressed_incident_ids": suppressed_ids}),
        )
    return suppressed_ids


def _merge_incident_into_parent(db, *, parent: IncidentModel, child_summary: dict, tenant_id: Optional[str], child_alerts: list[Any]):
    parent.severity = _severity_max(parent.severity, child_summary["severity"])
    parent.priority = max(int(parent.priority or 0), int(child_summary["priority"] or 0))
    parent.total_events = max(int(parent.total_events or 0), int(parent.total_events or 0) + int(child_summary["total_events"] or 0))
    parent.spread_depth = max(int(parent.spread_depth or 0), int(child_summary["spread_depth"] or 0))
    parent.playbook = parent.playbook or child_summary["playbook"]
    merged_hosts = sorted({*(parent.affected_hosts() or []), *(child_summary.get("affected_hosts") or [])})
    parent.affected_hosts_json = json.dumps(merged_hosts)
    merged_actions = list(dict.fromkeys([*(parent.recommended_actions() or []), *(child_summary.get("recommended_actions") or [])]))
    parent.recommended_actions_json = json.dumps(merged_actions)
    # attack story merge
    if hasattr(parent, "attack_story_json"):
        current_story = json.loads(getattr(parent, "attack_story_json", "[]") or "[]")
        merged_story = list(
        dict.fromkeys([*current_story, *(child_summary.get("attack_story") or [])])
        )
        parent.attack_story_json = json.dumps(merged_story)
    parent.updated_at = _now_utc()
    db.add(parent)
    db.commit()
    db.refresh(parent)

    child_rules = sorted(
        {
            normalize_rule(_safe_str(a.get("rule"), "")) if isinstance(a, dict) else normalize_rule(_safe_str(getattr(a, "rule", None), ""))
            for a in child_alerts
            if (a.get("rule") if isinstance(a, dict) else getattr(a, "rule", None))
        }
    )

    add_incident_timeline_event(
        db,
        incident_id=parent.id,
        tenant_id=tenant_id,
        event_type="campaign_merge",
        actor="system",
        title=f"Merged child campaign {child_summary['campaign_family']} into {parent.campaign_family}",
        details=json.dumps({"merged_campaign_family": child_summary["campaign_family"], "merged_total_events": child_summary["total_events"], "merged_rules": child_rules, "confidence": child_summary.get("confidence")}),
    )
    suppress_stale_child_incidents(db, tenant_id=tenant_id, user=parent.username, parent=parent)
    return "merged_into_parent", _incident_to_dict(parent)


def _find_parent_incident_for_merge(db, *, tenant_id: Optional[str], user: str, candidate_family: str):
    if candidate_family not in {"malicious_execution", "lateral_movement", "persistence"}:
        return None

    stronger_families = []
    if candidate_family == "malicious_execution":
        stronger_families = ["credential_access", "lateral_movement", "impact_ransomware"]
    elif candidate_family == "lateral_movement":
        stronger_families = ["credential_access", "impact_ransomware"]
    elif candidate_family == "persistence":
        stronger_families = ["credential_access", "impact_ransomware"]

    rows = (
        _incident_scope(
            db.query(IncidentModel).filter(
                IncidentModel.username == user,
                IncidentModel.source_type == "global_campaign",
                IncidentModel.status.in_(["open", "acknowledged", "in_progress"]),
            ),
            tenant_id,
        )
        .order_by(desc(IncidentModel.updated_at), desc(IncidentModel.priority))
        .limit(20)
        .all()
    )

    for row in rows:
        if row.campaign_family in stronger_families and _is_incident_recent(row, minutes=180):
            return row
    return None


def upsert_incident_from_campaign(db, *, tenant_id: Optional[str], campaign_family: str, user: str, severity: str, priority: int, playbook: Optional[str], recommended_actions: list[str],attack_story: list[str], affected_hosts: list[str], total_events: int, spread_depth: int):
    source_key = f"{campaign_family}:{user}".lower().strip()
    incident = get_incident_by_campaign(db, campaign_family, user, tenant_id=tenant_id)
    now = _now_utc()

    if incident:
        incident.severity = _severity_max(incident.severity, severity)
        incident.priority = max(int(incident.priority or 0), int(priority or 0))
        incident.playbook = playbook or incident.playbook
        incident.total_events = max(int(incident.total_events or 0), int(total_events or 0))
        incident.spread_depth = max(int(incident.spread_depth or 0), int(spread_depth or 0))
        current_hosts = incident.affected_hosts()
        merged_hosts = sorted({*(current_hosts or []), *(affected_hosts or [])})
        incident.affected_hosts_json = json.dumps(merged_hosts)
        current_actions = incident.recommended_actions()
        incident.recommended_actions_json = json.dumps(
        list(dict.fromkeys([*(current_actions or []), *(recommended_actions or [])]))
        )

        if hasattr(incident, "attack_story_json"):
            current_story = json.loads(getattr(incident, "attack_story_json", "[]") or "[]")
            incident.attack_story_json = json.dumps(
        list(dict.fromkeys([*current_story, *(attack_story or [])]))
        )

        incident.updated_at = now
        db.add(incident)
        db.commit()
        db.refresh(incident)
        add_incident_timeline_event(db, incident_id=incident.id, tenant_id=tenant_id, event_type="campaign_update", actor="system", title=f"Campaign updated: {campaign_family}", details=f"user={user}; total_events={incident.total_events}; spread_depth={incident.spread_depth}")
        return "updated", _incident_to_dict(incident)

    incident = IncidentModel(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        campaign_family=campaign_family,
        username=user,
        title=f"{campaign_family} campaign detected for user {user}",
        severity=severity,
        priority=int(priority or 0),
        status="open",
        owner=None,
        analyst_note=None,
        playbook=playbook,
        recommended_actions_json=json.dumps(recommended_actions or []),
        attack_story_json=json.dumps(attack_story or []),
        affected_hosts_json=json.dumps(affected_hosts or []),
        total_events=int(total_events or 0),
        spread_depth=int(spread_depth or 0),
        source_type="global_campaign",
        source_key=source_key,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    add_incident_timeline_event(db, incident_id=incident.id, tenant_id=tenant_id, event_type="created", actor="system", title=f"Incident created: {campaign_family}", details=f"user={user}; severity={severity}; priority={priority}")
    return "created", _incident_to_dict(incident)


def upsert_incident_from_alerts(db, *, alerts: list[Any], tenant_id: Optional[str] = None):
    summary = summarize_alert_group(alerts)
    parent = _find_parent_incident_for_merge(db, tenant_id=tenant_id, user=summary["user"], candidate_family=summary["campaign_family"])
    if parent is not None:
        return _merge_incident_into_parent(db, parent=parent, child_summary=summary, tenant_id=tenant_id, child_alerts=alerts)

    status, incident = upsert_incident_from_campaign(
        db,
        tenant_id=tenant_id,
        campaign_family=summary["campaign_family"],
        user=summary["user"],
        severity=summary["severity"],
        priority=summary["priority"],
        playbook=summary["playbook"],
        recommended_actions=summary["recommended_actions"],
        attack_story=summary["attack_story"],
        affected_hosts=summary["affected_hosts"],
        total_events=summary["total_events"],
        spread_depth=summary["spread_depth"],
    )

    if isinstance(incident, dict) and summary["campaign_family"] == "credential_access":
        parent_row = _get_incident_row(db, incident["id"], tenant_id=tenant_id)
        if parent_row:
            suppress_stale_child_incidents(db, tenant_id=tenant_id, user=summary["user"], parent=parent_row)

    return status, incident


def upsert_incident_for_new_alert(db, *, alert: Any, tenant_id: Optional[str] = None, lookback_minutes: int = 45):
    username = _alert_username(alert)
    hostname = _alert_hostname(alert)
    query = db.query(AlertModel)

    if tenant_id:
        query = query.filter(or_(AlertModel.tenant_id == tenant_id, AlertModel.tenant_id.is_(None)))
    if username and username != "unknown-user":
        query = query.filter(AlertModel.username == username)
    if hostname and hostname != "unknown-host":
        query = query.filter(AlertModel.hostname == hostname)

    rows = query.order_by(AlertModel.created_at.desc()).limit(50).all()
    cutoff = _now_utc() - timedelta(minutes=lookback_minutes)
    related = []
    for row in rows:
        dt = _alert_created_at(row)
        if dt and dt >= cutoff:
            related.append(row)

    if not related:
        related = [alert]

    return upsert_incident_from_alerts(db, alerts=related, tenant_id=tenant_id)


def list_incidents(db, tenant_id: Optional[str] = None, limit: int = 100):
    rows = (_incident_scope(db.query(IncidentModel), tenant_id).order_by(desc(IncidentModel.updated_at), desc(IncidentModel.priority)).limit(max(1, min(limit, 500))).all())
    return {"total": len(rows), "items": [_incident_to_dict(row) for row in rows]}


def get_incident_by_id(db, incident_id: str, tenant_id: Optional[str] = None):
    row = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    return _incident_to_dict(row) if row else None


def update_incident_status(db, incident_id: str, status: str, tenant_id: Optional[str] = None):
    row = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    if not row:
        return None
    row.status = status
    row.updated_at = _now_utc()
    db.add(row)
    db.commit()
    db.refresh(row)
    add_incident_timeline_event(db, incident_id=row.id, tenant_id=tenant_id, event_type="status_change", actor="analyst", title=f"Incident status changed to {status}")
    return _incident_to_dict(row)


def assign_incident(db, incident_id: str, owner: str, tenant_id: Optional[str] = None):
    row = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    if not row:
        return None
    row.owner = owner
    row.updated_at = _now_utc()
    db.add(row)
    db.commit()
    db.refresh(row)
    add_incident_timeline_event(db, incident_id=row.id, tenant_id=tenant_id, event_type="assignment", actor="analyst", title=f"Incident assigned to {owner}")
    return _incident_to_dict(row)


def update_incident_note(db, incident_id: str, note: str, tenant_id: Optional[str] = None):
    row = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    if not row:
        return None
    row.analyst_note = note
    row.updated_at = _now_utc()
    db.add(row)
    db.commit()
    db.refresh(row)
    add_incident_timeline_event(db, incident_id=row.id, tenant_id=tenant_id, event_type="note", actor="analyst", title="Incident note updated", details=note)
    return _incident_to_dict(row)


def list_incident_timeline(db, incident_id: str, tenant_id: Optional[str] = None):
    rows = (_timeline_scope(db.query(IncidentTimelineModel).filter(IncidentTimelineModel.incident_id == incident_id), tenant_id).order_by(desc(IncidentTimelineModel.created_at)).limit(500).all())
    return {"incident_id": incident_id, "items": [_timeline_to_dict(row) for row in rows]}


def _campaign_rule_filters(campaign_family: str):
    campaign_family = (campaign_family or "").lower()
    if campaign_family == "credential_access":
        return or_(AlertModel.rule.ilike("%credential%"), AlertModel.rule.ilike("%mimikatz%"), AlertModel.rule.ilike("%lsass%"), AlertModel.details.ilike("%lsass%"), AlertModel.command_line.ilike("%lsass%"), AlertModel.command_line.ilike("%sekurlsa%"), AlertModel.command_line.ilike("%procdump%"))
    if campaign_family == "lateral_movement":
        return or_(AlertModel.rule.ilike("%psexec%"), AlertModel.rule.ilike("%remote%"), AlertModel.rule.ilike("%wmiexec%"), AlertModel.command_line.ilike("%psexec%"), AlertModel.command_line.ilike("%paexec%"), AlertModel.command_line.ilike("%wmiexec%"), AlertModel.command_line.ilike("%admin$%"), AlertModel.command_line.ilike("%\\\\%"))
    if campaign_family == "malicious_execution":
        return or_(AlertModel.rule.ilike("%powershell%"), AlertModel.rule.ilike("%wmic%"), AlertModel.command_line.ilike("%powershell%"), AlertModel.command_line.ilike("%wmic%"), AlertModel.command_line.ilike("%process call create%"), AlertModel.command_line.ilike("%/node:%"), AlertModel.command_line.ilike("%-enc%"), AlertModel.command_line.ilike("%downloadstring%"))
    if campaign_family == "persistence":
        return or_(AlertModel.rule.ilike("%scheduled task%"), AlertModel.rule.ilike("%run key%"), AlertModel.command_line.ilike("%schtasks%"), AlertModel.details.ilike("%currentversion\\run%"))
    if campaign_family == "impact_ransomware":
        return or_(AlertModel.rule.ilike("%ransom%"), AlertModel.details.ilike("%encrypt%"), AlertModel.command_line.ilike("%vssadmin delete shadows%"), AlertModel.command_line.ilike("%wbadmin delete catalog%"))
    return None


def get_incident_alerts(db, incident_id: str, tenant_id: Optional[str] = None):
    incident = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    if not incident:
        return None

    query = db.query(AlertModel)
    if tenant_id:
        query = query.filter(or_(AlertModel.tenant_id == tenant_id, AlertModel.tenant_id.is_(None)))

    filters = []
    if incident.username:
        filters.append(AlertModel.username == incident.username)
    hosts = incident.affected_hosts()
    if hosts:
        filters.append(AlertModel.hostname.in_(hosts))
    source_key = getattr(incident, "source_key", None)
    if source_key and ":" in source_key:
        _, src_user = source_key.split(":", 1)
        if src_user:
            filters.append(AlertModel.username == src_user)

    campaign_filter = _campaign_rule_filters(getattr(incident, "campaign_family", None))
    if campaign_filter is not None:
        filters.append(campaign_filter)

    if filters:
        query = query.filter(or_(*filters))

    rows = query.filter(AlertModel.risk_score >= 30).order_by(AlertModel.created_at.desc()).limit(200).all()
    items = []
    for row in rows:
        items.append({
            "id": row.id,
            "created_at": _to_iso(getattr(row, "created_at", None)) or "",
            "hostname": getattr(row, "hostname", None),
            "username": getattr(row, "username", None),
            "type": getattr(row, "type", None),
            "risk_score": int(getattr(row, "risk_score", 0) or 0),
            "rule": getattr(row, "rule", None),
            "severity": getattr(row, "severity", None),
            "details": getattr(row, "details", None),
            "command_line": getattr(row, "command_line", None),
            "pid": getattr(row, "pid", None),
            "serial": getattr(row, "serial", None),
            "tenant_id": getattr(row, "tenant_id", None),
            "status": getattr(row, "status", "open"),
            "analyst_note": getattr(row, "analyst_note", None),
            "resolved_at": _to_iso(getattr(row, "resolved_at", None)),
            "resolved_by": getattr(row, "resolved_by", None),
            "assigned_to": getattr(row, "assigned_to", None),
            "assigned_at": _to_iso(getattr(row, "assigned_at", None)),
        })
    return {"incident_id": incident_id, "total": len(items), "items": items}


def get_incident_graph(db, incident_id: str, tenant_id: Optional[str] = None):
    incident = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    if not incident:
        return None
    alerts_payload = get_incident_alerts(db, incident_id, tenant_id=tenant_id)
    if not alerts_payload:
        return None

    alerts = alerts_payload.get("items", [])
    node_map = {}
    edge_map = set()
    edges = []

    def add_node(node_id, label, node_type, risk=None, meta=None, tactic=None, technique_id=None, technique_name=None, role=None, score=0.0, highlighted=False):
        existing = node_map.get(node_id)
        if existing:
            if risk is not None:
                existing["risk"] = max(existing.get("risk") or 0, risk)
            if highlighted:
                existing["highlighted"] = True
            if score > (existing.get("score") or 0):
                existing["score"] = score
            if tactic and not existing.get("tactic"):
                existing["tactic"] = tactic
            if role and not existing.get("role"):
                existing["role"] = role
            if technique_id and not existing.get("technique_id"):
                existing["technique_id"] = technique_id
            if technique_name and not existing.get("technique_name"):
                existing["technique_name"] = technique_name
            return
        node_map[node_id] = {"id": node_id, "label": label, "type": node_type, "risk": risk, "meta": meta, "tactic": tactic, "technique_id": technique_id, "technique_name": technique_name, "role": role, "score": score, "highlighted": highlighted}

    def add_edge(src, dst, label, weight=1.0, highlighted=False):
        key = (src, dst, label)
        if key in edge_map:
            return
        edge_map.add(key)
        edges.append({"from": src, "to": dst, "label": label, "weight": weight, "highlighted": highlighted})

    incident_node_id = f"incident:{incident.id}"
    add_node(incident_node_id, incident.title, "incident", risk=int(incident.priority or 0), meta=f"status={incident.status}", role="context", score=float(incident.priority or 0), highlighted=True)

    entry_nodes = set()
    pivot_nodes = set()
    impact_nodes = set()
    kill_chain = set()

    grouped_alerts = {}
    for alert in alerts:
        rule = normalize_rule(alert.get("rule"))
        group_key = (rule or "").strip().lower()
        if group_key not in grouped_alerts or int(alert.get("risk_score") or 0) > int(grouped_alerts[group_key].get("risk_score") or 0):
            grouped_alerts[group_key] = alert
    alerts = list(grouped_alerts.values())

    for alert in alerts:
        risk_score = int(alert.get("risk_score") or 0)
        if risk_score < 70:
            continue
        hostname = alert.get("hostname")
        username = alert.get("username")
        rule = normalize_rule(alert.get("rule"))
        command_line = alert.get("command_line")
        severity = alert.get("severity")

        if rule and any(marker in rule.strip().lower() for marker in LOW_VALUE_RULE_MARKERS):
            continue
        if command_line and any(marker in command_line.lower() for marker in NOISE_PROCESS_MARKERS):
            command_line = None

        mitre = infer_mitre(rule, command_line)
        tactic = mitre.get("tactic") if mitre else None
        technique_id = mitre.get("technique_id") if mitre else None
        technique_name = mitre.get("technique_name") if mitre else None
        if tactic:
            kill_chain.add(tactic)

        alert_id = f"alert:{alert['id']}"
        add_node(alert_id, rule or f"ALERT-{alert['id']}", "alert", risk=risk_score, meta=severity, tactic=tactic, technique_id=technique_id, technique_name=technique_name, role="impact", score=float(risk_score + 30), highlighted=risk_score >= 90)
        add_edge(incident_node_id, alert_id, "contains", weight=1.0 + (risk_score / 100.0), highlighted=risk_score >= 90)
        impact_nodes.add(alert_id)

        if hostname:
            host_id = f"host:{hostname}"
            add_node(host_id, hostname, "host", risk=risk_score, meta="affected host", role="impact" if risk_score >= 70 else "pivot", score=float(risk_score + 5), highlighted=risk_score >= 90)
            add_edge(alert_id, host_id, "on_host", weight=1.1, highlighted=risk_score >= 90)
            pivot_nodes.add(host_id)

        if username and str(username).upper() != "SYSTEM":
            user_id = f"user:{username}"
            add_node(user_id, username, "user", risk=risk_score, meta="related user", role="entry", score=float(risk_score + 5), highlighted=risk_score >= 90)
            add_edge(alert_id, user_id, "by_user", weight=1.05, highlighted=risk_score >= 90)
            entry_nodes.add(user_id)

        if rule:
            rule_id = f"rule:{rule}"
            add_node(rule_id, rule, "rule", risk=risk_score, meta="detection rule", tactic=tactic, technique_id=technique_id, technique_name=technique_name, role="pivot", score=float(risk_score + 10), highlighted=risk_score >= 90)
            add_edge(alert_id, rule_id, "matched_rule", weight=0.95, highlighted=risk_score >= 90)
            pivot_nodes.add(rule_id)

        if command_line:
            proc_label = command_line[:140]
            proc_lower = proc_label.lower()
            proc_id = f"process:{proc_label}"
            proc_score = float(risk_score + 15)
            proc_highlight = risk_score >= 90
            if any(x in proc_lower for x in ["mimikatz", "lsass", "sekurlsa", "invoke-webrequest", "wmic", "powershell", "psexec", "paexec", "wmiexec"]):
                proc_score += 25
                proc_highlight = True
            add_node(proc_id, proc_label, "process", risk=risk_score, meta=f"pid={alert.get('pid')}", tactic=tactic, technique_id=technique_id, technique_name=technique_name, role="entry" if "powershell" in proc_lower else "pivot", score=proc_score, highlighted=proc_highlight)
            add_edge(alert_id, proc_id, "spawned_process", weight=1.15, highlighted=proc_highlight)
            if "powershell" in proc_lower:
                entry_nodes.add(proc_id)
            else:
                pivot_nodes.add(proc_id)

    nodes = sorted(list(node_map.values()), key=lambda n: (0 if n.get("highlighted") else 1, -(n.get("risk") or 0), -(n.get("score") or 0), n.get("type") or "", n.get("label") or ""))
    edges = sorted(edges, key=lambda e: (0 if e.get("highlighted") else 1, e.get("from") or "", e.get("to") or "", e.get("label") or ""))

    primary_attack_path = []
    primary_attack_path.extend(sorted([n for n in entry_nodes if n.startswith("user:")])[:1])
    primary_attack_path.extend(sorted([n for n in entry_nodes if n.startswith("process:")])[:1])
    primary_attack_path.extend(sorted([n for n in pivot_nodes if n.startswith("rule:")])[:1])
    primary_attack_path.extend(sorted([n for n in impact_nodes if n.startswith("alert:")])[:1])

    return {
        "incident_id": incident.id,
        "title": incident.title,
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "summary": f"{incident.title} | campaign={incident.campaign_family} | total_alerts={len(alerts)}",
            "related_alerts": len(alerts),
            "severity": incident.severity,
            "status": incident.status,
            "entry_nodes": sorted(entry_nodes),
            "pivot_nodes": sorted(pivot_nodes),
            "impact_nodes": sorted(impact_nodes),
            "primary_attack_path": primary_attack_path,
            "kill_chain_phases": sorted(list(kill_chain)),
            "campaign_confidence": "high" if incident.spread_depth >= 3 or int(incident.priority or 0) >= 90 else "medium",
            "related_investigation_ids": [a["id"] for a in alerts[:10]],
        },
    }


def get_incident_attack_chain(db, incident_id: str, tenant_id: Optional[str] = None):
    graph = get_incident_graph(db, incident_id, tenant_id=tenant_id)
    if not graph:
        return None
    nodes = graph.get("nodes", [])
    meta = graph.get("meta", {})
    title = graph.get("title", "")
    graph_incident_id = graph.get("incident_id", incident_id)

    user_nodes = sorted([n for n in nodes if n.get("id", "").startswith("user:")], key=lambda n: (-(n.get("risk") or 0), -(n.get("score") or 0), n.get("label") or ""))
    process_nodes = sorted([n for n in nodes if n.get("id", "").startswith("process:")], key=lambda n: (-(n.get("risk") or 0), -(n.get("score") or 0), n.get("label") or ""))
    rule_nodes = sorted([n for n in nodes if n.get("id", "").startswith("rule:")], key=lambda n: (-(n.get("risk") or 0), -(n.get("score") or 0), n.get("label") or ""))
    host_nodes = sorted([n for n in nodes if n.get("id", "").startswith("host:")], key=lambda n: (-(n.get("risk") or 0), -(n.get("score") or 0), n.get("label") or ""))
    alert_nodes = sorted([n for n in nodes if n.get("id", "").startswith("alert:")], key=lambda n: (-(n.get("risk") or 0), -(n.get("score") or 0), n.get("label") or ""))

    primary_user = user_nodes[0] if user_nodes else None
    primary_process = process_nodes[0] if process_nodes else None
    primary_rule = rule_nodes[0] if rule_nodes else None
    primary_alert = alert_nodes[0] if alert_nodes else None

    steps = []
    step_no = 1

    def add_step(stage: str, node: dict, evidence: Optional[str] = None):
        nonlocal step_no
        if not node:
            return
        mitre = {"technique_id": node.get("technique_id"), "technique_name": node.get("technique_name"), "tactic": node.get("tactic")} if node.get("technique_id") else infer_mitre(node.get("label"), evidence or node.get("label"))
        steps.append({"step": step_no, "stage": stage, "node_id": node.get("id"), "label": node.get("label"), "node_type": node.get("type"), "evidence": evidence, "risk": int(node.get("risk") or 0), "technique_id": mitre.get("technique_id") if mitre else None, "technique_name": mitre.get("technique_name") if mitre else None, "tactic": mitre.get("tactic") if mitre else stage})
        step_no += 1

    if primary_user:
        add_step("Initial Context", primary_user, evidence="Primary related user identified from incident graph")
    if primary_process:
        add_step(primary_process.get("tactic") or "Execution", primary_process, evidence=primary_process.get("label"))
    if primaryRule := primary_rule:
        add_step(primaryRule.get("tactic") or "Detection", primaryRule, evidence=primaryRule.get("label"))
    if primary_alert:
        add_step("Impact", primary_alert, evidence=primary_alert.get("meta"))

    return {"incident_id": graph_incident_id, "title": title, "confidence": meta.get("campaign_confidence") or "medium", "primary_user": primary_user.get("label") if primary_user else None, "primary_process": primary_process.get("label") if primary_process else None, "primary_rule": primary_rule.get("label") if primary_rule else None, "affected_hosts": [n.get("label") for n in host_nodes if n.get("label")][:10], "kill_chain_phases": meta.get("kill_chain_phases", []), "steps": steps}


def get_incident_response_plan(db, incident_id: str, tenant_id: Optional[str] = None):
    incident = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    if not incident:
        return None
    alerts_payload = get_incident_alerts(db, incident_id, tenant_id=tenant_id) or {"items": []}
    max_risk_score = max([int(item.get("risk_score") or 0) for item in alerts_payload.get("items", [])], default=0)
    top_sev = "INFO"
    for item in alerts_payload.get("items", []):
        top_sev = _severity_max(top_sev, item.get("severity"))

    escalation = _escalate_campaign(campaign_family=incident.campaign_family, total_events=int(incident.total_events or 0), spread_depth=int(incident.spread_depth or 0), affected_hosts=incident.affected_hosts(), max_risk_score=max_risk_score, top_severity=top_sev, recent_event_count=min(len(alerts_payload.get("items", [])), 5))
    plan = _build_response_plan(campaign_family=incident.campaign_family, severity=incident.severity, spread_depth=int(incident.spread_depth or 0), affected_hosts=incident.affected_hosts(), total_events=int(incident.total_events or 0), user=incident.username)

    actions = [{"action": action, "automated": False, "reason": incident.campaign_family, "priority": int(escalation["incident_priority"])} for action in plan["recommended_actions"]]
    return {"incident_id": incident.id, "title": incident.title, "confidence": "high" if int(incident.priority or 0) >= 85 else "medium", "auto_execute": bool(plan["auto_incident"]), "recommended_actions": actions, "escalation_reasons": escalation["escalation_reasons"]}


def execute_incident_response(db, incident_id: str, tenant_id: Optional[str] = None):
    incident = _get_incident_row(db, incident_id, tenant_id=tenant_id)
    if not incident:
        return None
    executed = []
    skipped = []
    errors = []
    hosts = incident.affected_hosts()
    campaign = incident.campaign_family

    def _queue(action: str, hostname: str, **kwargs):
        command_id = f"incident-{incident.id}-{action.lower()}-{uuid.uuid4().hex[:8]}"
        coro = broadcast_command(action, hostname, command_id=command_id, requested_by="incident-engine", tenant_id=tenant_id, incident_id=incident.id, **kwargs)
        try:
            asyncio.get_running_loop().create_task(coro)
        except RuntimeError:
            asyncio.run(coro)

    try:
        if campaign in {"credential_access", "impact_ransomware", "lateral_movement"}:
            for host in hosts:
                _queue("ISOLATE_HOST", host)
                executed.append(f"isolate:{host}")
        else:
            skipped.append("auto_isolation_not_required")

        if campaign in {"malicious_execution", "lateral_movement", "credential_access"}:
            for host in hosts:
                _queue("ANALYZE_HOST", host)
                executed.append(f"analyze:{host}")
    except Exception as exc:
        errors.append(str(exc))

    add_incident_timeline_event(db, incident_id=incident.id, tenant_id=tenant_id, event_type="response_execution", actor="system", title="Incident response executed", details=json.dumps({"executed": executed, "skipped": skipped, "errors": errors}))
    return {"incident_id": incident.id, "executed": executed, "skipped": skipped, "errors": errors}

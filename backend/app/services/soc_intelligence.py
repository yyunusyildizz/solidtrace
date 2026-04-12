
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import text

from app.api.websockets import broadcast_command

logger = logging.getLogger("SolidTrace.SOCIntelligence")


@dataclass
class EntityRiskUpdate:
    entity_type: str
    entity_key: str
    applied_risk: int
    new_risk_score: int
    status: str


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _safe_str(value: object | None, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value)


def _alert_value(alert_like: Any, field: str, fallback: Any = None) -> Any:
    if isinstance(alert_like, dict):
        return alert_like.get(field, fallback)
    return getattr(alert_like, field, fallback)


def _alert_text(alert_like: Any) -> str:
    parts = [
        _safe_str(_alert_value(alert_like, "rule"), ""),
        _safe_str(_alert_value(alert_like, "details"), ""),
        _safe_str(_alert_value(alert_like, "command_line"), ""),
        _safe_str(_alert_value(alert_like, "type"), ""),
    ]
    return " ".join([p for p in parts if p]).lower()


def _alert_created_at(alert_like: Any) -> Optional[datetime]:
    raw = _alert_value(alert_like, "created_at")
    if not raw:
        return None
    try:
        dt = raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _normalize_entity_key(value: str) -> str:
    return value.strip().lower()


def _risk_status(score: int) -> str:
    if score >= 250:
        return "compromised"
    if score >= 150:
        return "high_risk"
    if score >= 70:
        return "elevated"
    return "normal"


def _entity_multiplier(entity_type: str) -> float:
    if entity_type == "host":
        return 0.8
    if entity_type == "user":
        return 0.7
    return 0.5


def _has_any(text: str, markers: list[str]) -> bool:
    return any(m in text for m in markers)


def detect_credential_access(alerts: list[Any]) -> bool:
    blob = " || ".join(_alert_text(a) for a in alerts)
    return _has_any(blob, ["lsass", "mimikatz", "sekurlsa", "logonpasswords", "procdump.exe -ma lsass", "credential dumping"])


def detect_lateral_movement(alerts: list[Any]) -> bool:
    blob = " || ".join(_alert_text(a) for a in alerts)
    return _has_any(blob, ["psexec", "paexec", "wmiexec", "admin$", "remote service", "smbexec"])


def detect_execution(alerts: list[Any]) -> bool:
    blob = " || ".join(_alert_text(a) for a in alerts)
    return _has_any(blob, ["wmic", "process call create", "/node:", "powershell", "-enc", "invoke-webrequest", "downloadstring"])


def detect_persistence(alerts: list[Any]) -> bool:
    blob = " || ".join(_alert_text(a) for a in alerts)
    return _has_any(blob, ["schtasks", "scheduled task", "run key", "currentversion\\run", "autorun"])


def detect_ransomware(alerts: list[Any]) -> bool:
    blob = " || ".join(_alert_text(a) for a in alerts)
    return _has_any(blob, ["ransomware", "encrypt", "vssadmin delete shadows", "wbadmin delete catalog"])


def calculate_confidence(alerts: list[Any]) -> str:
    score = 0
    if detect_credential_access(alerts):
        score += 40
    if detect_lateral_movement(alerts):
        score += 30
    if detect_execution(alerts):
        score += 15
    if detect_persistence(alerts):
        score += 10
    if len(alerts) >= 3:
        score += 15
    if len({_safe_str(_alert_value(a, "hostname"), "") for a in alerts if _safe_str(_alert_value(a, "hostname"), "")}) >= 2:
        score += 10
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def build_attack_timeline(alerts: list[Any], max_gap_minutes: int = 15) -> list[dict[str, Any]]:
    ordered = sorted(
        [a for a in alerts if _alert_created_at(a) is not None],
        key=lambda a: _alert_created_at(a),
    )
    chain: list[dict[str, Any]] = []
    for idx, alert in enumerate(ordered):
        created_at = _alert_created_at(alert)
        prev = ordered[idx - 1] if idx > 0 else None
        gap_seconds = None
        linked = False
        if prev is not None:
            prev_dt = _alert_created_at(prev)
            gap = created_at - prev_dt
            gap_seconds = int(gap.total_seconds())
            linked = gap <= timedelta(minutes=max_gap_minutes)

        chain.append(
            {
                "step": idx + 1,
                "timestamp": created_at.isoformat() if created_at else None,
                "rule": _safe_str(_alert_value(alert, "rule"), "unknown"),
                "severity": _safe_str(_alert_value(alert, "severity"), "INFO").upper(),
                "risk_score": int(_alert_value(alert, "risk_score", 0) or 0),
                "hostname": _safe_str(_alert_value(alert, "hostname"), "unknown-host"),
                "username": _safe_str(_alert_value(alert, "username"), "unknown-user"),
                "linked_to_previous": linked,
                "gap_seconds_from_previous": gap_seconds,
            }
        )
    return chain


def resolve_campaign_advanced(alerts: list[Any]) -> tuple[str, str, int]:
    has_credential = detect_credential_access(alerts)
    has_lateral = detect_lateral_movement(alerts)
    has_execution = detect_execution(alerts)
    has_persist = detect_persistence(alerts)
    has_ransom = detect_ransomware(alerts)
    max_risk = max((int(_alert_value(a, "risk_score", 0) or 0) for a in alerts), default=0)

    if has_ransom:
        return "impact_ransomware", "CRITICAL", max(95, max_risk)

    if has_credential and (has_lateral or has_execution):
        return "credential_access", "CRITICAL", max(90, max_risk)

    if has_credential:
        return "credential_access", "HIGH", max(80, max_risk)

    if has_lateral and has_execution:
        return "lateral_movement", "HIGH", max(75, max_risk)

    if has_lateral:
        return "lateral_movement", "HIGH", max(70, max_risk)

    if has_persist and has_execution:
        return "persistence", "HIGH", max(65, max_risk)

    if has_execution:
        return "malicious_execution", "HIGH" if max_risk >= 70 else "WARNING", max_risk

    return "generic_activity", "INFO", max(5, max_risk)


def get_global_threat_level(db) -> int:
    try:
        row = db.execute(
            text(
                """
                SELECT value_int
                FROM system_state
                WHERE key = 'global_threat_level'
                LIMIT 1
                """
            )
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception:
        logger.warning("global_threat_level_read_failed", exc_info=True)
        return 0


def increase_global_threat_level(db, amount: int, reason: str) -> int:
    amount = max(0, int(amount or 0))
    try:
        current = get_global_threat_level(db)
        new_value = min(current + amount, 1000)

        db.execute(
            text(
                """
                INSERT INTO system_state (key, value_int, value_json, updated_at)
                VALUES ('global_threat_level', :value_int, :value_json, NOW())
                ON CONFLICT (key)
                DO UPDATE SET
                    value_int = EXCLUDED.value_int,
                    value_json = EXCLUDED.value_json,
                    updated_at = EXCLUDED.updated_at
                """
            ),
            {
                "value_int": new_value,
                "value_json": json.dumps({"reason": reason, "delta": amount}),
            },
        )
        db.commit()
        return new_value
    except Exception:
        logger.warning("global_threat_level_write_failed", exc_info=True)
        db.rollback()
        return get_global_threat_level(db)


def get_or_create_entity_profile(db, *, entity_type: str, entity_key: str):
    norm_key = _normalize_entity_key(entity_key)
    row = db.execute(
        text(
            """
            SELECT entity_type, entity_key, risk_score, anomaly_score, status, last_seen_at, last_incident_family
            FROM entity_profiles
            WHERE entity_type = :entity_type AND entity_key = :entity_key
            LIMIT 1
            """
        ),
        {"entity_type": entity_type, "entity_key": norm_key},
    ).mappings().first()

    if row:
        return dict(row)

    db.execute(
        text(
            """
            INSERT INTO entity_profiles (
                entity_type, entity_key, risk_score, anomaly_score, status, last_seen_at, last_incident_family, created_at, updated_at
            )
            VALUES (
                :entity_type, :entity_key, 0, 0, 'normal', NOW(), NULL, NOW(), NOW()
            )
            """
        ),
        {"entity_type": entity_type, "entity_key": norm_key},
    )
    db.commit()

    return {
        "entity_type": entity_type,
        "entity_key": norm_key,
        "risk_score": 0,
        "anomaly_score": 0,
        "status": "normal",
        "last_seen_at": _now_utc().isoformat(),
        "last_incident_family": None,
    }


def update_entity_profile(
    db,
    *,
    entity_type: str,
    entity_key: str,
    risk_delta: int,
    incident_family: Optional[str] = None,
) -> EntityRiskUpdate:
    profile = get_or_create_entity_profile(db, entity_type=entity_type, entity_key=entity_key)
    current_score = int(profile.get("risk_score") or 0)
    new_score = max(0, current_score + int(risk_delta or 0))
    status = _risk_status(new_score)

    db.execute(
        text(
            """
            UPDATE entity_profiles
            SET
                risk_score = :risk_score,
                status = :status,
                last_seen_at = NOW(),
                last_incident_family = COALESCE(:incident_family, last_incident_family),
                updated_at = NOW()
            WHERE entity_type = :entity_type AND entity_key = :entity_key
            """
        ),
        {
            "risk_score": new_score,
            "status": status,
            "incident_family": incident_family,
            "entity_type": entity_type,
            "entity_key": _normalize_entity_key(entity_key),
        },
    )
    db.commit()

    return EntityRiskUpdate(
        entity_type=entity_type,
        entity_key=_normalize_entity_key(entity_key),
        applied_risk=int(risk_delta or 0),
        new_risk_score=new_score,
        status=status,
    )


def propagate_risk(db, *, alert: Any, incident: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    risk = int(_alert_value(alert, "risk_score", 0) or 0)
    username = _safe_str(_alert_value(alert, "username"), "").strip()
    hostname = _safe_str(_alert_value(alert, "hostname"), "").strip()
    incident_family = incident.get("campaign_family") if isinstance(incident, dict) else None

    updates = []

    try:
        if username:
            user_delta = int(round(risk * _entity_multiplier("user")))
            updates.append(
                update_entity_profile(
                    db,
                    entity_type="user",
                    entity_key=username,
                    risk_delta=user_delta,
                    incident_family=incident_family,
                ).__dict__
            )

        if hostname:
            host_delta = int(round(risk * _entity_multiplier("host")))
            updates.append(
                update_entity_profile(
                    db,
                    entity_type="host",
                    entity_key=hostname,
                    risk_delta=host_delta,
                    incident_family=incident_family,
                ).__dict__
            )

        text_blob = _alert_text(alert)
        threat_delta = 0
        if "lsass" in text_blob or "mimikatz" in text_blob:
            threat_delta += 15
        if "psexec" in text_blob or "wmiexec" in text_blob:
            threat_delta += 10
        if "wmic" in text_blob or "powershell" in text_blob:
            threat_delta += 5

        threat_level = increase_global_threat_level(db, threat_delta, reason=_safe_str(incident_family, "alert_propagation")) if threat_delta > 0 else get_global_threat_level(db)

        return {
            "updates": updates,
            "global_threat_level": threat_level,
        }
    except Exception:
        logger.warning("risk_propagation_failed", exc_info=True)
        db.rollback()
        return {"updates": [], "global_threat_level": get_global_threat_level(db)}


def evaluate_incident_intelligence(alerts: list[Any]) -> dict[str, Any]:
    campaign_family, severity, suggested_priority = resolve_campaign_advanced(alerts)
    confidence = calculate_confidence(alerts)
    timeline = build_attack_timeline(alerts)

    hosts = sorted({_safe_str(_alert_value(a, "hostname"), "") for a in alerts if _safe_str(_alert_value(a, "hostname"), "")})
    users = sorted({_safe_str(_alert_value(a, "username"), "") for a in alerts if _safe_str(_alert_value(a, "username"), "")})

    return {
        "campaign_family": campaign_family,
        "severity": severity,
        "priority": suggested_priority,
        "confidence": confidence,
        "timeline": timeline,
        "affected_hosts": hosts,
        "users": users,
        "has_credential_access": detect_credential_access(alerts),
        "has_lateral_movement": detect_lateral_movement(alerts),
        "has_execution": detect_execution(alerts),
        "has_persistence": detect_persistence(alerts),
        "has_ransomware": detect_ransomware(alerts),
    }


def auto_response(incident: dict[str, Any], tenant_id: Optional[str] = None) -> dict[str, Any]:
    executed: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    hosts = list(dict.fromkeys(incident.get("affected_hosts") or []))
    campaign = _safe_str(incident.get("campaign_family"), "")
    severity = _safe_str(incident.get("severity"), "INFO").upper()

    def _dispatch(action: str, hostname: str, **kwargs):
        command_id = f"soc-auto-{action.lower()}-{uuid.uuid4().hex[:8]}"
        coro = broadcast_command(
            action,
            hostname,
            command_id=command_id,
            requested_by="soc-intelligence",
            tenant_id=tenant_id,
            incident_id=incident.get("id"),
            **kwargs,
        )
        try:
            asyncio.get_running_loop().create_task(coro)
        except RuntimeError:
            asyncio.run(coro)

    try:
        if severity == "CRITICAL" and campaign in {"credential_access", "impact_ransomware"}:
            for host in hosts:
                _dispatch("ISOLATE_HOST", host)
                executed.append(f"isolate:{host}")
        else:
            skipped.append("critical_auto_isolation_not_triggered")

        if campaign in {"credential_access", "lateral_movement", "malicious_execution"}:
            for host in hosts:
                _dispatch("ANALYZE_HOST", host)
                executed.append(f"analyze:{host}")
        else:
            skipped.append("host_analysis_not_required")
    except Exception as exc:
        errors.append(str(exc))
        logger.warning("auto_response_failed", exc_info=True)

    return {
        "executed": executed,
        "skipped": skipped,
        "errors": errors,
    }

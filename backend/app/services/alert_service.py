from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.database.db_manager import AlertModel

logger = logging.getLogger("SolidTrace.AlertService")

SIGMA_PREFIX = "SIGMA:"
BLOCKED_SIGMA_TYPES = {"SIGMA_ALERT", "SIGMA_SIGNAL"}

NOISY_SIGMA_RULES = {
    "SIGMA:HackTool - Mimikatz Execution",
    "SIGMA:PowerShell Download and Execution Cradles",
    "SIGMA:WMIC Remote Command Execution",
    "SIGMA:New User Created Via Net.EXE",
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recent_cutoff(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def _should_block_alert(event_data: dict[str, Any], score: int, rule: str, severity: str) -> bool:
    event_type = str(event_data.get("type") or "").upper()
    command_line = str(event_data.get("command_line") or "").strip()
    details = str(event_data.get("details") or "").strip()
    hostname = str(event_data.get("hostname") or "")
    text = f"{details} {command_line}".lower()

    if event_type in BLOCKED_SIGMA_TYPES:
        logger.warning("ALERT_SERVICE_SIGMA_TYPE_BLOCKED type=%s rule=%s", event_type, rule)
        return True

    if str(rule or "").startswith(SIGMA_PREFIX):
        logger.warning("ALERT_SERVICE_SIGMA_RULE_BLOCKED rule=%s", rule)
        return True

    if not hostname:
        logger.warning("ALERT_SERVICE_NO_HOST_BLOCKED rule=%s", rule)
        return True

    if not text:
        logger.warning("ALERT_SERVICE_EMPTY_TEXT_BLOCKED rule=%s", rule)
        return True

    if int(score or 0) < 50:
        logger.warning("ALERT_SERVICE_LOW_SCORE_BLOCKED rule=%s score=%s", rule, score)
        return True

    if event_type in {"PROCESS_START", "PROCESS_CREATED", "PROCESS_CREATE_EVT"} and not command_line:
        logger.warning("ALERT_SERVICE_NO_CMD_PROCESS_BLOCKED type=%s rule=%s", event_type, rule)
        return True

    # Extra hard stop for legacy noisy Sigma names if they somehow leak in.
    if rule in NOISY_SIGMA_RULES:
        logger.warning("ALERT_SERVICE_NOISY_SIGMA_BLOCKED rule=%s", rule)
        return True

    if "mimikatz" in str(rule or "").lower() and not any(x in text for x in ["sekurlsa", "logonpasswords", "lsass"]):
        logger.warning("ALERT_SERVICE_FAKE_MIMIKATZ_BLOCKED rule=%s", rule)
        return True

    if "yol:" in text and ".exe" in text and not any(x in text for x in ["powershell", "cmd.exe", "wmic", "rundll32", "psexec", "paexec"]):
        logger.warning("ALERT_SERVICE_BENIGN_PATH_BLOCKED rule=%s", rule)
        return True

    if "eventid:4672" in text and "nt authority" in text and "system" in text:
        logger.warning("ALERT_SERVICE_SPECIAL_LOGON_NOISE_BLOCKED rule=%s", rule)
        return True

    return False


def find_merge_candidate(
    db,
    *,
    hostname: Optional[str],
    rule: Optional[str],
    tenant_id: Optional[str],
    window_minutes: int = 10,
):
    query = db.query(AlertModel).filter(
        AlertModel.hostname == hostname,
        AlertModel.rule == rule,
        AlertModel.status == "open",
        AlertModel.created_at >= _recent_cutoff(window_minutes),
    )

    if hasattr(AlertModel, "tenant_id"):
        if tenant_id is None:
            query = query.filter(AlertModel.tenant_id.is_(None))
        else:
            query = query.filter(AlertModel.tenant_id == tenant_id)

    return query.order_by(AlertModel.created_at.desc()).first()


def create_or_merge_alert(
    db,
    event_data: dict[str, Any],
    score: int,
    rule: str,
    severity: str,
    tenant_id: Optional[str],
    *,
    merge_window_minutes: int = 10,
):
    if _should_block_alert(event_data, score, rule, severity):
        return None, False

    existing = find_merge_candidate(
        db,
        hostname=event_data.get("hostname"),
        rule=rule,
        tenant_id=tenant_id,
        window_minutes=merge_window_minutes,
    )

    if existing:
        existing.risk_score = max(int(existing.risk_score or 0), int(score or 0))
        existing.severity = severity or existing.severity
        existing.details = event_data.get("details") or existing.details
        existing.command_line = event_data.get("command_line") or existing.command_line
        existing.pid = event_data.get("pid") or existing.pid
        existing.serial = event_data.get("serial") or existing.serial
        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing, True

    alert = AlertModel(
        id=str(uuid.uuid4()),
        created_at=utcnow_iso(),
        hostname=event_data.get("hostname"),
        username=event_data.get("user"),
        type=event_data.get("type"),
        risk_score=int(score or 0),
        rule=rule,
        severity=severity or "INFO",
        details=event_data.get("details"),
        command_line=event_data.get("command_line"),
        pid=event_data.get("pid"),
        serial=event_data.get("serial"),
        tenant_id=tenant_id,
        status="open",
        analyst_note=None,
        resolved_at=None,
        resolved_by=None,
        assigned_to=None,
        assigned_at=None,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert, False


def create_alert(
    db,
    event_data: dict[str, Any],
    score: int,
    rule: str,
    severity: str,
    tenant_id: Optional[str],
):
    alert, _ = create_or_merge_alert(
        db,
        event_data=event_data,
        score=score,
        rule=rule,
        severity=severity,
        tenant_id=tenant_id,
    )
    return alert

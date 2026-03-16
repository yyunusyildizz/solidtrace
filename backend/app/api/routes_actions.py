"""
app.api.routes_actions
======================
Agent komutları ve event ingest endpoint'leri
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status

from app.api.websockets import broadcast, broadcast_command
from app.core.security import (
    get_current_tenant_id,
    require_role,
    verify_agent_request,
)
from app.database.db_manager import SessionLocal, AlertModel, RuleModel, write_audit
from app.schemas.models import ActionRequest, EventBase, HashReport
from app.services.ai_analysis import perform_groq_analysis
from app.services.detection_queue import DetectionQueueService
from app.services.threat_intel import process_threat_intel

logger = logging.getLogger("SolidTrace.Actions")
router = APIRouter(tags=["actions"])

_correlator = None
_sigma_engine = None
_ueba_engine = None
_cef_output = None
_queue_service = DetectionQueueService(worker_name="ingest-queue")

MAX_BATCH = int(os.getenv("INGEST_MAX_BATCH", "100"))
MAX_HOSTNAME_LEN = int(os.getenv("INGEST_MAX_HOSTNAME_LEN", "255"))
MAX_USER_LEN = int(os.getenv("INGEST_MAX_USER_LEN", "128"))
MAX_TYPE_LEN = int(os.getenv("INGEST_MAX_TYPE_LEN", "128"))
MAX_DETAILS_LEN = int(os.getenv("INGEST_MAX_DETAILS_LEN", "4000"))
MAX_CMD_LEN = int(os.getenv("INGEST_MAX_CMD_LEN", "2000"))
MAX_SERIAL_LEN = int(os.getenv("INGEST_MAX_SERIAL_LEN", "255"))
MAX_SEVERITY_LEN = int(os.getenv("INGEST_MAX_SEVERITY_LEN", "32"))

MIN_ALERT_SCORE = int(os.getenv("MIN_ALERT_SCORE", "50"))
ALLOW_LOCAL_PROCESS_ENUM = os.getenv("ALLOW_LOCAL_PROCESS_ENUM", "false").lower() == "true"

_EVENT_DEDUP_CACHE: dict[str, float] = {}
_EVENT_DEDUP_WINDOW_SECONDS = int(os.getenv("EVENT_DEDUP_WINDOW_SECONDS", "20"))
_EVENT_DEDUP_MAX_ITEMS = int(os.getenv("EVENT_DEDUP_MAX_ITEMS", "10000"))


def set_engines(correlator, sigma, ueba, cef):
    global _correlator, _sigma_engine, _ueba_engine, _cef_output
    _correlator = correlator
    _sigma_engine = sigma
    _ueba_engine = ueba
    _cef_output = cef


STATIC_RULES = [
    ("usb", 90, "USB Device Activity", "HIGH"),
    ("ransomware", 100, "Ransomware Alert", "CRITICAL"),
    ("mimikatz", 95, "Credential Dumping", "CRITICAL"),
    ("lsass", 90, "LSASS Access", "CRITICAL"),
    ("psexec", 75, "Lateral Movement (PsExec)", "HIGH"),
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _utcnow().isoformat()


def _new_command_id(action: str, hostname: str) -> str:
    return f"cmd-{action.lower()}-{hostname.lower()}-{uuid.uuid4().hex[:12]}"


def _to_str(value: Any, max_len: int, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()[:max_len]


def _safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_request_id(request: Optional[Request]) -> str:
    if request is None:
        return "n/a"
    return getattr(request.state, "request_id", "n/a")


def _safe_action_request_dict(req: ActionRequest) -> Dict[str, Any]:
    if hasattr(req, "model_dump"):
        return req.model_dump()
    return req.dict()


def _cleanup_event_dedup_cache() -> None:
    now = time.time()
    expired = [k for k, v in _EVENT_DEDUP_CACHE.items() if v <= now]
    for k in expired:
        _EVENT_DEDUP_CACHE.pop(k, None)

    if len(_EVENT_DEDUP_CACHE) > _EVENT_DEDUP_MAX_ITEMS:
        for key in list(_EVENT_DEDUP_CACHE.keys())[:1000]:
            _EVENT_DEDUP_CACHE.pop(key, None)


def _event_fingerprint(event_data: Dict[str, Any], tenant_id: Optional[str]) -> str:
    raw = "|".join(
        [
            str(tenant_id or ""),
            str(event_data.get("hostname") or ""),
            str(event_data.get("type") or ""),
            str(event_data.get("user") or ""),
            str(event_data.get("pid") or ""),
            str(event_data.get("command_line") or "")[:300],
            str(event_data.get("details") or "")[:500],
            str(event_data.get("serial") or ""),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_duplicate_event(event_data: Dict[str, Any], tenant_id: Optional[str]) -> bool:
    _cleanup_event_dedup_cache()

    fp = _event_fingerprint(event_data, tenant_id)
    now = time.time()
    exp = _EVENT_DEDUP_CACHE.get(fp)

    if exp and exp > now:
        return True

    _EVENT_DEDUP_CACHE[fp] = now + _EVENT_DEDUP_WINDOW_SECONDS
    return False


def _normalize_event(event: EventBase) -> Dict[str, Any]:
    return {
        "type": _to_str(event.type, MAX_TYPE_LEN),
        "hostname": _to_str(event.hostname, MAX_HOSTNAME_LEN),
        "user": _to_str(event.user, MAX_USER_LEN),
        "pid": _safe_int(event.pid),
        "details": _to_str(event.details, MAX_DETAILS_LEN),
        "command_line": _to_str(event.command_line, MAX_CMD_LEN),
        "serial": _to_str(event.serial, MAX_SERIAL_LEN),
        "severity": _to_str(event.severity or "INFO", MAX_SEVERITY_LEN, default="INFO").upper(),
        "timestamp": event.timestamp,
    }


def _normalize_runtime_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": _to_str(event_data.get("type"), MAX_TYPE_LEN),
        "hostname": _to_str(event_data.get("hostname"), MAX_HOSTNAME_LEN),
        "user": _to_str(event_data.get("user"), MAX_USER_LEN),
        "pid": _safe_int(event_data.get("pid")),
        "details": _to_str(event_data.get("details"), MAX_DETAILS_LEN),
        "command_line": _to_str(event_data.get("command_line"), MAX_CMD_LEN),
        "serial": _to_str(event_data.get("serial"), MAX_SERIAL_LEN),
        "severity": _to_str(
            event_data.get("severity") or "INFO",
            MAX_SEVERITY_LEN,
            default="INFO",
        ).upper(),
        "timestamp": event_data.get("timestamp"),
    }


def _query_rules_for_tenant(db, tenant_id: Optional[str]):
    query = db.query(RuleModel)
    if tenant_id and hasattr(RuleModel, "tenant_id"):
        query = query.filter(RuleModel.tenant_id == tenant_id)
    return query.all()


def _validated_hostname(hostname: Optional[str]) -> str:
    value = (hostname or "").strip()[:MAX_HOSTNAME_LEN]
    if not value:
        raise HTTPException(status_code=400, detail="hostname gerekli")
    return value


def _validated_pid(pid: Any) -> int:
    pid_value = _safe_int(pid)
    if pid_value is None or pid_value <= 0:
        raise HTTPException(status_code=400, detail="Geçerli bir pid gerekli")
    return pid_value


async def _write_action_audit(
    current_user: str,
    action: str,
    target: str,
    detail: str = "",
    tenant_id: Optional[str] = None,
) -> None:
    db = SessionLocal()
    try:
        await write_audit(
            db,
            current_user,
            action,
            target=target,
            detail=_to_str(detail, 1000),
            tenant_id=tenant_id,
        )
    finally:
        db.close()


def _build_alert_payload(alert: AlertModel) -> dict:
    if hasattr(alert, "to_dict"):
        return alert.to_dict()

    return {
        "id": alert.id,
        "created_at": alert.created_at,
        "hostname": alert.hostname,
        "username": alert.username,
        "type": alert.type,
        "risk_score": alert.risk_score,
        "rule": alert.rule,
        "severity": alert.severity,
        "details": alert.details,
        "command_line": alert.command_line,
        "pid": alert.pid,
        "serial": getattr(alert, "serial", None),
        "tenant_id": getattr(alert, "tenant_id", None),
        "status": getattr(alert, "status", "open"),
        "assigned_to": getattr(alert, "assigned_to", None),
        "analyst_note": getattr(alert, "analyst_note", None),
    }


@router.post("/api/v1/ingest")
async def ingest_event(
    events: List[EventBase],
    request: Request,
    tenant_id: str = Depends(verify_agent_request),
):
    if not events:
        raise HTTPException(status_code=400, detail="En az 1 event gerekli")

    if len(events) > MAX_BATCH:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch limiti aşıldı. Maks. {MAX_BATCH} event gönderilebilir.",
        )

    payloads = [_normalize_event(event) for event in events]
    queued = _queue_service.enqueue_many(tenant_id, payloads)

    logger.info(
        "ingest_batch_queued request_id=%s tenant=%s event_count=%s",
        _get_request_id(request),
        tenant_id,
        queued,
    )
    return {"status": "queued", "count": queued}


async def process_single_event(event_data: dict, tenant_id: Optional[str] = None):
    db = SessionLocal()
    try:
        event_data = _normalize_runtime_event(event_data)

        if _is_duplicate_event(event_data, tenant_id):
            logger.info(
                "event_deduplicated tenant=%s host=%s type=%s pid=%s",
                tenant_id,
                event_data.get("hostname"),
                event_data.get("type"),
                event_data.get("pid"),
            )
            return

        active_rules = _query_rules_for_tenant(db, tenant_id)

        raw_details = event_data.get("details") or ""
        if isinstance(raw_details, bytes):
            try:
                raw_details = raw_details.decode("utf-8")
            except UnicodeDecodeError:
                raw_details = raw_details.decode("windows-1254", errors="replace")

        final_details = str(raw_details).lstrip("\ufeff").strip()[:MAX_DETAILS_LEN]
        if event_data.get("serial"):
            serial_fragment = f"\n🔍 Donanım Kimliği: {event_data['serial']}"
            final_details = f"{final_details}{serial_fragment}"[:MAX_DETAILS_LEN]

        score = 10
        rule_name = "Normal Activity"
        current_sev = event_data.get("severity") or "INFO"

        full_text = (
            f"{final_details} "
            f"{event_data.get('command_line') or ''} "
            f"{event_data.get('type') or ''}"
        ).lower()

        matched = False
        for rule in active_rules:
            keyword = (rule.keyword or "").lower()
            if keyword and keyword in full_text:
                score = int(rule.risk_score or 0)
                rule_name = rule.name or "Custom Rule Match"
                current_sev = (rule.severity or current_sev).upper()
                matched = True
                break

        if not matched:
            for keyword, s, name, sev in STATIC_RULES:
                if keyword in full_text:
                    score = s
                    rule_name = name
                    current_sev = sev
                    break

        corr_event = {
            "type": event_data.get("type"),
            "hostname": event_data.get("hostname") or "unknown",
            "user": event_data.get("user") or "unknown",
            "details": final_details,
            "timestamp": event_data.get("timestamp") or _now_iso(),
            "severity": current_sev,
            "pid": event_data.get("pid") or 0,
            "risk": {"score": score, "level": current_sev},
            "tenant_id": tenant_id,
            "rule": rule_name,
            "description": final_details,
            "command_line": event_data.get("command_line") or "",
            "serial": event_data.get("serial") or "",
        }

        sigma_promoted = False

        if _correlator:
            await _correlator.process_event(corr_event)

        if _sigma_engine:
            try:
                sigma_matches = await _sigma_engine.process_event(
                    {**corr_event, "details": final_details}
                )
                if sigma_matches:
                    top_sigma = max(
                        sigma_matches,
                        key=lambda m: int(m.get("risk", {}).get("score", 0) or 0),
                    )
                    sigma_score = int(top_sigma.get("risk", {}).get("score", 75) or 75)
                    sigma_sev = str(top_sigma.get("severity", "HIGH")).upper()
                    sigma_rule = str(top_sigma.get("rule", "Sigma Detection Match")).strip()

                    score = max(score, sigma_score)
                    if current_sev != "CRITICAL":
                        current_sev = sigma_sev if sigma_sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "HIGH"
                    if rule_name == "Normal Activity":
                        rule_name = sigma_rule

                    sigma_promoted = True
            except Exception as exc:
                logger.warning("sigma_processing_failed tenant=%s error=%s", tenant_id, exc)

        if _ueba_engine:
            asyncio.create_task(_ueba_engine.process_event(corr_event))

        if _cef_output:
            _cef_output.send({**corr_event, "timestamp": event_data.get("timestamp")})

        if score < MIN_ALERT_SCORE:
            logger.info(
                "event_below_alert_threshold tenant=%s host=%s type=%s risk_score=%s sigma_promoted=%s",
                tenant_id,
                event_data.get("hostname"),
                event_data.get("type"),
                score,
                sigma_promoted,
            )
            return

        alert = AlertModel(
            id=str(uuid.uuid4()),
            created_at=_now_iso(),
            hostname=event_data.get("hostname"),
            username=event_data.get("user"),
            type=event_data.get("type"),
            risk_score=score,
            rule=rule_name,
            severity=current_sev,
            details=final_details,
            command_line=event_data.get("command_line"),
            pid=event_data.get("pid"),
            serial=event_data.get("serial"),
            tenant_id=tenant_id,
            status="open",
            analyst_note=None,
            resolved_at=None,
            resolved_by=None,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        await broadcast(
            {
                "type": "alert",
                "timestamp": _now_iso(),
                "data": _build_alert_payload(alert),
            }
        )

        logger.info(
            "alert_created tenant=%s host=%s type=%s risk_score=%s rule=%s sigma_promoted=%s",
            tenant_id,
            event_data.get("hostname"),
            event_data.get("type"),
            score,
            rule_name,
            sigma_promoted,
        )

    except Exception as exc:
        db.rollback()
        logger.exception("queue_event_processing_failed tenant=%s error=%s", tenant_id, exc)
        raise
    finally:
        db.close()


@router.post("/api/v1/report_hash")
async def report_hash(
    report: HashReport,
    bg: BackgroundTasks,
    request: Request,
    tenant_id: str = Depends(verify_agent_request),
):
    logger.info(
        "hash_report_received request_id=%s tenant=%s file_hash=%s",
        _get_request_id(request),
        tenant_id,
        report.file_hash,
    )
    bg.add_task(process_threat_intel, report, broadcast)
    return {"status": "analyzing", "hash": report.file_hash}


@router.post("/api/actions/analyze")
async def analyze_host(
    req: ActionRequest,
    bg: BackgroundTasks,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    hostname = _validated_hostname(req.hostname)
    command_id = _new_command_id("ANALYZE_HOST", hostname)

    await broadcast_command(
        "ANALYZE_HOST",
        hostname,
        command_id=command_id,
        requested_by=current_user,
        tenant_id=tenant_id,
        rule=_to_str(req.rule, 255),
    )

    logger.info(
        "action_analyze_host request_id=%s tenant=%s host=%s user=%s rule=%s command_id=%s",
        _get_request_id(request),
        tenant_id,
        hostname,
        current_user,
        _to_str(req.rule, 255),
        command_id,
    )

    bg.add_task(perform_groq_analysis, _safe_action_request_dict(req), broadcast)
    await _write_action_audit(
        current_user=current_user,
        action="ANALYZE_HOST",
        target=hostname,
        detail=req.rule or "",
        tenant_id=tenant_id,
    )
    return {
        "status": "sent",
        "action": "ANALYZE_HOST",
        "command_id": command_id,
        "message": "AI analizi ve agent komutu başlatıldı",
    }


@router.post("/api/actions/kill")
async def kill_process(
    req: ActionRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    hostname = _validated_hostname(req.hostname)
    pid = _validated_pid(req.pid)
    command_id = _new_command_id("KILL_PROCESS", hostname)

    await broadcast_command(
        "KILL_PROCESS",
        hostname,
        command_id=command_id,
        requested_by=current_user,
        tenant_id=tenant_id,
        target_pid=pid,
    )

    logger.warning(
        "action_kill_process request_id=%s tenant=%s host=%s pid=%s user=%s command_id=%s",
        _get_request_id(request),
        tenant_id,
        hostname,
        pid,
        current_user,
        command_id,
    )

    await _write_action_audit(
        current_user=current_user,
        action="KILL_PROCESS",
        target=f"{hostname}:PID{pid}",
        detail=req.rule or "",
        tenant_id=tenant_id,
    )
    return {"status": "sent", "action": "KILL_PROCESS", "command_id": command_id}


@router.post("/api/actions/isolate")
async def isolate_host(
    req: ActionRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    hostname = _validated_hostname(req.hostname)
    command_id = _new_command_id("ISOLATE_HOST", hostname)

    await broadcast_command(
        "ISOLATE_HOST",
        hostname,
        command_id=command_id,
        requested_by=current_user,
        tenant_id=tenant_id,
    )

    logger.warning(
        "action_isolate_host request_id=%s tenant=%s host=%s user=%s command_id=%s",
        _get_request_id(request),
        tenant_id,
        hostname,
        current_user,
        command_id,
    )

    await _write_action_audit(
        current_user=current_user,
        action="ISOLATE_HOST",
        target=hostname,
        detail=req.rule or "",
        tenant_id=tenant_id,
    )
    return {"status": "sent", "action": "ISOLATE_HOST", "command_id": command_id}


@router.post("/api/actions/unisolate")
async def unisolate_host(
    req: ActionRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    hostname = _validated_hostname(req.hostname)
    logger.warning("### UNISOLATE ROUTE HIT ### hostname=%s", hostname)
    command_id = _new_command_id("UNISOLATE_HOST", hostname)

    await broadcast_command(
        "UNISOLATE_HOST",
        hostname,
        command_id=command_id,
        requested_by=current_user,
        tenant_id=tenant_id,
    )

    logger.warning(
        "action_unisolate_host request_id=%s tenant=%s host=%s user=%s command_id=%s",
        _get_request_id(request),
        tenant_id,
        hostname,
        current_user,
        command_id,
    )

    await _write_action_audit(
        current_user=current_user,
        action="UNISOLATE_HOST",
        target=hostname,
        detail=req.rule or "",
        tenant_id=tenant_id,
    )
    return {"status": "sent", "action": "UNISOLATE_HOST", "command_id": command_id}


@router.post("/api/actions/usb_disable")
async def usb_disable(
    req: ActionRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    hostname = _validated_hostname(req.hostname)
    command_id = _new_command_id("USB_DISABLE", hostname)

    await broadcast_command(
        "USB_DISABLE",
        hostname,
        command_id=command_id,
        requested_by=current_user,
        tenant_id=tenant_id,
    )

    logger.warning(
        "action_usb_disable request_id=%s tenant=%s host=%s user=%s command_id=%s",
        _get_request_id(request),
        tenant_id,
        hostname,
        current_user,
        command_id,
    )

    await _write_action_audit(
        current_user=current_user,
        action="USB_DISABLE",
        target=hostname,
        detail=req.rule or "",
        tenant_id=tenant_id,
    )
    return {"status": "sent", "action": "USB_DISABLE", "command_id": command_id}


@router.post("/api/actions/usb_enable")
async def usb_enable(
    req: ActionRequest,
    request: Request,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    hostname = _validated_hostname(req.hostname)
    command_id = _new_command_id("USB_ENABLE", hostname)

    await broadcast_command(
        "USB_ENABLE",
        hostname,
        command_id=command_id,
        requested_by=current_user,
        tenant_id=tenant_id,
    )

    logger.warning(
        "action_usb_enable request_id=%s tenant=%s host=%s user=%s command_id=%s",
        _get_request_id(request),
        tenant_id,
        hostname,
        current_user,
        command_id,
    )

    await _write_action_audit(
        current_user=current_user,
        action="USB_ENABLE",
        target=hostname,
        detail=req.rule or "",
        tenant_id=tenant_id,
    )
    return {"status": "sent", "action": "USB_ENABLE", "command_id": command_id}


@router.get("/api/v1/processes/{hostname}")
async def get_processes(
    hostname: str,
    request: Request,
    current_user: str = Depends(require_role("admin")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    hostname = _validated_hostname(hostname)

    local_names = {
        socket.gethostname().lower(),
        socket.gethostname().upper(),
        "localhost",
        "127.0.0.1",
    }

    if hostname.lower() in local_names or hostname.upper() in local_names:
        if not ALLOW_LOCAL_PROCESS_ENUM:
            raise HTTPException(status_code=403, detail="Local process enumeration devre dışı")

        import psutil

        processes = []
        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_info", "status", "username", "cmdline"]
        ):
            try:
                info = proc.info
                processes.append(
                    {
                        "pid": info["pid"],
                        "name": (info.get("name") or "?")[:128],
                        "cpu": round(info.get("cpu_percent") or 0.0, 2),
                        "memory": round((info["memory_info"].rss if info["memory_info"] else 0) / 1024 / 1024, 1),
                        "status": (info.get("status") or "running")[:64],
                        "user": (info.get("username") or "SYSTEM")[:128],
                        "cmdline": " ".join((info.get("cmdline") or [])[:4])[:200],
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        processes.sort(key=lambda item: item["cpu"], reverse=True)

        logger.info(
            "process_list_requested request_id=%s tenant=%s host=%s user=%s source=%s process_count=%s",
            _get_request_id(request),
            tenant_id,
            hostname,
            current_user,
            "local",
            len(processes[:200]),
        )
        return {"hostname": hostname, "source": "local", "processes": processes[:200]}

    command_id = _new_command_id("SCAN_PROCESSES", hostname)

    await broadcast_command(
        "SCAN_PROCESSES",
        hostname,
        command_id=command_id,
        requested_by=current_user,
        tenant_id=tenant_id,
    )

    db = SessionLocal()
    try:
        cutoff = (_utcnow() - timedelta(seconds=120)).isoformat()

        query = db.query(AlertModel).filter(
            AlertModel.hostname == hostname,
            AlertModel.type == "PROCESS_CREATED",
            AlertModel.created_at >= cutoff,
        )

        if tenant_id and hasattr(AlertModel, "tenant_id"):
            query = query.filter(AlertModel.tenant_id == tenant_id)

        recent = query.order_by(AlertModel.created_at.desc()).limit(100).all()

        seen = set()
        processes = []
        for record in recent:
            if record.pid and record.pid not in seen:
                seen.add(record.pid)
                processes.append(
                    {
                        "pid": record.pid,
                        "name": (record.rule or record.type or "?")[:128],
                        "cpu": 0.0,
                        "memory": 0.0,
                        "status": "running",
                        "user": (record.username or "SYSTEM")[:128],
                        "cmdline": (record.command_line or "")[:200],
                    }
                )

        logger.info(
            "process_list_requested request_id=%s tenant=%s host=%s user=%s source=%s process_count=%s command_id=%s",
            _get_request_id(request),
            tenant_id,
            hostname,
            current_user,
            "db_recent",
            len(processes),
            command_id,
        )
        return {
            "hostname": hostname,
            "source": "db_recent",
            "command_id": command_id,
            "processes": processes,
        }
    finally:
        db.close()

@router.get("/api/commands")
async def list_command_executions(
    limit: int = 50,
    hostname: Optional[str] = None,
    request: Request = None,
    current_user: str = Depends(require_role("analyst")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    from app.database.db_manager import CommandExecutionModel

    db = SessionLocal()
    try:
        q = db.query(CommandExecutionModel)

        if tenant_id and hasattr(CommandExecutionModel, "tenant_id"):
            q = q.filter(CommandExecutionModel.tenant_id == tenant_id)

        if hostname:
            q = q.filter(CommandExecutionModel.target_hostname == hostname.strip())

        rows = (
            q.order_by(CommandExecutionModel.created_at.desc())
            .limit(max(1, min(limit, 200)))
            .all()
        )

        logger.info(
            "command_history_requested request_id=%s tenant=%s user=%s hostname=%s count=%s",
            _get_request_id(request),
            tenant_id,
            current_user,
            hostname,
            len(rows),
        )

        return [row.to_dict() for row in rows]
    finally:
        db.close()
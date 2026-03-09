"""
app.api.routes_actions
======================
Agent komutları ve event ingest endpoint'leri:
  /api/v1/ingest, /api/v1/report_hash
  /api/actions/kill, isolate, unisolate, usb_disable, usb_enable, analyze
  /api/v1/processes/{hostname}
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import desc

from app.api.websockets import broadcast, broadcast_command
from app.core.security import (
    get_current_user, verify_agent_key, verify_tenant_agent_key,
)
from app.database.db_manager import SessionLocal, AlertModel, RuleModel, write_audit
from app.schemas.models import ActionRequest, EventBase, HashReport
from app.services.ai_analysis import perform_groq_analysis
from app.services.threat_intel import process_threat_intel

logger = logging.getLogger("SolidTrace.Actions")
router = APIRouter(tags=["actions"])

# Korelasyon + Sigma + UEBA motorları — main.py'de init edilir, burada referans
_correlator   = None
_sigma_engine = None
_ueba_engine  = None
_cef_output   = None


def set_engines(correlator, sigma, ueba, cef):
    """main.py startup'ta çağrılır."""
    global _correlator, _sigma_engine, _ueba_engine, _cef_output
    _correlator   = correlator
    _sigma_engine = sigma
    _ueba_engine  = ueba
    _cef_output   = cef


# ---------------------------------------------------------------------------
# EVENT INGEST
# ---------------------------------------------------------------------------

STATIC_RULES = [
    ("usb",        90,  "USB Device Activity",       "HIGH"),
    ("ransomware", 100, "Ransomware Alert",           "CRITICAL"),
    ("mimikatz",   95,  "Credential Dumping",         "CRITICAL"),
    ("lsass",      90,  "LSASS Access",               "CRITICAL"),
    ("psexec",     75,  "Lateral Movement (PsExec)",  "HIGH"),
]


@router.post("/api/v1/ingest")
async def ingest_event(
    events:     List[EventBase],
    bg:         BackgroundTasks,
    agent_auth: dict = Depends(verify_tenant_agent_key),
):
    MAX_BATCH = 100
    if len(events) > MAX_BATCH:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch limiti aşıldı. Maks. {MAX_BATCH} event gönderilebilir.",
        )
    bg.add_task(_process_events_bg, list(events), agent_auth.get("tenant_id"))
    return {"status": "ok", "count": len(events)}


async def _process_events_bg(events: List[EventBase], tenant_id: Optional[str] = None):
    db = SessionLocal()
    try:
        active_rules = db.query(RuleModel).all()
        processed    = 0

        for event in events:
            # Encoding temizleme
            _raw = event.details or ""
            if isinstance(_raw, bytes):
                try:
                    _raw = _raw.decode("utf-8")
                except UnicodeDecodeError:
                    _raw = _raw.decode("windows-1254", errors="replace")
            final_details = _raw.lstrip("\ufeff").strip()
            if event.serial:
                final_details += f"\n🔍 Donanım Kimliği: {event.serial}"

            score       = 10
            rule_name   = "Normal Activity"
            current_sev = event.severity or "INFO"
            full_text   = f"{final_details} {event.command_line} {event.type}".lower()

            # 1. Dinamik kurallar (DB)
            matched = False
            for r in active_rules:
                if r.keyword.lower() in full_text:
                    score       = r.risk_score
                    rule_name   = r.name
                    current_sev = r.severity
                    matched     = True
                    break

            # 2. Statik fallback
            if not matched:
                for keyword, s, name, sev in STATIC_RULES:
                    if keyword in full_text:
                        score       = s
                        rule_name   = name
                        current_sev = sev
                        break

            alert = AlertModel(
                id=str(uuid.uuid4()),
                created_at=event.timestamp or datetime.now().isoformat(),
                hostname=event.hostname,
                username=event.user,
                type=event.type,
                risk_score=score,
                rule=rule_name,
                severity=current_sev,
                details=final_details,
                command_line=event.command_line,
                pid=event.pid,
                serial=event.serial,
                tenant_id=tenant_id,
            )
            db.add(alert)
            await broadcast({"type": "alert", "data": alert.to_dict()})

            corr_event = {
                "type": event.type, "hostname": event.hostname or "unknown",
                "user": event.user or "unknown", "details": final_details,
                "timestamp": event.timestamp or datetime.now().isoformat(),
                "severity": current_sev, "pid": event.pid or 0,
                "risk": {"score": score, "level": current_sev},
            }

            if _correlator:
                await _correlator.process_event(corr_event)
            if _sigma_engine:
                asyncio.create_task(_sigma_engine.process_event({
                    **corr_event, "details": final_details,
                }))
            if _ueba_engine:
                asyncio.create_task(_ueba_engine.process_event(corr_event))
            if _cef_output:
                _cef_output.send({**corr_event, "timestamp": event.timestamp})

            processed += 1

        db.commit()
        logger.info(f"📥 {processed} event işlendi")
    except Exception as e:
        db.rollback()
        logger.error(f"Ingest Hatası: {e}")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# HASH RAPORU (Tehdit İstihbaratı)
# ---------------------------------------------------------------------------

@router.post("/api/v1/report_hash")
async def report_hash(
    report:        HashReport,
    bg:            BackgroundTasks,
    authenticated: bool = Depends(verify_agent_key),
):
    bg.add_task(process_threat_intel, report, broadcast)
    return {"status": "analyzing", "hash": report.file_hash}


# ---------------------------------------------------------------------------
# AI ANALİZ
# ---------------------------------------------------------------------------

@router.post("/api/actions/analyze")
async def analyze_host(
    req:          ActionRequest,
    bg:           BackgroundTasks,
    current_user: str = Depends(get_current_user),
):
    await broadcast({
        "type":    "ACTION_LOG",
        "message": f"🔍 Analiz: {req.hostname} | Kural: {req.rule} | Kullanıcı: {current_user}",
    })
    bg.add_task(perform_groq_analysis, req.dict(), broadcast)
    return {"status": "started", "message": "AI analizi arka planda çalışıyor"}


# ---------------------------------------------------------------------------
# AGENT KOMUTLARI
# ---------------------------------------------------------------------------

@router.post("/api/actions/kill")
async def kill_process(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("KILL_PROCESS", req.hostname, target_pid=req.pid)
    logger.warning(f"⚠️  KILL: {req.hostname}:{req.pid} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "KILL_PROCESS",
                          target=f"{req.hostname}:PID{req.pid}", detail=req.rule or "")
    finally:
        db.close()
    return {"status": "sent", "action": "KILL_PROCESS"}


@router.post("/api/actions/isolate")
async def isolate_host(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("ISOLATE_HOST", req.hostname)
    logger.warning(f"🔒 İZOLASYON: {req.hostname} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "ISOLATE_HOST", target=req.hostname)
    finally:
        db.close()
    return {"status": "sent", "action": "ISOLATE_HOST"}


@router.post("/api/actions/unisolate")
async def unisolate_host(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("UNISOLATE_HOST", req.hostname)
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "UNISOLATE_HOST", target=req.hostname)
    finally:
        db.close()
    return {"status": "sent", "action": "UNISOLATE_HOST"}


@router.post("/api/actions/usb_disable")
async def usb_disable(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("USB_DISABLE", req.hostname)
    await broadcast({"type": "ACTION_LOG",
                     "message": f"🔌 USB Devre Dışı: {req.hostname} (by {current_user})"})
    logger.warning(f"⚠️  USB_DISABLE: {req.hostname} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "USB_DISABLE", target=req.hostname)
    finally:
        db.close()
    return {"status": "sent", "action": "USB_DISABLE"}


@router.post("/api/actions/usb_enable")
async def usb_enable(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("USB_ENABLE", req.hostname)
    await broadcast({"type": "ACTION_LOG",
                     "message": f"🔌 USB Aktif: {req.hostname} (by {current_user})"})
    logger.warning(f"⚠️  USB_ENABLE: {req.hostname} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "USB_ENABLE", target=req.hostname)
    finally:
        db.close()
    return {"status": "sent", "action": "USB_ENABLE"}


# ---------------------------------------------------------------------------
# PROCESS LİSTESİ
# ---------------------------------------------------------------------------

@router.get("/api/v1/processes/{hostname}")
async def get_processes(hostname: str, current_user: str = Depends(get_current_user)):
    import socket
    local_names = {
        socket.gethostname().lower(), "localhost", "127.0.0.1",
        socket.gethostname().upper(),
    }

    if hostname.lower() in local_names or hostname.upper() in local_names:
        import psutil
        processes = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent",
                                          "memory_info", "status", "username", "cmdline"]):
            try:
                info = proc.info
                processes.append({
                    "pid":     info["pid"],
                    "name":    info["name"] or "?",
                    "cpu":     round(info.get("cpu_percent") or 0.0, 2),
                    "memory":  round((info["memory_info"].rss if info["memory_info"] else 0) / 1024 / 1024, 1),
                    "status":  info.get("status") or "running",
                    "user":    info.get("username") or "SYSTEM",
                    "cmdline": " ".join((info.get("cmdline") or [])[:4]),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        processes.sort(key=lambda x: x["cpu"], reverse=True)
        return {"hostname": hostname, "source": "local", "processes": processes[:200]}

    db = SessionLocal()
    try:
        cutoff = (datetime.now() - timedelta(seconds=120)).isoformat()
        recent = (
            db.query(AlertModel)
            .filter(AlertModel.hostname == hostname,
                    AlertModel.type == "PROCESS_CREATED",
                    AlertModel.created_at >= cutoff)
            .order_by(AlertModel.created_at.desc())
            .limit(100)
            .all()
        )
        seen, processes = set(), []
        for r in recent:
            if r.pid and r.pid not in seen:
                seen.add(r.pid)
                processes.append({
                    "pid": r.pid, "name": r.rule or r.type,
                    "cpu": 0.0, "memory": 0.0, "status": "running",
                    "user": r.username or "SYSTEM",
                    "cmdline": (r.command_line or "")[:80],
                })
        await broadcast({"type": "COMMAND", "action": "SCAN_PROCESSES",
                         "target_hostname": hostname})
        return {"hostname": hostname, "source": "db_recent", "processes": processes}
    finally:
        db.close()

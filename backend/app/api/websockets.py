"""
app.api.websockets
==================
WebSocket connection management and broadcast helpers.
Frontend and agent clients are tracked separately.
Command lifecycle is persisted into DB.
Command results are also written into incident timeline when possible.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import WebSocket

from app.database.db_manager import (
    SessionLocal,
    create_command_execution,
    get_command_execution,
    update_command_execution,
)

logger = logging.getLogger("SolidTrace.WebSocket")

ACTIVE_CONNECTIONS: List[WebSocket] = []
AGENT_CONNECTIONS: Dict[str, WebSocket] = {}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_remove(ws: WebSocket) -> None:
    if ws in ACTIVE_CONNECTIONS:
        ACTIVE_CONNECTIONS.remove(ws)

    to_delete = [hostname for hostname, conn in AGENT_CONNECTIONS.items() if conn == ws]
    for hostname in to_delete:
        AGENT_CONNECTIONS.pop(hostname, None)


async def _send_to_connections(connections: List[WebSocket], payload: str) -> None:
    if not connections:
        return

    snapshot = list(connections)
    results = await asyncio.gather(
        *[ws.send_text(payload) for ws in snapshot],
        return_exceptions=True,
    )

    for ws, result in zip(snapshot, results):
        if isinstance(result, Exception):
            _safe_remove(ws)


async def broadcast(msg: Dict[str, Any]) -> None:
    payload = json.dumps(msg, default=str)

    await _send_to_connections(ACTIVE_CONNECTIONS, payload)

    if msg.get("type") == "COMMAND":
        await _send_to_connections(list(AGENT_CONNECTIONS.values()), payload)


async def _broadcast_command_event(
    command_id: str,
    hostname: str,
    action: str,
    status: str,
    *,
    success: bool | None = None,
    message: str | None = None,
    extra: Dict[str, Any] | None = None,
) -> None:
    payload = {
        "type": "COMMAND_EVENT",
        "timestamp": _utcnow_iso(),
        "command_id": command_id,
        "hostname": hostname,
        "action": action,
        "status": status,
        "success": success,
        "message": message,
        "data": extra or {},
    }
    await _send_to_connections(ACTIVE_CONNECTIONS, json.dumps(payload, default=str))


def _safe_json_loads(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            loaded = json.loads(value)
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {}
    return {}


def _append_incident_timeline_from_command_row(
    row: Any,
    *,
    event_type: str,
    actor: str,
    title: str,
    details: str,
) -> None:
    """
    CommandExecution row'dan incident_id / tenant_id çıkartıp
    incident timeline'a event yazar.
    import'u local yapıyoruz ki circular import oluşmasın.
    """
    if not row:
        return

    payload = _safe_json_loads(getattr(row, "result_payload", None))
    incident_id = payload.get("incident_id")
    tenant_id = getattr(row, "tenant_id", None)

    if not incident_id:
        return

    try:
        from app.services.incident_service import add_incident_timeline_event

        db = SessionLocal()
        try:
            add_incident_timeline_event(
                db,
                incident_id=incident_id,
                tenant_id=tenant_id,
                event_type=event_type,
                actor=actor,
                title=title,
                details=details,
            )
        finally:
            db.close()
    except Exception as exc:
        logger.warning(
            "incident_timeline_append_failed command_id=%s incident_id=%s error=%s",
            getattr(row, "command_id", None),
            incident_id,
            exc,
        )


def register_command(
    command_id: str,
    action: str,
    target_hostname: str,
    *,
    requested_by: str | None = None,
    tenant_id: str | None = None,
    extra: Dict[str, Any] | None = None,
) -> None:
    logger.warning(
        "### REGISTER_COMMAND HIT ### command_id=%s action=%s target=%s",
        command_id,
        action,
        target_hostname,
    )

    db = SessionLocal()
    try:
        create_command_execution(
            db,
            command_id=command_id,
            action=action,
            target_hostname=target_hostname,
            requested_by=requested_by,
            tenant_id=tenant_id,
            status="queued",
            message="Command queued",
            result_payload=json.dumps(extra or {}, default=str),
        )
        logger.warning("### COMMAND DB INSERT DONE ### command_id=%s", command_id)
    finally:
        db.close()


def get_command_state(command_id: str) -> Dict[str, Any] | None:
    db = SessionLocal()
    try:
        row = get_command_execution(db, command_id)
        return row.to_dict() if row else None
    finally:
        db.close()


async def broadcast_command(
    action: str,
    target_hostname: str,
    command_id: str,
    *,
    requested_by: str | None = None,
    tenant_id: str | None = None,
    **kwargs,
) -> None:
    register_command(
        command_id=command_id,
        action=action,
        target_hostname=target_hostname,
        requested_by=requested_by,
        tenant_id=tenant_id,
        extra=kwargs,
    )

    command_msg = {
        "type": "COMMAND",
        "command_id": command_id,
        "action": action,
        "target_hostname": target_hostname,
        **kwargs,
    }

    logger.warning(
        "### COMMAND SEND DEBUG ### action=%s target=%s command_id=%s agent_count=%s",
        action,
        target_hostname,
        command_id,
        len(AGENT_CONNECTIONS),
    )

    await _broadcast_command_event(
        command_id=command_id,
        hostname=target_hostname,
        action=action,
        status="queued",
        success=None,
        message=f"Komut kuyruğa alındı: {action}",
        extra=kwargs,
    )

    target_ws = AGENT_CONNECTIONS.get(target_hostname)
    if not target_ws:
        db = SessionLocal()
        try:
            row = update_command_execution(
                db,
                command_id,
                status="failed",
                success=False,
                message=f"Target agent not connected: {target_hostname}",
                finished=True,
            )
        finally:
            db.close()

        _append_incident_timeline_from_command_row(
            row,
            event_type="response_result",
            actor="system",
            title=f"Command failed: {action}",
            details=f"target={target_hostname}; status=failed; message=Target agent not connected",
        )

        await _broadcast_command_event(
            command_id=command_id,
            hostname=target_hostname,
            action=action,
            status="failed",
            success=False,
            message=f"Hedef agent bağlı değil: {target_hostname}",
            extra=kwargs,
        )
        return

    await _send_to_connections([target_ws], json.dumps(command_msg, default=str))
    logger.info("📡 COMMAND sent: %s → %s (%s)", action, target_hostname, command_id)


async def websocket_frontend(websocket: WebSocket) -> None:
    await websocket.accept()
    ACTIVE_CONNECTIONS.append(websocket)
    logger.info("🔌 Frontend WS bağlandı. Toplam: %s", len(ACTIVE_CONNECTIONS))

    try:
        while True:
            data = await websocket.receive_text()

            if data == "ping":
                await websocket.send_json(
                    {
                        "type": "pong",
                        "timestamp": _utcnow_iso(),
                        "connections": len(ACTIVE_CONNECTIONS),
                        "agents": len(AGENT_CONNECTIONS),
                    }
                )
    except Exception as exc:
        logger.debug("Frontend WS hatası: %s", exc)
    finally:
        _safe_remove(websocket)
        logger.info("🔌 Frontend WS koptu. Kalan: %s", len(ACTIVE_CONNECTIONS))


async def websocket_agent(websocket: WebSocket) -> None:
    await websocket.accept()

    agent_hostname = "unknown"
    logger.info("🤖 Agent WS bağlandı. Toplam: %s", len(AGENT_CONNECTIONS))

    try:
        while True:
            data = await websocket.receive_text()

            if data == "ping":
                await websocket.send_json(
                    {
                        "type": "pong",
                        "timestamp": _utcnow_iso(),
                    }
                )
                continue

            try:
                msg = json.loads(data)
            except Exception:
                msg = {}

            msg_type = msg.get("type")

            if msg_type == "ping":
                agent_hostname = msg.get("hostname", agent_hostname)
                if agent_hostname and agent_hostname != "unknown":
                    AGENT_CONNECTIONS[agent_hostname] = websocket
                await websocket.send_json(
                    {
                        "type": "pong",
                        "timestamp": _utcnow_iso(),
                        "hostname": agent_hostname,
                    }
                )
                continue

            if msg_type == "register":
                agent_hostname = msg.get("hostname", "unknown")
                if agent_hostname and agent_hostname != "unknown":
                    AGENT_CONNECTIONS[agent_hostname] = websocket

                logger.info("🤖 Agent kayıt: %s", agent_hostname)
                await websocket.send_json(
                    {
                        "type": "registered",
                        "hostname": agent_hostname,
                        "timestamp": _utcnow_iso(),
                    }
                )

                await _broadcast_command_event(
                    command_id=f"register-{agent_hostname}",
                    hostname=agent_hostname,
                    action="REGISTER",
                    status="registered",
                    success=True,
                    message="Agent registered",
                    extra={
                        "capabilities": msg.get("capabilities", []),
                        "agent_version": msg.get("agent_version"),
                    },
                )
                continue

            if msg_type == "COMMAND_ACK":
                command_id = str(msg.get("command_id", "")).strip()
                action = str(msg.get("action", "")).strip() or "UNKNOWN"
                status = str(msg.get("status", "received")).strip() or "received"
                hostname = str(msg.get("hostname", agent_hostname)).strip() or agent_hostname

                if hostname and hostname != "unknown":
                    AGENT_CONNECTIONS[hostname] = websocket

                row = None
                if command_id:
                    db = SessionLocal()
                    try:
                        row = update_command_execution(
                            db,
                            command_id,
                            status=status,
                            message="Agent command acknowledged",
                            agent_hostname=hostname,
                            acknowledged=True,
                        )
                        if row:
                            action = row.action or action
                    finally:
                        db.close()

                _append_incident_timeline_from_command_row(
                    row,
                    event_type="response_result",
                    actor="agent",
                    title=f"Command acknowledged: {action}",
                    details=f"target={hostname}; status={status}; success=pending",
                )

                await _broadcast_command_event(
                    command_id=command_id or f"ack-{hostname}",
                    hostname=hostname,
                    action=action,
                    status=status,
                    success=None,
                    message="Agent acknowledged command",
                )
                continue

            if msg_type == "COMMAND_RESULT":
                command_id = str(msg.get("command_id", "")).strip()
                action = str(msg.get("action", "")).strip() or "UNKNOWN"
                status = str(msg.get("status", "completed")).strip() or "completed"
                hostname = str(msg.get("hostname", agent_hostname)).strip() or agent_hostname
                success = bool(msg.get("success", False))
                message = str(msg.get("message", "")).strip() or "Command execution finished"

                if hostname and hostname != "unknown":
                    AGENT_CONNECTIONS[hostname] = websocket

                row = None
                if command_id:
                    db = SessionLocal()
                    try:
                        row = update_command_execution(
                            db,
                            command_id,
                            status=status,
                            success=success,
                            message=message,
                            agent_hostname=hostname,
                            result_payload=json.dumps(msg, default=str),
                            finished=True,
                        )
                        if row:
                            action = row.action or action
                    finally:
                        db.close()

                _append_incident_timeline_from_command_row(
                    row,
                    event_type="response_result",
                    actor="agent",
                    title=f"Command result: {action}",
                    details=f"target={hostname}; status={status}; success={success}; message={message}",
                )

                await _broadcast_command_event(
                    command_id=command_id or f"result-{hostname}",
                    hostname=hostname,
                    action=action,
                    status=status,
                    success=success,
                    message=message,
                )

                logger.info(
                    "🤖 Command result: %s | host=%s | action=%s | success=%s",
                    command_id,
                    hostname,
                    action,
                    success,
                )
                continue
    except Exception as exc:
        logger.debug("Agent WS hatası (%s): %s", agent_hostname, exc)
    finally:
        _safe_remove(websocket)
        logger.info("🤖 Agent WS koptu (%s). Kalan: %s", agent_hostname, len(AGENT_CONNECTIONS))

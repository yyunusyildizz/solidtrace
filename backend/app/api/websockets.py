"""
app.api.websockets
==================
WebSocket connection management and broadcast helpers.
Frontend and agent clients are tracked separately.
Command lifecycle is persisted into DB.
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
AGENT_CONNECTIONS: List[WebSocket] = []


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_remove(ws: WebSocket) -> None:
    for pool in (ACTIVE_CONNECTIONS, AGENT_CONNECTIONS):
        if ws in pool:
            pool.remove(ws)


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
        await _send_to_connections(AGENT_CONNECTIONS, payload)


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

    await _send_to_connections(AGENT_CONNECTIONS, json.dumps(command_msg, default=str))
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
    AGENT_CONNECTIONS.append(websocket)

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
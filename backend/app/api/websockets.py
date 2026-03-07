"""
app.api.websockets
==================
WebSocket bağlantı yönetimi ve broadcast fonksiyonları.
Frontend bağlantıları (ACTIVE_CONNECTIONS) ve Agent bağlantıları (AGENT_CONNECTIONS)
ayrı listede tutulur.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from fastapi import WebSocket

logger = logging.getLogger("SolidTrace.WebSocket")

# ---------------------------------------------------------------------------
# BAĞLANTI HAVUZLARI
# ---------------------------------------------------------------------------

ACTIVE_CONNECTIONS: List[WebSocket] = []   # Frontend istemcileri
AGENT_CONNECTIONS:  List[WebSocket] = []   # Rust agent'ları


# ---------------------------------------------------------------------------
# GÖNDERİM YARDIMCILARI
# ---------------------------------------------------------------------------

async def _send_to_connections(connections: List[WebSocket], payload: str) -> None:
    """Bağlantı listesine mesaj gönderir, kopukları otomatik temizler."""
    if not connections:
        return
    snapshot = list(connections)
    results  = await asyncio.gather(
        *[ws.send_text(payload) for ws in snapshot],
        return_exceptions=True,
    )
    for ws, result in zip(snapshot, results):
        if isinstance(result, Exception):
            for lst in (ACTIVE_CONNECTIONS, AGENT_CONNECTIONS):
                if ws in lst:
                    lst.remove(ws)


async def broadcast(msg: Dict[str, Any]) -> None:
    """Frontend bağlantılarına gönderir. COMMAND ise agent'lara da iletir."""
    payload = json.dumps(msg, default=str)
    await _send_to_connections(ACTIVE_CONNECTIONS, payload)
    if msg.get("type") == "COMMAND":
        await _send_to_connections(AGENT_CONNECTIONS, payload)


async def broadcast_command(action: str, target_hostname: str, **kwargs) -> None:
    """Sadece agent'lara hedefli komut gönderir. Frontend'e ACTION_LOG yazar."""
    msg     = {"type": "COMMAND", "action": action, "target_hostname": target_hostname, **kwargs}
    payload = json.dumps(msg, default=str)
    await _send_to_connections(ACTIVE_CONNECTIONS, json.dumps({
        "type":    "ACTION_LOG",
        "message": f"📡 Komut gönderildi → {target_hostname}: {action}",
    }))
    await _send_to_connections(AGENT_CONNECTIONS, payload)
    logger.info(f"📡 COMMAND sent: {action} → {target_hostname}")


# ---------------------------------------------------------------------------
# WEBSOCKET ENDPOINTLERİ
# ---------------------------------------------------------------------------

async def websocket_frontend(websocket: WebSocket) -> None:
    """
    /ws/alerts — Frontend istemci bağlantısı.
    Alert ve ACTION_LOG mesajlarını alır. ping/pong destekler.
    """
    await websocket.accept()
    ACTIVE_CONNECTIONS.append(websocket)
    logger.info(f"🔌 Frontend WS bağlandı. Toplam: {len(ACTIVE_CONNECTIONS)}")
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({
                    "type":        "pong",
                    "timestamp":   datetime.utcnow().isoformat(),
                    "connections": len(ACTIVE_CONNECTIONS),
                    "agents":      len(AGENT_CONNECTIONS),
                })
    except Exception as e:
        logger.debug(f"Frontend WS hatası: {e}")
    finally:
        if websocket in ACTIVE_CONNECTIONS:
            ACTIVE_CONNECTIONS.remove(websocket)
        logger.info(f"🔌 Frontend WS koptu. Kalan: {len(ACTIVE_CONNECTIONS)}")


async def websocket_agent(websocket: WebSocket) -> None:
    """
    /ws/agent — Rust agent bağlantısı.
    COMMAND mesajlarını alır, ping/register destekler.
    """
    await websocket.accept()
    agent_hostname = "unknown"
    AGENT_CONNECTIONS.append(websocket)
    logger.info(f"🤖 Agent WS bağlandı. Toplam: {len(AGENT_CONNECTIONS)}")
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") in ("ping",) or data == "ping":
                    agent_hostname = msg.get("hostname", agent_hostname)
                    await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
                elif msg.get("type") == "register":
                    agent_hostname = msg.get("hostname", "unknown")
                    logger.info(f"🤖 Agent kayıt: {agent_hostname}")
                    await websocket.send_json({"type": "registered", "hostname": agent_hostname})
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Agent WS hatası ({agent_hostname}): {e}")
    finally:
        if websocket in AGENT_CONNECTIONS:
            AGENT_CONNECTIONS.remove(websocket)
        logger.info(f"🤖 Agent WS koptu ({agent_hostname}). Kalan: {len(AGENT_CONNECTIONS)}")

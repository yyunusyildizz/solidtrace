"""
SolidTrace WebSocket Server - v2.0 (REVISED)
Düzeltmeler:
  - broadcast() içinde kopan bağlantılar temizleniyor (memory leak & ValueError önlendi)
  - Bağlantı sayısı loglama iyileştirildi
  - ping/pong heartbeat eklendi
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import List, Dict
import asyncio
import json
from datetime import datetime


class ConnectionManager:
    """Manage WebSocket connections"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger_print(f"✔ WebSocket bağlandı (Toplam: {len(self.active_connections)})")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger_print(f"✗ WebSocket ayrıldı (Toplam: {len(self.active_connections)})")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        """
        FIX: Kopan bağlantılar broadcast sırasında tespit edilip kaldırılıyor.
        Önceki implementasyonda dead connections birikiyordu ve ValueError riski vardı.
        """
        dead_connections: List[WebSocket] = []

        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                dead_connections.append(connection)

        # Batch cleanup — iteration sırasında liste değiştirilmiyor
        for dead in dead_connections:
            if dead in self.active_connections:
                self.active_connections.remove(dead)

        if dead_connections:
            logger_print(f"🧹 {len(dead_connections)} kopuk bağlantı temizlendi "
                         f"(Kalan: {len(self.active_connections)})")

    async def broadcast_alert(self, alert: Dict):
        message = json.dumps({
            "type": "alert",
            "data": _serialize_alert(alert),
            "timestamp": datetime.utcnow().isoformat()
        }, default=str)
        await self.broadcast(message)

    async def broadcast_stats(self, stats: Dict):
        message = json.dumps({
            "type": "stats",
            "data": stats,
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.broadcast(message)

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


def _serialize_alert(alert: Dict) -> Dict:
    """Alert dict'inden JSON serializable olmayan objeleri temizle"""
    safe = {}
    for key, value in alert.items():
        try:
            json.dumps(value, default=str)
            safe[key] = value
        except (TypeError, ValueError):
            safe[key] = str(value)
    return safe


def logger_print(msg: str):
    """Basit loglama — logger bağlı değilse print kullan"""
    import logging
    logging.getLogger("SolidTraceWS").info(msg)


# ==========================================
# WEBSOCKET ENDPOINT'LERİ (FastAPI app'e ekle)
# ==========================================
manager = ConnectionManager()


async def websocket_alerts_endpoint(websocket: WebSocket, soc_engine=None):
    """
    Gerçek zamanlı alert stream.
    Kullanım: @app.websocket("/ws/alerts")(websocket_alerts_endpoint)
    """
    await manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "connected",
            "message": "SolidTrace alert stream'e bağlandınız",
            "timestamp": datetime.utcnow().isoformat()
        })

        while True:
            data = await websocket.receive_text()

            # Heartbeat desteği
            if data == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat(),
                    "connections": manager.connection_count
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def websocket_stats_endpoint(websocket: WebSocket, soc_engine=None):
    """
    Gerçek zamanlı istatistik stream (5 sn interval).
    Kullanım: @app.websocket("/ws/stats")(websocket_stats_endpoint)
    """
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(5)
            if soc_engine:
                stats = soc_engine.get_statistics()
                await websocket.send_json({
                    "type": "stats_update",
                    "data": stats,
                    "timestamp": datetime.utcnow().isoformat()
                })
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ==========================================
# BACKGROUND BROADCASTER
# ==========================================
class AlertBroadcaster:
    def __init__(self, connection_manager: ConnectionManager):
        self.manager = connection_manager
        self.running = False

    async def start(self):
        self.running = True
        logger_print("✔ Alert broadcaster başlatıldı")
        while self.running:
            await asyncio.sleep(1)

    def stop(self):
        self.running = False
        logger_print("✗ Alert broadcaster durduruldu")

    async def broadcast_alert(self, alert: Dict):
        await self.manager.broadcast_alert(alert)


# ==========================================
# STANDALONE TEST SUNUCUSU
# ==========================================
if __name__ == "__main__":
    import uvicorn

    app = FastAPI(title="SolidTrace WebSocket Test")
    test_manager = ConnectionManager()

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await test_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
                else:
                    await test_manager.broadcast(f"Echo: {data}")
        except WebSocketDisconnect:
            test_manager.disconnect(websocket)

    print("""
╔══════════════════════════════════════════╗
║   SolidTrace WebSocket Server v2.0      ║
║   ws://localhost:8001/ws                ║
╚══════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8001)

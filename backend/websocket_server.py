"""
SolidTrace WebSocket Server
Real-time alert streaming to dashboard
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import List, Dict
import asyncio
import json
from datetime import datetime

# ==========================================
# CONNECTION MANAGER
# ==========================================
class ConnectionManager:
    """Manage WebSocket connections"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        """Accept new connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"✓ WebSocket connected (Total: {len(self.active_connections)})")
    
    def disconnect(self, websocket: WebSocket):
        """Remove connection"""
        self.active_connections.remove(websocket)
        print(f"✗ WebSocket disconnected (Total: {len(self.active_connections)})")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific client"""
        await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        """Broadcast message to all connected clients"""
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Connection closed, will be removed on next iteration
                pass
    
    async def broadcast_alert(self, alert: Dict):
        """Broadcast alert to all clients"""
        message = json.dumps({
            "type": "alert",
            "data": alert,
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.broadcast(message)
    
    async def broadcast_stats(self, stats: Dict):
        """Broadcast statistics update"""
        message = json.dumps({
            "type": "stats",
            "data": stats,
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.broadcast(message)

# ==========================================
# WEBSOCKET ENDPOINTS (Add to FastAPI app)
# ==========================================

# Create manager instance
manager = ConnectionManager()

# Add these to your api_advanced.py:
"""
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    '''Real-time alert stream'''
    await manager.connect(websocket)
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to SolidTrace alert stream",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Keep connection alive
        while True:
            # Wait for client messages (heartbeat)
            data = await websocket.receive_text()
            
            if data == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                })
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.websocket("/ws/stats")
async def websocket_stats(websocket: WebSocket):
    '''Real-time statistics stream'''
    await manager.connect(websocket)
    
    try:
        while True:
            # Send stats every 5 seconds
            await asyncio.sleep(5)
            stats = soc.get_statistics()
            await websocket.send_json({
                "type": "stats_update",
                "data": stats,
                "timestamp": datetime.utcnow().isoformat()
            })
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
"""

# ==========================================
# ALERT BROADCASTER (Background Task)
# ==========================================
class AlertBroadcaster:
    """Background task to broadcast alerts"""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.manager = connection_manager
        self.running = False
    
    async def start(self):
        """Start broadcasting"""
        self.running = True
        print("✓ Alert broadcaster started")
        
        while self.running:
            await asyncio.sleep(1)  # Check every second
    
    def stop(self):
        """Stop broadcasting"""
        self.running = False
        print("✗ Alert broadcaster stopped")
    
    async def broadcast_alert(self, alert: Dict):
        """Broadcast new alert to all clients"""
        await self.manager.broadcast_alert(alert)

# ==========================================
# USAGE IN SOC ENGINE
# ==========================================

# Update soc_engine_advanced.py:
"""
class SOCEngine:
    def __init__(self, websocket_manager=None):
        # ... existing code ...
        self.ws_manager = websocket_manager
    
    async def process_event(self, event: Dict) -> Optional[Dict]:
        # ... existing detection logic ...
        
        if alert and self.ws_manager:
            # Broadcast alert to connected clients
            await self.ws_manager.broadcast_alert(alert)
        
        return alert
"""

# ==========================================
# STANDALONE WEBSOCKET SERVER
# ==========================================
if __name__ == "__main__":
    import uvicorn
    from fastapi import FastAPI
    
    app = FastAPI()
    manager = ConnectionManager()
    
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                await manager.broadcast(f"Client says: {data}")
        except WebSocketDisconnect:
            manager.disconnect(websocket)
    
    print("""
    ╔════════════════════════════════════════╗
    ║   SolidTrace WebSocket Server         ║
    ║   Real-time Alert Streaming           ║
    ╚════════════════════════════════════════╝
    
    WebSocket URL: ws://localhost:8001/ws
    """)
    
    uvicorn.run(app, host="0.0.0.0", port=8001)

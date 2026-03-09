"""
app.main
========
FastAPI uygulama fabrikası.
Sadece şunları yapar:
  1. FastAPI instance + middleware konfigürasyonu
  2. Tüm router'ları kaydet
  3. WebSocket endpoint'lerini bağla
  4. Startup event'inde motorları başlat
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

sys.stdout.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SolidTrace.Core")

# ---------------------------------------------------------------------------
# UYGULAMA
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

app = FastAPI(
    title="SolidTrace Ultimate SOC",
    description="Next-Gen AI Powered SIEM & EDR Backend",
    version="6.1.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_raw_origins    = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

_env = os.getenv("ENV", "development").lower()
if _env == "production" and not ALLOWED_ORIGINS:
    import sys; logger.critical("ALLOWED_ORIGINS production ortaminda bos birakilamaz."); sys.exit(1)
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://localhost:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Agent-Key", "X-Refresh-Token"],
)

# ---------------------------------------------------------------------------
# ROUTER KAYDI
# ---------------------------------------------------------------------------

from app.api.routes_auth    import router as auth_router
from app.api.routes_alerts  import router as alerts_router
from app.api.routes_actions import router as actions_router
from app.api.routes_admin   import router as admin_router

app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(actions_router)
app.include_router(admin_router)

# ---------------------------------------------------------------------------
# WEBSOCKET ENDPOINTLERİ
# ---------------------------------------------------------------------------

from app.api.websockets import websocket_frontend, websocket_agent


@app.websocket("/ws/alerts")
async def ws_frontend(websocket: WebSocket):
    await websocket_frontend(websocket)


@app.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket):
    await websocket_agent(websocket)


# ---------------------------------------------------------------------------
# STARTUP
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    """Veritabanı, motorlar ve router'ları başlat."""
    from app.database.db_manager import init_db
    from app.api.websockets      import broadcast
    from app.api.routes_actions  import set_engines
    from app.services.notification import NotificationManager

    init_db()

    # Korelasyon motoru
    try:
        from correlation_engine import init_engine, CorrelationEngine
        from cef_output import get_cef_output

        async def _handle_correlation_alert(alert_dict: dict) -> None:
            from sqlalchemy import desc
            from app.database.db_manager import SessionLocal, AlertModel
            import uuid
            from datetime import datetime

            logger.warning(f"🔗 [KORELASYON] {alert_dict.get('rule')} | {alert_dict.get('description')}")
            # DB'ye yaz
            score = alert_dict.get("risk", {}).get("score", 50)
            severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "WARNING"
            db = SessionLocal()
            try:
                alert = AlertModel(
                    id=str(uuid.uuid4()),
                    created_at=datetime.now().isoformat(),
                    hostname=alert_dict.get("hostname", "unknown"),
                    username=alert_dict.get("user", "SYSTEM"),
                    type="SIGMA_DETECTION",
                    risk_score=score,
                    rule=alert_dict.get("rule", "Correlation"),
                    severity=severity,
                    details=alert_dict.get("description", ""),
                    command_line="",
                    pid=0,
                )
                db.add(alert)
                db.commit()
                await broadcast({"type": "alert", "data": alert.to_dict()})
            except Exception as e:
                logger.error(f"Korelasyon alert DB hatası: {e}")
                db.rollback()
            finally:
                db.close()

            cef = get_cef_output()
            cef.send(alert_dict)
            min_risk = int(os.getenv("MIN_ALERT_RISK", "50"))
            if score >= min_risk:
                NotificationManager().send_all(alert_dict)

        correlator = await init_engine(alert_callback=_handle_correlation_alert)
        cef        = get_cef_output()
        logger.info("🔗 [CORRELATOR] Korelasyon motoru başlatıldı.")
    except Exception as e:
        logger.warning(f"⚠️  Korelasyon motoru yüklenemedi: {e}")
        correlator = None
        cef        = None

    # Sigma motoru
    try:
        from sigma_engine import init_sigma
        sigma = await init_sigma(alert_callback=_handle_correlation_alert
                                 if correlator else None)
        logger.info("🎯 [SIGMA] Sigma motoru başlatıldı.")
    except Exception as e:
        logger.warning(f"⚠️  Sigma motoru yüklenemedi: {e}")
        sigma = None

    # UEBA motoru
    try:
        from ueba_engine import init_ueba
        ueba = await init_ueba(alert_callback=_handle_correlation_alert
                               if correlator else None)
        logger.info("🧠 [UEBA] UEBA motoru başlatıldı.")
    except Exception as e:
        logger.warning(f"⚠️  UEBA motoru yüklenemedi: {e}")
        ueba = None

    # Motorları routes_actions'a enjekte et
    set_engines(correlator, sigma, ueba, cef)

    # Threat Hunting router (opsiyonel)
    try:
        from threat_hunting import get_hunting_routes
        from app.database.db_manager import SessionLocal, AlertModel
        from app.core.security import get_current_user
        from sigma_engine import get_sigma
        from ueba_engine  import get_ueba
        app.include_router(
            get_hunting_routes(SessionLocal, AlertModel, get_current_user, get_ueba, get_sigma)
        )
        logger.info("🔍 [HUNT] Threat Hunting API aktif.")
    except Exception as e:
        logger.warning(f"⚠️  Threat Hunting yüklenemedi: {e}")

    logger.info("=" * 60)
    logger.info("🚀 SolidTrace SOC Backend v6.1 hazır.")
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# GİRİŞ NOKTASI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
    )

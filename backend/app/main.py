"""
app.main
========
SolidTrace backend entrypoint.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.config import settings
from app.core.request_logging import RequestLoggingMiddleware
    

# -------------------------------------------------
# Logging
# -------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("SolidTrace.Core")

# -------------------------------------------------
# Rate Limiting
# -------------------------------------------------

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.API_RATE_LIMIT],
)

# -------------------------------------------------
# FastAPI
# -------------------------------------------------

app = FastAPI(
    title="SolidTrace Ultimate SOC",
    description="Next-Gen AI Powered SIEM & EDR Backend",
    version="6.2.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# -------------------------------------------------
# CORS
# -------------------------------------------------

ALLOWED_ORIGINS = settings.ALLOWED_ORIGINS

if settings.ENV == "production" and not ALLOWED_ORIGINS:
    raise RuntimeError("ALLOWED_ORIGINS production ortamında boş bırakılamaz.")

if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Agent-Key",
        "X-Refresh-Token",
        "X-Agent-Id",
        "X-Agent-Timestamp",
        "X-Agent-Nonce",
        "X-Agent-Signature",
        "X-Tenant-Id",
    ],
)

app.add_middleware(RequestLoggingMiddleware)

# -------------------------------------------------
# Health endpoints
# -------------------------------------------------


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "solidtrace-backend"}


@app.get("/api/system/status")
async def system_status():
    return {
        "status": "online",
        "time": datetime.now(timezone.utc).isoformat(),
        "origins": ALLOWED_ORIGINS,
        "env": settings.ENV,
    }


# -------------------------------------------------
# Router loader
# -------------------------------------------------


def safe_include_router(import_path: str, attr_name: str = "router", label: str | None = None):

    label = label or import_path

    try:
        module = __import__(import_path, fromlist=[attr_name])
        router = getattr(module, attr_name)

        app.include_router(router)

        logger.info("✅ Router yüklendi: %s", label)

    except Exception as exc:
        logger.warning("⚠️ Router yüklenemedi: %s | %s", label, exc)


safe_include_router("app.api.routes_auth", label="auth")
safe_include_router("app.api.routes_alerts", label="alerts")
safe_include_router("app.api.routes_actions", label="actions")
safe_include_router("app.api.routes_admin", label="admin")
safe_include_router("app.api.routes_agents", label="agents")
safe_include_router("app.api.routes_assets", label="assets")
safe_include_router("app.api.routes_dashboard", label="dashboard")
safe_include_router("app.api.routes_sigma", label="sigma")
safe_include_router("app.api.routes_ueba", label="ueba")


# -------------------------------------------------
# WebSockets
# -------------------------------------------------

broadcast = None

try:

    from app.api.websockets import websocket_frontend, websocket_agent, broadcast

    @app.websocket("/ws/alerts")
    async def ws_frontend(websocket: WebSocket):
        await websocket_frontend(websocket)

    @app.websocket("/ws/agent")
    async def ws_agent(websocket: WebSocket):
        await websocket_agent(websocket)

    logger.info("✅ WebSocket endpoint'leri yüklendi.")

except Exception as exc:
    logger.warning("⚠️ WebSocket endpoint'leri yüklenemedi: %s", exc)

# -------------------------------------------------
# Startup
# -------------------------------------------------


@app.on_event("startup")
async def startup_event():

    logger.info("=" * 60)
    logger.info("🚀 SolidTrace startup başlıyor...")
    logger.info("=" * 60)

    # DB init

    try:
        from app.database.db_manager import init_db

        init_db()

    except Exception as exc:
        logger.critical("❌ init_db başarısız: %s", exc)
        raise

    correlator = None
    sigma = None
    ueba = None
    cef = None

    async def _handle_correlation_alert(alert_dict: dict):

        if not broadcast:
            return

        try:

            from app.database.db_manager import SessionLocal, AlertModel

            score = alert_dict.get("risk", {}).get("score", 50)

            severity = (
                "CRITICAL" if score >= 90
                else "HIGH" if score >= 70
                else "WARNING"
            )

            db = SessionLocal()

            try:

                alert = AlertModel(
                    id=str(uuid.uuid4()),
                    created_at=datetime.now(timezone.utc).isoformat(),
                    hostname=alert_dict.get("hostname", "unknown"),
                    username=alert_dict.get("user", "SYSTEM"),
                    type="SIGMA_DETECTION",
                    risk_score=score,
                    rule=alert_dict.get("rule", "Correlation"),
                    severity=severity,
                    details=alert_dict.get("description", ""),
                    command_line="",
                    pid=0,
                    tenant_id=alert_dict.get("tenant_id"),
                )

                db.add(alert)
                db.commit()

                if hasattr(alert, "to_dict"):
                    await broadcast({"type": "alert", "data": alert.to_dict()})

            finally:
                db.close()

        except Exception as exc:
            logger.error("Correlation alert handler hatası: %s", exc)

    # -------------------------------------------------
    # Detection engines
    # -------------------------------------------------

    try:

        from correlation_engine import init_engine
        from cef_output import get_cef_output

        correlator = await init_engine(alert_callback=_handle_correlation_alert)
        cef = get_cef_output()

        logger.info("🔗 Correlation engine aktif")

    except Exception as exc:
        logger.warning("⚠️ Correlation engine yüklenemedi: %s", exc)

    try:

        from sigma_engine import init_sigma

        sigma = await init_sigma(alert_callback=_handle_correlation_alert)

        logger.info("🎯 Sigma engine aktif")

    except Exception as exc:
        logger.warning("⚠️ Sigma engine yüklenemedi: %s", exc)

    try:

        from ueba_engine import init_ueba

        ueba = await init_ueba(alert_callback=_handle_correlation_alert)

        logger.info("🧠 UEBA engine aktif")

    except Exception as exc:
        logger.warning("⚠️ UEBA engine yüklenemedi: %s", exc)

    # -------------------------------------------------
    # Inject engines
    # -------------------------------------------------

    try:

        from app.api.routes_actions import set_engines

        set_engines(correlator, sigma, ueba, cef)

        logger.info("✅ Detection engine injection tamam")

    except Exception as exc:
        logger.warning("⚠️ Engine injection başarısız: %s", exc)

    # -------------------------------------------------
    # Queue worker
    # -------------------------------------------------

    try:

        from app.services.detection_queue import DetectionQueueService
        from app.api.routes_actions import process_single_event

        worker = DetectionQueueService(
            worker_name="worker-main",
            batch_size=settings.QUEUE_BATCH_SIZE,
            poll_interval=settings.QUEUE_POLL_INTERVAL,
        )

        app.state.queue_worker = worker
        app.state.queue_task = asyncio.create_task(
            worker.run_forever(process_single_event)
        )

        logger.info("🧵 Detection queue worker başlatıldı.")

    except Exception as exc:
        logger.warning("⚠️ Detection queue worker başlatılamadı: %s", exc)

    logger.info("=" * 60)
    logger.info("✅ SolidTrace backend hazır.")
    logger.info("=" * 60)


# -------------------------------------------------
# Shutdown
# -------------------------------------------------


@app.on_event("shutdown")
async def shutdown_event():

    logger.info("🛑 SolidTrace shutdown başlıyor...")

    worker = getattr(app.state, "queue_worker", None)

    if worker:
        try:
            await worker.stop()
        except Exception:
            pass

    logger.info("🛑 SolidTrace shutdown tamam.")


# -------------------------------------------------
# Dev server
# -------------------------------------------------

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
"""
app.main
========
SolidTrace backend entrypoint.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SolidTrace.Core")

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

app = FastAPI(
    title="SolidTrace Ultimate SOC",
    description="Next-Gen AI Powered SIEM & EDR Backend",
    version="6.1.1",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

_env = os.getenv("ENV", "development").lower()
if _env == "production" and not ALLOWED_ORIGINS:
    logger.critical("ALLOWED_ORIGINS production ortamında boş bırakılamaz.")
    sys.exit(1)

if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://localhost:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
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


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "solidtrace-backend"}


@app.get("/api/system/status")
async def system_status():
    return {
        "status": "online",
        "service": "solidtrace-backend",
        "time": datetime.now(timezone.utc).isoformat(),
        "origins": ALLOWED_ORIGINS,
    }


def safe_include_router(import_path: str, attr_name: str = "router", label: str | None = None) -> None:
    label = label or import_path
    try:
        module = __import__(import_path, fromlist=[attr_name])
        router = getattr(module, attr_name)
        app.include_router(router)
        logger.info(f"✅ Router yüklendi: {label}")
    except Exception as exc:
        logger.warning(f"⚠️ Router yüklenemedi: {label} | {exc}")


safe_include_router("app.api.routes_auth", "router", "auth")
safe_include_router("app.api.routes_alerts", "router", "alerts")
safe_include_router("app.api.routes_actions", "router", "actions")
safe_include_router("app.api.routes_admin", "router", "admin")
safe_include_router("app.api.routes_agents", "router", "agents")


try:
    from app.api.websockets import websocket_frontend, websocket_agent, broadcast  # type: ignore

    @app.websocket("/ws/alerts")
    async def ws_frontend(websocket: WebSocket):
        await websocket_frontend(websocket)

    @app.websocket("/ws/agent")
    async def ws_agent(websocket: WebSocket):
        await websocket_agent(websocket)

    logger.info("✅ WebSocket endpoint'leri yüklendi.")
except Exception as exc:
    broadcast = None  # type: ignore
    logger.warning(f"⚠️ WebSocket endpoint'leri yüklenemedi: {exc}")


@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("🚀 SolidTrace startup başlıyor...")
    logger.info("=" * 60)

    try:
        from app.database.db_manager import init_db
        init_db()
    except Exception as exc:
        logger.critical(f"❌ init_db başarısız: {exc}")
        raise

    set_engines = None
    try:
        from app.api.routes_actions import set_engines as _set_engines  # type: ignore
        set_engines = _set_engines
    except Exception as exc:
        logger.warning(f"⚠️ set_engines import edilemedi: {exc}")

    NotificationManager = None
    try:
        from app.services.notification import NotificationManager as _NotificationManager  # type: ignore
        NotificationManager = _NotificationManager
    except Exception as exc:
        logger.warning(f"⚠️ NotificationManager yüklenemedi: {exc}")

    correlator = None
    sigma = None
    ueba = None
    cef = None

    async def _handle_correlation_alert(alert_dict: dict) -> None:
        if not broadcast:
            logger.warning("⚠️ broadcast yok; alert websocket'e gönderilemedi.")
            return

        try:
            from app.database.db_manager import SessionLocal, AlertModel

            score = alert_dict.get("risk", {}).get("score", 50)
            severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "WARNING"

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
            except Exception as exc:
                logger.error(f"Korelasyon alert DB hatası: {exc}")
                db.rollback()
            finally:
                db.close()

            if cef is not None:
                try:
                    cef.send(alert_dict)
                except Exception as exc:
                    logger.warning(f"⚠️ CEF gönderimi başarısız: {exc}")

            min_risk = int(os.getenv("MIN_ALERT_RISK", "50"))
            if NotificationManager is not None and score >= min_risk:
                try:
                    NotificationManager().send_all(alert_dict)
                except Exception as exc:
                    logger.warning(f"⚠️ Notification gönderimi başarısız: {exc}")

        except Exception as exc:
            logger.error(f"_handle_correlation_alert hatası: {exc}")

    try:
        from correlation_engine import init_engine
        from cef_output import get_cef_output

        correlator = await init_engine(alert_callback=_handle_correlation_alert)
        cef = get_cef_output()
        logger.info("🔗 [CORRELATOR] Korelasyon motoru başlatıldı.")
    except Exception as exc:
        correlator = None
        cef = None
        logger.warning(f"⚠️ Korelasyon motoru yüklenemedi: {exc}")

    try:
        from sigma_engine import init_sigma

        sigma = await init_sigma(alert_callback=_handle_correlation_alert if correlator else None)
        logger.info("🎯 [SIGMA] Sigma motoru başlatıldı.")
    except Exception as exc:
        sigma = None
        logger.warning(f"⚠️ Sigma motoru yüklenemedi: {exc}")

    try:
        from ueba_engine import init_ueba

        ueba = await init_ueba(alert_callback=_handle_correlation_alert if correlator else None)
        logger.info("🧠 [UEBA] UEBA motoru başlatıldı.")
    except Exception as exc:
        ueba = None
        logger.warning(f"⚠️ UEBA motoru yüklenemedi: {exc}")

    if set_engines is not None:
        try:
            set_engines(correlator, sigma, ueba, cef)
            logger.info("✅ Motorlar routes_actions'a enjekte edildi.")
        except Exception as exc:
            logger.warning(f"⚠️ set_engines başarısız: {exc}")

    try:
        from app.services.detection_queue import DetectionQueueService
        from app.api.routes_actions import process_single_event

        queue_worker = DetectionQueueService(worker_name="worker-main", batch_size=50, poll_interval=1.0)
        app.state.queue_worker = queue_worker
        asyncio.create_task(queue_worker.run_forever(process_single_event))
        logger.info("🧵 Detection queue worker başlatıldı.")
    except Exception as exc:
        logger.warning(f"⚠️ Detection queue worker başlatılamadı: {exc}")

    try:
        from threat_hunting import get_hunting_routes
        from app.database.db_manager import SessionLocal, AlertModel
        from app.core.security import get_current_user
        from sigma_engine import get_sigma
        from ueba_engine import get_ueba

        app.include_router(
            get_hunting_routes(SessionLocal, AlertModel, get_current_user, get_ueba, get_sigma)
        )
        logger.info("🔍 [HUNT] Threat Hunting API aktif.")
    except Exception as exc:
        logger.warning(f"⚠️ Threat Hunting yüklenemedi: {exc}")

    logger.info("=" * 60)
    logger.info("✅ SolidTrace backend hazır.")
    logger.info("=" * 60)


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
"""
app.main
========
SolidTrace backend entrypoint.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from importlib import import_module
from typing import Any, Optional

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.request_logging import RequestLoggingMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("SolidTrace.Core")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.API_RATE_LIMIT],
)

app = FastAPI(
    title="SolidTrace Ultimate SOC",
    description="Next-Gen AI Powered SIEM & EDR Backend",
    version="6.2.1",
)

app.state.limiter = limiter
app.state.broadcast = None
app.state.queue_worker = None
app.state.queue_task = None
app.state.command_cleanup_task = None
app.state.correlator = None
app.state.sigma = None
app.state.ueba = None
app.state.cef = None

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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

app.add_middleware(RequestLoggingMiddleware)


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
        "queue_worker": bool(app.state.queue_worker),
        "websocket_broadcast": bool(app.state.broadcast),
        "command_cleanup_worker": bool(app.state.command_cleanup_task),
        "sigma_loaded": bool(app.state.sigma),
        "correlator_loaded": bool(app.state.correlator),
        "ueba_loaded": bool(app.state.ueba),
    }


def safe_include_router(import_path: str, attr_name: str = "router", label: str | None = None):
    label = label or import_path
    try:
        module = import_module(import_path)
        router = getattr(module, attr_name)
        app.include_router(router)
        logger.info("✅ Router yüklendi: %s", label)
    except Exception:
        logger.exception("❌ Router yüklenemedi: %s", label)


safe_include_router("app.api.routes_auth", label="auth")
safe_include_router("app.api.routes_alerts", label="alerts")
safe_include_router("app.api.routes_investigations", label="investigations")
safe_include_router("app.api.routes_cases", label="cases")
safe_include_router("app.api.routes_actions", label="actions")
safe_include_router("app.api.routes_admin", label="admin")
safe_include_router("app.api.routes_agents", label="agents")
#safe_include_router("app.api.routes_agent_ingest", label="agent_ingest")
safe_include_router("app.api.routes_assets", label="assets")
safe_include_router("app.api.routes_dashboard", label="dashboard")
safe_include_router("app.api.routes_sigma", label="sigma")
safe_include_router("app.api.routes_ueba", label="ueba")


def _load_optional_module(*paths: str) -> Optional[Any]:
    for path in paths:
        try:
            return import_module(path)
        except Exception:
            continue
    return None


try:
    from app.api.websockets import websocket_frontend, websocket_agent, broadcast

    app.state.broadcast = broadcast

    @app.websocket("/ws/alerts")
    async def ws_frontend(websocket: WebSocket):
        await websocket_frontend(websocket)

    @app.websocket("/ws/agent")
    async def ws_agent(websocket: WebSocket):
        await websocket_agent(websocket)

    logger.info("✅ WebSocket endpoint'leri yüklendi.")

except Exception as exc:
    logger.warning("⚠️ WebSocket endpoint'leri yüklenemedi: %s", exc)


async def _handle_detection_alert(alert_dict: dict):
    broadcast_fn = app.state.broadcast
    if not broadcast_fn:
        return

    try:
        from app.database.db_manager import SessionLocal, AlertModel

        score = int(alert_dict.get("risk", {}).get("score", 50) or 0)

        severity = (
            "CRITICAL" if score >= 90
            else "HIGH" if score >= 70
            else "WARNING" if score >= 40
            else "INFO"
        )

        db = SessionLocal()
        try:
            alert = AlertModel(
                id=str(uuid.uuid4()),
                created_at=datetime.now(timezone.utc).isoformat(),
                hostname=alert_dict.get("hostname", "unknown"),
                username=alert_dict.get("user", "SYSTEM"),
                type=alert_dict.get("type", "DETECTION"),
                risk_score=score,
                rule=alert_dict.get("rule", "Correlation"),
                severity=severity,
                details=alert_dict.get("description", ""),
                command_line=alert_dict.get("command_line", ""),
                pid=int(alert_dict.get("pid", 0) or 0),
                tenant_id=alert_dict.get("tenant_id"),
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)

            if hasattr(alert, "to_dict"):
                await broadcast_fn({"type": "alert", "data": alert.to_dict()})
        finally:
            db.close()

    except Exception as exc:
        logger.error("Detection alert handler hatası: %s", exc)


async def _init_detection_engines():
    correlator = None
    sigma = None
    ueba = None
    cef = None

    correlation_module = _load_optional_module("app.detection.correlation_engine", "correlation_engine")
    sigma_module = _load_optional_module("app.detection.sigma_engine", "sigma_engine")
    ueba_module = _load_optional_module("app.detection.ueba_engine", "ueba_engine")
    cef_module = _load_optional_module("cef_output")

    if correlation_module and hasattr(correlation_module, "init_engine"):
        try:
            correlator = await correlation_module.init_engine(alert_callback=_handle_detection_alert)
            logger.info("🔗 Correlation engine aktif")
        except Exception as exc:
            logger.warning("⚠️ Correlation engine yüklenemedi: %s", exc)
    else:
        logger.info("ℹ️ Correlation engine modülü bulunamadı, atlandı.")

    if sigma_module and hasattr(sigma_module, "init_sigma"):
        try:
            sigma = await sigma_module.init_sigma(alert_callback=_handle_detection_alert)
            logger.info("🎯 Sigma engine aktif")
        except Exception as exc:
            logger.warning("⚠️ Sigma engine yüklenemedi: %s", exc)
    else:
        logger.info("ℹ️ Sigma engine modülü bulunamadı, atlandı.")

    if ueba_module and hasattr(ueba_module, "init_ueba"):
        try:
            ueba = await ueba_module.init_ueba(alert_callback=_handle_detection_alert)
            logger.info("🧠 UEBA engine aktif")
        except Exception as exc:
            logger.warning("⚠️ UEBA engine yüklenemedi: %s", exc)
    else:
        logger.info("ℹ️ UEBA engine modülü bulunamadı, atlandı.")

    if cef_module and hasattr(cef_module, "get_cef_output"):
        try:
            cef = cef_module.get_cef_output()
        except Exception as exc:
            logger.warning("⚠️ CEF output yüklenemedi: %s", exc)

    app.state.correlator = correlator
    app.state.sigma = sigma
    app.state.ueba = ueba
    app.state.cef = cef

    try:
        from app.api.routes_actions import set_engines
        set_engines(correlator, sigma, ueba, cef)
        logger.info("✅ Detection engine injection tamam")
    except Exception as exc:
        logger.warning("⚠️ Engine injection başarısız: %s", exc)


async def _start_queue_worker():
    try:
        from app.services.detection_queue import DetectionQueueService
        from app.api.routes_actions import process_single_event

        worker = DetectionQueueService(
            worker_name="worker-main",
            batch_size=settings.QUEUE_BATCH_SIZE,
            poll_interval=settings.QUEUE_POLL_INTERVAL,
        )

        task = asyncio.create_task(worker.run_forever(process_single_event))
        app.state.queue_worker = worker
        app.state.queue_task = task
        logger.info("🧵 Detection queue worker başlatıldı.")
    except Exception as exc:
        logger.warning("⚠️ Detection queue worker başlatılamadı: %s", exc)


async def _start_command_cleanup_worker():
    async def _runner():
        while True:
            try:
                from app.database.db_manager import SessionLocal, expire_stale_commands
                db = SessionLocal()
                try:
                    updated = expire_stale_commands(db, older_than_seconds=120)
                    if updated:
                        logger.info("🧹 Expired stale commands: %s", updated)
                finally:
                    db.close()
            except Exception as exc:
                logger.warning("⚠️ Command cleanup worker hatası: %s", exc)
            await asyncio.sleep(30)
    return asyncio.create_task(_runner())


@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("🚀 SolidTrace startup başlıyor...")
    logger.info("=" * 60)

    try:
        from app.database.db_manager import init_db
        init_db()
    except Exception as exc:
        logger.critical("❌ init_db başarısız: %s", exc)
        raise

    await _init_detection_engines()
    await _start_queue_worker()
    app.state.command_cleanup_task = await _start_command_cleanup_worker()

    logger.info("=" * 60)
    logger.info("✅ SolidTrace backend hazır.")
    logger.info("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("🛑 SolidTrace shutdown başlıyor...")

    worker = getattr(app.state, "queue_worker", None)
    task = getattr(app.state, "queue_task", None)
    cleanup_task = getattr(app.state, "command_cleanup_task", None)

    if worker:
        try:
            worker.stop()
        except Exception as exc:
            logger.warning("Queue worker stop hatası: %s", exc)

    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    if cleanup_task and not cleanup_task.done():
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    try:
        from app.services.threat_intel import close_client
        await close_client()
    except Exception:
        pass

    logger.info("✅ SolidTrace shutdown tamam")

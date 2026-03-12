"""
app.core.config
================
SolidTrace merkezi konfigürasyon sistemi.
"""

from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    ENV: str = os.getenv("ENV", "development").lower()
    DEBUG: bool = ENV != "production"

    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    AGENT_SECRET_KEK: str = os.getenv("AGENT_SECRET_KEK", "")

    ALLOWED_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]

    API_RATE_LIMIT: str = os.getenv("API_RATE_LIMIT", "200/minute")

    INGEST_MAX_BATCH: int = int(os.getenv("INGEST_MAX_BATCH", "100"))
    INGEST_MAX_DETAILS: int = int(os.getenv("INGEST_MAX_DETAILS", "4000"))
    MIN_ALERT_SCORE: int = int(os.getenv("MIN_ALERT_SCORE", "50"))

    QUEUE_BATCH_SIZE: int = int(os.getenv("QUEUE_BATCH_SIZE", "50"))
    QUEUE_POLL_INTERVAL: float = float(os.getenv("QUEUE_POLL_INTERVAL", "1.0"))


settings = Settings()
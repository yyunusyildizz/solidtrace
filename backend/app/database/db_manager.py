"""
app.database.db_manager
=======================
Veritabanı katmanı — tek sorumluluk:
  - SQLAlchemy engine ve session factory
  - ORM modelleri
  - backfill_security_columns() — SQLite migration
  - write_audit() yardımcı fonksiyonu
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

logger = logging.getLogger("SolidTrace.DB")

DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./solidtrace.db")

try:
    engine = create_engine(
        DATABASE_URL,
        **(
            {"connect_args": {"check_same_thread": False}}
            if DATABASE_URL.startswith("sqlite")
            else {
                "pool_size": 20,
                "max_overflow": 10,
                "pool_pre_ping": True,
                "pool_recycle": 3600,
            }
        ),
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("✅ Veritabanı bağlantısı kuruldu.")
except Exception as exc:
    logger.critical("❌ VERİTABANI HATASI: %s", exc)
    raise

Base = declarative_base()


class TenantModel(Base):
    __tablename__ = "tenants"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, index=True)
    agent_key = Column(String, unique=True, nullable=True)
    max_agents = Column(Integer, default=10)
    is_active = Column(Boolean, default=True)
    created_at = Column(String)
    plan = Column(String, default="starter")
    contact_email = Column(String, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")
    email = Column(String, nullable=True)
    tenant_id = Column(String, index=True, nullable=True)

    created_at = Column(String)
    last_login = Column(String, nullable=True)

    failed_attempts = Column(Integer, default=0)
    locked_until = Column(String, nullable=True)

    password_change_required = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)

    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)

    invite_token_hash = Column(String, nullable=True)
    invite_expires_at = Column(String, nullable=True)
    must_setup_password = Column(Boolean, default=False)
    password_changed_at = Column(String, nullable=True)
    token_version = Column(Integer, default=0)

    def to_dict(self) -> dict:
        safe = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        safe.pop("hashed_password", None)
        safe.pop("totp_secret", None)
        safe.pop("invite_token_hash", None)
        return safe


class AuditLogModel(Base):
    __tablename__ = "audit_log"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, index=True)
    username = Column(String, index=True)
    action = Column(String, index=True)
    target = Column(String, nullable=True)
    detail = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    result = Column(String, default="SUCCESS")
    tenant_id = Column(String, nullable=True, index=True)


class RefreshTokenModel(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, index=True, nullable=False)
    token_version = Column(Integer, default=0)
    issued_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
    revoked_at = Column(String, nullable=True)
    replaced_by = Column(String, nullable=True)


class AlertModel(Base):
    __tablename__ = "alerts_production_v2"

    id = Column(String, primary_key=True, index=True)
    created_at = Column(String, index=True)
    hostname = Column(String, index=True)
    username = Column(String, nullable=True)
    type = Column(String, index=True)
    risk_score = Column(Integer, default=0)
    rule = Column(String, nullable=True)
    severity = Column(String, default="INFO")
    details = Column(Text, nullable=True)
    command_line = Column(Text, nullable=True)
    pid = Column(Integer, nullable=True)
    serial = Column(String, nullable=True)
    tenant_id = Column(String, index=True, nullable=True)

    status = Column(String, default="open", index=True)
    analyst_note = Column(Text, nullable=True)
    resolved_at = Column(String, nullable=True)
    resolved_by = Column(String, nullable=True)

    assigned_to = Column(String, nullable=True, index=True)
    assigned_at = Column(String, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class RuleModel(Base):
    __tablename__ = "detection_rules"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    keyword = Column(String, nullable=False)
    risk_score = Column(Integer, default=50)
    severity = Column(String, default="WARNING")
    created_at = Column(String)
    created_by = Column(String, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class DetectionQueueModel(Base):
    __tablename__ = "detection_queue"

    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    payload_json = Column(Text, nullable=False)
    status = Column(String, index=True, default="pending")
    attempts = Column(Integer, default=0)
    created_at = Column(String, index=True, nullable=False)
    available_at = Column(String, index=True, nullable=False)
    locked_by = Column(String, nullable=True)
    locked_at = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)


class AgentEnrollmentTokenModel(Base):
    __tablename__ = "agent_enrollment_tokens"

    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=False)
    token_hash = Column(String, nullable=False, unique=True)
    created_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    used_at = Column(String, nullable=True, index=True)
    revoked_at = Column(String, nullable=True, index=True)

    def to_dict(self) -> dict:
        safe = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        safe.pop("token_hash", None)
        return safe


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=False)

    hostname = Column(String, index=True, nullable=False)
    device_fingerprint = Column(String, index=True, nullable=False)
    os_name = Column(String, nullable=True)
    agent_version = Column(String, nullable=True)

    secret_hash = Column(String, nullable=False)
    secret_enc = Column(Text, nullable=False)

    enrolled_at = Column(String, nullable=False, index=True)
    last_seen = Column(String, index=True, nullable=True)

    is_active = Column(Boolean, default=True, index=True)
    revoked_at = Column(String, nullable=True, index=True)

    secret_rotated_at = Column(String, nullable=True)
    secret_version = Column(Integer, default=1)

    last_ip = Column(String, nullable=True)
    last_user = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "device_fingerprint", name="uq_agent_tenant_fingerprint"),
    )

    def to_dict(self) -> dict:
        safe = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        safe.pop("secret_hash", None)
        safe.pop("secret_enc", None)
        return safe


class AgentNonceModel(Base):
    __tablename__ = "agent_nonce_cache"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String, index=True, nullable=False)
    nonce = Column(String, index=True, nullable=False)
    created_at = Column(String, index=True)

    __table_args__ = (
        UniqueConstraint("agent_id", "nonce", name="uq_agent_nonce"),
    )


def backfill_security_columns() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        logger.info("PostgreSQL algılandı; güvenlik kolonları için Alembic migration kullanın.")
        return

    required_user_columns = {
        "invite_token_hash": "TEXT",
        "invite_expires_at": "TEXT",
        "must_setup_password": "BOOLEAN DEFAULT 0",
        "password_changed_at": "TEXT",
        "token_version": "INTEGER DEFAULT 0",
    }

    with engine.begin() as conn:
        existing = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()}
        for name, ddl in required_user_columns.items():
            if name not in existing:
                conn.exec_driver_sql(f"ALTER TABLE users ADD COLUMN {name} {ddl}")
                logger.info("users.%s kolonu eklendi", name)

        tables = {
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        if "agent_nonce_cache" not in tables:
            conn.exec_driver_sql(
                """
                CREATE TABLE agent_nonce_cache (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    nonce TEXT,
                    created_at TEXT,
                    UNIQUE(agent_id, nonce)
                )
                """
            )
            logger.info("agent_nonce_cache tablosu oluşturuldu")

        if "agents" in tables:
            agent_existing = {
                row[1] for row in conn.exec_driver_sql("PRAGMA table_info(agents)").fetchall()
            }
            agent_required = {
                "secret_enc": "TEXT",
                "revoked_at": "TEXT",
                "last_seen": "TEXT",
                "agent_version": "TEXT",
                "os_name": "TEXT",
                "secret_rotated_at": "TEXT",
                "secret_version": "INTEGER DEFAULT 1",
                "last_ip": "TEXT",
                "last_user": "TEXT",
            }
            for name, ddl in agent_required.items():
                if name not in agent_existing:
                    conn.exec_driver_sql(f"ALTER TABLE agents ADD COLUMN {name} {ddl}")
                    logger.info("agents.%s kolonu eklendi", name)

        if "alerts_production_v2" in tables:
            alert_existing = {
                row[1] for row in conn.exec_driver_sql("PRAGMA table_info(alerts_production_v2)").fetchall()
            }
            alert_required = {
                "status": "TEXT DEFAULT 'open'",
                "analyst_note": "TEXT",
                "resolved_at": "TEXT",
                "resolved_by": "TEXT",
                "assigned_to": "TEXT",
                "assigned_at": "TEXT",
            }
            for name, ddl in alert_required.items():
                if name not in alert_existing:
                    conn.exec_driver_sql(f"ALTER TABLE alerts_production_v2 ADD COLUMN {name} {ddl}")
                    logger.info("alerts_production_v2.%s kolonu eklendi", name)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    backfill_security_columns()
    logger.info("✅ Tablolar hazır.")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def write_audit(
    db: Session,
    username: str,
    action: str,
    target: str = "",
    detail: str = "",
    ip: str = "",
    result: str = "SUCCESS",
    tenant_id: Optional[str] = None,
) -> None:
    entry = AuditLogModel(
        id=str(uuid.uuid4()),
        timestamp=utcnow_iso(),
        username=username,
        action=action,
        target=target,
        detail=detail,
        ip_address=ip,
        result=result,
        tenant_id=tenant_id,
    )
    db.add(entry)
    try:
        db.commit()
    except Exception as exc:
        logger.error("Audit log yazılamadı: %s", exc)
        db.rollback()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
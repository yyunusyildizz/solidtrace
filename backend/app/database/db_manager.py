"""
app.database.db_manager
=======================
Veritabanı katmanı — tek sorumluluk:
  - SQLAlchemy engine ve session factory
  - ORM modelleri
  - backfill_security_columns() — SQLite migration
  - write_audit() yardımcı fonksiyonu
  - command execution lifecycle kayıtları
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
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


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


class CommandExecutionModel(Base):
    __tablename__ = "command_executions"

    id = Column(String, primary_key=True, index=True)
    command_id = Column(String, unique=True, index=True, nullable=False)

    action = Column(String, index=True, nullable=False)
    target_hostname = Column(String, index=True, nullable=False)
    requested_by = Column(String, nullable=True, index=True)
    tenant_id = Column(String, nullable=True, index=True)

    status = Column(String, index=True, default="queued")
    success = Column(Boolean, nullable=True)
    message = Column(Text, nullable=True)

    created_at = Column(String, index=True, nullable=False)
    updated_at = Column(String, index=True, nullable=False)
    acknowledged_at = Column(String, nullable=True)
    finished_at = Column(String, nullable=True)

    agent_hostname = Column(String, nullable=True, index=True)
    result_payload = Column(Text, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class CaseModel(Base):
    __tablename__ = "cases"

    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, nullable=True, index=True)

    title = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)

    status = Column(String, nullable=False, default="open", index=True)
    severity = Column(String, nullable=False, default="INFO", index=True)

    owner = Column(String, nullable=True, index=True)
    analyst_note = Column(Text, nullable=True)

    created_at = Column(String, nullable=False, index=True)
    updated_at = Column(String, nullable=False, index=True)
    closed_at = Column(String, nullable=True, index=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class CaseAlertLinkModel(Base):
    __tablename__ = "case_alert_links"

    id = Column(String, primary_key=True, index=True)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    alert_id = Column(String, ForeignKey("alerts_production_v2.id"), nullable=False, index=True)
    linked_at = Column(String, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("case_id", "alert_id", name="uq_case_alert_link"),
        Index("ix_case_alert_links_case_alert", "case_id", "alert_id"),
    )

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, nullable=True, index=True)

    campaign_family = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False, index=True)

    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="INFO")
    priority = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="open")

    owner = Column(String, nullable=True, index=True)
    analyst_note = Column(Text, nullable=True)

    playbook = Column(String, nullable=True)
    recommended_actions_json = Column(Text, nullable=True)
    attack_story_json = Column(Text, nullable=True, default="[]")  # EKLENDİ/Teyit edildi
    affected_hosts_json = Column(Text, nullable=True)

    total_events = Column(Integer, nullable=False, default=0)
    spread_depth = Column(Integer, nullable=False, default=0)

    source_type = Column(String, nullable=False, default="global_campaign")
    source_key = Column(String, nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def recommended_actions(self):
        try:
            return json.loads(self.recommended_actions_json or "[]")
        except Exception:
            return []

    def affected_hosts(self):
        try:
            return json.loads(self.affected_hosts_json or "[]")
        except Exception:
            return []

    # EKLENDİ: Helper metod
    def attack_story(self):
        try:
            return json.loads(self.attack_story_json or "[]")
        except Exception:
            return []

class IncidentTimelineModel(Base):
    __tablename__ = "incident_timeline"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, nullable=False, index=True)
    tenant_id = Column(String, nullable=True, index=True)

    event_type = Column(String, nullable=False)
    actor = Column(String, nullable=True)

    title = Column(String, nullable=False)
    details = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


def backfill_security_columns() -> None:
    # SQLite ve PostgreSQL için hafif migration/backfill
    with engine.begin() as conn:
        if DATABASE_URL.startswith("sqlite"):
            required_user_columns = {
                "invite_token_hash": "TEXT",
                "invite_expires_at": "TEXT",
                "must_setup_password": "BOOLEAN DEFAULT 0",
                "password_changed_at": "TEXT",
                "token_version": "INTEGER DEFAULT 0",
            }

            existing = {
                row[1]
                for row in conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()
            }
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
                    row[1]
                    for row in conn.exec_driver_sql("PRAGMA table_info(agents)").fetchall()
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
                    row[1]
                    for row in conn.exec_driver_sql("PRAGMA table_info(alerts_production_v2)").fetchall()
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
                        conn.exec_driver_sql(
                            f"ALTER TABLE alerts_production_v2 ADD COLUMN {name} {ddl}"
                        )
                        logger.info("alerts_production_v2.%s kolonu eklendi", name)

            if "command_executions" in tables:
                cmd_existing = {
                    row[1]
                    for row in conn.exec_driver_sql("PRAGMA table_info(command_executions)").fetchall()
                }
                cmd_required = {
                    "command_id": "TEXT",
                    "action": "TEXT",
                    "target_hostname": "TEXT",
                    "requested_by": "TEXT",
                    "tenant_id": "TEXT",
                    "status": "TEXT DEFAULT 'queued'",
                    "success": "BOOLEAN",
                    "message": "TEXT",
                    "created_at": "TEXT",
                    "updated_at": "TEXT",
                    "acknowledged_at": "TEXT",
                    "finished_at": "TEXT",
                    "agent_hostname": "TEXT",
                    "result_payload": "TEXT",
                }

                for name, ddl in cmd_required.items():
                    if name not in cmd_existing:
                        conn.exec_driver_sql(
                            f"ALTER TABLE command_executions ADD COLUMN {name} {ddl}"
                        )
                        logger.info("command_executions.%s kolonu eklendi", name)
            else:
                conn.exec_driver_sql(
                    """
                    CREATE TABLE command_executions (
                        id TEXT PRIMARY KEY,
                        command_id TEXT UNIQUE,
                        action TEXT,
                        target_hostname TEXT,
                        requested_by TEXT,
                        tenant_id TEXT,
                        status TEXT DEFAULT 'queued',
                        success BOOLEAN,
                        message TEXT,
                        created_at TEXT,
                        updated_at TEXT,
                        acknowledged_at TEXT,
                        finished_at TEXT,
                        agent_hostname TEXT,
                        result_payload TEXT
                    )
                    """
                )
                conn.exec_driver_sql(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ix_command_executions_command_id ON command_executions(command_id)"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_command_executions_status ON command_executions(status)"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_command_executions_target_hostname ON command_executions(target_hostname)"
                )
                logger.info("command_executions tablosu oluşturuldu")

            if "incidents" in tables:
                incident_existing = {
                    row[1]
                    for row in conn.exec_driver_sql("PRAGMA table_info(incidents)").fetchall()
                }
                if "attack_story_json" not in incident_existing:
                    conn.exec_driver_sql(
                        "ALTER TABLE incidents ADD COLUMN attack_story_json TEXT DEFAULT '[]'"
                    )
                    logger.info("incidents.attack_story_json kolonu eklendi")

            if "cases" not in tables:
                conn.exec_driver_sql(
                    """
                    CREATE TABLE cases (
                        id TEXT PRIMARY KEY,
                        tenant_id TEXT,
                        title TEXT NOT NULL,
                        description TEXT,
                        status TEXT NOT NULL DEFAULT 'open',
                        severity TEXT NOT NULL DEFAULT 'INFO',
                        owner TEXT,
                        analyst_note TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        closed_at TEXT
                    )
                    """
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_cases_tenant_id ON cases(tenant_id)"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_cases_status ON cases(status)"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_cases_severity ON cases(severity)"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_cases_created_at ON cases(created_at)"
                )
                logger.info("cases tablosu oluşturuldu")

            if "case_alert_links" not in tables:
                conn.exec_driver_sql(
                    """
                    CREATE TABLE case_alert_links (
                        id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL,
                        alert_id TEXT NOT NULL,
                        linked_at TEXT NOT NULL,
                        UNIQUE(case_id, alert_id)
                    )
                    """
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_case_alert_links_case_id ON case_alert_links(case_id)"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_case_alert_links_alert_id ON case_alert_links(alert_id)"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_case_alert_links_linked_at ON case_alert_links(linked_at)"
                )
                logger.info("case_alert_links tablosu oluşturuldu")

        else:
            logger.info("PostgreSQL algılandı; hafif backfill kontrolü başlatılıyor.")

            # incidents.attack_story_json
            incident_cols = {
                row[0]
                for row in conn.exec_driver_sql(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'incidents'
                    """
                ).fetchall()
            }
            if "attack_story_json" not in incident_cols:
                conn.exec_driver_sql(
                    "ALTER TABLE incidents ADD COLUMN attack_story_json TEXT DEFAULT '[]'"
                )
                logger.info("PostgreSQL: incidents.attack_story_json kolonu eklendi")


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    backfill_security_columns()
    logger.info("✅ Tablolar hazır.")


def create_command_execution(
    db: Session,
    *,
    command_id: str,
    action: str,
    target_hostname: str,
    requested_by: str | None = None,
    tenant_id: str | None = None,
    status: str = "queued",
    message: str | None = None,
    result_payload: str | None = None,
) -> CommandExecutionModel:
    now = utcnow_iso()
    existing = db.query(CommandExecutionModel).filter(
        CommandExecutionModel.command_id == command_id
    ).first()

    if existing:
        return existing

    row = CommandExecutionModel(
        id=str(uuid.uuid4()),
        command_id=command_id,
        action=action,
        target_hostname=target_hostname,
        requested_by=requested_by,
        tenant_id=tenant_id,
        status=status,
        success=None,
        message=message,
        created_at=now,
        updated_at=now,
        acknowledged_at=None,
        finished_at=None,
        agent_hostname=None,
        result_payload=result_payload,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_command_execution(db: Session, command_id: str) -> CommandExecutionModel | None:
    return db.query(CommandExecutionModel).filter(
        CommandExecutionModel.command_id == command_id
    ).first()


def update_command_execution(
    db: Session,
    command_id: str,
    *,
    status: str | None = None,
    success: bool | None = None,
    message: str | None = None,
    agent_hostname: str | None = None,
    result_payload: str | None = None,
    acknowledged: bool = False,
    finished: bool = False,
) -> CommandExecutionModel | None:
    row = get_command_execution(db, command_id)
    if not row:
        return None

    if row.status in {"completed", "failed", "expired"}:
        return row

    now = utcnow_iso()

    if status is not None:
        row.status = status
    if success is not None:
        row.success = success
    if message is not None:
        row.message = message
    if agent_hostname is not None:
        row.agent_hostname = agent_hostname
    if result_payload is not None:
        row.result_payload = result_payload

    row.updated_at = now

    if acknowledged and not row.acknowledged_at:
        row.acknowledged_at = now
    if finished and not row.finished_at:
        row.finished_at = now

    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def expire_stale_commands(db: Session, older_than_seconds: int = 120) -> int:
    now = datetime.now(timezone.utc)
    rows = db.query(CommandExecutionModel).filter(
        CommandExecutionModel.status.in_(["queued", "received"])
    ).all()

    updated = 0
    for row in rows:
        try:
            created = datetime.fromisoformat(row.created_at.replace("Z", "+00:00"))
        except Exception:
            continue

        age = (now - created).total_seconds()
        if age >= older_than_seconds:
            row.status = "expired"
            row.success = False
            row.message = "Command timed out"
            row.updated_at = utcnow_iso()
            row.finished_at = utcnow_iso()
            db.add(row)
            updated += 1

    if updated:
        db.commit()

    return updated


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

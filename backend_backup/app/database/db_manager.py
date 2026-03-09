"""
app.database.db_manager
=======================
Veritabanı katmanı — tek sorumluluk:
  - SQLAlchemy engine ve session factory
  - ORM modelleri (tüm tablolar)
  - write_audit() yardımcı fonksiyonu
  - create_default_user() başlangıç seed'i

Hiçbir FastAPI endpoint'i veya iş mantığı içermez.
"""

from __future__ import annotations

import os
import uuid
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    create_engine,
    Column, String, Integer, Text, Boolean,
    desc, or_, func,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger("SolidTrace.DB")

# ---------------------------------------------------------------------------
# 1. BAĞLANTI
# ---------------------------------------------------------------------------

DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "sqlite:///./solidtrace.db"          # geliştirme ortamı için SQLite fallback
)

try:
    engine = create_engine(
        DATABASE_URL,
        # SQLite için connect_args gerekli, PostgreSQL için pool ayarları
        **({"connect_args": {"check_same_thread": False}}
           if DATABASE_URL.startswith("sqlite") else
           {"pool_size": 20, "max_overflow": 10,
            "pool_pre_ping": True, "pool_recycle": 3600}),
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("✅ Veritabanı bağlantısı kuruldu.")
except Exception as exc:
    logger.critical(f"❌ VERİTABANI HATASI: {exc}")
    raise


# ---------------------------------------------------------------------------
# 2. BASE
# ---------------------------------------------------------------------------

Base = declarative_base()


# ---------------------------------------------------------------------------
# 3. ORM MODELLERİ
# ---------------------------------------------------------------------------

class TenantModel(Base):
    """
    Her müşteri = 1 tenant.
    MSSP senaryosunda her müşteriye ayrı tenant_id verilir.
    Veriler DB'de karışmaz.
    """
    __tablename__ = "tenants"

    id            = Column(String, primary_key=True, index=True)
    name          = Column(String, nullable=False)           # "ABC Şirketi"
    slug          = Column(String, unique=True, index=True)  # "abc-sirketi"
    agent_key     = Column(String, unique=True)              # tenant'a özel agent key
    max_agents    = Column(Integer, default=10)              # lisans limiti
    is_active     = Column(Boolean, default=True)
    created_at    = Column(String)
    plan          = Column(String, default="starter")        # starter/pro/enterprise
    contact_email = Column(String, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class UserModel(Base):
    __tablename__ = "users"

    id                       = Column(String, primary_key=True, index=True)
    username                 = Column(String, index=True, nullable=False)
    hashed_password          = Column(String, nullable=False)
    role                     = Column(String, default="analyst")   # admin/analyst/viewer
    email                    = Column(String, nullable=True)
    tenant_id                = Column(String, index=True, nullable=True)  # None = süper admin
    created_at               = Column(String)
    last_login               = Column(String, nullable=True)
    failed_attempts          = Column(Integer, default=0)
    locked_until             = Column(String, nullable=True)
    password_change_required = Column(Boolean, default=True)
    is_active                = Column(Boolean, default=True)
    totp_secret              = Column(String, nullable=True)   # 2FA secret (base32)
    totp_enabled             = Column(Boolean, default=False)  # 2FA aktif mi?

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class AuditLogModel(Base):
    """Her kritik aksiyonu kayıt altına alır — KVKK uyumu için zorunlu."""
    __tablename__ = "audit_log"

    id         = Column(String, primary_key=True, index=True)
    timestamp  = Column(String, index=True)
    username   = Column(String, index=True)
    action     = Column(String)
    target     = Column(String, nullable=True)
    detail     = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    result     = Column(String, default="SUCCESS")
    tenant_id  = Column(String, index=True, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class RuleModel(Base):
    __tablename__ = "detection_rules"

    id         = Column(String, primary_key=True, index=True)
    name       = Column(String, nullable=False)
    keyword    = Column(String, nullable=False)
    risk_score = Column(Integer, default=50)
    severity   = Column(String, default="WARNING")
    created_at = Column(String)
    created_by = Column(String, nullable=True)
    tenant_id  = Column(String, index=True, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class AlertModel(Base):
    __tablename__ = "alerts_production_v2"

    id           = Column(String, primary_key=True, index=True)
    created_at   = Column(String, index=True)
    hostname     = Column(String, index=True)
    username     = Column(String)
    type         = Column(String)
    risk_score   = Column(Integer)
    rule         = Column(String)
    severity     = Column(String)
    details      = Column(Text)
    command_line = Column(Text)
    pid          = Column(Integer)
    serial       = Column(String, nullable=True)
    tenant_id    = Column(String, index=True, nullable=True)
    # Alert lifecycle
    status       = Column(String, default="open")       # open/investigating/resolved/false_positive
    analyst_note = Column(Text, nullable=True)
    resolved_at  = Column(String, nullable=True)
    resolved_by  = Column(String, nullable=True)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# ---------------------------------------------------------------------------
# 4. TABLO OLUŞTURMA
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Tüm tabloları oluştur (yoksa). Uygulama başlangıcında çağrılır."""
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Tablolar hazır.")


# ---------------------------------------------------------------------------
# 5. YARDIMCI FONKSİYONLAR
# ---------------------------------------------------------------------------

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
    """Audit log kaydı oluştur — tüm kritik aksiyonlardan çağrılır."""
    entry = AuditLogModel(
        id         = str(uuid.uuid4()),
        timestamp  = datetime.now().isoformat(),
        username   = username,
        action     = action,
        target     = target,
        detail     = detail,
        ip_address = ip,
        result     = result,
        tenant_id  = tenant_id,
    )
    db.add(entry)
    try:
        db.commit()
    except Exception as exc:
        logger.error(f"Audit log yazılamadı: {exc}")
        db.rollback()


def create_default_user() -> None:
    """
    Başlangıçta varsayılan admin oluştur.
    ⚠️  Üretimde şifreyi mutlaka değiştirin!
    """
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    db = SessionLocal()
    try:
        if not db.query(UserModel).filter(UserModel.username == "admin").first():
            hashed = pwd_context.hash("admin123")
            db.add(UserModel(
                id                       = str(uuid.uuid4()),
                username                 = "admin",
                hashed_password          = hashed,
                role                     = "admin",
                email                    = "",
                created_at               = datetime.now().isoformat(),
                password_change_required = True,
                is_active                = True,
            ))
            db.commit()
            logger.info("🔐 Varsayılan admin oluşturuldu → kullanıcı: admin / şifre: admin123")
            logger.warning("⚠️  Üretimde şifreyi mutlaka değiştirin!")
    except Exception as exc:
        logger.error(f"Varsayılan kullanıcı oluşturulamadı: {exc}")
        db.rollback()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 6. SESSION DEPENDENCY (FastAPI Depends ile kullanım için)
# ---------------------------------------------------------------------------

def get_db():
    """
    FastAPI endpoint'lerinde kullanım:
        db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

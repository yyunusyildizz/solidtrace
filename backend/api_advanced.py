import sys
import os
import json
import uuid
import logging
import asyncio
import httpx
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, Query, Depends, status, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from pydantic import BaseModel, Field, field_validator

from sqlalchemy import create_engine, Column, String, Integer, Text, Boolean, DateTime, desc, or_, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from passlib.context import CryptContext
from jose import JWTError, jwt

from dotenv import load_dotenv
from groq import Groq

# Yeni modüller
from correlation_engine import init_engine, CorrelationEngine
from cef_output import get_cef_output
from notification_service import NotificationManager
from sigma_engine import init_sigma, get_sigma
from ueba_engine import init_ueba, get_ueba
from threat_hunting import get_hunting_routes

# -----------------------------------------------------------------------------
# 1. AYARLAR VE LOGLAMA
# -----------------------------------------------------------------------------
load_dotenv()

sys.stdout.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("SolidTrace.Core")

DATABASE_URL   = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/solidtrace_db")
OTX_API_KEY    = os.getenv("OTX_API_KEY")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY")
BAZAAR_API_KEY = os.getenv("BAZAAR_API_KEY")
_raw_agent_key = os.getenv("AGENT_API_KEY", "")
if not _raw_agent_key:
    # .env'de tanımlı değil — güvenli rastgele key üret ve uyar
    import secrets as _secrets
    AGENT_API_KEY = _secrets.token_urlsafe(32)
    logger.warning("⚠️  AGENT_API_KEY tanımlı değil — bu oturum için rastgele key üretildi:")
    logger.warning(f"   AGENT_API_KEY={AGENT_API_KEY}")
    logger.warning("   → .env dosyasına ekleyerek agent'ları yeniden yapılandırın!")
else:
    AGENT_API_KEY = _raw_agent_key

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    # ENV tanımlı değilse varsayılan DEVELOPMENT — production için .env zorunlu
    env = os.getenv("ENV", "development").lower()
    if env == "production":
        logger.critical("❌ JWT_SECRET_KEY tanımlı değil! Üretim ortamında başlatılamaz.")
        logger.critical("   → .env dosyasına ekleyin: JWT_SECRET_KEY=<anahtar>")
        logger.critical("   → Üret: python -c \"import secrets; print(secrets.token_hex(32))\"")
        sys.exit(1)
    else:
        SECRET_KEY = "DEV-ONLY-NOT-FOR-PRODUCTION"
        logger.warning("⚠️  JWT_SECRET_KEY eksik — development modu aktif")
        logger.warning("   → .env dosyasına JWT_SECRET_KEY ekleyin")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 saat

# FIX: Rate limiting için basit in-memory sayaç
# Üretimde Redis tabanlı slowapi ile değiştirin
LOGIN_ATTEMPTS: Dict[str, list] = {}  # ip -> [timestamp, ...]
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300  # 5 dakika

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

INTEL_CACHE: Dict[str, bool] = {}

# -----------------------------------------------------------------------------
# 2. UYGULAMA VE MIDDLEWARE
# -----------------------------------------------------------------------------
# Rate limiter — brute force ve DDoS koruması
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

app = FastAPI(
    title="SolidTrace Ultimate SOC",
    description="Next-Gen AI Powered SIEM & EDR Backend",
    version="6.1.0"
)

# FIX: CORS — allow_origins=["*"] üretimde güvensiz.
# .env'den ALLOWED_ORIGINS alınıyor, yoksa sadece localhost
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Agent-Key"],
)

# Threat Hunting + Asset Inventory + UEBA + Sigma API endpoint'leri
# SessionLocal ve AlertModel veritabanı hazır olduktan sonra kayıt edilir
# (aşağıda _register_routers() ile çağrılır)

# -----------------------------------------------------------------------------
# 3. VERİTABANI
# -----------------------------------------------------------------------------
Base = declarative_base()

try:
    engine = create_engine(
        DATABASE_URL,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=3600
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("✅ Veritabanı bağlantısı kuruldu.")
except Exception as e:
    logger.critical(f"❌ VERİTABANI HATASI: {e}")
    sys.exit(1)


class TenantModel(Base):
    """
    Her müşteri = 1 tenant.
    MSSP senaryosunda her müşteriye ayrı tenant_id verilir.
    Veriler DB'de karışmaz.
    """
    __tablename__ = "tenants"
    id           = Column(String, primary_key=True, index=True)
    name         = Column(String, nullable=False)          # "ABC Şirketi"
    slug         = Column(String, unique=True, index=True) # "abc-sirketi"
    agent_key    = Column(String, unique=True)             # tenant'a özel agent key
    max_agents   = Column(Integer, default=10)             # lisans limiti
    is_active    = Column(Boolean, default=True)
    created_at   = Column(String)
    plan         = Column(String, default="starter")       # starter/pro/enterprise
    contact_email= Column(String, nullable=True)


class UserModel(Base):
    __tablename__ = "users"
    id                       = Column(String, primary_key=True, index=True)
    username                 = Column(String, index=True, nullable=False)
    hashed_password          = Column(String, nullable=False)
    role                     = Column(String, default="analyst")
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

    def to_dict(self):
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

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


Base.metadata.create_all(bind=engine)


async def write_audit(db, username: str, action: str,
                      target: str = "", detail: str = "",
                      ip: str = "", result: str = "SUCCESS"):
    """Audit log kaydı oluştur."""
    entry = AuditLogModel(
        id         = str(uuid.uuid4()),
        timestamp  = datetime.now().isoformat(),
        username   = username,
        action     = action,
        target     = target,
        detail     = detail,
        ip_address = ip,
        result     = result,
    )
    db.add(entry)
    try:
        db.commit()
    except Exception:
        db.rollback()


def create_default_user():
    """Başlangıçta varsayılan admin oluştur."""
    db = SessionLocal()
    try:
        if not db.query(UserModel).filter(UserModel.username == "admin").first():
            hashed = pwd_context.hash("admin123")
            db.add(UserModel(
                id=str(uuid.uuid4()),
                username="admin",
                hashed_password=hashed,
                role="admin",
                email="",
                created_at=datetime.now().isoformat(),
                password_change_required=True,
                is_active=True,
            ))
            db.commit()
            logger.info("🔐 Varsayılan admin oluşturuldu (admin / admin123)")
            logger.warning("⚠️  Üretimde şifreyi mutlaka değiştirin!")
    except Exception as e:
        logger.error(f"Varsayılan kullanıcı hatası: {e}")
    finally:
        db.close()


create_default_user()

# -----------------------------------------------------------------------------
# 4. PYDANTIC ŞEMALARI
# -----------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type:   str

class TenantCreateRequest(BaseModel):
    name:          str
    contact_email: Optional[str] = None
    max_agents:    int = 10
    plan:          str = "starter"

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role:     str = "analyst"
    email:    Optional[str] = None
    tenant_id: Optional[str] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password:     str

class AdminPasswordResetRequest(BaseModel):
    username:     str
    new_password: str

class DetectionRuleSchema(BaseModel):
    name:       str = Field(..., min_length=3, max_length=100)
    keyword:    str = Field(..., min_length=1, max_length=200)
    risk_score: int = Field(..., ge=0, le=100)
    severity:   str = Field(..., pattern="^(INFO|WARNING|HIGH|CRITICAL)$")


class EventBase(BaseModel):
    type:         str
    hostname:     str
    user:         Optional[str] = "SYSTEM"
    pid:          Optional[int] = 0
    details:      Optional[str] = ""
    command_line: Optional[str] = ""
    serial:       Optional[str] = None
    severity:     Optional[str] = "INFO"
    timestamp:    Optional[str] = None

    # FIX: hostname boş veya sahte değer gelmesin
    @field_validator("hostname")
    @classmethod
    def hostname_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("hostname boş olamaz")
        cleaned = v.strip()
        # Bilinen sahte/geçici değerleri reddet
        fake_values = {"localhost", "unknown", "unknown-host", "sys_internal",
                       "none", "null", "(none)", "computer"}
        if cleaned.lower() in fake_values:
            raise ValueError(f"Geçersiz hostname: '{cleaned}'. Agent COMPUTERNAME değişkenini okuyamıyor.")
        return cleaned

    # FIX: Batch ingest'te aşırı büyük payload koruması (details max 10KB)
    @field_validator("details", "command_line")
    @classmethod
    def truncate_long_fields(cls, v):
        if v and len(v) > 10_000:
            return v[:10_000] + "...[truncated]"
        return v


class ActionRequest(BaseModel):
    hostname:   str
    pid:        Optional[int]  = 0
    rule:       Optional[str]  = None
    severity:   Optional[str]  = None
    details:    Optional[str]  = None
    serial:     Optional[str]  = None
    risk_score: Optional[int]  = 0


class HashReport(BaseModel):
    hostname:  str
    file_path: str
    file_hash: str
    pid:       int

    # FIX: Hash format doğrulama (MD5=32, SHA256=64 hex karakter)
    @field_validator("file_hash")
    @classmethod
    def validate_hash(cls, v):
        v = v.strip().lower()
        if len(v) not in (32, 64) or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("Geçersiz hash formatı (MD5 veya SHA256 bekleniyor)")
        return v

# -----------------------------------------------------------------------------
# 5. AUTH YARDIMCI FONKSİYONLARI
# -----------------------------------------------------------------------------
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Kimlik doğrulama başarısız",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise exc
    except JWTError:
        raise exc
    return username


async def get_current_tenant_id(
    current_user: str = Depends(get_current_user)
) -> Optional[str]:
    """
    JWT sahibinin tenant_id'sini döndür.
    Süper admin (tenant_id=None) tüm tenant'lara erişebilir.
    """
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        return user.tenant_id if user else None
    finally:
        db.close()


def tenant_filter(query, model, tenant_id: Optional[str]):
    """
    Süper admin (tenant_id=None) → filtre yok, hepsini görür.
    Normal kullanıcı → sadece kendi tenant'ını görür.
    """
    if tenant_id is not None:
        query = query.filter(model.tenant_id == tenant_id)
    return query

def require_role(required_role: str):
    """
    FIX: Rol tabanlı erişim kontrolü (RBAC).
    Kullanım: Depends(require_role("admin"))
    """
    async def _check(current_user: str = Depends(get_current_user)):
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.username == current_user).first()
            if not user:
                raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
            role_hierarchy = {"viewer": 0, "analyst": 1, "admin": 2}
            if role_hierarchy.get(user.role, 0) < role_hierarchy.get(required_role, 99):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Bu işlem için '{required_role}' rolü gerekli"
                )
            return current_user
        finally:
            db.close()
    return _check

def verify_agent_key(x_agent_key: Optional[str] = Header(None)):
    if not x_agent_key or x_agent_key != AGENT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz Agent API Key"
        )
    return True

# -----------------------------------------------------------------------------
# 6. WEBSOCKET YÖNETİMİ
# -----------------------------------------------------------------------------
ACTIVE_CONNECTIONS: List[WebSocket] = []   # Frontend bağlantıları
AGENT_CONNECTIONS:  List[WebSocket] = []   # Agent bağlantıları

# Korelasyon motoru — uygulama başlangıcında init_engine ile başlatılır
_correlator: CorrelationEngine = None
_cef_output = get_cef_output()
_sigma_engine = None
_ueba_engine  = None

async def _send_to_connections(connections: list, payload: str) -> None:
    """Verilen bağlantı listesine mesaj gönderir, kopukları temizler."""
    if not connections:
        return
    snapshot = list(connections)
    results = await asyncio.gather(*[ws.send_text(payload) for ws in snapshot], return_exceptions=True)
    for ws, result in zip(snapshot, results):
        if isinstance(result, Exception):
            for lst in (ACTIVE_CONNECTIONS, AGENT_CONNECTIONS):
                if ws in lst:
                    lst.remove(ws)


async def broadcast(msg: Dict[str, Any]):
    """Frontend bağlantılarına + agent bağlantılarına gönder."""
    payload = json.dumps(msg, default=str)
    await _send_to_connections(ACTIVE_CONNECTIONS, payload)
    # COMMAND mesajları agent'lara da gönderilsin
    if msg.get("type") == "COMMAND":
        await _send_to_connections(AGENT_CONNECTIONS, payload)


async def broadcast_command(action: str, target_hostname: str, **kwargs):
    """Sadece agent'lara hedefli komut gönder."""
    msg = {"type": "COMMAND", "action": action, "target_hostname": target_hostname, **kwargs}
    payload = json.dumps(msg, default=str)
    # Frontend'e ACTION_LOG olarak bildir
    await _send_to_connections(ACTIVE_CONNECTIONS, json.dumps({
        "type": "ACTION_LOG",
        "message": f"📡 Komut gönderildi → {target_hostname}: {action}"
    }))
    # Agent'lara komutu gönder
    await _send_to_connections(AGENT_CONNECTIONS, payload)
    logger.info(f"📡 COMMAND sent: {action} → {target_hostname}")


@app.on_event("startup")
async def startup_event():
    """Uygulama başlangıcında korelasyon motorunu başlat."""
    global _correlator
    _correlator = await init_engine(alert_callback=_handle_correlation_alert)
    logger.info("🔗 [CORRELATOR] Korelasyon motoru başlatıldı.")

    global _sigma_engine, _ueba_engine
    _sigma_engine = await init_sigma(alert_callback=_handle_correlation_alert)
    _ueba_engine  = await init_ueba(alert_callback=_handle_correlation_alert)
    logger.info("🎯 [SIGMA] Sigma motoru başlatıldı.")
    logger.info("🧠 [UEBA] UEBA motoru başlatıldı.")

    # Threat Hunting router'ını kaydet
    app.include_router(
        get_hunting_routes(SessionLocal, AlertModel, get_current_user, get_ueba, get_sigma)
    )
    logger.info("🔍 [HUNT] Threat Hunting API aktif.")

async def _handle_correlation_alert(alert_dict: dict) -> None:
    """Korelasyon alarmı geldiğinde WebSocket + bildirim gönder."""
    logger.warning(f"🔗 [KORELASYON] {alert_dict['rule']} | {alert_dict['description']}")
    await broadcast({"type": "correlation_alert", "data": alert_dict})
    _cef_output.send(alert_dict)
    min_risk = int(os.getenv("MIN_ALERT_RISK", "50"))
    if alert_dict["risk"]["score"] >= min_risk:
        notifier = NotificationManager()
        notifier.send_all(alert_dict)


@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """Frontend bağlantısı — alert ve ACTION_LOG mesajlarını alır."""
    await websocket.accept()
    ACTIVE_CONNECTIONS.append(websocket)
    logger.info(f"🔌 Frontend WS bağlandı. Toplam: {len(ACTIVE_CONNECTIONS)}")
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat(),
                    "connections": len(ACTIVE_CONNECTIONS),
                    "agents": len(AGENT_CONNECTIONS),
                })
    except Exception as e:
        logger.debug(f"Frontend WS hatası: {e}")
    finally:
        if websocket in ACTIVE_CONNECTIONS:
            ACTIVE_CONNECTIONS.remove(websocket)
        logger.info(f"🔌 Frontend WS koptu. Kalan: {len(ACTIVE_CONNECTIONS)}")


@app.websocket("/ws/agent")
async def agent_websocket_endpoint(websocket: WebSocket):
    """Agent bağlantısı — COMMAND mesajlarını alır, EVENT gönderir."""
    await websocket.accept()
    agent_hostname = "unknown"
    AGENT_CONNECTIONS.append(websocket)
    logger.info(f"🤖 Agent WS bağlandı. Toplam agent: {len(AGENT_CONNECTIONS)}")
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping" or data == "ping":
                    agent_hostname = msg.get("hostname", agent_hostname)
                    await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
                elif msg.get("type") == "register":
                    agent_hostname = msg.get("hostname", "unknown")
                    logger.info(f"🤖 Agent kayıt: {agent_hostname}")
                    await websocket.send_json({"type": "registered", "hostname": agent_hostname})
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Agent WS hatası ({agent_hostname}): {e}")
    finally:
        if websocket in AGENT_CONNECTIONS:
            AGENT_CONNECTIONS.remove(websocket)
        logger.info(f"🤖 Agent WS koptu ({agent_hostname}). Kalan: {len(AGENT_CONNECTIONS)}")

# -----------------------------------------------------------------------------
# 7. TEHDİT İSTİHBARATI VE AI
# -----------------------------------------------------------------------------
async def check_otx(file_hash: str) -> Optional[str]:
    if not OTX_API_KEY:
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
            if res.status_code == 200:
                count = res.json().get("pulse_info", {}).get("count", 0)
                if count > 0:
                    return f"OTX: {count} Tehdit Kaydı!"
    except Exception as e:
        logger.error(f"OTX Hatası: {e}")
    return None


async def check_malware_bazaar(file_hash: str) -> Optional[str]:
    if not BAZAAR_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash},
                headers={"Auth-Key": BAZAAR_API_KEY}
            )
            if res.status_code == 200:
                j = res.json()
                if j.get("query_status") == "ok":
                    sig = j["data"][0].get("signature", "Malware")
                    return f"Bazaar: {sig} Tespit!"
    except Exception as e:
        logger.error(f"Bazaar Hatası: {e}")
    return None


async def process_threat_intel(report: HashReport):
    if report.file_hash in INTEL_CACHE:
        return

    otx_res, bazaar_res = await asyncio.gather(
        check_otx(report.file_hash),
        check_malware_bazaar(report.file_hash),
        return_exceptions=True
    )

    for label, result in [("OTX", otx_res), ("Bazaar", bazaar_res)]:
        if result and not isinstance(result, Exception):
            await broadcast({
                "type": "ACTION_LOG",
                "message": f"🚨 [{label}] {result} → {report.file_path}"
            })

    INTEL_CACHE[report.file_hash] = True


async def perform_groq_analysis(data: dict):
    try:
        local_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
    except Exception as e:
        logger.error(f"AI Client başlatılamadı: {e}")
        local_client = None

    if not local_client:
        await broadcast({"type": "ACTION_LOG", "message": "❌ AI Devre Dışı (API Key Eksik)"})
        return

    await broadcast({"type": "ACTION_LOG", "message": f"🤖 AI Analizi: {data.get('rule', '?')}"})

    system_prompt = """Sen dünyanın en yetkin SOC merkezinde 'Senior Tier 3 SOC Analisti'sin.

Kurallar:
1. Genel geçer tavsiyeler değil, spesifik teknik aksiyon ver.
2. MITRE ATT&CK teknik kodlarını mutlaka kullan (T1059, T1003 vb.)
3. False Positive ise açıkça belirt.
4. Türkçe, profesyonel, maks. 200 kelime."""

    user_prompt = f"""
ANALİZ EDİLECEK LOG:
Host: {data.get('hostname')}
PID: {data.get('pid')}
Kural: {data.get('rule')}
Komut/Dosya: {data.get('details')} {data.get('command_line') or ''}
Risk: {data.get('risk_score')} | Şiddet: {data.get('severity')}
"""
    try:
        completion = local_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt}
            ],
            temperature=0.1,
            max_tokens=500
        )
        report_content = completion.choices[0].message.content
        await broadcast({"type": "ACTION_LOG", "message": f"🧠 AI RAPORU:\n{report_content}"})
        logger.info(f"AI Analizi tamamlandı: {data.get('hostname')}")
    except Exception as e:
        logger.error(f"AI Sorgu Hatası: {e}")
        await broadcast({"type": "ACTION_LOG", "message": f"❌ AI Hatası: {e}"})

# -----------------------------------------------------------------------------
# 8. API ENDPOINTLERİ
# -----------------------------------------------------------------------------

# --- AUTH ---

@app.post("/api/login", response_model=Token)
@limiter.limit("10/minute")  # Brute force koruması
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    FIX: Brute-force koruması eklendi.
    Aynı kullanıcı adından 5 dakikada 5 başarısız deneme → 5 dk kilit.
    """
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == form_data.username).first()

        # FIX: Hesap kilitli mi kontrol et
        if user and user.locked_until:
            lock_time = datetime.fromisoformat(user.locked_until)
            if datetime.now() < lock_time:
                remaining = int((lock_time - datetime.now()).total_seconds() / 60)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Hesap kilitli. {remaining} dakika sonra tekrar deneyin."
                )
            else:
                # Kilit süresi dolmuş, sıfırla
                user.failed_attempts = 0
                user.locked_until = None

        if not user or not verify_password(form_data.password, user.hashed_password):
            # FIX: Başarısız deneme say
            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.locked_until = (datetime.now() + timedelta(seconds=LOGIN_WINDOW_SECONDS)).isoformat()
                    logger.warning(f"🔒 Hesap kilitlendi: {form_data.username}")
                db.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kullanıcı adı veya şifre hatalı",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Başarılı giriş — sayaçları sıfırla
        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now().isoformat()
        db.commit()

        token = create_access_token(data={"sub": user.username, "role": user.role})
        logger.info(f"✅ Giriş: {user.username} ({user.role})")
        await write_audit(db, user.username, "LOGIN",
                          detail=f"role={user.role}",
                          result="SUCCESS")
        return {
            "access_token":           token,
            "token_type":             "bearer",
            "password_change_required": bool(user.password_change_required),
            "role":                   user.role,
            "username":               user.username,
        }

    finally:
        db.close()


@app.get("/api/me")
async def get_me(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        return {
            "username":   user.username,
            "role":       user.role,
            "created_at": user.created_at,
            "last_login": user.last_login
        }
    finally:
        db.close()

# --- ANALİTİK ---

@app.get("/api/analytics")
async def get_analytics(
    current_user: str        = Depends(get_current_user),
    tenant_id:    Optional[str] = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        q = db.query(AlertModel)
        if tenant_id:
            q = q.filter(AlertModel.tenant_id == tenant_id)
        alerts = q.order_by(desc(AlertModel.created_at)).limit(500).all()
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        timeline: Dict[str, int] = {}

        for a in alerts:
            sev = a.severity if a.severity in severity_counts else "INFO"
            severity_counts[sev] += 1
            try:
                if a.created_at:
                    key = datetime.fromisoformat(a.created_at).strftime("%H:00")
                    timeline[key] = timeline.get(key, 0) + 1
            except Exception:
                pass

        return {
            "severity_distribution": [{"name": k, "value": v} for k, v in severity_counts.items() if v > 0],
            "activity_trend": [{"time": k, "count": v} for k, v in sorted(timeline.items())]
        }
    finally:
        db.close()


@app.get("/api/stats")
async def get_stats(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        total    = db.query(AlertModel).count()
        critical = db.query(AlertModel).filter(AlertModel.risk_score >= 70).count()
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        recent   = db.query(AlertModel).filter(AlertModel.created_at >= yesterday).count()
        return {"total_logs": total, "critical_count": critical, "last_24h": recent}
    finally:
        db.close()

# --- KURAL YÖNETİMİ ---

@app.post("/api/rules")
async def add_rule(rule: DetectionRuleSchema, current_user: str = Depends(require_role("analyst"))):
    """FIX: Artık sadece analyst ve admin kural ekleyebilir (viewer edemez)"""
    db = SessionLocal()
    try:
        new_rule = RuleModel(
            id=str(uuid.uuid4()),
            name=rule.name,
            keyword=rule.keyword,
            risk_score=rule.risk_score,
            severity=rule.severity,
            created_at=datetime.now().isoformat(),
            created_by=current_user
        )
        db.add(new_rule)
        db.commit()
        logger.info(f"✅ Kural oluşturuldu: {rule.name} (by {current_user})")
        return {"status": "ok", "rule": new_rule.to_dict()}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get("/api/rules")
async def get_rules(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        rules = db.query(RuleModel).order_by(desc(RuleModel.created_at)).all()
        return [r.to_dict() for r in rules]
    finally:
        db.close()


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str, current_user: str = Depends(require_role("admin"))):
    """FIX: Kural silme sadece admin yetkisi gerektirir"""
    db = SessionLocal()
    try:
        deleted = db.query(RuleModel).filter(RuleModel.id == rule_id).delete()
        db.commit()
        if deleted:
            logger.info(f"🗑️  Kural silindi: {rule_id} (by {current_user})")
            return {"status": "deleted"}
        raise HTTPException(status_code=404, detail="Kural bulunamadı")
    finally:
        db.close()

# --- INGEST ---

# ─────────────────────────────────────────────────────────────────────────────
# TENANT (MÜŞTERİ) YÖNETİMİ — sadece süper admin (tenant_id=None)
# ─────────────────────────────────────────────────────────────────────────────

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    email: Optional[str] = None
    tenant_id: Optional[int] = None


@app.get("/api/tenants")
async def list_tenants(current_user: str = Depends(require_role("admin"))):
    """Tüm tenant'ları listele — süper admin."""
    db = SessionLocal()
    try:
        me = db.query(UserModel).filter(UserModel.username == current_user).first()
        if me and me.tenant_id:
            raise HTTPException(status_code=403, detail="Sadece süper admin erişebilir")
        tenants = db.query(TenantModel).all()
        result = []
        for t in tenants:
            agent_count = db.query(AlertModel).filter(
                AlertModel.tenant_id == t.id
            ).distinct(AlertModel.hostname).count()
            result.append({
                "id":            t.id,
                "name":          t.name,
                "slug":          t.slug,
                "plan":          t.plan,
                "max_agents":    t.max_agents,
                "active_agents": agent_count,
                "is_active":     t.is_active,
                "created_at":    t.created_at,
                "contact_email": t.contact_email,
                "agent_key":     t.agent_key,
            })
        return result
    finally:
        db.close()


@app.post("/api/tenants")
async def create_tenant(
    req: TenantCreateRequest,
    current_user: str = Depends(require_role("admin"))
):
    """Yeni müşteri (tenant) oluştur."""
    import re, secrets as _s
    db = SessionLocal()
    try:
        me = db.query(UserModel).filter(UserModel.username == current_user).first()
        if me and me.tenant_id:
            raise HTTPException(status_code=403, detail="Sadece süper admin tenant oluşturabilir")

        slug = re.sub(r"[^a-z0-9]+", "-", req.name.lower()).strip("-")
        if db.query(TenantModel).filter(TenantModel.slug == slug).first():
            slug = f"{slug}-{_s.token_hex(3)}"

        tenant = TenantModel(
            id            = str(uuid.uuid4()),
            name          = req.name,
            slug          = slug,
            agent_key     = f"st-{_s.token_urlsafe(24)}",
            max_agents    = req.max_agents,
            plan          = req.plan,
            is_active     = True,
            created_at    = datetime.now().isoformat(),
            contact_email = req.contact_email,
        )
        db.add(tenant)
        db.commit()
        await write_audit(db, current_user, "TENANT_CREATE",
                          target=req.name, detail=f"plan={req.plan} max_agents={req.max_agents}")
        logger.info(f"🏢 Yeni tenant: {req.name} ({slug})")
        return {
            "id":        tenant.id,
            "name":      tenant.name,
            "slug":      tenant.slug,
            "agent_key": tenant.agent_key,
            "plan":      tenant.plan,
        }
    finally:
        db.close()


@app.post("/api/users/invite")
async def invite_user(
    req: UserCreateRequest,
    current_user: str = Depends(require_role("admin")),
    tenant_id: Optional[str] = Depends(get_current_tenant_id),
):
    """
    Yeni kullanıcı oluştur + hoş geldin e-postası gönder.
    E-posta ayarları .env'den (SMTP_USER, SMTP_PASSWORD) okunur.
    """
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı")
    if req.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")

    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == req.username).first():
            raise HTTPException(status_code=409, detail="Kullanıcı adı zaten mevcut")

        user = UserModel(
            id                       = str(uuid.uuid4()),
            username                 = req.username,
            hashed_password          = pwd_context.hash(req.password),
            role                     = req.role,
            email                    = req.email,
            tenant_id                = tenant_id,
            created_at               = datetime.now().isoformat(),
            password_change_required = True,
            is_active                = True,
        )
        db.add(user)
        db.commit()
        await write_audit(db, current_user, "USER_INVITE",
                          target=req.username, detail=f"email={req.email} role={req.role}")

        # E-posta gönder (SMTP ayarları varsa)
        if req.email and os.getenv("SMTP_USER"):
            try:
                _send_invite_email(req.email, req.username, req.password)
                logger.info(f"📧 Davet e-postası gönderildi: {req.email}")
            except Exception as e:
                logger.warning(f"⚠️  E-posta gönderilemedi: {e}")

        return {"status": "invited", "username": req.username, "email_sent": bool(req.email and os.getenv("SMTP_USER"))}
    finally:
        db.close()


def _send_invite_email(to_email: str, username: str, temp_password: str):
    """Davet e-postası gönder."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    smtp_server   = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port     = int(os.getenv("SMTP_PORT", "587"))
    smtp_user     = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    server_url    = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")[0]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "SolidTrace — Hesabınız Hazır"
    msg["From"]    = smtp_user
    msg["To"]      = to_email

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#0d0d14;color:#e0e0e0;border-radius:12px;overflow:hidden">
      <div style="background:#1a1a2e;padding:28px 32px;border-bottom:1px solid #ffffff10">
        <h1 style="margin:0;font-size:20px;color:#fff">🛡 SolidTrace</h1>
        <p style="margin:4px 0 0;font-size:12px;color:#aaa">Siber Güvenlik İzleme Platformu</p>
      </div>
      <div style="padding:28px 32px">
        <h2 style="font-size:16px;color:#fff;margin-top:0">Hesabınız Oluşturuldu</h2>
        <p style="color:#aaa;font-size:13px">Aşağıdaki bilgilerle giriş yapabilirsiniz. <strong style="color:#f59e0b">İlk girişte şifrenizi değiştirmeniz zorunludur.</strong></p>
        <div style="background:#ffffff08;border:1px solid #ffffff12;border-radius:8px;padding:16px;margin:16px 0">
          <p style="margin:0 0 8px;font-size:12px;color:#888">Kullanıcı Adı</p>
          <code style="font-size:15px;color:#60a5fa">{username}</code>
          <p style="margin:12px 0 8px;font-size:12px;color:#888">Geçici Şifre</p>
          <code style="font-size:15px;color:#34d399">{temp_password}</code>
        </div>
        <a href="{server_url}" style="display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:10px 24px;border-radius:8px;font-size:13px;font-weight:bold">
          Platforma Giriş Yap →
        </a>
      </div>
      <div style="padding:16px 32px;border-top:1px solid #ffffff08;font-size:11px;color:#555">
        Bu e-posta otomatik gönderilmiştir. Lütfen yanıtlamayınız.
      </div>
    </div>
    """
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(smtp_server, smtp_port) as s:
        s.starttls()
        s.login(smtp_user, smtp_password)
        s.sendmail(smtp_user, to_email, msg.as_string())


@app.delete("/api/tenants/{tenant_id}")
async def delete_tenant(
    tenant_id: str,
    current_user: str = Depends(require_role("admin"))
):
    """Tenant ve tüm verilerini sil."""
    db = SessionLocal()
    try:
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant bulunamadı")
        db.query(AlertModel).filter(AlertModel.tenant_id == tenant_id).delete()
        db.query(UserModel).filter(UserModel.tenant_id == tenant_id).delete()
        db.query(AuditLogModel).filter(AuditLogModel.tenant_id == tenant_id).delete()
        db.delete(tenant)
        db.commit()
        await write_audit(db, current_user, "TENANT_DELETE", target=tenant.name)
        return {"status": "deleted", "name": tenant.name}
    finally:
        db.close()


@app.get("/api/tenants/{tenant_id}/stats")
async def tenant_stats(
    tenant_id: str,
    current_user: str = Depends(get_current_user)
):
    """Tenant istatistikleri — agent sayısı, alert sayısı, plan durumu."""
    db = SessionLocal()
    try:
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant bulunamadı")

        total_alerts = db.query(AlertModel).filter(AlertModel.tenant_id == tenant_id).count()
        critical     = db.query(AlertModel).filter(
            AlertModel.tenant_id == tenant_id,
            AlertModel.severity  == "CRITICAL"
        ).count()
        # Aktif agent = son 5 dakikada event gönderen
        cutoff = (datetime.now() - __import__('datetime').timedelta(minutes=5)).isoformat()
        active_agents = db.query(AlertModel.hostname).filter(
            AlertModel.tenant_id == tenant_id,
            AlertModel.created_at >= cutoff
        ).distinct().count()

        return {
            "tenant":        tenant.name,
            "plan":          tenant.plan,
            "max_agents":    tenant.max_agents,
            "active_agents": active_agents,
            "license_ok":    active_agents <= tenant.max_agents,
            "total_alerts":  total_alerts,
            "critical":      critical,
        }
    finally:
        db.close()


# ─── Tenant'a özel agent key ile kimlik doğrulama ─────────────────────────────

def verify_tenant_agent_key(x_agent_key: Optional[str] = Header(None)):
    """
    Agent'lar bu fonksiyon ile doğrulanır.
    Global AGENT_API_KEY VEYA tenant'a özel agent_key kabul edilir.
    """
    if not x_agent_key:
        raise HTTPException(status_code=401, detail="Agent key eksik")

    # Global key kontrolü (geriye dönük uyumluluk)
    if x_agent_key == AGENT_API_KEY:
        return {"tenant_id": None, "tenant_name": "global"}

    # Tenant key kontrolü
    db = SessionLocal()
    try:
        tenant = db.query(TenantModel).filter(
            TenantModel.agent_key == x_agent_key,
            TenantModel.is_active == True
        ).first()
        if not tenant:
            raise HTTPException(status_code=401, detail="Geçersiz agent key")

        # Agent limit kontrolü
        cutoff = (datetime.now() - __import__('datetime').timedelta(minutes=10)).isoformat()
        active = db.query(AlertModel.hostname).filter(
            AlertModel.tenant_id == tenant.id,
            AlertModel.created_at >= cutoff
        ).distinct().count()

        if active > tenant.max_agents:
            logger.warning(f"⚠️  Tenant {tenant.name}: agent limit aşıldı ({active}/{tenant.max_agents})")
            raise HTTPException(
                status_code=429,
                detail=f"Agent limit aşıldı ({active}/{tenant.max_agents}). Planınızı yükseltiniz."
            )

        return {"tenant_id": tenant.id, "tenant_name": tenant.name}
    finally:
        db.close()


@app.post("/api/v1/ingest")
async def ingest_event(
    events:     List[EventBase],
    bg:         BackgroundTasks,
    agent_auth: dict = Depends(verify_tenant_agent_key),
):
    """
    Agent event ingest — tenant_id otomatik eklenir, agent limit kontrol edilir.
    """
    MAX_BATCH = 100
    if len(events) > MAX_BATCH:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch limiti aşıldı. Maks. {MAX_BATCH} event gönderilebilir."
        )
    bg.add_task(_process_events_bg, list(events), agent_auth.get("tenant_id"))
    return {"status": "ok", "count": len(events)}


async def _process_events_bg(events: List[EventBase], tenant_id: Optional[str] = None):
    """Arka planda event işleme — tenant_id alert'lere eklenir."""
    db = SessionLocal()
    try:
        active_rules = db.query(RuleModel).all()
        processed = 0

        # Statik fallback kurallar — tek yerde tanımlı
        STATIC_RULES = [
            ("usb",         90,  "USB Device Activity",       "HIGH"),
            ("ransomware",  100, "Ransomware Alert",          "CRITICAL"),
            ("mimikatz",    95,  "Credential Dumping",        "CRITICAL"),
            ("lsass",       90,  "LSASS Access",              "CRITICAL"),
            ("psexec",      75,  "Lateral Movement (PsExec)", "HIGH"),
        ]

        for event in events:
            # Encoding temizleme — Windows-1254 / CP1252 bozuk karakterleri düzelt
            _raw = event.details or ""
            if isinstance(_raw, bytes):
                try:
                    _raw = _raw.decode('utf-8')
                except UnicodeDecodeError:
                    _raw = _raw.decode('windows-1254', errors='replace')
            # BOM ve kontrol karakterlerini temizle
            final_details = _raw.lstrip('\ufeff').strip()
            if event.serial:
                final_details += f"\n🔍 Donanım Kimliği: {event.serial}"

            score         = 10
            rule_name     = "Normal Activity"
            current_sev   = event.severity or "INFO"

            full_text = f"{final_details} {event.command_line} {event.type}".lower()

            # 1. Dinamik kurallar (DB'den)
            rule_matched = False
            for r in active_rules:
                if r.keyword.lower() in full_text:
                    score       = r.risk_score
                    rule_name   = r.name
                    current_sev = r.severity
                    rule_matched = True
                    break

            # 2. Statik fallback kurallar
            if not rule_matched:
                for keyword, s, name, sev in STATIC_RULES:
                    if keyword in full_text:
                        score       = s
                        rule_name   = name
                        current_sev = sev
                        break

            alert = AlertModel(
                id=str(uuid.uuid4()),
                created_at=event.timestamp or datetime.now().isoformat(),
                hostname=event.hostname,
                username=event.user,
                type=event.type,
                risk_score=score,
                rule=rule_name,
                severity=current_sev,
                details=final_details,
                command_line=event.command_line,
                pid=event.pid,
                serial=event.serial,
                tenant_id=tenant_id,
            )
            db.add(alert)
            await broadcast({"type": "alert", "data": alert.to_dict()})

            # Korelasyon motoruna besle
            if _correlator:
                corr_event = {
                    "type":      event.type,
                    "hostname":  event.hostname or "unknown",
                    "user":      event.user or "unknown",
                    "details":   final_details,
                    "timestamp": event.timestamp or datetime.now().isoformat(),
                    "severity":  current_sev,
                    "pid":       event.pid or 0,
                    "risk":      {"score": score, "level": current_sev},
                }
                await _correlator.process_event(corr_event)

            # Sigma kurallarına karşı çalıştır
            if _sigma_engine:
                sigma_event = {
                    "type":     event.type,
                    "hostname": event.hostname or "unknown",
                    "user":     event.user or "unknown",
                    "details":  final_details,
                    "severity": current_sev,
                    "risk":     {"score": score, "level": current_sev},
                }
                asyncio.create_task(_sigma_engine.process_event(sigma_event))

            # UEBA motoruna besle
            if _ueba_engine:
                ueba_event = {
                    "type":     event.type,
                    "hostname": event.hostname or "unknown",
                    "user":     event.user or "unknown",
                    "details":  final_details,
                    "risk":     {"score": score, "level": current_sev},
                }
                asyncio.create_task(_ueba_engine.process_event(ueba_event))

            # CEF formatında kaydet/gönder
            _cef_output.send({
                "type":      event.type,
                "hostname":  event.hostname,
                "user":      event.user,
                "details":   final_details,
                "severity":  current_sev,
                "timestamp": event.timestamp,
                "pid":       event.pid or 0,
                "risk":      {"score": score, "level": current_sev},
            })

            processed += 1

        db.commit()
        logger.info(f"📥 {processed} event işlendi (arka plan)")

    except Exception as e:
        db.rollback()
        logger.error(f"Ingest Hatası: {e}")
        raise HTTPException(status_code=500, detail=f"Ingest başarısız: {e}")
    finally:
        db.close()

# --- ARAMA ---

@app.get("/api/alerts")
async def get_alerts(
    q:         Optional[str] = None,
    severity:  Optional[str] = None,
    limit:     int            = Query(default=100, ge=1, le=1000),
    current_user: str         = Depends(get_current_user),
    tenant_id: Optional[str]  = Depends(get_current_tenant_id),
):
    db = SessionLocal()
    try:
        query = db.query(AlertModel)
        if severity and severity.strip():
            query = query.filter(AlertModel.severity == severity)
        if q and q.strip():
            term = f"%{q}%"
            query = query.filter(or_(
                AlertModel.hostname.ilike(term),
                AlertModel.rule.ilike(term),
                AlertModel.details.ilike(term),
                AlertModel.username.ilike(term)
            ))
        alerts = query.order_by(desc(AlertModel.created_at)).limit(limit).all()
        return [a.to_dict() for a in alerts]
    except Exception as e:
        logger.error(f"Alerts Hatası: {e}")
        return []
    finally:
        db.close()

# --- ANALİZ VE AKSİYON ---

@app.post("/api/actions/analyze")
async def analyze_host(
    req: ActionRequest,
    bg:  BackgroundTasks,
    current_user: str = Depends(get_current_user)
):
    """AI analizi — tüm giriş yapmış kullanıcılar kullanabilir."""
    await broadcast({
        "type": "ACTION_LOG",
        "message": f"🔍 Analiz başlatıldı: {req.hostname} | Kural: {req.rule} | Kullanıcı: {current_user}"
    })
    bg.add_task(perform_groq_analysis, req.dict())
    return {"status": "started", "message": "AI analizi arka planda çalışıyor"}


@app.post("/api/v1/report_hash")
async def report_hash(
    report: HashReport,
    bg: BackgroundTasks,
    authenticated: bool = Depends(verify_agent_key)  # FIX: Agent key zorunlu
):
    """FIX: Hash raporu artık agent key ile korumalı"""
    bg.add_task(process_threat_intel, report)
    return {"status": "analyzing", "hash": report.file_hash}

# --- YÖNETİM ---


# ─────────────────────────────────────────────────────────────────────────────
# AGENT İNDİRME & SİSTEM DURUMU
# ─────────────────────────────────────────────────────────────────────────────

import platform as _platform
import time as _time

_START_TIME = _time.time()

AGENT_VERSION    = os.getenv("AGENT_VERSION", "1.0.0")
AGENT_BUILD_DATE = os.getenv("AGENT_BUILD_DATE", datetime.now().strftime("%Y-%m-%d"))
AGENT_BINARY_DIR = os.getenv("AGENT_BINARY_DIR", "releases")  # releases/ klasörü

@app.get("/api/agent/info")
async def agent_info():
    """Agent sürüm bilgisi — indirme sayfası için."""
    binary_path = os.path.join(AGENT_BINARY_DIR, "solidtrace-agent.zip")
    size_mb     = round(os.path.getsize(binary_path) / 1024 / 1024, 1) if os.path.exists(binary_path) else 0.0

    # SHA256 hesapla
    sha256 = "—"
    if os.path.exists(binary_path):
        import hashlib
        h = hashlib.sha256()
        with open(binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        sha256 = h.hexdigest()

    return {
        "version":    AGENT_VERSION,
        "build_date": AGENT_BUILD_DATE,
        "platform":   "windows-x86_64",
        "size_mb":    size_mb,
        "sha256":     sha256,
        "changelog": [
            "Rust tabanlı hafif agent mimarisi",
            "Windows Event Log izleme (Security/System/Application)",
            "Process, dosya, USB, registry monitörü",
            "Gerçek zamanlı SOC panel entegrasyonu",
            "Sigma kural motoru desteği",
            "Otomatik yeniden bağlanma",
        ],
    }


@app.get("/api/agent/download")
async def agent_download():
    """Agent binary indirme — releases/solidtrace-agent.zip dosyasını serve eder."""
    from fastapi.responses import FileResponse
    binary_path = os.path.join(AGENT_BINARY_DIR, "solidtrace-agent.zip")

    if not os.path.exists(binary_path):
        # Releases klasörü yoksa oluştur ve README bırak
        os.makedirs(AGENT_BINARY_DIR, exist_ok=True)
        readme = os.path.join(AGENT_BINARY_DIR, "README.txt")
        if not os.path.exists(readme):
            with open(readme, "w") as f:
                f.write("Bu klasöre Rust ile derlenen agent binary'sini koyun:\n")
                f.write("cd agent_rust && cargo build --release\n")
                f.write("Çıktı: agent_rust/target/release/solidtrace-agent.exe\n")
                f.write("ZIP'e sıkıştırıp buraya solidtrace-agent.zip olarak koyun.\n")
        raise HTTPException(
            status_code=404,
            detail="Agent binary henüz hazır değil. releases/solidtrace-agent.zip dosyasını oluşturun."
        )

    return FileResponse(
        path=binary_path,
        filename=f"solidtrace-agent-v{AGENT_VERSION}.zip",
        media_type="application/zip",
    )


@app.get("/api/system/status")
async def system_status():
    """Sistem sağlık durumu — indirme sayfası için."""
    db_ok = False
    total_alerts = 0
    agents_online = 0
    try:
        db = SessionLocal()
        total_alerts  = db.query(AlertModel).count()
        # Son 24 saatte heartbeat gönderen agent = online
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        agents_online = db.query(AlertModel)            .filter(AlertModel.type == "ASSET_HEARTBEAT")            .filter(AlertModel.created_at >= cutoff)            .distinct(AlertModel.hostname).count()
        db.close()
        db_ok = True
    except Exception:
        pass

    return {
        "backend":       True,
        "db":            db_ok,
        "agents_online": agents_online,
        "total_alerts":  total_alerts,
        "uptime_seconds": int(_time.time() - _START_TIME),
    }


@app.delete("/api/alerts/clear")
async def clear_alerts(current_user: str = Depends(require_role("admin"))):
    """FIX: Alarm silme sadece admin yapabilir"""
    db = SessionLocal()
    try:
        count = db.query(AlertModel).count()
        db.query(AlertModel).delete()
        db.commit()
        await broadcast({
            "type": "ACTION_LOG",
            "message": f"🧹 {count} alarm temizlendi (by {current_user})"
        })
        logger.warning(f"⚠️  {count} alarm silindi (by {current_user})")
        return {"status": "cleared", "count": count}
    finally:
        db.close()

# --- AGENT KOMUTLARI ---

@app.post("/api/actions/kill")
async def kill_process(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("KILL_PROCESS", req.hostname, target_pid=req.pid)
    logger.warning(f"⚠️  KILL: {req.hostname}:{req.pid} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "KILL_PROCESS",
                          target=f"{req.hostname}:PID{req.pid}",
                          detail=req.rule or "")
    finally:
        db.close()
    return {"status": "sent", "action": "KILL_PROCESS"}


@app.post("/api/actions/isolate")
async def isolate_host(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("ISOLATE_HOST", req.hostname)
    logger.warning(f"🔒 İZOLASYON: {req.hostname} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "ISOLATE_HOST", target=req.hostname)
    finally:
        db.close()
    return {"status": "sent", "action": "ISOLATE_HOST"}


@app.post("/api/actions/unisolate")
async def unisolate_host(req: ActionRequest, current_user: str = Depends(get_current_user)):
    await broadcast_command("UNISOLATE_HOST", req.hostname)
    logger.info(f"🔓 İZOLASYON KALDIRILDI: {req.hostname} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "UNISOLATE_HOST", target=req.hostname)
    finally:
        db.close()
    return {"status": "sent", "action": "UNISOLATE_HOST"}


@app.post("/api/actions/usb_disable")
async def usb_disable(req: ActionRequest, current_user: str = Depends(get_current_user)):
    """USB portlarını devre dışı bırak."""
    await broadcast_command("USB_DISABLE", req.hostname)
    await broadcast({"type": "ACTION_LOG", "message": f"🔌 USB Devre Dışı: {req.hostname} (by {current_user})"})
    logger.warning(f"⚠️  USB_DISABLE: {req.hostname} (by {current_user})")
    db = SessionLocal()
    try:
        await write_audit(db, current_user, "USB_DISABLE", target=req.hostname)
    finally:
        db.close()
    return {"status": "sent", "action": "USB_DISABLE"}


@app.post("/api/actions/usb_enable")
async def usb_enable(req: ActionRequest, current_user: str = Depends(get_current_user)):
    """USB portlarını aktif et."""
    await broadcast_command("USB_ENABLE", req.hostname)
    await broadcast({"type": "ACTION_LOG", "message": f"🔌 USB Aktif: {req.hostname} (by {current_user})"})
    logger.warning(f"⚠️  USB_ENABLE: {req.hostname} (by {current_user})")
    return {"status": "sent", "action": "USB_ENABLE"}


@app.get("/api/v1/processes/{hostname}")
async def get_processes(hostname: str, current_user: str = Depends(get_current_user)):
    """Hedef host'taki çalışan süreçleri döndür."""
    import psutil, socket
    local_names = {socket.gethostname().lower(), "localhost", "127.0.0.1",
                   socket.gethostname().upper(), "DESKTOP-" + socket.gethostname().split("-")[-1]}

    if hostname.lower() in local_names or hostname.upper() in local_names:
        processes = []
        for proc in psutil.process_iter(['pid','name','cpu_percent','memory_info','status','username','cmdline']):
            try:
                info = proc.info
                processes.append({
                    "pid":     info['pid'],
                    "name":    info['name'] or "?",
                    "cpu":     round(info.get('cpu_percent') or 0.0, 2),
                    "memory":  round((info['memory_info'].rss if info['memory_info'] else 0) / 1024 / 1024, 1),
                    "status":  info.get('status') or "running",
                    "user":    info.get('username') or "SYSTEM",
                    "cmdline": " ".join((info.get('cmdline') or [])[:4]),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        processes.sort(key=lambda x: x['cpu'], reverse=True)
        return {"hostname": hostname, "source": "local", "processes": processes[:200]}

    # Uzak host: son 2 dakikadaki PROCESS_CREATED eventlerinden liste
    db = SessionLocal()
    try:
        cutoff = (datetime.now() - timedelta(seconds=120)).isoformat()
        recent = db.query(AlertModel)            .filter(AlertModel.hostname == hostname)            .filter(AlertModel.type == "PROCESS_CREATED")            .filter(AlertModel.created_at >= cutoff)            .order_by(AlertModel.created_at.desc())            .limit(100).all()
        seen = set()
        processes = []
        for r in recent:
            if r.pid and r.pid not in seen:
                seen.add(r.pid)
                processes.append({
                    "pid":     r.pid,
                    "name":    r.rule or r.type,
                    "cpu":     0.0, "memory": 0.0,
                    "status":  "running",
                    "user":    r.username or "SYSTEM",
                    "cmdline": (r.command_line or "")[:80],
                })
        # Agent'a scan komutu gönder
        await broadcast({"type": "COMMAND", "action": "SCAN_PROCESSES", "target_hostname": hostname})
        return {"hostname": hostname, "source": "db_recent", "processes": processes}
    finally:
        db.close()


# --- HEALTH CHECK ---

# ─────────────────────────────────────────────────────────────────────────────
# KULLANICI YÖNETİMİ
# ─────────────────────────────────────────────────────────────────────────────

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role:     str = "analyst"
    email:    Optional[str] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password:     str

class AdminPasswordResetRequest(BaseModel):
    username:     str
    new_password: str


@app.get("/api/users")
async def list_users(current_user: str = Depends(require_role("admin"))):
    """Tüm kullanıcıları listele — sadece admin."""
    db = SessionLocal()
    try:
        users = db.query(UserModel).all()
        return [
            {
                "username":   u.username,
                "role":       u.role,
                "email":      u.email,
                "is_active":  u.is_active,
                "last_login": u.last_login,
                "created_at": u.created_at,
                "password_change_required": u.password_change_required,
            }
            for u in users
        ]
    finally:
        db.close()


@app.post("/api/users")
async def create_user(
    req: UserCreateRequest,
    current_user: str = Depends(require_role("admin"))
):
    """Yeni kullanıcı oluştur — sadece admin."""
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı")
    if req.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")

    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == req.username).first():
            raise HTTPException(status_code=409, detail="Kullanıcı adı zaten mevcut")
        user = UserModel(
            id                       = str(uuid.uuid4()),
            username                 = req.username,
            hashed_password          = pwd_context.hash(req.password),
            role                     = req.role,
            email                    = req.email,
            created_at               = datetime.now().isoformat(),
            password_change_required = True,
            is_active                = True,
        )
        db.add(user)
        db.commit()
        await write_audit(db, current_user, "USER_CREATE",
                          target=req.username, detail=f"role={req.role}")
        logger.info(f"✅ Kullanıcı oluşturuldu: {req.username} ({req.role}) by {current_user}")
        return {"status": "created", "username": req.username}
    finally:
        db.close()


@app.delete("/api/users/{username}")
async def delete_user(
    username: str,
    current_user: str = Depends(require_role("admin"))
):
    """Kullanıcı sil — sadece admin. Kendi hesabını silemez."""
    if username == current_user:
        raise HTTPException(status_code=400, detail="Kendi hesabınızı silemezsiniz")
    if username == "admin":
        raise HTTPException(status_code=400, detail="Ana admin silinemez")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        db.delete(user)
        db.commit()
        await write_audit(db, current_user, "USER_DELETE", target=username)
        return {"status": "deleted", "username": username}
    finally:
        db.close()


@app.put("/api/users/{username}/role")
async def update_user_role(
    username: str,
    body: dict,
    current_user: str = Depends(require_role("admin"))
):
    """Kullanıcı rolünü güncelle."""
    new_role = body.get("role")
    if new_role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Geçersiz rol")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        old_role = user.role
        user.role = new_role
        db.commit()
        await write_audit(db, current_user, "USER_ROLE_CHANGE",
                          target=username, detail=f"{old_role} → {new_role}")
        return {"status": "updated", "username": username, "role": new_role}
    finally:
        db.close()


@app.post("/api/users/2fa/setup")
async def setup_2fa(current_user: str = Depends(get_current_user)):
    """
    2FA kurulumu başlat.
    QR code URI + backup kodları döner.
    Kullanıcı bunu Google Authenticator ile tarar.
    """
    try:
        import pyotp, base64
    except ImportError:
        raise HTTPException(status_code=503, detail="2FA için 'pyotp' paketi gerekli: pip install pyotp")

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        if user.totp_enabled:
            raise HTTPException(status_code=400, detail="2FA zaten aktif")

        # Yeni secret üret
        secret = pyotp.random_base32()
        user.totp_secret = secret
        db.commit()

        totp     = pyotp.TOTP(secret)
        issuer   = "SolidTrace"
        uri      = totp.provisioning_uri(name=current_user, issuer_name=issuer)

        # QR code data URL (base64 PNG)
        try:
            import qrcode, io
            qr  = qrcode.make(uri)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")
            qr_b64 = base64.b64encode(buf.getvalue()).decode()
            qr_data_url = f"data:image/png;base64,{qr_b64}"
        except ImportError:
            qr_data_url = None  # qrcode paketi yoksa URI yeterli

        return {
            "secret":      secret,
            "uri":         uri,
            "qr_data_url": qr_data_url,
            "message":     "QR kodu Google Authenticator ile tarayın, ardından /api/users/2fa/verify ile doğrulayın"
        }
    finally:
        db.close()


@app.post("/api/users/2fa/verify")
async def verify_2fa_setup(
    body: dict,
    current_user: str = Depends(get_current_user)
):
    """2FA kurulumunu onayla — doğru kodu girdikten sonra aktif olur."""
    try:
        import pyotp
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    code = body.get("code", "").strip()
    db   = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not user.totp_secret:
            raise HTTPException(status_code=400, detail="Önce /api/users/2fa/setup çağrılmalı")

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(code, valid_window=1):
            raise HTTPException(status_code=400, detail="Kod hatalı veya süresi geçmiş")

        user.totp_enabled = True
        db.commit()
        await write_audit(db, current_user, "2FA_ENABLED")
        return {"status": "enabled", "message": "2FA başarıyla aktifleştirildi"}
    finally:
        db.close()


@app.post("/api/users/2fa/disable")
async def disable_2fa(
    body: dict,
    current_user: str = Depends(get_current_user)
):
    """2FA'yı kapat — şifre doğrulaması gerekir."""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        if not verify_password(body.get("password", ""), user.hashed_password):
            raise HTTPException(status_code=401, detail="Şifre hatalı")

        user.totp_enabled = False
        user.totp_secret  = None
        db.commit()
        await write_audit(db, current_user, "2FA_DISABLED")
        return {"status": "disabled"}
    finally:
        db.close()


@app.post("/api/login/2fa")
async def login_2fa(
    body: dict
):
    """
    2FA'lı giriş — normal login'den sonra bu endpoint çağrılır.
    body: { "username": "...", "totp_code": "123456" }
    Token döner.
    """
    try:
        import pyotp
    except ImportError:
        raise HTTPException(status_code=503, detail="pyotp paketi gerekli")

    username  = body.get("username", "")
    totp_code = body.get("totp_code", "").strip()

    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user or not user.totp_enabled or not user.totp_secret:
            raise HTTPException(status_code=400, detail="2FA aktif değil veya kullanıcı bulunamadı")

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            await write_audit(db, username, "2FA_LOGIN_FAIL", result="FAILURE")
            raise HTTPException(status_code=401, detail="2FA kodu hatalı")

        token = create_access_token(data={"sub": user.username, "role": user.role})
        await write_audit(db, username, "2FA_LOGIN_SUCCESS")
        return {
            "access_token":             token,
            "token_type":               "bearer",
            "password_change_required": bool(user.password_change_required),
            "role":                     user.role,
            "username":                 user.username,
        }
    finally:
        db.close()


@app.get("/api/me/2fa-status")
async def get_2fa_status(current_user: str = Depends(get_current_user)):
    """Kullanıcının 2FA durumunu döner."""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        return {
            "totp_enabled": bool(user.totp_enabled) if user else False,
            "username":     current_user,
        }
    finally:
        db.close()


@app.post("/api/users/change-password")
async def change_password(
    req: PasswordChangeRequest,
    current_user: str = Depends(get_current_user)
):
    """Kendi şifreni değiştir."""
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Yeni şifre en az 8 karakter olmalı")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user or not verify_password(req.current_password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Mevcut şifre hatalı")
        user.hashed_password          = pwd_context.hash(req.new_password)
        user.password_change_required = False
        db.commit()
        await write_audit(db, current_user, "PASSWORD_CHANGE", result="SUCCESS")
        logger.info(f"🔑 Şifre değiştirildi: {current_user}")
        return {"status": "changed"}
    finally:
        db.close()


@app.post("/api/admin/reset-password")
async def admin_reset_password(
    req: AdminPasswordResetRequest,
    current_user: str = Depends(require_role("admin"))
):
    """Admin başka kullanıcının şifresini sıfırlar."""
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı")
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == req.username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        user.hashed_password          = pwd_context.hash(req.new_password)
        user.password_change_required = True
        db.commit()
        await write_audit(db, current_user, "ADMIN_PASSWORD_RESET",
                          target=req.username)
        return {"status": "reset", "username": req.username}
    finally:
        db.close()


@app.get("/api/audit-log")
async def get_audit_log(
    limit: int = Query(default=100, ge=1, le=1000),
    username: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    current_user: str = Depends(require_role("admin"))
):
    """Audit log — sadece admin görebilir."""
    db = SessionLocal()
    try:
        q = db.query(AuditLogModel).order_by(desc(AuditLogModel.timestamp))
        if username:
            q = q.filter(AuditLogModel.username == username)
        if action:
            q = q.filter(AuditLogModel.action == action)
        entries = q.limit(limit).all()
        return [
            {
                "timestamp":  e.timestamp,
                "username":   e.username,
                "action":     e.action,
                "target":     e.target,
                "detail":     e.detail,
                "ip_address": e.ip_address,
                "result":     e.result,
            }
            for e in entries
        ]
    finally:
        db.close()


@app.get("/api/report/monthly")
async def monthly_report(
    month:    Optional[str] = Query(default=None, description="YYYY-MM formatında, boşsa bu ay"),
    format:   str           = Query(default="json", regex="^(json|pdf)$"),
    current_user: str       = Depends(get_current_user),
):
    """
    Aylık güvenlik raporu — JSON veya PDF olarak indir.
    MSSP müşterilere gönderilecek executive özet içerir.
    """
    from fastapi.responses import StreamingResponse
    import io

    # Ay aralığını belirle
    if month:
        try:
            report_dt = datetime.strptime(month, "%Y-%m")
        except ValueError:
            raise HTTPException(status_code=400, detail="Tarih formatı: YYYY-MM")
    else:
        report_dt = datetime.now().replace(day=1)

    month_start = report_dt.replace(day=1, hour=0, minute=0, second=0).isoformat()
    if report_dt.month == 12:
        month_end = report_dt.replace(year=report_dt.year+1, month=1, day=1).isoformat()
    else:
        month_end = report_dt.replace(month=report_dt.month+1, day=1).isoformat()

    month_label = report_dt.strftime("%B %Y")

    db = SessionLocal()
    try:
        alerts = db.query(AlertModel).filter(
            AlertModel.created_at >= month_start,
            AlertModel.created_at <  month_end
        ).all()

        total          = len(alerts)
        critical_count = sum(1 for a in alerts if a.severity == "CRITICAL")
        high_count     = sum(1 for a in alerts if a.severity == "HIGH")
        warning_count  = sum(1 for a in alerts if a.severity == "WARNING")
        unique_hosts   = len(set(a.hostname for a in alerts))
        top_rules      = {}
        for a in alerts:
            top_rules[a.rule] = top_rules.get(a.rule, 0) + 1
        top_rules_sorted = sorted(top_rules.items(), key=lambda x: x[1], reverse=True)[:5]

        # Risk skoru ortalaması
        avg_risk = round(sum(a.risk_score for a in alerts) / total, 1) if total else 0

        # Audit log özeti
        audit_entries = db.query(AuditLogModel).filter(
            AuditLogModel.timestamp >= month_start,
            AuditLogModel.timestamp <  month_end
        ).all()
        actions_taken = len(audit_entries)

        report_data = {
            "report_type":    "Aylık Güvenlik Raporu",
            "period":         month_label,
            "generated_at":   datetime.now().isoformat(),
            "generated_by":   current_user,
            "summary": {
                "total_alerts":    total,
                "critical":        critical_count,
                "high":            high_count,
                "warning":         warning_count,
                "unique_endpoints": unique_hosts,
                "avg_risk_score":  avg_risk,
                "actions_taken":   actions_taken,
                "risk_level":      "KRİTİK" if critical_count > 10 else
                                   "YÜKSEK" if critical_count > 3 else
                                   "ORTA"   if high_count > 10 else "DÜŞÜK",
            },
            "top_threats":     [{"rule": r, "count": c} for r, c in top_rules_sorted],
            "kvkk_note":       (
                "Bu dönemde veri ihlali riski taşıyan kritik alarm tespit edilmiştir. "
                "KVKK Madde 12 kapsamında gerekli teknik tedbirler alınmıştır."
                if critical_count > 0 else
                "Bu dönemde veri ihlali riski taşıyan kritik alarm tespit edilmemiştir."
            ),
            "recommendations": _build_recommendations(critical_count, high_count, top_rules_sorted),
        }

        if format == "json":
            return report_data

        # PDF oluştur
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.units import cm
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4,
                                    rightMargin=2*cm, leftMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)

            styles = getSampleStyleSheet()
            story  = []

            # Başlık
            title_style = ParagraphStyle("title", parent=styles["Title"],
                                         fontSize=20, textColor=colors.HexColor("#1a1a2e"),
                                         spaceAfter=6)
            sub_style   = ParagraphStyle("sub", parent=styles["Normal"],
                                         fontSize=11, textColor=colors.HexColor("#444"),
                                         spaceAfter=4)
            label_style = ParagraphStyle("label", parent=styles["Normal"],
                                         fontSize=9, textColor=colors.HexColor("#888"),
                                         spaceAfter=2)
            body_style  = ParagraphStyle("body", parent=styles["Normal"],
                                         fontSize=10, spaceAfter=6, leading=14)

            story.append(Paragraph("🛡 SolidTrace", title_style))
            story.append(Paragraph(f"Aylık Güvenlik Raporu — {month_label}", sub_style))
            story.append(Paragraph(f"Oluşturulma: {datetime.now().strftime('%d.%m.%Y %H:%M')} | Hazırlayan: {current_user}", label_style))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#ddd"), spaceAfter=12))

            # Özet kutuları
            risk_color = {"KRİTİK": "#e74c3c", "YÜKSEK": "#e67e22",
                          "ORTA": "#f39c12", "DÜŞÜK": "#27ae60"}
            rl = report_data["summary"]["risk_level"]
            summary_data = [
                ["Toplam Alarm", "Kritik", "Yüksek", "Risk Skoru Ort.", "Genel Risk"],
                [
                    str(total), str(critical_count), str(high_count),
                    str(avg_risk), rl,
                ],
            ]
            t = Table(summary_data, colWidths=[3.2*cm]*5)
            t.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
                ("FONTSIZE",    (0,0), (-1,0), 9),
                ("FONTSIZE",    (0,1), (-1,1), 13),
                ("FONTNAME",    (0,1), (-1,1), "Helvetica-Bold"),
                ("BACKGROUND",  (4,1), (4,1), colors.HexColor(risk_color.get(rl, "#888"))),
                ("TEXTCOLOR",   (4,1), (4,1), colors.white),
                ("ALIGN",       (0,0), (-1,-1), "CENTER"),
                ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0,1), (-1,1), [colors.HexColor("#f8f9fa")]),
                ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#dee2e6")),
                ("TOPPADDING",  (0,0), (-1,-1), 8),
                ("BOTTOMPADDING",(0,0), (-1,-1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.5*cm))

            # En çok tetiklenen kurallar
            story.append(Paragraph("En Çok Tetiklenen Tehdit Kuralları", styles["Heading2"]))
            if top_rules_sorted:
                threat_data = [["#", "Kural Adı", "Tetiklenme"]]
                for i, (rule, cnt) in enumerate(top_rules_sorted, 1):
                    threat_data.append([str(i), rule[:60], str(cnt)])
                tt = Table(threat_data, colWidths=[1*cm, 12*cm, 3*cm])
                tt.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
                    ("FONTSIZE",      (0,0), (-1,-1), 9),
                    ("ROWBACKGROUNDS",(0,1), (-1,-1),
                     [colors.HexColor("#ffffff"), colors.HexColor("#f2f2f2")]),
                    ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#ccc")),
                    ("TOPPADDING",    (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ]))
                story.append(tt)
            else:
                story.append(Paragraph("Bu dönemde tehdit tespit edilmedi.", body_style))
            story.append(Spacer(1, 0.4*cm))

            # KVKK notu
            story.append(Paragraph("KVKK Uyum Notu", styles["Heading2"]))
            story.append(Paragraph(report_data["kvkk_note"], body_style))
            story.append(Spacer(1, 0.3*cm))

            # Öneriler
            story.append(Paragraph("Öneriler ve Aksiyonlar", styles["Heading2"]))
            for rec in report_data["recommendations"]:
                story.append(Paragraph(f"• {rec}", body_style))
            story.append(Spacer(1, 0.5*cm))

            # Alt bilgi
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#ccc")))
            story.append(Paragraph(
                "Bu rapor SolidTrace Siber Güvenlik İzleme Platformu tarafından otomatik oluşturulmuştur. "
                "Gizli ve kişiye özeldir.",
                ParagraphStyle("footer", parent=styles["Normal"],
                               fontSize=8, textColor=colors.HexColor("#999"), spaceAfter=0)
            ))

            doc.build(story)
            buf.seek(0)
            filename = f"solidtrace-rapor-{report_dt.strftime('%Y-%m')}.pdf"
            return StreamingResponse(
                buf,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )

        except ImportError:
            raise HTTPException(
                status_code=503,
                detail="PDF oluşturmak için 'reportlab' paketi gerekli: pip install reportlab"
            )
    finally:
        db.close()


def _build_recommendations(critical: int, high: int, top_rules: list) -> list:
    """Alarm istatistiklerine göre otomatik öneri üret."""
    recs = []
    if critical > 0:
        recs.append(f"Bu dönemde {critical} kritik alarm tespit edildi. Etkilenen endpoint'ler incelenmeli.")
    if high > 5:
        recs.append("Yüksek riskli alarm sayısı yüksek — endpoint güvenlik politikaları güçlendirilmeli.")
    if top_rules:
        top_rule = top_rules[0][0]
        recs.append(f"En sık tetiklenen kural: '{top_rule}' — bu konuda kullanıcı farkındalık eğitimi önerilir.")
    recs.append("Tüm kullanıcı parolalarının 90 günde bir değiştirilmesi önerilir.")
    recs.append("Agent'ların güncel sürümde çalıştığından emin olunuz.")
    if not recs:
        recs.append("Bu dönemde önemli bir tehdit tespit edilmedi. İzleme sürdürülmeli.")
    return recs


@app.get("/health")
async def health_check():
    return {
        "status":             "healthy",
        "version":            "6.1.0",
        "timestamp":          datetime.now().isoformat(),
        "active_connections": len(ACTIVE_CONNECTIONS)
    }

# -----------------------------------------------------------------------------
# 9. GİRİŞ NOKTASI
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    logger.info("🚀 SolidTrace SOC Backend v6.1 Başlatılıyor...")
    logger.info("=" * 60)
    logger.info("📋 Varsayılan Giriş: admin / admin123")
    logger.info("=" * 60)

    uvicorn.run(
        "api_advanced:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
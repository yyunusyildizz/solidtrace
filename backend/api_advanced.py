import sys
import os
import json
import uuid
import logging
import asyncio
import httpx
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

# FastAPI ve Yan Bileşenleri
from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, Query, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Pydantic Veri Doğrulama Modelleri
from pydantic import BaseModel, Field

# SQLAlchemy Veritabanı Araçları
from sqlalchemy import create_engine, Column, String, Integer, Text, Boolean, DateTime, desc, or_, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Şifreleme ve JWT
from passlib.context import CryptContext
from jose import JWTError, jwt

# Çevresel Değişken Yönetimi
from dotenv import load_dotenv

# Yapay Zeka Motoru
from groq import Groq

# -----------------------------------------------------------------------------
# 1. AYARLAR, GÜVENLİK VE LOGLAMA KONFİGÜRASYONU
# -----------------------------------------------------------------------------
load_dotenv() 

# Konsol çıktılarını UTF-8'e zorla (Windows karakter hatası önlemi)
sys.stdout.reconfigure(encoding='utf-8')

# Loglama Ayarları
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("SolidTrace.Core")

# Ortam Değişkenlerini Çek
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/solidtrace_db")
OTX_API_KEY = os.getenv("OTX_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
BAZAAR_API_KEY = os.getenv("BAZAAR_API_KEY") 
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "solidtrace-agent-key-2024")  # 🔥 YENİ: Agent güvenliği

# 🔥 AUTH AYARLARI - ÖNEMLİ: Prodüksiyonda SECRET_KEY'i değiştirin!
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION-USE-STRONG-SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 saat (vardiya süresi)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# AI İstemcisi (Global tanımlamıyoruz, Windows multiprocessing hatasını önlemek için)
client_ai = None 

# Basit In-Memory Cache (Tehdit istihbaratını tekrar tekrar sormamak için)
INTEL_CACHE = {} 

# -----------------------------------------------------------------------------
# 2. UYGULAMA BAŞLATMA VE ORTA KATMANLAR (MIDDLEWARE)
# -----------------------------------------------------------------------------
app = FastAPI(
    title="SolidTrace Ultimate SOC",
    description="Next-Gen AI Powered SIEM & EDR Backend - Production Ready",
    version="6.0.0"
)

# CORS Ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 🔒 PRODÜKSIYON: Burayı spesifik domain'e çevirin: ["https://yourdomain.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# 3. VERİTABANI BAĞLANTISI VE MODELLER
# -----------------------------------------------------------------------------
Base = declarative_base()

try:
    # Veritabanı Motoru (Connection Pooling ile)
    engine = create_engine(
        DATABASE_URL, 
        pool_size=20,       # Aynı anda açık bağlantı sayısı
        max_overflow=10,    # Yük binerse ekstra açılacak bağlantı
        pool_pre_ping=True, # Bağlantı kopuk mu diye kontrol et
        pool_recycle=3600   # 1 saatte bir bağlantıyı yenile
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("✅ Veritabanı bağlantısı başarıyla kuruldu.")
except Exception as e:
    logger.critical(f"❌ VERİTABANI HATASI: {str(e)}")
    exit(1)

# --- DB Modeli: Kullanıcılar ---
class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")  # admin, analyst, viewer
    created_at = Column(String)
    last_login = Column(String, nullable=True)

# --- DB Modeli: Tespit Kuralları (Rule Engine) ---
class RuleModel(Base):
    __tablename__ = "detection_rules"
    
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    keyword = Column(String, nullable=False)
    risk_score = Column(Integer, default=50)
    severity = Column(String, default="WARNING")
    created_at = Column(String)
    created_by = Column(String, nullable=True)  # Hangi kullanıcı oluşturdu

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# --- DB Modeli: Alarmlar (Loglar) ---
class AlertModel(Base):
    __tablename__ = "alerts_production_v2"
    
    id = Column(String, primary_key=True, index=True)
    created_at = Column(String, index=True)
    hostname = Column(String, index=True)
    username = Column(String)
    type = Column(String)
    risk_score = Column(Integer)
    rule = Column(String)
    severity = Column(String)
    details = Column(Text)
    command_line = Column(Text)
    pid = Column(Integer)
    serial = Column(String, nullable=True)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# Tabloları oluştur (Yoksa)
Base.metadata.create_all(bind=engine)

# 🔥 BAŞLANGIÇTA VARSAYILAN KULLANICI OLUŞTUR
def create_default_user():
    db = SessionLocal()
    try:
        if not db.query(UserModel).filter(UserModel.username == "admin").first():
            hashed = pwd_context.hash("admin123")
            user = UserModel(
                id=str(uuid.uuid4()), 
                username="admin", 
                hashed_password=hashed, 
                role="admin",
                created_at=datetime.now().isoformat()
            )
            db.add(user)
            db.commit()
            logger.info("🔐 Varsayılan kullanıcı oluşturuldu: admin / admin123")
            logger.warning("⚠️  PRODÜKSIYON: admin şifresini mutlaka değiştirin!")
    except Exception as e:
        logger.error(f"Varsayılan kullanıcı oluşturma hatası: {e}")
    finally:
        db.close()

create_default_user()

# -----------------------------------------------------------------------------
# 4. API VERİ ŞEMALARI (PYDANTIC)
# -----------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str

class DetectionRuleSchema(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    keyword: str = Field(..., min_length=1, max_length=200)
    risk_score: int = Field(..., ge=0, le=100)  # 0-100 arası
    severity: str = Field(..., pattern="^(INFO|WARNING|HIGH|CRITICAL)$")

class EventBase(BaseModel):
    type: str          
    hostname: str      
    user: Optional[str] = "SYSTEM"
    pid: Optional[int] = 0
    details: Optional[str] = ""
    command_line: Optional[str] = ""
    serial: Optional[str] = None
    severity: Optional[str] = "INFO" 
    timestamp: Optional[str] = None

class ActionRequest(BaseModel):
    hostname: str
    pid: Optional[int] = 0
    rule: Optional[str] = None
    severity: Optional[str] = None
    details: Optional[str] = None
    serial: Optional[str] = None
    risk_score: Optional[int] = 0

class HashReport(BaseModel):
    hostname: str
    file_path: str
    file_hash: str
    pid: int

# -----------------------------------------------------------------------------
# 5. AUTH HELPER FONKSİYONLARI
# -----------------------------------------------------------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Şifreyi doğrula"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Şifreyi hashle"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """JWT Token oluştur"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """Token'dan kullanıcıyı çıkar"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Kimlik doğrulama başarısız",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    return username

def verify_agent_key(x_agent_key: Optional[str] = Header(None)):
    """Agent API Key kontrolü"""
    if x_agent_key != AGENT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz Agent API Key"
        )
    return True

# -----------------------------------------------------------------------------
# 6. WEBSOCKET & BROADCAST SİSTEMİ (ANLIK İLETİŞİM)
# -----------------------------------------------------------------------------
ACTIVE_CONNECTIONS: List[WebSocket] = []

async def broadcast(msg: Dict[str, Any]):
    """Tüm bağlı istemcilere (Frontend) mesaj gönderir"""
    if not ACTIVE_CONNECTIONS:
        return
    
    payload = json.dumps(msg, default=str)
    tasks = []
    to_remove = []
    
    for ws in ACTIVE_CONNECTIONS:
        try:
            tasks.append(ws.send_text(payload))
        except Exception:
            to_remove.append(ws)
            
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
        
    for ws in to_remove:
        if ws in ACTIVE_CONNECTIONS:
            ACTIVE_CONNECTIONS.remove(ws)

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket bağlantı endpointi"""
    await websocket.accept()
    ACTIVE_CONNECTIONS.append(websocket)
    logger.info(f"🔌 Yeni WebSocket Bağlantısı. Toplam: {len(ACTIVE_CONNECTIONS)}")
    
    try: 
        while True:
            await websocket.receive_text()  # Kalp atışı / veri bekleme
    except Exception as e:
        logger.debug(f"WebSocket bağlantı hatası: {e}")
    finally:
        if websocket in ACTIVE_CONNECTIONS:
            ACTIVE_CONNECTIONS.remove(websocket)
        logger.info(f"🔌 WebSocket Bağlantısı Koptu. Kalan: {len(ACTIVE_CONNECTIONS)}")

# -----------------------------------------------------------------------------
# 7. TEHDİT İSTİHBARATI VE AI MOTORU
# -----------------------------------------------------------------------------

async def check_otx(file_hash: str) -> Optional[str]:
    """AlienVault OTX Sorgusu"""
    if not OTX_API_KEY:
        return None
        
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(
                url, 
                headers={"X-OTX-API-KEY": OTX_API_KEY}, 
                timeout=5.0
            )
            if res.status_code == 200:
                data = res.json()
                count = data.get("pulse_info", {}).get("count", 0)
                if count > 0:
                    return f"OTX: {count} Tehdit Kaydı Bulundu!"
    except Exception as e:
        logger.error(f"OTX API Hatası: {e}")
        
    return None

async def check_malware_bazaar(file_hash: str) -> Optional[str]:
    """Malware Bazaar Sorgusu"""
    if not BAZAAR_API_KEY:
        return None
        
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}
    
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                url, 
                data=data, 
                headers={"Auth-Key": BAZAAR_API_KEY}, 
                timeout=15.0
            )
            if res.status_code == 200:
                j = res.json()
                if j.get("query_status") == "ok":
                    signature = j['data'][0].get('signature', 'Malware')
                    return f"Bazaar: {signature} Tespit Edildi!"
    except Exception as e:
        logger.error(f"Malware Bazaar API Hatası: {e}")
        
    return None

async def process_threat_intel(report: HashReport):
    """Arka planda tehdit istihbaratı sorgularını çalıştırır"""
    if report.file_hash in INTEL_CACHE:
        return  # Zaten sorgulandı
    
    # Paralel sorgu (Daha hızlı)
    results = await asyncio.gather(
        check_otx(report.file_hash),
        check_malware_bazaar(report.file_hash),
        return_exceptions=True
    )
    
    otx_res, bazaar_res = results
    
    if otx_res and not isinstance(otx_res, Exception):
        await broadcast({
            "type": "ACTION_LOG", 
            "message": f"🚨 [OTX] {otx_res} -> {report.file_path}"
        })
        
    if bazaar_res and not isinstance(bazaar_res, Exception):
        await broadcast({
            "type": "ACTION_LOG", 
            "message": f"🦠 [Bazaar] {bazaar_res} -> {report.file_path}"
        })
        
    # Cache'e al
    INTEL_CACHE[report.file_hash] = True

async def perform_groq_analysis(data: dict):
    """Tier 3 Senior SOC Analisti Modu (AI Analizi)"""
    
    # 🔥 Windows Fix: Client'ı yerel kapsamda başlatıyoruz
    try:
        local_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
    except Exception as e:
        logger.error(f"AI Client Başlatılamadı: {e}")
        local_client = None

    if not local_client: 
        await broadcast({
            "type": "ACTION_LOG", 
            "message": "❌ AI Devre Dışı (API Key Eksik veya Hatalı)"
        })
        return
        
    await broadcast({
        "type": "ACTION_LOG", 
        "message": f"🤖 AI Analizi Başlatıldı: {data.get('rule', 'Bilinmeyen Kural')}"
    })
    
    system_prompt = """Sen dünyanın en yetkin siber güvenlik merkezinde 'Senior Tier 3 SOC Analisti'sin.
    
    Görevin: Sana verilen log verisini analiz edip teknik, kısa ve net bir rapor sunmak.
    
    Kurallar:
    1. ASLA 'Kullanıcıyı eğitin' gibi genel geçer tavsiyeler verme. Teknik aksiyon ver.
    2. MITRE ATT&CK teknik kodlarını (T1059, T1003 vb.) mutlaka kullan.
    3. Eğer olay bir 'False Positive' (Yanıltıcı Alarm) ise bunu açıkça belirt.
    4. Rapor dilin Türkçe ve profesyonel olsun.
    5. Maksimum 200 kelime ile özetle.
    """
    
    user_prompt = f"""
    ANALİZ EDİLECEK LOG PAKETİ:
    --------------------------------------------------
    Host: {data.get('hostname')}
    Process ID: {data.get('pid')}
    Kural: {data.get('rule')}
    Dosya/Komut: {data.get('details')} {data.get('command_line') or ''}
    Risk Skoru: {data.get('risk_score')}
    Şiddet: {data.get('severity')}
    --------------------------------------------------
    
    Lütfen kısa ve öz bir analiz yap. MITRE ATT&CK tekniklerini belirt.
    """

    try:
        completion = local_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,  # Tutarlılık için düşük
            max_tokens=500     # Token limiti
        )
        
        report_content = completion.choices[0].message.content
        
        # Frontend'in anlaması için mesajda 'AI RAPORU' geçmeli
        await broadcast({
            "type": "ACTION_LOG", 
            "message": f"🧠 AI RAPORU:\n{report_content}"
        })
        
        logger.info(f"AI Analizi Tamamlandı: {data.get('hostname')}")
        
    except Exception as e:
        logger.error(f"AI Sorgu Hatası: {e}")
        await broadcast({
            "type": "ACTION_LOG", 
            "message": f"❌ AI Hatası: {str(e)}"
        })

# -----------------------------------------------------------------------------
# 8. API ENDPOINTLERİ
# -----------------------------------------------------------------------------

# --- ⚡ AUTH ENDPOINTLER ---

@app.post("/api/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Kullanıcı girişi - JWT token alır"""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == form_data.username).first()
        
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kullanıcı adı veya şifre hatalı",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Son giriş zamanını güncelle
        user.last_login = datetime.now().isoformat()
        db.commit()
        
        access_token = create_access_token(data={"sub": user.username})
        logger.info(f"✅ Başarılı Giriş: {user.username}")
        
        return {"access_token": access_token, "token_type": "bearer"}
        
    finally:
        db.close()

@app.get("/api/me")
async def get_current_user_info(current_user: str = Depends(get_current_user)):
    """Mevcut kullanıcı bilgisini döner"""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
        
        return {
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at,
            "last_login": user.last_login
        }
    finally:
        db.close()

# --- 📊 ANALİTİK ENDPOINTLER ---

@app.get("/api/analytics")
async def get_analytics(current_user: str = Depends(get_current_user)):
    """Analitik ve grafikler için veri döner"""
    db = SessionLocal()
    try:
        # Son 500 olayı analiz için çek
        alerts = db.query(AlertModel).order_by(desc(AlertModel.created_at)).limit(500).all()
        
        # 1. Şiddet Dağılımı
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        
        # 2. Zaman Çizelgesi
        timeline = {} 
        
        for a in alerts:
            # Severity say
            sev = a.severity if a.severity in severity_counts else "INFO"
            severity_counts[sev] += 1
            
            # Zamanı grupla (Saatlik)
            try:
                if a.created_at:
                    dt = datetime.fromisoformat(a.created_at)
                    time_key = dt.strftime("%H:00") 
                    timeline[time_key] = timeline.get(time_key, 0) + 1
            except: 
                pass

        # Grafiğin düzgün görünmesi için zamanı sırala
        chart_data = [{"time": k, "count": v} for k, v in sorted(timeline.items())]

        return {
            "severity_distribution": [
                {"name": k, "value": v} for k, v in severity_counts.items() if v > 0
            ],
            "activity_trend": chart_data
        }
    finally:
        db.close()

@app.get("/api/stats")
async def get_stats(current_user: str = Depends(get_current_user)):
    """Genel istatistikler"""
    db = SessionLocal()
    try:
        total = db.query(AlertModel).count()
        critical = db.query(AlertModel).filter(AlertModel.risk_score >= 70).count()
        
        # Son 24 saatteki alarm sayısı
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        recent = db.query(AlertModel).filter(AlertModel.created_at >= yesterday).count()
        
        return {
            "total_logs": total,
            "critical_count": critical,
            "last_24h": recent
        }
    finally:
        db.close()

# --- 🎯 KURAL YÖNETİMİ (RULE ENGINE) ---

@app.post("/api/rules")
async def add_rule(rule: DetectionRuleSchema, current_user: str = Depends(get_current_user)):
    """Yeni tespit kuralı ekle"""
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
        
        logger.info(f"✅ Yeni Kural Oluşturuldu: {rule.name} (by {current_user})")
        
        return {"status": "ok", "rule": new_rule.to_dict()}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Kural oluşturma hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/api/rules")
async def get_rules(current_user: str = Depends(get_current_user)):
    """Tüm kuralları listele"""
    db = SessionLocal()
    try:
        rules = db.query(RuleModel).order_by(desc(RuleModel.created_at)).all()
        return [r.to_dict() for r in rules]
    finally:
        db.close()

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str, current_user: str = Depends(get_current_user)):
    """Kural sil"""
    db = SessionLocal()
    try:
        deleted_count = db.query(RuleModel).filter(RuleModel.id == rule_id).delete()
        db.commit()
        
        if deleted_count > 0:
            logger.info(f"🗑️  Kural Silindi: {rule_id} (by {current_user})")
            return {"status": "deleted"}
        else:
            raise HTTPException(status_code=404, detail="Kural bulunamadı")
            
    finally:
        db.close()

# --- 📥 VERİ GİRİŞİ (INGEST) - 🔥 AGENT GÜVENLİĞİ İLE ---

@app.post("/api/v1/ingest") 
async def ingest_event(
    events: List[EventBase], 
    authenticated: bool = Depends(verify_agent_key)
):
    """
    Agent'lardan log girişi - API Key ile korumalı
    
    Header gerekli: X-Agent-Key
    """
    db = SessionLocal()
    try:
        # Veritabanındaki Aktif Kuralları Hafızaya Çek
        active_rules = db.query(RuleModel).all()
        
        processed_count = 0
        
        for event in events:
            # Veriyi temizle ve hazırla
            final_details = event.details or ""
            if event.serial: 
                final_details += f"\n🔍 Donanım Kimliği: {event.serial}"
            
            # Varsayılan Değerler
            score = 10
            rule_name = "Normal Activity"
            current_severity = event.severity or "INFO"
            
            # Arama metnini hazırla
            full_text_search = f"{final_details} {event.command_line} {event.type}".lower()

            # 🎯 Dinamik Kural Eşleştirme (Rule Engine)
            rule_matched = False
            for r in active_rules:
                if r.keyword.lower() in full_text_search:
                    score = r.risk_score
                    rule_name = r.name
                    current_severity = r.severity
                    rule_matched = True
                    break  # İlk eşleşen kuralı al

            # 🛡️ Statik Fallback Kurallar
            if not rule_matched:
                if "usb" in full_text_search:
                    score = 90
                    rule_name = "USB Device Activity"
                    current_severity = "HIGH"
                elif "ransomware" in full_text_search:
                    score = 100
                    rule_name = "Ransomware Alert"
                    current_severity = "CRITICAL"
                elif "mimikatz" in full_text_search:
                    score = 95
                    rule_name = "Credential Dumping Detected"
                    current_severity = "CRITICAL"

            # Alarmı Oluştur ve Kaydet
            new_alert = AlertModel(
                id=str(uuid.uuid4()),
                created_at=event.timestamp or datetime.now().isoformat(),
                hostname=event.hostname,
                username=event.user,
                type=event.type,
                risk_score=score,
                rule=rule_name,
                severity=current_severity,
                details=final_details,
                command_line=event.command_line,
                pid=event.pid,
                serial=event.serial
            )
            db.add(new_alert)
            
            # WebSocket ile frontend'e anlık gönder
            await broadcast({"type": "alert", "data": new_alert.to_dict()})
            processed_count += 1
            
        db.commit()
        logger.info(f"📥 {processed_count} Event İşlendi")
        
        return {"status": "ok", "count": processed_count}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Ingest Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ingest failed: {str(e)}")
    finally:
        db.close()

# --- 🔍 ARAMA VE FİLTRELEME ---

@app.get("/api/alerts")
async def get_alerts(
    q: Optional[str] = None, 
    severity: Optional[str] = None, 
    limit: int = 100,
    current_user: str = Depends(get_current_user)
):
    """
    Gelişmiş Alarm Arama ve Filtreleme
    
    Parametreler:
    - q: Arama terimi (hostname, rule, details, username)
    - severity: Şiddet filtresi (INFO, WARNING, HIGH, CRITICAL)
    - limit: Maksimum sonuç sayısı
    """
    db = SessionLocal()
    try:
        query = db.query(AlertModel)
        
        # Filtre: Şiddet Seviyesi
        if severity and severity.strip():
            query = query.filter(AlertModel.severity == severity)
            
        # Arama: Çoklu sütunda arama
        if q and q.strip():
            search_term = f"%{q}%"
            query = query.filter(or_(
                AlertModel.hostname.ilike(search_term),
                AlertModel.rule.ilike(search_term),
                AlertModel.details.ilike(search_term),
                AlertModel.username.ilike(search_term)
            ))
            
        # Sıralama ve limit
        alerts = query.order_by(desc(AlertModel.created_at)).limit(limit).all()
        return [a.to_dict() for a in alerts]
        
    except Exception as e:
        logger.error(f"Alerts Fetch Error: {e}")
        return []
    finally:
        db.close()

# --- 🧠 ANALİZ VE AKSIYON ---

@app.post("/api/actions/analyze")
async def analyze_host(
    req: ActionRequest, 
    bg: BackgroundTasks, 
    current_user: str = Depends(get_current_user)
):
    """AI destekli olay analizi başlat"""
    await broadcast({
        "type": "ACTION_LOG", 
        "message": f"🔍 Analiz İsteği Alındı: {req.hostname} (PID: {req.pid}) - Talep eden: {current_user}"
    })
    
    # Arka planda AI motorunu tetikle
    bg.add_task(perform_groq_analysis, req.dict()) 
    
    logger.info(f"AI Analizi Başlatıldı: {req.hostname} (by {current_user})")
    
    return {"status": "started", "message": "AI analizi arka planda çalışıyor"}

@app.post("/api/v1/report_hash")
async def report_hash(report: HashReport, bg: BackgroundTasks):
    """Dosya hash'ini tehdit istihbaratı platformlarında sorgula"""
    # Hash kontrolünü arka plana at
    bg.add_task(process_threat_intel, report)
    
    logger.info(f"Hash Analizi Başlatıldı: {report.file_hash[:16]}...")
    
    return {"status": "analyzing", "hash": report.file_hash}

# --- 🧹 YÖNETİM ---

@app.delete("/api/alerts/clear")
async def clear_alerts(current_user: str = Depends(get_current_user)):
    """Tüm alarmları temizle - DİKKAT: Geri alınamaz!"""
    db = SessionLocal()
    try:
        count = db.query(AlertModel).count()
        db.query(AlertModel).delete()
        db.commit()
        
        await broadcast({
            "type": "ACTION_LOG", 
            "message": f"🧹 {count} Alarm Temizlendi (by {current_user})"
        })
        
        logger.warning(f"⚠️  TÜM ALARMLAR TEMİZLENDİ: {count} kayıt (by {current_user})")
        
        return {"status": "cleared", "count": count}
    finally:
        db.close()

# --- ⚡ AGENT KOMUTLARI ---

@app.post("/api/actions/kill")
async def kill_process(req: ActionRequest, current_user: str = Depends(get_current_user)):
    """Process'i sonlandır komutu gönder"""
    await broadcast({
        "type": "COMMAND", 
        "action": "KILL_PROCESS", 
        "target_hostname": req.hostname, 
        "target_pid": req.pid
    })
    
    logger.warning(f"⚠️  KILL PROCESS Komutu: {req.hostname}:{req.pid} (by {current_user})")
    
    return {"status": "sent", "action": "KILL_PROCESS"}

@app.post("/api/actions/isolate")
async def isolate_host(req: ActionRequest, current_user: str = Depends(get_current_user)):
    """Host'u ağdan izole et"""
    await broadcast({
        "type": "COMMAND", 
        "action": "ISOLATE_HOST", 
        "target_hostname": req.hostname
    })
    
    logger.warning(f"🔒 HOST İZOLE EDİLDİ: {req.hostname} (by {current_user})")
    
    return {"status": "sent", "action": "ISOLATE_HOST"}

@app.post("/api/actions/unisolate")
async def unisolate_host(req: ActionRequest, current_user: str = Depends(get_current_user)):
    """Host izolasyonunu kaldır"""
    await broadcast({
        "type": "COMMAND", 
        "action": "UNISOLATE_HOST", 
        "target_hostname": req.hostname
    })
    
    logger.info(f"🔓 HOST İZOLASYON KALDIRILDI: {req.hostname} (by {current_user})")
    
    return {"status": "sent", "action": "UNISOLATE_HOST"}

# --- 🏥 HEALTH CHECK ---

@app.get("/health")
async def health_check():
    """Sistem sağlık durumu kontrolü"""
    return {
        "status": "healthy",
        "version": "6.0.0",
        "timestamp": datetime.now().isoformat(),
        "active_connections": len(ACTIVE_CONNECTIONS)
    }

# -----------------------------------------------------------------------------
# 9. UYGULAMA GİRİŞ NOKTASI
# -----------------------------------------------------------------------------


if __name__ == "__main__":
    import uvicorn
    if sys.platform == 'win32': 
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    logger.info("🚀 SolidTrace SOC Backend v6.0 Başlatılıyor...")
    logger.info("=" * 60)
    logger.info("📋 Varsayılan Giriş Bilgileri:")
    logger.info("   Kullanıcı: admin")
    logger.info("   Şifre: admin123")
    logger.info("=" * 60)
    logger.info("🔑 Agent API Key: Lütfen .env dosyasına AGENT_API_KEY ekleyin")
    logger.info("=" * 60)
    
    uvicorn.run(
        "api_advanced:app",  # ← BURAYI DEĞİŞTİRİN (api_solidtrace_final yerine api_advanced)
        host="127.0.0.1", 
        port=8000, 
        reload=True,
        log_level="info"
    )
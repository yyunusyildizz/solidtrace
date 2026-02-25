"""
threat_hunting.py
Threat Hunting API + Asset & Inventory Yönetimi

Threat Hunting:
  Analist "son 30 günde PowerShell'den Base64 kullanan tüm kullanıcılar"
  gibi proaktif sorgular yapabilir.

Asset & Inventory:
  Her agent kayıt olduğunda makine bilgilerini gönderir.
  SIEM'de "hangi makineler var, hangisi şu an aktif, OS versiyonu ne" görülür.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, func, or_, desc
from sqlalchemy.orm import Session

logger = logging.getLogger("SolidTrace.Hunting")

router = APIRouter(prefix="/api/v1", tags=["threat-hunting"])


# ============================================================
# ASSET (VARLIK) MODELİ — SQLAlchemy
# ============================================================

# Bu satırı api_advanced_v2.py'deki Base ve SessionLocal ile kullan
# from api_advanced_v2 import Base, SessionLocal, get_current_user, AlertModel

class AssetModel:
    """
    Kayıtlı agent/makine bilgisi.
    api_advanced_v2.py'deki Base'den türetilecek — burada şablon olarak gösteriliyor.

    Gerçek kullanım için api_advanced_v2.py'ye şu class'ı ekle:
    class AssetModel(Base):
        __tablename__ = "assets"
        ...
    """
    __tablename__ = "assets"

    id             = Column(String, primary_key=True)   # hostname
    hostname       = Column(String, index=True)
    ip_address     = Column(String)
    os_version     = Column(String)
    agent_version  = Column(String)
    username       = Column(String)                     # Son aktif kullanıcı
    first_seen     = Column(String)
    last_seen      = Column(String, index=True)
    is_online      = Column(Boolean, default=True)
    is_isolated    = Column(Boolean, default=False)
    alert_count    = Column(Integer, default=0)
    risk_score     = Column(Integer, default=0)
    tags           = Column(Text, default="")           # CSV: server,critical,dc


# ============================================================
# PYDANTIC MODELLER
# ============================================================

class AssetRegister(BaseModel):
    """Agent başlangıçta bu bilgileri gönderir."""
    hostname:      str
    ip_address:    Optional[str] = None
    os_version:    Optional[str] = None
    agent_version: Optional[str] = "unknown"
    username:      Optional[str] = None

class HuntingQuery(BaseModel):
    """
    Threat hunting sorgu modeli.
    Desteklenen alanlar: hostname, user, type, severity, details
    Desteklenen operatörler: AND, OR, NOT, wildcards (*)
    Örnekler:
      type:PROCESS_CREATED AND details:*powershell* AND details:*base64*
      severity:CRITICAL AND hostname:WORKSTATION-*
      user:admin AND NOT hostname:DC-01
    """
    query:      str
    start_date: Optional[str] = None    # ISO format: 2026-01-01
    end_date:   Optional[str] = None
    limit:      int = 100
    page:       int = 1

class HuntingResult(BaseModel):
    total:    int
    page:     int
    results:  List[dict]
    took_ms:  int


# ============================================================
# THREAT HUNTING SORGU MOTORU
# ============================================================

class QueryParser:
    """
    Basit alan:değer sorgu dili.
    'type:PROCESS_CREATED AND details:*base64* AND NOT user:system'
    """

    SUPPORTED_FIELDS = {"hostname", "user", "type", "severity", "details",
                        "command_line", "pid", "rule"}

    def parse(self, query_str: str) -> dict:
        """Sorguyu SQLAlchemy filtrelerine çevirilebilir yapıya parse et."""
        tokens = self._tokenize(query_str)
        return {"tokens": tokens, "raw": query_str}

    def _tokenize(self, query: str) -> List[dict]:
        import re
        tokens = []
        # field:value veya field:*wildcard* veya AND/OR/NOT
        pattern = r'(\w+):(\S+)|(\bAND\b|\bOR\b|\bNOT\b)'

        for match in re.finditer(pattern, query, re.IGNORECASE):
            if match.group(1):  # field:value
                field = match.group(1).lower()
                value = match.group(2).strip('"\'')
                if field in self.SUPPORTED_FIELDS:
                    tokens.append({"type": "condition", "field": field, "value": value})
            elif match.group(3):  # AND/OR/NOT
                tokens.append({"type": "operator", "op": match.group(3).upper()})

        return tokens

    def to_sql_filters(self, tokens: List[dict], AlertModel) -> List:
        """Token listesini SQLAlchemy filter listesine çevir."""
        from sqlalchemy import and_, or_, not_
        import fnmatch
        filters = []
        negate  = False

        for token in tokens:
            if token["type"] == "operator":
                if token["op"] == "NOT":
                    negate = True
                continue

            if token["type"] == "condition":
                field = token["field"]
                value = token["value"]

                # Wildcard desteği (* → SQL LIKE %)
                if "*" in value:
                    sql_value = value.replace("*", "%")
                    col = getattr(AlertModel, field, None)
                    if col is not None:
                        f = col.ilike(sql_value)
                        filters.append(~f if negate else f)
                else:
                    col = getattr(AlertModel, field, None)
                    if col is not None:
                        f = col.ilike(f"%{value}%")
                        filters.append(~f if negate else f)

                negate = False

        return filters


# ============================================================
# API ENDPOINTLERİ
# ============================================================
# Bu fonksiyonları api_advanced_v2.py'ye entegre et
# from threat_hunting import get_hunting_routes
# app.include_router(get_hunting_routes(SessionLocal, AlertModel, get_current_user))

def get_hunting_routes(SessionLocal, AlertModel, get_current_user, get_ueba_fn=None, get_sigma_fn=None):
    """FastAPI router'ı döndür — api_advanced_v2.py'ye include edilecek."""

    parser = QueryParser()

    @router.post("/hunt", response_model=dict)
    async def threat_hunt(
        q: HuntingQuery,
        current_user: str = Depends(get_current_user)
    ):
        """
        Threat Hunting ana endpoint.
        Örnek sorgu: {"query": "type:PROCESS_CREATED AND details:*mimikatz*", "start_date": "2026-01-01"}
        """
        import time
        start = time.time()

        db = SessionLocal()
        try:
            parsed = parser.parse(q.query)
            filters = parser.to_sql_filters(parsed["tokens"], AlertModel)

            query = db.query(AlertModel)

            # Tarih filtreleri
            if q.start_date:
                query = query.filter(AlertModel.created_at >= q.start_date)
            if q.end_date:
                query = query.filter(AlertModel.created_at <= q.end_date + "T23:59:59")

            # Alan filtreleri
            if filters:
                from sqlalchemy import and_
                query = query.filter(and_(*filters))

            total  = query.count()
            offset = (q.page - 1) * q.limit
            rows   = query.order_by(desc(AlertModel.created_at)).offset(offset).limit(q.limit).all()

            took_ms = int((time.time() - start) * 1000)
            logger.info("🔍 [HUNT] '%s' → %d sonuç (%dms)", q.query, total, took_ms)

            return {
                "total":   total,
                "page":    q.page,
                "took_ms": took_ms,
                "query":   q.query,
                "results": [r.to_dict() for r in rows],
            }
        finally:
            db.close()

    @router.get("/hunt/suggestions")
    async def hunt_suggestions(current_user: str = Depends(get_current_user)):
        """Hazır hunting sorgu önerileri."""
        return {
            "queries": [
                {
                    "name":        "PowerShell Base64 Komutlar",
                    "description": "Encode edilmiş PowerShell komutları — genellikle malware imzası",
                    "query":       "type:PROCESS_CREATED AND details:*base64*",
                    "mitre":       "T1059.001",
                },
                {
                    "name":        "Mimikatz Tespiti",
                    "description": "Credential dumping araçları",
                    "query":       "details:*mimikatz* OR details:*sekurlsa* OR details:*lsadump*",
                    "mitre":       "T1003",
                },
                {
                    "name":        "Lateral Movement (PsExec/WMI)",
                    "description": "Uzak komut çalıştırma araçları",
                    "query":       "details:*psexec* OR details:*wmiexec* OR details:*smbexec*",
                    "mitre":       "T1021",
                },
                {
                    "name":        "Scheduled Task Oluşturma",
                    "description": "Persistence için zamanlı görev",
                    "query":       "type:SCHTASK_CREATED OR details:*schtasks*",
                    "mitre":       "T1053",
                },
                {
                    "name":        "Admin Grubu Değişiklikleri",
                    "description": "Administrators grubuna ekleme",
                    "query":       "type:GROUP_MEMBER_ADDED OR details:*administrators*",
                    "mitre":       "T1098",
                },
                {
                    "name":        "Log Temizleme",
                    "description": "Saldırı izlerini silme",
                    "query":       "type:LOG_CLEARED OR details:*clear-eventlog*",
                    "mitre":       "T1070",
                },
                {
                    "name":        "Kritik Alarmlar (Son 24 saat)",
                    "description": "En yüksek riskli olaylar",
                    "query":       "severity:CRITICAL",
                    "mitre":       "",
                },
                {
                    "name":        "USB Cihaz Aktivitesi",
                    "description": "Takılan/çıkarılan USB cihazlar",
                    "query":       "type:USB_DEVICE_DETECTED",
                    "mitre":       "T1091",
                },
            ]
        }

    @router.post("/assets/register")
    async def register_asset(asset: AssetRegister):
        """
        Agent her başladığında bu endpoint'i çağırır.
        Makine envanterini günceller.
        """
        db = SessionLocal()
        try:
            now = datetime.utcnow().isoformat() + "Z"
            existing = db.query(AlertModel).filter(
                AlertModel.hostname == asset.hostname
            ).first()

            # AlertModel yerine AssetModel kullanılacak — entegrasyon notu
            # Şimdilik inventory verisi alerts tablosuna özel tip olarak gönderilsin
            from uuid import uuid4
            inventory_event = AlertModel(
                id          = str(uuid4()),
                created_at  = now,
                hostname    = asset.hostname,
                username    = asset.username or "system",
                type        = "ASSET_HEARTBEAT",
                risk_score  = 0,
                rule        = "Asset Inventory",
                severity    = "INFO",
                details     = f"OS: {asset.os_version} | IP: {asset.ip_address} | Agent: {asset.agent_version}",
                command_line= "",
                pid         = 0,
            )
            db.add(inventory_event)
            db.commit()

            return {"status": "registered", "hostname": asset.hostname, "timestamp": now}
        finally:
            db.close()

    @router.get("/assets")
    async def list_assets(current_user: str = Depends(get_current_user)):
        """
        Kayıtlı tüm asset'leri listele.
        Son 24 saat içinde heartbeat gönderenleri 'online' olarak işaretle.
        """
        db = SessionLocal()
        try:
            cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()

            # Her hostname'in en son heartbeat'ini al
            from sqlalchemy import func
            subq = db.query(
                AlertModel.hostname,
                func.max(AlertModel.created_at).label("last_seen"),
                func.count(AlertModel.id).label("alert_count"),
                func.max(AlertModel.risk_score).label("max_risk"),
            ).filter(
                AlertModel.type == "ASSET_HEARTBEAT"
            ).group_by(AlertModel.hostname).subquery()

            rows = db.query(subq).all()

            assets = []
            for row in rows:
                last_seen = row.last_seen or ""
                is_online = last_seen >= cutoff if last_seen else False
                assets.append({
                    "hostname":    row.hostname,
                    "last_seen":   last_seen,
                    "is_online":   is_online,
                    "alert_count": row.alert_count,
                    "max_risk":    row.max_risk or 0,
                    "status":      "🟢 Online" if is_online else "🔴 Offline",
                })

            assets.sort(key=lambda x: x["last_seen"], reverse=True)
            return {"total": len(assets), "assets": assets}
        finally:
            db.close()

    @router.get("/assets/{hostname}/timeline")
    async def asset_timeline(
        hostname: str,
        hours:    int = Query(default=24, ge=1, le=168),
        current_user: str = Depends(get_current_user)
    ):
        """Bir makinenin son N saatlik olay zaman çizelgesi."""
        db = SessionLocal()
        try:
            cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            events = db.query(AlertModel).filter(
                AlertModel.hostname == hostname,
                AlertModel.created_at >= cutoff,
            ).order_by(desc(AlertModel.created_at)).limit(200).all()

            return {
                "hostname": hostname,
                "hours":    hours,
                "count":    len(events),
                "events":   [e.to_dict() for e in events],
            }
        finally:
            db.close()

    @router.get("/ueba/profiles")
    async def ueba_profiles(current_user: str = Depends(get_current_user)):
        """Tüm UEBA kullanıcı profillerini listele."""
        if not get_ueba_fn or not get_ueba_fn():
            return {"error": "UEBA motoru aktif değil"}
        return {"profiles": get_ueba_fn().get_all_profiles()}

    @router.get("/ueba/profiles/{username}")
    async def ueba_profile(username: str, current_user: str = Depends(get_current_user)):
        """Tek kullanıcının UEBA profilini getir."""
        if not get_ueba_fn or not get_ueba_fn():
            return {"error": "UEBA motoru aktif değil"}
        profile = get_ueba_fn().get_user_profile(username)
        if not profile:
            raise HTTPException(status_code=404, detail=f"{username} profili bulunamadı")
        return profile

    @router.get("/sigma/stats")
    async def sigma_stats(current_user: str = Depends(get_current_user)):
        """Yüklü Sigma kural istatistikleri."""
        if not get_sigma_fn or not get_sigma_fn():
            return {"error": "Sigma motoru aktif değil"}
        return get_sigma_fn().stats()

    @router.post("/sigma/rules")
    async def add_sigma_rule(
        yaml_content: str,
        current_user: str = Depends(get_current_user)
    ):
        """Manuel Sigma kural ekle."""
        if not get_sigma_fn or not get_sigma_fn():
            raise HTTPException(status_code=503, detail="Sigma motoru aktif değil")
        ok = get_sigma_fn().add_rule_from_yaml(yaml_content)
        if not ok:
            raise HTTPException(status_code=400, detail="Geçersiz Sigma kural formatı")
        return {"status": "ok", "total_rules": len(get_sigma_fn().rules)}

    @router.post("/sigma/update")
    async def update_sigma_rules(current_user: str = Depends(get_current_user)):
        """Sigma kurallarını GitHub'dan güncelle."""
        if not get_sigma_fn or not get_sigma_fn():
            raise HTTPException(status_code=503, detail="Sigma motoru aktif değil")
        count = await get_sigma_fn().update_rules()
        return {"status": "ok", "downloaded": count, "total": len(get_sigma_fn().rules)}

    return router

"""
ueba_engine.py
User and Entity Behavior Analytics

QRadar UBA / Splunk UBA'nın temel özelliği:
Kullanıcının ve makinenin "normal" davranışını öğrenir,
sapmaları tespit eder.

Öğrenilen baseline'lar:
  - Çalışma saatleri (hangi saatte login olur)
  - Hangi makinelerden bağlanır
  - Günlük ortalama process sayısı
  - Tipik network hedefleri
  - Dosya erişim hızı
  - Ortalama risk skoru

Anomali tespiti:
  - Olağandışı saat (gece 3 login)
  - Yeni makine (daha önce hiç bağlanmadığı)
  - Risk skoru ani artışı
  - Normalden çok fazla process
  - İlk kez görülen network hedefi
"""

import os
import json
import math
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("SolidTrace.UEBA")

BASELINE_DIR  = Path(os.getenv("UEBA_BASELINE_DIR", "ueba_baselines"))
LEARN_DAYS    = int(os.getenv("UEBA_LEARN_DAYS", "7"))       # Baseline öğrenme süresi
ANOMALY_SCORE = int(os.getenv("UEBA_ANOMALY_THRESHOLD", "70"))  # Bu skorun üstü alarm


@dataclass
class UserBaseline:
    """Bir kullanıcının öğrenilmiş normal davranış profili."""
    username:       str
    first_seen:     str                     # ISO timestamp
    last_updated:   str
    observation_days: int = 0

    # Çalışma saatleri (0-23 saat, sıklık sayısı)
    hour_distribution: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # Bağlandığı makineler ve sıklığı
    known_hosts:    Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Günlük ortalama event sayısı
    daily_events:   List[int] = field(default_factory=list)

    # Risk skoru geçmişi (son 30 gün ortalaması)
    risk_scores:    List[float] = field(default_factory=list)

    # Erişilen network hedefleri
    network_targets: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Tipik process'ler
    typical_processes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def is_mature(self) -> bool:
        """Baseline yeterince olgun mu? (En az LEARN_DAYS gün gözlem)"""
        return self.observation_days >= LEARN_DAYS

    def avg_risk(self) -> float:
        if not self.risk_scores:
            return 0.0
        return sum(self.risk_scores[-30:]) / len(self.risk_scores[-30:])

    def typical_hours(self) -> List[int]:
        """En sık kullanılan 3 saatlik pencereyi döndür."""
        if not self.hour_distribution:
            return list(range(9, 18))
        total = sum(self.hour_distribution.values())
        return [h for h, c in self.hour_distribution.items()
                if c / total > 0.05]  # %5'ten fazla aktivite olan saatler

    def to_dict(self) -> dict:
        d = asdict(self)
        d["hour_distribution"]  = dict(self.hour_distribution)
        d["known_hosts"]        = dict(self.known_hosts)
        d["network_targets"]    = dict(self.network_targets)
        d["typical_processes"]  = dict(self.typical_processes)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "UserBaseline":
        b = cls(
            username       = data["username"],
            first_seen     = data["first_seen"],
            last_updated   = data["last_updated"],
            observation_days = data.get("observation_days", 0),
            daily_events   = data.get("daily_events", []),
            risk_scores    = data.get("risk_scores", []),
        )
        b.hour_distribution  = defaultdict(int, {int(k): v for k, v in data.get("hour_distribution", {}).items()})
        b.known_hosts        = defaultdict(int, data.get("known_hosts", {}))
        b.network_targets    = defaultdict(int, data.get("network_targets", {}))
        b.typical_processes  = defaultdict(int, data.get("typical_processes", {}))
        return b


@dataclass
class AnomalyAlert:
    username:    str
    hostname:    str
    anomaly:     str
    score:       int       # 0-100
    description: str
    evidence:    dict
    timestamp:   str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_alert_dict(self) -> dict:
        return {
            "type":        "UEBA_ANOMALY",
            "rule":        f"UEBA:{self.anomaly}",
            "severity":    "HIGH" if self.score >= 80 else "MEDIUM",
            "description": self.description,
            "hostname":    self.hostname,
            "user":        self.username,
            "details":     f"Anomali skoru: {self.score}/100 | {self.description}",
            "timestamp":   self.timestamp,
            "mitre":       [],
            "risk": {
                "score": self.score,
                "level": "HIGH" if self.score >= 80 else "MEDIUM",
            },
            "evidence": self.evidence,
        }


class BaselineStore:
    """Baseline'ları disk'e kaydet/oku — JSON formatında."""

    def __init__(self):
        BASELINE_DIR.mkdir(exist_ok=True)

    def load(self, username: str) -> Optional[UserBaseline]:
        path = BASELINE_DIR / f"{self._safe(username)}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return UserBaseline.from_dict(data)
        except Exception as e:
            logger.debug("Baseline yükleme hatası [%s]: %s", username, e)
            return None

    def save(self, baseline: UserBaseline) -> None:
        path = BASELINE_DIR / f"{self._safe(baseline.username)}.json"
        try:
            path.write_text(
                json.dumps(baseline.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception as e:
            logger.debug("Baseline kaydetme hatası: %s", e)

    def load_all(self) -> Dict[str, UserBaseline]:
        baselines = {}
        for path in BASELINE_DIR.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                b = UserBaseline.from_dict(data)
                baselines[b.username] = b
            except Exception:
                pass
        return baselines

    @staticmethod
    def _safe(username: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_-]", "_", username)[:64]


import re


class UEBAEngine:
    """
    Ana UEBA motoru.
    Her gelen event ile baseline'ı günceller,
    olgun baseline varsa anomali kontrolü yapar.
    """

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.store          = BaselineStore()
        self.baselines:     Dict[str, UserBaseline] = {}
        self._today_counts: Dict[str, int] = defaultdict(int)  # user → bugünkü event sayısı
        self._today         = datetime.utcnow().date()
        self._suppress:     Dict[str, datetime] = {}

        # Var olan baseline'ları yükle
        self.baselines = self.store.load_all()
        logger.info(
            "🧠 [UEBA] Motor başlatıldı. %d kullanıcı profili yüklendi.",
            len(self.baselines)
        )

    async def process_event(self, event: dict) -> None:
        """Her olayı baseline güncelleme + anomali tespiti için işle."""
        user     = event.get("user", "")
        hostname = event.get("hostname", "")

        if not user or user in ("unknown", "N/A", "SYSTEM"):
            return

        # Baseline güncelle
        baseline = self._get_or_create(user)
        self._update_baseline(baseline, event)

        # Yeterince olgun değilse anomali kontrolü yapma
        if not baseline.is_mature():
            return

        # Anomali kontrolleri
        anomalies = []
        anomalies += self._check_off_hours(event, baseline)
        anomalies += self._check_new_host(event, baseline)
        anomalies += self._check_risk_spike(event, baseline)
        anomalies += self._check_high_frequency(user, baseline)
        anomalies += self._check_new_network_target(event, baseline)

        # En yüksek skorlu anomaliyi bildir
        if anomalies:
            anomalies.sort(key=lambda a: a.score, reverse=True)
            top = anomalies[0]
            if top.score >= ANOMALY_SCORE:
                await self._emit(top)

    def _get_or_create(self, username: str) -> UserBaseline:
        if username not in self.baselines:
            b = self.store.load(username)
            if b is None:
                b = UserBaseline(
                    username     = username,
                    first_seen   = datetime.utcnow().isoformat(),
                    last_updated = datetime.utcnow().isoformat(),
                )
                logger.info("👤 [UEBA] Yeni kullanıcı profili: %s", username)
            self.baselines[username] = b
        return self.baselines[username]

    def _update_baseline(self, baseline: UserBaseline, event: dict) -> None:
        """Baseline'ı gelen event verisiyle güncelle."""
        now      = datetime.utcnow()
        hostname = event.get("hostname", "")

        # Saat dağılımı
        baseline.hour_distribution[now.hour] += 1

        # Bilinen makineler
        if hostname:
            baseline.known_hosts[hostname] += 1

        # Risk skoru geçmişi
        risk = event.get("risk", {}).get("score", 0)
        if risk:
            baseline.risk_scores.append(float(risk))
            baseline.risk_scores = baseline.risk_scores[-90:]  # Son 90 kayıt

        # Process tespiti
        if event.get("type") in ("PROCESS_CREATED", "PROCESS_CREATE_EVT"):
            proc = event.get("details", "").split("\\")[-1].lower()
            if proc:
                baseline.typical_processes[proc] += 1

        # Network hedefleri
        if event.get("type") == "NETWORK_CONNECTION":
            target = event.get("details", "")
            if target:
                baseline.network_targets[target] += 1

        # Bugünkü event sayacı
        today = now.date()
        if today != self._today:
            # Gün değişti — günlük sayıyı kaydet
            for u, count in self._today_counts.items():
                if u in self.baselines:
                    self.baselines[u].daily_events.append(count)
                    self.baselines[u].daily_events = self.baselines[u].daily_events[-30:]
                    self.baselines[u].observation_days += 1
            self._today_counts.clear()
            self._today = today

        self._today_counts[baseline.username] += 1
        baseline.last_updated = now.isoformat()

        # Her 50 event'te bir diske kaydet
        total = sum(baseline.hour_distribution.values())
        if total % 50 == 0:
            self.store.save(baseline)

    # ------------------------------------------------------------------
    # ANOMALİ KONTROL KURALLARI
    # ------------------------------------------------------------------

    def _check_off_hours(self, event: dict, b: UserBaseline) -> List[AnomalyAlert]:
        """Kullanıcı için olağandışı saatte aktivite."""
        hour          = datetime.utcnow().hour
        typical_hours = b.typical_hours()

        if not typical_hours or hour in typical_hours:
            return []

        # Ne kadar olağandışı? Hiç aktivite yoksa maksimum skor
        hour_freq = b.hour_distribution.get(hour, 0)
        total     = sum(b.hour_distribution.values()) or 1
        ratio     = hour_freq / total

        if ratio < 0.02:  # %2'den az aktivite olan saat
            score = 85 if 0 <= hour <= 5 else 65  # Gece yarısı daha kritik
            return [AnomalyAlert(
                username    = b.username,
                hostname    = event.get("hostname", ""),
                anomaly     = "OFF_HOURS_ACCESS",
                score       = score,
                description = f"{b.username} olağandışı saatte aktif: {hour:02d}:00 (normal: {min(typical_hours):02d}:00-{max(typical_hours):02d}:00)",
                evidence    = {"hour": hour, "typical_hours": typical_hours, "event_type": event.get("type")},
            )]
        return []

    def _check_new_host(self, event: dict, b: UserBaseline) -> List[AnomalyAlert]:
        """Kullanıcı daha önce hiç bağlanmadığı makineden geliyor."""
        hostname = event.get("hostname", "")
        if not hostname or hostname in b.known_hosts:
            return []

        return [AnomalyAlert(
            username    = b.username,
            hostname    = hostname,
            anomaly     = "NEW_HOST_ACCESS",
            score       = 75,
            description = f"{b.username} daha önce hiç kullanmadığı makineden bağlandı: {hostname}",
            evidence    = {
                "new_host":   hostname,
                "known_hosts": list(b.known_hosts.keys())[:10],
            },
        )]

    def _check_risk_spike(self, event: dict, b: UserBaseline) -> List[AnomalyAlert]:
        """Risk skoru normalin çok üzerinde."""
        current_risk = event.get("risk", {}).get("score", 0)
        avg_risk     = b.avg_risk()

        if avg_risk < 10 or current_risk < 50:
            return []

        # Normalin 3 katı üzerindeyse anomali
        if current_risk > avg_risk * 3:
            score = min(95, int(50 + (current_risk - avg_risk * 3)))
            return [AnomalyAlert(
                username    = b.username,
                hostname    = event.get("hostname", ""),
                anomaly     = "RISK_SPIKE",
                score       = score,
                description = f"{b.username} risk skoru anormal yükseldi: {current_risk:.0f} (normal ortalama: {avg_risk:.0f})",
                evidence    = {"current_risk": current_risk, "avg_risk": avg_risk},
            )]
        return []

    def _check_high_frequency(self, username: str, b: UserBaseline) -> List[AnomalyAlert]:
        """Bugün normalden çok fazla event üretildi."""
        today_count = self._today_counts.get(username, 0)
        if not b.daily_events or today_count < 10:
            return []

        avg_daily = sum(b.daily_events) / len(b.daily_events)
        if avg_daily < 1:
            return []

        if today_count > avg_daily * 4:
            return [AnomalyAlert(
                username    = username,
                hostname    = "multiple",
                anomaly     = "HIGH_FREQUENCY",
                score       = 70,
                description = f"{username} bugün normalin 4 katı event üretti: {today_count} (günlük ort: {avg_daily:.0f})",
                evidence    = {"today": today_count, "avg_daily": avg_daily},
            )]
        return []

    def _check_new_network_target(self, event: dict, b: UserBaseline) -> List[AnomalyAlert]:
        """Kullanıcı daha önce hiç bağlanmadığı network hedefine erişiyor."""
        if event.get("type") != "NETWORK_CONNECTION":
            return []

        target = event.get("details", "")
        if not target or target in b.network_targets:
            return []

        # Çok az bilinen target varsa kontrol etme (henüz öğrenme aşaması)
        if len(b.network_targets) < 5:
            return []

        return [AnomalyAlert(
            username    = b.username,
            hostname    = event.get("hostname", ""),
            anomaly     = "NEW_NETWORK_TARGET",
            score       = 60,
            description = f"{b.username} daha önce bağlanmadığı hedefe erişiyor: {target}",
            evidence    = {"new_target": target},
        )]

    # ------------------------------------------------------------------
    # ALARM GÖNDERME
    # ------------------------------------------------------------------

    async def _emit(self, anomaly: AnomalyAlert) -> None:
        key  = f"{anomaly.anomaly}:{anomaly.username}:{anomaly.hostname}"
        now  = datetime.utcnow()
        last = self._suppress.get(key)
        if last and (now - last).total_seconds() < 300:  # 5 dk suppression
            return

        self._suppress[key] = now

        logger.warning(
            "🧠 [UEBA] Anomali: %s | %s | Skor: %d",
            anomaly.anomaly, anomaly.username, anomaly.score
        )

        if self.alert_callback:
            await self.alert_callback(anomaly.to_alert_dict())

    def get_user_profile(self, username: str) -> Optional[dict]:
        """API endpoint için kullanıcı profili döndür."""
        b = self.baselines.get(username)
        if not b:
            b = self.store.load(username)
        if not b:
            return None

        typical_hours = b.typical_hours()
        return {
            "username":        b.username,
            "first_seen":      b.first_seen,
            "last_updated":    b.last_updated,
            "observation_days": b.observation_days,
            "is_mature":       b.is_mature(),
            "typical_hours":   f"{min(typical_hours, default=9):02d}:00 - {max(typical_hours, default=18):02d}:00" if typical_hours else "Öğreniliyor...",
            "known_hosts":     list(b.known_hosts.keys()),
            "avg_risk_score":  round(b.avg_risk(), 1),
            "top_processes":   sorted(b.typical_processes.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    def get_all_profiles(self) -> List[dict]:
        """Tüm kullanıcı profillerini döndür."""
        result = []
        for username in self.baselines:
            profile = self.get_user_profile(username)
            if profile:
                result.append(profile)
        return result

    def flush_baselines(self) -> None:
        """Tüm baseline'ları diske kaydet."""
        for baseline in self.baselines.values():
            self.store.save(baseline)
        logger.info("💾 [UEBA] %d baseline kaydedildi.", len(self.baselines))


# Singleton
_ueba: Optional[UEBAEngine] = None

async def init_ueba(alert_callback) -> UEBAEngine:
    global _ueba
    _ueba = UEBAEngine(alert_callback=alert_callback)
    return _ueba

def get_ueba() -> Optional[UEBAEngine]:
    return _ueba

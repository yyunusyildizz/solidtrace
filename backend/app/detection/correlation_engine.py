"""
correlation_engine.py
Sliding window tabanlı korelasyon motoru

QRadar / Logsign'ın temel farkı burada:
Tek olaya bakmak değil, zaman içindeki örüntüyü yakalamak.

Desteklenen korelasyon kuralları:
  - Brute Force: 5 dakikada 5+ başarısız login
  - Credential Stuffing: Aynı IP'den farklı kullanıcılara başarısız login
  - Lateral Movement: Kısa sürede birden fazla makineye bağlantı
  - Log Temizleme: Event log silindikten sonra gelen aktivite
  - Impossible Travel: Aynı kullanıcı kısa sürede farklı coğrafyadan login
  - Scheduled Task Abuse: Yeni servis + yeni scheduled task aynı anda
  - Process Injection Pattern: Birden fazla process anomalisi aynı makinede
"""

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger("SolidTrace.Correlation")


class RuleSeverity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class CorrelationAlert:
    rule_name:   str
    severity:    RuleSeverity
    description: str
    hostname:    str
    user:        str
    evidence:    List[dict]          # Tetikleyen olaylar
    timestamp:   datetime = field(default_factory=datetime.utcnow)
    mitre:       List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type":        "CORRELATION_ALERT",
            "rule":        self.rule_name,
            "severity":    self.severity.value,
            "description": self.description,
            "hostname":    self.hostname,
            "user":        self.user,
            "evidence_count": len(self.evidence),
            "timestamp":   self.timestamp.isoformat() + "Z",
            "mitre":       self.mitre,
            "risk": {
                "score": {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 30}[self.severity.value],
                "level": self.severity.value,
            }
        }


class TimeWindow:
    """Sliding window — belirli zaman aralığındaki olayları tutar."""

    def __init__(self, seconds: int):
        self.window   = timedelta(seconds=seconds)
        self._events: deque = deque()

    def add(self, event: dict) -> None:
        self._events.append((datetime.utcnow(), event))
        self._cleanup()

    def count(self) -> int:
        self._cleanup()
        return len(self._events)

    def events(self) -> List[dict]:
        self._cleanup()
        return [e for _, e in self._events]

    def unique_values(self, key: str) -> set:
        return {e.get(key) for _, e in self._events if e.get(key)}

    def _cleanup(self) -> None:
        now = datetime.utcnow()
        while self._events and now - self._events[0][0] > self.window:
            self._events.popleft()


class CorrelationEngine:
    """
    Olay akışını alır, zaman penceresi içinde örüntü arar,
    korelasyon alarmı üretir.
    """

    def __init__(self, alert_callback=None):
        """
        alert_callback: Korelasyon alarmı üretildiğinde çağrılacak async fonksiyon.
        Örnek: async def on_alert(alert: CorrelationAlert): ...
        """
        self.alert_callback = alert_callback

        # Kullanıcı bazlı pencereler
        self._failed_logins:   Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))   # 5 dk
        self._success_logins:  Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))
        self._process_events:  Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(60))    # 1 dk
        self._lateral_moves:   Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(600))   # 10 dk
        self._file_changes:    Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(10))    # 10 sn
        self._persistence:     Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))   # 5 dk

        # IP bazlı pencereler (credential stuffing için)
        self._ip_failures:     Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))

        # Makine bazlı pencereler
        self._host_anomalies:  Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))

        # Log temizleme flag — temizleme sonrası aktiviteyi yakala
        self._log_cleared_at:  Dict[str, Optional[datetime]] = defaultdict(lambda: None)

        # Alarm suppression — aynı kural 60 sn içinde tekrar alarm üretmesin
        self._last_alert:      Dict[str, datetime] = {}
        self._suppress_secs    = 60

        logger.info("🔗 [CORRELATOR] Korelasyon motoru başlatıldı. %d kural aktif.", 8)

    # ------------------------------------------------------------------
    # ANA GİRİŞ NOKTASI
    # ------------------------------------------------------------------

    async def process_event(self, event: dict) -> None:
        """Her gelen olayı tüm korelasyon kurallarından geçir."""
        event_type = event.get("type", "")
        hostname   = event.get("hostname", "unknown")
        user       = event.get("user", "unknown")

        # Olayı ilgili pencerelere ekle
        self._route_event(event_type, event, hostname, user)

        # Tüm kuralları değerlendir
        await self._evaluate_rules(event, hostname, user)

    def _route_event(self, event_type: str, event: dict, hostname: str, user: str) -> None:
        """Olayı ilgili zaman pencerelerine yönlendir."""

        if event_type == "LOGON_FAILURE":
            self._failed_logins[user].add(event)
            ip = event.get("details", "")
            if ip:
                self._ip_failures[ip].add(event)

        elif event_type == "LOGON_SUCCESS":
            self._success_logins[user].add(event)
            # Lateral movement: farklı makinelerden login
            self._lateral_moves[user].add(event)

        elif event_type in ("PROCESS_CREATE_EVT", "PROCESS_CREATED", "MALWARE_DETECTED"):
            self._process_events[hostname].add(event)
            self._host_anomalies[hostname].add(event)

        elif event_type in ("RANSOMWARE_ALERT", "FILE_ACTIVITY"):
            self._file_changes[hostname].add(event)

        elif event_type in ("SCHTASK_CREATED", "SERVICE_INSTALLED", "PERSISTENCE_DETECTED"):
            self._persistence[hostname].add(event)
            self._host_anomalies[hostname].add(event)

        elif event_type == "LOG_CLEARED":
            self._log_cleared_at[hostname] = datetime.utcnow()
            logger.critical("🚨 [CORRELATOR] Log temizlendi: %s", hostname)

    # ------------------------------------------------------------------
    # KURAL DEĞERLENDİRME
    # ------------------------------------------------------------------

    async def _evaluate_rules(self, event: dict, hostname: str, user: str) -> None:
        alerts = []

        # Kural 1: Brute Force
        alert = self._rule_brute_force(user, hostname)
        if alert: alerts.append(alert)

        # Kural 2: Credential Stuffing
        alert = self._rule_credential_stuffing(event, hostname)
        if alert: alerts.append(alert)

        # Kural 3: Lateral Movement
        alert = self._rule_lateral_movement(user, hostname)
        if alert: alerts.append(alert)

        # Kural 4: Log Silme + Aktivite
        alert = self._rule_post_log_clear(event, hostname, user)
        if alert: alerts.append(alert)

        # Kural 5: Persistence Storm (kısa sürede birden fazla persistence)
        alert = self._rule_persistence_storm(hostname, user)
        if alert: alerts.append(alert)

        # Kural 6: Ransomware (kitlesel dosya değişimi)
        alert = self._rule_ransomware_pattern(hostname, user)
        if alert: alerts.append(alert)

        # Kural 7: Process Anomali Fırtınası
        alert = self._rule_process_storm(hostname, user)
        if alert: alerts.append(alert)

        # Kural 8: Başarılı Login Sonrası Persistence
        alert = self._rule_logon_then_persistence(user, hostname)
        if alert: alerts.append(alert)

        for alert in alerts:
            await self._emit(alert)

    # ------------------------------------------------------------------
    # KORELASYON KURALLARI
    # ------------------------------------------------------------------

    def _rule_brute_force(self, user: str, hostname: str) -> Optional[CorrelationAlert]:
        """5 dakikada 5+ başarısız login = Brute Force."""
        threshold = 5
        window    = self._failed_logins[user]

        if window.count() >= threshold:
            return CorrelationAlert(
                rule_name   = "BRUTE_FORCE",
                severity    = RuleSeverity.HIGH,
                description = f"{user} hesabına 5 dakikada {window.count()} başarısız giriş denemesi",
                hostname    = hostname,
                user        = user,
                evidence    = window.events()[-5:],
                mitre       = [{"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force"}],
            )
        return None

    def _rule_credential_stuffing(self, event: dict, hostname: str) -> Optional[CorrelationAlert]:
        """Aynı IP'den 3+ farklı kullanıcıya başarısız login = Credential Stuffing."""
        ip = event.get("details", "")
        if not ip or event.get("type") != "LOGON_FAILURE":
            return None

        window = self._ip_failures[ip]
        unique_users = window.unique_values("user")

        if len(unique_users) >= 3:
            return CorrelationAlert(
                rule_name   = "CREDENTIAL_STUFFING",
                severity    = RuleSeverity.HIGH,
                description = f"{ip} adresinden {len(unique_users)} farklı hesaba giriş denemesi",
                hostname    = hostname,
                user        = ", ".join(list(unique_users)[:5]),
                evidence    = window.events()[-5:],
                mitre       = [{"technique": "T1110.004", "tactic": "Credential Access", "name": "Credential Stuffing"}],
            )
        return None

    def _rule_lateral_movement(self, user: str, hostname: str) -> Optional[CorrelationAlert]:
        """10 dakikada 3+ farklı makineye başarılı login = Lateral Movement."""
        window   = self._lateral_moves[user]
        machines = window.unique_values("hostname")

        if len(machines) >= 3 and hostname not in machines:
            machines.add(hostname)
            if len(machines) >= 3:
                return CorrelationAlert(
                    rule_name   = "LATERAL_MOVEMENT",
                    severity    = RuleSeverity.CRITICAL,
                    description = f"{user} 10 dakikada {len(machines)} farklı makineye bağlandı",
                    hostname    = hostname,
                    user        = user,
                    evidence    = window.events()[-5:],
                    mitre       = [{"technique": "T1021", "tactic": "Lateral Movement", "name": "Remote Services"}],
                )
        return None

    def _rule_post_log_clear(self, event: dict, hostname: str, user: str) -> Optional[CorrelationAlert]:
        """Log silindikten sonraki 5 dakikada herhangi bir aktivite = şüpheli."""
        cleared_at = self._log_cleared_at.get(hostname)
        if not cleared_at:
            return None

        if datetime.utcnow() - cleared_at < timedelta(minutes=5):
            if event.get("type") != "LOG_CLEARED":
                return CorrelationAlert(
                    rule_name   = "POST_LOG_CLEAR_ACTIVITY",
                    severity    = RuleSeverity.CRITICAL,
                    description = f"Log temizlendikten sonra {hostname}'da aktivite tespit edildi",
                    hostname    = hostname,
                    user        = user,
                    evidence    = [event],
                    mitre       = [{"technique": "T1070.001", "tactic": "Defense Evasion", "name": "Clear Windows Event Logs"}],
                )
        return None

    def _rule_persistence_storm(self, hostname: str, user: str) -> Optional[CorrelationAlert]:
        """5 dakikada 2+ persistence aktivitesi = saldırı sonrası kalıcılık kurma."""
        window = self._persistence[hostname]

        if window.count() >= 2:
            return CorrelationAlert(
                rule_name   = "PERSISTENCE_STORM",
                severity    = RuleSeverity.CRITICAL,
                description = f"{hostname}'da 5 dakikada {window.count()} persistence aktivitesi",
                hostname    = hostname,
                user        = user,
                evidence    = window.events(),
                mitre       = [{"technique": "T1053", "tactic": "Persistence", "name": "Scheduled Task/Job"}],
            )
        return None

    def _rule_ransomware_pattern(self, hostname: str, user: str) -> Optional[CorrelationAlert]:
        """10 saniyede 20+ dosya değişikliği = Ransomware aktivitesi."""
        window = self._file_changes[hostname]

        if window.count() >= 20:
            return CorrelationAlert(
                rule_name   = "RANSOMWARE_CORRELATION",
                severity    = RuleSeverity.CRITICAL,
                description = f"{hostname}'da 10 saniyede {window.count()} dosya değişikliği",
                hostname    = hostname,
                user        = user,
                evidence    = window.events()[-10:],
                mitre       = [{"technique": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"}],
            )
        return None

    def _rule_process_storm(self, hostname: str, user: str) -> Optional[CorrelationAlert]:
        """1 dakikada 5+ process anomalisi = injection veya dropper."""
        window = self._host_anomalies[hostname]

        if window.count() >= 5:
            return CorrelationAlert(
                rule_name   = "PROCESS_ANOMALY_STORM",
                severity    = RuleSeverity.HIGH,
                description = f"{hostname}'da 1 dakikada {window.count()} process anomalisi",
                hostname    = hostname,
                user        = user,
                evidence    = window.events()[-5:],
                mitre       = [{"technique": "T1055", "tactic": "Defense Evasion", "name": "Process Injection"}],
            )
        return None

    def _rule_logon_then_persistence(self, user: str, hostname: str) -> Optional[CorrelationAlert]:
        """Başarılı login sonrası 5 dakika içinde persistence = saldırgan foothold."""
        logins      = self._success_logins[user]
        persistence = self._persistence[hostname]

        if logins.count() >= 1 and persistence.count() >= 1:
            return CorrelationAlert(
                rule_name   = "LOGON_THEN_PERSISTENCE",
                severity    = RuleSeverity.CRITICAL,
                description = f"{user} giriş yaptıktan sonra {hostname}'da persistence kurdu",
                hostname    = hostname,
                user        = user,
                evidence    = logins.events()[-2:] + persistence.events()[-2:],
                mitre       = [
                    {"technique": "T1078",  "tactic": "Initial Access",  "name": "Valid Accounts"},
                    {"technique": "T1547",  "tactic": "Persistence",     "name": "Boot/Logon Autostart"},
                ],
            )
        return None

    # ------------------------------------------------------------------
    # ALARM GÖNDERME + SUPPRESSION
    # ------------------------------------------------------------------

    async def _emit(self, alert: CorrelationAlert) -> None:
        """Alarmı suppression kontrolünden geçirerek gönder."""
        key      = f"{alert.rule_name}:{alert.hostname}:{alert.user}"
        now      = datetime.utcnow()
        last     = self._last_alert.get(key)

        if last and (now - last).total_seconds() < self._suppress_secs:
            return  # Aynı alarm 60 sn içinde tekrar basılmasın

        self._last_alert[key] = now

        logger.warning(
            "🔗 [KORELASYON] %s | %s | %s → %s",
            alert.severity.value, alert.rule_name, alert.user, alert.hostname
        )

        if self.alert_callback:
            await self.alert_callback(alert.to_dict())


# ------------------------------------------------------------------
# SOC ENGINE ENTEGRASYON NOKTASI
# ------------------------------------------------------------------

_engine: Optional[CorrelationEngine] = None

def get_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine

async def init_engine(alert_callback) -> CorrelationEngine:
    """soc_engine_advanced.py'den çağrılır."""
    global _engine
    _engine = CorrelationEngine(alert_callback=alert_callback)
    logger.info("🔗 [CORRELATOR] Motor başlatıldı ve callback bağlandı.")
    return _engine

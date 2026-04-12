from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional

from app.detection.detection_policy import BENIGN_TEXT_MARKERS, normalize_text

logger = logging.getLogger("SolidTrace.Correlation")

STRONG_ATTACK_MARKERS = [
    "mimikatz", "sekurlsa", "lsass dump", "procdump lsass", "comsvcs.dll, minidump",
    "powershell", "invoke-webrequest", "downloadstring", "frombase64string",
    "psexec", "paexec", "wmic", "process call create", "/node:",
    "vssadmin delete shadows", "wbadmin delete catalog",
]

class RuleSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class CorrelationAlert:
    rule_name: str
    severity: RuleSeverity
    description: str
    hostname: str
    user: str
    evidence: List[dict]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    mitre: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        score_map = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 30}
        return {
            "type": "CORRELATION_ALERT",
            "rule": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "hostname": self.hostname,
            "user": self.user,
            "evidence_count": len(self.evidence),
            "timestamp": self.timestamp.isoformat() + "Z",
            "mitre": self.mitre,
            "risk": {"score": score_map[self.severity.value], "level": self.severity.value},
        }

class TimeWindow:
    def __init__(self, seconds: int):
        self.window = timedelta(seconds=seconds)
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
        self._cleanup()
        return {e.get(key) for _, e in self._events if e.get(key)}

    def _cleanup(self) -> None:
        now = datetime.utcnow()
        while self._events and now - self._events[0][0] > self.window:
            self._events.popleft()

class CorrelationEngine:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self._failed_logins: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))
        self._success_logins: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))
        self._process_events: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(60))
        self._lateral_moves: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(600))
        self._file_changes: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(10))
        self._persistence: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))
        self._ip_failures: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(300))
        self._log_cleared_at: Dict[str, Optional[datetime]] = defaultdict(lambda: None)
        self._last_alert: Dict[str, datetime] = {}
        self._suppress_secs = 300
        logger.info("🔗 [CORRELATOR] Korelasyon motoru başlatıldı. Hardened mode aktif.")

    def _event_text(self, event: dict) -> str:
        return normalize_text(
            event.get("type"),
            event.get("rule"),
            event.get("details"),
            event.get("command_line"),
        )

    def _event_is_noise(self, event: dict) -> bool:
        risk = int(event.get("risk_score") or event.get("risk", {}).get("score", 0) or 0)
        text = self._event_text(event)
        event_type = str(event.get("type") or "").upper()

        if risk and risk < 40:
            return True
        if any(marker in text for marker in BENIGN_TEXT_MARKERS):
            return True
        if event_type in {"PROCESS_START", "PROCESS_CREATED", "PROCESS_CREATE_EVT", "LOGON_SUCCESS", "SPECIAL_LOGON", "PERSISTENCE_DETECTED"}:
            if not any(marker in text for marker in STRONG_ATTACK_MARKERS):
                return True
        return False

    async def process_event(self, event: dict) -> None:
        event_type = str(event.get("type") or "")
        hostname = str(event.get("hostname") or "unknown")
        user = str(event.get("user") or "unknown")

        if self._event_is_noise(event):
            return

        self._route_event(event_type, event, hostname, user)
        await self._evaluate_rules(event, hostname, user)

    def _route_event(self, event_type: str, event: dict, hostname: str, user: str) -> None:
        if event_type == "LOGON_FAILURE":
            self._failed_logins[user].add(event)
            ip = event.get("details", "")
            if ip:
                self._ip_failures[ip].add(event)
        elif event_type == "LOGON_SUCCESS":
            self._success_logins[user].add(event)
            self._lateral_moves[user].add(event)
        elif event_type in ("PROCESS_CREATE_EVT", "PROCESS_CREATED", "MALWARE_DETECTED", "PROCESS_START"):
            self._process_events[hostname].add(event)
        elif event_type in ("RANSOMWARE_ALERT", "FILE_ACTIVITY"):
            self._file_changes[hostname].add(event)
        elif event_type in ("PERSISTENCE_DETECTED", "SERVICE_INSTALLED", "SCHTASK_CREATED"):
            self._persistence[hostname].add(event)
        elif event_type == "LOG_CLEARED":
            self._log_cleared_at[hostname] = datetime.utcnow()

    async def _evaluate_rules(self, event: dict, hostname: str, user: str) -> None:
        candidates = [
            self._rule_bruteforce(user, hostname),
            self._rule_credential_stuffing(event, hostname),
            self._rule_lateral_movement(user),
            self._rule_log_cleared_followed_by_activity(event, hostname, user),
            self._rule_schtask_plus_service(hostname, user),
        ]
        for alert in candidates:
            if alert:
                await self._emit(alert)

    def _rule_bruteforce(self, user: str, hostname: str) -> Optional[CorrelationAlert]:
        logins = self._failed_logins[user]
        if logins.count() >= 5:
            return CorrelationAlert(
                "BRUTE_FORCE",
                RuleSeverity.HIGH,
                f"{user} için 5 dakikada 5+ başarısız giriş tespit edildi",
                hostname,
                user,
                logins.events()[-5:],
                [{"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force"}],
            )
        return None

    def _rule_credential_stuffing(self, event: dict, hostname: str) -> Optional[CorrelationAlert]:
        details = str(event.get("details") or "")
        ip_key = details if "." in details else None
        if not ip_key:
            return None
        failures = self._ip_failures[ip_key]
        if len(failures.unique_values("user")) >= 3 and failures.count() >= 5:
            return CorrelationAlert(
                "CREDENTIAL_STUFFING",
                RuleSeverity.HIGH,
                "Aynı kaynaktan farklı kullanıcılara çoklu başarısız giriş",
                hostname,
                "multiple",
                failures.events()[-5:],
                [{"technique": "T1110.004", "tactic": "Credential Access", "name": "Credential Stuffing"}],
            )
        return None

    def _rule_lateral_movement(self, user: str) -> Optional[CorrelationAlert]:
        moves = self._lateral_moves[user]
        if len(moves.unique_values("hostname")) >= 3 and moves.count() >= 3:
            events = moves.events()[-5:]
            host = str(events[-1].get("hostname") or "unknown")
            return CorrelationAlert(
                "LATERAL_MOVEMENT",
                RuleSeverity.HIGH,
                f"{user} kısa sürede birden fazla makineye bağlandı",
                host,
                user,
                events,
                [{"technique": "T1021", "tactic": "Lateral Movement", "name": "Remote Services"}],
            )
        return None

    def _rule_log_cleared_followed_by_activity(self, event: dict, hostname: str, user: str) -> Optional[CorrelationAlert]:
        cleared_at = self._log_cleared_at.get(hostname)
        if not cleared_at:
            return None
        if datetime.utcnow() - cleared_at > timedelta(minutes=5):
            return None
        return CorrelationAlert(
            "LOG_CLEARED_THEN_ACTIVITY",
            RuleSeverity.CRITICAL,
            f"{hostname} üzerinde log temizliği sonrası aktivite görüldü",
            hostname,
            user,
            [event],
            [{"technique": "T1070", "tactic": "Defense Evasion", "name": "Indicator Removal on Host"}],
        )

    def _rule_schtask_plus_service(self, hostname: str, user: str) -> Optional[CorrelationAlert]:
        persistence = self._persistence[hostname]
        events = persistence.events()
        if persistence.count() < 2:
            return None
        types = {str(e.get("type") or "").upper() for e in events}
        if "SERVICE_INSTALLED" in types and "SCHTASK_CREATED" in types:
            return CorrelationAlert(
                "SERVICE_AND_SCHEDULED_TASK_ABUSE",
                RuleSeverity.CRITICAL,
                f"{hostname} üzerinde service + scheduled task kombinasyonu tespit edildi",
                hostname,
                user,
                events[-4:],
                [
                    {"technique": "T1543", "tactic": "Persistence", "name": "Create or Modify System Process"},
                    {"technique": "T1053", "tactic": "Execution", "name": "Scheduled Task/Job"},
                ],
            )
        return None

    async def _emit(self, alert: CorrelationAlert) -> None:
        key = f"{alert.rule_name}:{alert.hostname}:{alert.user}"
        now = datetime.utcnow()
        last = self._last_alert.get(key)
        if last and (now - last).total_seconds() < self._suppress_secs:
            return
        self._last_alert[key] = now
        logger.warning("🔗 [KORELASYON] %s | %s | %s → %s", alert.severity.value, alert.rule_name, alert.user, alert.hostname)
        if self.alert_callback:
            await self.alert_callback(alert.to_dict())


_engine: Optional[CorrelationEngine] = None


def get_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine


async def init_engine(alert_callback) -> CorrelationEngine:
    global _engine
    _engine = CorrelationEngine(alert_callback=alert_callback)
    logger.info("🔗 [CORRELATOR] Motor başlatıldı ve callback bağlandı.")
    return _engine

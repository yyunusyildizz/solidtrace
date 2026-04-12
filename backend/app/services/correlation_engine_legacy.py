from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple


class CorrelationEngine:
    """
    Aynı host üzerinde kısa zaman penceresindeki olay zincirlerini korele eder.
    Gürültüyü azaltmak için:
      - tek event ile ağır korelasyon üretmez
      - aynı korelasyon imzasını kısa süre içinde tekrar üretmez
      - generic process-only fırtınalarını zincir olarak yükseltmez
    """

    def __init__(
        self,
        window_minutes: int = 5,
        max_events_per_host: int = 100,
        min_distinct_events: int = 3,
        cooldown_seconds: int = 180,
    ) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.max_events_per_host = max_events_per_host
        self.min_distinct_events = min_distinct_events
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self._state: Dict[str, Deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self.max_events_per_host)
        )
        self._last_emitted: Dict[Tuple[str, str], datetime] = {}

    def _utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    def _parse_ts(self, value: Optional[str]) -> datetime:
        if not value:
            return self._utcnow()
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return self._utcnow()

    def _prune(self, hostname: str, now: datetime) -> None:
        dq = self._state[hostname]
        while dq and (now - self._parse_ts(dq[0].get("timestamp")) > self.window):
            dq.popleft()

    def _event_text(self, ev: dict[str, Any]) -> str:
        return " ".join(
            [
                str(ev.get("type") or ""),
                str(ev.get("rule") or ""),
                str(ev.get("details") or ""),
                str(ev.get("command_line") or ""),
            ]
        ).lower()

    def _count_matching_events(self, events: List[dict[str, Any]], keywords: List[str]) -> int:
        count = 0
        for ev in events:
            hay = self._event_text(ev)
            if any(kw in hay for kw in keywords):
                count += 1
        return count

    def _distinct_event_types(self, events: List[dict[str, Any]]) -> int:
        vals = {str(ev.get("type") or "").strip().lower() for ev in events if ev.get("type")}
        return len(vals)

    def _only_process_events(self, events: List[dict[str, Any]]) -> bool:
        accepted = {"process_start", "process_created"}
        seen = {str(ev.get("type") or "").strip().lower() for ev in events if ev.get("type")}
        return bool(seen) and seen.issubset(accepted)

    def _allow_emit(self, hostname: str, name: str, now: datetime) -> bool:
        key = (hostname, name)
        last = self._last_emitted.get(key)
        if last and (now - last) < self.cooldown:
            return False
        self._last_emitted[key] = now
        return True

    def _build_match(
        self,
        *,
        hostname: str,
        now: datetime,
        name: str,
        score: int,
        severity: str,
        summary: str,
        related_events: List[dict[str, Any]],
    ) -> Optional[dict[str, Any]]:
        if self._distinct_event_types(related_events) < self.min_distinct_events:
            return None
        if self._only_process_events(related_events):
            return None
        if not self._allow_emit(hostname, name, now):
            return None
        return {
            "matched": True,
            "name": name,
            "score": score,
            "severity": severity,
            "summary": summary,
            "related_events": related_events[-10:],
        }

    def process_event(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        hostname = str(event.get("hostname") or "unknown").strip() or "unknown"
        now = self._parse_ts(event.get("timestamp"))

        self._prune(hostname, now)
        self._state[hostname].append(event)

        recent = list(self._state[hostname])
        if len(recent) < 3:
            return None

        # 1) Failed login + suspicious execution
        login_fail_count = self._count_matching_events(
            recent, ["failed_login", "login failed", "authentication failure"]
        )
        suspicious_exec_count = self._count_matching_events(
            recent, ["powershell", "cmd.exe", "wscript", "cscript", "invoke-webrequest", "downloadstring"]
        )
        if login_fail_count >= 1 and suspicious_exec_count >= 1:
            return self._build_match(
                hostname=hostname,
                now=now,
                name="Brute Force to Suspicious Execution",
                score=90,
                severity="HIGH",
                summary="Başarısız giriş denemelerini şüpheli komut çalıştırma takip etti.",
                related_events=recent,
            )

        # 2) Credential access chain — require 2 independent strong indicators
        cred_count = self._count_matching_events(
            recent, ["mimikatz", "sekurlsa", "procdump lsass", "lsass dump", "credential dumping", "comsvcs.dll, minidump"]
        )
        if cred_count >= 2:
            return self._build_match(
                hostname=hostname,
                now=now,
                name="Credential Access Chain",
                score=95,
                severity="CRITICAL",
                summary="Kimlik bilgisi erişimi/dumping göstergeleri bir olay zinciri halinde tespit edildi.",
                related_events=recent,
            )

        # 3) Lateral movement chain — require multiple remote-exec indicators
        lateral_count = self._count_matching_events(
            recent, ["psexec", "wmic", "wmiexec", "admin$", "remote service", "process call create", "/node:"]
        )
        if lateral_count >= 2:
            return self._build_match(
                hostname=hostname,
                now=now,
                name="Lateral Movement Chain",
                score=88,
                severity="HIGH",
                summary="Yanal hareket göstergeleri birden fazla olayla doğrulandı.",
                related_events=recent,
            )

        # 4) USB + suspicious execution
        usb_count = self._count_matching_events(recent, ["usb"])
        exec_count = self._count_matching_events(
            recent, ["powershell", ".ps1", ".bat", ".vbs", ".js", ".zip", "invoke-webrequest"]
        )
        if usb_count >= 1 and exec_count >= 1:
            return self._build_match(
                hostname=hostname,
                now=now,
                name="USB Followed by Suspicious Execution",
                score=85,
                severity="HIGH",
                summary="USB aktivitesini şüpheli çalıştırma izledi.",
                related_events=recent,
            )

        # 5) Ransomware sequence
        ransomware_count = self._count_matching_events(
            recent, ["vssadmin delete shadows", "shadow copy", "encrypt", "ransomware", "wbadmin delete catalog"]
        )
        if ransomware_count >= 2:
            return self._build_match(
                hostname=hostname,
                now=now,
                name="Ransomware Sequence",
                score=98,
                severity="CRITICAL",
                summary="Ransomware davranış zinciri birden fazla olayla tespit edildi.",
                related_events=recent,
            )

        return None

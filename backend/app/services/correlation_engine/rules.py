"""
app.services.correlation_engine.rules
=======================================
Correlation rule seti.

Her rule, NormalizedSecurityEvent listesini analiz edip eşleşme sonucu döndürür.
Rule'lar stateless — pure fonksiyon tabanlı.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional

from app.models.normalized_event import NormalizedSecurityEvent


# ---------------------------------------------------------------------------
# Rule sonuç yapısı
# ---------------------------------------------------------------------------

@dataclass
class MatchResult:
    """Bir rule eşleşmesinin sonucu."""
    matched_events: List[NormalizedSecurityEvent]
    reason: str


# ---------------------------------------------------------------------------
# Rule tanımlama yapısı
# ---------------------------------------------------------------------------

@dataclass
class CorrelationRule:
    """
    Tek bir correlation rule'ının tanımı.

    Attributes:
        name:        Rule'un teknik adı (snake_case)
        title:       Okunabilir başlık
        description: Açıklama
        severity:    Varsayılan severity
        confidence:  Varsayılan confidence (low/medium/high)
        match:       Eşleşme fonksiyonu — event listesi alır, MatchResult | None döndürür
    """
    name: str
    title: str
    description: str
    severity: str
    confidence: str
    match: Callable[[List[NormalizedSecurityEvent]], Optional[MatchResult]]


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _text_of(event: NormalizedSecurityEvent) -> str:
    """Event'in aranabilir metin temsilini oluşturur (lowercase)."""
    parts = [
        event.command_line or "",
        event.process_name or "",
        str(event.attributes.get("details", "")),
        str(event.attributes.get("rule", "")),
    ]
    return " ".join(parts).lower()


def _parse_timestamp(ts: str) -> datetime:
    """ISO 8601 timestamp'ı datetime'a çevirir."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _group_by_host(
    events: List[NormalizedSecurityEvent],
) -> dict[str, List[NormalizedSecurityEvent]]:
    """Event'leri hostname bazında gruplar. hostname=None olanlar atlanır."""
    groups: dict[str, List[NormalizedSecurityEvent]] = {}
    for ev in events:
        key = (ev.hostname or "").strip()
        if not key:
            continue
        groups.setdefault(key, []).append(ev)
    return groups


# ---------------------------------------------------------------------------
# Rule 1: Suspicious PowerShell Chain
# ---------------------------------------------------------------------------

_PS_PRIMARY = {"powershell", "pwsh", "powershell.exe", "pwsh.exe"}
_PS_EVASION = {
    "-encodedcommand", "-enc", "-nop", "-noprofile",
    "-w hidden", "-windowstyle hidden", "bypass",
}
_PS_DOWNLOAD = {
    "downloadstring", "invoke-webrequest", "iwr",
    "invoke-expression", "iex", "net.webclient",
    "start-bitstransfer", "downloadfile",
}


def _match_powershell_chain(
    events: List[NormalizedSecurityEvent],
) -> Optional[MatchResult]:
    """
    Suspicious PowerShell Chain rule.

    Eşleşme koşulu:
    - Aynı host üzerinde en az 2 farklı event'te PowerShell primary keyword
      + (evasion VEYA download cradle) birlikte bulunmalı.
    """
    host_groups = _group_by_host(events)

    for hostname, host_events in host_groups.items():
        matched: List[NormalizedSecurityEvent] = []

        for ev in host_events:
            text = _text_of(ev)
            has_primary = any(kw in text for kw in _PS_PRIMARY)
            has_evasion = any(kw in text for kw in _PS_EVASION)
            has_download = any(kw in text for kw in _PS_DOWNLOAD)

            if has_primary and (has_evasion or has_download):
                matched.append(ev)

        if len(matched) >= 2:
            indicators = []
            combined = " ".join(_text_of(e) for e in matched)
            if any(kw in combined for kw in _PS_EVASION):
                indicators.append("evasion")
            if any(kw in combined for kw in _PS_DOWNLOAD):
                indicators.append("download cradle")
            return MatchResult(
                matched_events=matched,
                reason=(
                    f"{hostname} üzerinde {len(matched)} event'te "
                    f"şüpheli PowerShell zinciri tespit edildi "
                    f"(göstergeler: {', '.join(indicators)})"
                ),
            )

    return None


powershell_chain_rule = CorrelationRule(
    name="suspicious_powershell_chain",
    title="Suspicious PowerShell Chain",
    description=(
        "Aynı host üzerinde evasion veya download cradle tekniklerini "
        "içeren birden fazla PowerShell yürütmesi tespit edildi."
    ),
    severity="HIGH",
    confidence="high",
    match=_match_powershell_chain,
)


# ---------------------------------------------------------------------------
# Rule 2: Credential Dumping Chain
# ---------------------------------------------------------------------------

_CRED_PRIMARY = {"mimikatz", "sekurlsa", "lsass"}
_CRED_SUPPORTING = {
    "procdump", "comsvcs.dll", "minidump",
    "credential dumping", "hashdump", "sam dump",
}
_CRED_MITRE_PREFIX = "T1003"


def _match_credential_dumping(
    events: List[NormalizedSecurityEvent],
) -> Optional[MatchResult]:
    """
    Credential Dumping Chain rule.

    Eşleşme koşulu:
    - Aynı host üzerinde en az 2 farklı event'te credential dumping
      göstergesi (primary/supporting keyword VEYA T1003 technique).
    """
    host_groups = _group_by_host(events)

    for hostname, host_events in host_groups.items():
        matched: List[NormalizedSecurityEvent] = []

        for ev in host_events:
            text = _text_of(ev)
            has_keyword = (
                any(kw in text for kw in _CRED_PRIMARY)
                or any(kw in text for kw in _CRED_SUPPORTING)
            )
            has_mitre = (
                ev.mitre_technique is not None
                and ev.mitre_technique.startswith(_CRED_MITRE_PREFIX)
            )

            if has_keyword or has_mitre:
                matched.append(ev)

        if len(matched) >= 2:
            return MatchResult(
                matched_events=matched,
                reason=(
                    f"{hostname} üzerinde {len(matched)} event'te "
                    f"kimlik bilgisi erişimi/dumping zinciri tespit edildi"
                ),
            )

    return None


credential_dumping_rule = CorrelationRule(
    name="credential_dumping_chain",
    title="Credential Dumping Chain",
    description=(
        "Aynı host üzerinde birden fazla kimlik bilgisi erişimi/dumping "
        "göstergesi tespit edildi (mimikatz, lsass, sekurlsa, T1003)."
    ),
    severity="CRITICAL",
    confidence="high",
    match=_match_credential_dumping,
)


# ---------------------------------------------------------------------------
# Rule 3: Same Host High Risk Burst
# ---------------------------------------------------------------------------

_BURST_WINDOW_SECONDS = 300  # 5 dakika
_BURST_MIN_EVENTS = 3
_BURST_MIN_AVG_RISK = 60


def _match_high_risk_burst(
    events: List[NormalizedSecurityEvent],
) -> Optional[MatchResult]:
    """
    Same Host High Risk Burst rule.

    Eşleşme koşulu:
    - Aynı host üzerinde 5 dakika içinde 3+ event
    - Ortalama risk_score ≥ 60
    """
    host_groups = _group_by_host(events)

    for hostname, host_events in host_groups.items():
        if len(host_events) < _BURST_MIN_EVENTS:
            continue

        # Zaman sırasına göre sırala
        sorted_events = sorted(host_events, key=lambda e: e.timestamp)

        # Sliding window: her event'ten başlayarak 5 dk pencere
        for i in range(len(sorted_events)):
            window_start = _parse_timestamp(sorted_events[i].timestamp)
            window_events: List[NormalizedSecurityEvent] = []

            for j in range(i, len(sorted_events)):
                ev_time = _parse_timestamp(sorted_events[j].timestamp)
                if (ev_time - window_start).total_seconds() <= _BURST_WINDOW_SECONDS:
                    window_events.append(sorted_events[j])
                else:
                    break

            if len(window_events) < _BURST_MIN_EVENTS:
                continue

            avg_risk = sum(e.risk_score for e in window_events) / len(window_events)
            if avg_risk >= _BURST_MIN_AVG_RISK:
                return MatchResult(
                    matched_events=window_events,
                    reason=(
                        f"{hostname} üzerinde {len(window_events)} event "
                        f"5 dakika içinde yüksek risk patlaması tespit edildi "
                        f"(ortalama risk: {avg_risk:.0f})"
                    ),
                )

    return None


high_risk_burst_rule = CorrelationRule(
    name="same_host_high_risk_burst",
    title="Same Host High Risk Burst",
    description=(
        "Aynı host üzerinde kısa zaman aralığında birden fazla "
        "yüksek riskli olay tespit edildi."
    ),
    severity="HIGH",
    confidence="medium",
    match=_match_high_risk_burst,
)


# ---------------------------------------------------------------------------
# Rule Registry
# ---------------------------------------------------------------------------

CORRELATION_RULES: List[CorrelationRule] = [
    powershell_chain_rule,
    credential_dumping_rule,
    high_risk_burst_rule,
]

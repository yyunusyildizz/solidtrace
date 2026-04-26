"""
app.services.correlation_engine.engine
=======================================
CorrelationEngine — NormalizedSecurityEvent listesini correlation rule'larına
karşı değerlendirip CorrelationGroup'lar üretir.

Standalone — DB persistence yok, runtime pipeline entegrasyonu yok.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from app.models.normalized_event import NormalizedSecurityEvent

from .models import SEVERITY_ORDER, CorrelationGroup
from .rules import CORRELATION_RULES, CorrelationRule, MatchResult

logger = logging.getLogger("SolidTrace.CorrelationEngine")

# ---------------------------------------------------------------------------
# Critical keyword bonus listesi
# ---------------------------------------------------------------------------

_CRITICAL_KEYWORDS = {
    "mimikatz", "ransomware", "lsass", "sekurlsa",
    "cobalt strike", "beacon", "meterpreter",
}


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    NormalizedSecurityEvent listesini tüm correlation rule'larına karşı
    değerlendirip eşleşen her rule için bir CorrelationGroup üretir.

    Kullanım:
        engine = CorrelationEngine()
        groups = engine.correlate(events)
    """

    def __init__(self, rules: Optional[List[CorrelationRule]] = None) -> None:
        self.rules = rules if rules is not None else list(CORRELATION_RULES)

    def correlate(
        self,
        events: List[NormalizedSecurityEvent],
    ) -> List[CorrelationGroup]:
        """
        Event listesini tüm rule'lara karşı değerlendirir.

        Args:
            events: NormalizedSecurityEvent listesi

        Returns:
            Eşleşen rule'lar için CorrelationGroup listesi
        """
        if not events:
            return []

        # Tenant bazında grupla
        tenant_groups: dict[str, List[NormalizedSecurityEvent]] = {}
        for ev in events:
            tenant = ev.tenant_id or "default_tenant"
            tenant_groups.setdefault(tenant, []).append(ev)

        results: List[CorrelationGroup] = []

        for tenant_id, tenant_events in tenant_groups.items():
            for rule in self.rules:
                try:
                    match_result = rule.match(tenant_events)
                except Exception as exc:
                    logger.error(
                        "correlation_rule_error rule=%s tenant=%s error=%s",
                        rule.name, tenant_id, exc,
                    )
                    continue

                if match_result is None:
                    continue

                group = self._build_group(
                    tenant_id=tenant_id,
                    rule=rule,
                    match_result=match_result,
                )
                results.append(group)

                logger.info(
                    "correlation_group_created rule=%s tenant=%s "
                    "event_count=%d risk_score=%d severity=%s",
                    rule.name, tenant_id,
                    len(group.event_ids), group.risk_score, group.severity,
                )

        return results

    def _build_group(
        self,
        *,
        tenant_id: str,
        rule: CorrelationRule,
        match_result: MatchResult,
    ) -> CorrelationGroup:
        """Rule eşleşmesinden CorrelationGroup oluşturur."""
        group = CorrelationGroup(
            tenant_id=tenant_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            confidence=rule.confidence,
            reason=match_result.reason,
        )

        for ev in match_result.matched_events:
            group.add_event(ev)

        group.risk_score = self._aggregate_risk(
            match_result.matched_events, rule,
        )

        # Severity'yi risk'e göre yükselt (asla düşürme)
        group.severity = self._adjust_severity(
            group.severity, group.risk_score,
        )

        return group

    @staticmethod
    def _aggregate_risk(
        events: List[NormalizedSecurityEvent],
        rule: CorrelationRule,
    ) -> int:
        """
        Risk aggregation.

        Bileşenler:
            - base:           max event risk_score
            - sequence_bonus: 3 puan/event, max 15
            - entity_bonus:   2 puan/unique entity, max 10
            - mitre_bonus:    MITRE bilgisi varsa +5
            - critical_bonus: critical keyword varsa +10

        Sonuç: 0-100 aralığında clamp.
        """
        if not events:
            return 0

        # Base: max risk
        base = max(ev.risk_score for ev in events)

        # Sequence bonus
        sequence_bonus = min(len(events) * 3, 15)

        # Entity bonus — unique hostname + username + IP sayısı
        entities: set[str] = set()
        for ev in events:
            if ev.hostname:
                entities.add(ev.hostname)
            if ev.username:
                entities.add(ev.username)
            if ev.source_ip:
                entities.add(ev.source_ip)
            if ev.destination_ip:
                entities.add(ev.destination_ip)
        entity_bonus = min(len(entities) * 2, 10)

        # MITRE bonus
        mitre_bonus = 5 if any(ev.mitre_tactic for ev in events) else 0

        # Critical keyword bonus
        combined_text = " ".join(
            f"{ev.command_line or ''} {ev.process_name or ''} "
            f"{ev.attributes.get('details', '')} {ev.attributes.get('rule', '')}"
            for ev in events
        ).lower()
        critical_bonus = (
            10 if any(kw in combined_text for kw in _CRITICAL_KEYWORDS) else 0
        )

        total = base + sequence_bonus + entity_bonus + mitre_bonus + critical_bonus
        return max(0, min(total, 100))

    @staticmethod
    def _adjust_severity(current: str, risk_score: int) -> str:
        """Risk score'a göre severity'yi yükseltir (asla düşürmez)."""
        if risk_score >= 90:
            target = "CRITICAL"
        elif risk_score >= 70:
            target = "HIGH"
        elif risk_score >= 50:
            target = "MEDIUM"
        elif risk_score >= 30:
            target = "LOW"
        else:
            target = "INFO"

        current_rank = SEVERITY_ORDER.get(current.upper(), 0)
        target_rank = SEVERITY_ORDER.get(target, 0)

        return target if target_rank > current_rank else current.upper()

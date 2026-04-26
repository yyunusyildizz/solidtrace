"""
app.services.attack_story.builder
====================================
StoryBuilder — CorrelationGroup'tan AttackStory üretir.

Template-based story generation. Her bilinen correlation rule title'ı
için özel template, bilinmeyenler için generic fallback.

Standalone — DB persistence yok, runtime pipeline entegrasyonu yok.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from app.services.correlation_engine.models import CorrelationGroup

from .models import AttackStory, RecommendedAction

logger = logging.getLogger("SolidTrace.AttackStoryBuilder")


# ---------------------------------------------------------------------------
# Action metadata tablosu
# ---------------------------------------------------------------------------

_ACTION_META: Dict[str, Dict[str, str]] = {
    "isolate_host": {
        "title": "Host'u İzole Et",
        "description": "Etkilenen host'u ağdan izole ederek yanal hareketi önle",
    },
    "review_process_tree": {
        "title": "Süreç Ağacını İncele",
        "description": "Şüpheli sürecin parent/child ilişkilerini analiz et",
    },
    "collect_artifacts": {
        "title": "Artifact Topla",
        "description": "Memory dump, event log ve ilgili dosyaları topla",
    },
    "reset_credentials": {
        "title": "Kimlik Bilgilerini Sıfırla",
        "description": "Etkilenen kullanıcıların parolalarını sıfırla",
    },
    "disable_usb": {
        "title": "USB Erişimini Kapat",
        "description": "Host üzerinde USB depolama erişimini devre dışı bırak",
    },
    "monitor_host": {
        "title": "Host'u İzle",
        "description": "Etkilenen host'u artırılmış izleme altına al",
    },
    "create_case": {
        "title": "Vaka Oluştur",
        "description": "Detaylı soruşturma için yeni vaka oluştur",
    },
}


# ---------------------------------------------------------------------------
# StoryBuilder
# ---------------------------------------------------------------------------

class StoryBuilder:
    """
    CorrelationGroup'tan AttackStory üretir.

    Template dispatch: Group title'ına göre doğru template seçilir.
    Bilinmeyen title'lar için generic fallback çalışır.

    Kullanım:
        builder = StoryBuilder()
        story = builder.build(group)
    """

    # Template dispatch haritası: group title → builder metodu adı
    _TEMPLATE_MAP: Dict[str, str] = {
        "Credential Dumping Chain": "_build_credential_story",
        "Suspicious PowerShell Chain": "_build_powershell_story",
        "Same Host High Risk Burst": "_build_burst_story",
    }

    def build(self, group: CorrelationGroup) -> AttackStory:
        """
        CorrelationGroup'tan AttackStory üretir.

        Args:
            group: CorrelationGroup instance

        Returns:
            AttackStory instance
        """
        method_name = self._TEMPLATE_MAP.get(group.title)

        if method_name and hasattr(self, method_name):
            story = getattr(self, method_name)(group)
        else:
            story = self._build_generic_story(group)

        logger.info(
            "attack_story_built group_id=%s title=%s severity=%s risk=%d",
            group.id, story.title, story.severity, story.risk_score,
        )

        return story

    # -- Base builder --------------------------------------------------------

    def _build_base(self, group: CorrelationGroup) -> AttackStory:
        """Tüm template'ler için ortak alanları doldurur."""
        entities = group.entities or {"hostnames": [], "usernames": [], "ips": []}
        hostnames = entities.get("hostnames", [])
        usernames = entities.get("usernames", [])
        ips = entities.get("ips", [])

        return AttackStory(
            tenant_id=group.tenant_id,
            correlation_group_id=group.id,
            severity=group.severity,
            confidence=group.confidence,
            risk_score=group.risk_score,
            affected_hosts=list(hostnames),
            affected_users=list(usernames),
            source_ips=[ip for ip in ips],
            destination_ips=[],
            tactics=list(group.tactics),
            techniques=list(group.techniques),
            timeline=self._build_timeline(group),
            attributes={
                "correlation_rule_title": group.title,
                "event_count": len(group.event_ids),
                "alert_count": len(group.alert_ids),
            },
        )

    # -- Template: Credential Dumping ----------------------------------------

    def _build_credential_story(self, group: CorrelationGroup) -> AttackStory:
        story = self._build_base(group)
        hosts = ", ".join(story.affected_hosts) or "bilinmeyen host"
        users = ", ".join(story.affected_users) or "bilinmeyen kullanıcı"
        event_count = len(group.event_ids)

        story.title = "Possible Credential Dumping Activity"

        story.executive_summary = (
            f"{hosts} üzerinde kimlik bilgisi erişimi girişimi tespit edildi. "
            f"Saldırgan, kullanıcı parolalarına veya hash'lerine ulaşmak için "
            f"bilinen araçları kullanmış olabilir. "
            f"Acil müdahale önerilir."
        )

        techniques_str = ", ".join(group.techniques) if group.techniques else "N/A"
        story.technical_summary = (
            f"{group.description} "
            f"Korelasyon nedeni: {group.reason}. "
            f"{event_count} ilişkili event tespit edildi. "
            f"MITRE ATT&CK teknikleri: {techniques_str}."
        )

        story.key_findings = self._build_key_findings(group, [
            "Kimlik bilgisi erişimi/dumping göstergeleri tespit edildi",
            f"Etkilenen host(lar): {hosts}",
            f"Etkilenen kullanıcı(lar): {users}",
        ])

        story.recommended_actions = self._make_actions(
            [
                ("isolate_host", "immediate"),
                ("collect_artifacts", "immediate"),
                ("reset_credentials", "high"),
                ("create_case", "high"),
            ],
            target_host=story.affected_hosts[0] if story.affected_hosts else None,
        )

        story.analyst_questions = [
            "Etkilenen hostlarda başka suspicious process var mı?",
            "Credential'lar lateral movement için kullanılmış mı?",
            "Dumping sonrası ağ üzerinde anormal authentication trafiği var mı?",
            "Etkilenen kullanıcı hesapları ayrıcalıklı (admin, service account) mı?",
        ]

        return story

    # -- Template: PowerShell Chain ------------------------------------------

    def _build_powershell_story(self, group: CorrelationGroup) -> AttackStory:
        story = self._build_base(group)
        hosts = ", ".join(story.affected_hosts) or "bilinmeyen host"
        event_count = len(group.event_ids)

        story.title = "Suspicious PowerShell Execution Chain"

        story.executive_summary = (
            f"{hosts} üzerinde şüpheli PowerShell yürütme zinciri tespit edildi. "
            f"Evasion teknikleri veya download cradle kullanımı, "
            f"kötü amaçlı yazılım dağıtımına işaret edebilir."
        )

        techniques_str = ", ".join(group.techniques) if group.techniques else "N/A"
        story.technical_summary = (
            f"{group.description} "
            f"Korelasyon nedeni: {group.reason}. "
            f"{event_count} ilişkili PowerShell event tespit edildi. "
            f"MITRE ATT&CK teknikleri: {techniques_str}."
        )

        story.key_findings = self._build_key_findings(group, [
            "Şüpheli PowerShell yürütme zinciri tespit edildi",
            f"Etkilenen host(lar): {hosts}",
            "Evasion ve/veya download cradle teknikleri kullanılmış olabilir",
        ])

        story.recommended_actions = self._make_actions(
            [
                ("isolate_host", "immediate"),
                ("review_process_tree", "immediate"),
                ("collect_artifacts", "high"),
                ("monitor_host", "medium"),
            ],
            target_host=story.affected_hosts[0] if story.affected_hosts else None,
        )

        story.analyst_questions = [
            "İndirilen payload'lar neler?",
            "PowerShell çalıştıran kullanıcı yetkili mi?",
            "Encoded command decode edildiğinde ne içeriyor?",
            "Download edilen URL/IP bilinen bir C2 sunucusu mu?",
        ]

        return story

    # -- Template: High Risk Burst -------------------------------------------

    def _build_burst_story(self, group: CorrelationGroup) -> AttackStory:
        story = self._build_base(group)
        hosts = ", ".join(story.affected_hosts) or "bilinmeyen host"
        event_count = len(group.event_ids)

        story.title = "High Risk Activity Burst on Host"

        story.executive_summary = (
            f"{hosts} üzerinde kısa sürede yoğun yüksek riskli aktivite "
            f"tespit edildi. Bu, aktif bir saldırı veya otomatik zararlı "
            f"yazılım davranışına işaret edebilir."
        )

        story.technical_summary = (
            f"{group.description} "
            f"Korelasyon nedeni: {group.reason}. "
            f"{event_count} event kısa zaman aralığında tespit edildi. "
            f"Risk skoru: {group.risk_score}/100."
        )

        story.key_findings = self._build_key_findings(group, [
            f"Kısa sürede {event_count} yüksek riskli event tespit edildi",
            f"Etkilenen host(lar): {hosts}",
            f"Toplam risk skoru: {group.risk_score}/100",
        ])

        story.recommended_actions = self._make_actions(
            [
                ("monitor_host", "immediate"),
                ("review_process_tree", "high"),
                ("create_case", "high"),
            ],
            target_host=story.affected_hosts[0] if story.affected_hosts else None,
        )

        story.analyst_questions = [
            "Aktivite otomatik mi yoksa insan etkileşimli mi?",
            "Benzer pattern başka hostlarda görülüyor mu?",
            "Event'ler arasında bir saldırı zinciri (kill chain) ilişkisi var mı?",
        ]

        return story

    # -- Template: Generic Fallback ------------------------------------------

    def _build_generic_story(self, group: CorrelationGroup) -> AttackStory:
        story = self._build_base(group)
        hosts = ", ".join(story.affected_hosts) or "bilinmeyen host"
        event_count = len(group.event_ids)

        story.title = group.title or "Security Correlation Alert"

        story.executive_summary = (
            f"{hosts} üzerinde ilişkili güvenlik olayları tespit edildi. "
            f"{event_count} event korelasyon kuralı tarafından gruplandı. "
            f"Severity: {group.severity}, Risk: {group.risk_score}/100."
        )

        story.technical_summary = (
            f"{group.description} "
            f"Korelasyon nedeni: {group.reason}. "
            f"Toplam {event_count} ilişkili event."
        )

        story.key_findings = self._build_key_findings(group, [
            f"Korelasyon kuralı eşleşmesi: {group.title}",
            f"Etkilenen host(lar): {hosts}",
        ])

        # Severity'ye göre default actions
        if group.severity in ("CRITICAL", "HIGH"):
            action_spec = [
                ("isolate_host", "immediate"),
                ("collect_artifacts", "high"),
                ("create_case", "high"),
            ]
        else:
            action_spec = [
                ("monitor_host", "high"),
                ("review_process_tree", "medium"),
            ]

        story.recommended_actions = self._make_actions(
            action_spec,
            target_host=story.affected_hosts[0] if story.affected_hosts else None,
        )

        story.analyst_questions = [
            "Bu korelasyon grubundaki event'ler gerçek bir tehdit mi?",
            "Etkilenen sistemlerde ek inceleme gerekli mi?",
        ]

        return story

    # -- Yardımcı fonksiyonlar -----------------------------------------------

    @staticmethod
    def _build_timeline(group: CorrelationGroup) -> List[Dict]:
        """Event ID'lerinden basit timeline üretir."""
        timeline = []
        for idx, event_id in enumerate(group.event_ids, start=1):
            timeline.append({
                "order": idx,
                "event_id": event_id,
                "description": "Correlation event detected",
            })
        return timeline

    @staticmethod
    def _build_key_findings(
        group: CorrelationGroup,
        extra_findings: List[str],
    ) -> List[str]:
        """Key findings listesi oluşturur."""
        findings = list(extra_findings)

        if group.tactics:
            findings.append(
                f"MITRE ATT&CK taktikleri: {', '.join(group.tactics)}"
            )
        if group.techniques:
            findings.append(
                f"MITRE ATT&CK teknikleri: {', '.join(group.techniques)}"
            )
        if group.alert_ids:
            findings.append(
                f"İlişkili alert sayısı: {len(group.alert_ids)}"
            )

        return findings

    @staticmethod
    def _make_actions(
        action_specs: List[tuple],
        target_host: Optional[str] = None,
    ) -> List[RecommendedAction]:
        """Action spec listesinden RecommendedAction listesi üretir."""
        actions = []
        for action_type, priority in action_specs:
            meta = _ACTION_META.get(action_type, {})
            actions.append(RecommendedAction(
                action_type=action_type,
                title=meta.get("title", action_type),
                description=meta.get("description", ""),
                priority=priority,
                target=target_host,
            ))
        return actions

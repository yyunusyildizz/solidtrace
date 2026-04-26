"""
app.services.story_pipeline.pipeline
======================================
StoryPipeline — Mevcut standalone modülleri birbirine bağlayan pipeline:

    raw event / alert / command result
    → NormalizedSecurityEvent
    → CorrelationGroup
    → AttackStory

Standalone — DB persistence yok, runtime entegrasyonu yok.
Hatalı input tüm pipeline'ı crash ettirmez; warnings listesine eklenir.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from app.models.normalized_event import NormalizedSecurityEvent
from app.services.event_normalizer import EventNormalizer
from app.services.correlation_engine.engine import CorrelationEngine
from app.services.correlation_engine.models import CorrelationGroup
from app.services.attack_story.builder import StoryBuilder
from app.services.attack_story.models import AttackStory

logger = logging.getLogger("SolidTrace.StoryPipeline")


# ---------------------------------------------------------------------------
# Severity sıralaması (summary hesabı için)
# ---------------------------------------------------------------------------

_SEVERITY_RANK: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# ---------------------------------------------------------------------------
# StoryPipelineResult
# ---------------------------------------------------------------------------

class StoryPipelineResult(BaseModel):
    """
    Pipeline çıktısı.

    Attributes:
        normalized_events:  Normalize edilmiş event listesi
        correlation_groups: Üretilen korelasyon grupları
        attack_stories:     Üretilen saldırı hikayeleri
        summary:            Özet istatistikler
        warnings:           Normalization/processing uyarıları
        attributes:         Serbest metadata
    """

    normalized_events: List[NormalizedSecurityEvent] = Field(default_factory=list)
    correlation_groups: List[CorrelationGroup] = Field(default_factory=list)
    attack_stories: List[AttackStory] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "from_attributes": True,
    }


# ---------------------------------------------------------------------------
# StoryPipeline
# ---------------------------------------------------------------------------

class StoryPipeline:
    """
    raw event / alert / command result → NormalizedSecurityEvent
    → CorrelationGroup → AttackStory pipeline'ı.

    Kullanım:
        pipeline = StoryPipeline()
        result = pipeline.build_from_raw_events(raw_list, tenant_id="t-1")
        result = pipeline.build_from_alerts(alert_list)
        result = pipeline.build_from_normalized_events(event_list)
    """

    def __init__(
        self,
        normalizer: Optional[EventNormalizer] = None,
        engine: Optional[CorrelationEngine] = None,
        builder: Optional[StoryBuilder] = None,
    ) -> None:
        self.normalizer = normalizer or EventNormalizer()
        self.engine = engine or CorrelationEngine()
        self.builder = builder or StoryBuilder()

    # -- Public entry-points -------------------------------------------------

    def build_from_normalized_events(
        self,
        events: List[NormalizedSecurityEvent],
    ) -> StoryPipelineResult:
        """
        Pre-normalized event listesinden pipeline çalıştırır.
        Normalization adımını atlar.

        Args:
            events: NormalizedSecurityEvent listesi

        Returns:
            StoryPipelineResult
        """
        if not events:
            return self._empty_result()

        warnings: List[str] = []
        groups = self._correlate(events, warnings)
        stories = self._build_stories(groups, warnings)
        summary = self._build_summary(events, groups, stories)

        logger.info(
            "pipeline_complete source=normalized events=%d groups=%d stories=%d",
            len(events), len(groups), len(stories),
        )

        return StoryPipelineResult(
            normalized_events=events,
            correlation_groups=groups,
            attack_stories=stories,
            summary=summary,
            warnings=warnings,
        )

    def build_from_raw_events(
        self,
        raw_events: List[Dict[str, Any]],
        tenant_id: Optional[str] = None,
    ) -> StoryPipelineResult:
        """
        Raw event dict listesinden full pipeline çalıştırır.

        Args:
            raw_events: Raw event dict listesi
            tenant_id:  Kiracı kimliği (None → default_tenant)

        Returns:
            StoryPipelineResult
        """
        if not raw_events:
            return self._empty_result()

        events, warnings = self._normalize_batch("raw_event", raw_events, tenant_id)
        return self._run_pipeline(events, warnings)

    def build_from_alerts(
        self,
        alerts: List[Dict[str, Any]],
        tenant_id: Optional[str] = None,
    ) -> StoryPipelineResult:
        """
        Alert dict listesinden full pipeline çalıştırır.

        Args:
            alerts:    Alert dict listesi
            tenant_id: Kiracı kimliği (None → default_tenant)

        Returns:
            StoryPipelineResult
        """
        if not alerts:
            return self._empty_result()

        events, warnings = self._normalize_batch("alert", alerts, tenant_id)
        return self._run_pipeline(events, warnings)

    def build_from_command_results(
        self,
        commands: List[Dict[str, Any]],
        tenant_id: Optional[str] = None,
    ) -> StoryPipelineResult:
        """
        Command result dict listesinden full pipeline çalıştırır.

        Args:
            commands:  Command result dict listesi
            tenant_id: Kiracı kimliği (None → default_tenant)

        Returns:
            StoryPipelineResult
        """
        if not commands:
            return self._empty_result()

        events, warnings = self._normalize_batch("response_result", commands, tenant_id)
        return self._run_pipeline(events, warnings)

    # -- Internal pipeline ---------------------------------------------------

    def _run_pipeline(
        self,
        events: List[NormalizedSecurityEvent],
        warnings: List[str],
    ) -> StoryPipelineResult:
        """Normalize edilmiş event'lerden correlation + story aşamalarını çalıştırır."""
        if not events:
            return StoryPipelineResult(
                summary=self._build_summary([], [], []),
                warnings=warnings,
            )

        groups = self._correlate(events, warnings)
        stories = self._build_stories(groups, warnings)
        summary = self._build_summary(events, groups, stories)

        logger.info(
            "pipeline_complete events=%d groups=%d stories=%d warnings=%d",
            len(events), len(groups), len(stories), len(warnings),
        )

        return StoryPipelineResult(
            normalized_events=events,
            correlation_groups=groups,
            attack_stories=stories,
            summary=summary,
            warnings=warnings,
        )

    def _normalize_batch(
        self,
        source_type: str,
        items: List[Dict[str, Any]],
        tenant_id: Optional[str],
    ) -> Tuple[List[NormalizedSecurityEvent], List[str]]:
        """
        Dict listesini normalize eder. Her item bağımsız try/except
        ile sarılır. Hatalı item'lar warning'e eklenir, atlanır.
        """
        events: List[NormalizedSecurityEvent] = []
        warnings: List[str] = []

        for idx, item in enumerate(items):
            try:
                event = self.normalizer.normalize(source_type, item, tenant_id)
                events.append(event)
            except Exception as exc:
                msg = (
                    f"Normalization hatası (index={idx}, "
                    f"source_type={source_type}): {exc}"
                )
                warnings.append(msg)
                logger.warning("normalize_error %s", msg)

        return events, warnings

    def _correlate(
        self,
        events: List[NormalizedSecurityEvent],
        warnings: List[str],
    ) -> List[CorrelationGroup]:
        """Correlation engine'i çalıştırır. Hata durumunda warning ekler."""
        try:
            return self.engine.correlate(events)
        except Exception as exc:
            msg = f"Correlation hatası: {exc}"
            warnings.append(msg)
            logger.error("correlate_error %s", msg)
            return []

    def _build_stories(
        self,
        groups: List[CorrelationGroup],
        warnings: List[str],
    ) -> List[AttackStory]:
        """Her CorrelationGroup için AttackStory üretir. Hata durumunda warning ekler."""
        stories: List[AttackStory] = []

        for group in groups:
            try:
                story = self.builder.build(group)
                stories.append(story)
            except Exception as exc:
                msg = (
                    f"Story build hatası (group_id={group.id}, "
                    f"title={group.title}): {exc}"
                )
                warnings.append(msg)
                logger.warning("story_build_error %s", msg)

        return stories

    # -- Summary & helpers ---------------------------------------------------

    @staticmethod
    def _build_summary(
        events: List[NormalizedSecurityEvent],
        groups: List[CorrelationGroup],
        stories: List[AttackStory],
    ) -> Dict[str, Any]:
        """Pipeline çıktısından özet istatistikler hesaplar."""
        # Affected hosts/users — story'lerden topla
        all_hosts: List[str] = []
        all_users: List[str] = []
        all_tactics: List[str] = []
        all_techniques: List[str] = []

        for story in stories:
            for h in story.affected_hosts:
                if h not in all_hosts:
                    all_hosts.append(h)
            for u in story.affected_users:
                if u not in all_users:
                    all_users.append(u)
            for t in story.tactics:
                if t not in all_tactics:
                    all_tactics.append(t)
            for t in story.techniques:
                if t not in all_techniques:
                    all_techniques.append(t)

        # Max risk ve highest severity — story'lerden
        max_risk = 0
        highest_severity = "INFO"

        for story in stories:
            if story.risk_score > max_risk:
                max_risk = story.risk_score
            story_rank = _SEVERITY_RANK.get(story.severity, 0)
            current_rank = _SEVERITY_RANK.get(highest_severity, 0)
            if story_rank > current_rank:
                highest_severity = story.severity

        # Story yoksa event'lerden de bakabiliriz
        if not stories and events:
            for ev in events:
                if ev.risk_score > max_risk:
                    max_risk = ev.risk_score
                ev_rank = _SEVERITY_RANK.get(ev.severity, 0)
                current_rank = _SEVERITY_RANK.get(highest_severity, 0)
                if ev_rank > current_rank:
                    highest_severity = ev.severity

        return {
            "total_events": len(events),
            "total_groups": len(groups),
            "total_stories": len(stories),
            "max_risk_score": max_risk,
            "highest_severity": highest_severity,
            "affected_hosts": all_hosts,
            "affected_users": all_users,
            "tactics": all_tactics,
            "techniques": all_techniques,
        }

    @staticmethod
    def _empty_result() -> StoryPipelineResult:
        """Boş input için güvenli boş result döndürür."""
        return StoryPipelineResult(
            summary={
                "total_events": 0,
                "total_groups": 0,
                "total_stories": 0,
                "max_risk_score": 0,
                "highest_severity": "INFO",
                "affected_hosts": [],
                "affected_users": [],
                "tactics": [],
                "techniques": [],
            },
        )

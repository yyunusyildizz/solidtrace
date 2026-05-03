"""
app.services.case_engine.engine
================================
CaseEngine — AttackStory + isteğe bağlı StoryGraph → CaseDraft üretir.

Pure in-memory, DB bağımlılığı yok.
Hiçbir public metot exception fırlatmaz; edge case'ler güvenli default ile ele alınır.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from app.services.attack_story.models import (
    AttackStory,
    RecommendedAction,
)
from app.services.story_graph.models import StoryGraph

from .models import (
    CaseDraft,
    EvidenceItem,
    TimelineItem,
    SEVERITY_ORDER,
)

logger = logging.getLogger("SolidTrace.CaseEngine")


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

CONFIDENCE_ORDER: Dict[str, int] = {"low": 0, "medium": 1, "high": 2}
PRIORITY_ORDER: Dict[str, int] = {"immediate": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# CaseEngine
# ---------------------------------------------------------------------------

class CaseEngine:
    """
    AttackStory + isteğe bağlı StoryGraph → CaseDraft üretir.
    Pure in-memory, DB bağımlılığı yok.

    Public metotlar exception fırlatmaz.
    """

    # -- Public API ----------------------------------------------------------

    def build_single(
        self,
        story: AttackStory,
        graph: Optional[StoryGraph] = None,
    ) -> CaseDraft:
        """Tek AttackStory'den tek CaseDraft üretir."""
        try:
            return self._build_single_impl(story, graph)
        except Exception as exc:
            logger.error("build_single error: %s", exc)
            return CaseDraft()

    def build_consolidated(
        self,
        stories: List[AttackStory],
        graphs: Optional[List[StoryGraph]] = None,
    ) -> CaseDraft:
        """
        Birden fazla ilişkili AttackStory'den tek birleşik CaseDraft üretir.
        Boş liste verilirse güvenli default CaseDraft döner.
        """
        try:
            if not stories:
                return CaseDraft()
            if len(stories) == 1:
                g = graphs[0] if graphs else None
                return self._build_single_impl(stories[0], g)
            return self._build_consolidated_impl(stories, graphs)
        except Exception as exc:
            logger.error("build_consolidated error: %s", exc)
            return CaseDraft()

    def build_batch(
        self,
        stories: List[AttackStory],
        graphs: Optional[List[StoryGraph]] = None,
    ) -> List[CaseDraft]:
        """
        Story listesinden CaseDraft listesi üretir.
        İlişkili story'leri otomatik gruplayıp consolidated case üretir.
        İlişkisiz story'ler tekil case olur.
        Boş liste → boş liste [].
        """
        try:
            if not stories:
                return []
            return self._build_batch_impl(stories, graphs)
        except Exception as exc:
            logger.error("build_batch error: %s", exc)
            return []

    # -- Internal: build_single ----------------------------------------------

    def _build_single_impl(
        self,
        story: AttackStory,
        graph: Optional[StoryGraph] = None,
    ) -> CaseDraft:
        hosts = _deduplicate_strings(story.affected_hosts)
        users = _deduplicate_strings(story.affected_users)
        tactics = _deduplicate_strings(story.tactics)
        techniques = _deduplicate_strings(story.techniques)
        severity = story.severity
        risk_score = story.risk_score
        priority = _calculate_priority(severity, risk_score)
        confidence = story.confidence
        title = story.title or "Security Case"
        summary = story.executive_summary or story.technical_summary or ""
        alert_ids = _extract_alert_ids(story)
        graph_ids = [graph.id] if graph else []
        evidence = self._build_evidence_single(story, graph)
        timeline = self._build_timeline_single(story)
        actions = list(story.recommended_actions)
        questions = _deduplicate_questions(story.analyst_questions)
        tags = _generate_tags(severity, tactics, consolidated=False)

        return CaseDraft(
            tenant_id=story.tenant_id,
            title=title,
            severity=severity,
            risk_score=risk_score,
            priority=priority,
            confidence=confidence,
            summary=summary,
            affected_hosts=hosts,
            affected_users=users,
            tactics=tactics,
            techniques=techniques,
            related_alert_ids=alert_ids,
            related_story_ids=[story.id],
            graph_ids=graph_ids,
            evidence_items=evidence,
            timeline_items=timeline,
            recommended_actions=actions,
            analyst_questions=questions,
            tags=tags,
            attributes={
                "source": "case_engine",
                "story_count": 1,
            },
        )

    # -- Internal: build_consolidated ----------------------------------------

    def _build_consolidated_impl(
        self,
        stories: List[AttackStory],
        graphs: Optional[List[StoryGraph]] = None,
    ) -> CaseDraft:
        graphs = graphs or []

        # Collect all fields from stories
        all_hosts: List[str] = []
        all_users: List[str] = []
        all_tactics: List[str] = []
        all_techniques: List[str] = []
        all_alert_ids: List[str] = []
        all_story_ids: List[str] = []
        all_actions: List[RecommendedAction] = []
        all_questions: List[str] = []
        all_evidence: List[EvidenceItem] = []
        all_timeline_raw: List[TimelineItem] = []

        for story in stories:
            all_hosts.extend(story.affected_hosts)
            all_users.extend(story.affected_users)
            all_tactics.extend(story.tactics)
            all_techniques.extend(story.techniques)
            all_alert_ids.extend(_extract_alert_ids(story))
            all_story_ids.append(story.id)
            all_actions.extend(story.recommended_actions)
            all_questions.extend(story.analyst_questions)
            all_evidence.extend(self._build_evidence_single(story, None))
            all_timeline_raw.extend(self._build_timeline_single(story))

        # Graph evidence
        graph_ids: List[str] = []
        for g in graphs:
            graph_ids.append(g.id)
            all_evidence.append(
                EvidenceItem(
                    evidence_type="graph_summary",
                    source_id=g.id,
                    description=(
                        f"Investigation graph: "
                        f"{g.summary.get('node_count', 0)} nodes, "
                        f"{g.summary.get('edge_count', 0)} edges"
                    ),
                    data=g.summary,
                )
            )

        # Deduplicate
        hosts = _deduplicate_strings(all_hosts)
        users = _deduplicate_strings(all_users)
        tactics = _deduplicate_strings(all_tactics)
        techniques = _deduplicate_strings(all_techniques)
        alert_ids = _deduplicate_strings(all_alert_ids)
        actions = _deduplicate_actions(all_actions)
        questions = _deduplicate_questions(all_questions)

        # Reorder timeline
        reordered_timeline: List[TimelineItem] = []
        for idx, item in enumerate(all_timeline_raw, start=1):
            reordered_timeline.append(item.model_copy(update={"order": idx}))

        # Calculate severity/risk/priority/confidence
        severity = _max_severity(stories)
        risk_score = max((s.risk_score for s in stories), default=0)
        priority = _calculate_priority(severity, risk_score)
        confidence = _max_confidence(stories)
        tenant_id = stories[0].tenant_id

        host_str = ", ".join(hosts[:3]) if hosts else "unknown hosts"
        if len(hosts) > 3:
            host_str += f" (+{len(hosts) - 3} more)"

        title = (
            f"Consolidated Security Case: "
            f"{len(hosts)} host{'s' if len(hosts) != 1 else ''}, "
            f"{len(stories)} stories"
        )
        summary = (
            f"Consolidated case from {len(stories)} attack stories "
            f"affecting {host_str}. "
            f"Highest severity: {severity}, max risk: {risk_score}."
        )
        tags = _generate_tags(severity, tactics, consolidated=True)

        return CaseDraft(
            tenant_id=tenant_id,
            title=title,
            severity=severity,
            risk_score=risk_score,
            priority=priority,
            confidence=confidence,
            summary=summary,
            affected_hosts=hosts,
            affected_users=users,
            tactics=tactics,
            techniques=techniques,
            related_alert_ids=alert_ids,
            related_story_ids=all_story_ids,
            graph_ids=graph_ids,
            evidence_items=all_evidence,
            timeline_items=reordered_timeline,
            recommended_actions=actions,
            analyst_questions=questions,
            tags=tags,
            attributes={
                "source": "case_engine",
                "story_count": len(stories),
            },
        )

    # -- Internal: build_batch -----------------------------------------------

    def _build_batch_impl(
        self,
        stories: List[AttackStory],
        graphs: Optional[List[StoryGraph]] = None,
    ) -> List[CaseDraft]:
        graphs = graphs or []

        # Build graph lookup: story_id → StoryGraph
        graph_map: Dict[str, StoryGraph] = {}
        for g in graphs:
            if g.story_id:
                graph_map[g.story_id] = g

        # Group related stories by shared hosts/users
        groups = self._group_related_stories(stories)

        results: List[CaseDraft] = []
        for group in groups:
            group_graphs = [graph_map[s.id] for s in group if s.id in graph_map]
            if len(group) == 1:
                g = group_graphs[0] if group_graphs else None
                results.append(self._build_single_impl(group[0], g))
            else:
                results.append(
                    self._build_consolidated_impl(group, group_graphs or None)
                )

        return results

    @staticmethod
    def _group_related_stories(
        stories: List[AttackStory],
    ) -> List[List[AttackStory]]:
        """
        Story'leri ortak affected_hosts veya affected_users kesişimine göre
        gruplar. Union-Find algoritması kullanır.
        tenant_id tek başına ilişki sebebi değildir.
        """
        n = len(stories)
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for i in range(n):
            hosts_i = set(stories[i].affected_hosts)
            users_i = set(stories[i].affected_users)
            for j in range(i + 1, n):
                hosts_j = set(stories[j].affected_hosts)
                users_j = set(stories[j].affected_users)
                if (hosts_i & hosts_j) or (users_i & users_j):
                    union(i, j)

        groups_map: Dict[int, List[AttackStory]] = {}
        for i in range(n):
            root = find(i)
            if root not in groups_map:
                groups_map[root] = []
            groups_map[root].append(stories[i])

        return list(groups_map.values())

    # -- Internal: evidence & timeline builders ------------------------------

    def _build_evidence_single(
        self,
        story: AttackStory,
        graph: Optional[StoryGraph],
    ) -> List[EvidenceItem]:
        evidence: List[EvidenceItem] = []

        # Alert evidence
        alert_ids = _extract_alert_ids(story)
        if alert_ids:
            evidence.append(
                EvidenceItem(
                    evidence_type="alert",
                    source_id=story.id,
                    description=f"Related alerts: {', '.join(alert_ids[:5])}",
                    data={"alert_ids": alert_ids},
                )
            )

        # Story timeline evidence
        if story.timeline:
            evidence.append(
                EvidenceItem(
                    evidence_type="story_timeline",
                    source_id=story.id,
                    description=f"Attack timeline: {len(story.timeline)} events",
                    data={"timeline": story.timeline},
                )
            )

        # MITRE mapping evidence
        if story.tactics or story.techniques:
            evidence.append(
                EvidenceItem(
                    evidence_type="mitre_mapping",
                    source_id=story.id,
                    description=(
                        f"MITRE ATT&CK: {', '.join(story.tactics[:3])} / "
                        f"{', '.join(story.techniques[:3])}"
                    ),
                    data={
                        "tactics": story.tactics,
                        "techniques": story.techniques,
                    },
                )
            )

        # Graph summary evidence
        if graph:
            evidence.append(
                EvidenceItem(
                    evidence_type="graph_summary",
                    source_id=graph.id,
                    description=(
                        f"Investigation graph: "
                        f"{graph.summary.get('node_count', 0)} nodes, "
                        f"{graph.summary.get('edge_count', 0)} edges"
                    ),
                    data=graph.summary,
                )
            )

        return evidence

    def _build_timeline_single(self, story: AttackStory) -> List[TimelineItem]:
        if not story.timeline:
            return []

        items: List[TimelineItem] = []
        for idx, entry in enumerate(story.timeline, start=1):
            items.append(
                TimelineItem(
                    order=idx,
                    timestamp=str(entry.get("timestamp", "")),
                    event_id=str(entry.get("event_id", "")),
                    description=str(entry.get("description", f"Event {idx}")),
                    source_story_id=story.id,
                )
            )
        return items


# ---------------------------------------------------------------------------
# Utility fonksiyonlar
# ---------------------------------------------------------------------------

def _calculate_priority(severity: str, risk_score: int) -> str:
    """Severity ve risk_score'a göre priority hesaplar."""
    if severity == "CRITICAL" or risk_score >= 90:
        return "immediate"
    if severity == "HIGH" or risk_score >= 75:
        return "high"
    if severity == "MEDIUM" or risk_score >= 50:
        return "medium"
    return "low"


def _max_severity(stories: List[AttackStory]) -> str:
    """Story listesinden en yüksek severity'yi döndürür."""
    if not stories:
        return "INFO"
    return max(
        (s.severity for s in stories),
        key=lambda sv: SEVERITY_ORDER.get(sv, 0),
        default="INFO",
    )


def _max_confidence(stories: List[AttackStory]) -> str:
    """Story listesinden en yüksek confidence'ı döndürür."""
    if not stories:
        return "medium"
    return max(
        (s.confidence for s in stories),
        key=lambda c: CONFIDENCE_ORDER.get(c, 0),
        default="medium",
    )


def _extract_alert_ids(story: AttackStory) -> List[str]:
    """
    Story'den alert ID'lerini güvenli fallback ile çıkarır.
    Sırasıyla:
      1. story.attributes["alert_ids"]
      2. story.attributes["related_alert_ids"]
      3. story.attributes["event_ids"]
      4. story.timeline içindeki event_id değerleri
    Hiçbiri yoksa [].
    """
    attrs = story.attributes or {}

    for key in ("alert_ids", "related_alert_ids", "event_ids"):
        val = attrs.get(key)
        if isinstance(val, list) and val:
            return [str(v) for v in val if v]

    # Fallback: timeline event_ids
    if story.timeline:
        ids = []
        for entry in story.timeline:
            eid = entry.get("event_id")
            if eid:
                ids.append(str(eid))
        if ids:
            return ids

    return []


def _deduplicate_strings(items: List[str]) -> List[str]:
    """Sırayı koruyarak string listesinden duplikatları temizler."""
    seen: Set[str] = set()
    result: List[str] = []
    for item in items:
        cleaned = item.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def _deduplicate_actions(
    actions: List[RecommendedAction],
) -> List[RecommendedAction]:
    """
    (action_type, target) çifti bazında deduplicate.
    Aynı key varsa daha yüksek priority korunur.
    """
    seen: Dict[Tuple[str, Optional[str]], RecommendedAction] = {}
    for action in actions:
        key = (action.action_type, action.target)
        if key not in seen:
            seen[key] = action
        else:
            existing = seen[key]
            if PRIORITY_ORDER.get(action.priority, 99) < PRIORITY_ORDER.get(
                existing.priority, 99
            ):
                seen[key] = action
    return list(seen.values())


def _deduplicate_questions(questions: List[str]) -> List[str]:
    """Sırayı koruyarak string bazında deduplicate (case-insensitive)."""
    seen: Set[str] = set()
    result: List[str] = []
    for q in questions:
        key = q.strip().lower()
        if key and key not in seen:
            seen.add(key)
            result.append(q.strip())
    return result


def _generate_tags(
    severity: str, tactics: List[str], consolidated: bool
) -> List[str]:
    """Deterministic tag listesi üretir."""
    tags: List[str] = []

    # Severity tag
    if severity:
        tags.append(f"severity:{severity.lower()}")

    # Tactic tags (sorted for determinism)
    for tactic in sorted(set(tactics)):
        tag = f"tactic:{tactic.lower().replace(' ', '-')}"
        tags.append(tag)

    # Consolidated tag
    if consolidated:
        tags.append("consolidated")

    return tags

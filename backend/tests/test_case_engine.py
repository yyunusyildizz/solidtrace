"""
tests.test_case_engine
=========================
CaseEngine, CaseDraft, EvidenceItem, TimelineItem unit testleri.
DB erişimi yok — tamamen in-memory.
"""

import pytest
from pydantic import ValidationError

from app.services.attack_story.models import AttackStory, RecommendedAction
from app.services.story_graph.models import StoryGraph
from app.services.case_engine.models import (
    CaseDraft, EvidenceItem, TimelineItem,
    SEVERITY_ORDER, PRIORITY_LEVELS, CONFIDENCE_LEVELS, STATUS_VALUES,
)
from app.services.case_engine.engine import (
    CaseEngine, _calculate_priority, _extract_alert_ids,
    _deduplicate_strings, _deduplicate_actions, _deduplicate_questions,
    _generate_tags, _max_severity, _max_confidence,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _make_story(**kwargs) -> AttackStory:
    defaults = {
        "tenant_id": "test-tenant",
        "title": "Test Story",
        "executive_summary": "Executive summary text",
        "technical_summary": "Technical summary text",
        "severity": "HIGH",
        "confidence": "high",
        "risk_score": 80,
        "affected_hosts": ["WS-01"],
        "affected_users": ["admin"],
        "tactics": ["Execution"],
        "techniques": ["T1059.001"],
        "timeline": [
            {"order": 1, "event_id": "evt-1", "timestamp": "2026-01-01T00:00:00Z", "description": "First event"},
            {"order": 2, "event_id": "evt-2", "timestamp": "2026-01-01T00:01:00Z", "description": "Second event"},
        ],
        "recommended_actions": [
            RecommendedAction(action_type="isolate_host", title="Isolate", priority="immediate", target="WS-01"),
            RecommendedAction(action_type="review_process_tree", title="Review", priority="high", target="WS-01"),
        ],
        "analyst_questions": ["Is lateral movement present?", "Was data exfiltrated?"],
        "attributes": {"alert_ids": ["alert-1", "alert-2"], "event_count": 3},
    }
    defaults.update(kwargs)
    return AttackStory(**defaults)


def _make_graph(story: AttackStory) -> StoryGraph:
    return StoryGraph(
        story_id=story.id, tenant_id=story.tenant_id, title=story.title,
        severity=story.severity, risk_score=story.risk_score,
        summary={"node_count": 5, "edge_count": 4, "host_count": 1},
    )


# ---------------------------------------------------------------------------
# CaseDraft Model Tests
# ---------------------------------------------------------------------------

class TestCaseDraftModel:

    def test_valid_creation(self):
        cd = CaseDraft(title="Test", severity="HIGH", risk_score=85, priority="high")
        assert cd.title == "Test"
        assert cd.severity == "HIGH"
        assert cd.risk_score == 85
        assert cd.id
        assert cd.created_at

    def test_minimal_defaults(self):
        cd = CaseDraft()
        assert cd.title == ""
        assert cd.severity == "INFO"
        assert cd.risk_score == 0
        assert cd.status == "new"
        assert cd.priority == "low"
        assert cd.confidence == "medium"
        assert cd.affected_hosts == []
        assert cd.recommended_actions == []

    def test_id_auto_generated_unique(self):
        assert CaseDraft().id != CaseDraft().id

    def test_risk_score_clamped_high(self):
        assert CaseDraft(risk_score=150).risk_score == 100

    def test_risk_score_clamped_low(self):
        assert CaseDraft(risk_score=-10).risk_score == 0

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError, match="severity"):
            CaseDraft(severity="UNKNOWN")

    def test_invalid_priority_rejected(self):
        with pytest.raises(ValidationError, match="priority"):
            CaseDraft(priority="urgent")

    def test_invalid_confidence_rejected(self):
        with pytest.raises(ValidationError, match="confidence"):
            CaseDraft(confidence="super_high")

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError, match="status"):
            CaseDraft(status="deleted")

    def test_severity_case_insensitive(self):
        assert CaseDraft(severity="critical").severity == "CRITICAL"

    def test_status_default_new(self):
        assert CaseDraft().status == "new"

    def test_to_dict_returns_complete_data(self):
        cd = CaseDraft(title="T", severity="HIGH", risk_score=75, affected_hosts=["H1"])
        d = cd.to_dict()
        assert isinstance(d, dict)
        assert d["title"] == "T"
        assert d["severity"] == "HIGH"
        assert d["affected_hosts"] == ["H1"]
        assert "id" in d and "created_at" in d


# ---------------------------------------------------------------------------
# EvidenceItem Model Tests
# ---------------------------------------------------------------------------

class TestEvidenceItemModel:

    def test_valid_evidence(self):
        ei = EvidenceItem(evidence_type="alert", source_id="a-1", description="test")
        assert ei.evidence_type == "alert"

    def test_invalid_evidence_type(self):
        with pytest.raises(ValidationError, match="evidence_type"):
            EvidenceItem(evidence_type="invalid_type")

    def test_all_evidence_types(self):
        from app.services.case_engine.models import EVIDENCE_TYPES
        for et in EVIDENCE_TYPES:
            assert EvidenceItem(evidence_type=et).evidence_type == et


# ---------------------------------------------------------------------------
# TimelineItem Model Tests
# ---------------------------------------------------------------------------

class TestTimelineItemModel:

    def test_valid_timeline(self):
        ti = TimelineItem(order=1, event_id="e-1", description="First")
        assert ti.order == 1

    def test_order_clamped_to_1(self):
        assert TimelineItem(order=0).order == 1
        assert TimelineItem(order=-5).order == 1


# ---------------------------------------------------------------------------
# CaseEngine — Single Story
# ---------------------------------------------------------------------------

class TestCaseEngineSingle:

    def setup_method(self):
        self.engine = CaseEngine()

    def test_produces_case(self):
        story = _make_story()
        cd = self.engine.build_single(story)
        assert isinstance(cd, CaseDraft)
        assert cd.id

    def test_title_mapped(self):
        cd = self.engine.build_single(_make_story(title="Credential Dump"))
        assert cd.title == "Credential Dump"

    def test_empty_title_fallback(self):
        cd = self.engine.build_single(_make_story(title=""))
        assert cd.title == "Security Case"

    def test_severity_preserved(self):
        cd = self.engine.build_single(_make_story(severity="CRITICAL"))
        assert cd.severity == "CRITICAL"

    def test_risk_preserved(self):
        cd = self.engine.build_single(_make_story(risk_score=92))
        assert cd.risk_score == 92

    def test_priority_calculated(self):
        cd = self.engine.build_single(_make_story(severity="CRITICAL", risk_score=95))
        assert cd.priority == "immediate"

    def test_hosts_mapped(self):
        cd = self.engine.build_single(_make_story(affected_hosts=["H1", "H2"]))
        assert cd.affected_hosts == ["H1", "H2"]

    def test_users_mapped(self):
        cd = self.engine.build_single(_make_story(affected_users=["u1", "u2"]))
        assert cd.affected_users == ["u1", "u2"]

    def test_tactics_mapped(self):
        cd = self.engine.build_single(_make_story(tactics=["Execution", "Persistence"]))
        assert cd.tactics == ["Execution", "Persistence"]

    def test_techniques_mapped(self):
        cd = self.engine.build_single(_make_story(techniques=["T1059.001"]))
        assert cd.techniques == ["T1059.001"]

    def test_with_graph(self):
        story = _make_story()
        graph = _make_graph(story)
        cd = self.engine.build_single(story, graph)
        assert graph.id in cd.graph_ids
        assert any(e.evidence_type == "graph_summary" for e in cd.evidence_items)

    def test_without_graph(self):
        cd = self.engine.build_single(_make_story())
        assert cd.graph_ids == []

    def test_timeline_from_story(self):
        story = _make_story(timeline=[
            {"order": 1, "event_id": "e-1", "description": "A"},
            {"order": 2, "event_id": "e-2", "description": "B"},
        ])
        cd = self.engine.build_single(story)
        assert len(cd.timeline_items) == 2
        assert cd.timeline_items[0].event_id == "e-1"
        assert cd.timeline_items[1].order == 2

    def test_recommended_actions_copied(self):
        story = _make_story()
        cd = self.engine.build_single(story)
        assert len(cd.recommended_actions) == 2
        assert cd.recommended_actions[0].action_type == "isolate_host"

    def test_analyst_questions_copied(self):
        story = _make_story()
        cd = self.engine.build_single(story)
        assert len(cd.analyst_questions) == 2

    def test_tenant_preserved(self):
        cd = self.engine.build_single(_make_story(tenant_id="t-xyz"))
        assert cd.tenant_id == "t-xyz"

    def test_related_story_id(self):
        story = _make_story()
        cd = self.engine.build_single(story)
        assert story.id in cd.related_story_ids

    def test_alert_ids_from_attributes(self):
        story = _make_story(attributes={"alert_ids": ["a-1", "a-2"]})
        cd = self.engine.build_single(story)
        assert cd.related_alert_ids == ["a-1", "a-2"]


# ---------------------------------------------------------------------------
# Priority Calculation
# ---------------------------------------------------------------------------

class TestPriorityCalculation:

    def test_critical_immediate(self):
        assert _calculate_priority("CRITICAL", 50) == "immediate"

    def test_risk_90_immediate(self):
        assert _calculate_priority("LOW", 90) == "immediate"

    def test_high_high(self):
        assert _calculate_priority("HIGH", 60) == "high"

    def test_risk_75_high(self):
        assert _calculate_priority("LOW", 75) == "high"

    def test_medium_medium(self):
        assert _calculate_priority("MEDIUM", 40) == "medium"

    def test_risk_50_medium(self):
        assert _calculate_priority("LOW", 50) == "medium"

    def test_low_low(self):
        assert _calculate_priority("LOW", 30) == "low"

    def test_info_low(self):
        assert _calculate_priority("INFO", 0) == "low"


# ---------------------------------------------------------------------------
# Multi-Story Consolidation
# ---------------------------------------------------------------------------

class TestCaseEngineConsolidated:

    def setup_method(self):
        self.engine = CaseEngine()

    def test_two_stories_consolidated(self):
        s1 = _make_story(title="Story A", severity="HIGH", risk_score=70)
        s2 = _make_story(title="Story B", severity="CRITICAL", risk_score=95)
        cd = self.engine.build_consolidated([s1, s2])
        assert "Consolidated" in cd.title
        assert cd.attributes["story_count"] == 2

    def test_severity_max_used(self):
        s1 = _make_story(severity="MEDIUM", risk_score=40)
        s2 = _make_story(severity="CRITICAL", risk_score=95)
        cd = self.engine.build_consolidated([s1, s2])
        assert cd.severity == "CRITICAL"

    def test_risk_max_used(self):
        s1 = _make_story(risk_score=40)
        s2 = _make_story(risk_score=90)
        cd = self.engine.build_consolidated([s1, s2])
        assert cd.risk_score == 90

    def test_hosts_merged_deduplicated(self):
        s1 = _make_story(affected_hosts=["H1", "H2"])
        s2 = _make_story(affected_hosts=["H2", "H3"])
        cd = self.engine.build_consolidated([s1, s2])
        assert sorted(cd.affected_hosts) == ["H1", "H2", "H3"]

    def test_users_merged_deduplicated(self):
        s1 = _make_story(affected_users=["admin", "root"])
        s2 = _make_story(affected_users=["root", "svc"])
        cd = self.engine.build_consolidated([s1, s2])
        assert sorted(cd.affected_users) == ["admin", "root", "svc"]

    def test_tactics_merged_deduplicated(self):
        s1 = _make_story(tactics=["Execution"])
        s2 = _make_story(tactics=["Execution", "Persistence"])
        cd = self.engine.build_consolidated([s1, s2])
        assert "Execution" in cd.tactics
        assert "Persistence" in cd.tactics
        assert cd.tactics.count("Execution") == 1

    def test_techniques_merged_deduplicated(self):
        s1 = _make_story(techniques=["T1059.001"])
        s2 = _make_story(techniques=["T1059.001", "T1003"])
        cd = self.engine.build_consolidated([s1, s2])
        assert cd.techniques.count("T1059.001") == 1
        assert "T1003" in cd.techniques

    def test_related_story_ids_all_included(self):
        s1 = _make_story()
        s2 = _make_story()
        cd = self.engine.build_consolidated([s1, s2])
        assert s1.id in cd.related_story_ids
        assert s2.id in cd.related_story_ids

    def test_actions_deduplicated(self):
        action = RecommendedAction(action_type="isolate_host", title="Isolate", priority="immediate", target="WS-01")
        s1 = _make_story(recommended_actions=[action])
        s2 = _make_story(recommended_actions=[action])
        cd = self.engine.build_consolidated([s1, s2])
        isolate_actions = [a for a in cd.recommended_actions if a.action_type == "isolate_host" and a.target == "WS-01"]
        assert len(isolate_actions) == 1

    def test_questions_deduplicated(self):
        s1 = _make_story(analyst_questions=["Is lateral movement present?"])
        s2 = _make_story(analyst_questions=["Is lateral movement present?", "New question?"])
        cd = self.engine.build_consolidated([s1, s2])
        q_lower = [q.lower() for q in cd.analyst_questions]
        assert q_lower.count("is lateral movement present?") == 1

    def test_timeline_reordered(self):
        s1 = _make_story(timeline=[{"order": 1, "event_id": "e-1"}])
        s2 = _make_story(timeline=[{"order": 1, "event_id": "e-2"}])
        cd = self.engine.build_consolidated([s1, s2])
        assert len(cd.timeline_items) == 2
        assert cd.timeline_items[0].order == 1
        assert cd.timeline_items[1].order == 2

    def test_priority_recalculated(self):
        s1 = _make_story(severity="MEDIUM", risk_score=40)
        s2 = _make_story(severity="CRITICAL", risk_score=95)
        cd = self.engine.build_consolidated([s1, s2])
        assert cd.priority == "immediate"

    def test_confidence_max_used(self):
        s1 = _make_story(confidence="low")
        s2 = _make_story(confidence="high")
        cd = self.engine.build_consolidated([s1, s2])
        assert cd.confidence == "high"

    def test_single_story_delegates_to_single(self):
        story = _make_story()
        cd = self.engine.build_consolidated([story])
        assert "Consolidated" not in cd.title
        assert cd.attributes["story_count"] == 1


# ---------------------------------------------------------------------------
# Batch Tests
# ---------------------------------------------------------------------------

class TestCaseEngineBatch:

    def setup_method(self):
        self.engine = CaseEngine()

    def test_related_stories_grouped(self):
        s1 = _make_story(affected_hosts=["H1"], affected_users=["admin"])
        s2 = _make_story(affected_hosts=["H1"], affected_users=["root"])
        cases = self.engine.build_batch([s1, s2])
        assert len(cases) == 1
        assert "Consolidated" in cases[0].title

    def test_unrelated_stories_separate(self):
        s1 = _make_story(affected_hosts=["H1"], affected_users=["admin"])
        s2 = _make_story(affected_hosts=["H2"], affected_users=["root"])
        cases = self.engine.build_batch([s1, s2])
        assert len(cases) == 2

    def test_mixed_related_unrelated(self):
        s1 = _make_story(affected_hosts=["H1"], affected_users=["admin"])
        s2 = _make_story(affected_hosts=["H1"], affected_users=["root"])
        s3 = _make_story(affected_hosts=["H3"], affected_users=["other"])
        cases = self.engine.build_batch([s1, s2, s3])
        assert len(cases) == 2

    def test_tenant_id_alone_not_grouping(self):
        """Aynı tenant_id ama farklı host/user → ayrı case'ler."""
        s1 = _make_story(tenant_id="t-1", affected_hosts=["H1"], affected_users=["u1"])
        s2 = _make_story(tenant_id="t-1", affected_hosts=["H2"], affected_users=["u2"])
        cases = self.engine.build_batch([s1, s2])
        assert len(cases) == 2


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestCaseEngineEdgeCases:

    def setup_method(self):
        self.engine = CaseEngine()

    def test_empty_story_no_crash(self):
        cd = self.engine.build_single(AttackStory())
        assert isinstance(cd, CaseDraft)
        assert cd.severity == "INFO"
        assert cd.risk_score == 0

    def test_empty_story_list_consolidated(self):
        cd = self.engine.build_consolidated([])
        assert isinstance(cd, CaseDraft)

    def test_empty_batch_returns_empty_list(self):
        result = self.engine.build_batch([])
        assert result == []

    def test_duplicate_hosts_cleaned(self):
        story = _make_story(affected_hosts=["H1", "H1", "H2", "H1"])
        cd = self.engine.build_single(story)
        assert cd.affected_hosts == ["H1", "H2"]

    def test_empty_timeline_safe(self):
        cd = self.engine.build_single(_make_story(timeline=[]))
        assert cd.timeline_items == []

    def test_none_graph_safe(self):
        cd = self.engine.build_single(_make_story(), graph=None)
        assert cd.graph_ids == []


# ---------------------------------------------------------------------------
# Alert ID Extraction Fallback
# ---------------------------------------------------------------------------

class TestAlertIdExtraction:

    def test_from_alert_ids(self):
        story = _make_story(attributes={"alert_ids": ["a-1"]})
        assert _extract_alert_ids(story) == ["a-1"]

    def test_from_related_alert_ids(self):
        story = _make_story(attributes={"related_alert_ids": ["ra-1"]})
        assert _extract_alert_ids(story) == ["ra-1"]

    def test_from_event_ids(self):
        story = _make_story(attributes={"event_ids": ["ev-1"]})
        assert _extract_alert_ids(story) == ["ev-1"]

    def test_from_timeline_fallback(self):
        story = _make_story(
            attributes={},
            timeline=[{"event_id": "t-1"}, {"event_id": "t-2"}],
        )
        assert _extract_alert_ids(story) == ["t-1", "t-2"]

    def test_empty_fallback(self):
        story = _make_story(attributes={}, timeline=[])
        assert _extract_alert_ids(story) == []

    def test_priority_order(self):
        """alert_ids key varsa diğerlerine bakılmaz."""
        story = _make_story(attributes={
            "alert_ids": ["a-1"],
            "related_alert_ids": ["r-1"],
            "event_ids": ["e-1"],
        })
        assert _extract_alert_ids(story) == ["a-1"]


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestCaseDraftSerialization:

    def setup_method(self):
        self.engine = CaseEngine()

    def test_to_dict_complete(self):
        story = _make_story()
        graph = _make_graph(story)
        cd = self.engine.build_single(story, graph)
        d = cd.to_dict()
        assert isinstance(d, dict)
        for key in ("id", "title", "severity", "risk_score", "status", "priority",
                     "evidence_items", "timeline_items", "recommended_actions", "tags"):
            assert key in d

    def test_evidence_items_are_dicts(self):
        cd = self.engine.build_single(_make_story())
        d = cd.to_dict()
        for ei in d["evidence_items"]:
            assert isinstance(ei, dict)
            assert "evidence_type" in ei

    def test_timeline_items_are_dicts(self):
        cd = self.engine.build_single(_make_story())
        d = cd.to_dict()
        for ti in d["timeline_items"]:
            assert isinstance(ti, dict)
            assert "order" in ti

    def test_recommended_actions_are_dicts(self):
        cd = self.engine.build_single(_make_story())
        d = cd.to_dict()
        for ra in d["recommended_actions"]:
            assert isinstance(ra, dict)
            assert "action_type" in ra


# ---------------------------------------------------------------------------
# Tag Generation
# ---------------------------------------------------------------------------

class TestTagGeneration:

    def test_severity_tag(self):
        tags = _generate_tags("CRITICAL", [], False)
        assert "severity:critical" in tags

    def test_tactic_tags(self):
        tags = _generate_tags("HIGH", ["Credential Access", "Execution"], False)
        assert "tactic:credential-access" in tags
        assert "tactic:execution" in tags

    def test_consolidated_tag_multi(self):
        tags = _generate_tags("HIGH", [], True)
        assert "consolidated" in tags

    def test_no_consolidated_tag_single(self):
        tags = _generate_tags("HIGH", [], False)
        assert "consolidated" not in tags

    def test_deterministic_order(self):
        """Tactic tags are sorted for determinism."""
        tags1 = _generate_tags("HIGH", ["Execution", "Credential Access"], False)
        tags2 = _generate_tags("HIGH", ["Credential Access", "Execution"], False)
        assert tags1 == tags2

    def test_engine_single_severity_tag(self):
        engine = CaseEngine()
        cd = engine.build_single(_make_story(severity="CRITICAL", tactics=["Execution"]))
        assert "severity:critical" in cd.tags
        assert "tactic:execution" in cd.tags

    def test_engine_consolidated_tag(self):
        engine = CaseEngine()
        s1 = _make_story(severity="HIGH")
        s2 = _make_story(severity="CRITICAL")
        cd = engine.build_consolidated([s1, s2])
        assert "consolidated" in cd.tags


# ---------------------------------------------------------------------------
# Deduplication Utilities
# ---------------------------------------------------------------------------

class TestDeduplication:

    def test_deduplicate_strings(self):
        assert _deduplicate_strings(["a", "b", "a", "c"]) == ["a", "b", "c"]

    def test_deduplicate_strings_strips(self):
        assert _deduplicate_strings([" a ", "a", " b"]) == ["a", "b"]

    def test_deduplicate_strings_skips_empty(self):
        assert _deduplicate_strings(["", "a", "", "b"]) == ["a", "b"]

    def test_deduplicate_actions_by_type_target(self):
        a1 = RecommendedAction(action_type="isolate_host", priority="high", target="H1")
        a2 = RecommendedAction(action_type="isolate_host", priority="immediate", target="H1")
        result = _deduplicate_actions([a1, a2])
        assert len(result) == 1
        assert result[0].priority == "immediate"  # higher priority kept

    def test_deduplicate_actions_different_targets(self):
        a1 = RecommendedAction(action_type="isolate_host", priority="high", target="H1")
        a2 = RecommendedAction(action_type="isolate_host", priority="high", target="H2")
        result = _deduplicate_actions([a1, a2])
        assert len(result) == 2

    def test_deduplicate_questions_case_insensitive(self):
        result = _deduplicate_questions(["Is it safe?", "IS IT SAFE?", "New?"])
        assert len(result) == 2

    def test_max_severity(self):
        stories = [_make_story(severity="LOW"), _make_story(severity="CRITICAL")]
        assert _max_severity(stories) == "CRITICAL"

    def test_max_confidence(self):
        stories = [_make_story(confidence="low"), _make_story(confidence="high")]
        assert _max_confidence(stories) == "high"


# ---------------------------------------------------------------------------
# Import / Regression Tests
# ---------------------------------------------------------------------------

class TestPackageImports:

    def test_import_from_package(self):
        from app.services.case_engine import CaseEngine, CaseDraft, EvidenceItem, TimelineItem
        assert CaseEngine is not None
        assert CaseDraft is not None
        assert EvidenceItem is not None
        assert TimelineItem is not None

    def test_existing_attack_story_unchanged(self):
        from app.services.attack_story import AttackStory, RecommendedAction, StoryBuilder
        assert AttackStory is not None
        assert RecommendedAction is not None
        assert StoryBuilder is not None

    def test_existing_story_graph_unchanged(self):
        from app.services.story_graph import StoryGraph, StoryGraphBuilder, GraphNode, GraphEdge
        assert StoryGraph is not None
        assert StoryGraphBuilder is not None

    def test_existing_story_pipeline_unchanged(self):
        from app.services.story_pipeline import StoryPipeline, StoryPipelineResult
        assert StoryPipeline is not None
        assert StoryPipelineResult is not None

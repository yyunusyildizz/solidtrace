"""
tests.test_attack_story_builder
=================================
AttackStory modeli, RecommendedAction modeli ve StoryBuilder servisi
için unit testler. DB erişimi yok — tamamen in-memory.
"""

import pytest
from pydantic import ValidationError

from app.services.correlation_engine.models import CorrelationGroup
from app.services.attack_story.models import (
    ACTION_TYPES,
    AttackStory,
    RecommendedAction,
)
from app.services.attack_story.builder import StoryBuilder


# ---------------------------------------------------------------------------
# Test Helper
# ---------------------------------------------------------------------------

def _make_group(**kwargs) -> CorrelationGroup:
    """Test CorrelationGroup oluşturur."""
    defaults = {
        "tenant_id": "test-tenant",
        "title": "Test Group",
        "description": "Test correlation group",
        "severity": "HIGH",
        "confidence": "high",
        "risk_score": 80,
        "status": "open",
        "event_ids": ["evt-1", "evt-2", "evt-3"],
        "alert_ids": ["alert-1"],
        "entities": {
            "hostnames": ["WORKSTATION-01"],
            "usernames": ["admin"],
            "ips": ["10.0.0.1"],
        },
        "tactics": ["Execution"],
        "techniques": ["T1059.001"],
        "reason": "Test correlation reason",
    }
    defaults.update(kwargs)
    return CorrelationGroup(**defaults)


# ---------------------------------------------------------------------------
# AttackStory Model Testleri
# ---------------------------------------------------------------------------

class TestAttackStoryModel:

    def test_valid_story_creation(self):
        story = AttackStory(
            tenant_id="t-123",
            correlation_group_id="grp-456",
            title="Test Story",
            executive_summary="Summary for executives",
            technical_summary="Technical details",
            severity="HIGH",
            confidence="high",
            risk_score=85,
        )
        assert story.title == "Test Story"
        assert story.severity == "HIGH"
        assert story.risk_score == 85
        assert story.id  # UUID auto-generated
        assert story.created_at

    def test_minimal_story_creation(self):
        story = AttackStory()
        assert story.title == ""
        assert story.severity == "INFO"
        assert story.confidence == "medium"
        assert story.risk_score == 0
        assert story.affected_hosts == []
        assert story.recommended_actions == []
        assert story.analyst_questions == []

    def test_id_auto_generated_unique(self):
        s1 = AttackStory()
        s2 = AttackStory()
        assert s1.id != s2.id

    def test_risk_score_clamped_high(self):
        story = AttackStory(risk_score=150)
        assert story.risk_score == 100

    def test_risk_score_clamped_low(self):
        story = AttackStory(risk_score=-10)
        assert story.risk_score == 0

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError, match="severity"):
            AttackStory(severity="UNKNOWN")

    def test_invalid_confidence_rejected(self):
        with pytest.raises(ValidationError, match="confidence"):
            AttackStory(confidence="super_high")

    def test_severity_case_insensitive(self):
        story = AttackStory(severity="critical")
        assert story.severity == "CRITICAL"

    def test_to_dict_returns_complete_data(self):
        story = AttackStory(
            title="Test",
            severity="HIGH",
            risk_score=75,
            affected_hosts=["HOST-1"],
        )
        d = story.to_dict()
        assert isinstance(d, dict)
        assert d["title"] == "Test"
        assert d["severity"] == "HIGH"
        assert d["affected_hosts"] == ["HOST-1"]
        assert "id" in d
        assert "recommended_actions" in d


# ---------------------------------------------------------------------------
# RecommendedAction Model Testleri
# ---------------------------------------------------------------------------

class TestRecommendedActionModel:

    def test_valid_action_creation(self):
        action = RecommendedAction(
            action_type="isolate_host",
            title="Isolate",
            description="Isolate the host",
            priority="immediate",
            target="HOST-01",
        )
        assert action.action_type == "isolate_host"
        assert action.priority == "immediate"
        assert action.target == "HOST-01"

    def test_invalid_action_type_rejected(self):
        with pytest.raises(ValidationError, match="action_type"):
            RecommendedAction(action_type="unknown_action")

    def test_invalid_priority_rejected(self):
        with pytest.raises(ValidationError, match="priority"):
            RecommendedAction(action_type="isolate_host", priority="urgent")

    def test_all_action_types_valid(self):
        for at in ACTION_TYPES:
            action = RecommendedAction(action_type=at)
            assert action.action_type == at

    def test_action_type_case_insensitive(self):
        action = RecommendedAction(action_type="ISOLATE_HOST")
        assert action.action_type == "isolate_host"

    def test_priority_case_insensitive(self):
        action = RecommendedAction(
            action_type="monitor_host",
            priority="HIGH",
        )
        assert action.priority == "high"


# ---------------------------------------------------------------------------
# StoryBuilder — Credential Dumping Template
# ---------------------------------------------------------------------------

class TestStoryBuilderCredentialDumping:

    def setup_method(self):
        self.builder = StoryBuilder()

    def test_produces_credential_story(self):
        group = _make_group(
            title="Credential Dumping Chain",
            severity="CRITICAL",
            risk_score=95,
            tactics=["Credential Access"],
            techniques=["T1003", "T1003.001"],
        )
        story = self.builder.build(group)
        assert story.title == "Possible Credential Dumping Activity"
        assert story.severity == "CRITICAL"
        assert story.risk_score == 95

    def test_executive_summary_mentions_host(self):
        group = _make_group(
            title="Credential Dumping Chain",
            entities={"hostnames": ["DC-01"], "usernames": ["admin"], "ips": []},
        )
        story = self.builder.build(group)
        assert "DC-01" in story.executive_summary

    def test_recommended_actions_include_isolate_and_reset(self):
        group = _make_group(title="Credential Dumping Chain")
        story = self.builder.build(group)
        action_types = [a.action_type for a in story.recommended_actions]
        assert "isolate_host" in action_types
        assert "reset_credentials" in action_types
        assert "collect_artifacts" in action_types
        assert "create_case" in action_types

    def test_key_findings_populated(self):
        group = _make_group(
            title="Credential Dumping Chain",
            tactics=["Credential Access"],
            techniques=["T1003"],
        )
        story = self.builder.build(group)
        assert len(story.key_findings) >= 3
        findings_text = " ".join(story.key_findings)
        assert "T1003" in findings_text

    def test_analyst_questions_populated(self):
        group = _make_group(title="Credential Dumping Chain")
        story = self.builder.build(group)
        assert len(story.analyst_questions) >= 2


# ---------------------------------------------------------------------------
# StoryBuilder — PowerShell Chain Template
# ---------------------------------------------------------------------------

class TestStoryBuilderPowerShell:

    def setup_method(self):
        self.builder = StoryBuilder()

    def test_produces_powershell_story(self):
        group = _make_group(
            title="Suspicious PowerShell Chain",
            severity="HIGH",
            risk_score=85,
        )
        story = self.builder.build(group)
        assert story.title == "Suspicious PowerShell Execution Chain"
        assert story.severity == "HIGH"

    def test_executive_summary_mentions_powershell(self):
        group = _make_group(title="Suspicious PowerShell Chain")
        story = self.builder.build(group)
        assert "PowerShell" in story.executive_summary

    def test_recommended_actions_include_review_and_monitor(self):
        group = _make_group(title="Suspicious PowerShell Chain")
        story = self.builder.build(group)
        action_types = [a.action_type for a in story.recommended_actions]
        assert "isolate_host" in action_types
        assert "review_process_tree" in action_types
        assert "monitor_host" in action_types

    def test_analyst_questions_about_payload(self):
        group = _make_group(title="Suspicious PowerShell Chain")
        story = self.builder.build(group)
        questions_text = " ".join(story.analyst_questions)
        assert "payload" in questions_text.lower()


# ---------------------------------------------------------------------------
# StoryBuilder — High Risk Burst Template
# ---------------------------------------------------------------------------

class TestStoryBuilderHighRiskBurst:

    def setup_method(self):
        self.builder = StoryBuilder()

    def test_produces_burst_story(self):
        group = _make_group(
            title="Same Host High Risk Burst",
            severity="HIGH",
            risk_score=78,
        )
        story = self.builder.build(group)
        assert story.title == "High Risk Activity Burst on Host"

    def test_executive_summary_mentions_burst(self):
        group = _make_group(title="Same Host High Risk Burst")
        story = self.builder.build(group)
        assert "yoğun" in story.executive_summary or "kısa sürede" in story.executive_summary

    def test_recommended_actions_include_monitor(self):
        group = _make_group(title="Same Host High Risk Burst")
        story = self.builder.build(group)
        action_types = [a.action_type for a in story.recommended_actions]
        assert "monitor_host" in action_types
        assert "review_process_tree" in action_types
        assert "create_case" in action_types

    def test_technical_summary_includes_risk_score(self):
        group = _make_group(
            title="Same Host High Risk Burst",
            risk_score=88,
        )
        story = self.builder.build(group)
        assert "88" in story.technical_summary


# ---------------------------------------------------------------------------
# StoryBuilder — Generic Fallback
# ---------------------------------------------------------------------------

class TestStoryBuilderGenericFallback:

    def setup_method(self):
        self.builder = StoryBuilder()

    def test_unknown_title_uses_generic(self):
        group = _make_group(title="Unknown Rule ABC")
        story = self.builder.build(group)
        assert story.title == "Unknown Rule ABC"

    def test_empty_title_uses_default(self):
        group = _make_group(title="")
        story = self.builder.build(group)
        assert story.title == "Security Correlation Alert"

    def test_critical_severity_gets_isolate_action(self):
        group = _make_group(
            title="Custom Rule",
            severity="CRITICAL",
        )
        story = self.builder.build(group)
        action_types = [a.action_type for a in story.recommended_actions]
        assert "isolate_host" in action_types

    def test_low_severity_gets_monitor_action(self):
        group = _make_group(
            title="Custom Rule",
            severity="LOW",
            risk_score=25,
        )
        story = self.builder.build(group)
        action_types = [a.action_type for a in story.recommended_actions]
        assert "monitor_host" in action_types
        assert "isolate_host" not in action_types


# ---------------------------------------------------------------------------
# StoryBuilder — Entity Mapping
# ---------------------------------------------------------------------------

class TestStoryBuilderEntities:

    def setup_method(self):
        self.builder = StoryBuilder()

    def test_hosts_mapped(self):
        group = _make_group(
            entities={
                "hostnames": ["HOST-A", "HOST-B"],
                "usernames": [],
                "ips": [],
            },
        )
        story = self.builder.build(group)
        assert story.affected_hosts == ["HOST-A", "HOST-B"]

    def test_users_mapped(self):
        group = _make_group(
            entities={
                "hostnames": [],
                "usernames": ["admin", "svc_acct"],
                "ips": [],
            },
        )
        story = self.builder.build(group)
        assert story.affected_users == ["admin", "svc_acct"]

    def test_ips_mapped(self):
        group = _make_group(
            entities={
                "hostnames": [],
                "usernames": [],
                "ips": ["10.0.0.1", "192.168.1.50"],
            },
        )
        story = self.builder.build(group)
        assert "10.0.0.1" in story.source_ips
        assert "192.168.1.50" in story.source_ips

    def test_tactics_and_techniques_mapped(self):
        group = _make_group(
            tactics=["Execution", "Credential Access"],
            techniques=["T1059.001", "T1003"],
        )
        story = self.builder.build(group)
        assert story.tactics == ["Execution", "Credential Access"]
        assert story.techniques == ["T1059.001", "T1003"]


# ---------------------------------------------------------------------------
# StoryBuilder — Edge Cases
# ---------------------------------------------------------------------------

class TestStoryBuilderEdgeCases:

    def setup_method(self):
        self.builder = StoryBuilder()

    def test_empty_entities(self):
        group = _make_group(
            entities={"hostnames": [], "usernames": [], "ips": []},
        )
        story = self.builder.build(group)
        assert story.affected_hosts == []
        assert story.affected_users == []
        assert "bilinmeyen host" in story.executive_summary

    def test_minimal_group(self):
        group = CorrelationGroup()
        story = self.builder.build(group)
        assert story.title == "Security Correlation Alert"
        assert story.correlation_group_id == group.id
        assert story.risk_score == 0

    def test_timeline_matches_event_ids(self):
        group = _make_group(event_ids=["e-1", "e-2", "e-3"])
        story = self.builder.build(group)
        assert len(story.timeline) == 3
        assert story.timeline[0]["order"] == 1
        assert story.timeline[0]["event_id"] == "e-1"
        assert story.timeline[2]["order"] == 3
        assert story.timeline[2]["event_id"] == "e-3"

    def test_attributes_include_metadata(self):
        group = _make_group(
            title="Credential Dumping Chain",
            event_ids=["e-1", "e-2"],
            alert_ids=["a-1"],
        )
        story = self.builder.build(group)
        assert story.attributes["correlation_rule_title"] == "Credential Dumping Chain"
        assert story.attributes["event_count"] == 2
        assert story.attributes["alert_count"] == 1

    def test_action_target_is_first_host(self):
        group = _make_group(
            title="Credential Dumping Chain",
            entities={
                "hostnames": ["TARGET-HOST", "OTHER"],
                "usernames": [],
                "ips": [],
            },
        )
        story = self.builder.build(group)
        for action in story.recommended_actions:
            assert action.target == "TARGET-HOST"

    def test_correlation_group_id_preserved(self):
        group = _make_group()
        story = self.builder.build(group)
        assert story.correlation_group_id == group.id

    def test_tenant_id_preserved(self):
        group = _make_group(tenant_id="tenant-xyz")
        story = self.builder.build(group)
        assert story.tenant_id == "tenant-xyz"

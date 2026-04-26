"""
tests.test_event_normalizer
============================
NormalizedSecurityEvent modeli ve EventNormalizer servisi için unit testler.
DB erişimi yok — tamamen in-memory.
"""

import pytest
from pydantic import ValidationError

from app.models.normalized_event import (
    EVENT_TYPES,
    SEVERITY_LEVELS,
    NormalizedSecurityEvent,
)
from app.services.event_normalizer import EventNormalizer


# ---------------------------------------------------------------------------
# NormalizedSecurityEvent Model Testleri
# ---------------------------------------------------------------------------

class TestNormalizedSecurityEventModel:

    def test_valid_event_creation(self):
        event = NormalizedSecurityEvent(
            tenant_id="t-123",
            event_type="process_execution",
            hostname="WORKSTATION-01",
            username="admin",
            process_name="cmd.exe",
            command_line="cmd.exe /c whoami",
            risk_score=75,
            severity="HIGH",
            mitre_tactic="Execution",
            mitre_technique="T1059.003",
            source="raw_event",
        )
        assert event.event_type == "process_execution"
        assert event.hostname == "WORKSTATION-01"
        assert event.risk_score == 75
        assert event.severity == "HIGH"
        assert event.id  # UUID auto-generated
        assert event.timestamp  # timestamp auto-generated

    def test_minimal_event_creation(self):
        event = NormalizedSecurityEvent(event_type="alert_created")
        assert event.event_type == "alert_created"
        assert event.risk_score == 0
        assert event.severity == "INFO"
        assert event.attributes == {}
        assert event.id
        assert event.timestamp

    def test_id_auto_generated_unique(self):
        e1 = NormalizedSecurityEvent(event_type="alert_created")
        e2 = NormalizedSecurityEvent(event_type="alert_created")
        assert e1.id != e2.id

    def test_timestamp_auto_generated(self):
        event = NormalizedSecurityEvent(event_type="alert_created")
        assert "T" in event.timestamp
        assert "+" in event.timestamp or "Z" in event.timestamp

    def test_invalid_event_type_rejected(self):
        with pytest.raises(ValidationError, match="event_type"):
            NormalizedSecurityEvent(event_type="unknown_type")

    def test_risk_score_too_high(self):
        with pytest.raises(ValidationError, match="risk_score"):
            NormalizedSecurityEvent(event_type="alert_created", risk_score=150)

    def test_risk_score_negative(self):
        with pytest.raises(ValidationError, match="risk_score"):
            NormalizedSecurityEvent(event_type="alert_created", risk_score=-1)

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError, match="severity"):
            NormalizedSecurityEvent(event_type="alert_created", severity="UNKNOWN")

    def test_severity_case_insensitive(self):
        event = NormalizedSecurityEvent(event_type="alert_created", severity="high")
        assert event.severity == "HIGH"

    def test_event_type_case_insensitive(self):
        event = NormalizedSecurityEvent(event_type="PROCESS_EXECUTION")
        assert event.event_type == "process_execution"

    def test_to_dict_returns_complete_data(self):
        event = NormalizedSecurityEvent(
            event_type="sigma_match",
            hostname="SRV-01",
            risk_score=80,
        )
        d = event.to_dict()
        assert isinstance(d, dict)
        assert d["event_type"] == "sigma_match"
        assert d["hostname"] == "SRV-01"
        assert d["risk_score"] == 80
        assert "id" in d
        assert "timestamp" in d

    def test_attributes_default_empty_dict(self):
        e1 = NormalizedSecurityEvent(event_type="alert_created")
        e2 = NormalizedSecurityEvent(event_type="alert_created")
        assert e1.attributes == {}
        assert e2.attributes == {}
        e1.attributes["key"] = "value"
        assert "key" not in e2.attributes  # mutable default yok

    def test_all_event_types_valid(self):
        for et in EVENT_TYPES:
            event = NormalizedSecurityEvent(event_type=et)
            assert event.event_type == et

    def test_all_severity_levels_valid(self):
        for sev in SEVERITY_LEVELS:
            event = NormalizedSecurityEvent(event_type="alert_created", severity=sev)
            assert event.severity == sev


# ---------------------------------------------------------------------------
# EventNormalizer Testleri
# ---------------------------------------------------------------------------

class TestEventNormalizerDispatch:

    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_unknown_source_type_raises_error(self):
        with pytest.raises(ValueError, match="Bilinmeyen source_type"):
            self.normalizer.normalize("invalid_source", {})

    def test_dispatch_raw_event(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
            "user": "admin",
            "command_line": "cmd.exe /c dir",
        })
        assert result.source == "raw_event"
        assert result.event_type == "process_execution"

    def test_dispatch_sigma_match(self):
        result = self.normalizer.normalize("sigma_match", {
            "rule": "Test Rule",
            "hostname": "WS-01",
            "severity": "HIGH",
        })
        assert result.source == "sigma_engine"
        assert result.event_type == "sigma_match"

    def test_dispatch_alert(self):
        result = self.normalizer.normalize("alert", {
            "id": "alert-123",
            "hostname": "SRV-01",
            "risk_score": 85,
        })
        assert result.source == "alert_service"
        assert result.event_type == "alert_created"

    def test_dispatch_response_result(self):
        result = self.normalizer.normalize("response_result", {
            "command_id": "cmd-456",
            "action": "isolate",
            "target_hostname": "WS-02",
        })
        assert result.source == "response_action"
        assert result.event_type == "response_result"


class TestTenantIdNormalization:

    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_tenant_id_none_becomes_default(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
        }, tenant_id=None)
        assert result.tenant_id == "default_tenant"

    def test_tenant_id_empty_becomes_default(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
        }, tenant_id="")
        assert result.tenant_id == "default_tenant"

    def test_tenant_id_whitespace_becomes_default(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
        }, tenant_id="   ")
        assert result.tenant_id == "default_tenant"

    def test_tenant_id_preserved_when_valid(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
        }, tenant_id="tenant-abc")
        assert result.tenant_id == "tenant-abc"


class TestRawEventNormalization:

    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_process_start_event(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WORKSTATION-01",
            "user": "admin",
            "command_line": "C:\\Windows\\System32\\cmd.exe /c whoami",
            "pid": 1234,
            "severity": "INFO",
        }, tenant_id="t-1")
        assert result.event_type == "process_execution"
        assert result.hostname == "WORKSTATION-01"
        assert result.username == "admin"
        assert result.process_name == "cmd.exe"
        assert result.attributes.get("pid") == 1234

    def test_logon_event_becomes_user_login(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "LOGON",
            "hostname": "DC-01",
            "user": "admin",
            "details": "Logon from 192.168.1.100",
        }, tenant_id="t-1")
        assert result.event_type == "user_login"
        assert result.source_ip == "192.168.1.100"
        assert result.mitre_tactic == "Initial Access"

    def test_network_connection_event(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "NETWORK_CONNECTION",
            "hostname": "WS-01",
            "details": "Connection from 10.0.0.1 to 192.168.1.50",
        }, tenant_id="t-1")
        assert result.event_type == "network_connection"
        assert result.source_ip == "10.0.0.1"
        assert result.destination_ip == "192.168.1.50"

    def test_unknown_raw_type_fallback(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "CUSTOM_EVENT",
            "hostname": "WS-01",
        }, tenant_id="t-1")
        assert result.event_type == "process_execution"

    def test_details_preserved_in_attributes(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
            "details": "Important detail info",
            "command_line": "cmd.exe",
        }, tenant_id="t-1")
        assert result.attributes.get("details") == "Important detail info"

    def test_serial_preserved_in_attributes(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
            "serial": "USB-SER-123",
            "command_line": "cmd.exe",
        }, tenant_id="t-1")
        assert result.attributes.get("serial") == "USB-SER-123"


class TestAlertNormalization:

    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_alert_maps_all_fields(self):
        result = self.normalizer.normalize("alert", {
            "id": "alert-abc-123",
            "hostname": "SRV-PROD",
            "username": "svc_account",
            "type": "PROCESS_START",
            "risk_score": 85,
            "rule": "Credential Dumping Detected",
            "severity": "CRITICAL",
            "details": "sekurlsa::logonpasswords",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            "pid": 5678,
            "status": "open",
            "created_at": "2026-01-01T00:00:00+00:00",
        }, tenant_id="t-prod")
        assert result.event_type == "alert_created"
        assert result.raw_ref_id == "alert-abc-123"
        assert result.hostname == "SRV-PROD"
        assert result.username == "svc_account"
        assert result.risk_score == 90  # CRITICAL severity → min 90 (calibrated from 85)
        assert result.process_name == "mimikatz.exe"
        assert result.source == "alert_service"
        assert result.attributes["rule"] == "Credential Dumping Detected"
        assert result.attributes["status"] == "open"
        assert result.timestamp == "2026-01-01T00:00:00+00:00"

    def test_alert_raw_ref_id_is_alert_id(self):
        result = self.normalizer.normalize("alert", {
            "id": "unique-alert-id",
            "hostname": "WS-01",
        })
        assert result.raw_ref_id == "unique-alert-id"


class TestSigmaMatchNormalization:

    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_sigma_with_mitre_data(self):
        result = self.normalizer.normalize("sigma_match", {
            "rule": "Mimikatz Usage",
            "hostname": "DC-01",
            "user": "attacker",
            "command_line": "mimikatz.exe",
            "severity": "CRITICAL",
            "risk": {"score": 95},
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1003",
        }, tenant_id="t-1")
        assert result.event_type == "sigma_match"
        assert result.mitre_tactic == "Credential Access"
        assert result.mitre_technique == "T1003"
        assert result.risk_score == 95
        assert result.severity == "CRITICAL"
        assert result.attributes["rule"] == "Mimikatz Usage"

    def test_sigma_without_mitre_infers(self):
        result = self.normalizer.normalize("sigma_match", {
            "rule": "PowerShell Suspicious",
            "command_line": "powershell -ep bypass",
            "hostname": "WS-01",
        }, tenant_id="t-1")
        assert result.mitre_tactic == "Execution"
        assert result.mitre_technique == "T1059.001"

    def test_sigma_raw_ref_id_uses_rule(self):
        result = self.normalizer.normalize("sigma_match", {
            "rule": "My Rule",
            "hostname": "WS-01",
        }, tenant_id="t-1")
        assert result.raw_ref_id == "My Rule"


class TestResponseResultNormalization:

    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_successful_response(self):
        result = self.normalizer.normalize("response_result", {
            "command_id": "cmd-001",
            "action": "isolate",
            "target_hostname": "WS-INFECTED",
            "status": "completed",
            "success": True,
            "message": "Host isolated",
            "requested_by": "analyst1",
        }, tenant_id="t-1")
        assert result.event_type == "response_result"
        assert result.hostname == "WS-INFECTED"
        assert result.raw_ref_id == "cmd-001"
        assert result.risk_score == 0
        assert result.severity == "INFO"
        assert result.attributes["action"] == "isolate"
        assert result.attributes["success"] is True

    def test_failed_response(self):
        result = self.normalizer.normalize("response_result", {
            "command_id": "cmd-002",
            "action": "unisolate",
            "target_hostname": "WS-02",
            "success": False,
            "message": "Agent offline",
        }, tenant_id="t-1")
        assert result.risk_score == 30
        assert result.severity == "MEDIUM"
        assert result.attributes["success"] is False


class TestHelperFunctions:

    def test_extract_process_name_full_path(self):
        name = EventNormalizer._extract_process_name(
            "C:\\Windows\\System32\\cmd.exe /c whoami"
        )
        assert name == "cmd.exe"

    def test_extract_process_name_quoted_path(self):
        name = EventNormalizer._extract_process_name(
            '"C:\\Program Files\\app.exe" --flag'
        )
        assert name == "app.exe"

    def test_extract_process_name_simple(self):
        name = EventNormalizer._extract_process_name("powershell -ep bypass")
        assert name == "powershell"

    def test_extract_process_name_empty(self):
        assert EventNormalizer._extract_process_name("") is None
        assert EventNormalizer._extract_process_name("   ") is None

    def test_infer_event_type_known(self):
        assert EventNormalizer._infer_event_type("PROCESS_START") == "process_execution"
        assert EventNormalizer._infer_event_type("LOGON") == "user_login"
        assert EventNormalizer._infer_event_type("NETWORK_CONNECTION") == "network_connection"

    def test_infer_event_type_unknown_fallback(self):
        assert EventNormalizer._infer_event_type("CUSTOM") == "process_execution"
        assert EventNormalizer._infer_event_type("") == "process_execution"

    def test_infer_severity_high_risk(self):
        assert EventNormalizer._infer_severity("INFO", 95) == "CRITICAL"
        assert EventNormalizer._infer_severity("INFO", 75) == "HIGH"
        assert EventNormalizer._infer_severity("INFO", 55) == "MEDIUM"

    def test_infer_severity_keeps_higher_raw(self):
        assert EventNormalizer._infer_severity("CRITICAL", 10) == "CRITICAL"

    def test_infer_mitre_powershell(self):
        mitre = EventNormalizer._infer_mitre("powershell -ep bypass", "")
        assert mitre["tactic"] == "Execution"
        assert mitre["technique"] == "T1059.001"

    def test_infer_mitre_no_match(self):
        mitre = EventNormalizer._infer_mitre("notepad.exe", "opened file")
        assert mitre["tactic"] is None
        assert mitre["technique"] is None


class TestEdgeCases:

    def setup_method(self):
        self.normalizer = EventNormalizer()

    def test_none_values_handled(self):
        result = self.normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": None,
            "user": None,
            "command_line": None,
            "details": None,
        })
        assert result.hostname is None
        assert result.username is None
        assert result.command_line is None

    def test_empty_dict_handled(self):
        result = self.normalizer.normalize("raw_event", {})
        assert result.event_type == "process_execution"
        assert result.tenant_id == "default_tenant"

    def test_risk_score_clamped_in_normalizer(self):
        result = self.normalizer.normalize("alert", {
            "hostname": "WS-01",
            "risk_score": 999,
        })
        assert result.risk_score == 100

    def test_ip_extraction_from_details(self):
        ip = EventNormalizer._extract_ip_from_text("Login from 10.0.0.5 detected")
        assert ip == "10.0.0.5"

    def test_ip_extraction_none(self):
        ip = EventNormalizer._extract_ip_from_text("No IP here")
        assert ip is None

    def test_multiple_ip_extraction(self):
        ips = EventNormalizer._extract_all_ips_from_text("src=10.0.0.1 dst=192.168.1.1")
        assert len(ips) == 2
        assert ips[0] == "10.0.0.1"
        assert ips[1] == "192.168.1.1"


# ---------------------------------------------------------------------------
# Risk Score Calibration Testleri
# ---------------------------------------------------------------------------

class TestRiskScoreCalibration:

    def test_critical_severity_min_90(self):
        result = EventNormalizer._calibrate_risk_score(0, "CRITICAL")
        assert result == 90

    def test_high_severity_min_75(self):
        result = EventNormalizer._calibrate_risk_score(0, "HIGH")
        assert result == 75

    def test_medium_severity_min_50(self):
        result = EventNormalizer._calibrate_risk_score(10, "MEDIUM")
        assert result == 50

    def test_low_severity_min_25(self):
        result = EventNormalizer._calibrate_risk_score(5, "LOW")
        assert result == 25

    def test_info_no_raise(self):
        result = EventNormalizer._calibrate_risk_score(15, "INFO")
        assert result == 15

    def test_already_high_risk_unchanged(self):
        result = EventNormalizer._calibrate_risk_score(80, "HIGH")
        assert result == 80

    def test_risk_clamped_at_100(self):
        result = EventNormalizer._calibrate_risk_score(150, "CRITICAL")
        assert result == 100

    def test_case_insensitive(self):
        result = EventNormalizer._calibrate_risk_score(0, "high")
        assert result == 75

    def test_raw_event_high_severity_zero_risk_calibrated(self):
        normalizer = EventNormalizer()
        result = normalizer.normalize("raw_event", {
            "type": "PROCESS_START",
            "hostname": "WS-01",
            "command_line": "suspicious.exe",
            "severity": "HIGH",
            "risk_score": 0,
        }, tenant_id="t-1")
        assert result.risk_score >= 75
        assert result.severity == "HIGH"

    def test_alert_critical_severity_low_risk_calibrated(self):
        normalizer = EventNormalizer()
        result = normalizer.normalize("alert", {
            "id": "alert-cal-1",
            "hostname": "SRV-01",
            "command_line": "evil.exe",
            "severity": "CRITICAL",
            "risk_score": 10,
        }, tenant_id="t-1")
        assert result.risk_score >= 90
        assert result.severity == "CRITICAL"

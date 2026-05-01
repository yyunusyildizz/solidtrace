"""
tests.test_story_graph_builder
=================================
StoryGraph modelleri ve StoryGraphBuilder servisi için unit testler.
DB erişimi yok — tamamen in-memory.
"""

import pytest
from pydantic import ValidationError

from app.services.attack_story.models import AttackStory, RecommendedAction
from app.services.story_graph.models import (
    EDGE_TYPES,
    NODE_TYPES,
    GraphEdge,
    GraphNode,
    StoryGraph,
)
from app.services.story_graph.builder import StoryGraphBuilder


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _make_credential_story() -> AttackStory:
    """Credential dumping senaryosu için zengin AttackStory."""
    return AttackStory(
        title="Possible Credential Dumping Activity",
        severity="CRITICAL",
        confidence="high",
        risk_score=95,
        tenant_id="test-tenant",
        correlation_group_id="grp-cred-001",
        affected_hosts=["DC-01", "WS-05"],
        affected_users=["admin", "svc_backup"],
        source_ips=["10.0.0.50"],
        destination_ips=["192.168.1.1"],
        tactics=["Credential Access"],
        techniques=["T1003", "T1003.001"],
        key_findings=[
            "Mimikatz activity detected",
            "LSASS memory access observed",
        ],
        recommended_actions=[
            RecommendedAction(
                action_type="isolate_host",
                title="Host'u İzole Et",
                description="Etkilenen host'u ağdan izole et",
                priority="immediate",
                target="DC-01",
            ),
            RecommendedAction(
                action_type="reset_credentials",
                title="Kimlik Bilgilerini Sıfırla",
                description="Parolaları sıfırla",
                priority="high",
                target="DC-01",
            ),
            RecommendedAction(
                action_type="collect_artifacts",
                title="Artifact Topla",
                description="Memory dump topla",
                priority="high",
                target=None,
            ),
        ],
        analyst_questions=[
            "Lateral movement var mı?",
            "Admin hesabı compromise olmuş mu?",
        ],
    )


def _make_powershell_story() -> AttackStory:
    """PowerShell chain senaryosu için AttackStory."""
    return AttackStory(
        title="Suspicious PowerShell Execution Chain",
        severity="HIGH",
        confidence="high",
        risk_score=85,
        tenant_id="test-tenant",
        affected_hosts=["WS-01"],
        affected_users=["admin"],
        source_ips=["10.0.0.1"],
        tactics=["Execution", "Defense Evasion"],
        techniques=["T1059.001", "T1562.001"],
        recommended_actions=[
            RecommendedAction(
                action_type="isolate_host",
                title="Host'u İzole Et",
                priority="immediate",
                target="WS-01",
            ),
            RecommendedAction(
                action_type="review_process_tree",
                title="Süreç Ağacını İncele",
                priority="immediate",
                target="WS-01",
            ),
            RecommendedAction(
                action_type="monitor_host",
                title="Host'u İzle",
                priority="medium",
                target="WS-01",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# 1. Minimal AttackStory graph üretir
# ---------------------------------------------------------------------------

class TestMinimalStoryGraph:

    def setup_method(self):
        self.builder = StoryGraphBuilder()

    def test_minimal_story_produces_graph(self):
        """Default AttackStory() → graph üretir, en az 1 story node var."""
        story = AttackStory()
        graph = self.builder.build(story)

        assert isinstance(graph, StoryGraph)
        assert graph.story_id == story.id
        assert len(graph.nodes) >= 1

        # Root story node var mı?
        story_nodes = [n for n in graph.nodes if n.node_type == "story"]
        assert len(story_nodes) == 1

    def test_minimal_story_graph_id_unique(self):
        """Her graph benzersiz ID'ye sahip."""
        story = AttackStory()
        g1 = self.builder.build(story)
        g2 = self.builder.build(story)
        assert g1.id != g2.id

    def test_minimal_story_severity_and_risk(self):
        """Graph severity ve risk_score story'den alınır."""
        story = AttackStory(severity="HIGH", risk_score=70)
        graph = self.builder.build(story)
        assert graph.severity == "HIGH"
        assert graph.risk_score == 70


# ---------------------------------------------------------------------------
# 2. Credential story host/user/tactic/action node üretir
# ---------------------------------------------------------------------------

class TestCredentialStoryNodes:

    def setup_method(self):
        self.builder = StoryGraphBuilder()
        self.story = _make_credential_story()
        self.graph = self.builder.build(self.story)

    def test_host_nodes_created(self):
        host_nodes = [n for n in self.graph.nodes if n.node_type == "host"]
        labels = {n.label for n in host_nodes}
        assert "DC-01" in labels
        assert "WS-05" in labels

    def test_user_nodes_created(self):
        user_nodes = [n for n in self.graph.nodes if n.node_type == "user"]
        labels = {n.label for n in user_nodes}
        assert "admin" in labels
        assert "svc_backup" in labels

    def test_tactic_nodes_created(self):
        tactic_nodes = [n for n in self.graph.nodes if n.node_type == "tactic"]
        labels = {n.label for n in tactic_nodes}
        assert "Credential Access" in labels

    def test_technique_nodes_created(self):
        technique_nodes = [n for n in self.graph.nodes if n.node_type == "technique"]
        labels = {n.label for n in technique_nodes}
        assert "T1003" in labels
        assert "T1003.001" in labels

    def test_action_nodes_created(self):
        action_nodes = [n for n in self.graph.nodes if n.node_type == "action"]
        labels = {n.label for n in action_nodes}
        assert "Host'u İzole Et" in labels
        assert "Kimlik Bilgilerini Sıfırla" in labels
        assert "Artifact Topla" in labels

    def test_ip_nodes_created(self):
        src_nodes = [n for n in self.graph.nodes if n.node_type == "source_ip"]
        dst_nodes = [n for n in self.graph.nodes if n.node_type == "destination_ip"]
        assert any(n.label == "10.0.0.50" for n in src_nodes)
        assert any(n.label == "192.168.1.1" for n in dst_nodes)

    def test_tenant_id_preserved(self):
        assert self.graph.tenant_id == "test-tenant"


# ---------------------------------------------------------------------------
# 3. PowerShell story technique ve action node üretir
# ---------------------------------------------------------------------------

class TestPowerShellStoryNodes:

    def setup_method(self):
        self.builder = StoryGraphBuilder()
        self.story = _make_powershell_story()
        self.graph = self.builder.build(self.story)

    def test_technique_nodes(self):
        technique_nodes = [n for n in self.graph.nodes if n.node_type == "technique"]
        labels = {n.label for n in technique_nodes}
        assert "T1059.001" in labels
        assert "T1562.001" in labels

    def test_action_nodes(self):
        action_nodes = [n for n in self.graph.nodes if n.node_type == "action"]
        labels = {n.label for n in action_nodes}
        assert "Host'u İzole Et" in labels
        assert "Süreç Ağacını İncele" in labels
        assert "Host'u İzle" in labels

    def test_multiple_tactics(self):
        tactic_nodes = [n for n in self.graph.nodes if n.node_type == "tactic"]
        labels = {n.label for n in tactic_nodes}
        assert "Execution" in labels
        assert "Defense Evasion" in labels


# ---------------------------------------------------------------------------
# 4. Duplicate host/action node üretmez
# ---------------------------------------------------------------------------

class TestNoDuplicateNodes:

    def setup_method(self):
        self.builder = StoryGraphBuilder()

    def test_no_duplicate_host_nodes(self):
        """Aynı hostname tekrar ederse tek host node üretilmeli."""
        story = AttackStory(
            title="Dup Host Test",
            severity="HIGH",
            risk_score=60,
            affected_hosts=["HOST-A", "HOST-A", "HOST-B", "HOST-A"],
        )
        graph = self.builder.build(story)
        host_nodes = [n for n in graph.nodes if n.node_type == "host"]
        labels = [n.label for n in host_nodes]
        assert labels.count("HOST-A") == 1
        assert labels.count("HOST-B") == 1

    def test_no_duplicate_action_nodes(self):
        """Aynı action_type farklı RecommendedAction'larda olsa da tek action node."""
        story = AttackStory(
            title="Dup Action Test",
            severity="HIGH",
            risk_score=60,
            affected_hosts=["WS-01"],
            recommended_actions=[
                RecommendedAction(
                    action_type="isolate_host",
                    title="Host'u İzole Et",
                    priority="immediate",
                    target="WS-01",
                ),
                RecommendedAction(
                    action_type="isolate_host",
                    title="Host'u İzole Et",
                    priority="high",
                    target="WS-01",
                ),
            ],
        )
        graph = self.builder.build(story)
        action_nodes = [n for n in graph.nodes if n.node_type == "action"]
        labels = [n.label for n in action_nodes]
        assert labels.count("Host'u İzole Et") == 1


# ---------------------------------------------------------------------------
# 5. Boş entity listeleri crash etmez
# ---------------------------------------------------------------------------

class TestEmptyEntities:

    def setup_method(self):
        self.builder = StoryGraphBuilder()

    def test_all_empty_no_crash(self):
        """Tüm entity listeleri boş → crash olmaz, sadece story node."""
        story = AttackStory(
            title="Empty Test",
            severity="INFO",
            risk_score=0,
            affected_hosts=[],
            affected_users=[],
            source_ips=[],
            destination_ips=[],
            tactics=[],
            techniques=[],
            recommended_actions=[],
        )
        graph = self.builder.build(story)
        assert len(graph.nodes) == 1  # Sadece root story node
        assert len(graph.edges) == 0
        assert graph.nodes[0].node_type == "story"

    def test_default_story_no_crash(self):
        """AttackStory() default → crash olmaz."""
        story = AttackStory()
        graph = self.builder.build(story)
        assert isinstance(graph, StoryGraph)
        assert len(graph.nodes) >= 1

    def test_empty_string_entities_skipped(self):
        """Boş string entity'ler atlanır."""
        story = AttackStory(
            title="Empty Strings",
            severity="LOW",
            affected_hosts=["", "HOST-A", ""],
            affected_users=["", "admin"],
            source_ips=["", "10.0.0.1"],
        )
        graph = self.builder.build(story)
        host_nodes = [n for n in graph.nodes if n.node_type == "host"]
        user_nodes = [n for n in graph.nodes if n.node_type == "user"]
        ip_nodes = [n for n in graph.nodes if n.node_type == "source_ip"]
        assert len(host_nodes) == 1
        assert host_nodes[0].label == "HOST-A"
        assert len(user_nodes) == 1
        assert len(ip_nodes) == 1


# ---------------------------------------------------------------------------
# 6. Edge tipleri doğru oluşur
# ---------------------------------------------------------------------------

class TestEdgeTypes:

    def setup_method(self):
        self.builder = StoryGraphBuilder()
        self.story = _make_credential_story()
        self.graph = self.builder.build(self.story)

    def _edge_types_for(self, source_type: str, target_type: str) -> set:
        """source_type node'dan target_type node'a giden edge tiplerini döndürür."""
        source_ids = {n.id for n in self.graph.nodes if n.node_type == source_type}
        target_ids = {n.id for n in self.graph.nodes if n.node_type == target_type}
        return {
            e.edge_type
            for e in self.graph.edges
            if e.source in source_ids and e.target in target_ids
        }

    def test_story_to_host_affects(self):
        assert "affects" in self._edge_types_for("story", "host")

    def test_story_to_user_affects(self):
        assert "affects" in self._edge_types_for("story", "user")

    def test_story_to_tactic_maps_to(self):
        assert "maps_to" in self._edge_types_for("story", "tactic")

    def test_story_to_technique_maps_to(self):
        assert "maps_to" in self._edge_types_for("story", "technique")

    def test_story_to_action_recommends(self):
        assert "recommends" in self._edge_types_for("story", "action")

    def test_story_to_source_ip_communicates(self):
        assert "communicates_with" in self._edge_types_for("story", "source_ip")

    def test_story_to_dest_ip_communicates(self):
        assert "communicates_with" in self._edge_types_for("story", "destination_ip")

    def test_host_to_user_related_to(self):
        assert "related_to" in self._edge_types_for("host", "user")

    def test_tactic_to_technique_maps_to(self):
        assert "maps_to" in self._edge_types_for("tactic", "technique")

    def test_host_to_action_recommends(self):
        """Action target bir host ise host → action recommends edge var."""
        assert "recommends" in self._edge_types_for("host", "action")


# ---------------------------------------------------------------------------
# 7. Summary doğru hesaplanır
# ---------------------------------------------------------------------------

class TestSummaryCorrect:

    def setup_method(self):
        self.builder = StoryGraphBuilder()

    def test_credential_story_summary(self):
        story = _make_credential_story()
        graph = self.builder.build(story)
        s = graph.summary

        assert s["node_count"] == len(graph.nodes)
        assert s["edge_count"] == len(graph.edges)
        assert s["host_count"] == 2   # DC-01, WS-05
        assert s["user_count"] == 2   # admin, svc_backup
        assert s["action_count"] == 3  # isolate, reset, collect

    def test_empty_story_summary(self):
        story = AttackStory()
        graph = self.builder.build(story)
        s = graph.summary

        assert s["node_count"] == 1  # Sadece story node
        assert s["edge_count"] == 0
        assert s["host_count"] == 0
        assert s["user_count"] == 0
        assert s["action_count"] == 0

    def test_summary_node_count_matches_nodes(self):
        story = _make_powershell_story()
        graph = self.builder.build(story)
        assert graph.summary["node_count"] == len(graph.nodes)
        assert graph.summary["edge_count"] == len(graph.edges)


# ---------------------------------------------------------------------------
# 8. to_dict / model serialization çalışır
# ---------------------------------------------------------------------------

class TestSerialization:

    def setup_method(self):
        self.builder = StoryGraphBuilder()

    def test_to_dict_returns_complete_data(self):
        story = _make_credential_story()
        graph = self.builder.build(story)
        d = graph.to_dict()

        assert isinstance(d, dict)
        assert d["story_id"] == story.id
        assert d["title"] == "Possible Credential Dumping Activity"
        assert d["severity"] == "CRITICAL"
        assert d["risk_score"] == 95
        assert "nodes" in d
        assert "edges" in d
        assert "summary" in d
        assert "id" in d
        assert "created_at" in d

    def test_to_dict_nodes_are_dicts(self):
        story = _make_credential_story()
        graph = self.builder.build(story)
        d = graph.to_dict()

        assert isinstance(d["nodes"], list)
        assert len(d["nodes"]) > 0
        for node in d["nodes"]:
            assert isinstance(node, dict)
            assert "id" in node
            assert "node_type" in node
            assert "label" in node

    def test_to_dict_edges_are_dicts(self):
        story = _make_credential_story()
        graph = self.builder.build(story)
        d = graph.to_dict()

        assert isinstance(d["edges"], list)
        assert len(d["edges"]) > 0
        for edge in d["edges"]:
            assert isinstance(edge, dict)
            assert "source" in edge
            assert "target" in edge
            assert "edge_type" in edge

    def test_graph_node_model_validation(self):
        """Geçersiz node_type rejected."""
        with pytest.raises(ValidationError, match="node_type"):
            GraphNode(node_type="invalid_type", label="test")

    def test_graph_edge_model_validation(self):
        """Geçersiz edge_type rejected."""
        with pytest.raises(ValidationError, match="edge_type"):
            GraphEdge(source="a", target="b", edge_type="invalid_edge")

    def test_story_graph_severity_validation(self):
        """Geçersiz severity rejected."""
        with pytest.raises(ValidationError, match="severity"):
            StoryGraph(severity="UNKNOWN")


# ---------------------------------------------------------------------------
# 9. Mevcut testlerin bozulmadığını doğrulayan regresyon testi
#    (bu test sınıfı sadece import'ların çalıştığını kontrol eder)
# ---------------------------------------------------------------------------

class TestPackageImports:

    def test_import_from_package(self):
        """Package import çalışır."""
        from app.services.story_graph import (
            GraphEdge,
            GraphNode,
            StoryGraph,
            StoryGraphBuilder,
        )
        assert StoryGraphBuilder is not None
        assert GraphNode is not None
        assert GraphEdge is not None
        assert StoryGraph is not None

    def test_attack_story_import_unchanged(self):
        """attack_story package hâlâ import edilebilir."""
        from app.services.attack_story import (
            AttackStory,
            RecommendedAction,
            StoryBuilder,
        )
        assert AttackStory is not None
        assert RecommendedAction is not None
        assert StoryBuilder is not None

    def test_story_pipeline_import_unchanged(self):
        """story_pipeline package hâlâ import edilebilir."""
        from app.services.story_pipeline import (
            StoryPipeline,
            StoryPipelineResult,
        )
        assert StoryPipeline is not None
        assert StoryPipelineResult is not None

    def test_node_types_constant(self):
        assert "story" in NODE_TYPES
        assert "host" in NODE_TYPES
        assert "action" in NODE_TYPES
        assert len(NODE_TYPES) == 8

    def test_edge_types_constant(self):
        assert "affects" in EDGE_TYPES
        assert "recommends" in EDGE_TYPES
        assert "maps_to" in EDGE_TYPES
        assert len(EDGE_TYPES) == 6


# ---------------------------------------------------------------------------
# 10. MITRE Tactic → Technique mapping doğru çalışır
# ---------------------------------------------------------------------------

class TestMitreTacticTechniqueMapping:
    """MITRE mapping ile doğru tactic → technique edge üretimini test eder."""

    def setup_method(self):
        self.builder = StoryGraphBuilder()

    def _build_mixed_story(self):
        """Execution + Defense Evasion tactics, T1059.001 + T1562.001 techniques."""
        return AttackStory(
            title="Mixed Tactic Story",
            severity="HIGH",
            risk_score=80,
            tactics=["Execution", "Defense Evasion"],
            techniques=["T1059.001", "T1562.001"],
        )

    def _get_edges_between(self, graph, source_label: str, target_label: str):
        """source_label → target_label arasındaki tüm edge'leri döndürür."""
        node_map = {n.label: n.id for n in graph.nodes}
        src_id = node_map.get(source_label)
        tgt_id = node_map.get(target_label)
        if not src_id or not tgt_id:
            return []
        return [e for e in graph.edges if e.source == src_id and e.target == tgt_id]

    # -- Doğru mapping testleri --

    def test_correct_mapping_execution_t1059(self):
        """Execution → T1059.001 edge olmalı."""
        graph = self.builder.build(self._build_mixed_story())
        edges = self._get_edges_between(graph, "Execution", "T1059.001")
        assert len(edges) == 1
        assert edges[0].edge_type == "maps_to"

    def test_correct_mapping_defense_evasion_t1562(self):
        """Defense Evasion → T1562.001 edge olmalı."""
        graph = self.builder.build(self._build_mixed_story())
        edges = self._get_edges_between(graph, "Defense Evasion", "T1562.001")
        assert len(edges) == 1
        assert edges[0].edge_type == "maps_to"

    # -- Çapraz mapping olmamalı --

    def test_no_cross_mapping_execution_t1562(self):
        """Execution → T1562.001 edge OLMAMALI."""
        graph = self.builder.build(self._build_mixed_story())
        edges = self._get_edges_between(graph, "Execution", "T1562.001")
        assert len(edges) == 0

    def test_no_cross_mapping_defense_evasion_t1059(self):
        """Defense Evasion → T1059.001 edge OLMAMALI."""
        graph = self.builder.build(self._build_mixed_story())
        edges = self._get_edges_between(graph, "Defense Evasion", "T1059.001")
        assert len(edges) == 0

    # -- Credential Access mapping --

    def test_credential_access_t1003_mapping(self):
        """Credential Access → T1003.001 edge olmalı."""
        story = AttackStory(
            title="Cred Test",
            severity="HIGH",
            risk_score=90,
            tactics=["Credential Access", "Execution"],
            techniques=["T1003.001", "T1059.003"],
        )
        graph = self.builder.build(story)

        # Doğru bağlantılar
        assert len(self._get_edges_between(graph, "Credential Access", "T1003.001")) == 1
        assert len(self._get_edges_between(graph, "Execution", "T1059.003")) == 1

        # Çapraz bağlantılar olmamalı
        assert len(self._get_edges_between(graph, "Execution", "T1003.001")) == 0
        assert len(self._get_edges_between(graph, "Credential Access", "T1059.003")) == 0

    # -- Bilinmeyen technique fallback --

    def test_unknown_technique_fallback(self):
        """Bilinmeyen technique → tüm tactic'lerle bağlanır (fallback)."""
        story = AttackStory(
            title="Unknown Tech",
            severity="HIGH",
            risk_score=50,
            tactics=["Execution", "Discovery"],
            techniques=["T9999.001"],
        )
        graph = self.builder.build(story)

        # Bilinmeyen technique: her iki tactic'le de bağlı olmalı (fallback)
        assert len(self._get_edges_between(graph, "Execution", "T9999.001")) == 1
        assert len(self._get_edges_between(graph, "Discovery", "T9999.001")) == 1

    # -- story → tactic/technique edge'leri korunuyor --

    def test_story_to_tactic_edges_preserved(self):
        """story → tactic maps_to edge'leri korunuyor."""
        graph = self.builder.build(self._build_mixed_story())
        story_node = [n for n in graph.nodes if n.node_type == "story"][0]
        tactic_ids = {n.id for n in graph.nodes if n.node_type == "tactic"}
        story_to_tactic = [
            e for e in graph.edges
            if e.source == story_node.id and e.target in tactic_ids and e.edge_type == "maps_to"
        ]
        assert len(story_to_tactic) == 2  # Execution, Defense Evasion

    def test_story_to_technique_edges_preserved(self):
        """story → technique maps_to edge'leri korunuyor."""
        graph = self.builder.build(self._build_mixed_story())
        story_node = [n for n in graph.nodes if n.node_type == "story"][0]
        technique_ids = {n.id for n in graph.nodes if n.node_type == "technique"}
        story_to_technique = [
            e for e in graph.edges
            if e.source == story_node.id and e.target in technique_ids and e.edge_type == "maps_to"
        ]
        assert len(story_to_technique) == 2  # T1059.001, T1562.001

    # -- Duplicate edge kontrolü --

    def test_no_duplicate_edges(self):
        """Duplicate edge oluşmuyor."""
        graph = self.builder.build(self._build_mixed_story())
        edge_keys = [f"{e.source}:{e.target}:{e.edge_type}" for e in graph.edges]
        assert len(edge_keys) == len(set(edge_keys))

    # -- Multi-tactic technique --

    def test_multi_tactic_technique_t1078(self):
        """T1078 birden fazla tactic'e ait — story'de bulunan tactic'lerle edge var."""
        story = AttackStory(
            title="Multi Tactic",
            severity="HIGH",
            risk_score=70,
            tactics=["Defense Evasion", "Persistence", "Execution"],
            techniques=["T1078"],
        )
        graph = self.builder.build(story)

        # T1078 → Defense Evasion ve Persistence ile bağlı olmalı
        assert len(self._get_edges_between(graph, "Defense Evasion", "T1078")) == 1
        assert len(self._get_edges_between(graph, "Persistence", "T1078")) == 1

        # T1078 mapping'de Execution yok → edge olmamalı
        assert len(self._get_edges_between(graph, "Execution", "T1078")) == 0


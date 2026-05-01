"""
app.services.story_graph.builder
====================================
StoryGraphBuilder — AttackStory'den StoryGraph üretir.

Her AttackStory için bir investigation graph oluşturur:
  - Root story node
  - Entity node'ları (host, user, IP, tactic, technique, action)
  - Typed edge'ler (affects, maps_to, communicates_with, recommends, related_to)

Duplicate node/edge üretmez. Boş alanlarda crash olmaz.
Standalone — DB persistence yok, runtime entegrasyonu yok.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from app.services.attack_story.models import AttackStory

from .models import GraphEdge, GraphNode, StoryGraph

logger = logging.getLogger("SolidTrace.StoryGraphBuilder")


# ---------------------------------------------------------------------------
# MITRE ATT&CK — Technique Prefix → Tactic(ler) Mapping
# ---------------------------------------------------------------------------
# Technique ID'nin prefix'i (nokta öncesi kısım) → Ait olduğu tactic(ler).
# Kaynak: MITRE ATT&CK Enterprise Matrix (subset).
# Bilinmeyen technique'ler için fallback uygulanır.
# ---------------------------------------------------------------------------

TECHNIQUE_TACTIC_MAP: Dict[str, List[str]] = {
    "T1003": ["Credential Access"],
    "T1110": ["Credential Access"],
    "T1552": ["Credential Access"],
    "T1059": ["Execution"],
    "T1047": ["Execution"],
    "T1053": ["Execution", "Persistence"],
    "T1021": ["Lateral Movement"],
    "T1105": ["Command and Control"],
    "T1078": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1562": ["Defense Evasion"],
    "T1027": ["Defense Evasion"],
    "T1070": ["Defense Evasion"],
    "T1547": ["Persistence", "Privilege Escalation"],
    "T1548": ["Privilege Escalation", "Defense Evasion"],
    "T1071": ["Command and Control"],
    "T1082": ["Discovery"],
    "T1083": ["Discovery"],
    "T1057": ["Discovery"],
    "T1041": ["Exfiltration"],
    "T1486": ["Impact"],
}


class StoryGraphBuilder:
    """
    AttackStory'den StoryGraph üretir.

    Kullanım:
        builder = StoryGraphBuilder()
        graph = builder.build(story)
    """

    def build(self, story: AttackStory) -> StoryGraph:
        """
        AttackStory'den StoryGraph üretir.

        Args:
            story: AttackStory instance

        Returns:
            StoryGraph instance
        """
        self._node_registry: Dict[str, GraphNode] = {}
        self._edge_registry: Dict[str, GraphEdge] = {}

        # 1. Root story node
        root = self._get_or_create_node(
            node_type="story",
            label=story.title or f"Story {story.id}",
            severity=story.severity,
            risk_score=story.risk_score,
            attributes={
                "story_id": story.id,
                "correlation_group_id": story.correlation_group_id,
                "confidence": story.confidence,
            },
        )

        # 2. Host node'ları
        host_nodes: List[GraphNode] = []
        for hostname in story.affected_hosts:
            if not hostname:
                continue
            node = self._get_or_create_node(
                node_type="host",
                label=hostname,
            )
            host_nodes.append(node)
            self._get_or_create_edge(
                source=root.id,
                target=node.id,
                edge_type="affects",
                label=f"affects {hostname}",
            )

        # 3. User node'ları
        user_nodes: List[GraphNode] = []
        for username in story.affected_users:
            if not username:
                continue
            node = self._get_or_create_node(
                node_type="user",
                label=username,
            )
            user_nodes.append(node)
            self._get_or_create_edge(
                source=root.id,
                target=node.id,
                edge_type="affects",
                label=f"affects {username}",
            )

        # 3b. Host ↔ User ilişkisi
        for host_node in host_nodes:
            for user_node in user_nodes:
                self._get_or_create_edge(
                    source=host_node.id,
                    target=user_node.id,
                    edge_type="related_to",
                    label=f"{host_node.label} — {user_node.label}",
                )

        # 4. Source IP node'ları
        for ip in story.source_ips:
            if not ip:
                continue
            node = self._get_or_create_node(
                node_type="source_ip",
                label=ip,
            )
            self._get_or_create_edge(
                source=root.id,
                target=node.id,
                edge_type="communicates_with",
                label=f"source {ip}",
            )

        # 5. Destination IP node'ları
        for ip in story.destination_ips:
            if not ip:
                continue
            node = self._get_or_create_node(
                node_type="destination_ip",
                label=ip,
            )
            self._get_or_create_edge(
                source=root.id,
                target=node.id,
                edge_type="communicates_with",
                label=f"destination {ip}",
            )

        # 6. Tactic node'ları
        tactic_nodes: List[GraphNode] = []
        for tactic in story.tactics:
            if not tactic:
                continue
            node = self._get_or_create_node(
                node_type="tactic",
                label=tactic,
            )
            tactic_nodes.append(node)
            self._get_or_create_edge(
                source=root.id,
                target=node.id,
                edge_type="maps_to",
                label=f"maps to {tactic}",
            )

        # 7. Technique node'ları
        for technique in story.techniques:
            if not technique:
                continue
            node = self._get_or_create_node(
                node_type="technique",
                label=technique,
            )
            self._get_or_create_edge(
                source=root.id,
                target=node.id,
                edge_type="maps_to",
                label=f"maps to {technique}",
            )

            # Tactic → Technique ilişkisi (MITRE mapping ile)
            mapped_tactics = self._resolve_tactics_for_technique(technique)

            if mapped_tactics:
                # Mapping bilinen: sadece ilgili tactic node'larla bağla
                for tactic_node in tactic_nodes:
                    if tactic_node.label in mapped_tactics:
                        self._get_or_create_edge(
                            source=tactic_node.id,
                            target=node.id,
                            edge_type="maps_to",
                            label=f"{tactic_node.label} → {technique}",
                        )
            else:
                # Mapping bilinmeyen: fallback — tüm tactic'lerle bağla
                for tactic_node in tactic_nodes:
                    self._get_or_create_edge(
                        source=tactic_node.id,
                        target=node.id,
                        edge_type="maps_to",
                        label=f"{tactic_node.label} → {technique}",
                    )

        # 8. Recommended Action node'ları
        for action in story.recommended_actions:
            action_label = action.title or action.action_type
            node = self._get_or_create_node(
                node_type="action",
                label=action_label,
                attributes={
                    "action_type": action.action_type,
                    "priority": action.priority,
                    "description": action.description,
                    "target": action.target,
                },
            )

            # Story → Action edge
            self._get_or_create_edge(
                source=root.id,
                target=node.id,
                edge_type="recommends",
                label=f"recommends {action_label}",
            )

            # Host → Action edge (eğer action.target bir host ise)
            if action.target:
                target_host_node = self._find_host_node(action.target)
                if target_host_node:
                    self._get_or_create_edge(
                        source=target_host_node.id,
                        target=node.id,
                        edge_type="recommends",
                        label=f"{action.target} → {action_label}",
                    )

        # Sonuç graph'ı oluştur
        nodes = list(self._node_registry.values())
        edges = list(self._edge_registry.values())

        summary = self._build_summary(nodes, edges)

        graph = StoryGraph(
            story_id=story.id,
            tenant_id=story.tenant_id,
            title=story.title or f"Graph for Story {story.id}",
            severity=story.severity,
            risk_score=story.risk_score,
            nodes=nodes,
            edges=edges,
            summary=summary,
        )

        logger.info(
            "story_graph_built story_id=%s nodes=%d edges=%d",
            story.id, len(nodes), len(edges),
        )

        return graph

    # -- Node registry -------------------------------------------------------

    def _get_or_create_node(
        self,
        node_type: str,
        label: str,
        severity: str = "INFO",
        risk_score: int = 0,
        attributes: Optional[Dict] = None,
    ) -> GraphNode:
        """
        Registry'den mevcut node döndürür veya yeni node oluşturur.
        Key: '{node_type}:{label}'
        """
        key = f"{node_type}:{label}"

        if key in self._node_registry:
            return self._node_registry[key]

        node = GraphNode(
            node_type=node_type,
            label=label,
            severity=severity,
            risk_score=risk_score,
            attributes=attributes or {},
        )

        self._node_registry[key] = node
        return node

    # -- Edge registry -------------------------------------------------------

    def _get_or_create_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        label: str = "",
        attributes: Optional[Dict] = None,
    ) -> GraphEdge:
        """
        Registry'den mevcut edge döndürür veya yeni edge oluşturur.
        Key: '{source}:{target}:{edge_type}'
        """
        key = f"{source}:{target}:{edge_type}"

        if key in self._edge_registry:
            return self._edge_registry[key]

        edge = GraphEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            label=label,
            attributes=attributes or {},
        )

        self._edge_registry[key] = edge
        return edge

    # -- Helpers -------------------------------------------------------------

    def _find_host_node(self, hostname: str) -> Optional[GraphNode]:
        """Registry'den host node arar."""
        key = f"host:{hostname}"
        return self._node_registry.get(key)

    @staticmethod
    def _resolve_tactics_for_technique(technique: str) -> List[str]:
        """
        Technique ID'den ait olduğu tactic isimlerini döndürür.

        Sub-technique (T1003.001) ise prefix'i (T1003) kullanır.
        Bilinmiyorsa boş liste döner → fallback davranışı tetiklenir.
        """
        prefix = technique.split(".")[0]
        return TECHNIQUE_TACTIC_MAP.get(prefix, [])

    @staticmethod
    def _build_summary(nodes: List[GraphNode], edges: List[GraphEdge]) -> Dict:
        """Node ve edge listelerinden özet istatistikler hesaplar."""
        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "host_count": sum(1 for n in nodes if n.node_type == "host"),
            "user_count": sum(1 for n in nodes if n.node_type == "user"),
            "action_count": sum(1 for n in nodes if n.node_type == "action"),
        }

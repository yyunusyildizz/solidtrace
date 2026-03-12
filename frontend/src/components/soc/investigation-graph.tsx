"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Cpu,
  Server,
  Shield,
  User,
} from "lucide-react";

type NodeType = "host" | "user" | "process" | "rule" | "alert";

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  risk?: number;
  meta?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  label?: string;
}

export interface InvestigationGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

function nodeStyle(type: NodeType) {
  switch (type) {
    case "host":
      return {
        border: "border-sky-200 dark:border-sky-500/20",
        bg: "bg-sky-50 dark:bg-sky-500/10",
        text: "text-sky-700 dark:text-sky-300",
        icon: <Server size={15} />,
      };
    case "user":
      return {
        border: "border-violet-200 dark:border-violet-500/20",
        bg: "bg-violet-50 dark:bg-violet-500/10",
        text: "text-violet-700 dark:text-violet-300",
        icon: <User size={15} />,
      };
    case "process":
      return {
        border: "border-amber-200 dark:border-amber-500/20",
        bg: "bg-amber-50 dark:bg-amber-500/10",
        text: "text-amber-700 dark:text-amber-300",
        icon: <Cpu size={15} />,
      };
    case "rule":
      return {
        border: "border-red-200 dark:border-red-500/20",
        bg: "bg-red-50 dark:bg-red-500/10",
        text: "text-red-700 dark:text-red-300",
        icon: <Shield size={15} />,
      };
    default:
      return {
        border: "border-zinc-200 dark:border-white/10",
        bg: "bg-zinc-50 dark:bg-white/[0.04]",
        text: "text-zinc-700 dark:text-zinc-300",
        icon: <AlertTriangle size={15} />,
      };
  }
}

function riskBarClass(risk?: number) {
  const n = Number(risk || 0);
  if (n >= 80) return "bg-red-500";
  if (n >= 60) return "bg-orange-500";
  if (n >= 40) return "bg-amber-500";
  return "bg-emerald-500";
}

export default function InvestigationGraph({
  data,
}: {
  data: InvestigationGraphData;
}) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(
    data.nodes[0]?.id || null,
  );

  const selectedNode = useMemo(
    () => data.nodes.find((n) => n.id === selectedNodeId) || null,
    [data.nodes, selectedNodeId],
  );

  const relatedEdges = useMemo(
    () =>
      data.edges.filter(
        (e) => e.from === selectedNodeId || e.to === selectedNodeId,
      ),
    [data.edges, selectedNodeId],
  );

  const relatedNodeIds = useMemo(() => {
    const ids = new Set<string>();
    for (const edge of relatedEdges) {
      ids.add(edge.from);
      ids.add(edge.to);
    }
    return ids;
  }, [relatedEdges]);

  return (
    <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
      <section className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/[0.03]">
        <div className="mb-4">
          <div className="text-sm font-black">Investigation Graph</div>
          <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
            Host, user, process, rule ve alert ilişkileri
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data.nodes.map((node) => {
            const style = nodeStyle(node.type);
            const active = selectedNodeId === node.id;
            const related = relatedNodeIds.has(node.id);

            return (
              <button
                key={node.id}
                onClick={() => setSelectedNodeId(node.id)}
                className={`rounded-2xl border p-4 text-left transition ${
                  active
                    ? "border-zinc-900 bg-zinc-50 dark:border-white dark:bg-white/[0.06]"
                    : related
                      ? "border-zinc-300 bg-zinc-50/70 dark:border-white/20 dark:bg-white/[0.04]"
                      : "border-zinc-200 bg-white hover:bg-zinc-50 dark:border-white/10 dark:bg-white/[0.03] dark:hover:bg-white/[0.05]"
                }`}
              >
                <div
                  className={`inline-flex items-center gap-2 rounded-xl border px-2.5 py-1.5 text-xs font-semibold ${style.border} ${style.bg} ${style.text}`}
                >
                  {style.icon}
                  <span className="uppercase tracking-wide">{node.type}</span>
                </div>

                <div className="mt-3 text-sm font-semibold">{node.label}</div>

                {node.meta ? (
                  <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                    {node.meta}
                  </div>
                ) : null}

                {typeof node.risk === "number" ? (
                  <div className="mt-3">
                    <div className="mb-1 text-xs text-zinc-500 dark:text-zinc-400">
                      Risk: {node.risk}
                    </div>
                    <div className="h-2 rounded-full bg-zinc-200 dark:bg-white/10">
                      <div
                        className={`h-2 rounded-full ${riskBarClass(node.risk)}`}
                        style={{ width: `${Math.min(100, node.risk)}%` }}
                      />
                    </div>
                  </div>
                ) : null}
              </button>
            );
          })}
        </div>
      </section>

      <section className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/[0.03]">
        <div className="mb-4">
          <div className="text-sm font-black">Node Detail</div>
          <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
            Seçilen düğümün ilişkileri
          </div>
        </div>

        {!selectedNode ? (
          <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-6 text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
            Node seçilmedi.
          </div>
        ) : (
          <div className="space-y-4">
            <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
              <div className="text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                Selected
              </div>
              <div className="mt-2 text-sm font-semibold">{selectedNode.label}</div>
              <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                {selectedNode.type}
                {selectedNode.meta ? ` · ${selectedNode.meta}` : ""}
              </div>
            </div>

            <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
              <div className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                Relationships
              </div>

              {relatedEdges.length === 0 ? (
                <div className="text-sm text-zinc-500 dark:text-zinc-400">
                  İlişki bulunamadı.
                </div>
              ) : (
                <div className="space-y-3">
                  {relatedEdges.map((edge, idx) => (
                    <div
                      key={`${edge.from}-${edge.to}-${idx}`}
                      className="rounded-xl border border-zinc-200 p-3 dark:border-white/10"
                    >
                      <div className="text-sm font-medium">
                        {edge.from} → {edge.to}
                      </div>
                      <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                        {edge.label || "linked"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
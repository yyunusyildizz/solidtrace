"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Network,
  Server,
  Shield,
  User,
  Waypoints,
} from "lucide-react";

export type GraphNodeType = "alert" | "host" | "user" | "process" | "rule";

export interface InvestigationGraphNode {
  id: string;
  label?: string;
  type: GraphNodeType;
  risk?: number;
  meta?: string;
}

export interface InvestigationGraphEdge {
  from: string;
  to: string;
  label?: string;
}

export interface InvestigationGraphData {
  nodes: InvestigationGraphNode[];
  edges: InvestigationGraphEdge[];
}

function nodeTone(type: GraphNodeType) {
  switch (type) {
    case "alert":
      return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300";
    case "host":
      return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-300";
    case "user":
      return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-300";
    case "process":
      return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300";
    case "rule":
      return "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-500/20 dark:bg-violet-500/10 dark:text-violet-300";
    default:
      return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300";
  }
}

function nodeIcon(type: GraphNodeType) {
  switch (type) {
    case "alert":
      return <AlertTriangle size={14} />;
    case "host":
      return <Server size={14} />;
    case "user":
      return <User size={14} />;
    case "rule":
      return <Shield size={14} />;
    default:
      return <Waypoints size={14} />;
  }
}

function riskTone(risk?: number) {
  const value = risk ?? 0;
  if (value >= 80) return "text-red-500";
  if (value >= 60) return "text-orange-500";
  if (value >= 40) return "text-amber-500";
  return "text-emerald-500";
}

function riskBar(risk?: number) {
  const value = Math.max(0, Math.min(100, risk ?? 0));
  if (value >= 80) return { width: `${value}%`, className: "bg-red-500" };
  if (value >= 60) return { width: `${value}%`, className: "bg-orange-500" };
  if (value >= 40) return { width: `${value}%`, className: "bg-amber-500" };
  return { width: `${value}%`, className: "bg-emerald-500" };
}

function displayNodeLabel(node: InvestigationGraphNode) {
  return node.label || `${node.type}:${node.id}`;
}

function MiniStat({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div
      className="rounded-2xl border p-3"
      style={{
        borderColor: "var(--border)",
        background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
      }}
    >
      <div
        className="text-[11px] font-bold uppercase tracking-[0.18em]"
        style={{ color: "var(--muted)" }}
      >
        {label}
      </div>
      <div className="mt-2 text-lg font-black">{value}</div>
    </div>
  );
}

export default function InvestigationGraph({ data }: { data: InvestigationGraphData }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    setSelectedId(data.nodes[0]?.id ?? null);
  }, [data]);

  const selectedNode = useMemo(
    () => data.nodes.find((node) => node.id === selectedId) ?? null,
    [data.nodes, selectedId],
  );

  const relatedEdges = useMemo(() => {
    if (!selectedNode) return [];
    return data.edges.filter(
      (edge) => edge.from === selectedNode.id || edge.to === selectedNode.id,
    );
  }, [data.edges, selectedNode]);

  const stats = useMemo(() => {
    return {
      nodes: data.nodes.length,
      edges: data.edges.length,
      highRisk: data.nodes.filter((node) => (node.risk ?? 0) >= 70).length,
    };
  }, [data]);

  if (!data.nodes.length) {
    return (
      <div
        className="rounded-2xl border p-8 text-center text-sm"
        style={{
          borderColor: "var(--border)",
          background: "var(--surface-1)",
          color: "var(--muted)",
        }}
      >
        Graph verisi bulunamadı.
      </div>
    );
  }

  return (
    <section
      className="rounded-3xl border p-4"
      style={{
        borderColor: "var(--border)",
        background: "var(--panel-strong)",
        boxShadow: "var(--shadow-soft)",
      }}
    >
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-black tracking-tight">
            <Network size={16} />
            Investigation Graph
          </div>
          <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
            Entity relationships derived from the selected investigation alert.
          </div>
        </div>

        <div
          className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-bold uppercase tracking-[0.18em]"
          style={{
            borderColor: "var(--border)",
            background: "var(--surface-1)",
            color: "var(--muted-strong)",
          }}
        >
          <Waypoints size={12} />
          Live Context
        </div>
      </div>

      <div className="mb-4 grid gap-3 md:grid-cols-3">
        <MiniStat label="Nodes" value={stats.nodes} />
        <MiniStat label="Edges" value={stats.edges} />
        <MiniStat label="High Risk" value={stats.highRisk} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[0.92fr_1.08fr]">
        <div
          className="rounded-3xl border p-4"
          style={{
            borderColor: "var(--border)",
            background: "color-mix(in srgb, var(--surface-1) 86%, transparent)",
          }}
        >
          <div
            className="mb-3 text-[11px] font-bold uppercase tracking-[0.2em]"
            style={{ color: "var(--muted)" }}
          >
            Entity List
          </div>

          <div className="space-y-3">
            {data.nodes.map((node) => {
              const active = selectedId === node.id;
              const bar = riskBar(node.risk);

              return (
                <button
                  key={node.id}
                  onClick={() => setSelectedId(node.id)}
                  className="w-full rounded-2xl border p-4 text-left transition"
                  style={
                    active
                      ? {
                          borderColor: "var(--foreground)",
                          background: "color-mix(in srgb, var(--surface-1) 92%, transparent)",
                        }
                      : {
                          borderColor: "var(--border)",
                          background: "var(--surface-0)",
                        }
                  }
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${nodeTone(node.type)}`}
                        >
                          {nodeIcon(node.type)}
                          {node.type}
                        </span>
                      </div>

                      <div className="mt-3 truncate text-sm font-semibold">
                        {displayNodeLabel(node)}
                      </div>
                      <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                        {node.meta || "No metadata"}
                      </div>
                    </div>

                    <div className={`text-sm font-black ${riskTone(node.risk)}`}>
                      {node.risk ?? 0}
                    </div>
                  </div>

                  <div
                    className="mt-3 h-2 rounded-full"
                    style={{ background: "var(--surface-2)" }}
                  >
                    <div
                      className={`h-2 rounded-full ${bar.className}`}
                      style={{ width: bar.width }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div
          className="rounded-3xl border p-4"
          style={{
            borderColor: "var(--border)",
            background: "color-mix(in srgb, var(--surface-1) 86%, transparent)",
          }}
        >
          <div
            className="mb-3 text-[11px] font-bold uppercase tracking-[0.2em]"
            style={{ color: "var(--muted)" }}
          >
            Selected Entity
          </div>

          {selectedNode ? (
            <div className="space-y-4">
              <section
                className="rounded-2xl border p-4"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                }}
              >
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span
                    className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${nodeTone(selectedNode.type)}`}
                  >
                    {nodeIcon(selectedNode.type)}
                    {selectedNode.type}
                  </span>
                </div>

                <div className="text-lg font-black">
                  {displayNodeLabel(selectedNode)}
                </div>
                <div className="mt-2 text-sm" style={{ color: "var(--muted-strong)" }}>
                  {selectedNode.meta || "No metadata available."}
                </div>

                <div className="mt-4">
                  <div
                    className="mb-2 text-xs font-bold uppercase tracking-[0.18em]"
                    style={{ color: "var(--muted)" }}
                  >
                    Risk Score
                  </div>
                  <div className="flex items-center gap-3">
                    <div className={`text-2xl font-black ${riskTone(selectedNode.risk)}`}>
                      {selectedNode.risk ?? 0}
                    </div>
                    <div
                      className="h-2 flex-1 rounded-full"
                      style={{ background: "var(--surface-2)" }}
                    >
                      <div
                        className={`h-2 rounded-full ${riskBar(selectedNode.risk).className}`}
                        style={{ width: riskBar(selectedNode.risk).width }}
                      />
                    </div>
                  </div>
                </div>
              </section>

              <section
                className="rounded-2xl border p-4"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                }}
              >
                <div
                  className="mb-3 text-xs font-bold uppercase tracking-[0.18em]"
                  style={{ color: "var(--muted)" }}
                >
                  Related Edges
                </div>

                {relatedEdges.length === 0 ? (
                  <div className="text-sm" style={{ color: "var(--muted)" }}>
                    No direct relationships found for this entity.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {relatedEdges.map((edge, index) => (
                      <div
                        key={`${edge.from}-${edge.to}-${index}`}
                        className="rounded-xl border px-3 py-3 text-sm"
                        style={{
                          borderColor: "var(--border)",
                          background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
                        }}
                      >
                        <div className="font-medium">
                          {edge.from} → {edge.to}
                        </div>
                        <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                          {edge.label || "Unlabelled relationship"}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
          ) : (
            <div
              className="rounded-2xl border p-6 text-sm"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted)",
              }}
            >
              Node seçilmedi.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Network,
  Server,
  Shield,
  User,
  Waypoints,
  Crosshair,
  Link2,
  Sparkles,
} from "lucide-react";

export type GraphNodeType =
  | "alert"
  | "host"
  | "user"
  | "process"
  | "rule"
  | "incident";

export interface InvestigationGraphNode {
  id: string;
  label?: string;
  type: GraphNodeType | string;
  risk?: number;
  meta?: string;
  tactic?: string | null;
  technique_id?: string | null;
  technique_name?: string | null;
  role?: string | null;
  score?: number;
  highlighted?: boolean;
}

export interface InvestigationGraphEdge {
  from: string;
  to: string;
  label?: string;
  weight?: number;
  highlighted?: boolean;
}

export interface InvestigationGraphData {
  nodes: InvestigationGraphNode[];
  edges: InvestigationGraphEdge[];
}

function nodeTone(type: string) {
  switch (type) {
    case "incident":
      return "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700 dark:border-fuchsia-500/20 dark:bg-fuchsia-500/10 dark:text-fuchsia-300";
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

function nodeIcon(type: string) {
  switch (type) {
    case "incident":
      return <Sparkles size={14} />;
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
    const highlighted = data.nodes.find((node) => node.highlighted);
    setSelectedId(highlighted?.id ?? data.nodes[0]?.id ?? null);
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
    const highlighted = data.nodes.filter((node) => node.highlighted).length;
    const mitre = data.nodes.filter((node) => node.technique_id).length;
    return {
      nodes: data.nodes.length,
      edges: data.edges.length,
      highRisk: data.nodes.filter((node) => (node.risk ?? 0) >= 70).length,
      highlighted,
      mitre,
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
            Incident graph with risk, MITRE context and highlighted pivot nodes.
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

      <div className="mb-4 grid gap-3 md:grid-cols-5">
        <MiniStat label="Nodes" value={stats.nodes} />
        <MiniStat label="Edges" value={stats.edges} />
        <MiniStat label="High Risk" value={stats.highRisk} />
        <MiniStat label="Highlighted" value={stats.highlighted} />
        <MiniStat label="MITRE Tagged" value={stats.mitre} />
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
                      : node.highlighted
                        ? {
                            borderColor: "color-mix(in srgb, var(--foreground) 40%, var(--border))",
                            background: "color-mix(in srgb, var(--surface-1) 90%, transparent)",
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
                        {node.highlighted ? (
                          <span
                            className="inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                            style={{
                              borderColor: "var(--border)",
                              background: "var(--surface-1)",
                              color: "var(--muted-strong)",
                            }}
                          >
                            <Crosshair size={11} />
                            highlighted
                          </span>
                        ) : null}
                      </div>

                      <div className="mt-3 truncate text-sm font-semibold">
                        {displayNodeLabel(node)}
                      </div>
                      <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                        {node.meta || "No metadata"}
                      </div>

                      {(node.tactic || node.technique_id || node.role) ? (
                        <div className="mt-2 flex flex-wrap gap-2">
                          {node.tactic ? (
                            <span
                              className="inline-flex rounded-full border px-2 py-1 text-[10px]"
                              style={{
                                borderColor: "var(--border)",
                                background: "var(--surface-1)",
                                color: "var(--muted-strong)",
                              }}
                            >
                              {node.tactic}
                            </span>
                          ) : null}
                          {node.technique_id ? (
                            <span
                              className="inline-flex rounded-full border px-2 py-1 text-[10px]"
                              style={{
                                borderColor: "var(--border)",
                                background: "var(--surface-1)",
                                color: "var(--muted-strong)",
                              }}
                            >
                              {node.technique_id}
                            </span>
                          ) : null}
                          {node.role ? (
                            <span
                              className="inline-flex rounded-full border px-2 py-1 text-[10px]"
                              style={{
                                borderColor: "var(--border)",
                                background: "var(--surface-1)",
                                color: "var(--muted-strong)",
                              }}
                            >
                              {node.role}
                            </span>
                          ) : null}
                        </div>
                      ) : null}
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
                  {selectedNode.highlighted ? (
                    <span
                      className="inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-1)",
                        color: "var(--muted-strong)",
                      }}
                    >
                      <Crosshair size={11} />
                      highlighted
                    </span>
                  ) : null}
                </div>

                <div className="text-lg font-black">
                  {displayNodeLabel(selectedNode)}
                </div>
                <div className="mt-2 text-sm" style={{ color: "var(--muted-strong)" }}>
                  {selectedNode.meta || "No metadata available."}
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  <MiniStat label="Risk" value={selectedNode.risk ?? 0} />
                  <MiniStat label="Score" value={selectedNode.score ?? 0} />
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

                {(selectedNode.tactic || selectedNode.technique_id || selectedNode.technique_name || selectedNode.role) ? (
                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <MiniStat label="Tactic" value={selectedNode.tactic || "—"} />
                    <MiniStat label="Technique" value={selectedNode.technique_id || "—"} />
                    <MiniStat label="Technique Name" value={selectedNode.technique_name || "—"} />
                    <MiniStat label="Role" value={selectedNode.role || "—"} />
                  </div>
                ) : null}
              </section>

              <section
                className="rounded-2xl border p-4"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                }}
              >
                <div
                  className="mb-3 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em]"
                  style={{ color: "var(--muted)" }}
                >
                  <Link2 size={12} />
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
                          borderColor: edge.highlighted
                            ? "color-mix(in srgb, var(--foreground) 35%, var(--border))"
                            : "var(--border)",
                          background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
                        }}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="font-medium break-all">
                            {edge.from} → {edge.to}
                          </div>
                          {typeof edge.weight === "number" ? (
                            <span
                              className="inline-flex rounded-full border px-2 py-1 text-[10px]"
                              style={{
                                borderColor: "var(--border)",
                                background: "var(--surface-1)",
                                color: "var(--muted-strong)",
                              }}
                            >
                              weight: {edge.weight.toFixed(2)}
                            </span>
                          ) : null}
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

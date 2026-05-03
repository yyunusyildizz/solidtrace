"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Briefcase,
  CheckCircle2,
  Clock3,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserPlus,
  Workflow,
  XCircle,
  Usb,
  PowerOff,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { HostResponseActions } from "@/components/soc/host-response-actions";
import { HostLastResponseActions } from "@/components/soc/host-last-response-actions";
import {
  acknowledgeAlert,
  assignAlert,
  getAlertDetail,
  getAlerts,
  reopenAlert,
  resolveAlert,
  unassignAlert,
  updateAlertNote,
  type AlertItem,
} from "@/lib/api/alerts";
import { disableUsb, enableUsb, isolateHost, unisolateHost } from "@/lib/api/actions";
import { previewStory, previewStoryGraph, type StoryPreviewResponse, type StoryGraphPreviewResponse, type StoryGraphItem, type AttackStoryItem } from "@/lib/api/story";
import { previewCaseDraft, type CasePreviewResponse, type CaseDraftItem } from "@/lib/api/case-preview";
import { clearAuthSession, getToken } from "@/lib/auth";

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "WARNING" | "INFO";
type StatusFilter = "ALL" | "open" | "acknowledged" | "resolved";
type QuickBusy = "isolate" | "unisolate" | "usb_disable" | "usb_enable" | null;

function severityTone(severity?: string | null) {
  const value = (severity || "INFO").toUpperCase();

  if (value === "CRITICAL") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  }
  if (value === "HIGH") {
    return "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-500/20 dark:bg-orange-500/10 dark:text-orange-400";
  }
  if (value === "WARNING") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-400";
}

function statusTone(status?: string | null) {
  const value = (status || "open").toLowerCase();

  if (value === "resolved") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
  }
  if (value === "acknowledged") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
}

function fmtDate(value?: string | null) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("tr-TR");
  } catch {
    return value;
  }
}

function relativeTime(value?: string | null) {
  if (!value) return "—";
  try {
    const diff = Date.now() - new Date(value).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "az önce";
    if (mins < 60) return `${mins}dk önce`;
    if (mins < 1440) return `${Math.floor(mins / 60)}sa önce`;
    return `${Math.floor(mins / 1440)}g önce`;
  } catch {
    return value;
  }
}

function displayTitle(alert: AlertItem) {
  if (alert.rule?.trim()) return alert.rule;
  if (alert.type?.trim() && alert.hostname?.trim()) {
    return `${alert.type} on ${alert.hostname}`;
  }
  if (alert.type?.trim()) return alert.type;
  return `Alert ${alert.id}`;
}

function SummaryCard({
  title,
  value,
  hint,
  icon,
}: {
  title: string;
  value: number;
  hint: string;
  icon: React.ReactNode;
}) {
  return (
    <div
      className="rounded-3xl border p-4"
      style={{
        background: "var(--panel-strong)",
        borderColor: "var(--border)",
        boxShadow: "var(--shadow-soft)",
      }}
    >
      <div className="mb-3 flex items-center justify-between">
        <div
          className="text-[11px] font-bold uppercase tracking-[0.22em]"
          style={{ color: "var(--muted)" }}
        >
          {title}
        </div>
        <div style={{ color: "var(--muted)" }}>{icon}</div>
      </div>
      <div className="text-3xl font-black tracking-tight">{value}</div>
      <div className="mt-2 text-xs" style={{ color: "var(--muted)" }}>
        {hint}
      </div>
    </div>
  );
}

function InfoCard({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div
      className="min-w-0 rounded-2xl border p-4"
      style={{
        borderColor: "var(--border)",
        background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
      }}
    >
      <div
        className="mb-2 text-xs font-bold uppercase tracking-[0.2em]"
        style={{ color: "var(--muted)" }}
      >
        {label}
      </div>
      <div className="break-words text-sm" style={{ color: "var(--foreground)" }}>
        {value}
      </div>
    </div>
  );
}

function QuickHostActions({
  alert,
  disabled,
  onDone,
}: {
  alert: AlertItem;
  disabled?: boolean;
  onDone: () => Promise<void>;
}) {
  const [busy, setBusy] = useState<QuickBusy>(null);
  const [message, setMessage] = useState<string | null>(null);

  if (!alert.hostname) return null;

  async function runQuick(type: QuickBusy) {
    if (!type || !alert.hostname) return;

    try {
      setBusy(type);
      setMessage(null);
      const token = getToken();

      if (type === "isolate") {
        await isolateHost(
          {
            hostname: alert.hostname,
            rule: `quick isolate from alert queue: ${alert.id}`,
          },
          token ?? undefined,
        );
        setMessage("Isolate queued");
      }

      if (type === "unisolate") {
        await unisolateHost(
          {
            hostname: alert.hostname,
            rule: `quick unisolate from alert queue: ${alert.id}`,
          },
          token ?? undefined,
        );
        setMessage("Unisolate queued");
      }

      if (type === "usb_disable") {
        await disableUsb(
          {
            hostname: alert.hostname,
            rule: `quick usb off from alert queue: ${alert.id}`,
          },
          token ?? undefined,
        );
        setMessage("USB Off queued");
      }

      if (type === "usb_enable") {
        await enableUsb(
          {
            hostname: alert.hostname,
            rule: `quick usb on from alert queue: ${alert.id}`,
          },
          token ?? undefined,
        );
        setMessage("USB On queued");
      }

      await onDone();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(null);
    }
  }

  const buttonClass =
    "inline-flex w-full items-center justify-center gap-1.5 rounded-xl border px-2.5 py-2 text-[11px] font-semibold transition disabled:cursor-not-allowed disabled:opacity-60";

  return (
    <div
      className="mt-3 min-w-0 border-t pt-3"
      style={{ borderColor: "var(--border)" }}
    >
      <div
        className="mb-2 text-[11px] font-bold uppercase tracking-[0.18em]"
        style={{ color: "var(--muted)" }}
      >
        Quick Response
      </div>

      <div className="grid min-w-0 grid-cols-2 gap-2 sm:grid-cols-4">
        <button
          disabled={disabled || busy !== null}
          onClick={() => runQuick("isolate")}
          className={buttonClass}
          style={{
            borderColor: "var(--border-strong)",
            background: "var(--surface-1)",
          }}
        >
          {busy === "isolate" ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <ShieldAlert size={14} />
          )}
          Isolate
        </button>

        <button
          disabled={disabled || busy !== null}
          onClick={() => runQuick("unisolate")}
          className={buttonClass}
          style={{
            borderColor: "var(--border-strong)",
            background: "var(--surface-1)",
          }}
        >
          {busy === "unisolate" ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <ShieldCheck size={14} />
          )}
          Unisolate
        </button>

        <button
          disabled={disabled || busy !== null}
          onClick={() => runQuick("usb_disable")}
          className={buttonClass}
          style={{
            borderColor: "var(--border-strong)",
            background: "var(--surface-1)",
          }}
        >
          {busy === "usb_disable" ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <Usb size={14} />
          )}
          USB Off
        </button>

        <button
          disabled={disabled || busy !== null}
          onClick={() => runQuick("usb_enable")}
          className={buttonClass}
          style={{
            borderColor: "var(--border-strong)",
            background: "var(--surface-1)",
          }}
        >
          {busy === "usb_enable" ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <PowerOff size={14} />
          )}
          USB On
        </button>
      </div>

      {message ? (
        <div className="mt-2 break-words text-xs" style={{ color: "var(--muted)" }}>
          {message}
        </div>
      ) : null}
    </div>
  );
}

function InspectorSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section
      className="min-w-0 rounded-2xl border p-4"
      style={{
        borderColor: "var(--border)",
        background: "var(--surface-0)",
      }}
    >
      <div
        className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
        style={{ color: "var(--muted)" }}
      >
        {title}
      </div>
      {children}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Attack Story Preview
// ---------------------------------------------------------------------------

const MAX_STORY_ALERTS = 50;

function AttackStoryPreview({
  selectedAlert,
  allAlerts,
}: {
  selectedAlert: AlertItem;
  allAlerts: AlertItem[];
}) {
  const [storyLoading, setStoryLoading] = useState(false);
  const [storyError, setStoryError] = useState<string | null>(null);
  const [storyResult, setStoryResult] = useState<StoryPreviewResponse | null>(null);

  // Reset when selected alert changes
  useEffect(() => {
    setStoryResult(null);
    setStoryError(null);
  }, [selectedAlert.id]);

  const hostname = selectedAlert.hostname;

  async function handlePreview() {
    if (!hostname) return;

    try {
      setStoryLoading(true);
      setStoryError(null);
      setStoryResult(null);

      const token = getToken();
      const sameHostAlerts = allAlerts
        .filter((a) => a.hostname === hostname)
        .slice(0, MAX_STORY_ALERTS);

      const result = await previewStory(
        { source_type: "alerts", items: sameHostAlerts as unknown as Record<string, unknown>[] },
        token ?? undefined,
      );

      setStoryResult(result);
    } catch (err) {
      setStoryError(err instanceof Error ? err.message : "Story preview failed");
    } finally {
      setStoryLoading(false);
    }
  }

  // -- No hostname → disabled state --
  if (!hostname) {
    return (
      <div
        className="rounded-xl p-4 text-center text-sm"
        style={{ background: "var(--surface-1)", color: "var(--muted)" }}
      >
        No hostname available — unable to generate an attack story.
      </div>
    );
  }

  // -- Button --
  const btnClass =
    "inline-flex w-full items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-60";

  return (
    <div className="min-w-0 space-y-4">
      {/* Generate / Retry button */}
      {!storyResult && (
        <button
          disabled={storyLoading}
          onClick={handlePreview}
          className={btnClass}
          style={{
            background: "var(--foreground)",
            color: "var(--background)",
          }}
        >
          {storyLoading ? (
            <>
              <Loader2 size={14} className="animate-spin" />
              Generating story…
            </>
          ) : (
            <>
              <BookOpen size={14} />
              Preview Attack Story
            </>
          )}
        </button>
      )}

      {/* Error state */}
      {storyError && (
        <div
          className="min-w-0 rounded-xl border border-red-200 p-3 text-sm dark:border-red-500/20"
          style={{ background: "var(--surface-1)" }}
        >
          <div className="break-words text-red-600 dark:text-red-400">{storyError}</div>
          <button
            onClick={handlePreview}
            disabled={storyLoading}
            className="mt-2 inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
            style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
          >
            <RefreshCw size={12} />
            Retry
          </button>
        </div>
      )}

      {/* Success — render stories */}
      {storyResult && (
        <div className="min-w-0 space-y-4">
          {/* Warnings */}
          {storyResult.warnings.length > 0 && (
            <div
              className="min-w-0 rounded-xl border border-amber-200 p-3 text-xs dark:border-amber-500/20"
              style={{
                background: "color-mix(in srgb, var(--surface-1) 90%, transparent)",
              }}
            >
              <div className="mb-1 font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">
                Warnings
              </div>
              <ul className="min-w-0 list-inside list-disc space-y-1">
                {storyResult.warnings.map((w, i) => (
                  <li key={i} className="min-w-0 break-words text-amber-700 dark:text-amber-300">
                    {w}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Empty stories */}
          {storyResult.attack_stories.length === 0 && (
            <div
              className="rounded-xl p-4 text-center text-sm"
              style={{ background: "var(--surface-1)", color: "var(--muted)" }}
            >
              No attack story could be generated for this host&apos;s alerts.
            </div>
          )}

          {/* Story cards */}
          {storyResult.attack_stories.map((story) => (
            <StoryCard key={story.id} story={story} />
          ))}

          {/* Re-generate button */}
          <button
            disabled={storyLoading}
            onClick={handlePreview}
            className={btnClass}
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--surface-1)",
              color: "var(--foreground)",
            }}
          >
            {storyLoading ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                Regenerating…
              </>
            ) : (
              <>
                <RefreshCw size={14} />
                Regenerate Story
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Story Card (single story render)
// ---------------------------------------------------------------------------

function StoryCard({ story }: { story: AttackStoryItem }) {
  return (
    <div
      className="min-w-0 space-y-3 rounded-xl border p-4"
      style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
    >
      {/* Title + severity + risk */}
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span
            className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityTone(story.severity)}`}
          >
            {story.severity}
          </span>
          <span className="text-xs font-medium" style={{ color: "var(--muted-strong)" }}>
            Risk {story.risk_score}/100
          </span>
          <span className="text-xs" style={{ color: "var(--muted)" }}>
            Confidence: {story.confidence}
          </span>
        </div>
        <div className="mt-2 min-w-0 break-words text-sm font-bold">{story.title}</div>
      </div>

      {/* Executive Summary */}
      {story.executive_summary && (
        <div className="min-w-0">
          <div
            className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]"
            style={{ color: "var(--muted)" }}
          >
            Executive Summary
          </div>
          <div
            className="min-w-0 break-words text-sm leading-relaxed"
            style={{ color: "var(--muted-strong)" }}
          >
            {story.executive_summary}
          </div>
        </div>
      )}

      {/* Key Findings */}
      {story.key_findings.length > 0 && (
        <div className="min-w-0">
          <div
            className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]"
            style={{ color: "var(--muted)" }}
          >
            Key Findings
          </div>
          <ul className="min-w-0 list-inside list-disc space-y-1 text-sm" style={{ color: "var(--muted-strong)" }}>
            {story.key_findings.map((finding, i) => (
              <li key={i} className="min-w-0 break-words">
                {finding}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommended Actions */}
      {story.recommended_actions.length > 0 && (
        <div className="min-w-0">
          <div
            className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]"
            style={{ color: "var(--muted)" }}
          >
            Recommended Actions
          </div>
          <div className="min-w-0 space-y-2">
            {story.recommended_actions.map((action, i) => (
              <div
                key={i}
                className="min-w-0 rounded-lg border p-2.5"
                style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
              >
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold" style={{ color: "var(--foreground)" }}>
                    {action.title || action.action_type}
                  </span>
                  <span
                    className="inline-flex rounded-full border px-1.5 py-0.5 text-[9px] font-bold uppercase"
                    style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                  >
                    {action.priority}
                  </span>
                </div>
                {action.description && (
                  <div className="mt-1 min-w-0 break-words text-xs" style={{ color: "var(--muted)" }}>
                    {action.description}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analyst Questions */}
      {story.analyst_questions.length > 0 && (
        <div className="min-w-0">
          <div
            className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]"
            style={{ color: "var(--muted)" }}
          >
            Analyst Questions
          </div>
          <ul className="min-w-0 list-inside list-disc space-y-1 text-sm" style={{ color: "var(--muted-strong)" }}>
            {story.analyst_questions.map((q, i) => (
              <li key={i} className="min-w-0 break-words">
                {q}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Tactics & Techniques tags */}
      {(story.tactics.length > 0 || story.techniques.length > 0) && (
        <div className="flex min-w-0 flex-wrap gap-1.5">
          {story.tactics.map((t) => (
            <span
              key={`tactic-${t}`}
              className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium"
              style={{ borderColor: "var(--border)", color: "var(--muted-strong)" }}
            >
              {t}
            </span>
          ))}
          {story.techniques.map((t) => (
            <span
              key={`technique-${t}`}
              className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium"
              style={{
                borderColor: "var(--border)",
                color: "var(--muted)",
                background: "var(--surface-0)",
              }}
            >
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Story Graph Preview
// ---------------------------------------------------------------------------

const NODE_TYPE_META: Record<string, { emoji: string; title: string }> = {
  story:          { emoji: "📖", title: "Story" },
  host:           { emoji: "🖥️", title: "Hosts" },
  user:           { emoji: "👤", title: "Users" },
  tactic:         { emoji: "🎯", title: "Tactics" },
  technique:      { emoji: "⚙️", title: "Techniques" },
  action:         { emoji: "✅", title: "Recommended Actions" },
  source_ip:      { emoji: "📡", title: "Source IPs" },
  destination_ip: { emoji: "📍", title: "Destination IPs" },
};

const EDGE_DISPLAY_LIMIT = 20;

function GraphCard({ graph }: { graph: StoryGraphItem }) {
  const [showAllEdges, setShowAllEdges] = useState(false);

  // Group nodes by node_type
  const grouped = useMemo(() => {
    const map = new Map<string, { id: string; label: string; severity: string; risk_score: number }[]>();
    for (const node of graph.nodes) {
      const arr = map.get(node.node_type) || [];
      arr.push({ id: node.id, label: node.label, severity: node.severity, risk_score: node.risk_score });
      map.set(node.node_type, arr);
    }
    return map;
  }, [graph.nodes]);

  // Build node id -> label map for edge display
  const nodeLabels = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of graph.nodes) {
      m.set(n.id, n.label || n.node_type);
    }
    return m;
  }, [graph.nodes]);

  const visibleEdges = showAllEdges
    ? graph.edges
    : graph.edges.slice(0, EDGE_DISPLAY_LIMIT);

  const groupOrder = ["story", "host", "user", "tactic", "technique", "action", "source_ip", "destination_ip"];

  return (
    <div
      className="min-w-0 space-y-3 rounded-xl border p-4"
      style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
    >
      {/* Header */}
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span
            className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityTone(graph.severity)}`}
          >
            {graph.severity}
          </span>
          <span className="text-xs font-medium" style={{ color: "var(--muted-strong)" }}>
            Risk {graph.risk_score}/100
          </span>
          <span className="text-xs" style={{ color: "var(--muted)" }}>
            {graph.summary.node_count} nodes · {graph.summary.edge_count} edges
          </span>
        </div>
        <div className="mt-2 min-w-0 break-words text-sm font-bold">{graph.title || "Investigation Graph"}</div>
      </div>

      {/* Node groups */}
      <div className="min-w-0 space-y-2">
        {groupOrder.map((type) => {
          const nodes = grouped.get(type);
          if (!nodes || nodes.length === 0) return null;
          const meta = NODE_TYPE_META[type] || { emoji: "🔹", title: type };

          return (
            <div key={type} className="min-w-0">
              <div
                className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]"
                style={{ color: "var(--muted)" }}
              >
                {meta.emoji} {meta.title}
              </div>
              <div className="flex min-w-0 flex-wrap gap-1.5">
                {nodes.map((node) => (
                  <span
                    key={node.id}
                    className="inline-flex min-w-0 rounded-full border px-2 py-0.5 text-[10px] font-medium"
                    style={{
                      borderColor: "var(--border)",
                      color: "var(--muted-strong)",
                      background: "var(--surface-0)",
                    }}
                    title={`${meta.title}: ${node.label}`}
                  >
                    <span className="min-w-0 truncate max-w-[180px]">{node.label || node.id}</span>
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Edge list */}
      {graph.edges.length > 0 && (
        <div className="min-w-0">
          <div
            className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]"
            style={{ color: "var(--muted)" }}
          >
            Edges ({graph.edges.length})
          </div>
          <div
            className="min-w-0 space-y-1 rounded-lg border p-2"
            style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
          >
            {visibleEdges.map((edge) => (
              <div
                key={edge.id}
                className="flex min-w-0 flex-wrap items-center gap-1 text-[11px]"
                style={{ color: "var(--muted-strong)" }}
              >
                <span className="min-w-0 break-words font-medium">
                  {nodeLabels.get(edge.source) || edge.source}
                </span>
                <span style={{ color: "var(--muted)" }}>→</span>
                <span
                  className="inline-flex rounded border px-1 py-0.5 text-[9px] font-bold uppercase"
                  style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                >
                  {edge.edge_type}
                </span>
                <span style={{ color: "var(--muted)" }}>→</span>
                <span className="min-w-0 break-words font-medium">
                  {nodeLabels.get(edge.target) || edge.target}
                </span>
              </div>
            ))}
          </div>

          {graph.edges.length > EDGE_DISPLAY_LIMIT && (
            <button
              onClick={() => setShowAllEdges(!showAllEdges)}
              className="mt-1 text-[11px] font-medium transition"
              style={{ color: "var(--muted-strong)" }}
            >
              {showAllEdges
                ? "Show less"
                : `Show all ${graph.edges.length} edges`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function StoryGraphPreview({
  selectedAlert,
  allAlerts,
}: {
  selectedAlert: AlertItem;
  allAlerts: AlertItem[];
}) {
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [graphResult, setGraphResult] = useState<StoryGraphPreviewResponse | null>(null);

  // Reset when selected alert changes
  useEffect(() => {
    setGraphResult(null);
    setGraphError(null);
  }, [selectedAlert.id]);

  const hostname = selectedAlert.hostname;

  async function handleGenerateGraph() {
    if (!hostname) return;

    try {
      setGraphLoading(true);
      setGraphError(null);
      setGraphResult(null);

      const token = getToken();
      const sameHostAlerts = allAlerts
        .filter((a) => a.hostname === hostname)
        .slice(0, MAX_STORY_ALERTS);

      const result = await previewStoryGraph(
        { source_type: "alerts", items: sameHostAlerts as unknown as Record<string, unknown>[] },
        token ?? undefined,
      );

      setGraphResult(result);
    } catch (err) {
      setGraphError(err instanceof Error ? err.message : "Graph preview failed");
    } finally {
      setGraphLoading(false);
    }
  }

  // -- No hostname → disabled state --
  if (!hostname) {
    return (
      <div
        className="rounded-xl p-4 text-center text-sm"
        style={{ background: "var(--surface-1)", color: "var(--muted)" }}
      >
        No hostname available — unable to generate a story graph.
      </div>
    );
  }

  const btnClass =
    "inline-flex w-full items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-60";

  return (
    <div className="min-w-0 space-y-4">
      {/* Generate / Retry button */}
      {!graphResult && (
        <button
          disabled={graphLoading}
          onClick={handleGenerateGraph}
          className={btnClass}
          style={{
            background: "var(--foreground)",
            color: "var(--background)",
          }}
        >
          {graphLoading ? (
            <>
              <Loader2 size={14} className="animate-spin" />
              Generating graph…
            </>
          ) : (
            <>
              <Workflow size={14} />
              Preview Story Graph
            </>
          )}
        </button>
      )}

      {/* Error state */}
      {graphError && (
        <div
          className="min-w-0 rounded-xl border border-red-200 p-3 text-sm dark:border-red-500/20"
          style={{ background: "var(--surface-1)" }}
        >
          <div className="break-words text-red-600 dark:text-red-400">{graphError}</div>
          <button
            onClick={handleGenerateGraph}
            disabled={graphLoading}
            className="mt-2 inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
            style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
          >
            <RefreshCw size={12} />
            Retry
          </button>
        </div>
      )}

      {/* Success — render graphs */}
      {graphResult && (
        <div className="min-w-0 space-y-4">
          {/* Warnings */}
          {graphResult.warnings.length > 0 && (
            <div
              className="min-w-0 rounded-xl border border-amber-200 p-3 text-xs dark:border-amber-500/20"
              style={{
                background: "color-mix(in srgb, var(--surface-1) 90%, transparent)",
              }}
            >
              <div className="mb-1 font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">
                Warnings
              </div>
              <ul className="min-w-0 list-inside list-disc space-y-1">
                {graphResult.warnings.map((w, i) => (
                  <li key={i} className="min-w-0 break-words text-amber-700 dark:text-amber-300">
                    {w}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Summary stats */}
          <div className="grid min-w-0 grid-cols-3 gap-2">
            <div
              className="rounded-lg border p-3 text-center"
              style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
            >
              <div className="text-lg font-black">{graphResult.summary.graph_count}</div>
              <div className="text-[10px] font-bold uppercase tracking-wider" style={{ color: "var(--muted)" }}>
                Graphs
              </div>
            </div>
            <div
              className="rounded-lg border p-3 text-center"
              style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
            >
              <div className="text-lg font-black">{graphResult.summary.total_nodes}</div>
              <div className="text-[10px] font-bold uppercase tracking-wider" style={{ color: "var(--muted)" }}>
                Nodes
              </div>
            </div>
            <div
              className="rounded-lg border p-3 text-center"
              style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
            >
              <div className="text-lg font-black">{graphResult.summary.total_edges}</div>
              <div className="text-[10px] font-bold uppercase tracking-wider" style={{ color: "var(--muted)" }}>
                Edges
              </div>
            </div>
          </div>

          {/* Empty graphs */}
          {graphResult.story_graphs.length === 0 && (
            <div
              className="rounded-xl p-4 text-center text-sm"
              style={{ background: "var(--surface-1)", color: "var(--muted)" }}
            >
              No story graph could be generated for this host&apos;s alerts.
            </div>
          )}

          {/* Graph cards */}
          {graphResult.story_graphs.map((graph) => (
            <GraphCard key={graph.id} graph={graph} />
          ))}

          {/* Regenerate button */}
          <button
            disabled={graphLoading}
            onClick={handleGenerateGraph}
            className={btnClass}
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--surface-1)",
              color: "var(--foreground)",
            }}
          >
            {graphLoading ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                Regenerating…
              </>
            ) : (
              <>
                <RefreshCw size={14} />
                Regenerate Graph
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Case Preview
// ---------------------------------------------------------------------------

const CASE_EVIDENCE_LIMIT = 8;
const CASE_TIMELINE_LIMIT = 8;

function priorityTone(priority?: string | null) {
  const value = (priority || "low").toLowerCase();
  if (value === "immediate") return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  if (value === "high") return "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-500/20 dark:bg-orange-500/10 dark:text-orange-400";
  if (value === "medium") return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-400";
}

function CaseDraftCard({ draft }: { draft: CaseDraftItem }) {
  const evidence = draft.evidence_items || [];
  const timeline = draft.timeline_items || [];
  const actions = draft.recommended_actions || [];
  const questions = draft.analyst_questions || [];
  const tags = draft.tags || [];
  const hosts = draft.affected_hosts || [];
  const users = draft.affected_users || [];
  const tactics = draft.tactics || [];
  const techniques = draft.techniques || [];
  const alertIds = draft.related_alert_ids || [];

  const visibleEvidence = evidence.slice(0, CASE_EVIDENCE_LIMIT);
  const remainingEvidence = evidence.length - CASE_EVIDENCE_LIMIT;
  const visibleTimeline = timeline.slice(0, CASE_TIMELINE_LIMIT);
  const remainingTimeline = timeline.length - CASE_TIMELINE_LIMIT;

  const evidenceEmoji: Record<string, string> = {
    alert: "\uD83D\uDD14",
    story_timeline: "\uD83D\uDCCB",
    graph_summary: "\uD83D\uDDFA\uFE0F",
    mitre_mapping: "\uD83C\uDFAF",
  };

  return (
    <div
      className="min-w-0 space-y-3 rounded-xl border p-4"
      style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
    >
      {/* Header: severity + priority + risk + confidence */}
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span
            className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityTone(draft.severity)}`}
          >
            {draft.severity || "INFO"}
          </span>
          <span
            className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${priorityTone(draft.priority)}`}
          >
            {draft.priority || "low"}
          </span>
          <span className="text-xs font-medium" style={{ color: "var(--muted-strong)" }}>
            Risk {draft.risk_score ?? 0}/100
          </span>
          <span className="text-xs" style={{ color: "var(--muted)" }}>
            Confidence: {draft.confidence || "medium"}
          </span>
        </div>
        <div className="mt-2 min-w-0 break-words text-sm font-bold">{draft.title || "Case Draft"}</div>
      </div>

      {/* Summary */}
      {draft.summary && (
        <div className="min-w-0">
          <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
            Summary
          </div>
          <div className="min-w-0 break-words text-sm leading-relaxed" style={{ color: "var(--muted-strong)" }}>
            {draft.summary}
          </div>
        </div>
      )}

      {/* Tags */}
      {tags.length > 0 && (
        <div className="flex min-w-0 flex-wrap gap-1.5">
          {tags.map((tag) => (
            <span
              key={tag}
              className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium"
              style={{ borderColor: "var(--border)", color: "var(--muted-strong)", background: "var(--surface-0)" }}
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* Affected Hosts & Users */}
      {(hosts.length > 0 || users.length > 0) && (
        <div className="grid min-w-0 grid-cols-2 gap-3">
          {hosts.length > 0 && (
            <div className="min-w-0">
              <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
                Affected Hosts
              </div>
              <div className="min-w-0 break-words text-xs" style={{ color: "var(--muted-strong)" }}>
                {hosts.join(", ")}
              </div>
            </div>
          )}
          {users.length > 0 && (
            <div className="min-w-0">
              <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
                Affected Users
              </div>
              <div className="min-w-0 break-words text-xs" style={{ color: "var(--muted-strong)" }}>
                {users.join(", ")}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tactics & Techniques */}
      {(tactics.length > 0 || techniques.length > 0) && (
        <div className="flex min-w-0 flex-wrap gap-1.5">
          {tactics.map((t) => (
            <span
              key={`tactic-${t}`}
              className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium"
              style={{ borderColor: "var(--border)", color: "var(--muted-strong)" }}
            >
              {t}
            </span>
          ))}
          {techniques.map((t) => (
            <span
              key={`technique-${t}`}
              className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium"
              style={{ borderColor: "var(--border)", color: "var(--muted)", background: "var(--surface-0)" }}
            >
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Related Alert IDs */}
      {alertIds.length > 0 && (
        <div className="min-w-0">
          <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
            Related Alerts ({alertIds.length})
          </div>
          <div className="min-w-0 break-words text-xs" style={{ color: "var(--muted-strong)" }}>
            {alertIds.slice(0, 5).join(", ")}{alertIds.length > 5 ? ` (+${alertIds.length - 5} more)` : ""}
          </div>
        </div>
      )}

      {/* Evidence Items */}
      {evidence.length > 0 && (
        <div className="min-w-0">
          <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
            Evidence ({evidence.length})
          </div>
          <ul className="min-w-0 list-inside list-disc space-y-1 text-xs" style={{ color: "var(--muted-strong)" }}>
            {visibleEvidence.map((ei, i) => (
              <li key={i} className="min-w-0 break-words">
                {evidenceEmoji[ei.evidence_type] || "\uD83D\uDD39"} {ei.description || ei.evidence_type}
              </li>
            ))}
          </ul>
          {remainingEvidence > 0 && (
            <div className="mt-1 text-[11px]" style={{ color: "var(--muted)" }}>
              +{remainingEvidence} more
            </div>
          )}
        </div>
      )}

      {/* Timeline Items */}
      {timeline.length > 0 && (
        <div className="min-w-0">
          <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
            Timeline ({timeline.length})
          </div>
          <div className="min-w-0 space-y-1">
            {visibleTimeline.map((ti, i) => (
              <div key={i} className="flex min-w-0 gap-2 text-xs" style={{ color: "var(--muted-strong)" }}>
                <span className="shrink-0 font-mono text-[10px]" style={{ color: "var(--muted)" }}>
                  {ti.order ?? i + 1}.
                </span>
                {ti.timestamp && (
                  <span className="shrink-0 text-[10px]" style={{ color: "var(--muted)" }}>
                    {ti.timestamp}
                  </span>
                )}
                <span className="min-w-0 break-words">{ti.description || "Event"}</span>
              </div>
            ))}
          </div>
          {remainingTimeline > 0 && (
            <div className="mt-1 text-[11px]" style={{ color: "var(--muted)" }}>
              +{remainingTimeline} more
            </div>
          )}
        </div>
      )}

      {/* Recommended Actions */}
      {actions.length > 0 && (
        <div className="min-w-0">
          <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
            Recommended Actions
          </div>
          <div className="min-w-0 space-y-2">
            {actions.map((action, i) => (
              <div
                key={i}
                className="min-w-0 rounded-lg border p-2.5"
                style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
              >
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold" style={{ color: "var(--foreground)" }}>
                    {action.title || action.action_type}
                  </span>
                  <span
                    className="inline-flex rounded-full border px-1.5 py-0.5 text-[9px] font-bold uppercase"
                    style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                  >
                    {action.priority}
                  </span>
                </div>
                {action.description && (
                  <div className="mt-1 min-w-0 break-words text-xs" style={{ color: "var(--muted)" }}>
                    {action.description}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analyst Questions */}
      {questions.length > 0 && (
        <div className="min-w-0">
          <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: "var(--muted)" }}>
            Analyst Questions
          </div>
          <ul className="min-w-0 list-inside list-disc space-y-1 text-sm" style={{ color: "var(--muted-strong)" }}>
            {questions.map((q, i) => (
              <li key={i} className="min-w-0 break-words">{q}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function CasePreviewPanel({
  selectedAlert,
  allAlerts,
}: {
  selectedAlert: AlertItem;
  allAlerts: AlertItem[];
}) {
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [caseResult, setCaseResult] = useState<CasePreviewResponse | null>(null);

  // Reset when selected alert changes
  useEffect(() => {
    setCaseResult(null);
    setCaseError(null);
  }, [selectedAlert.id]);

  const hostname = selectedAlert.hostname;

  async function handleCasePreview() {
    if (!hostname) return;

    try {
      setCaseLoading(true);
      setCaseError(null);
      setCaseResult(null);

      const token = getToken();
      const sameHostAlerts = allAlerts
        .filter((a) => a.hostname === hostname)
        .slice(0, MAX_STORY_ALERTS);

      const items = sameHostAlerts.length > 0
        ? sameHostAlerts
        : [selectedAlert];

      const result = await previewCaseDraft(
        {
          source_type: "alerts",
          items: items as unknown as Record<string, unknown>[],
          include_graph: true,
          consolidate: true,
        },
        token ?? undefined,
      );

      setCaseResult(result);
    } catch (err) {
      setCaseError(err instanceof Error ? err.message : "Case preview failed");
    } finally {
      setCaseLoading(false);
    }
  }

  // No hostname → disabled
  if (!hostname) {
    return (
      <div
        className="rounded-xl p-4 text-center text-sm"
        style={{ background: "var(--surface-1)", color: "var(--muted)" }}
      >
        No hostname available — unable to generate a case draft.
      </div>
    );
  }

  const btnClass =
    "inline-flex w-full items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-60";

  return (
    <div className="min-w-0 space-y-4">
      {/* Generate / Retry button */}
      {!caseResult && (
        <button
          disabled={caseLoading}
          onClick={handleCasePreview}
          className={btnClass}
          style={{
            background: "var(--foreground)",
            color: "var(--background)",
          }}
        >
          {caseLoading ? (
            <>
              <Loader2 size={14} className="animate-spin" />
              Generating case draft\u2026
            </>
          ) : (
            <>
              <Briefcase size={14} />
              Preview Case Draft
            </>
          )}
        </button>
      )}

      {/* Error state */}
      {caseError && (
        <div
          className="min-w-0 rounded-xl border border-red-200 p-3 text-sm dark:border-red-500/20"
          style={{ background: "var(--surface-1)" }}
        >
          <div className="break-words text-red-600 dark:text-red-400">{caseError}</div>
          <button
            onClick={handleCasePreview}
            disabled={caseLoading}
            className="mt-2 inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
            style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
          >
            <RefreshCw size={12} />
            Retry
          </button>
        </div>
      )}

      {/* Success */}
      {caseResult && (
        <div className="min-w-0 space-y-4">
          {/* Warnings */}
          {caseResult.warnings.length > 0 && (
            <div
              className="min-w-0 rounded-xl border border-amber-200 p-3 text-xs dark:border-amber-500/20"
              style={{ background: "color-mix(in srgb, var(--surface-1) 90%, transparent)" }}
            >
              <div className="mb-1 font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">
                Warnings
              </div>
              <ul className="min-w-0 list-inside list-disc space-y-1">
                {caseResult.warnings.map((w, i) => (
                  <li key={i} className="min-w-0 break-words text-amber-700 dark:text-amber-300">
                    {w}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Empty case drafts */}
          {caseResult.case_drafts.length === 0 && (
            <div
              className="rounded-xl p-4 text-center text-sm"
              style={{ background: "var(--surface-1)", color: "var(--muted)" }}
            >
              No case draft could be generated for this host&apos;s alerts.
            </div>
          )}

          {/* Case draft cards */}
          {caseResult.case_drafts.map((cd) => (
            <CaseDraftCard key={cd.id} draft={cd} />
          ))}

          {/* Regenerate button */}
          <button
            disabled={caseLoading}
            onClick={handleCasePreview}
            className={btnClass}
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--surface-1)",
              color: "var(--foreground)",
            }}
          >
            {caseLoading ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                Regenerating\u2026
              </>
            ) : (
              <>
                <RefreshCw size={14} />
                Regenerate Case Draft
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Alert Inspector
// ---------------------------------------------------------------------------

function AlertInspector({
  selectedAlert,
  detailLoading,
  actionLoading,
  assignTo,
  setAssignTo,
  noteDraft,
  setNoteDraft,
  allAlerts,
  refreshSelected,
  runAction,
  onInvestigate,
}: {
  selectedAlert: AlertItem | null;
  detailLoading: boolean;
  actionLoading: boolean;
  assignTo: string;
  setAssignTo: (value: string) => void;
  noteDraft: string;
  setNoteDraft: (value: string) => void;
  allAlerts: AlertItem[];
  refreshSelected: () => Promise<void>;
  runAction: (fn: (token: string) => Promise<unknown>) => Promise<void>;
  onInvestigate: (alertId: string) => void;
}) {
  if (!selectedAlert) {
    return (
      <Panel title="Alert Inspector" subtitle="Select an alert to inspect and respond">
        <div
          className="rounded-2xl border p-8 text-center text-sm"
          style={{
            borderColor: "var(--border)",
            background: "var(--surface-1)",
            color: "var(--muted)",
          }}
        >
          Soldaki kuyruktan bir alert seç. Detaylar, response aksiyonları ve analyst workflow burada sabit kalacak.
        </div>
      </Panel>
    );
  }

  if (detailLoading) {
    return (
      <Panel title="Alert Inspector" subtitle="Loading selected alert detail">
        <div
          className="rounded-2xl border p-6 text-sm"
          style={{
            borderColor: "var(--border)",
            background: "var(--surface-1)",
            color: "var(--muted)",
          }}
        >
          Alert detayı yükleniyor...
        </div>
      </Panel>
    );
  }

  return (
    <Panel title="Alert Inspector" subtitle="Triage, ownership, escalation and response panel">
      <div className="min-w-0 space-y-4">
        <InspectorSection title="Detection Summary">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span
              className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityTone(selectedAlert.severity)}`}
            >
              {selectedAlert.severity || "INFO"}
            </span>
            <span
              className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusTone(selectedAlert.status)}`}
            >
              {selectedAlert.status || "open"}
            </span>
          </div>

          <div className="min-w-0 break-words text-base font-black">
            {displayTitle(selectedAlert)}
          </div>
          <div className="mt-2 break-words text-sm" style={{ color: "var(--muted-strong)" }}>
            {selectedAlert.details || "No alert details available."}
          </div>
        </InspectorSection>

        <div className="grid min-w-0 gap-3 md:grid-cols-2 lg:grid-cols-1 2xl:grid-cols-2">
          <InfoCard label="Alert ID" value={selectedAlert.id} />
          <InfoCard label="Hostname" value={selectedAlert.hostname || "—"} />
          <InfoCard label="Username" value={selectedAlert.username || "—"} />
          <InfoCard label="Type" value={selectedAlert.type || "—"} />
          <InfoCard label="Rule" value={selectedAlert.rule || "—"} />
          <InfoCard label="Risk Score" value={String(selectedAlert.risk_score ?? 0)} />
          <InfoCard
            label="PID"
            value={selectedAlert.pid != null ? String(selectedAlert.pid) : "—"}
          />
          <InfoCard label="Created At" value={fmtDate(selectedAlert.created_at)} />
        </div>

        {selectedAlert.hostname ? (
          <InspectorSection title="Response Actions">
            <HostResponseActions
              hostname={selectedAlert.hostname}
              compact
              onActionComplete={refreshSelected}
            />
          </InspectorSection>
        ) : null}

        {selectedAlert.hostname ? (
          <InspectorSection title="Last Response Actions">
            <HostLastResponseActions hostname={selectedAlert.hostname} />
          </InspectorSection>
        ) : null}

        <InspectorSection title="Command Line">
          <div
            className="max-h-44 overflow-y-auto rounded-xl p-3 font-mono text-xs leading-relaxed"
            style={{
              background: "var(--surface-1)",
              color: "var(--muted-strong)",
            }}
          >
            <pre className="whitespace-pre-wrap break-words">
              {selectedAlert.command_line || "No command line data"}
            </pre>
          </div>
        </InspectorSection>

        <InspectorSection title="Attack Story Preview">
          <AttackStoryPreview
            selectedAlert={selectedAlert}
            allAlerts={allAlerts}
          />
        </InspectorSection>

        <InspectorSection title="Story Graph Preview">
          <StoryGraphPreview
            selectedAlert={selectedAlert}
            allAlerts={allAlerts}
          />
        </InspectorSection>

        <InspectorSection title="Case Preview">
          <CasePreviewPanel
            selectedAlert={selectedAlert}
            allAlerts={allAlerts}
          />
        </InspectorSection>

        <InspectorSection title="Assignment">
          <div className="grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] 2xl:grid-cols-1">
            <input
              value={assignTo}
              onChange={(e) => setAssignTo(e.target.value)}
              placeholder="analyst username"
              className="min-w-0 rounded-xl border px-4 py-3 text-sm outline-none transition"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
                color: "var(--foreground)",
              }}
            />

            <div className="flex flex-wrap gap-2">
              <button
                disabled={actionLoading || !assignTo.trim()}
                onClick={() =>
                  runAction((token) => assignAlert(selectedAlert.id, assignTo.trim(), token))
                }
                className="inline-flex items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
                style={{
                  background: "var(--foreground)",
                  color: "var(--background)",
                }}
              >
                <UserPlus size={14} />
                Assign
              </button>

              <button
                disabled={actionLoading}
                onClick={() => runAction((token) => unassignAlert(selectedAlert.id, token))}
                className="rounded-xl border px-4 py-3 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                }}
              >
                Unassign
              </button>
            </div>
          </div>

          <div className="mt-3 text-xs" style={{ color: "var(--muted)" }}>
            Current owner: {selectedAlert.assigned_to || "Unassigned"}
          </div>
        </InspectorSection>

        <InspectorSection title="Analyst Note">
          <textarea
            value={noteDraft}
            onChange={(e) => setNoteDraft(e.target.value)}
            rows={4}
            className="min-w-0 w-full rounded-xl border px-4 py-3 text-sm outline-none transition"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-0)",
              color: "var(--foreground)",
            }}
            placeholder="Investigation notes, triage context, next steps..."
          />

          <div className="mt-3 flex flex-wrap gap-3">
            <button
              disabled={actionLoading}
              onClick={() =>
                runAction((token) => updateAlertNote(selectedAlert.id, noteDraft, token))
              }
              className="rounded-xl px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                background: "var(--foreground)",
                color: "var(--background)",
              }}
            >
              Save Note
            </button>
          </div>
        </InspectorSection>

        <InspectorSection title="Workflow Actions">
          <div className="flex min-w-0 flex-wrap gap-3">
            <button
              disabled={actionLoading}
              onClick={() => runAction((token) => acknowledgeAlert(selectedAlert.id, token))}
              className="inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
              }}
            >
              <Clock3 size={14} />
              Acknowledge
            </button>

            <button
              disabled={actionLoading}
              onClick={() => onInvestigate(selectedAlert.id)}
              className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                background: "var(--foreground)",
                color: "var(--background)",
              }}
            >
              <Workflow size={14} />
              Investigate
            </button>

            <button
              disabled={actionLoading}
              onClick={() =>
                runAction((token) =>
                  resolveAlert(
                    selectedAlert.id,
                    noteDraft.trim() || "Resolved by analyst workflow",
                    token,
                  ),
                )
              }
              className="inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
              }}
            >
              <CheckCircle2 size={14} />
              Resolve
            </button>

            <button
              disabled={actionLoading}
              onClick={() => runAction((token) => reopenAlert(selectedAlert.id, token))}
              className="inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
              }}
            >
              <XCircle size={14} />
              Reopen
            </button>
          </div>
        </InspectorSection>
      </div>
    </Panel>
  );
}

export default function AlertsPage() {
  const router = useRouter();

  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("ALL");

  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [assignTo, setAssignTo] = useState("");
  const [noteDraft, setNoteDraft] = useState("");

  async function loadAlerts() {
    try {
      setLoading(true);
      setError(null);

      const token = getToken();
      if (!token) {
        router.replace("/login?next=/alerts");
        return;
      }

      const data = await getAlerts(token, 100);
      setAlerts(data);
    } catch (err) {
      if (err instanceof Error && err.message.includes("Not authenticated")) {
        clearAuthSession();
        router.replace("/login?next=/alerts");
        return;
      }
      setError(err instanceof Error ? err.message : "Alert listesi yüklenemedi");
    } finally {
      setLoading(false);
    }
  }

  async function loadAlertDetail(alertId: string) {
    try {
      setDetailLoading(true);
      setError(null);

      const token = getToken();
      if (!token) {
        router.replace("/login?next=/alerts");
        return;
      }

      const detail = await getAlertDetail(alertId, token);
      setSelectedAlert(detail);
      setNoteDraft(detail.analyst_note || "");
      setAssignTo(detail.assigned_to || "");
    } catch (err) {
      if (err instanceof Error && err.message.includes("Not authenticated")) {
        clearAuthSession();
        router.replace("/login?next=/alerts");
        return;
      }
      setError(err instanceof Error ? err.message : "Alert detayı yüklenemedi");
    } finally {
      setDetailLoading(false);
    }
  }

  useEffect(() => {
    loadAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      const sev = (alert.severity || "INFO").toUpperCase();
      const status = (alert.status || "open").toLowerCase();

      const severityOk = severityFilter === "ALL" || sev === severityFilter;
      const statusOk = statusFilter === "ALL" || status === statusFilter;

      const queryOk =
        !q ||
        [
          alert.id,
          alert.hostname,
          alert.username,
          alert.rule,
          alert.type,
          alert.details,
          alert.command_line,
          alert.assigned_to,
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(q));

      return severityOk && statusOk && queryOk;
    });
  }, [alerts, search, severityFilter, statusFilter]);

  const summary = useMemo(() => {
    return {
      total: alerts.length,
      open: alerts.filter((a) => (a.status || "open").toLowerCase() === "open").length,
      acknowledged: alerts.filter((a) => (a.status || "").toLowerCase() === "acknowledged")
        .length,
      resolved: alerts.filter((a) => (a.status || "").toLowerCase() === "resolved").length,
      critical: alerts.filter((a) => (a.severity || "").toUpperCase() === "CRITICAL").length,
    };
  }, [alerts]);

  async function refreshSelected() {
    if (!selectedAlert?.id) return;
    await loadAlertDetail(selectedAlert.id);
    await loadAlerts();
  }

  async function runAction(fn: (token: string) => Promise<unknown>) {
    try {
      setActionLoading(true);
      setError(null);

      const token = getToken();
      if (!token) {
        router.replace("/login?next=/alerts");
        return;
      }

      await fn(token);
      await loadAlerts();
      await refreshSelected();
    } catch (err) {
      if (err instanceof Error && err.message.includes("Not authenticated")) {
        clearAuthSession();
        router.replace("/login?next=/alerts");
        return;
      }
      setError(err instanceof Error ? err.message : "İşlem başarısız");
    } finally {
      setActionLoading(false);
    }
  }

  async function refreshAfterQuickAction(alertId: string) {
    await loadAlerts();
    if (selectedAlert?.id === alertId) {
      await refreshSelected();
    }
  }

  return (
    <div className="grid min-w-0 gap-6 overflow-x-hidden">
      <div className="flex min-w-0 flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <div
            className="text-[11px] font-bold uppercase tracking-[0.24em]"
            style={{ color: "var(--muted)" }}
          >
            Alert Triage
          </div>
          <div className="mt-2 break-words text-2xl font-black tracking-tight">
            Prioritize, assign and escalate high-signal detections
          </div>
          <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
            Queue-driven analyst workflow with a persistent right-side inspector.
          </div>
        </div>

        <button
          onClick={loadAlerts}
          className="inline-flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-sm font-medium transition"
          style={{
            background: "var(--surface-1)",
            borderColor: "var(--border-strong)",
          }}
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      <div className="grid min-w-0 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard title="Total Alerts" value={summary.total} hint="Toplam uyarı" icon={<Activity size={15} />} />
        <SummaryCard title="Open" value={summary.open} hint="Yeni / aksiyon bekliyor" icon={<ShieldAlert size={15} />} />
        <SummaryCard title="Acknowledged" value={summary.acknowledged} hint="Analist üzerinde" icon={<Workflow size={15} />} />
        <SummaryCard title="Resolved" value={summary.resolved} hint="Kapatılan uyarılar" icon={<CheckCircle2 size={15} />} />
        <SummaryCard title="Critical" value={summary.critical} hint="En yüksek öncelik" icon={<AlertTriangle size={15} />} />
      </div>

      {error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300">
          {error}
        </div>
      ) : null}

      <div className="grid min-w-0 gap-6 overflow-x-hidden lg:grid-cols-[minmax(0,1fr)_430px] 2xl:grid-cols-[minmax(0,1fr)_480px]">
        <Panel title="Alert Queue" subtitle="SOC triage queue with stable layout">
          <div className="mb-4 grid min-w-0 gap-3 lg:grid-cols-[minmax(0,1fr)_auto_auto]">
            <div className="relative min-w-0">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="id, host, user, rule, process..."
                className="min-w-0 w-full rounded-2xl border px-10 py-3 text-sm outline-none transition"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                  color: "var(--foreground)",
                }}
              />
            </div>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
              className="rounded-2xl border px-4 py-3 text-sm outline-none"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
                color: "var(--foreground)",
              }}
            >
              <option value="ALL">All Severity</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="WARNING">Warning</option>
              <option value="INFO">Info</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
              className="rounded-2xl border px-4 py-3 text-sm outline-none"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
                color: "var(--foreground)",
              }}
            >
              <option value="ALL">All Status</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          {loading ? (
            <div
              className="rounded-2xl border p-6 text-sm"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted)",
              }}
            >
              Alert listesi yükleniyor...
            </div>
          ) : filteredAlerts.length === 0 ? (
            <div
              className="rounded-2xl border p-6 text-sm"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted)",
              }}
            >
              Eşleşen alert bulunamadı.
            </div>
          ) : (
            <div className="grid min-w-0 gap-3">
              {filteredAlerts.map((alert) => {
                const isSelected = selectedAlert?.id === alert.id;

                return (
                  <div
                    key={alert.id}
                    className="min-w-0 rounded-2xl border p-4 transition"
                    style={
                      isSelected
                        ? {
                            borderColor: "var(--foreground)",
                            background:
                              "color-mix(in srgb, var(--surface-1) 92%, transparent)",
                          }
                        : {
                            borderColor: "var(--border)",
                            background: "var(--surface-0)",
                          }
                    }
                  >
                    <button
                      onClick={() => loadAlertDetail(alert.id)}
                      className="min-w-0 w-full text-left"
                    >
                      <div className="flex min-w-0 flex-wrap items-center gap-2">
                        <span
                          className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityTone(alert.severity)}`}
                        >
                          {alert.severity || "INFO"}
                        </span>
                        <span
                          className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusTone(alert.status)}`}
                        >
                          {alert.status || "open"}
                        </span>
                      </div>

                      <div className="mt-3 min-w-0 break-words text-sm font-semibold">
                        {displayTitle(alert)}
                      </div>

                      <div className="mt-1 min-w-0 break-words text-xs" style={{ color: "var(--muted)" }}>
                        {alert.id} · {alert.hostname || "unknown-host"} ·{" "}
                        {alert.username || "unknown-user"}
                      </div>

                      <div
                        className="mt-2 flex min-w-0 flex-wrap gap-3 text-xs"
                        style={{ color: "var(--muted-strong)" }}
                      >
                        <span>Risk: {alert.risk_score ?? 0}</span>
                        <span>Created: {relativeTime(alert.created_at)}</span>
                        <span>Owner: {alert.assigned_to || "Unassigned"}</span>
                      </div>
                    </button>

                    <QuickHostActions
                      alert={alert}
                      disabled={actionLoading}
                      onDone={() => refreshAfterQuickAction(alert.id)}
                    />
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <div className="min-w-0 lg:sticky lg:top-6 lg:max-h-[calc(100vh-6rem)] lg:overflow-y-auto">
          <AlertInspector
            selectedAlert={selectedAlert}
            detailLoading={detailLoading}
            actionLoading={actionLoading}
            assignTo={assignTo}
            setAssignTo={setAssignTo}
            noteDraft={noteDraft}
            setNoteDraft={setNoteDraft}
            allAlerts={alerts}
            refreshSelected={refreshSelected}
            runAction={runAction}
            onInvestigate={(alertId) => router.push(`/investigations?alert_id=${alertId}`)}
          />
        </div>
      </div>
    </div>
  );
}

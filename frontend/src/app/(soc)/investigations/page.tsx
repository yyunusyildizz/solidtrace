"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Briefcase,
  CheckCircle2,
  Clock3,
  Filter,
  Search,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import InvestigationGraph, {
  type InvestigationGraphData,
} from "@/components/soc/investigation-graph";
import {
  getInvestigationGraph,
  getInvestigations,
  type InvestigationQueueItem,
  type InvestigationSeverity,
  type InvestigationStatus,
} from "@/lib/api/investigations";
import { clearAuthSession, getToken } from "@/lib/auth";

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

function severityBadge(severity: InvestigationSeverity) {
  if (severity === "CRITICAL") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  }
  if (severity === "HIGH") {
    return "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-500/20 dark:bg-orange-500/10 dark:text-orange-400";
  }
  if (severity === "WARNING") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-400";
}

function statusBadge(status: InvestigationStatus) {
  if (status === "open") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  }
  if (status === "in_progress") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  if (status === "contained") {
    return "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-500/20 dark:bg-violet-500/10 dark:text-violet-400";
  }
  return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
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
      className="rounded-2xl border p-4"
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
      <div className="text-sm" style={{ color: "var(--foreground)" }}>
        {value}
      </div>
    </div>
  );
}

export default function InvestigationsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | InvestigationStatus>("ALL");
  const [queue, setQueue] = useState<InvestigationQueueItem[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [graph, setGraph] = useState<InvestigationGraphData | null>(null);
  const [loadingQueue, setLoadingQueue] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const requestedAlertId = searchParams.get("alert_id");

  useEffect(() => {
    let active = true;

    async function loadQueue() {
      try {
        setLoadingQueue(true);
        setError(null);

        const token = getToken();
        if (!token) {
          router.replace(`/login?next=${encodeURIComponent("/investigations")}`);
          return;
        }

        const data = await getInvestigations(token);

        if (!active) return;

        setQueue(data);

        const firstAvailableId = data[0]?.alert_id ?? null;
        const initialId =
          requestedAlertId && data.some((item) => item.alert_id === requestedAlertId)
            ? requestedAlertId
            : firstAvailableId;

        setSelectedAlertId(initialId);
      } catch (err) {
        if (!active) return;
        if (err instanceof Error && err.message.includes("Not authenticated")) {
          clearAuthSession();
          router.replace(`/login?next=${encodeURIComponent("/investigations")}`);
          return;
        }
        setError(err instanceof Error ? err.message : "Investigation queue yüklenemedi");
      } finally {
        if (active) setLoadingQueue(false);
      }
    }

    loadQueue();

    return () => {
      active = false;
    };
  }, [requestedAlertId, router]);

  useEffect(() => {
    let active = true;

    async function loadGraph(alertId: string) {
      try {
        setLoadingGraph(true);

        const token = getToken();
        if (!token) {
          router.replace(`/login?next=${encodeURIComponent("/investigations")}`);
          return;
        }

        const data = await getInvestigationGraph(alertId, token);
        if (!active) return;

        setGraph({
          nodes: data.nodes ?? [],
          edges: data.edges ?? [],
        });
      } catch (err) {
        if (!active) return;
        if (err instanceof Error && err.message.includes("Not authenticated")) {
          clearAuthSession();
          router.replace(`/login?next=${encodeURIComponent("/investigations")}`);
          return;
        }
        setGraph({ nodes: [], edges: [] });
        setError(err instanceof Error ? err.message : "Investigation graph yüklenemedi");
      } finally {
        if (active) setLoadingGraph(false);
      }
    }

    if (selectedAlertId) {
      loadGraph(selectedAlertId);
    } else {
      setGraph(null);
    }

    return () => {
      active = false;
    };
  }, [selectedAlertId, router]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();

    return queue.filter((item) => {
      const statusOk = statusFilter === "ALL" || item.status === statusFilter;
      const queryOk =
        !q ||
        [
          item.id,
          item.title,
          item.owner,
          item.affected_host,
          item.summary,
          ...item.tags,
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return statusOk && queryOk;
    });
  }, [queue, search, statusFilter]);

  const selected = useMemo(
    () => queue.find((item) => item.alert_id === selectedAlertId) ?? null,
    [queue, selectedAlertId],
  );

  const summary = useMemo(() => {
    return {
      total: queue.length,
      open: queue.filter((x) => x.status === "open").length,
      active: queue.filter((x) => x.status === "in_progress").length,
      contained: queue.filter((x) => x.status === "contained").length,
      closed: queue.filter((x) => x.status === "closed").length,
    };
  }, [queue]);

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div
            className="text-[11px] font-bold uppercase tracking-[0.24em]"
            style={{ color: "var(--muted)" }}
          >
            Investigation Workspace
          </div>
          <div className="mt-2 text-2xl font-black tracking-tight">
            Alert-driven investigations with graph-based context
          </div>
          <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
            Queue, detail and entity graph designed for analyst workflow continuity.
          </div>
        </div>

        <div
          className="inline-flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-sm font-medium"
          style={{
            background: "var(--surface-1)",
            borderColor: "var(--border-strong)",
            color: "var(--muted-strong)",
          }}
        >
          <Filter size={14} />
          Filtered queue
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard title="Total Cases" value={summary.total} hint="Toplam investigation" icon={<Briefcase size={15} />} />
        <SummaryCard title="Open" value={summary.open} hint="Yeni vakalar" icon={<ShieldAlert size={15} />} />
        <SummaryCard title="In Progress" value={summary.active} hint="Aktif analiz" icon={<Workflow size={15} />} />
        <SummaryCard title="Contained" value={summary.contained} hint="Containment sonrası" icon={<Clock3 size={15} />} />
        <SummaryCard title="Closed" value={summary.closed} hint="Tamamlanan" icon={<CheckCircle2 size={15} />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.88fr_1.12fr]">
        <Panel title="Investigation Queue" subtitle="Alert-driven SOC görünümü">
          <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto]">
            <div className="relative">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="case id, title, owner, host..."
                className="w-full rounded-2xl border px-10 py-3 text-sm outline-none transition"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                  color: "var(--foreground)",
                }}
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as "ALL" | InvestigationStatus)}
              className="rounded-2xl border px-4 py-3 text-sm outline-none"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
                color: "var(--foreground)",
              }}
            >
              <option value="ALL">All Status</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="contained">Contained</option>
              <option value="closed">Closed</option>
            </select>
          </div>

          {loadingQueue ? (
            <div
              className="rounded-2xl border p-6 text-sm"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted)",
              }}
            >
              Investigation queue yükleniyor...
            </div>
          ) : filtered.length === 0 ? (
            <div
              className="rounded-2xl border p-6 text-sm"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted)",
              }}
            >
              No active investigations derived from current alerts.
            </div>
          ) : (
            <div className="space-y-3">
              {filtered.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setSelectedAlertId(item.alert_id)}
                  className="w-full rounded-2xl border p-4 text-left transition"
                  style={
                    selected?.id === item.id
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
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityBadge(item.severity)}`}>
                      {item.severity}
                    </span>
                    <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusBadge(item.status)}`}>
                      {item.status}
                    </span>
                  </div>

                  <div className="mt-3 text-sm font-semibold">{item.title}</div>
                  <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                    {item.id} · {item.affected_host} · {item.related_alerts} related alerts
                  </div>
                  <div className="mt-2 text-xs" style={{ color: "var(--muted-strong)" }}>
                    Owner: {item.owner} · Updated: {relativeTime(item.updated_at)}
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Investigation Detail" subtitle="Graph, context and analyst actions">
          {error ? (
            <div className="mb-4 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300">
              {error}
            </div>
          ) : null}

          {!selected ? (
            <div
              className="rounded-2xl border p-8 text-center text-sm"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted)",
              }}
            >
              Investigation seçilmedi.
            </div>
          ) : (
            <div className="space-y-6">
              <section
                className="rounded-2xl border p-4"
                style={{
                  borderColor: "var(--border)",
                  background: "color-mix(in srgb, var(--surface-1) 86%, transparent)",
                }}
              >
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityBadge(selected.severity)}`}>
                    {selected.severity}
                  </span>
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusBadge(selected.status)}`}>
                    {selected.status}
                  </span>
                </div>

                <div className="text-base font-black">{selected.title}</div>
                <div className="mt-3 text-sm leading-relaxed" style={{ color: "var(--muted-strong)" }}>
                  {selected.summary}
                </div>
              </section>

              <div className="grid gap-3 md:grid-cols-2">
                <InfoCard label="Case ID" value={selected.id} />
                <InfoCard label="Owner" value={selected.owner} />
                <InfoCard label="Affected Host" value={selected.affected_host} />
                <InfoCard label="Related Alerts" value={String(selected.related_alerts)} />
                <InfoCard label="Created At" value={fmtDate(selected.created_at)} />
                <InfoCard label="Updated At" value={fmtDate(selected.updated_at)} />
              </div>

              <section
                className="rounded-2xl border p-4"
                style={{ borderColor: "var(--border)" }}
              >
                <div
                  className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
                  style={{ color: "var(--muted)" }}
                >
                  Tags
                </div>
                <div className="flex flex-wrap gap-2">
                  {selected.tags.map((tag) => (
                    <span
                      key={tag}
                      className="inline-flex rounded-full border px-3 py-1 text-xs"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-1)",
                        color: "var(--muted-strong)",
                      }}
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </section>

              {loadingGraph ? (
                <div
                  className="rounded-2xl border p-6 text-sm"
                  style={{
                    borderColor: "var(--border)",
                    background: "var(--surface-1)",
                    color: "var(--muted)",
                  }}
                >
                  Investigation graph yükleniyor...
                </div>
              ) : graph ? (
                <InvestigationGraph data={graph} />
              ) : (
                <div
                  className="rounded-2xl border p-6 text-sm"
                  style={{
                    borderColor: "var(--border)",
                    background: "var(--surface-1)",
                    color: "var(--muted)",
                  }}
                >
                  Graph verisi bulunamadı.
                </div>
              )}

              <section
                className="rounded-2xl border p-4"
                style={{ borderColor: "var(--border)" }}
              >
                <div
                  className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
                  style={{ color: "var(--muted)" }}
                >
                  Quick Actions
                </div>

                <div className="flex flex-wrap gap-3">
                  <button
                    className="rounded-xl px-4 py-2 text-sm font-medium transition"
                    style={{
                      background: "var(--foreground)",
                      color: "var(--background)",
                    }}
                  >
                    Assign Owner
                  </button>
                  <button
                    className="rounded-xl border px-4 py-2 text-sm font-medium transition"
                    style={{
                      borderColor: "var(--border)",
                      background: "var(--surface-0)",
                    }}
                  >
                    Add Note
                  </button>
                  <button
                    className="rounded-xl border px-4 py-2 text-sm font-medium transition"
                    style={{
                      borderColor: "var(--border)",
                      background: "var(--surface-0)",
                    }}
                  >
                    Contain Host
                  </button>
                  <button
                    className="rounded-xl border px-4 py-2 text-sm font-medium transition"
                    style={{
                      borderColor: "var(--border)",
                      background: "var(--surface-0)",
                    }}
                  >
                    Close Case
                  </button>
                </div>
              </section>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
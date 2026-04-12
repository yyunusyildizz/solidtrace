"use client";

import AuthGuard from "@/components/auth/AuthGuard";
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
  Milestone,
  Target,
  UserPlus2,
  StickyNote,
  Shield,
  CheckCheck,
  BadgeInfo,
  Sparkles,
  Activity,
  TerminalSquare,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import InvestigationGraph, {
  type InvestigationGraphData,
} from "@/components/soc/investigation-graph";
import {
  assignIncident,
  getIncidentAttackChain,
  getIncidentDetail,
  getIncidentGraph,
  getIncidentTimeline,
  getIncidents,
  updateIncidentNote,
  updateIncidentStatus,
  type IncidentAttackChainResponse,
  type IncidentQueueItem,
  type IncidentTimelineItem,
  type InvestigationSeverity,
  type InvestigationStatus,
  mapIncidentToQueueItem,
} from "@/lib/api/investigations";
import { clearAuthSession, getToken } from "@/lib/auth";
import { isolateHost } from "@/lib/api/actions";

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
  if (status === "acknowledged") {
    return "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-500/20 dark:bg-blue-500/10 dark:text-blue-400";
  }
  if (status === "suppressed") {
    return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300";
  }
  return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
}

function confidenceBadge(confidence?: string) {
  const value = (confidence || "medium").toLowerCase();
  if (value === "high") {
    return "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700 dark:border-fuchsia-500/20 dark:bg-fuchsia-500/10 dark:text-fuchsia-300";
  }
  if (value === "low") {
    return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-300";
  }
  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-300";
}

function timelineTone(eventType?: string) {
  const value = (eventType || "").toLowerCase();
  if (value.includes("response")) return "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-500/20 dark:bg-violet-500/10 dark:text-violet-300";
  if (value.includes("status")) return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-300";
  if (value.includes("note")) return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300";
  if (value.includes("merge") || value.includes("suppressed")) return "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700 dark:border-fuchsia-500/20 dark:bg-fuchsia-500/10 dark:text-fuchsia-300";
  return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-300";
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

function ActionCard({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section
      className="rounded-2xl border p-4"
      style={{
        borderColor: "var(--border)",
        background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
      }}
    >
      <div
        className="mb-3 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em]"
        style={{ color: "var(--muted)" }}
      >
        {icon}
        {title}
      </div>
      {children}
    </section>
  );
}

function InvestigationsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | InvestigationStatus>("ALL");
  const [queue, setQueue] = useState<IncidentQueueItem[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [graph, setGraph] = useState<InvestigationGraphData | null>(null);
  const [attackChain, setAttackChain] = useState<IncidentAttackChainResponse | null>(null);
  const [timeline, setTimeline] = useState<IncidentTimelineItem[]>([]);
  const [loadingQueue, setLoadingQueue] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [acting, setActing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [ownerDraft, setOwnerDraft] = useState("");
  const [noteDraft, setNoteDraft] = useState("");

  const requestedIncidentId = searchParams.get("incident_id");

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

        const data = await getIncidents(token);

        if (!active) return;

        setQueue(data);

        const firstAvailableId = data[0]?.incident_id ?? null;
        const initialId =
          requestedIncidentId && data.some((item) => item.incident_id === requestedIncidentId)
            ? requestedIncidentId
            : firstAvailableId;

        setSelectedIncidentId(initialId);
      } catch (err) {
        if (!active) return;
        if (err instanceof Error && err.message.includes("Not authenticated")) {
          clearAuthSession();
          router.replace(`/login?next=${encodeURIComponent("/investigations")}`);
          return;
        }
        setError(err instanceof Error ? err.message : "Incident queue yüklenemedi");
      } finally {
        if (active) setLoadingQueue(false);
      }
    }

    loadQueue();

    return () => {
      active = false;
    };
  }, [requestedIncidentId, router]);

  useEffect(() => {
    let active = true;

    async function loadDetail(incidentId: string) {
      try {
        setLoadingDetail(true);
        setLoadingGraph(true);

        const token = getToken();
        if (!token) {
          router.replace(`/login?next=${encodeURIComponent("/investigations")}`);
          return;
        }

        const [detail, graphData, chainData, timelineData] = await Promise.all([
          getIncidentDetail(incidentId, token),
          getIncidentGraph(incidentId, token),
          getIncidentAttackChain(incidentId, token),
          getIncidentTimeline(incidentId, token),
        ]);

        if (!active) return;

        setQueue((prev) =>
          prev.map((item) =>
            item.incident_id === incidentId ? { ...item, ...mapIncidentToQueueItem(detail) } : item,
          ),
        );

        setOwnerDraft(detail.owner || "");
        setNoteDraft(detail.analyst_note || "");
        setGraph({
          nodes: graphData.nodes ?? [],
          edges: graphData.edges ?? [],
        });
        setAttackChain(chainData);
        setTimeline(timelineData.items ?? []);
      } catch (err) {
        if (!active) return;
        if (err instanceof Error && err.message.includes("Not authenticated")) {
          clearAuthSession();
          router.replace(`/login?next=${encodeURIComponent("/investigations")}`);
          return;
        }
        setGraph({ nodes: [], edges: [] });
        setAttackChain(null);
        setTimeline([]);
        setError(err instanceof Error ? err.message : "Incident detail yüklenemedi");
      } finally {
        if (active) {
          setLoadingDetail(false);
          setLoadingGraph(false);
        }
      }
    }

    if (selectedIncidentId) {
      setSuccess(null);
      setError(null);
      loadDetail(selectedIncidentId);
    } else {
      setGraph(null);
      setAttackChain(null);
      setTimeline([]);
      setOwnerDraft("");
      setNoteDraft("");
    }

    return () => {
      active = false;
    };
  }, [selectedIncidentId, router]);

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
          item.campaign_family,
          item.confidence,
          item.analyst_note || "",
          ...item.tags,
          ...item.attack_story,
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return statusOk && queryOk;
    });
  }, [queue, search, statusFilter]);

  const selected = useMemo(
    () => queue.find((item) => item.incident_id === selectedIncidentId) ?? null,
    [queue, selectedIncidentId],
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

  async function handleAssignOwner() {
    if (!selectedIncidentId) return;
    if (!ownerDraft.trim()) {
      setError("Owner boş bırakılamaz");
      return;
    }

    try {
      setActing("assign");
      setError(null);
      setSuccess(null);
      const token = getToken();
      if (!token) throw new Error("Not authenticated");
      const detail = await assignIncident(selectedIncidentId, ownerDraft.trim(), token);
      setQueue((prev) =>
        prev.map((item) =>
          item.incident_id === selectedIncidentId ? { ...item, ...mapIncidentToQueueItem(detail) } : item,
        ),
      );
      setSuccess("Owner güncellendi");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Assign owner başarısız");
    } finally {
      setActing(null);
    }
  }

  async function handleAddNote() {
    if (!selectedIncidentId) return;

    try {
      setActing("note");
      setError(null);
      setSuccess(null);
      const token = getToken();
      if (!token) throw new Error("Not authenticated");
      const detail = await updateIncidentNote(selectedIncidentId, noteDraft, token);
      setQueue((prev) =>
        prev.map((item) =>
          item.incident_id === selectedIncidentId ? { ...item, ...mapIncidentToQueueItem(detail) } : item,
        ),
      );
      setSuccess("Analyst note kaydedildi");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Note update başarısız");
    } finally {
      setActing(null);
    }
  }

  async function handleStatusChange(status: InvestigationStatus, label: string) {
    if (!selectedIncidentId) return;

    try {
      setActing(status);
      setError(null);
      setSuccess(null);
      const token = getToken();
      if (!token) throw new Error("Not authenticated");
      const detail = await updateIncidentStatus(selectedIncidentId, status, token);
      setQueue((prev) =>
        prev.map((item) =>
          item.incident_id === selectedIncidentId ? { ...item, ...mapIncidentToQueueItem(detail) } : item,
        ),
      );
      setSuccess(`${label} tamamlandı`);
    } catch (err) {
      setError(err instanceof Error ? err.message : `${label} başarısız`);
    } finally {
      setActing(null);
    }
  }

  async function handleContainHost() {
    if (!selected) return;
    const hostname = selected.affected_host;
    if (!hostname || hostname === "—") {
      setError("Containment için host bulunamadı");
      return;
    }

    try {
      setActing("contain");
      setError(null);
      setSuccess(null);
      const token = getToken();
      if (!token) throw new Error("Not authenticated");
      await isolateHost({ hostname }, token);
      if (selectedIncidentId) {
        const detail = await updateIncidentStatus(selectedIncidentId, "contained", token);
        setQueue((prev) =>
          prev.map((item) =>
            item.incident_id === selectedIncidentId ? { ...item, ...mapIncidentToQueueItem(detail) } : item,
          ),
        );
      }
      setSuccess(`${hostname} containment kuyruğuna alındı`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Contain host başarısız");
    } finally {
      setActing(null);
    }
  }

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
            Incident-driven investigations with attack chain context
          </div>
          <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
            Queue, attack story, MITRE chain, graph and inline analyst actions.
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
          Incident queue
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard title="Total Cases" value={summary.total} hint="Toplam incident" icon={<Briefcase size={15} />} />
        <SummaryCard title="Open" value={summary.open} hint="Yeni vakalar" icon={<ShieldAlert size={15} />} />
        <SummaryCard title="In Progress" value={summary.active} hint="Aktif analiz" icon={<Workflow size={15} />} />
        <SummaryCard title="Contained" value={summary.contained} hint="Containment sonrası" icon={<Clock3 size={15} />} />
        <SummaryCard title="Closed" value={summary.closed} hint="Tamamlanan" icon={<CheckCircle2 size={15} />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[460px_minmax(0,1fr)]">
        <Panel title="Incident Queue" subtitle="Campaign-driven SOC görünümü">
          <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto]">
            <div className="relative">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="incident id, title, owner, host, story..."
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
              <option value="acknowledged">Acknowledged</option>
              <option value="in_progress">In Progress</option>
              <option value="contained">Contained</option>
              <option value="suppressed">Suppressed</option>
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
              Incident queue yükleniyor...
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
              No active incidents derived from current alerts.
            </div>
          ) : (
            <div className="space-y-3">
              {filtered.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setSelectedIncidentId(item.incident_id)}
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
                    <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${confidenceBadge(item.confidence)}`}>
                      {item.confidence}
                    </span>
                  </div>

                  <div className="mt-3 text-sm font-semibold">{item.title}</div>
                  <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                    {item.id} · {item.affected_host} · {item.related_alerts} related alerts
                  </div>
                  <div className="mt-2 text-xs line-clamp-2" style={{ color: "var(--muted-strong)" }}>
                    {item.summary}
                  </div>
                  <div className="mt-2 text-xs" style={{ color: "var(--muted-strong)" }}>
                    Owner: {item.owner} · Updated: {relativeTime(item.updated_at)}
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="SOC Console" subtitle="Attack story, MITRE chain, graph, timeline and inline actions">
          {error ? (
            <div className="mb-4 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300">
              {error}
            </div>
          ) : null}

          {success ? (
            <div className="mb-4 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-300">
              {success}
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
              Incident seçilmedi.
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
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${confidenceBadge(selected.confidence)}`}>
                    confidence: {selected.confidence}
                  </span>
                </div>

                <div className="text-base font-black">{selected.title}</div>
                <div className="mt-3 text-sm leading-relaxed" style={{ color: "var(--muted-strong)" }}>
                  {selected.summary}
                </div>
              </section>

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <InfoCard label="Incident ID" value={selected.id} />
                <InfoCard label="Owner" value={selected.owner} />
                <InfoCard label="Primary Host" value={selected.affected_host} />
                <InfoCard label="Campaign" value={selected.campaign_family} />
                <InfoCard label="Related Alerts" value={String(selected.related_alerts)} />
                <InfoCard label="Spread Depth" value={String(selected.spread_depth)} />
                <InfoCard label="Created At" value={fmtDate(selected.created_at)} />
                <InfoCard label="Updated At" value={fmtDate(selected.updated_at)} />
              </div>

              <div className="grid gap-4 xl:grid-cols-[1fr_0.95fr]">
                <ActionCard title="Attack Story" icon={<Milestone size={13} />}>
                  {selected.attack_story?.length ? (
                    <ol className="space-y-3">
                      {selected.attack_story.map((line, index) => (
                        <li
                          key={`${line}-${index}`}
                          className="rounded-2xl border px-4 py-3 text-sm"
                          style={{
                            borderColor: "var(--border)",
                            background: "var(--surface-0)",
                          }}
                        >
                          <span
                            className="mr-3 inline-flex h-6 w-6 items-center justify-center rounded-full text-xs font-black"
                            style={{
                              background: "var(--foreground)",
                              color: "var(--background)",
                            }}
                          >
                            {index + 1}
                          </span>
                          {line}
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <div className="text-sm" style={{ color: "var(--muted)" }}>
                      Attack story bulunamadı.
                    </div>
                  )}
                </ActionCard>

                <ActionCard title="Recommended Actions" icon={<Sparkles size={13} />}>
                  {selected.recommended_actions?.length ? (
                    <div className="space-y-2">
                      {selected.recommended_actions.map((action, index) => (
                        <div
                          key={`${action}-${index}`}
                          className="rounded-xl border px-3 py-3 text-sm"
                          style={{
                            borderColor: "var(--border)",
                            background: "var(--surface-0)",
                          }}
                        >
                          {action}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm" style={{ color: "var(--muted)" }}>
                      Recommended action bulunamadı.
                    </div>
                  )}
                </ActionCard>
              </div>

              <ActionCard title="MITRE Attack Chain" icon={<Target size={13} />}>
                {loadingDetail ? (
                  <div className="text-sm" style={{ color: "var(--muted)" }}>
                    Attack chain yükleniyor...
                  </div>
                ) : attackChain?.steps?.length ? (
                  <div className="space-y-4">
                    {attackChain.kill_chain_phases?.length ? (
                      <div className="flex flex-wrap gap-2">
                        {attackChain.kill_chain_phases.map((phase) => (
                          <span
                            key={phase}
                            className="inline-flex rounded-full border px-3 py-1 text-xs"
                            style={{
                              borderColor: "var(--border)",
                              background: "var(--surface-0)",
                              color: "var(--muted-strong)",
                            }}
                          >
                            {phase}
                          </span>
                        ))}
                      </div>
                    ) : null}

                    <div className="space-y-3">
                      {attackChain.steps.map((step) => (
                        <div key={`${step.step}-${step.node_id}`} className="flex gap-3">
                          <div className="flex w-10 shrink-0 flex-col items-center">
                            <div
                              className="inline-flex h-8 w-8 items-center justify-center rounded-full text-xs font-black"
                              style={{
                                background: "var(--foreground)",
                                color: "var(--background)",
                              }}
                            >
                              {step.step}
                            </div>
                            <div
                              className="mt-2 w-px flex-1"
                              style={{ background: "var(--border)" }}
                            />
                          </div>

                          <div
                            className="flex-1 rounded-2xl border p-4"
                            style={{
                              borderColor: "var(--border)",
                              background: "var(--surface-0)",
                            }}
                          >
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-sm font-semibold">{step.stage}</span>
                              {step.technique_id ? (
                                <span
                                  className="inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                                  style={{
                                    borderColor: "var(--border)",
                                    background: "var(--surface-1)",
                                    color: "var(--muted-strong)",
                                  }}
                                >
                                  {step.technique_id}
                                </span>
                              ) : null}
                            </div>

                            <div className="mt-2 text-sm font-semibold">{step.label}</div>
                            {step.technique_name ? (
                              <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                                {step.technique_name}
                              </div>
                            ) : null}
                            {step.evidence ? (
                              <div className="mt-2 text-xs break-all" style={{ color: "var(--muted-strong)" }}>
                                {step.evidence}
                              </div>
                            ) : null}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-sm" style={{ color: "var(--muted)" }}>
                    Attack chain bulunamadı.
                  </div>
                )}
              </ActionCard>

              <div className="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
                <ActionCard title="Analyst Workspace" icon={<StickyNote size={13} />}>
                  <div className="space-y-4">
                    <div>
                      <label
                        className="mb-2 block text-xs font-bold uppercase tracking-[0.18em]"
                        style={{ color: "var(--muted)" }}
                      >
                        Owner
                      </label>
                      <div className="flex gap-2">
                        <input
                          value={ownerDraft}
                          onChange={(e) => setOwnerDraft(e.target.value)}
                          placeholder="Assign owner..."
                          className="w-full rounded-xl border px-3 py-2 text-sm outline-none"
                          style={{
                            borderColor: "var(--border)",
                            background: "var(--surface-0)",
                            color: "var(--foreground)",
                          }}
                        />
                        <button
                          onClick={handleAssignOwner}
                          disabled={acting !== null}
                          className="rounded-xl px-4 py-2 text-sm font-medium transition disabled:opacity-60"
                          style={{
                            background: "var(--foreground)",
                            color: "var(--background)",
                          }}
                        >
                          <span className="inline-flex items-center gap-2">
                            <UserPlus2 size={14} />
                            {acting === "assign" ? "..." : "Save"}
                          </span>
                        </button>
                      </div>
                    </div>

                    <div>
                      <label
                        className="mb-2 block text-xs font-bold uppercase tracking-[0.18em]"
                        style={{ color: "var(--muted)" }}
                      >
                        Analyst Note
                      </label>
                      <textarea
                        value={noteDraft}
                        onChange={(e) => setNoteDraft(e.target.value)}
                        placeholder="Write triage notes, findings, next steps..."
                        rows={6}
                        className="w-full rounded-xl border px-3 py-3 text-sm outline-none"
                        style={{
                          borderColor: "var(--border)",
                          background: "var(--surface-0)",
                          color: "var(--foreground)",
                        }}
                      />
                      <div className="mt-3 flex justify-end">
                        <button
                          onClick={handleAddNote}
                          disabled={acting !== null}
                          className="rounded-xl border px-4 py-2 text-sm font-medium transition disabled:opacity-60"
                          style={{
                            borderColor: "var(--border)",
                            background: "var(--surface-0)",
                          }}
                        >
                          <span className="inline-flex items-center gap-2">
                            <StickyNote size={14} />
                            {acting === "note" ? "Saving..." : "Save Note"}
                          </span>
                        </button>
                      </div>
                    </div>
                  </div>
                </ActionCard>

                <ActionCard title="Response Actions" icon={<Shield size={13} />}>
                  <div className="space-y-3">
                    <button
                      onClick={handleContainHost}
                      disabled={acting !== null}
                      className="flex w-full items-center justify-center gap-2 rounded-xl border px-4 py-3 text-sm font-medium transition disabled:opacity-60"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-0)",
                      }}
                    >
                      <Shield size={14} />
                      {acting === "contain" ? "Containing..." : "Contain Host"}
                    </button>

                    <button
                      onClick={() => handleStatusChange("in_progress", "In progress update")}
                      disabled={acting !== null}
                      className="flex w-full items-center justify-center gap-2 rounded-xl border px-4 py-3 text-sm font-medium transition disabled:opacity-60"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-0)",
                      }}
                    >
                      <BadgeInfo size={14} />
                      {acting === "in_progress" ? "Updating..." : "Mark In Progress"}
                    </button>

                    <button
                      onClick={() => handleStatusChange("acknowledged", "Acknowledge")}
                      disabled={acting !== null}
                      className="flex w-full items-center justify-center gap-2 rounded-xl border px-4 py-3 text-sm font-medium transition disabled:opacity-60"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-0)",
                      }}
                    >
                      <CheckCircle2 size={14} />
                      {acting === "acknowledged" ? "Updating..." : "Acknowledge"}
                    </button>

                    <button
                      onClick={() => handleStatusChange("closed", "Close case")}
                      disabled={acting !== null}
                      className="flex w-full items-center justify-center gap-2 rounded-xl border px-4 py-3 text-sm font-medium transition disabled:opacity-60"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-0)",
                      }}
                    >
                      <CheckCheck size={14} />
                      {acting === "closed" ? "Closing..." : "Close Case"}
                    </button>
                  </div>
                </ActionCard>
              </div>

              <ActionCard title="Case Activity Feed" icon={<Activity size={13} />}>
                {loadingDetail ? (
                  <div className="text-sm" style={{ color: "var(--muted)" }}>
                    Timeline yükleniyor...
                  </div>
                ) : timeline.length ? (
                  <div className="space-y-3">
                    {timeline.map((item, index) => (
                      <div key={item.id || `${item.event_type}-${index}`} className="flex gap-3">
                        <div className="flex w-10 shrink-0 flex-col items-center">
                          <div
                            className={`inline-flex h-8 w-8 items-center justify-center rounded-full border text-xs font-black ${timelineTone(item.event_type)}`}
                          >
                            {index + 1}
                          </div>
                          {index < timeline.length - 1 ? (
                            <div className="mt-2 w-px flex-1" style={{ background: "var(--border)" }} />
                          ) : null}
                        </div>

                        <div
                          className="flex-1 rounded-2xl border p-4"
                          style={{
                            borderColor: "var(--border)",
                            background: "var(--surface-0)",
                          }}
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${timelineTone(item.event_type)}`}>
                              {item.event_type}
                            </span>
                            <span className="text-sm font-semibold">{item.title}</span>
                          </div>
                          <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                            {relativeTime(item.created_at)} · {fmtDate(item.created_at)} · actor: {item.actor || "system"}
                          </div>
                          {item.details ? (
                            <div className="mt-2 text-xs whitespace-pre-wrap break-all" style={{ color: "var(--muted-strong)" }}>
                              {item.details}
                            </div>
                          ) : null}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm" style={{ color: "var(--muted)" }}>
                    Timeline verisi bulunamadı.
                  </div>
                )}
              </ActionCard>

              <ActionCard title="Command & Response Context" icon={<TerminalSquare size={13} />}>
                <div className="text-sm" style={{ color: "var(--muted-strong)" }}>
                  Response execution olayları timeline içinde gösteriliyor. Bir sonraki adımda bunu ayrı command result paneline bağlayabiliriz.
                </div>
              </ActionCard>

              {loadingGraph ? (
                <div
                  className="rounded-2xl border p-6 text-sm"
                  style={{
                    borderColor: "var(--border)",
                    background: "var(--surface-1)",
                    color: "var(--muted)",
                  }}
                >
                  Incident graph yükleniyor...
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
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

export default function InvestigationsPagePage() {
  return (
    <AuthGuard>
      <InvestigationsPage />
    </AuthGuard>
  );
}

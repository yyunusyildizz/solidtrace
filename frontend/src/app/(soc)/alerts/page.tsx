"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Search,
  ShieldAlert,
  UserPlus,
  Workflow,
  XCircle,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { HostResponseActions } from "@/components/soc/host-response-actions";
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
import { clearAuthSession, getToken } from "@/lib/auth";

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "WARNING" | "INFO";
type StatusFilter = "ALL" | "open" | "acknowledged" | "resolved";

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
      acknowledged: alerts.filter((a) => (a.status || "").toLowerCase() === "acknowledged").length,
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

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div
            className="text-[11px] font-bold uppercase tracking-[0.24em]"
            style={{ color: "var(--muted)" }}
          >
            Alert Triage
          </div>
          <div className="mt-2 text-2xl font-black tracking-tight">
            Prioritize, assign and escalate high-signal detections
          </div>
          <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
            Queue-driven analyst workflow with direct handoff into investigations and response.
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

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard title="Total Alerts" value={summary.total} hint="Toplam uyarı" icon={<Activity size={15} />} />
        <SummaryCard title="Open" value={summary.open} hint="Yeni / aksiyon bekliyor" icon={<ShieldAlert size={15} />} />
        <SummaryCard title="Acknowledged" value={summary.acknowledged} hint="Analist üzerinde" icon={<Workflow size={15} />} />
        <SummaryCard title="Resolved" value={summary.resolved} hint="Kapatılan uyarılar" icon={<CheckCircle2 size={15} />} />
        <SummaryCard title="Critical" value={summary.critical} hint="En yüksek öncelik" icon={<AlertTriangle size={15} />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.02fr_0.98fr]">
        <Panel title="Alert Queue" subtitle="SOC triage görünümü">
          <div className="mb-4 grid gap-3 lg:grid-cols-[1fr_auto_auto]">
            <div className="relative">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="id, host, user, rule, process..."
                className="w-full rounded-2xl border px-10 py-3 text-sm outline-none transition"
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
            <div className="space-y-3">
              {filteredAlerts.map((alert) => {
                const isSelected = selectedAlert?.id === alert.id;

                return (
                  <button
                    key={alert.id}
                    onClick={() => loadAlertDetail(alert.id)}
                    className="w-full rounded-2xl border p-4 text-left transition"
                    style={
                      isSelected
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
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityTone(alert.severity)}`}>
                        {alert.severity || "INFO"}
                      </span>
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusTone(alert.status)}`}>
                        {alert.status || "open"}
                      </span>
                    </div>

                    <div className="mt-3 text-sm font-semibold">{displayTitle(alert)}</div>

                    <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                      {alert.id} · {alert.hostname || "unknown-host"} · {alert.username || "unknown-user"}
                    </div>

                    <div className="mt-2 flex flex-wrap gap-3 text-xs" style={{ color: "var(--muted-strong)" }}>
                      <span>Risk: {alert.risk_score ?? 0}</span>
                      <span>Created: {relativeTime(alert.created_at)}</span>
                      <span>Owner: {alert.assigned_to || "Unassigned"}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </Panel>

        <Panel title="Alert Detail" subtitle="Triage, ownership, escalation and response panel">
          {error ? (
            <div className="mb-4 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300">
              {error}
            </div>
          ) : null}

          {!selectedAlert ? (
            <div
              className="rounded-2xl border p-8 text-center text-sm"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted)",
              }}
            >
              İncelemek için soldan bir alert seç.
            </div>
          ) : detailLoading ? (
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
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityTone(selectedAlert.severity)}`}>
                    {selectedAlert.severity || "INFO"}
                  </span>
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusTone(selectedAlert.status)}`}>
                    {selectedAlert.status || "open"}
                  </span>
                </div>

                <div className="text-base font-black">{displayTitle(selectedAlert)}</div>
                <div className="mt-2 text-sm" style={{ color: "var(--muted-strong)" }}>
                  {selectedAlert.details || "No alert details available."}
                </div>
              </section>

              <div className="grid gap-3 md:grid-cols-2">
                <InfoCard label="Alert ID" value={selectedAlert.id} />
                <InfoCard label="Hostname" value={selectedAlert.hostname || "—"} />
                <InfoCard label="Username" value={selectedAlert.username || "—"} />
                <InfoCard label="Type" value={selectedAlert.type || "—"} />
                <InfoCard label="Rule" value={selectedAlert.rule || "—"} />
                <InfoCard label="Risk Score" value={String(selectedAlert.risk_score ?? 0)} />
                <InfoCard label="PID" value={selectedAlert.pid != null ? String(selectedAlert.pid) : "—"} />
                <InfoCard label="Created At" value={fmtDate(selectedAlert.created_at)} />
              </div>

              {selectedAlert.hostname ? (
                <section
                  className="rounded-2xl border p-4"
                  style={{ borderColor: "var(--border)" }}
                >
                  <div
                    className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
                    style={{ color: "var(--muted)" }}
                  >
                    Response Actions
                  </div>
                  <HostResponseActions
                    hostname={selectedAlert.hostname}
                    compact
                    onActionComplete={refreshSelected}
                  />
                </section>
              ) : null}

              <section
                className="rounded-2xl border p-4"
                style={{ borderColor: "var(--border)" }}
              >
                <div
                  className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
                  style={{ color: "var(--muted)" }}
                >
                  Command Line
                </div>
                <div
                  className="rounded-xl p-3 font-mono-ui text-xs"
                  style={{
                    background: "var(--surface-1)",
                    color: "var(--muted-strong)",
                  }}
                >
                  {selectedAlert.command_line || "No command line data"}
                </div>
              </section>

              <section
                className="rounded-2xl border p-4"
                style={{ borderColor: "var(--border)" }}
              >
                <div
                  className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
                  style={{ color: "var(--muted)" }}
                >
                  Assignment
                </div>

                <div className="grid gap-3 md:grid-cols-[1fr_auto_auto]">
                  <input
                    value={assignTo}
                    onChange={(e) => setAssignTo(e.target.value)}
                    placeholder="analyst username"
                    className="rounded-xl border px-4 py-3 text-sm outline-none transition"
                    style={{
                      borderColor: "var(--border)",
                      background: "var(--surface-0)",
                      color: "var(--foreground)",
                    }}
                  />

                  <button
                    disabled={actionLoading || !assignTo.trim()}
                    onClick={() => runAction((token) => assignAlert(selectedAlert.id, assignTo.trim(), token))}
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

                <div className="mt-3 text-xs" style={{ color: "var(--muted)" }}>
                  Current owner: {selectedAlert.assigned_to || "Unassigned"}
                </div>
              </section>

              <section
                className="rounded-2xl border p-4"
                style={{ borderColor: "var(--border)" }}
              >
                <div
                  className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
                  style={{ color: "var(--muted)" }}
                >
                  Analyst Note
                </div>

                <textarea
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  rows={4}
                  className="w-full rounded-xl border px-4 py-3 text-sm outline-none transition"
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
                    onClick={() => runAction((token) => updateAlertNote(selectedAlert.id, noteDraft, token))}
                    className="rounded-xl px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
                    style={{
                      background: "var(--foreground)",
                      color: "var(--background)",
                    }}
                  >
                    Save Note
                  </button>
                </div>
              </section>

              <section
                className="rounded-2xl border p-4"
                style={{ borderColor: "var(--border)" }}
              >
                <div
                  className="mb-3 text-xs font-bold uppercase tracking-[0.2em]"
                  style={{ color: "var(--muted)" }}
                >
                  Workflow Actions
                </div>

                <div className="flex flex-wrap gap-3">
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
                    onClick={() => router.push(`/investigations?alert_id=${selectedAlert.id}`)}
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
              </section>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
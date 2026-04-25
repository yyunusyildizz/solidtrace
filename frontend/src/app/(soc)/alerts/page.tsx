"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  AlertTriangle,
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

function AlertInspector({
  selectedAlert,
  detailLoading,
  actionLoading,
  assignTo,
  setAssignTo,
  noteDraft,
  setNoteDraft,
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
            refreshSelected={refreshSelected}
            runAction={runAction}
            onInvestigate={(alertId) => router.push(`/investigations?alert_id=${alertId}`)}
          />
        </div>
      </div>
    </div>
  );
}

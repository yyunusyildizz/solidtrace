"use client";

import { useEffect, useMemo, useState } from "react";
import {
  CheckCheck,
  Loader2,
  RefreshCw,
  Search,
  UserPlus,
  UserX,
  RotateCcw,
  CheckCircle2,
  StickyNote,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { SeverityBadge } from "@/components/soc/ui/severity-badge";
import { StatusBadge } from "@/components/soc/ui/status-badge";
import { Drawer } from "@/components/soc/ui/drawer";
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

function riskClass(score?: number | null) {
  const n = Number(score || 0);
  if (n >= 80) return "bg-red-500";
  if (n >= 60) return "bg-orange-500";
  if (n >= 40) return "bg-amber-500";
  return "bg-emerald-500";
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const [assignTo, setAssignTo] = useState("analyst");
  const [note, setNote] = useState("");

  const [loading, setLoading] = useState(true);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState("");

  const token = typeof window !== "undefined" ? localStorage.getItem("soc_token") || undefined : undefined;

  const loadAlerts = async () => {
    setLoading(true);
    setError("");
    try {
      const rows = await getAlerts(token, 150);
      setAlerts(rows);
    } catch (err) {
      console.error(err);
      setError("Alert listesi alınamadı.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openAlert = async (alertId: string) => {
    setDrawerOpen(true);
    setDrawerLoading(true);
    try {
      const detail = await getAlertDetail(alertId, token);
      setSelectedAlert(detail);
      setNote(detail.analyst_note || "");
      setAssignTo(detail.assigned_to || "analyst");
    } catch (err) {
      console.error(err);
    } finally {
      setDrawerLoading(false);
    }
  };

  const runAction = async (key: string, fn: () => Promise<unknown>) => {
    if (!selectedAlert) return;
    setActionLoading(key);
    try {
      await fn();
      const detail = await getAlertDetail(selectedAlert.id, token);
      setSelectedAlert(detail);
      setNote(detail.analyst_note || "");
      setAssignTo(detail.assigned_to || "analyst");
      await loadAlerts();
    } catch (err) {
      console.error(err);
      alert("İşlem başarısız.");
    } finally {
      setActionLoading(null);
    }
  };

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      const severityOk =
        severityFilter === "ALL" || (alert.severity || "").toUpperCase() === severityFilter;

      const statusOk =
        statusFilter === "ALL" || (alert.status || "").toLowerCase() === statusFilter.toLowerCase();

      const queryOk =
        !q ||
        [
          alert.hostname,
          alert.username,
          alert.rule,
          alert.type,
          alert.details,
          alert.command_line,
          String(alert.pid || ""),
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return severityOk && statusOk && queryOk;
    });
  }, [alerts, search, severityFilter, statusFilter]);

  return (
    <div className="grid gap-6 xl:grid-cols-[1.35fr_0.65fr]">
      <Panel
        title="Alert Queue"
        subtitle="SOC triage kuyruğu"
        action={
          <button
            onClick={loadAlerts}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 px-3 py-2 text-sm text-zinc-700 transition hover:bg-zinc-50 dark:border-white/10 dark:text-zinc-200 dark:hover:bg-white/[0.05]"
          >
            <RefreshCw size={14} />
            Yenile
          </button>
        }
      >
        <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto_auto]">
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="rule, host, user, detay..."
              className="w-full rounded-2xl border border-zinc-200 bg-white px-10 py-3 text-sm outline-none transition focus:border-zinc-400 dark:border-white/10 dark:bg-white/[0.03] dark:text-white dark:focus:border-white/20"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-2xl border border-zinc-200 bg-white px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-white/[0.03]"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="WARNING">Warning</option>
            <option value="INFO">Info</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-2xl border border-zinc-200 bg-white px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-white/[0.03]"
          >
            <option value="ALL">All Status</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        {error ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400">
            {error}
          </div>
        ) : null}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-zinc-500 dark:text-zinc-400">
            <Loader2 size={16} className="animate-spin" />
            Alertler yükleniyor...
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-8 text-center text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
            Gösterilecek alert yok.
          </div>
        ) : (
          <div className="overflow-hidden rounded-2xl border border-zinc-200 dark:border-white/10">
            <div className="grid grid-cols-[1.3fr_0.8fr_0.45fr_0.55fr_0.5fr_0.6fr] gap-3 border-b border-zinc-200 bg-zinc-50 px-4 py-3 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
              <div>Rule / Details</div>
              <div>Host / User</div>
              <div>Severity</div>
              <div>Status</div>
              <div>Risk</div>
              <div>Time</div>
            </div>

            {filteredAlerts.map((alert) => (
              <button
                key={alert.id}
                onClick={() => openAlert(alert.id)}
                className="grid w-full grid-cols-[1.3fr_0.8fr_0.45fr_0.55fr_0.5fr_0.6fr] gap-3 border-b border-zinc-200 px-4 py-4 text-left transition hover:bg-zinc-50 last:border-b-0 dark:border-white/10 dark:hover:bg-white/[0.03]"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold">{alert.rule || alert.type || "Alert"}</div>
                  <div className="mt-1 truncate text-xs text-zinc-500 dark:text-zinc-400">
                    {alert.details || "Detay yok"}
                  </div>
                </div>

                <div className="min-w-0">
                  <div className="truncate text-sm">{alert.hostname || "unknown-host"}</div>
                  <div className="mt-1 truncate text-xs text-zinc-500 dark:text-zinc-400">
                    {alert.username || "SYSTEM"}
                  </div>
                </div>

                <div className="pt-0.5">
                  <SeverityBadge severity={alert.severity} />
                </div>

                <div className="pt-0.5">
                  <StatusBadge status={alert.status} />
                </div>

                <div>
                  <div className="text-sm font-bold">{alert.risk_score || 0}</div>
                  <div className="mt-2 h-2 rounded-full bg-zinc-200 dark:bg-white/10">
                    <div
                      className={`h-2 rounded-full ${riskClass(alert.risk_score)}`}
                      style={{ width: `${Math.min(100, Number(alert.risk_score || 0))}%` }}
                    />
                  </div>
                </div>

                <div className="text-xs text-zinc-500 dark:text-zinc-400">
                  <div>{relativeTime(alert.created_at)}</div>
                  <div className="mt-1">{fmtDate(alert.created_at)}</div>
                </div>
              </button>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Triage Guide" subtitle="Hızlı operasyon rehberi">
        <div className="space-y-4 text-sm">
          <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
            <div className="font-bold">1. Önce kritik ve açık alertler</div>
            <div className="mt-1 text-zinc-600 dark:text-zinc-400">
              Critical + open kombinasyonu ilk bakılacak kuyruğu oluşturur.
            </div>
          </div>

          <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
            <div className="font-bold">2. Host ve user ilişkisini kontrol et</div>
            <div className="mt-1 text-zinc-600 dark:text-zinc-400">
              Aynı host veya kullanıcı üzerinde tekrarlayan kurallar daha kritik olabilir.
            </div>
          </div>

          <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
            <div className="font-bold">3. Sahiplik ver</div>
            <div className="mt-1 text-zinc-600 dark:text-zinc-400">
              Assign edilmemiş alertler operasyon kuyruğunu kirletir.
            </div>
          </div>
        </div>
      </Panel>

      <Drawer
        open={drawerOpen}
        title="Alert Detail"
        onClose={() => {
          setDrawerOpen(false);
          setSelectedAlert(null);
        }}
      >
        {drawerLoading || !selectedAlert ? (
          <div className="flex items-center gap-2 text-sm text-zinc-500 dark:text-zinc-400">
            <Loader2 size={16} className="animate-spin" />
            Alert detayı yükleniyor...
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid gap-3 md:grid-cols-2">
              <InfoCard label="Rule" value={selectedAlert.rule || selectedAlert.type || "—"} />
              <InfoCard label="Hostname" value={selectedAlert.hostname || "—"} />
              <InfoCard label="User" value={selectedAlert.username || "—"} />
              <InfoCard label="PID" value={selectedAlert.pid ? String(selectedAlert.pid) : "—"} />
              <InfoCard label="Severity" value={<SeverityBadge severity={selectedAlert.severity} />} />
              <InfoCard label="Status" value={<StatusBadge status={selectedAlert.status} />} />
              <InfoCard label="Assigned To" value={selectedAlert.assigned_to || "—"} />
              <InfoCard label="Created At" value={fmtDate(selectedAlert.created_at)} />
            </div>

            <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
              <div className="mb-2 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                Details
              </div>
              <div className="whitespace-pre-wrap text-sm text-zinc-700 dark:text-zinc-300">
                {selectedAlert.details || "Detay yok"}
              </div>
            </section>

            <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
              <div className="mb-2 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                Command Line
              </div>
              <div className="whitespace-pre-wrap break-all rounded-xl bg-zinc-50 p-3 font-mono text-xs text-zinc-700 dark:bg-white/[0.04] dark:text-zinc-300">
                {selectedAlert.command_line || "Command line yok"}
              </div>
            </section>

            <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
              <div className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                Assignment
              </div>
              <div className="flex gap-3">
                <input
                  value={assignTo}
                  onChange={(e) => setAssignTo(e.target.value)}
                  className="flex-1 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none dark:border-white/10 dark:bg-white/[0.03]"
                  placeholder="analyst"
                />
                <button
                  onClick={() => runAction("assign", () => assignAlert(selectedAlert.id, assignTo, token))}
                  disabled={actionLoading === "assign"}
                  className="inline-flex items-center gap-2 rounded-xl bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-800 disabled:opacity-50 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-200"
                >
                  <UserPlus size={14} />
                  Assign
                </button>
                <button
                  onClick={() => runAction("unassign", () => unassignAlert(selectedAlert.id, token))}
                  disabled={actionLoading === "unassign"}
                  className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 px-4 py-2 text-sm font-medium transition hover:bg-zinc-50 disabled:opacity-50 dark:border-white/10 dark:hover:bg-white/[0.05]"
                >
                  <UserX size={14} />
                  Unassign
                </button>
              </div>
            </section>

            <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
              <div className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                Analyst Note
              </div>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={5}
                className="w-full rounded-xl border border-zinc-200 bg-white px-3 py-3 text-sm outline-none dark:border-white/10 dark:bg-white/[0.03]"
                placeholder="İnceleme notu..."
              />
              <div className="mt-3">
                <button
                  onClick={() => runAction("note", () => updateAlertNote(selectedAlert.id, note, token))}
                  disabled={actionLoading === "note"}
                  className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 px-4 py-2 text-sm font-medium transition hover:bg-zinc-50 disabled:opacity-50 dark:border-white/10 dark:hover:bg-white/[0.05]"
                >
                  <StickyNote size={14} />
                  Save Note
                </button>
              </div>
            </section>

            <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
              <div className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                Workflow Actions
              </div>

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={() => runAction("ack", () => acknowledgeAlert(selectedAlert.id, token))}
                  disabled={actionLoading === "ack"}
                  className="inline-flex items-center gap-2 rounded-xl bg-amber-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-amber-500 disabled:opacity-50"
                >
                  <CheckCheck size={14} />
                  Acknowledge
                </button>

                <button
                  onClick={() => runAction("resolve", () => resolveAlert(selectedAlert.id, note, token))}
                  disabled={actionLoading === "resolve"}
                  className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:opacity-50"
                >
                  <CheckCircle2 size={14} />
                  Resolve
                </button>

                <button
                  onClick={() => runAction("reopen", () => reopenAlert(selectedAlert.id, token))}
                  disabled={actionLoading === "reopen"}
                  className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 px-4 py-2 text-sm font-medium transition hover:bg-zinc-50 disabled:opacity-50 dark:border-white/10 dark:hover:bg-white/[0.05]"
                >
                  <RotateCcw size={14} />
                  Reopen
                </button>
              </div>
            </section>
          </div>
        )}
      </Drawer>
    </div>
  );
}

function InfoCard({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
      <div className="mb-2 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
        {label}
      </div>
      <div className="text-sm text-zinc-800 dark:text-zinc-200">{value}</div>
    </div>
  );
}
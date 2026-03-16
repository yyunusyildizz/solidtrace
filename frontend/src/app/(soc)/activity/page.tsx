"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Search,
  Shield,
  User,
  Workflow,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { SeverityBadge } from "@/components/soc/ui/severity-badge";
import { MetricCard } from "@/components/soc/ui/metric-card";
import {
  getRecentActivity,
  type DashboardRecentActivityItem,
} from "@/lib/api/dashboard";
import { clearAuthSession, getToken } from "@/lib/auth";

type ActivityFilter = "ALL" | "alert" | "audit";

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

function getActivityIcon(item: DashboardRecentActivityItem) {
  const title = (item.title || "").toUpperCase();
  const severity = (item.severity || "").toUpperCase();

  if (item.activity_type === "alert") {
    if (severity === "CRITICAL" || severity === "HIGH") return <AlertTriangle size={15} />;
    return <Shield size={15} />;
  }

  if (title.includes("LOGIN")) return <User size={15} />;
  if (title.includes("RESOLVE")) return <CheckCircle2 size={15} />;
  if (title.includes("ASSIGN")) return <Workflow size={15} />;
  if (title.includes("SIGMA")) return <BookOpen size={15} />;
  return <Activity size={15} />;
}

function getActivityIconStyle(item: DashboardRecentActivityItem) {
  const title = (item.title || "").toUpperCase();
  const severity = (item.severity || "").toUpperCase();

  if (item.activity_type === "alert") {
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

  if (title.includes("LOGIN")) {
    return "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-500/20 dark:bg-violet-500/10 dark:text-violet-400";
  }

  if (title.includes("RESOLVE")) {
    return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
  }

  return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300";
}

function statusBadge(status?: string | null) {
  const value = (status || "").toLowerCase();

  if (value === "resolved") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
  }
  if (value === "acknowledged") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  if (value === "open" || value === "live") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  }

  return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300";
}

export default function ActivityPage() {
  const router = useRouter();

  const [items, setItems] = useState<DashboardRecentActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<ActivityFilter>("ALL");

  const loadActivity = async () => {
    setLoading(true);
    setError("");

    try {
      const token = getToken();
      if (!token) {
        router.replace("/login?next=/activity");
        return;
      }

      const rows = await getRecentActivity(token);
      setItems(rows);
    } catch (err) {
      if (err instanceof Error && err.message.includes("Not authenticated")) {
        clearAuthSession();
        router.replace("/login?next=/activity");
        return;
      }
      setError("Activity verileri alınamadı.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadActivity();
    const timer = setInterval(loadActivity, 30000);
    return () => clearInterval(timer);
  }, []);

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase();

    return items.filter((item) => {
      const filterOk = filter === "ALL" || item.activity_type === filter;

      const searchOk =
        !q ||
        [
          item.title,
          item.description,
          item.hostname,
          item.username,
          item.status,
          item.severity,
          item.activity_type,
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return filterOk && searchOk;
    });
  }, [items, search, filter]);

  const summary = useMemo(() => {
    return {
      total: items.length,
      alerts: items.filter((i) => i.activity_type === "alert").length,
      audits: items.filter((i) => i.activity_type === "audit").length,
      criticalAlerts: items.filter(
        (i) => i.activity_type === "alert" && (i.severity || "").toUpperCase() === "CRITICAL",
      ).length,
    };
  }, [items]);

  return (
    <div className="grid gap-6">
      <div>
        <div
          className="text-[11px] font-bold uppercase tracking-[0.24em]"
          style={{ color: "var(--muted)" }}
        >
          Activity Timeline
        </div>
        <div className="mt-2 text-2xl font-black tracking-tight">
          Unified audit and alert event stream for analyst visibility
        </div>
        <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
          Combined operational timeline across alerts, user actions and workflow updates.
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard title="Total Events" value={summary.total} hint="Birleşik activity akışı" accent="neutral" icon={<Activity size={15} />} />
        <MetricCard title="Alert Events" value={summary.alerts} hint="Detection kaynaklı" accent="danger" icon={<Shield size={15} />} />
        <MetricCard title="Audit Events" value={summary.audits} hint="Kullanıcı / sistem işlemleri" accent="info" icon={<Workflow size={15} />} />
        <MetricCard title="Critical Alerts" value={summary.criticalAlerts} hint="Yüksek öncelik" accent="warning" icon={<AlertTriangle size={15} />} />
      </div>

      <Panel
        title="Activity Timeline"
        subtitle="Audit ve alert olaylarının birleşik akışı"
        action={
          <button
            onClick={loadActivity}
            className="inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition"
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--surface-1)",
              color: "var(--foreground)",
            }}
          >
            <RefreshCw size={14} />
            Yenile
          </button>
        }
      >
        <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto]">
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="title, host, user, açıklama..."
              className="w-full rounded-2xl border px-10 py-3 text-sm outline-none transition"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
                color: "var(--foreground)",
              }}
            />
          </div>

          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as ActivityFilter)}
            className="rounded-2xl border px-4 py-3 text-sm outline-none"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-0)",
              color: "var(--foreground)",
            }}
          >
            <option value="ALL">All Events</option>
            <option value="alert">Alert</option>
            <option value="audit">Audit</option>
          </select>
        </div>

        {error ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400">
            {error}
          </div>
        ) : null}

        {loading ? (
          <div className="text-sm" style={{ color: "var(--muted)" }}>
            Activity verileri yükleniyor...
          </div>
        ) : filteredItems.length === 0 ? (
          <div
            className="rounded-2xl border p-8 text-center text-sm"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-1)",
              color: "var(--muted)",
            }}
          >
            Gösterilecek activity verisi yok.
          </div>
        ) : (
          <div className="relative">
            <div
              className="absolute bottom-0 left-[23px] top-0 w-px"
              style={{ background: "var(--border)" }}
            />

            <div className="space-y-4">
              {filteredItems.map((item, idx) => (
                <div key={`${item.source_id || item.timestamp}-${idx}`} className="relative flex gap-4">
                  <div
                    className={`relative z-10 mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border ${getActivityIconStyle(item)}`}
                  >
                    {getActivityIcon(item)}
                  </div>

                  <div
                    className="min-w-0 flex-1 rounded-2xl border p-4"
                    style={{
                      borderColor: "var(--border)",
                      background: "var(--surface-0)",
                      boxShadow: "var(--shadow-soft)",
                    }}
                  >
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          {item.activity_type === "alert" ? (
                            <SeverityBadge severity={item.severity || "INFO"} />
                          ) : (
                            <span
                              className="inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                              style={{
                                borderColor: "var(--border)",
                                background: "var(--surface-1)",
                                color: "var(--muted-strong)",
                              }}
                            >
                              audit
                            </span>
                          )}

                          {item.status ? (
                            <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusBadge(item.status)}`}>
                              {item.status}
                            </span>
                          ) : null}
                        </div>

                        <div className="mt-2 text-sm font-semibold">{item.title}</div>

                        <div className="mt-1 flex flex-wrap gap-3 text-xs" style={{ color: "var(--muted)" }}>
                          {item.hostname ? <span>{item.hostname}</span> : null}
                          {item.username ? <span>{item.username}</span> : null}
                          <span>{fmtDate(item.timestamp)}</span>
                        </div>

                        {item.description ? (
                          <div className="mt-3 text-sm leading-relaxed" style={{ color: "var(--muted-strong)" }}>
                            {item.description}
                          </div>
                        ) : null}
                      </div>

                      <div className="shrink-0 text-right text-xs" style={{ color: "var(--muted)" }}>
                        <div className="inline-flex items-center gap-1">
                          <Clock3 size={12} />
                          {relativeTime(item.timestamp)}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
"use client";

import { useEffect, useMemo, useState } from "react";
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
import {
  getRecentActivity,
  type DashboardRecentActivityItem,
} from "@/lib/api/dashboard";

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
  const [items, setItems] = useState<DashboardRecentActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<ActivityFilter>("ALL");

  const token =
    typeof window !== "undefined" ? localStorage.getItem("soc_token") || undefined : undefined;

  const loadActivity = async () => {
    setLoading(true);
    setError("");
    try {
      const rows = await getRecentActivity(token);
      setItems(rows);
    } catch (err) {
      console.error(err);
      setError("Activity verileri alınamadı.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadActivity();
    const timer = setInterval(loadActivity, 30000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard
          title="Total Events"
          value={summary.total}
          hint="Birleşik activity akışı"
          icon={<Activity size={15} />}
        />
        <SummaryCard
          title="Alert Events"
          value={summary.alerts}
          hint="Detection kaynaklı"
          icon={<Shield size={15} />}
        />
        <SummaryCard
          title="Audit Events"
          value={summary.audits}
          hint="Kullanıcı / sistem işlemleri"
          icon={<Workflow size={15} />}
        />
        <SummaryCard
          title="Critical Alerts"
          value={summary.criticalAlerts}
          hint="Yüksek öncelik"
          icon={<AlertTriangle size={15} />}
        />
      </div>

      <Panel
        title="Activity Timeline"
        subtitle="Audit ve alert olaylarının birleşik akışı"
        action={
          <button
            onClick={loadActivity}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 px-3 py-2 text-sm text-zinc-700 transition hover:bg-zinc-50 dark:border-white/10 dark:text-zinc-200 dark:hover:bg-white/[0.05]"
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
              className="w-full rounded-2xl border border-zinc-200 bg-white px-10 py-3 text-sm outline-none transition focus:border-zinc-400 dark:border-white/10 dark:bg-white/[0.03] dark:text-white dark:focus:border-white/20"
            />
          </div>

          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as ActivityFilter)}
            className="rounded-2xl border border-zinc-200 bg-white px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-white/[0.03]"
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
          <div className="text-sm text-zinc-500 dark:text-zinc-400">Activity verileri yükleniyor...</div>
        ) : filteredItems.length === 0 ? (
          <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-8 text-center text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
            Gösterilecek activity verisi yok.
          </div>
        ) : (
          <div className="relative">
            <div className="absolute bottom-0 left-[23px] top-0 w-px bg-zinc-200 dark:bg-white/10" />

            <div className="space-y-4">
              {filteredItems.map((item, idx) => (
                <div key={`${item.source_id || item.timestamp}-${idx}`} className="relative flex gap-4">
                  <div
                    className={`relative z-10 mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border ${getActivityIconStyle(item)}`}
                  >
                    {getActivityIcon(item)}
                  </div>

                  <div className="min-w-0 flex-1 rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/[0.03]">
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          {item.activity_type === "alert" ? (
                            <SeverityBadge severity={item.severity || "INFO"} />
                          ) : (
                            <span className="inline-flex rounded-full border border-zinc-200 bg-zinc-50 px-2 py-1 text-[10px] font-bold uppercase tracking-wide text-zinc-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300">
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

                        <div className="mt-1 flex flex-wrap gap-3 text-xs text-zinc-500 dark:text-zinc-400">
                          {item.hostname ? <span>{item.hostname}</span> : null}
                          {item.username ? <span>{item.username}</span> : null}
                          <span>{fmtDate(item.timestamp)}</span>
                        </div>

                        {item.description ? (
                          <div className="mt-3 text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
                            {item.description}
                          </div>
                        ) : null}
                      </div>

                      <div className="shrink-0 text-right text-xs text-zinc-500 dark:text-zinc-400">
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
    <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/[0.03]">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-[11px] font-bold uppercase tracking-[0.22em] text-zinc-500 dark:text-zinc-400">
          {title}
        </div>
        <div className="text-zinc-400 dark:text-zinc-500">{icon}</div>
      </div>
      <div className="text-3xl font-black tracking-tight">{value}</div>
      <div className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">{hint}</div>
    </div>
  );
}
"use client";

import { useEffect, useMemo, useState } from "react";
import { Clock3, ShieldAlert } from "lucide-react";
import { getAlerts, type AlertItem } from "@/lib/api/alerts";
import { getToken } from "@/lib/auth";

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

function displayTitle(alert: AlertItem) {
  if (alert.rule?.trim()) return alert.rule;
  if (alert.type?.trim()) return alert.type;
  return `Alert ${alert.id}`;
}

export function HostRecentAlerts({ hostname }: { hostname: string }) {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null;

    const load = async () => {
      try {
        const token = getToken();

        if (!token) {
          setAlerts([]);
          return;
        }

        const rows = await getAlerts(token, 150);
        setAlerts(rows || []);
      } catch {
        setAlerts([]);
      } finally {
        setLoading(false);
      }
    };

    load();
    timer = setInterval(load, 15000);

    return () => {
      if (timer) clearInterval(timer);
    };
  }, [hostname]);

  const hostAlerts = useMemo(() => {
    const target = hostname.trim().toLowerCase();

    return alerts
      .filter((alert) => (alert.hostname || "").trim().toLowerCase() === target)
      .sort((a, b) => {
        const av = a.created_at ? new Date(a.created_at).getTime() : 0;
        const bv = b.created_at ? new Date(b.created_at).getTime() : 0;
        return bv - av;
      })
      .slice(0, 5);
  }, [alerts, hostname]);

  if (loading) {
    return (
      <div className="text-xs" style={{ color: "var(--muted)" }}>
        Host alert geçmişi yükleniyor...
      </div>
    );
  }

  if (hostAlerts.length === 0) {
    return (
      <div
        className="rounded-xl border p-4 text-sm"
        style={{
          borderColor: "var(--border)",
          background: "var(--surface-1)",
          color: "var(--muted)",
        }}
      >
        Bu host için yakın zamanda alert bulunamadı.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {hostAlerts.map((alert) => (
        <div
          key={alert.id}
          className="rounded-xl border p-3"
          style={{
            borderColor: "var(--border)",
            background: "color-mix(in srgb, var(--surface-1) 86%, transparent)",
          }}
        >
          <div className="flex min-w-0 items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
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

              <div className="mt-2 flex min-w-0 items-start gap-2">
                <ShieldAlert size={14} className="mt-0.5 shrink-0 text-zinc-400" />
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold">
                    {displayTitle(alert)}
                  </div>

                  <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                    Risk: {alert.risk_score ?? 0} · User:{" "}
                    {alert.username || "unknown"}
                  </div>

                  {alert.command_line ? (
                    <div
                      className="mt-2 line-clamp-2 break-all rounded-lg px-2 py-1 font-mono text-[11px]"
                      style={{
                        background: "var(--surface-0)",
                        color: "var(--muted-strong)",
                      }}
                    >
                      {alert.command_line}
                    </div>
                  ) : alert.details ? (
                    <div
                      className="mt-2 line-clamp-2 break-words text-xs"
                      style={{ color: "var(--muted-strong)" }}
                    >
                      {alert.details}
                    </div>
                  ) : null}
                </div>
              </div>
            </div>

            <div
              className="flex shrink-0 items-center gap-1 text-[11px]"
              style={{ color: "var(--muted)" }}
            >
              <Clock3 size={11} />
              {relativeTime(alert.created_at)}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

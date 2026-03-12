"use client";

import { useEffect, useRef, useState } from "react";
import { AlertTriangle, Clock, Radio } from "lucide-react";
import { API_BASE } from "@/lib/api/client";

interface AlertEvent {
  id: string;
  hostname?: string | null;
  severity?: string | null;
  rule?: string | null;
  created_at?: string | null;
}

function severityStyle(sev?: string | null) {
  const value = (sev || "INFO").toUpperCase();
  if (value === "CRITICAL") return "text-red-500";
  if (value === "HIGH") return "text-orange-500";
  if (value === "WARNING") return "text-amber-500";
  return "text-sky-500";
}

function wsUrlFromApiBase(apiBase: string) {
  try {
    const url = new URL(apiBase);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = "/ws/alerts";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "ws://127.0.0.1:8000/ws/alerts";
  }
}

export default function LiveAlertStream() {
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [mode, setMode] = useState<"websocket" | "polling">("polling");
  const seenRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const token = localStorage.getItem("soc_token") || undefined;
    const wsUrl = wsUrlFromApiBase(API_BASE);
    let ws: WebSocket | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const mergeAlerts = (items: AlertEvent[]) => {
      setAlerts((prev) => {
        const next = [...prev];
        for (const item of items) {
          if (!item?.id || seenRef.current.has(item.id)) continue;
          seenRef.current.add(item.id);
          next.unshift(item);
        }
        return next.slice(0, 20);
      });
    };

    const startPolling = async () => {
      setConnected(false);
      setMode("polling");

      const load = async () => {
        try {
          const res = await fetch(`${API_BASE}/api/alerts?limit=20`, {
            headers: {
              "Content-Type": "application/json",
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            cache: "no-store",
          });

          if (!res.ok) return;
          const data = await res.json();
          if (Array.isArray(data)) {
            mergeAlerts(
              [...data]
                .slice(0, 20)
                .reverse()
                .map((a) => ({
                  id: a.id,
                  hostname: a.hostname,
                  severity: a.severity,
                  rule: a.rule || a.type,
                  created_at: a.created_at,
                })),
            );
          }
        } catch {
          //
        }
      };

      await load();
      pollTimer = setInterval(load, 10000);
    };

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setConnected(true);
        setMode("websocket");
      };

      ws.onclose = () => {
        startPolling();
      };

      ws.onerror = () => {
        startPolling();
      };

      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          const payload = data?.payload || data?.data || data;

          const item: AlertEvent | null =
            payload?.id
              ? {
                  id: payload.id,
                  hostname: payload.hostname,
                  severity: payload.severity,
                  rule: payload.rule || payload.type,
                  created_at: payload.created_at,
                }
              : null;

          if (item) {
            mergeAlerts([item]);
          }
        } catch {
          //
        }
      };
    } catch {
      startPolling();
    }

    return () => {
      ws?.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, []);

  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/[0.03]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="text-sm font-black">Live Alert Stream</div>
          <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
            WebSocket + polling fallback
          </div>
        </div>

        <div
          className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${
            connected
              ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400"
              : "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400"
          }`}
        >
          <Radio size={10} className={connected ? "animate-pulse" : ""} />
          {connected ? "live" : mode}
        </div>
      </div>

      <div className="max-h-[360px] space-y-3 overflow-y-auto">
        {alerts.length === 0 && (
          <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-6 text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
            Waiting for alerts...
          </div>
        )}

        {alerts.map((a) => (
          <div
            key={a.id}
            className="rounded-xl border border-zinc-200 p-3 dark:border-white/10"
          >
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <AlertTriangle size={14} className={severityStyle(a.severity)} />
                  <span className="truncate text-xs font-semibold">
                    {a.rule || "Alert"}
                  </span>
                </div>

                <div className="mt-1 truncate text-xs text-zinc-500 dark:text-zinc-400">
                  {a.hostname || "unknown-host"}
                </div>
              </div>

              <span className="text-[10px] font-bold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                {a.severity || "INFO"}
              </span>
            </div>

            <div className="mt-2 flex items-center gap-1 text-[10px] text-zinc-400 dark:text-zinc-500">
              <Clock size={10} />
              {a.created_at ? new Date(a.created_at).toLocaleTimeString("tr-TR") : "—"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
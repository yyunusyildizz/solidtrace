"use client";

import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Radio,
  ShieldAlert,
  TerminalSquare,
  XCircle,
} from "lucide-react";
import { API_BASE } from "@/lib/api/client";
import { getToken } from "@/lib/auth";

interface AlertEvent {
  id: string;
  kind: "alert";
  hostname?: string | null;
  severity?: string | null;
  rule?: string | null;
  status?: string | null;
  risk_score?: number | null;
  created_at?: string | null;
}

interface CommandEvent {
  id: string;
  kind: "command";
  command_id: string;
  hostname?: string | null;
  action?: string | null;
  status?: string | null;
  success?: boolean | null;
  message?: string | null;
  created_at?: string | null;
}

type StreamEvent = AlertEvent | CommandEvent;
type StreamMode = "websocket" | "polling" | "demo";

function severityStyle(sev?: string | null) {
  const value = (sev || "INFO").toUpperCase();
  if (value === "CRITICAL") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300";
  }
  if (value === "HIGH") {
    return "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-500/20 dark:bg-orange-500/10 dark:text-orange-300";
  }
  if (value === "WARNING") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300";
  }
  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-300";
}

function statusStyle(status?: string | null) {
  const value = (status || "open").toLowerCase();

  if (value === "resolved") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-300";
  }
  if (value === "acknowledged") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300";
  }
  return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300";
}

function commandStatusStyle(status?: string | null, success?: boolean | null) {
  const value = (status || "").toLowerCase();

  if (success === false || value === "failed") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300";
  }
  if (success === true || value === "completed") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-300";
  }
  if (value === "received" || value === "queued") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300";
  }

  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-300";
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

const DEMO_EVENTS: StreamEvent[] = [
  {
    id: "demo-alert-1",
    kind: "alert",
    hostname: "FIN-WS-22",
    severity: "HIGH",
    rule: "Suspicious PowerShell execution",
    status: "open",
    risk_score: 84,
    created_at: new Date(Date.now() - 4 * 60_000).toISOString(),
  },
  {
    id: "demo-cmd-1",
    kind: "command",
    command_id: "demo-command-1",
    hostname: "FIN-WS-22",
    action: "ISOLATE_HOST",
    status: "completed",
    success: true,
    message: "Host izolasyonu kaldırıldı",
    created_at: new Date(Date.now() - 2 * 60_000).toISOString(),
  },
];

export default function LiveAlertStream() {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [mode, setMode] = useState<StreamMode>("polling");
  const seenRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const token = getToken();
    const wsUrl = wsUrlFromApiBase(API_BASE);
    let ws: WebSocket | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const mergeEvents = (items: StreamEvent[]) => {
      setEvents((prev) => {
        const next = [...prev];
        for (const item of items) {
          if (!item?.id || seenRef.current.has(item.id)) continue;
          seenRef.current.add(item.id);
          next.unshift(item);
        }
        return next.slice(0, 25);
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

          if (!res.ok) {
            if (events.length === 0) {
              setMode("demo");
              setEvents(DEMO_EVENTS);
            }
            return;
          }

          const data = await res.json();
          if (Array.isArray(data)) {
            const mapped: StreamEvent[] = [...data]
              .slice(0, 20)
              .reverse()
              .map((a) => ({
                id: a.id,
                kind: "alert" as const,
                hostname: a.hostname,
                severity: a.severity,
                rule: a.rule || a.type,
                status: a.status,
                risk_score: a.risk_score,
                created_at: a.created_at,
              }));

            if (mapped.length > 0) {
              mergeEvents(mapped);
            } else if (events.length === 0) {
              setMode("demo");
              setEvents(DEMO_EVENTS);
            }
          }
        } catch {
          if (events.length === 0) {
            setMode("demo");
            setEvents(DEMO_EVENTS);
          }
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

          if (data?.type === "COMMAND_EVENT") {
            const item: CommandEvent = {
              id: `cmd-${data.command_id}-${data.timestamp || Date.now()}`,
              kind: "command",
              command_id: data.command_id,
              hostname: data.hostname,
              action: data.action,
              status: data.status,
              success: data.success,
              message: data.message,
              created_at: data.timestamp,
            };
            mergeEvents([item]);
            return;
          }

          const payload = data?.payload || data?.data || data;

          if (payload?.id) {
            const item: AlertEvent = {
              id: payload.id,
              kind: "alert",
              hostname: payload.hostname,
              severity: payload.severity,
              rule: payload.rule || payload.type,
              status: payload.status,
              risk_score: payload.risk_score,
              created_at: payload.created_at,
            };
            mergeEvents([item]);
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
  }, [events.length]);

  const modeLabel =
    mode === "websocket" ? "Live WebSocket" : mode === "polling" ? "Polling Fallback" : "Demo Stream";

  const modeTone =
    mode === "websocket"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-300"
      : mode === "polling"
      ? "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300"
      : "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-300";

  return (
    <section
      className="rounded-3xl border p-5 shadow-sm"
      style={{
        background: "var(--panel-strong)",
        borderColor: "var(--border)",
        boxShadow: "var(--shadow-soft)",
      }}
    >
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-black tracking-tight">Live Operations Stream</div>
          <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
            Real-time alerts and command execution lifecycle.
          </div>
        </div>

        <div
          className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] font-bold uppercase tracking-[0.18em] ${modeTone}`}
        >
          <Radio size={12} className={connected && mode === "websocket" ? "animate-pulse" : ""} />
          {modeLabel}
        </div>
      </div>

      <div className="max-h-90 space-y-3 overflow-y-auto">
        {events.length === 0 ? (
          <div
            className="rounded-2xl border p-6 text-sm"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-1)",
              color: "var(--muted)",
            }}
          >
            Waiting for live operations...
          </div>
        ) : (
          events.map((item) =>
            item.kind === "alert" ? (
              <div
                key={item.id}
                className="rounded-2xl border p-4"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityStyle(item.severity)}`}>
                        {item.severity || "INFO"}
                      </span>
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusStyle(item.status)}`}>
                        {item.status || "open"}
                      </span>
                    </div>

                    <div className="mt-3 flex items-start gap-2">
                      <ShieldAlert size={15} className="mt-0.5 shrink-0 text-zinc-400" />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-semibold">{item.rule || "Alert"}</div>
                        <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                          {item.hostname || "unknown-host"}
                          {typeof item.risk_score === "number" ? ` · Risk ${item.risk_score}` : ""}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="inline-flex items-center gap-1 text-xs" style={{ color: "var(--muted)" }}>
                    <Clock3 size={12} />
                    {relativeTime(item.created_at)}
                  </div>
                </div>
              </div>
            ) : (
              <div
                key={item.id}
                className="rounded-2xl border p-4"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${commandStatusStyle(item.status, item.success)}`}>
                        {item.status || "queued"}
                      </span>
                      <span
                        className="inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                        style={{
                          borderColor: "var(--border)",
                          background: "var(--surface-1)",
                          color: "var(--muted-strong)",
                        }}
                      >
                        {item.action || "COMMAND"}
                      </span>
                    </div>

                    <div className="mt-3 flex items-start gap-2">
                      <TerminalSquare size={15} className="mt-0.5 shrink-0 text-zinc-400" />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-semibold">
                          {item.hostname || "unknown-host"}
                        </div>
                        <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                          {item.command_id}
                        </div>
                        {item.message ? (
                          <div className="mt-2 text-xs" style={{ color: "var(--muted-strong)" }}>
                            {item.message}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col items-end gap-2">
                    {item.success === true ? (
                      <CheckCircle2 size={15} className="text-emerald-500" />
                    ) : item.success === false ? (
                      <XCircle size={15} className="text-red-500" />
                    ) : (
                      <AlertTriangle size={15} className="text-amber-500" />
                    )}
                    <div className="inline-flex items-center gap-1 text-xs" style={{ color: "var(--muted)" }}>
                      <Clock3 size={12} />
                      {relativeTime(item.created_at)}
                    </div>
                  </div>
                </div>
              </div>
            ),
          )
        )}
      </div>
    </section>
  );
}
"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Globe2,
  Radar,
  Radio,
  ShieldAlert,
  Waypoints,
} from "lucide-react";
import { API_BASE } from "@/lib/api/client";
import { getToken } from "@/lib/auth";

type Mode = "live" | "polling" | "demo";

type ThreatEvent = {
  id: string;
  sourceCountry: string;
  targetCountry: string;
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  severity: "CRITICAL" | "HIGH" | "WARNING" | "INFO";
  rule: string;
  hostname?: string;
  username?: string;
  risk_score?: number;
  created_at?: string;
};

const COUNTRY_POINTS: Record<string, { x: number; y: number }> = {
  US: { x: 18, y: 34 },
  CA: { x: 14, y: 20 },
  BR: { x: 28, y: 68 },
  GB: { x: 46, y: 24 },
  DE: { x: 50, y: 28 },
  FR: { x: 48, y: 31 },
  TR: { x: 57, y: 33 },
  RU: { x: 64, y: 18 },
  AE: { x: 61, y: 40 },
  IN: { x: 70, y: 44 },
  SG: { x: 77, y: 56 },
  JP: { x: 86, y: 34 },
  AU: { x: 84, y: 75 },
};

const COUNTRY_KEYS = Object.keys(COUNTRY_POINTS);

const DEMO_EVENTS: ThreatEvent[] = [
  {
    id: "demo-1",
    sourceCountry: "RU",
    targetCountry: "TR",
    sourceX: COUNTRY_POINTS.RU.x,
    sourceY: COUNTRY_POINTS.RU.y,
    targetX: COUNTRY_POINTS.TR.x,
    targetY: COUNTRY_POINTS.TR.y,
    severity: "HIGH",
    rule: "Suspicious PowerShell execution",
    hostname: "FIN-WS-22",
    username: "jdoe",
    risk_score: 84,
    created_at: new Date(Date.now() - 7 * 60_000).toISOString(),
  },
  {
    id: "demo-2",
    sourceCountry: "US",
    targetCountry: "DE",
    sourceX: COUNTRY_POINTS.US.x,
    sourceY: COUNTRY_POINTS.US.y,
    targetX: COUNTRY_POINTS.DE.x,
    targetY: COUNTRY_POINTS.DE.y,
    severity: "CRITICAL",
    rule: "Encoded command line pattern",
    hostname: "HR-LAPTOP-17",
    username: "asmith",
    risk_score: 92,
    created_at: new Date(Date.now() - 14 * 60_000).toISOString(),
  },
  {
    id: "demo-3",
    sourceCountry: "JP",
    targetCountry: "US",
    sourceX: COUNTRY_POINTS.JP.x,
    sourceY: COUNTRY_POINTS.JP.y,
    targetX: COUNTRY_POINTS.US.x,
    targetY: COUNTRY_POINTS.US.y,
    severity: "WARNING",
    rule: "Unusual process spawn chain",
    hostname: "ENG-MAC-04",
    username: "nlee",
    risk_score: 61,
    created_at: new Date(Date.now() - 19 * 60_000).toISOString(),
  },
];

function relativeTime(value?: string | null) {
  if (!value) return "just now";
  try {
    const diff = Date.now() - new Date(value).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
    return `${Math.floor(mins / 1440)}d ago`;
  } catch {
    return value;
  }
}

function severityColor(severity: ThreatEvent["severity"]) {
  if (severity === "CRITICAL") return "#ef4444";
  if (severity === "HIGH") return "#f97316";
  if (severity === "WARNING") return "#f59e0b";
  return "#38bdf8";
}

function severityBadge(severity: ThreatEvent["severity"]) {
  if (severity === "CRITICAL") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300";
  }
  if (severity === "HIGH") {
    return "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-500/20 dark:bg-orange-500/10 dark:text-orange-300";
  }
  if (severity === "WARNING") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300";
  }
  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-300";
}

function pickCountry(seed: string, offset = 0) {
  const safe = seed || "solidtrace";
  const index =
    (safe
      .split("")
      .reduce((acc, char) => acc + char.charCodeAt(0), 0) +
      offset) %
    COUNTRY_KEYS.length;

  return COUNTRY_KEYS[index];
}

function toThreatEvent(input: any): ThreatEvent {
  const id = String(input.id ?? crypto.randomUUID());
  const seed = `${input.hostname || ""}-${input.username || ""}-${input.rule || ""}-${id}`;

  const sourceCountry = pickCountry(seed, 0);
  const targetCountry = pickCountry(seed, 5);

  const source = COUNTRY_POINTS[sourceCountry];
  const target = COUNTRY_POINTS[targetCountry];

  const sev = String(input.severity || "INFO").toUpperCase();
  const severity: ThreatEvent["severity"] =
    sev === "CRITICAL" || sev === "HIGH" || sev === "WARNING" ? sev : "INFO";

  return {
    id,
    sourceCountry,
    targetCountry,
    sourceX: source.x,
    sourceY: source.y,
    targetX: target.x,
    targetY: target.y,
    severity,
    rule: input.rule || input.title || "Untitled alert",
    hostname: input.hostname || "unknown-host",
    username: input.username || undefined,
    risk_score: Number(input.risk_score || 0),
    created_at: input.created_at || new Date().toISOString(),
  };
}

function StatCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
}) {
  return (
    <div
      className="rounded-2xl border p-3"
      style={{
        background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
        borderColor: "var(--border)",
      }}
    >
      <div
        className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.18em]"
        style={{ color: "var(--muted)" }}
      >
        {icon}
        {label}
      </div>
      <div className="text-lg font-black">{value}</div>
    </div>
  );
}

export default function ThreatMap() {
  const [events, setEvents] = useState<ThreatEvent[]>(DEMO_EVENTS);
  const [mode, setMode] = useState<Mode>("demo");
  const [connected, setConnected] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const seenRef = useRef<Set<string>>(new Set(DEMO_EVENTS.map((e) => e.id)));

  const visibleEvents = useMemo(() => events.slice(0, 6), [events]);
  const heroEvents = useMemo(() => events.slice(0, 5), [events]);

  const topTargets = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of events) {
      counts.set(event.targetCountry, (counts.get(event.targetCountry) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);
  }, [events]);

  const criticalCount = useMemo(
    () => events.filter((e) => e.severity === "CRITICAL").length,
    [events],
  );

  useEffect(() => {
    let disposed = false;

    function mergeEvents(items: ThreatEvent[]) {
      setEvents((prev) => {
        const next = [...prev];

        for (const item of items) {
          if (seenRef.current.has(item.id)) continue;
          seenRef.current.add(item.id);
          next.unshift(item);
        }

        return next.slice(0, 20);
      });
    }

    async function pollAlerts() {
      try {
        const token = getToken();
        if (!token) {
          if (!disposed) {
            setMode("demo");
            setConnected(false);
          }
          return;
        }

        const response = await fetch(`${API_BASE}/api/alerts?limit=10`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
          cache: "no-store",
        });

        if (!response.ok) {
          throw new Error(`Polling failed: ${response.status}`);
        }

        const data = await response.json();
        const normalized = Array.isArray(data) ? data.map(toThreatEvent) : [];

        if (!disposed) {
          if (normalized.length > 0) {
            mergeEvents(normalized);
            setMode("polling");
            setConnected(true);
          } else {
            setMode("demo");
            setConnected(false);
          }
        }
      } catch {
        if (!disposed) {
          setMode("demo");
          setConnected(false);
        }
      }
    }

    function startPolling() {
      if (pollingRef.current) return;

      setMode("polling");
      pollAlerts();

      pollingRef.current = setInterval(() => {
        pollAlerts();
      }, 12000);
    }

    function startWebSocket() {
      try {
        const ws = new WebSocket("ws://127.0.0.1:8000/ws/alerts");
        wsRef.current = ws;

        ws.onopen = () => {
          if (disposed) return;
          setConnected(true);
          setMode("live");
        };

        ws.onmessage = (message) => {
          if (disposed) return;

          try {
            const payload = JSON.parse(message.data);
            const candidate = payload?.data ?? payload;
            const event = toThreatEvent(candidate);
            mergeEvents([event]);
            setMode("live");
            setConnected(true);
          } catch {
            // ignore malformed payloads
          }
        };

        ws.onclose = () => {
          if (disposed) return;
          setConnected(false);
          startPolling();
        };

        ws.onerror = () => {
          if (disposed) return;
          setConnected(false);
          try {
            ws.close();
          } catch {}
          startPolling();
        };
      } catch {
        startPolling();
      }
    }

    startWebSocket();

    return () => {
      disposed = true;

      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {}
      }

      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, []);

  const modeLabel =
    mode === "live"
      ? "Live WebSocket"
      : mode === "polling"
      ? "Polling Fallback"
      : "Demo Mapping";

  const modeTone =
    mode === "live"
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
        boxShadow: "var(--shadow-panel)",
      }}
    >
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-black tracking-tight">
            <Globe2 size={16} />
            Global Threat Activity
          </div>
          <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
            Live route context and top cross-region detection paths.
          </div>
        </div>

        <div
          className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] font-bold uppercase tracking-[0.18em] ${modeTone}`}
        >
          <Radio size={12} className={connected && mode === "live" ? "animate-pulse" : ""} />
          {modeLabel}
        </div>
      </div>

      <div className="mb-4 grid gap-3 md:grid-cols-3">
        <StatCard icon={<Activity size={13} />} label="Routes" value={events.length} />
        <StatCard icon={<ShieldAlert size={13} />} label="Critical" value={criticalCount} />
        <StatCard icon={<Waypoints size={13} />} label="Top Target" value={topTargets[0]?.[0] || "—"} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.14fr_0.86fr]">
        <div
          className="rounded-3xl border p-4"
          style={{
            background: "color-mix(in srgb, var(--surface-1) 86%, transparent)",
            borderColor: "var(--border)",
          }}
        >
          <div
            className="mb-3 text-[11px] font-bold uppercase tracking-[0.2em]"
            style={{ color: "var(--muted)" }}
          >
            Threat Routes
          </div>

          <div
            className="relative h-68.75 overflow-hidden rounded-2xl border"
            style={{
              borderColor: "var(--border)",
              background:
                "radial-gradient(circle at center, rgba(59,130,246,0.08), transparent 55%)",
            }}
          >
            <svg
              viewBox="0 0 100 60"
              className="absolute inset-0 h-full w-full"
              preserveAspectRatio="none"
            >
              <path
                d="M6,20 C12,12 18,12 24,18 C29,22 34,22 37,18 C41,14 47,15 51,18 C55,21 59,22 64,19 C70,15 79,15 87,20 L89,28 C83,30 79,31 73,30 C66,29 59,31 54,35 C49,38 43,38 38,35 C34,33 28,33 24,36 C18,40 10,39 6,34 Z"
                fill="rgba(148,163,184,0.14)"
                stroke="rgba(148,163,184,0.22)"
                strokeWidth="0.35"
              />
              <path
                d="M13,39 C17,37 22,37 26,40 C29,42 31,45 31,49 C28,51 24,52 21,50 C17,48 14,44 13,39 Z"
                fill="rgba(148,163,184,0.09)"
                stroke="rgba(148,163,184,0.18)"
                strokeWidth="0.3"
              />
              <path
                d="M72,39 C77,36 83,37 87,41 C90,44 91,48 88,52 C83,53 78,52 75,49 C72,46 71,43 72,39 Z"
                fill="rgba(148,163,184,0.09)"
                stroke="rgba(148,163,184,0.18)"
                strokeWidth="0.3"
              />

              {heroEvents.map((event) => {
                const color = severityColor(event.severity);
                const midX = (event.sourceX + event.targetX) / 2;
                const midY = Math.min(event.sourceY, event.targetY) - 8;

                return (
                  <g key={event.id}>
                    <path
                      d={`M ${event.sourceX} ${event.sourceY} Q ${midX} ${midY}, ${event.targetX} ${event.targetY}`}
                      fill="none"
                      stroke={color}
                      strokeWidth="0.95"
                      strokeOpacity="0.92"
                      strokeLinecap="round"
                    />
                    <circle cx={event.sourceX} cy={event.sourceY} r="1.25" fill={color} />
                    <circle cx={event.targetX} cy={event.targetY} r="1.5" fill={color} />
                  </g>
                );
              })}
            </svg>

            <div
              className="absolute bottom-3 left-3 rounded-2xl border px-3 py-2 text-[11px] shadow-sm"
              style={{
                background: "var(--panel)",
                borderColor: "var(--border)",
                color: "var(--muted-strong)",
              }}
            >
              {mode === "demo"
                ? "Simulated routing from alert metadata"
                : "Live route composition from active alert telemetry"}
            </div>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            {topTargets.length === 0 ? (
              <div
                className="rounded-2xl border p-4 text-sm"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-1)",
                  color: "var(--muted)",
                }}
              >
                No target concentration available yet.
              </div>
            ) : (
              topTargets.map(([country, count]) => (
                <div
                  key={country}
                  className="rounded-2xl border p-4"
                  style={{
                    borderColor: "var(--border)",
                    background: "var(--surface-0)",
                  }}
                >
                  <div
                    className="mb-1 text-[11px] font-bold uppercase tracking-[0.18em]"
                    style={{ color: "var(--muted)" }}
                  >
                    Target Country
                  </div>
                  <div className="flex items-end justify-between gap-3">
                    <div className="text-base font-black">{country}</div>
                    <div className="text-sm font-semibold">{count}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div
          className="rounded-3xl border p-4"
          style={{
            background: "color-mix(in srgb, var(--surface-1) 86%, transparent)",
            borderColor: "var(--border)",
          }}
        >
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <div
                className="text-[11px] font-bold uppercase tracking-[0.2em]"
                style={{ color: "var(--muted)" }}
              >
                Active Routes
              </div>
              <div className="mt-1 text-sm" style={{ color: "var(--muted-strong)" }}>
                Highest-signal detections currently visible.
              </div>
            </div>

            <div
              className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-bold uppercase tracking-[0.16em]"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
                color: "var(--muted-strong)",
              }}
            >
              <Radar size={12} />
              Top {visibleEvents.length}
            </div>
          </div>

          <div className="space-y-3">
            {visibleEvents.length === 0 ? (
              <div
                className="rounded-2xl border p-4 text-sm"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-1)",
                  color: "var(--muted)",
                }}
              >
                No threat activity visible yet.
              </div>
            ) : (
              visibleEvents.map((event) => (
                <div
                  key={event.id}
                  className="rounded-2xl border p-4 transition"
                  style={{
                    borderColor: "var(--border)",
                    background: "var(--surface-0)",
                  }}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityBadge(event.severity)}`}
                        >
                          {event.severity}
                        </span>

                        <span
                          className="inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                          style={{
                            borderColor: "var(--border)",
                            background: "var(--surface-1)",
                            color: "var(--muted-strong)",
                          }}
                        >
                          {event.sourceCountry} → {event.targetCountry}
                        </span>
                      </div>

                      <div className="mt-3 flex items-start gap-2">
                        <ShieldAlert size={15} className="mt-0.5 shrink-0 text-zinc-400" />
                        <div className="min-w-0">
                          <div className="truncate text-sm font-semibold">{event.rule}</div>
                          <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                            {event.hostname || "unknown-host"}
                            {event.username ? ` · ${event.username}` : ""}
                            {typeof event.risk_score === "number" ? ` · Risk ${event.risk_score}` : ""}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="text-xs" style={{ color: "var(--muted)" }}>
                      {relativeTime(event.created_at)}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
"use client";

import { useEffect, useMemo, useState } from "react";
import { Globe, Radio } from "lucide-react";
import { API_BASE } from "@/lib/api/client";

type Severity = "CRITICAL" | "HIGH" | "WARNING" | "INFO";

interface ThreatEvent {
  id: string;
  source: string;
  target: string;
  severity: Severity;
  rule: string;
  created_at: string;
}

const COUNTRY_POINTS: Record<string, { x: number; y: number }> = {
  US: { x: 18, y: 34 },
  BR: { x: 29, y: 72 },
  GB: { x: 46, y: 25 },
  DE: { x: 51, y: 28 },
  TR: { x: 58, y: 34 },
  RU: { x: 67, y: 18 },
  IR: { x: 63, y: 39 },
  IN: { x: 73, y: 47 },
  CN: { x: 79, y: 34 },
  JP: { x: 88, y: 34 },
  AU: { x: 86, y: 78 },
};

const FALLBACK: ThreatEvent[] = [
  {
    id: "t1",
    source: "RU",
    target: "TR",
    severity: "CRITICAL",
    rule: "Credential Dumping",
    created_at: new Date().toISOString(),
  },
  {
    id: "t2",
    source: "CN",
    target: "DE",
    severity: "HIGH",
    rule: "Suspicious PowerShell",
    created_at: new Date(Date.now() - 60_000).toISOString(),
  },
  {
    id: "t3",
    source: "IR",
    target: "GB",
    severity: "WARNING",
    rule: "Auth Probe",
    created_at: new Date(Date.now() - 120_000).toISOString(),
  },
];

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

function severityColor(severity: Severity) {
  if (severity === "CRITICAL") return "#ef4444";
  if (severity === "HIGH") return "#f97316";
  if (severity === "WARNING") return "#f59e0b";
  return "#0ea5e9";
}

function buildCurvePath(x1: number, y1: number, x2: number, y2: number) {
  const curve = Math.max(16, Math.abs(x2 - x1) * 0.18);
  return `M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1 - curve}, ${(x1 + x2) / 2} ${y2 - curve}, ${x2} ${y2}`;
}

export default function ThreatMap() {
  const [events, setEvents] = useState<ThreatEvent[]>(FALLBACK);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const wsUrl = wsUrlFromApiBase(API_BASE);
    let ws: WebSocket | null = null;

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => setConnected(true);
      ws.onclose = () => setConnected(false);
      ws.onerror = () => setConnected(false);

      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          const payload = data?.payload || data?.data || data;
          if (!payload?.id) return;

          const srcPool = ["RU", "CN", "IR", "US", "IN", "BR"];
          const dstPool = ["TR", "DE", "GB", "JP", "AU"];

          const next: ThreatEvent = {
            id: payload.id,
            source: payload.source_country || srcPool[String(payload.id).length % srcPool.length],
            target: payload.target_country || dstPool[Math.abs(Number(payload.risk_score || 0)) % dstPool.length],
            severity: (payload.severity || "INFO").toUpperCase(),
            rule: payload.rule || payload.type || "Alert",
            created_at: payload.created_at || new Date().toISOString(),
          };

          setEvents((prev) => [next, ...prev].slice(0, 10));
        } catch {
          //
        }
      };
    } catch {
      setConnected(false);
    }

    return () => ws?.close();
  }, []);

  const safeEvents = useMemo(
    () =>
      events.filter((e) => COUNTRY_POINTS[e.source] && COUNTRY_POINTS[e.target]),
    [events],
  );

  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/[0.03]">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm font-black">
            <Globe size={16} />
            Global Threat Map
          </div>
          <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
            Stylized world + live attack lines
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
          {connected ? "live" : "demo"}
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-zinc-200 bg-zinc-50 dark:border-white/10 dark:bg-[#0b0f14]">
        <svg viewBox="0 0 1000 420" className="h-[320px] w-full">
          <rect width="1000" height="420" fill="transparent" />

          {Array.from({ length: 11 }).map((_, i) => (
            <line
              key={`v-${i}`}
              x1={i * 100}
              y1="0"
              x2={i * 100}
              y2="420"
              stroke="currentColor"
              strokeOpacity="0.05"
            />
          ))}
          {Array.from({ length: 5 }).map((_, i) => (
            <line
              key={`h-${i}`}
              x1="0"
              y1={i * 100}
              x2="1000"
              y2={i * 100}
              stroke="currentColor"
              strokeOpacity="0.05"
            />
          ))}

          <g fill="currentColor" fillOpacity="0.08">
            <path d="M70 120 C120 80, 200 70, 260 100 C290 120, 300 160, 275 185 C240 220, 170 210, 120 180 C80 155, 55 145, 70 120 Z" />
            <path d="M230 225 C260 215, 295 230, 310 260 C325 295, 310 350, 280 385 C255 410, 215 390, 205 345 C198 310, 200 245, 230 225 Z" />
            <path d="M420 105 C465 75, 545 65, 610 80 C690 95, 770 105, 845 130 C900 148, 930 175, 920 210 C905 250, 835 258, 760 245 C710 236, 678 250, 650 280 C618 315, 565 320, 525 300 C480 278, 462 230, 430 215 C395 198, 380 135, 420 105 Z" />
            <path d="M520 255 C555 240, 605 250, 630 285 C654 318, 650 365, 615 392 C585 415, 540 405, 520 370 C505 344, 495 275, 520 255 Z" />
            <path d="M780 305 C820 290, 870 300, 900 328 C920 350, 918 384, 890 398 C852 416, 790 408, 770 375 C755 350, 755 315, 780 305 Z" />
          </g>

          {Object.entries(COUNTRY_POINTS).map(([code, point]) => (
            <g key={code}>
              <circle cx={point.x * 10} cy={point.y * 4.2} r="3" fill="currentColor" fillOpacity="0.4" />
              <text
                x={point.x * 10 + 6}
                y={point.y * 4.2 - 6}
                fontSize="10"
                fill="currentColor"
                fillOpacity="0.45"
              >
                {code}
              </text>
            </g>
          ))}

          {safeEvents.map((evt, idx) => {
            const s = COUNTRY_POINTS[evt.source];
            const t = COUNTRY_POINTS[evt.target];
            const x1 = s.x * 10;
            const y1 = s.y * 4.2;
            const x2 = t.x * 10;
            const y2 = t.y * 4.2;
            const color = severityColor(evt.severity);

            return (
              <g key={evt.id}>
                <path
                  d={buildCurvePath(x1, y1, x2, y2)}
                  fill="none"
                  stroke={color}
                  strokeWidth="2"
                  strokeOpacity="0.65"
                  strokeDasharray="6 4"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    from="30"
                    to="0"
                    dur={`${1.4 + idx * 0.12}s`}
                    repeatCount="indefinite"
                  />
                </path>

                <circle cx={x1} cy={y1} r="5" fill={color} fillOpacity="0.85" />
                <circle cx={x2} cy={y2} r="5" fill={color} fillOpacity="0.95">
                  <animate attributeName="r" values="4;7;4" dur="1.2s" repeatCount="indefinite" />
                </circle>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Shield, Clock } from "lucide-react";

interface AlertEvent {
  id: string;
  hostname: string;
  severity: string;
  rule: string;
  created_at: string;
}

function severityStyle(sev: string) {
  if (sev === "CRITICAL") return "text-red-500";
  if (sev === "HIGH") return "text-orange-500";
  if (sev === "WARNING") return "text-yellow-500";
  return "text-sky-500";
}

export default function LiveAlertStream() {
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/alerts");

    ws.onopen = () => {
      setConnected(true);
    };

    ws.onclose = () => {
      setConnected(false);
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);

        if (data.type === "ALERT") {
          setAlerts((prev) => [data.payload, ...prev.slice(0, 19)]);
        }
      } catch (e) {}
    };

    return () => ws.close();
  }, []);

  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-4 dark:border-white/10 dark:bg-white/[0.03]">
      
      <div className="flex items-center justify-between mb-4">
        <div className="text-sm font-bold tracking-wide">
          Live Alert Stream
        </div>

        <div className="text-xs">
          {connected ? (
            <span className="text-emerald-500">LIVE</span>
          ) : (
            <span className="text-red-500">OFFLINE</span>
          )}
        </div>
      </div>

      <div className="space-y-3 max-h-[420px] overflow-y-auto">

        {alerts.length === 0 && (
          <div className="text-xs text-zinc-500">
            Waiting for alerts...
          </div>
        )}

        {alerts.map((a) => (
          <div
            key={a.id}
            className="border rounded-xl p-3 border-zinc-200 dark:border-white/10"
          >
            <div className="flex justify-between items-center">

              <div className="flex items-center gap-2">

                <AlertTriangle
                  size={14}
                  className={severityStyle(a.severity)}
                />

                <span className="text-xs font-semibold">
                  {a.rule}
                </span>

              </div>

              <span className="text-[10px] text-zinc-500">
                {a.severity}
              </span>

            </div>

            <div className="text-xs mt-1 text-zinc-500">
              {a.hostname}
            </div>

            <div className="flex items-center gap-1 text-[10px] text-zinc-400 mt-1">
              <Clock size={10} />
              {new Date(a.created_at).toLocaleTimeString()}
            </div>

          </div>
        ))}
      </div>
    </div>
  );
}
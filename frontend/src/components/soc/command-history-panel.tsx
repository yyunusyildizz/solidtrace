"use client";

import { useEffect, useState } from "react";
import { Clock3, TerminalSquare, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { StatusBadge } from "@/components/soc/ui/status-badge";
import { getCommandExecutions, type CommandExecutionItem } from "@/lib/api/commands";

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

function ResultIcon({ item }: { item: CommandExecutionItem }) {
  if (item.success === true) return <CheckCircle2 size={15} className="text-emerald-500" />;
  if (item.success === false || item.status === "failed") return <XCircle size={15} className="text-red-500" />;
  if (item.status === "queued" || item.status === "received") {
    return <AlertTriangle size={15} className="text-amber-500" />;
  }
  return <TerminalSquare size={15} className="text-zinc-400" />;
}

export function CommandHistoryPanel() {
  const [items, setItems] = useState<CommandExecutionItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null;

    const load = async () => {
      try {
        const data = await getCommandExecutions(12);
        setItems(data || []);
      } catch {
        //
      } finally {
        setLoading(false);
      }
    };

    load();
    timer = setInterval(load, 10000);

    return () => {
      if (timer) clearInterval(timer);
    };
  }, []);

  return (
    <Panel
      title="Response Operations"
      subtitle="Recent analyst actions and agent execution results."
    >
      {loading ? (
        <div className="text-sm" style={{ color: "var(--muted)" }}>
          Loading command history...
        </div>
      ) : items.length === 0 ? (
        <div className="text-sm" style={{ color: "var(--muted)" }}>
          No recent response actions.
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item) => (
            <div
              key={item.command_id}
              className="rounded-2xl border p-4"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
              }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge status={item.status} />
                    <span
                      className="inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-1)",
                        color: "var(--muted-strong)",
                      }}
                    >
                      {item.action}
                    </span>
                  </div>

                  <div className="mt-3 flex items-start gap-2">
                    <TerminalSquare size={15} className="mt-0.5 shrink-0 text-zinc-400" />
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold">
                        {item.target_hostname}
                      </div>
                      <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                        {item.command_id}
                      </div>
                      <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                        Requested by: {item.requested_by || "unknown"}
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
                  <ResultIcon item={item} />
                  <div className="inline-flex items-center gap-1 text-xs" style={{ color: "var(--muted)" }}>
                    <Clock3 size={12} />
                    {relativeTime(item.finished_at || item.updated_at || item.created_at)}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
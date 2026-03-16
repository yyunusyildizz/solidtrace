"use client";

import { useEffect, useState } from "react";
import { Clock3, TerminalSquare, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
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
  if (item.success === true) return <CheckCircle2 size={14} className="text-emerald-500" />;
  if (item.success === false || item.status === "failed") return <XCircle size={14} className="text-red-500" />;
  if (item.status === "queued" || item.status === "received") {
    return <AlertTriangle size={14} className="text-amber-500" />;
  }
  return <TerminalSquare size={14} className="text-zinc-400" />;
}

export function HostLastResponseActions({ hostname }: { hostname: string }) {
  const [items, setItems] = useState<CommandExecutionItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null;

    const load = async () => {
      try {
        const data = await getCommandExecutions(3, hostname);
        setItems(data || []);
      } catch {
        //
      } finally {
        setLoading(false);
      }
    };

    load();
    timer = setInterval(load, 12000);

    return () => {
      if (timer) clearInterval(timer);
    };
  }, [hostname]);

  if (loading) {
    return (
      <div className="text-xs" style={{ color: "var(--muted)" }}>
        Response history yükleniyor...
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="text-xs" style={{ color: "var(--muted)" }}>
        Bu host için response history yok.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div
          key={item.command_id}
          className="rounded-xl border p-3"
          style={{
            borderColor: "var(--border)",
            background: "color-mix(in srgb, var(--surface-1) 86%, transparent)",
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

              <div className="mt-2 text-xs" style={{ color: "var(--muted)" }}>
                {item.requested_by ? `By ${item.requested_by}` : "By analyst"}
              </div>

              {item.message ? (
                <div className="mt-2 line-clamp-2 text-xs" style={{ color: "var(--muted-strong)" }}>
                  {item.message}
                </div>
              ) : null}
            </div>

            <div className="flex flex-col items-end gap-2">
              <ResultIcon item={item} />
              <div className="inline-flex items-center gap-1 text-[11px]" style={{ color: "var(--muted)" }}>
                <Clock3 size={11} />
                {relativeTime(item.finished_at || item.updated_at || item.created_at)}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
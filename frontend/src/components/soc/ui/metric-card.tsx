import type { ReactNode } from "react";

export function MetricCard({
  title,
  value,
  hint,
  accent = "neutral",
  icon,
}: {
  title: string;
  value: ReactNode;
  hint?: string;
  accent?: "neutral" | "danger" | "warning" | "success" | "info" | "insight";
  icon?: ReactNode;
}) {
  const accentMap: Record<string, string> = {
    neutral: "from-zinc-500/10 to-zinc-500/0 border-zinc-200 dark:border-white/10",
    danger: "from-red-500/10 to-red-500/0 border-red-200 dark:border-red-500/15",
    warning: "from-amber-500/10 to-amber-500/0 border-amber-200 dark:border-amber-500/15",
    success: "from-emerald-500/10 to-emerald-500/0 border-emerald-200 dark:border-emerald-500/15",
    info: "from-sky-500/10 to-sky-500/0 border-sky-200 dark:border-sky-500/15",
    insight: "from-violet-500/10 to-violet-500/0 border-violet-200 dark:border-violet-500/15",
  };

  return (
    <div
      className={`rounded-2xl border bg-gradient-to-br p-4 ${accentMap[accent]} bg-white dark:bg-white/[0.03]`}
    >
      <div className="mb-3 flex items-center justify-between">
        <div className="text-[11px] font-bold uppercase tracking-[0.22em] text-zinc-500 dark:text-zinc-400">
          {title}
        </div>
        {icon ? <div className="text-zinc-400 dark:text-zinc-500">{icon}</div> : null}
      </div>

      <div className="text-3xl font-black tracking-tight">{value}</div>

      {hint ? (
        <div className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">{hint}</div>
      ) : null}
    </div>
  );
}
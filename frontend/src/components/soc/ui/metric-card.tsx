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
  const accentMap: Record<
    string,
    {
      border: string;
      glow: string;
      tint: string;
    }
  > = {
    neutral: {
      border: "rgba(148, 163, 184, 0.16)",
      glow: "rgba(15, 23, 42, 0.05)",
      tint: "rgba(148, 163, 184, 0.06)",
    },
    danger: {
      border: "rgba(239, 68, 68, 0.24)",
      glow: "rgba(239, 68, 68, 0.10)",
      tint: "rgba(239, 68, 68, 0.07)",
    },
    warning: {
      border: "rgba(245, 158, 11, 0.22)",
      glow: "rgba(245, 158, 11, 0.09)",
      tint: "rgba(245, 158, 11, 0.07)",
    },
    success: {
      border: "rgba(16, 185, 129, 0.22)",
      glow: "rgba(16, 185, 129, 0.09)",
      tint: "rgba(16, 185, 129, 0.07)",
    },
    info: {
      border: "rgba(59, 130, 246, 0.22)",
      glow: "rgba(59, 130, 246, 0.09)",
      tint: "rgba(59, 130, 246, 0.07)",
    },
    insight: {
      border: "rgba(139, 92, 246, 0.22)",
      glow: "rgba(139, 92, 246, 0.09)",
      tint: "rgba(139, 92, 246, 0.07)",
    },
  };

  const tone = accentMap[accent] || accentMap.neutral;

  return (
    <div
      className="rounded-3xl border p-4"
      style={{
        borderColor: tone.border,
        background: `linear-gradient(135deg, ${tone.tint}, color-mix(in srgb, var(--panel-strong) 94%, transparent))`,
        boxShadow: `0 12px 30px ${tone.glow}`,
      }}
    >
      <div className="mb-3 flex items-center justify-between">
        <div
          className="text-[11px] font-bold uppercase tracking-[0.22em]"
          style={{ color: "var(--muted)" }}
        >
          {title}
        </div>
        {icon ? <div style={{ color: "var(--muted)" }}>{icon}</div> : null}
      </div>

      <div className="text-3xl font-black tracking-tight">{value}</div>

      {hint ? (
        <div className="mt-2 text-xs" style={{ color: "var(--muted)" }}>
          {hint}
        </div>
      ) : null}
    </div>
  );
}
import type { ReactNode } from "react";

export function Panel({
  title,
  subtitle,
  action,
  children,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section
      className="rounded-3xl border"
      style={{
        borderColor: "var(--border)",
        background: "var(--panel-strong)",
        boxShadow: "var(--shadow-soft)",
      }}
    >
      <div
        className="flex items-start justify-between gap-4 px-5 py-4"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        <div>
          <h2 className="text-sm font-black">{title}</h2>
          {subtitle ? (
            <p className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
              {subtitle}
            </p>
          ) : null}
        </div>
        {action}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}
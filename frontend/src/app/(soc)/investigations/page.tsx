"use client";

import { useMemo, useState } from "react";
import {
  Briefcase,
  CheckCircle2,
  Clock3,
  Filter,
  Search,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import InvestigationGraph, {
  type InvestigationGraphData,
} from "@/components/soc/investigation-graph";

type InvestigationStatus = "open" | "in_progress" | "contained" | "closed";
type InvestigationSeverity = "CRITICAL" | "HIGH" | "WARNING" | "INFO";

interface InvestigationItem {
  id: string;
  title: string;
  status: InvestigationStatus;
  severity: InvestigationSeverity;
  owner: string;
  created_at: string;
  updated_at: string;
  related_alerts: number;
  affected_host: string;
  summary: string;
  tags: string[];
  graph: InvestigationGraphData;
}

const MOCK_INVESTIGATIONS: InvestigationItem[] = [
  {
    id: "INV-2026-001",
    title: "Credential Dumping investigation on DESKTOP-QA-0529904F",
    status: "open",
    severity: "CRITICAL",
    owner: "analyst",
    created_at: "2026-03-10T19:27:47.920936+00:00",
    updated_at: "2026-03-10T19:35:12.000000+00:00",
    related_alerts: 6,
    affected_host: "DESKTOP-QA-0529904F",
    summary:
      "Mimikatz benzeri davranış ve yüksek riskli process execution olayları inceleniyor.",
    tags: ["credential-dumping", "windows", "high-risk"],
    graph: {
      nodes: [
        { id: "host-1", label: "DESKTOP-QA-0529904F", type: "host", risk: 92, meta: "Windows endpoint" },
        { id: "user-1", label: "yunus", type: "user", risk: 68, meta: "Interactive session" },
        { id: "proc-1", label: "powershell.exe", type: "process", risk: 84, meta: "PID 4545" },
        { id: "rule-1", label: "Credential Dumping", type: "rule", risk: 95, meta: "Sigma-like detection" },
        { id: "alert-1", label: "ALERT-9767", type: "alert", risk: 95, meta: "Open / critical" },
      ],
      edges: [
        { from: "user-1", to: "proc-1", label: "executed" },
        { from: "proc-1", to: "host-1", label: "ran on" },
        { from: "proc-1", to: "rule-1", label: "matched" },
        { from: "rule-1", to: "alert-1", label: "generated" },
        { from: "host-1", to: "alert-1", label: "affected" },
      ],
    },
  },
  {
    id: "INV-2026-002",
    title: "Repeated suspicious PowerShell executions",
    status: "in_progress",
    severity: "HIGH",
    owner: "analyst",
    created_at: "2026-03-10T16:00:00.000000+00:00",
    updated_at: "2026-03-10T18:20:00.000000+00:00",
    related_alerts: 4,
    affected_host: "DESKTOP-QA-8AC3B995",
    summary:
      "Encoded PowerShell komutlarının tekrar ettiği olaylar korelasyon altında takip ediliyor.",
    tags: ["powershell", "execution", "correlation"],
    graph: {
      nodes: [
        { id: "host-2", label: "DESKTOP-QA-8AC3B995", type: "host", risk: 73, meta: "Windows endpoint" },
        { id: "user-2", label: "analyst", type: "user", risk: 41, meta: "Logged-in user" },
        { id: "proc-2", label: "powershell -enc ...", type: "process", risk: 79, meta: "Suspicious encoded command" },
        { id: "rule-2", label: "Suspicious PowerShell", type: "rule", risk: 82, meta: "Execution policy bypass" },
        { id: "alert-2", label: "ALERT-8831", type: "alert", risk: 82, meta: "Acknowledged / high" },
      ],
      edges: [
        { from: "user-2", to: "proc-2", label: "launched" },
        { from: "proc-2", to: "host-2", label: "executed on" },
        { from: "proc-2", to: "rule-2", label: "triggered" },
        { from: "rule-2", to: "alert-2", label: "created" },
      ],
    },
  },
  {
    id: "INV-2026-003",
    title: "Host isolation validation after suspicious lateral movement",
    status: "contained",
    severity: "HIGH",
    owner: "yunus",
    created_at: "2026-03-09T12:10:00.000000+00:00",
    updated_at: "2026-03-09T14:45:00.000000+00:00",
    related_alerts: 8,
    affected_host: "SERVER-FIN-01",
    summary:
      "İzolasyon sonrası host davranışları ve yeni alert üretimi izleniyor.",
    tags: ["containment", "lateral-movement", "server"],
    graph: {
      nodes: [
        { id: "host-3", label: "SERVER-FIN-01", type: "host", risk: 76, meta: "Critical server" },
        { id: "user-3", label: "svc-admin", type: "user", risk: 63, meta: "Privileged account" },
        { id: "proc-3", label: "wmic.exe", type: "process", risk: 71, meta: "Remote exec signal" },
        { id: "rule-3", label: "Lateral Movement", type: "rule", risk: 80, meta: "Remote execution pattern" },
        { id: "alert-3", label: "ALERT-7712", type: "alert", risk: 80, meta: "Contained" },
      ],
      edges: [
        { from: "user-3", to: "proc-3", label: "used" },
        { from: "proc-3", to: "host-3", label: "targeted" },
        { from: "proc-3", to: "rule-3", label: "matched" },
        { from: "rule-3", to: "alert-3", label: "generated" },
      ],
    },
  },
];

function fmtDate(value?: string | null) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("tr-TR");
  } catch {
    return value;
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

function severityBadge(severity: InvestigationSeverity) {
  if (severity === "CRITICAL") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  }
  if (severity === "HIGH") {
    return "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-500/20 dark:bg-orange-500/10 dark:text-orange-400";
  }
  if (severity === "WARNING") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  return "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-500/20 dark:bg-sky-500/10 dark:text-sky-400";
}

function statusBadge(status: InvestigationStatus) {
  if (status === "open") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  }
  if (status === "in_progress") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  if (status === "contained") {
    return "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-500/20 dark:bg-violet-500/10 dark:text-violet-400";
  }
  return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
}

export default function InvestigationsPage() {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | InvestigationStatus>("ALL");
  const [selected, setSelected] = useState<InvestigationItem | null>(MOCK_INVESTIGATIONS[0]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();

    return MOCK_INVESTIGATIONS.filter((item) => {
      const statusOk = statusFilter === "ALL" || item.status === statusFilter;
      const queryOk =
        !q ||
        [
          item.id,
          item.title,
          item.owner,
          item.affected_host,
          item.summary,
          ...item.tags,
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return statusOk && queryOk;
    });
  }, [search, statusFilter]);

  const summary = useMemo(() => {
    return {
      total: MOCK_INVESTIGATIONS.length,
      open: MOCK_INVESTIGATIONS.filter((x) => x.status === "open").length,
      active: MOCK_INVESTIGATIONS.filter((x) => x.status === "in_progress").length,
      contained: MOCK_INVESTIGATIONS.filter((x) => x.status === "contained").length,
      closed: MOCK_INVESTIGATIONS.filter((x) => x.status === "closed").length,
    };
  }, []);

  return (
    <div className="grid gap-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard title="Total Cases" value={summary.total} hint="Toplam investigation" icon={<Briefcase size={15} />} />
        <SummaryCard title="Open" value={summary.open} hint="Yeni vakalar" icon={<ShieldAlert size={15} />} />
        <SummaryCard title="In Progress" value={summary.active} hint="Aktif analiz" icon={<Workflow size={15} />} />
        <SummaryCard title="Contained" value={summary.contained} hint="Containment sonrası" icon={<Clock3 size={15} />} />
        <SummaryCard title="Closed" value={summary.closed} hint="Tamamlanan" icon={<CheckCircle2 size={15} />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <Panel
          title="Investigation Queue"
          subtitle="Case-driven SOC görünümü"
          action={
            <div className="inline-flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
              <Filter size={13} />
              Filtered list
            </div>
          }
        >
          <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto]">
            <div className="relative">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="case id, title, owner, host..."
                className="w-full rounded-2xl border border-zinc-200 bg-white px-10 py-3 text-sm outline-none transition focus:border-zinc-400 dark:border-white/10 dark:bg-white/[0.03] dark:text-white dark:focus:border-white/20"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as "ALL" | InvestigationStatus)}
              className="rounded-2xl border border-zinc-200 bg-white px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-white/[0.03]"
            >
              <option value="ALL">All Status</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="contained">Contained</option>
              <option value="closed">Closed</option>
            </select>
          </div>

          <div className="space-y-3">
            {filtered.map((item) => (
              <button
                key={item.id}
                onClick={() => setSelected(item)}
                className={`w-full rounded-2xl border p-4 text-left transition ${
                  selected?.id === item.id
                    ? "border-zinc-900 bg-zinc-50 dark:border-white dark:bg-white/[0.05]"
                    : "border-zinc-200 bg-white hover:bg-zinc-50 dark:border-white/10 dark:bg-white/[0.03] dark:hover:bg-white/[0.05]"
                }`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityBadge(item.severity)}`}>
                    {item.severity}
                  </span>
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusBadge(item.status)}`}>
                    {item.status}
                  </span>
                </div>

                <div className="mt-3 text-sm font-semibold">{item.title}</div>
                <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                  {item.id} · {item.affected_host} · {item.related_alerts} related alerts
                </div>
                <div className="mt-2 text-xs text-zinc-600 dark:text-zinc-400">
                  Owner: {item.owner} · Updated: {relativeTime(item.updated_at)}
                </div>
              </button>
            ))}
          </div>
        </Panel>

        <Panel title="Investigation Detail" subtitle="Analyst çalışma paneli">
          {!selected ? (
            <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-8 text-center text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
              Investigation seçilmedi.
            </div>
          ) : (
            <div className="space-y-6">
              <div className="grid gap-3 md:grid-cols-2">
                <InfoCard label="Case ID" value={selected.id} />
                <InfoCard label="Owner" value={selected.owner} />
                <InfoCard label="Affected Host" value={selected.affected_host} />
                <InfoCard label="Related Alerts" value={String(selected.related_alerts)} />
                <InfoCard label="Created At" value={fmtDate(selected.created_at)} />
                <InfoCard label="Updated At" value={fmtDate(selected.updated_at)} />
              </div>

              <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${severityBadge(selected.severity)}`}>
                    {selected.severity}
                  </span>
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusBadge(selected.status)}`}>
                    {selected.status}
                  </span>
                </div>

                <div className="text-base font-black">{selected.title}</div>
                <div className="mt-3 text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
                  {selected.summary}
                </div>
              </section>

              <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                <div className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                  Tags
                </div>
                <div className="flex flex-wrap gap-2">
                  {selected.tags.map((tag) => (
                    <span
                      key={tag}
                      className="inline-flex rounded-full border border-zinc-200 bg-zinc-50 px-3 py-1 text-xs text-zinc-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </section>

              <InvestigationGraph data={selected.graph} />

              <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                <div className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
                  Quick Actions
                </div>

                <div className="flex flex-wrap gap-3">
                  <button className="rounded-xl bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-200">
                    Assign Owner
                  </button>
                  <button className="rounded-xl border border-zinc-200 px-4 py-2 text-sm font-medium transition hover:bg-zinc-50 dark:border-white/10 dark:hover:bg-white/[0.05]">
                    Add Note
                  </button>
                  <button className="rounded-xl border border-zinc-200 px-4 py-2 text-sm font-medium transition hover:bg-zinc-50 dark:border-white/10 dark:hover:bg-white/[0.05]">
                    Contain Host
                  </button>
                  <button className="rounded-xl border border-zinc-200 px-4 py-2 text-sm font-medium transition hover:bg-zinc-50 dark:border-white/10 dark:hover:bg-white/[0.05]">
                    Close Case
                  </button>
                </div>
              </section>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

function SummaryCard({
  title,
  value,
  hint,
  icon,
}: {
  title: string;
  value: number;
  hint: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/[0.03]">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-[11px] font-bold uppercase tracking-[0.22em] text-zinc-500 dark:text-zinc-400">
          {title}
        </div>
        <div className="text-zinc-400 dark:text-zinc-500">{icon}</div>
      </div>
      <div className="text-3xl font-black tracking-tight">{value}</div>
      <div className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">{hint}</div>
    </div>
  );
}

function InfoCard({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
      <div className="mb-2 text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
        {label}
      </div>
      <div className="text-sm text-zinc-800 dark:text-zinc-200">{value}</div>
    </div>
  );
}
"use client";

import AuthGuard from "@/components/auth/AuthGuard";
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { HostLastResponseActions } from "@/components/soc/host-last-response-actions";
import {
  Activity,
  ChevronDown,
  ChevronUp,
  Monitor,
  RefreshCw,
  Search,
  ShieldAlert,
  User,
  Wifi,
  WifiOff,
  Server,
  ArrowUpDown,
  BadgeInfo,
  Network,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { HostResponseActions } from "@/components/soc/host-response-actions";
import { getAssets, type AssetListItemResponse } from "@/lib/api/dashboard";
import { clearAuthSession, getToken } from "@/lib/auth";

type SortKey =
  | "hostname"
  | "last_seen"
  | "risk"
  | "alerts"
  | "critical"
  | "status";

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

function riskClass(score?: number | null) {
  const n = Number(score || 0);
  if (n >= 80) return "bg-red-500";
  if (n >= 60) return "bg-orange-500";
  if (n >= 40) return "bg-amber-500";
  return "bg-emerald-500";
}

function riskTone(score?: number | null) {
  const n = Number(score || 0);
  if (n >= 80) return "text-red-600 dark:text-red-400";
  if (n >= 60) return "text-orange-600 dark:text-orange-400";
  if (n >= 40) return "text-amber-600 dark:text-amber-400";
  return "text-emerald-600 dark:text-emerald-400";
}

function riskBand(score?: number | null) {
  const n = Number(score || 0);
  if (n >= 80) return "critical";
  if (n >= 60) return "high";
  if (n >= 40) return "warning";
  return "low";
}

function statusBadge(status: AssetListItemResponse["online_status"]) {
  if (status === "online") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
  }
  if (status === "offline") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400";
  }
  return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
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
    <div
      className="rounded-3xl border p-4"
      style={{
        background: "var(--panel-strong)",
        borderColor: "var(--border)",
        boxShadow: "var(--shadow-soft)",
      }}
    >
      <div className="mb-3 flex items-center justify-between">
        <div
          className="text-[11px] font-bold uppercase tracking-[0.22em]"
          style={{ color: "var(--muted)" }}
        >
          {title}
        </div>
        <div style={{ color: "var(--muted)" }}>{icon}</div>
      </div>
      <div className="text-3xl font-black tracking-tight">{value}</div>
      <div className="mt-2 text-xs" style={{ color: "var(--muted)" }}>
        {hint}
      </div>
    </div>
  );
}

function MiniBadge({ label }: { label: string }) {
  return (
    <span
      className="inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
      style={{
        borderColor: "var(--border)",
        background: "var(--surface-1)",
        color: "var(--muted-strong)",
      }}
    >
      {label}
    </span>
  );
}

function InfoRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div
      className="rounded-2xl border p-3"
      style={{
        borderColor: "var(--border)",
        background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
      }}
    >
      <div
        className="text-[11px] font-bold uppercase tracking-[0.18em]"
        style={{ color: "var(--muted)" }}
      >
        {label}
      </div>
      <div className="mt-2 text-sm">{value}</div>
    </div>
  );
}

function AssetsPage() {
  const router = useRouter();

  const [assets, setAssets] = useState<AssetListItemResponse[]>([]);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "online" | "offline" | "unknown">(
    "ALL",
  );
  const [riskFilter, setRiskFilter] = useState<"ALL" | "critical" | "high" | "warning" | "low">(
    "ALL",
  );
  const [sortKey, setSortKey] = useState<SortKey>("risk");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const loadAssets = async () => {
    setLoading(true);
    setError("");

    try {
      const token = getToken();
      if (!token) {
        router.replace("/login?next=/assets");
        return;
      }

      const rows = await getAssets(token, 1000);
      setAssets(rows);
    } catch (err) {
      if (err instanceof Error && err.message.includes("Not authenticated")) {
        clearAuthSession();
        router.replace("/login?next=/assets");
        return;
      }
      setError("Asset listesi alınamadı.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const filteredAssets = useMemo(() => {
    const q = search.trim().toLowerCase();

    const rows = assets.filter((asset) => {
      const statusOk = statusFilter === "ALL" || asset.online_status === statusFilter;
      const riskOk = riskFilter === "ALL" || riskBand(asset.max_risk_score) === riskFilter;

      const queryOk =
        !q ||
        [
          asset.hostname,
          asset.os_name,
          asset.agent_version,
          asset.last_ip,
          asset.last_user,
          asset.online_status,
          riskBand(asset.max_risk_score),
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return statusOk && riskOk && queryOk;
    });

    rows.sort((a, b) => {
      let av: string | number = "";
      let bv: string | number = "";

      switch (sortKey) {
        case "hostname":
          av = a.hostname || "";
          bv = b.hostname || "";
          break;
        case "last_seen":
          av = a.last_seen ? new Date(a.last_seen).getTime() : 0;
          bv = b.last_seen ? new Date(b.last_seen).getTime() : 0;
          break;
        case "alerts":
          av = a.total_alerts || 0;
          bv = b.total_alerts || 0;
          break;
        case "critical":
          av = a.critical_count || 0;
          bv = b.critical_count || 0;
          break;
        case "status":
          av = a.online_status || "";
          bv = b.online_status || "";
          break;
        case "risk":
        default:
          av = a.max_risk_score || 0;
          bv = b.max_risk_score || 0;
          break;
      }

      if (typeof av === "string" && typeof bv === "string") {
        return sortDir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
      }

      return sortDir === "asc" ? Number(av) - Number(bv) : Number(bv) - Number(av);
    });

    return rows;
  }, [assets, search, statusFilter, riskFilter, sortKey, sortDir]);

  const summary = useMemo(() => {
    return {
      total: assets.length,
      online: assets.filter((x) => x.online_status === "online").length,
      offline: assets.filter((x) => x.online_status === "offline").length,
      unknown: assets.filter((x) => x.online_status === "unknown").length,
      highRisk: assets.filter((x) => (x.max_risk_score || 0) >= 70).length,
      criticalRisk: assets.filter((x) => (x.max_risk_score || 0) >= 80).length,
    };
  }, [assets]);

  function toggleExpand(id: string) {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  function toggleSort(next: SortKey) {
    if (sortKey === next) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(next);
      setSortDir(next === "hostname" || next === "status" ? "asc" : "desc");
    }
  }

  return (
    <div className="grid gap-6">
      <div>
        <div
          className="text-[11px] font-bold uppercase tracking-[0.24em]"
          style={{ color: "var(--muted)" }}
        >
          Asset Visibility
        </div>
        <div className="mt-2 text-2xl font-black tracking-tight">
          Inventory, heartbeat health and risk visibility for managed hosts
        </div>
        <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
          SOC-enriched inventory with risk, alert counts, ownership context and inline response controls.
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <SummaryCard title="Total Assets" value={summary.total} hint="Toplam agent" icon={<Monitor size={15} />} />
        <SummaryCard title="Online" value={summary.online} hint="Aktif görünen host" icon={<Wifi size={15} />} />
        <SummaryCard title="Offline" value={summary.offline} hint="Heartbeat bekleniyor" icon={<WifiOff size={15} />} />
        <SummaryCard title="Unknown" value={summary.unknown} hint="State belirsiz" icon={<Network size={15} />} />
        <SummaryCard title="High Risk" value={summary.highRisk} hint="Risk skoru 70+" icon={<ShieldAlert size={15} />} />
        <SummaryCard title="Critical Risk" value={summary.criticalRisk} hint="Risk skoru 80+" icon={<Activity size={15} />} />
      </div>

      <Panel
        title="Asset Inventory"
        subtitle="Managed host estate with status, ownership, alert context and inline response actions"
        action={
          <button
            onClick={loadAssets}
            className="inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition"
            style={{
              borderColor: "var(--border-strong)",
              background: "var(--surface-1)",
              color: "var(--foreground)",
            }}
          >
            <RefreshCw size={14} />
            Yenile
          </button>
        }
      >
        <div className="mb-4 grid gap-3 xl:grid-cols-[1fr_auto_auto_auto]">
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="hostname, os, ip, user..."
              className="w-full rounded-2xl border px-10 py-3 text-sm outline-none transition"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
                color: "var(--foreground)",
              }}
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}
            className="rounded-2xl border px-4 py-3 text-sm outline-none"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-0)",
              color: "var(--foreground)",
            }}
          >
            <option value="ALL">All Status</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="unknown">Unknown</option>
          </select>

          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as typeof riskFilter)}
            className="rounded-2xl border px-4 py-3 text-sm outline-none"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-0)",
              color: "var(--foreground)",
            }}
          >
            <option value="ALL">All Risk</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="warning">Warning</option>
            <option value="low">Low</option>
          </select>

          <button
            onClick={() => toggleSort(sortKey)}
            className="inline-flex items-center justify-center gap-2 rounded-2xl border px-4 py-3 text-sm"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-0)",
              color: "var(--foreground)",
            }}
          >
            <ArrowUpDown size={14} />
            {sortKey} / {sortDir}
          </button>
        </div>

        <div className="mb-4 flex flex-wrap gap-2">
          <button onClick={() => toggleSort("risk")} className="rounded-full border px-3 py-1.5 text-xs" style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}>Risk</button>
          <button onClick={() => toggleSort("alerts")} className="rounded-full border px-3 py-1.5 text-xs" style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}>Alerts</button>
          <button onClick={() => toggleSort("critical")} className="rounded-full border px-3 py-1.5 text-xs" style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}>Critical</button>
          <button onClick={() => toggleSort("last_seen")} className="rounded-full border px-3 py-1.5 text-xs" style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}>Last Seen</button>
          <button onClick={() => toggleSort("hostname")} className="rounded-full border px-3 py-1.5 text-xs" style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}>Hostname</button>
        </div>

        {error ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400">
            {error}
          </div>
        ) : null}

        {loading ? (
          <div
            className="rounded-2xl border p-6 text-sm"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-1)",
              color: "var(--muted)",
            }}
          >
            Assetler yükleniyor...
          </div>
        ) : filteredAssets.length === 0 ? (
          <div
            className="rounded-2xl border p-8 text-center text-sm"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-1)",
              color: "var(--muted)",
            }}
          >
            Gösterilecek asset yok.
          </div>
        ) : (
          <div className="space-y-4">
            {filteredAssets.map((asset) => {
              const isOpen = !!expanded[asset.id];
              return (
                <div
                  key={asset.id}
                  className="rounded-2xl border p-4"
                  style={{
                    borderColor: "var(--border)",
                    background: "var(--surface-0)",
                  }}
                >
                  <div className="grid gap-4 xl:grid-cols-[1.1fr_0.5fr_0.7fr_0.7fr_0.5fr_0.8fr_auto]">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="truncate text-sm font-semibold">{asset.hostname}</div>
                        <MiniBadge label={riskBand(asset.max_risk_score)} />
                        {!asset.is_active ? <MiniBadge label="inactive" /> : null}
                        {asset.revoked_at ? <MiniBadge label="revoked" /> : null}
                      </div>
                      <div className="mt-1 truncate text-xs" style={{ color: "var(--muted)" }}>
                        {asset.os_name || "OS bilinmiyor"} · v{asset.agent_version || "?"}
                      </div>
                    </div>

                    <div className="pt-0.5">
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusBadge(asset.online_status)}`}>
                        {asset.online_status}
                      </span>
                    </div>

                    <div className="text-xs" style={{ color: "var(--muted)" }}>
                      <div>{relativeTime(asset.last_seen)}</div>
                      <div className="mt-1">{fmtDate(asset.last_seen)}</div>
                    </div>

                    <div className="text-xs" style={{ color: "var(--muted)" }}>
                      <div className="inline-flex max-w-full items-center gap-1 truncate">
                        <User size={12} />
                        {asset.last_user || "—"}
                      </div>
                      <div className="mt-1 truncate">{asset.last_ip || "—"}</div>
                    </div>

                    <div className="text-sm font-bold">
                      {asset.total_alerts}
                      <div className="mt-1 text-xs font-normal" style={{ color: "var(--muted)" }}>
                        C:{asset.critical_count} H:{asset.high_count}
                      </div>
                    </div>

                    <div>
                      <div className={`text-sm font-bold ${riskTone(asset.max_risk_score)}`}>
                        {asset.max_risk_score || 0}
                      </div>
                      <div className="mt-2 h-2 rounded-full" style={{ background: "var(--surface-2)" }}>
                        <div
                          className={`h-2 rounded-full ${riskClass(asset.max_risk_score)}`}
                          style={{ width: `${Math.min(100, Number(asset.max_risk_score || 0))}%` }}
                        />
                      </div>
                    </div>

                    <div className="flex items-start justify-end">
                      <button
                        onClick={() => toggleExpand(asset.id)}
                        className="inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs"
                        style={{
                          borderColor: "var(--border)",
                          background: "var(--surface-1)",
                          color: "var(--foreground)",
                        }}
                      >
                        <Server size={13} />
                        Details
                        {isOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                      </button>
                    </div>
                  </div>

                  {isOpen ? (
                    <div className="mt-4 space-y-4">
                      <div
                        className="grid gap-3 border-t pt-4 md:grid-cols-2 xl:grid-cols-4"
                        style={{ borderColor: "var(--border)" }}
                      >
                        <InfoRow label="Asset ID" value={asset.id} />
                        <InfoRow label="Tenant" value={asset.tenant_id} />
                        <InfoRow label="Enrolled At" value={fmtDate(asset.enrolled_at)} />
                        <InfoRow label="Revoked At" value={fmtDate(asset.revoked_at)} />
                      </div>

                      <div
                        className="grid gap-4 border-t pt-4 xl:grid-cols-[1fr_1fr]"
                        style={{ borderColor: "var(--border)" }}
                      >
                        <div>
                          <div
                            className="mb-2 text-[11px] font-bold uppercase tracking-[0.2em]"
                            style={{ color: "var(--muted)" }}
                          >
                            Response Actions
                          </div>
                          <HostResponseActions
                            hostname={asset.hostname}
                            compact
                            onActionComplete={loadAssets}
                          />
                        </div>

                        <div>
                          <div
                            className="mb-2 text-[11px] font-bold uppercase tracking-[0.2em]"
                            style={{ color: "var(--muted)" }}
                          >
                            Last Response Actions
                          </div>
                          <HostLastResponseActions hostname={asset.hostname} />
                        </div>
                      </div>

                      <div
                        className="border-t pt-4"
                        style={{ borderColor: "var(--border)" }}
                      >
                        <div
                          className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.2em]"
                          style={{ color: "var(--muted)" }}
                        >
                          <BadgeInfo size={13} />
                          Asset Context
                        </div>
                        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                          <InfoRow label="Online Status" value={asset.online_status} />
                          <InfoRow label="Last User" value={asset.last_user || "—"} />
                          <InfoRow label="Last IP" value={asset.last_ip || "—"} />
                          <InfoRow label="Risk Band" value={riskBand(asset.max_risk_score)} />
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}

export default function AssetsPagePage() {
  return (
    <AuthGuard>
      <AssetsPage />
    </AuthGuard>
  );
}

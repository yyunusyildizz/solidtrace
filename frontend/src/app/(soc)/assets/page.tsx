"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { HostLastResponseActions } from "@/components/soc/host-last-response-actions";
import {
  Monitor,
  RefreshCw,
  Search,
  ShieldAlert,
  User,
  Wifi,
  WifiOff,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { HostResponseActions } from "@/components/soc/host-response-actions";
import { getAssets, type AssetListItemResponse } from "@/lib/api/dashboard";
import { clearAuthSession, getToken } from "@/lib/auth";

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

export default function AssetsPage() {
  const router = useRouter();

  const [assets, setAssets] = useState<AssetListItemResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "online" | "offline" | "unknown">(
    "ALL",
  );

  const loadAssets = async () => {
    setLoading(true);
    setError("");

    try {
      const token = getToken();
      if (!token) {
        router.replace("/login?next=/assets");
        return;
      }

      const rows = await getAssets(token);
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

    return assets.filter((asset) => {
      const statusOk = statusFilter === "ALL" || asset.online_status === statusFilter;

      const queryOk =
        !q ||
        [
          asset.hostname,
          asset.os_name,
          asset.agent_version,
          asset.last_ip,
          asset.last_user,
          asset.online_status,
        ]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return statusOk && queryOk;
    });
  }, [assets, search, statusFilter]);

  const summary = useMemo(() => {
    return {
      total: assets.length,
      online: assets.filter((x) => x.online_status === "online").length,
      offline: assets.filter((x) => x.online_status === "offline").length,
      unknown: assets.filter((x) => x.online_status === "unknown").length,
      highRisk: assets.filter((x) => (x.max_risk_score || 0) >= 70).length,
    };
  }, [assets]);

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
          SOC-enriched inventory with risk, alert counts and recent user context.
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard title="Total Assets" value={summary.total} hint="Toplam agent" icon={<Monitor size={15} />} />
        <SummaryCard title="Online" value={summary.online} hint="Aktif görünen host" icon={<Wifi size={15} />} />
        <SummaryCard title="Offline" value={summary.offline} hint="Heartbeat bekleniyor" icon={<WifiOff size={15} />} />
        <SummaryCard title="Unknown" value={summary.unknown} hint="State belirsiz" icon={<Monitor size={15} />} />
        <SummaryCard title="High Risk" value={summary.highRisk} hint="Risk skoru 70+" icon={<ShieldAlert size={15} />} />
      </div>

      <Panel
        title="Asset Inventory"
        subtitle="Managed host estate with status, ownership, alert context and response actions"
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
        <div className="mb-4 grid gap-3 md:grid-cols-[1fr_auto]">
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
            {filteredAssets.map((asset) => (
              <div
                key={asset.id}
                className="rounded-2xl border p-4"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                }}
              >
                <div className="grid gap-4 xl:grid-cols-[1.1fr_0.5fr_0.7fr_0.7fr_0.5fr_0.8fr]">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold">{asset.hostname}</div>
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
                    <div className="text-sm font-bold">{asset.max_risk_score || 0}</div>
                    <div className="mt-2 h-2 rounded-full" style={{ background: "var(--surface-2)" }}>
                      <div
                        className={`h-2 rounded-full ${riskClass(asset.max_risk_score)}`}
                        style={{ width: `${Math.min(100, Number(asset.max_risk_score || 0))}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* YENI EKLENEN/GÜNCELLENEN RESPONSE ACTIONS BÖLÜMÜ */}
                <div
                  className="mt-4 border-t pt-4"
                  style={{ borderColor: "var(--border)" }}
                >
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

                <div
                  className="mt-4 border-t pt-4"
                  style={{ borderColor: "var(--border)" }}
                >
                  <div
                    className="mb-2 text-[11px] font-bold uppercase tracking-[0.2em]"
                    style={{ color: "var(--muted)" }}
                  >
                    Last Response Actions
                  </div>
                  <HostLastResponseActions hostname={asset.hostname} />
                </div>
                {/* ------------------------------------------------ */}

              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
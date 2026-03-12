"use client";

import { useEffect, useMemo, useState } from "react";
import { Monitor, RefreshCw, Search, ShieldAlert, User, Wifi, WifiOff } from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { getAssets, type AssetListItemResponse } from "@/lib/api/dashboard";

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

export default function AssetsPage() {
  const [assets, setAssets] = useState<AssetListItemResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "online" | "offline" | "unknown">("ALL");

  const token =
    typeof window !== "undefined" ? localStorage.getItem("soc_token") || undefined : undefined;

  const loadAssets = async () => {
    setLoading(true);
    setError("");
    try {
      const rows = await getAssets(token);
      setAssets(rows);
    } catch (err) {
      console.error(err);
      setError("Asset listesi alınamadı.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard title="Total Assets" value={summary.total} hint="Toplam agent" icon={<Monitor size={15} />} />
        <SummaryCard title="Online" value={summary.online} hint="Aktif görünen host" icon={<Wifi size={15} />} />
        <SummaryCard title="Offline" value={summary.offline} hint="Heartbeat bekleniyor" icon={<WifiOff size={15} />} />
        <SummaryCard title="Unknown" value={summary.unknown} hint="State belirsiz" icon={<Monitor size={15} />} />
        <SummaryCard title="High Risk" value={summary.highRisk} hint="Risk skoru 70+" icon={<ShieldAlert size={15} />} />
      </div>

      <Panel
        title="Asset Inventory"
        subtitle="SOC-enriched host görünürlüğü"
        action={
          <button
            onClick={loadAssets}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 px-3 py-2 text-sm text-zinc-700 transition hover:bg-zinc-50 dark:border-white/10 dark:text-zinc-200 dark:hover:bg-white/[0.05]"
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
              className="w-full rounded-2xl border border-zinc-200 bg-white px-10 py-3 text-sm outline-none transition focus:border-zinc-400 dark:border-white/10 dark:bg-white/[0.03] dark:text-white dark:focus:border-white/20"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}
            className="rounded-2xl border border-zinc-200 bg-white px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-white/[0.03]"
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
          <div className="text-sm text-zinc-500 dark:text-zinc-400">Assetler yükleniyor...</div>
        ) : filteredAssets.length === 0 ? (
          <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-8 text-center text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
            Gösterilecek asset yok.
          </div>
        ) : (
          <div className="overflow-hidden rounded-2xl border border-zinc-200 dark:border-white/10">
            <div className="grid grid-cols-[1.2fr_0.55fr_0.65fr_0.65fr_0.55fr_0.8fr] gap-3 border-b border-zinc-200 bg-zinc-50 px-4 py-3 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
              <div>Host / OS</div>
              <div>Status</div>
              <div>Last Seen</div>
              <div>User / IP</div>
              <div>Alerts</div>
              <div>Risk</div>
            </div>

            {filteredAssets.map((asset) => (
              <div
                key={asset.id}
                className="grid grid-cols-[1.2fr_0.55fr_0.65fr_0.65fr_0.55fr_0.8fr] gap-3 border-b border-zinc-200 px-4 py-4 text-left last:border-b-0 dark:border-white/10"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold">{asset.hostname}</div>
                  <div className="mt-1 truncate text-xs text-zinc-500 dark:text-zinc-400">
                    {asset.os_name || "OS bilinmiyor"} · v{asset.agent_version || "?"}
                  </div>
                </div>

                <div className="pt-0.5">
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${statusBadge(asset.online_status)}`}>
                    {asset.online_status}
                  </span>
                </div>

                <div className="text-xs text-zinc-500 dark:text-zinc-400">
                  <div>{relativeTime(asset.last_seen)}</div>
                  <div className="mt-1">{fmtDate(asset.last_seen)}</div>
                </div>

                <div className="text-xs text-zinc-500 dark:text-zinc-400">
                  <div className="truncate inline-flex items-center gap-1">
                    <User size={12} />
                    {asset.last_user || "—"}
                  </div>
                  <div className="mt-1 truncate">{asset.last_ip || "—"}</div>
                </div>

                <div className="text-sm font-bold">
                  {asset.total_alerts}
                  <div className="mt-1 text-xs font-normal text-zinc-500 dark:text-zinc-400">
                    C:{asset.critical_count} H:{asset.high_count}
                  </div>
                </div>

                <div>
                  <div className="text-sm font-bold">{asset.max_risk_score || 0}</div>
                  <div className="mt-2 h-2 rounded-full bg-zinc-200 dark:bg-white/10">
                    <div
                      className={`h-2 rounded-full ${riskClass(asset.max_risk_score)}`}
                      style={{ width: `${Math.min(100, Number(asset.max_risk_score || 0))}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
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
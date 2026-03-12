"use client";

import { useEffect, useMemo, useState } from "react";
import LiveAlertStream from "@/components/soc/live-alert-stream";
import ThreatMap from "@/components/soc/threat-map";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Brain,
  Clock3,
  Package,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  getAssets,
  getDashboardSummary,
  getRecentActivity,
  getSigmaStats,
  getUEBAProfiles,
  type AssetListItemResponse,
  type DashboardRecentActivityItem,
  type DashboardSummaryResponse,
  type SigmaStatsResponse,
  type UEBAProfilesResponse,
} from "@/lib/api/dashboard";
import { MetricCard } from "@/components/soc/ui/metric-card";
import { Panel } from "@/components/soc/ui/panel";

function fmtDate(value?: string | null) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("tr-TR");
  } catch {
    return value;
  }
}

function riskClass(score: number) {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-amber-500";
  return "bg-emerald-500";
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [activity, setActivity] = useState<DashboardRecentActivityItem[]>([]);
  const [assets, setAssets] = useState<AssetListItemResponse[]>([]);
  const [sigma, setSigma] = useState<SigmaStatsResponse | null>(null);
  const [ueba, setUeba] = useState<UEBAProfilesResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("soc_token") || undefined;

    const run = async () => {
      try {
        const [s, a, assetData, sigmaData, uebaData] = await Promise.all([
          getDashboardSummary(token),
          getRecentActivity(token),
          getAssets(token),
          getSigmaStats(token),
          getUEBAProfiles(token),
        ]);

        setSummary(s);
        setActivity(a);
        setAssets(assetData);
        setSigma(sigmaData);
        setUeba(uebaData);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    run();
  }, []);

  const topRiskAssets = useMemo(() => {
    return [...assets].sort((a, b) => b.max_risk_score - a.max_risk_score).slice(0, 5);
  }, [assets]);

  const topProfiles = useMemo(() => {
    return [...(ueba?.profiles || [])].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);
  }, [ueba]);

  if (loading) {
    return (
      <div className="grid gap-6">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div
              key={i}
              className="h-32 animate-pulse rounded-2xl border border-zinc-200 bg-zinc-100 dark:border-white/10 dark:bg-white/[0.04]"
            />
          ))}
        </div>
        <div className="grid gap-6 xl:grid-cols-2">
          <div className="h-96 animate-pulse rounded-3xl border border-zinc-200 bg-zinc-100 dark:border-white/10 dark:bg-white/[0.04]" />
          <div className="h-96 animate-pulse rounded-3xl border border-zinc-200 bg-zinc-100 dark:border-white/10 dark:bg-white/[0.04]" />
        </div>
      </div>
    );
  }

  return (
    <div className="grid gap-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          title="Total Alerts"
          value={summary?.total_alerts ?? 0}
          hint="Tüm zamanlar"
          accent="neutral"
          icon={<Activity size={16} />}
        />
        <MetricCard
          title="Critical Open"
          value={summary?.critical_alerts ?? 0}
          hint="Öncelikli inceleme"
          accent="danger"
          icon={<ShieldAlert size={16} />}
        />
        <MetricCard
          title="Assets Online"
          value={summary?.online_assets ?? 0}
          hint={`${summary?.total_assets ?? 0} asset içinde`}
          accent="success"
          icon={<Server size={16} />}
        />
        <MetricCard
          title="Detections 24h"
          value={summary?.alerts_last_24h ?? 0}
          hint="Son 24 saat"
          accent="warning"
          icon={<Clock3 size={16} />}
        />
        <MetricCard
          title="Sigma Matches"
          value={sigma?.total_matches ?? 0}
          hint={sigma?.engine_status || "idle"}
          accent="insight"
          icon={<BookOpen size={16} />}
        />
        <MetricCard
          title="UEBA Risk"
          value={ueba?.risky_profile_count ?? 0}
          hint={ueba?.baseline_ready ? "baseline ready" : "baseline warming"}
          accent="warning"
          icon={<Brain size={16} />}
        />
        <MetricCard
          title="Open Alerts"
          value={summary?.open_alerts ?? 0}
          hint="Aktif triage kuyruğu"
          accent="danger"
          icon={<AlertTriangle size={16} />}
        />
        <MetricCard
          title="Resolved"
          value={summary?.resolved_alerts ?? 0}
          hint="Kapalı kayıtlar"
          accent="success"
          icon={<ShieldCheck size={16} />}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.3fr_0.7fr]">
        <div className="grid gap-6">
          <Panel title="Top Hosts" subtitle="En çok alert üreten hostlar">
            <div className="space-y-4">
              {(summary?.top_hosts || []).map((host) => (
                <div key={host.name}>
                  <div className="mb-1 flex items-center justify-between text-sm">
                    <span className="font-medium">{host.name}</span>
                    <span className="text-zinc-500 dark:text-zinc-400">{host.count}</span>
                  </div>
                  <div className="h-2 rounded-full bg-zinc-200 dark:bg-white/10">
                    <div
                      className="h-2 rounded-full bg-red-500"
                      style={{
                        width: `${Math.max(
                          8,
                          (host.count /
                            Math.max(...(summary?.top_hosts || [{ count: 1 }]).map((x) => x.count))) *
                            100,
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Top Rules" subtitle="En sık tetiklenen detection kuralları">
            <div className="space-y-4">
              {(summary?.top_rules || []).map((rule) => (
                <div key={rule.name}>
                  <div className="mb-1 flex items-center justify-between text-sm">
                    <span className="font-medium">{rule.name}</span>
                    <span className="text-zinc-500 dark:text-zinc-400">{rule.count}</span>
                  </div>
                  <div className="h-2 rounded-full bg-zinc-200 dark:bg-white/10">
                    <div
                      className="h-2 rounded-full bg-violet-500"
                      style={{
                        width: `${Math.max(
                          8,
                          (rule.count /
                            Math.max(...(summary?.top_rules || [{ count: 1 }]).map((x) => x.count))) *
                            100,
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        <div className="grid gap-6">
          <ThreatMap />
          <LiveAlertStream />
          <Panel title="Recent Activity" subtitle="Audit ve alert akışı">
            <div className="space-y-4">
              {activity.map((item, idx) => (
                <div key={`${item.source_id || item.timestamp}-${idx}`} className="rounded-2xl border border-zinc-200 p-3 dark:border-white/10">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm font-semibold">{item.title}</div>
                    <div className="text-xs text-zinc-500 dark:text-zinc-400">
                      {fmtDate(item.timestamp)}
                    </div>
                  </div>
                  <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                    {item.hostname ? `${item.hostname} · ` : ""}
                    {item.username ? `${item.username} · ` : ""}
                    {item.status || item.activity_type}
                  </div>
                  {item.description ? (
                    <div className="mt-2 text-sm text-zinc-700 dark:text-zinc-300">
                      {item.description}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Risky Assets" subtitle="En yüksek risk skoruna sahip hostlar">
            <div className="space-y-4">
              {topRiskAssets.map((asset) => (
                <div key={asset.id} className="rounded-2xl border border-zinc-200 p-3 dark:border-white/10">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold">{asset.hostname}</div>
                      <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                        {asset.os_name || "unknown os"} · {asset.online_status}
                      </div>
                    </div>
                    <div className="text-sm font-black">{asset.max_risk_score}</div>
                  </div>
                  <div className="mt-3 h-2 rounded-full bg-zinc-200 dark:bg-white/10">
                    <div
                      className={`h-2 rounded-full ${riskClass(asset.max_risk_score)}`}
                      style={{ width: `${Math.min(100, asset.max_risk_score)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="UEBA Spotlight" subtitle="En riskli kullanıcı ve host profilleri">
            <div className="space-y-4">
              {topProfiles.map((profile) => (
                <div key={`${profile.entity_type}-${profile.entity_name}`} className="rounded-2xl border border-zinc-200 p-3 dark:border-white/10">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold">{profile.entity_name}</div>
                      <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                        {profile.entity_type} · {profile.alert_count} alert
                      </div>
                    </div>
                    <div className="text-sm font-black">{profile.risk_score}</div>
                  </div>
                  <div className="mt-3 h-2 rounded-full bg-zinc-200 dark:bg-white/10">
                    <div
                      className={`h-2 rounded-full ${riskClass(profile.risk_score)}`}
                      style={{ width: `${Math.min(100, profile.risk_score)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      <Panel title="Latest Alerts" subtitle="Son oluşturulan alertler">
        <div className="overflow-hidden rounded-2xl border border-zinc-200 dark:border-white/10">
          <div className="grid grid-cols-[1.2fr_0.7fr_0.5fr_0.5fr_0.7fr] gap-3 border-b border-zinc-200 bg-zinc-50 px-4 py-3 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500 dark:border-white/10 dark:bg-white/[0.02] dark:text-zinc-400">
            <div>Rule</div>
            <div>Host</div>
            <div>Severity</div>
            <div>Status</div>
            <div>Time</div>
          </div>

          {(summary?.latest_alerts || []).map((alert) => (
            <div
              key={alert.id}
              className="grid grid-cols-[1.2fr_0.7fr_0.5fr_0.5fr_0.7fr] gap-3 border-b border-zinc-200 px-4 py-3 text-sm last:border-b-0 dark:border-white/10"
            >
              <div className="truncate font-medium">{alert.rule || "—"}</div>
              <div className="truncate text-zinc-600 dark:text-zinc-300">{alert.hostname || "—"}</div>
              <div>{alert.severity || "—"}</div>
              <div>{alert.status || "—"}</div>
              <div className="text-zinc-500 dark:text-zinc-400">{fmtDate(alert.created_at)}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
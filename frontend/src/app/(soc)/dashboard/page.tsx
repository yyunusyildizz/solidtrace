"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import ThreatMap from "@/components/soc/threat-map";
import { CommandHistoryPanel } from "@/components/soc/command-history-panel";
import LiveAlertStream from "@/components/soc/live-alert-stream";
import {
  AlertTriangle,
  Brain,
  Clock3,
  RefreshCw,
  Server,
  ShieldAlert,
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
import { Panel } from "@/components/soc/ui/panel";
import { clearAuthSession, getToken } from "@/lib/auth";

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

function EmptyPanel({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div
      className="rounded-2xl border p-6 text-sm"
      style={{
        background: "var(--surface-1)",
        borderColor: "var(--border)",
        color: "var(--muted)",
      }}
    >
      <div className="font-semibold" style={{ color: "var(--foreground)" }}>
        {title}
      </div>
      <div className="mt-2">{description}</div>
    </div>
  );
}

function HeroMetric({
  title,
  value,
  hint,
  icon,
  accent,
}: {
  title: string;
  value: string | number;
  hint: string;
  icon: React.ReactNode;
  accent: "danger" | "warning" | "info" | "success";
}) {
  const accentStyles =
    accent === "danger"
      ? {
          glow: "rgba(239, 68, 68, 0.16)",
          border: "rgba(239, 68, 68, 0.24)",
        }
      : accent === "warning"
      ? {
          glow: "rgba(245, 158, 11, 0.16)",
          border: "rgba(245, 158, 11, 0.22)",
        }
      : accent === "success"
      ? {
          glow: "rgba(16, 185, 129, 0.16)",
          border: "rgba(16, 185, 129, 0.22)",
        }
      : {
          glow: "rgba(59, 130, 246, 0.16)",
          border: "rgba(59, 130, 246, 0.22)",
        };

  return (
    <div
      className="rounded-3xl border p-5"
      style={{
        background:
          "linear-gradient(135deg, color-mix(in srgb, var(--panel-strong) 92%, transparent), color-mix(in srgb, var(--surface-1) 86%, transparent))",
        borderColor: accentStyles.border,
        boxShadow: `0 12px 30px ${accentStyles.glow}`,
      }}
    >
      <div className="mb-4 flex items-start justify-between gap-3">
        <div
          className="text-[11px] font-bold uppercase tracking-[0.22em]"
          style={{ color: "var(--muted)" }}
        >
          {title}
        </div>
        <div style={{ color: "var(--muted)" }}>{icon}</div>
      </div>

      <div className="text-4xl font-black tracking-tight">{value}</div>
      <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
        {hint}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();

  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [activity, setActivity] = useState<DashboardRecentActivityItem[]>([]);
  const [assets, setAssets] = useState<AssetListItemResponse[]>([]);
  const [sigma, setSigma] = useState<SigmaStatsResponse | null>(null);
  const [ueba, setUeba] = useState<UEBAProfilesResponse | null>(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const topRiskAssets = useMemo(() => {
    return [...assets]
      .sort((a, b) => b.max_risk_score - a.max_risk_score)
      .slice(0, 5);
  }, [assets]);

  const topProfiles = useMemo(() => {
    return [...(ueba?.profiles || [])]
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 5);
  }, [ueba]);

  async function loadDashboard(isRefresh = false) {
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError(null);

      const token = getToken();

      if (!token) {
        router.replace("/login?next=/dashboard");
        return;
      }

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
      if (err instanceof Error && err.message.includes("Not authenticated")) {
        clearAuthSession();
        router.replace("/login?next=/dashboard");
        return;
      }

      setError(err instanceof Error ? err.message : "Dashboard verileri yüklenemedi.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadDashboard();
      // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) {
    return (
      <div className="grid gap-6">
        <div className="grid gap-4 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-36 animate-pulse rounded-3xl border"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
              }}
            />
          ))}
        </div>

        <div className="grid gap-6 xl:grid-cols-[1fr_1fr_0.95fr]">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-[22rem] animate-pulse rounded-3xl border"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
              }}
            />
          ))}
        </div>

        <div className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
          <div
            className="h-[28rem] animate-pulse rounded-3xl border"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
            }}
          />
          <div className="grid gap-6">
            {Array.from({ length: 2 }).map((_, i) => (
              <div
                key={i}
                className="h-[13rem] animate-pulse rounded-3xl border"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                }}
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div
            className="text-[11px] font-bold uppercase tracking-[0.24em]"
            style={{ color: "var(--muted)" }}
          >
            Security Operations Dashboard
          </div>
          <div className="mt-2 text-2xl font-black tracking-tight">
            Unified visibility across alerts, detections, assets and behavior analytics
          </div>
          <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
            High-signal monitoring for triage, investigation and analyst prioritization.
          </div>
        </div>

        <button
          onClick={() => loadDashboard(true)}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
          style={{
            background: "var(--surface-1)",
            borderColor: "var(--border-strong)",
          }}
        >
          <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} />
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error ? (
        <div
          className="rounded-2xl border p-4 text-sm"
          style={{
            borderColor: "color-mix(in srgb, var(--danger) 30%, transparent)",
            background: "color-mix(in srgb, var(--danger) 10%, transparent)",
            color: "var(--danger)",
          }}
        >
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-4">
        <HeroMetric
          title="Open Alerts"
          value={summary?.open_alerts ?? 0}
          hint="Aktif triage kuyruğu"
          accent="danger"
          icon={<ShieldAlert size={17} />}
        />
        <HeroMetric
          title="Critical Open"
          value={summary?.critical_alerts ?? 0}
          hint="Öncelikli inceleme"
          accent="warning"
          icon={<AlertTriangle size={17} />}
        />
        <HeroMetric
          title="Assets Online"
          value={summary?.online_assets ?? 0}
          hint={`${summary?.total_assets ?? 0} asset içinde`}
          accent="success"
          icon={<Server size={17} />}
        />
        <HeroMetric
          title="UEBA Risk"
          value={ueba?.risky_profile_count ?? 0}
          hint={ueba?.baseline_ready ? "baseline ready" : "baseline warming"}
          accent="info"
          icon={<Brain size={17} />}
        />
      </div>

      {/* YENİ EKLENEN BÖLÜM: Canlı Uyarılar ve Komut Geçmişi */}
      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <LiveAlertStream />
        <CommandHistoryPanel />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr_0.92fr]">
        <Panel title="Top Hosts" subtitle="Most active hosts by alert volume">
          {(summary?.top_hosts || []).length === 0 ? (
            <EmptyPanel
              title="No host activity yet"
              description="Host concentration will appear here as detections accumulate."
            />
          ) : (
            <div className="space-y-5">
              {(summary?.top_hosts || []).slice(0, 5).map((host) => (
                <div key={host.name}>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span className="font-semibold">{host.name}</span>
                    <span style={{ color: "var(--muted)" }}>{host.count}</span>
                  </div>
                  <div
                    className="h-2.5 rounded-full"
                    style={{ background: "var(--surface-2)" }}
                  >
                    <div
                      className="h-2.5 rounded-full bg-red-500"
                      style={{
                        width: `${Math.max(
                          8,
                          (host.count /
                            Math.max(
                              ...(summary?.top_hosts || [{ count: 1 }]).map((x) => x.count),
                            )) *
                            100,
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Top Rules" subtitle="Most frequently triggered detections">
          {(summary?.top_rules || []).length === 0 ? (
            <EmptyPanel
              title="No rule telemetry yet"
              description="Top detections will appear here when matching activity is observed."
            />
          ) : (
            <div className="space-y-5">
              {(summary?.top_rules || []).slice(0, 5).map((rule) => (
                <div key={rule.name}>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span className="font-semibold">{rule.name}</span>
                    <span style={{ color: "var(--muted)" }}>{rule.count}</span>
                  </div>
                  <div
                    className="h-2.5 rounded-full"
                    style={{ background: "var(--surface-2)" }}
                  >
                    <div
                      className="h-2.5 rounded-full bg-violet-500"
                      style={{
                        width: `${Math.max(
                          8,
                          (rule.count /
                            Math.max(
                              ...(summary?.top_rules || [{ count: 1 }]).map((x) => x.count),
                            )) *
                            100,
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <ThreatMap />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
        <Panel title="Recent Activity" subtitle="Audit and analyst-relevant activity feed">
          {activity.length === 0 ? (
            <EmptyPanel
              title="No recent activity"
              description="New audit and detection events will appear here."
            />
          ) : (
            <div className="space-y-4">
              {activity.slice(0, 8).map((item, idx) => (
                <div
                  key={`${item.source_id || item.timestamp}-${idx}`}
                  className="rounded-2xl border p-4"
                  style={{
                    borderColor: "var(--border)",
                    background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
                  }}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm font-semibold">{item.title}</div>
                    <div className="text-xs" style={{ color: "var(--muted)" }}>
                      {fmtDate(item.timestamp)}
                    </div>
                  </div>
                  <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                    {item.hostname ? `${item.hostname} · ` : ""}
                    {item.username ? `${item.username} · ` : ""}
                    {item.status || item.activity_type}
                  </div>
                  {item.description ? (
                    <div className="mt-2 text-sm" style={{ color: "var(--muted-strong)" }}>
                      {item.description}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          )}
        </Panel>

        <div className="grid gap-6">
          <Panel title="Risky Assets" subtitle="Highest-risk hosts requiring analyst focus">
            {topRiskAssets.length === 0 ? (
              <EmptyPanel
                title="No risky assets yet"
                description="Asset risk scoring will surface critical systems here."
              />
            ) : (
              <div className="space-y-4">
                {topRiskAssets.map((asset) => (
                  <div
                    key={asset.id}
                    className="rounded-2xl border p-4"
                    style={{
                      borderColor: "var(--border)",
                      background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
                    }}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">{asset.hostname}</div>
                        <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                          {asset.os_name || "unknown os"} · {asset.online_status}
                        </div>
                      </div>
                      <div className="text-sm font-black">{asset.max_risk_score}</div>
                    </div>
                    <div
                      className="mt-3 h-2 rounded-full"
                      style={{ background: "var(--surface-2)" }}
                    >
                      <div
                        className={`h-2 rounded-full ${riskClass(asset.max_risk_score)}`}
                        style={{ width: `${Math.min(100, asset.max_risk_score)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel title="UEBA Spotlight" subtitle="Most suspicious user and host behavior profiles">
            {topProfiles.length === 0 ? (
              <EmptyPanel
                title="No UEBA profiles yet"
                description="Behavior analytics profiles will appear here as baseline matures."
              />
            ) : (
              <div className="space-y-4">
                {topProfiles.map((profile) => (
                  <div
                    key={`${profile.entity_type}-${profile.entity_name}`}
                    className="rounded-2xl border p-4"
                    style={{
                      borderColor: "var(--border)",
                      background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
                    }}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">{profile.entity_name}</div>
                        <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                          {profile.entity_type} · {profile.alert_count} alert
                        </div>
                      </div>
                      <div className="text-sm font-black">{profile.risk_score}</div>
                    </div>
                    <div
                      className="mt-3 h-2 rounded-full"
                      style={{ background: "var(--surface-2)" }}
                    >
                      <div
                        className={`h-2 rounded-full ${riskClass(profile.risk_score)}`}
                        style={{ width: `${Math.min(100, profile.risk_score)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
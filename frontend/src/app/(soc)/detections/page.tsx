"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Brain,
  Cpu,
  RefreshCw,
  Search,
  Shield,
  TrendingUp,
  Users,
} from "lucide-react";
import { Panel } from "@/components/soc/ui/panel";
import { SeverityBadge } from "@/components/soc/ui/severity-badge";
import { MetricCard } from "@/components/soc/ui/metric-card";
import { getAlerts, type AlertItem } from "@/lib/api/alerts";
import {
  getSigmaStats,
  getUEBAProfiles,
  type SigmaStatsResponse,
  type UEBAProfilesResponse,
} from "@/lib/api/dashboard";
import { clearAuthSession, getToken } from "@/lib/auth";

type DetectionTab = "sigma" | "ueba" | "correlation";

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

function engineBadge(status?: string | null) {
  const value = (status || "idle").toLowerCase();
  if (value === "healthy" || value === "ready") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400";
  }
  if (value === "degraded" || value === "warming") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400";
  }
  return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300";
}

function MiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div
      className="rounded-2xl border p-3"
      style={{
        borderColor: "var(--border)",
        background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
      }}
    >
      <div
        className="text-[10px] font-bold uppercase tracking-[0.2em]"
        style={{ color: "var(--muted)" }}
      >
        {label}
      </div>
      <div className="mt-2 text-2xl font-black">{value}</div>
    </div>
  );
}

export default function DetectionsPage() {
  const router = useRouter();

  const [tab, setTab] = useState<DetectionTab>("sigma");
  const [sigma, setSigma] = useState<SigmaStatsResponse | null>(null);
  const [ueba, setUeba] = useState<UEBAProfilesResponse | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const loadData = async () => {
    setLoading(true);
    setError("");

    try {
      const token = getToken();
      if (!token) {
        router.replace("/login?next=/detections");
        return;
      }

      const [sigmaData, uebaData, alertData] = await Promise.all([
        getSigmaStats(token),
        getUEBAProfiles(token),
        getAlerts(token, 150),
      ]);

      setSigma(sigmaData);
      setUeba(uebaData);
      setAlerts(alertData);
    } catch (err) {
      if (err instanceof Error && err.message.includes("Not authenticated")) {
        clearAuthSession();
        router.replace("/login?next=/detections");
        return;
      }
      setError("Detection verileri alınamadı.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const sigmaLikeAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      const haystack = `${alert.rule || ""} ${alert.type || ""} ${alert.details || ""}`.toLowerCase();

      const sigmaLike = [
        "sigma",
        "credential dumping",
        "mimikatz",
        "lsass",
        "psexec",
        "encoded command",
        "powershell",
        "ransomware",
        "suspicious process",
      ].some((k) => haystack.includes(k));

      const searchOk =
        !q ||
        [alert.rule, alert.hostname, alert.username, alert.details, alert.type]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));

      return sigmaLike && searchOk;
    });
  }, [alerts, search]);

  const topRiskProfiles = useMemo(() => {
    const q = search.trim().toLowerCase();

    return [...(ueba?.profiles || [])]
      .filter((p) => {
        if (!q) return true;
        return [p.entity_name, p.entity_type]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q));
      })
      .sort((a, b) => b.risk_score - a.risk_score);
  }, [ueba, search]);

  const correlationGroups = useMemo(() => {
    const map = new Map<
      string,
      {
        host: string;
        count: number;
        maxRisk: number;
        users: Set<string>;
        rules: Set<string>;
        lastSeen?: string | null;
      }
    >();

    for (const alert of alerts) {
      const host = alert.hostname || "unknown-host";
      const current = map.get(host) || {
        host,
        count: 0,
        maxRisk: 0,
        users: new Set<string>(),
        rules: new Set<string>(),
        lastSeen: alert.created_at || null,
      };

      current.count += 1;
      current.maxRisk = Math.max(current.maxRisk, Number(alert.risk_score || 0));
      if (alert.username) current.users.add(alert.username);
      if (alert.rule) current.rules.add(alert.rule);
      if (alert.created_at && (!current.lastSeen || alert.created_at > current.lastSeen)) {
        current.lastSeen = alert.created_at;
      }

      map.set(host, current);
    }

    const q = search.trim().toLowerCase();

    return [...map.values()]
      .filter((item) => item.count >= 2)
      .filter((item) => {
        if (!q) return true;
        return (
          item.host.toLowerCase().includes(q) ||
          [...item.users].some((u) => u.toLowerCase().includes(q)) ||
          [...item.rules].some((r) => r.toLowerCase().includes(q))
        );
      })
      .sort((a, b) => b.maxRisk - a.maxRisk || b.count - a.count);
  }, [alerts, search]);

  return (
    <div className="grid gap-6">
      <div>
        <div
          className="text-[11px] font-bold uppercase tracking-[0.24em]"
          style={{ color: "var(--muted)" }}
        >
          Detection Intelligence
        </div>
        <div className="mt-2 text-2xl font-black tracking-tight">
          Sigma, UEBA and correlation visibility across detection pipelines
        </div>
        <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
          Unified detection telemetry with engine health, risky profiles and repeated-host clustering.
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard title="Sigma Matches" value={sigma?.total_matches ?? 0} hint="Toplam eşleşme" accent="insight" icon={<BookOpen size={15} />} />
        <MetricCard title="24h Matches" value={sigma?.matches_last_24h ?? 0} hint="Son 24 saat" accent="warning" icon={<TrendingUp size={15} />} />
        <MetricCard title="UEBA Profiles" value={ueba?.profile_count ?? 0} hint="Davranış profili" accent="info" icon={<Users size={15} />} />
        <MetricCard title="Risky Profiles" value={ueba?.risky_profile_count ?? 0} hint="Yüksek risk" accent="danger" icon={<Brain size={15} />} />
        <MetricCard title="Sigma-like Alerts" value={sigmaLikeAlerts.length} hint="Alert korelasyonu" accent="warning" icon={<Shield size={15} />} />
        <MetricCard title="Correlation Groups" value={correlationGroups.length} hint="Tekrarlı host kümeleri" accent="neutral" icon={<Activity size={15} />} />
      </div>

      <Panel
        title="Detection Insights"
        subtitle="Sigma, UEBA ve korelasyon görünümü"
        action={
          <button
            onClick={loadData}
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
        <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div
            className="inline-flex rounded-2xl border p-1"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-1)",
            }}
          >
            {[
              { id: "sigma", label: "Sigma" },
              { id: "ueba", label: "UEBA" },
              { id: "correlation", label: "Correlation" },
            ].map((item) => (
              <button
                key={item.id}
                onClick={() => setTab(item.id as DetectionTab)}
                className="rounded-xl px-4 py-2 text-sm font-medium transition"
                style={
                  tab === item.id
                    ? {
                        background: "var(--foreground)",
                        color: "var(--background)",
                      }
                    : {
                        color: "var(--muted-strong)",
                      }
                }
              >
                {item.label}
              </button>
            ))}
          </div>

          <div className="relative w-full md:w-80">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="rule, host, user..."
              className="w-full rounded-2xl border px-10 py-3 text-sm outline-none transition"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-0)",
                color: "var(--foreground)",
              }}
            />
          </div>
        </div>

        {error ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400">
            {error}
          </div>
        ) : null}

        {loading ? (
          <div className="text-sm" style={{ color: "var(--muted)" }}>
            Detection verileri yükleniyor...
          </div>
        ) : (
          <>
            {tab === "sigma" && (
              <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
                <div className="space-y-6">
                  <section
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <div className="mb-3 flex items-center justify-between">
                      <div className="text-sm font-black">Engine Status</div>
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${engineBadge(sigma?.engine_status)}`}>
                        {sigma?.engine_status || "idle"}
                      </span>
                    </div>

                    <p className="text-sm" style={{ color: "var(--muted)" }}>
                      {sigma?.note || "Sigma eşleşmeleri ve kural dağılımı burada izlenir."}
                    </p>
                  </section>

                  <section
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <div className="mb-3 flex items-center gap-2">
                      <Cpu size={15} />
                      <div className="text-sm font-black">Severity Distribution</div>
                    </div>

                    <div className="space-y-4">
                      {Object.entries(sigma?.severity_distribution || {}).map(([sev, count]) => (
                        <div key={sev}>
                          <div className="mb-1 flex items-center justify-between text-sm">
                            <span>{sev}</span>
                            <span style={{ color: "var(--muted)" }}>{count}</span>
                          </div>
                          <div className="h-2 rounded-full" style={{ background: "var(--surface-2)" }}>
                            <div
                              className={`h-2 rounded-full ${
                                sev === "CRITICAL"
                                  ? "bg-red-500"
                                  : sev === "HIGH"
                                  ? "bg-orange-500"
                                  : sev === "WARNING"
                                  ? "bg-amber-500"
                                  : "bg-sky-500"
                              }`}
                              style={{
                                width: `${Math.max(
                                  8,
                                  (Number(count) /
                                    Math.max(...Object.values(sigma?.severity_distribution || { X: 1 }).map(Number))) *
                                    100,
                                )}%`,
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <div className="mb-3 flex items-center gap-2">
                      <BookOpen size={15} />
                      <div className="text-sm font-black">Top Rules</div>
                    </div>

                    <div className="space-y-4">
                      {(sigma?.top_rules || []).map((rule) => (
                        <div key={rule.name}>
                          <div className="mb-1 flex items-center justify-between text-sm">
                            <span className="truncate">{rule.name}</span>
                            <span style={{ color: "var(--muted)" }}>{rule.count}</span>
                          </div>
                          <div className="h-2 rounded-full" style={{ background: "var(--surface-2)" }}>
                            <div
                              className="h-2 rounded-full bg-violet-500"
                              style={{
                                width: `${Math.max(
                                  8,
                                  (rule.count /
                                    Math.max(...(sigma?.top_rules || [{ count: 1 }]).map((x) => x.count))) *
                                    100,
                                )}%`,
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                </div>

                <section
                  className="rounded-2xl border p-4"
                  style={{ borderColor: "var(--border)" }}
                >
                  <div className="mb-4 flex items-center gap-2">
                    <Shield size={15} />
                    <div className="text-sm font-black">Sigma-like Alerts</div>
                  </div>

                  {sigmaLikeAlerts.length === 0 ? (
                    <div
                      className="rounded-2xl border p-8 text-center text-sm"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-1)",
                        color: "var(--muted)",
                      }}
                    >
                      Eşleşen sigma-benzeri alert yok.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {sigmaLikeAlerts.slice(0, 30).map((alert) => (
                        <div
                          key={alert.id}
                          className="rounded-2xl border p-4"
                          style={{ borderColor: "var(--border)" }}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <SeverityBadge severity={alert.severity} />
                              </div>
                              <div className="mt-2 truncate text-sm font-semibold">
                                {alert.rule || alert.type || "Alert"}
                              </div>
                              <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                                {alert.hostname || "unknown-host"} · {alert.username || "SYSTEM"} · {relativeTime(alert.created_at)}
                              </div>
                              {alert.details ? (
                                <div className="mt-2 line-clamp-2 text-xs" style={{ color: "var(--muted-strong)" }}>
                                  {alert.details}
                                </div>
                              ) : null}
                            </div>

                            <div className="w-24 shrink-0">
                              <div className="text-right text-sm font-bold">{alert.risk_score || 0}</div>
                              <div className="mt-2 h-2 rounded-full" style={{ background: "var(--surface-2)" }}>
                                <div
                                  className={`h-2 rounded-full ${riskClass(alert.risk_score)}`}
                                  style={{ width: `${Math.min(100, Number(alert.risk_score || 0))}%` }}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              </div>
            )}

            {tab === "ueba" && (
              <div className="grid gap-6 xl:grid-cols-[0.75fr_1.25fr]">
                <section className="space-y-6">
                  <div
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <div className="mb-3 text-sm font-black">Baseline Status</div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm" style={{ color: "var(--muted)" }}>
                        Baseline Ready
                      </span>
                      <span
                        className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${
                          ueba?.baseline_ready
                            ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400"
                            : "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-400"
                        }`}
                      >
                        {ueba?.baseline_ready ? "ready" : "warming"}
                      </span>
                    </div>

                    <div className="mt-4 text-xs" style={{ color: "var(--muted)" }}>
                      Son güncelleme: {fmtDate(ueba?.last_profile_update_at)}
                    </div>
                    {ueba?.note ? (
                      <div className="mt-2 text-sm" style={{ color: "var(--muted)" }}>
                        {ueba.note}
                      </div>
                    ) : null}
                  </div>

                  <div
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <div className="mb-3 flex items-center gap-2">
                      <Users size={15} />
                      <div className="text-sm font-black">Profile Summary</div>
                    </div>

                    <div className="grid gap-3">
                      <MiniStat label="Profiles" value={ueba?.profile_count ?? 0} />
                      <MiniStat label="Risky Profiles" value={ueba?.risky_profile_count ?? 0} />
                      <MiniStat
                        label="User Profiles"
                        value={(ueba?.profiles || []).filter((p) => p.entity_type === "user").length}
                      />
                      <MiniStat
                        label="Host Profiles"
                        value={(ueba?.profiles || []).filter((p) => p.entity_type === "host").length}
                      />
                    </div>
                  </div>
                </section>

                <section
                  className="rounded-2xl border p-4"
                  style={{ borderColor: "var(--border)" }}
                >
                  <div className="mb-4 flex items-center gap-2">
                    <Brain size={15} />
                    <div className="text-sm font-black">Risky Profiles</div>
                  </div>

                  {topRiskProfiles.length === 0 ? (
                    <div
                      className="rounded-2xl border p-8 text-center text-sm"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-1)",
                        color: "var(--muted)",
                      }}
                    >
                      Gösterilecek profil yok.
                    </div>
                  ) : (
                    <div className="grid gap-3 md:grid-cols-2">
                      {topRiskProfiles.map((profile) => (
                        <div
                          key={`${profile.entity_type}-${profile.entity_name}`}
                          className="rounded-2xl border p-4"
                          style={{ borderColor: "var(--border)" }}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="min-w-0">
                              <div className="truncate text-sm font-semibold">{profile.entity_name}</div>
                              <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                                {profile.entity_type} · {profile.alert_count} alert · {relativeTime(profile.last_seen)}
                              </div>
                            </div>
                            <div className="text-sm font-black">{profile.risk_score}</div>
                          </div>

                          <div className="mt-3 h-2 rounded-full" style={{ background: "var(--surface-2)" }}>
                            <div
                              className={`h-2 rounded-full ${riskClass(profile.risk_score)}`}
                              style={{ width: `${Math.min(100, profile.risk_score)}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              </div>
            )}

            {tab === "correlation" && (
              <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
                <section className="space-y-6">
                  <div
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <div className="mb-3 flex items-center gap-2">
                      <Activity size={15} />
                      <div className="text-sm font-black">Correlation Summary</div>
                    </div>

                    <div className="grid gap-3">
                      <MiniStat label="Alert Count" value={alerts.length} />
                      <MiniStat label="Repeated Hosts" value={correlationGroups.length} />
                      <MiniStat
                        label="Critical Alerts"
                        value={alerts.filter((a) => (a.severity || "").toUpperCase() === "CRITICAL").length}
                      />
                    </div>
                  </div>

                  <div
                    className="rounded-2xl border p-4"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <div className="mb-3 flex items-center gap-2">
                      <AlertTriangle size={15} />
                      <div className="text-sm font-black">Correlation Logic</div>
                    </div>
                    <p className="text-sm" style={{ color: "var(--muted)" }}>
                      Aynı host üzerinde tekrar eden alertler, kullanıcı çeşitliliği ve kural çeşitliliği birlikte değerlendirilir.
                    </p>
                  </div>
                </section>

                <section
                  className="rounded-2xl border p-4"
                  style={{ borderColor: "var(--border)" }}
                >
                  <div className="mb-4 text-sm font-black">Repeated Host Groups</div>

                  {correlationGroups.length === 0 ? (
                    <div
                      className="rounded-2xl border p-8 text-center text-sm"
                      style={{
                        borderColor: "var(--border)",
                        background: "var(--surface-1)",
                        color: "var(--muted)",
                      }}
                    >
                      Korelasyon grubu bulunamadı.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {correlationGroups.slice(0, 30).map((group) => (
                        <div
                          key={group.host}
                          className="rounded-2xl border p-4"
                          style={{ borderColor: "var(--border)" }}
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="min-w-0">
                              <div className="truncate text-sm font-semibold">{group.host}</div>
                              <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                                {group.count} alert · {group.users.size} user · {group.rules.size} rule
                              </div>
                              <div className="mt-2 text-xs" style={{ color: "var(--muted-strong)" }}>
                                Users: {[...group.users].slice(0, 4).join(", ") || "—"}
                              </div>
                              <div className="mt-1 text-xs" style={{ color: "var(--muted-strong)" }}>
                                Last Seen: {fmtDate(group.lastSeen)}
                              </div>
                            </div>

                            <div className="w-28 shrink-0">
                              <div className="text-right text-sm font-bold">{group.maxRisk}</div>
                              <div className="mt-2 h-2 rounded-full" style={{ background: "var(--surface-2)" }}>
                                <div
                                  className={`h-2 rounded-full ${riskClass(group.maxRisk)}`}
                                  style={{ width: `${Math.min(100, group.maxRisk)}%` }}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              </div>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}
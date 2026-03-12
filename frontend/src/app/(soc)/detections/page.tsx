"use client";

import { useEffect, useMemo, useState } from "react";
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
import {
  getAlerts,
  type AlertItem,
} from "@/lib/api/alerts";
import {
  getSigmaStats,
  getUEBAProfiles,
  type SigmaStatsResponse,
  type UEBAProfilesResponse,
} from "@/lib/api/dashboard";

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

export default function DetectionsPage() {
  const [tab, setTab] = useState<DetectionTab>("sigma");
  const [sigma, setSigma] = useState<SigmaStatsResponse | null>(null);
  const [ueba, setUeba] = useState<UEBAProfilesResponse | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const token =
    typeof window !== "undefined" ? localStorage.getItem("soc_token") || undefined : undefined;

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const [sigmaData, uebaData, alertData] = await Promise.all([
        getSigmaStats(token),
        getUEBAProfiles(token),
        getAlerts(token, 150),
      ]);
      setSigma(sigmaData);
      setUeba(uebaData);
      setAlerts(alertData);
    } catch (err) {
      console.error(err);
      setError("Detection verileri alınamadı.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
        [
          alert.rule,
          alert.hostname,
          alert.username,
          alert.details,
          alert.type,
        ]
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
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <SummaryCard
          title="Sigma Matches"
          value={sigma?.total_matches ?? 0}
          hint="Toplam eşleşme"
          icon={<BookOpen size={15} />}
        />
        <SummaryCard
          title="24h Matches"
          value={sigma?.matches_last_24h ?? 0}
          hint="Son 24 saat"
          icon={<TrendingUp size={15} />}
        />
        <SummaryCard
          title="UEBA Profiles"
          value={ueba?.profile_count ?? 0}
          hint="Davranış profili"
          icon={<Users size={15} />}
        />
        <SummaryCard
          title="Risky Profiles"
          value={ueba?.risky_profile_count ?? 0}
          hint="Yüksek risk"
          icon={<Brain size={15} />}
        />
        <SummaryCard
          title="Sigma-like Alerts"
          value={sigmaLikeAlerts.length}
          hint="Alert korelasyonu"
          icon={<Shield size={15} />}
        />
        <SummaryCard
          title="Correlation Groups"
          value={correlationGroups.length}
          hint="Tekrarlı host kümeleri"
          icon={<Activity size={15} />}
        />
      </div>

      <Panel
        title="Detection Insights"
        subtitle="Sigma, UEBA ve korelasyon görünümü"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={loadData}
              className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 px-3 py-2 text-sm text-zinc-700 transition hover:bg-zinc-50 dark:border-white/10 dark:text-zinc-200 dark:hover:bg-white/[0.05]"
            >
              <RefreshCw size={14} />
              Yenile
            </button>
          </div>
        }
      >
        <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="inline-flex rounded-2xl border border-zinc-200 bg-zinc-50 p-1 dark:border-white/10 dark:bg-white/[0.03]">
            {[
              { id: "sigma", label: "Sigma" },
              { id: "ueba", label: "UEBA" },
              { id: "correlation", label: "Correlation" },
            ].map((item) => (
              <button
                key={item.id}
                onClick={() => setTab(item.id as DetectionTab)}
                className={`rounded-xl px-4 py-2 text-sm font-medium transition ${
                  tab === item.id
                    ? "bg-zinc-900 text-white dark:bg-white dark:text-zinc-900"
                    : "text-zinc-600 hover:text-zinc-900 dark:text-zinc-300 dark:hover:text-white"
                }`}
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
              className="w-full rounded-2xl border border-zinc-200 bg-white px-10 py-3 text-sm outline-none transition focus:border-zinc-400 dark:border-white/10 dark:bg-white/[0.03] dark:text-white dark:focus:border-white/20"
            />
          </div>
        </div>

        {error ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-400">
            {error}
          </div>
        ) : null}

        {loading ? (
          <div className="text-sm text-zinc-500 dark:text-zinc-400">Detection verileri yükleniyor...</div>
        ) : (
          <>
            {tab === "sigma" && (
              <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
                <div className="space-y-6">
                  <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                    <div className="mb-3 flex items-center justify-between">
                      <div className="text-sm font-black">Engine Status</div>
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${engineBadge(sigma?.engine_status)}`}>
                        {sigma?.engine_status || "idle"}
                      </span>
                    </div>

                    {sigma?.note ? (
                      <p className="text-sm text-zinc-600 dark:text-zinc-400">{sigma.note}</p>
                    ) : (
                      <p className="text-sm text-zinc-600 dark:text-zinc-400">
                        Sigma eşleşmeleri ve kural dağılımı burada izlenir.
                      </p>
                    )}
                  </section>

                  <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                    <div className="mb-3 flex items-center gap-2">
                      <Cpu size={15} />
                      <div className="text-sm font-black">Severity Distribution</div>
                    </div>

                    <div className="space-y-4">
                      {Object.entries(sigma?.severity_distribution || {}).map(([sev, count]) => (
                        <div key={sev}>
                          <div className="mb-1 flex items-center justify-between text-sm">
                            <span>{sev}</span>
                            <span className="text-zinc-500 dark:text-zinc-400">{count}</span>
                          </div>
                          <div className="h-2 rounded-full bg-zinc-200 dark:bg-white/10">
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

                  <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                    <div className="mb-3 flex items-center gap-2">
                      <BookOpen size={15} />
                      <div className="text-sm font-black">Top Rules</div>
                    </div>

                    <div className="space-y-4">
                      {(sigma?.top_rules || []).map((rule) => (
                        <div key={rule.name}>
                          <div className="mb-1 flex items-center justify-between text-sm">
                            <span className="truncate">{rule.name}</span>
                            <span className="text-zinc-500 dark:text-zinc-400">{rule.count}</span>
                          </div>
                          <div className="h-2 rounded-full bg-zinc-200 dark:bg-white/10">
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

                <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                  <div className="mb-4 flex items-center gap-2">
                    <Shield size={15} />
                    <div className="text-sm font-black">Sigma-like Alerts</div>
                  </div>

                  {sigmaLikeAlerts.length === 0 ? (
                    <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-8 text-center text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
                      Eşleşen sigma-benzeri alert yok.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {sigmaLikeAlerts.slice(0, 30).map((alert) => (
                        <div
                          key={alert.id}
                          className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <SeverityBadge severity={alert.severity} />
                              </div>
                              <div className="mt-2 truncate text-sm font-semibold">
                                {alert.rule || alert.type || "Alert"}
                              </div>
                              <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                                {alert.hostname || "unknown-host"} · {alert.username || "SYSTEM"} · {relativeTime(alert.created_at)}
                              </div>
                              {alert.details ? (
                                <div className="mt-2 line-clamp-2 text-xs text-zinc-600 dark:text-zinc-400">
                                  {alert.details}
                                </div>
                              ) : null}
                            </div>

                            <div className="w-24 shrink-0">
                              <div className="text-right text-sm font-bold">{alert.risk_score || 0}</div>
                              <div className="mt-2 h-2 rounded-full bg-zinc-200 dark:bg-white/10">
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
                  <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                    <div className="mb-3 text-sm font-black">Baseline Status</div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-zinc-600 dark:text-zinc-400">Baseline Ready</span>
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

                    <div className="mt-4 text-xs text-zinc-500 dark:text-zinc-400">
                      Son güncelleme: {fmtDate(ueba?.last_profile_update_at)}
                    </div>
                    {ueba?.note ? (
                      <div className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">{ueba.note}</div>
                    ) : null}
                  </div>

                  <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
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

                <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                  <div className="mb-4 flex items-center gap-2">
                    <Brain size={15} />
                    <div className="text-sm font-black">Risky Profiles</div>
                  </div>

                  {topRiskProfiles.length === 0 ? (
                    <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-8 text-center text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
                      Gösterilecek profil yok.
                    </div>
                  ) : (
                    <div className="grid gap-3 md:grid-cols-2">
                      {topRiskProfiles.map((profile) => (
                        <div
                          key={`${profile.entity_type}-${profile.entity_name}`}
                          className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="min-w-0">
                              <div className="truncate text-sm font-semibold">{profile.entity_name}</div>
                              <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                                {profile.entity_type} · {profile.alert_count} alert · {relativeTime(profile.last_seen)}
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
                  )}
                </section>
              </div>
            )}

            {tab === "correlation" && (
              <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
                <section className="space-y-6">
                  <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
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

                  <div className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                    <div className="mb-3 flex items-center gap-2">
                      <AlertTriangle size={15} />
                      <div className="text-sm font-black">Correlation Logic</div>
                    </div>
                    <p className="text-sm text-zinc-600 dark:text-zinc-400">
                      Aynı host üzerinde tekrar eden alertler, kullanıcı çeşitliliği ve kural çeşitliliği
                      birlikte değerlendirilir.
                    </p>
                  </div>
                </section>

                <section className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10">
                  <div className="mb-4 text-sm font-black">Repeated Host Groups</div>

                  {correlationGroups.length === 0 ? (
                    <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-8 text-center text-sm text-zinc-500 dark:border-white/10 dark:bg-white/[0.03] dark:text-zinc-400">
                      Korelasyon grubu bulunamadı.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {correlationGroups.slice(0, 30).map((group) => (
                        <div
                          key={group.host}
                          className="rounded-2xl border border-zinc-200 p-4 dark:border-white/10"
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="min-w-0">
                              <div className="truncate text-sm font-semibold">{group.host}</div>
                              <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                                {group.count} alert · {group.users.size} user · {group.rules.size} rule
                              </div>
                              <div className="mt-2 text-xs text-zinc-600 dark:text-zinc-400">
                                Users: {[...group.users].slice(0, 4).join(", ") || "—"}
                              </div>
                              <div className="mt-1 text-xs text-zinc-600 dark:text-zinc-400">
                                Last Seen: {fmtDate(group.lastSeen)}
                              </div>
                            </div>

                            <div className="w-28 shrink-0">
                              <div className="text-right text-sm font-bold">{group.maxRisk}</div>
                              <div className="mt-2 h-2 rounded-full bg-zinc-200 dark:bg-white/10">
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

function MiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-zinc-200 p-3 dark:border-white/10">
      <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-400">
        {label}
      </div>
      <div className="mt-2 text-2xl font-black">{value}</div>
    </div>
  );
}
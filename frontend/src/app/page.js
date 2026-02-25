"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import {
  Shield, Download, Terminal, Activity, Check, AlertCircle,
  Server, Lock, Zap, Monitor, HardDrive, Wifi, Clock, Package,
  ArrowRight, Globe, Search, ChevronRight, Copy, RefreshCw
} from "lucide-react";

const API = "http://localhost:8000";
const WS  = "ws://localhost:8000/ws/alerts";

const fmtUptime = (s) => {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}sa ${m}dk` : `${m}dk`;
};

const STEPS = [
  { n: "01", title: "İndir",    icon: <Download size={15}/>, code: null,
    desc: "Aşağıdaki butona tıklayarak agent ZIP dosyasını indirin." },
  { n: "02", title: "Çıkar",    icon: <Package size={15}/>,  code: null,
    desc: "ZIP'i istediğiniz bir klasöre çıkarın (ör: C:\\solidtrace)." },
  { n: "03", title: "Çalıştır", icon: <Terminal size={15}/>, code: `.\\solidtrace-agent.exe`,
    desc: "Yönetici olarak PowerShell açın ve çalıştırın." },
  { n: "04", title: "Doğrula",  icon: <Wifi size={15}/>,     code: null,
    desc: "SOC panelinde Asset sekmesini açın — makineniz saniyeler içinde görünür." },
];

const FEATURES = [
  { icon: <Activity size={13}/>,  label: "Process İzleme" },
  { icon: <HardDrive size={13}/>, label: "Dosya Sistemi" },
  { icon: <Monitor size={13}/>,   label: "Event Log" },
  { icon: <Zap size={13}/>,       label: "USB Monitörü" },
  { icon: <Globe size={13}/>,     label: "Ağ İzleme" },
  { icon: <Lock size={13}/>,      label: "Registry" },
  { icon: <Shield size={13}/>,    label: "Sigma Kuralları" },
  { icon: <Server size={13}/>,    label: "Düşük Kaynak" },
];

export default function Home() {
  const [socOnline,    setSocOnline]    = useState(false);
  const [status,       setStatus]       = useState(null);
  const [agentInfo,    setAgentInfo]    = useState(null);
  const [osintLoading, setOsintLoading] = useState(false);
  const [osintData,    setOsintData]    = useState(null);
  const [osintError,   setOsintError]   = useState(null);
  const [copied,       setCopied]       = useState(null);
  const [activeStep,   setActiveStep]   = useState(0);
  const [lastAlert,    setLastAlert]    = useState(null);
  const wsRef = useRef(null);

  const fetchStatus = useCallback(async () => {
    try {
      const [sRes, aRes] = await Promise.allSettled([
        fetch(`${API}/api/system/status`),
        fetch(`${API}/api/agent/info`),
      ]);
      if (sRes.status === "fulfilled" && sRes.value.ok) {
        const d = await sRes.value.json();
        setStatus(d); setSocOnline(d.backend);
      } else {
        try {
          const r = await fetch(`${API}/api/stats`);
          if (r.ok) {
            const d = await r.json();
            setSocOnline(true);
            setStatus({ backend: true, db: true, agents_online: 0, total_alerts: d.total_logs || 0, uptime_seconds: 0 });
          } else setSocOnline(false);
        } catch { setSocOnline(false); }
      }
      if (aRes.status === "fulfilled" && aRes.value.ok) {
        setAgentInfo(await aRes.value.json());
      } else {
        setAgentInfo({
          version: "1.0.0", build_date: "2026-02-22", size_mb: 4.2, sha256: "—",
          changelog: [
            "Rust tabanlı hafif agent", "Windows Event Log izleme",
            "USB, dosya, process, registry monitörü",
            "Gerçek zamanlı WebSocket raporlama",
            "Sigma kural motoru", "Otomatik yeniden bağlanma",
          ],
        });
      }
    } catch { setSocOnline(false); }
  }, []);

  useEffect(() => {
    fetchStatus();
    const t = setInterval(fetchStatus, 15000);
    return () => clearInterval(t);
  }, [fetchStatus]);

  useEffect(() => {
    if (!socOnline) return;
    const ws = new WebSocket(WS);
    wsRef.current = ws;
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "alert" || msg.type === "ALERT") {
          const d = msg.data || msg.payload;
          if (d) setLastAlert(d);
        }
      } catch {}
    };
    return () => { ws.close(); wsRef.current = null; };
  }, [socOnline]);

  const runOsint = async () => {
    setOsintLoading(true); setOsintData(null); setOsintError(null);
    try {
      let ip = "Bilinmiyor", isp = "—", city = "—", country = "—";
      try {
        const r = await fetch("https://ipapi.co/json/");
        if (r.ok) {
          const d = await r.json();
          ip = d.ip; isp = d.org || "—"; city = d.city || "—"; country = d.country_name || "—";
        }
      } catch {}

      let webRTC_Leak = "HAYIR ✓";
      try {
        const rtcIPs = [];
        await new Promise((resolve) => {
          const rtc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
          rtc.createDataChannel("");
          rtc.createOffer().then(o => rtc.setLocalDescription(o));
          rtc.onicecandidate = (ice) => {
            if (ice && ice.candidate && ice.candidate.candidate) {
              const m = ice.candidate.candidate.match(/([0-9]{1,3}\.){3}[0-9]{1,3}/g);
              if (m) rtcIPs.push(...m);
            } else if (!ice.candidate) { rtc.close(); resolve(); }
          };
          setTimeout(resolve, 3000);
        });
        const priv = rtcIPs.filter(i => i.startsWith("192.168.") || i.startsWith("10.") || i.startsWith("172."));
        if (priv.length > 0) webRTC_Leak = `EVET ⚠️ (${priv[0]})`;
      } catch {}

      const fingerprint = [
        navigator.userAgent.substring(0, 50),
        `${screen.width}x${screen.height}`,
        navigator.language,
        Intl.DateTimeFormat().resolvedOptions().timeZone,
      ].join(" · ");

      setOsintData({ ip, isp, city, country, webRTC_Leak, fingerprint });
    } catch (e) {
      setOsintError("Tarama başarısız: " + (e.message || "Bilinmeyen hata"));
    }
    setOsintLoading(false);
  };

  const copy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="min-h-screen bg-[#030303] text-white font-mono overflow-x-hidden">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700;800&display=swap');
        *{font-family:'JetBrains Mono',monospace;box-sizing:border-box}
        ::-webkit-scrollbar{display:none}
        .scan{background-image:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,255,255,0.007) 2px,rgba(255,255,255,0.007) 4px);pointer-events:none}
        @keyframes su{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
        .a1{animation:su .4s 0s both}.a2{animation:su .4s .08s both}
        .a3{animation:su .4s .16s both}.a4{animation:su .4s .24s both}
        @keyframes pb{0%,100%{border-color:rgba(239,68,68,0.12)}50%{border-color:rgba(239,68,68,0.35)}}
        .pb{animation:pb 2.5s infinite}
      `}</style>

      <div className="fixed inset-0 scan z-0" />
      <div className="fixed top-0 left-0 right-0 h-px bg-linear-to-r from-transparent via-red-500/40 to-transparent z-50" />
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-150 h-55 bg-red-500/4 blur-3xl pointer-events-none z-0" />

      {/* HEADER */}
      <header className="sticky top-0 z-40 border-b border-white/5 bg-black/70 backdrop-blur-2xl">
        <div className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center justify-center">
              <Shield size={13} className="text-red-400" />
            </div>
            <span className="text-xs font-black tracking-widest">SOLIDTRACE</span>
            <span className="text-[8px] text-white/20 border border-white/10 px-1.5 py-0.5 rounded tracking-widest">SOC v6.1</span>
          </div>
          <div className="flex items-center gap-3">
            <div className={`hidden sm:flex items-center gap-1.5 text-[9px] px-2.5 py-1.5 rounded-full border font-black ${
              socOnline
                ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400"
                : "border-red-500/20 bg-red-500/5 text-red-400 animate-pulse"
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${socOnline ? "bg-emerald-400" : "bg-red-500"}`} />
              {socOnline ? "BACKEND ONLINE" : "BACKEND OFFLINE"}
            </div>
            <Link href="/soc" className="flex items-center gap-1.5 px-4 py-2 bg-red-600 hover:bg-red-500 active:scale-95 text-white rounded-lg text-[10px] font-black uppercase tracking-widest transition-all">
              SOC Paneli <ArrowRight size={11} />
            </Link>
          </div>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-5 pb-24 relative z-10 space-y-10 pt-14">

        {/* HERO */}
        <div className="a1">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-red-500/5 border border-red-500/15 rounded-full text-[9px] text-red-400 font-black uppercase tracking-widest mb-6">
            <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />
            Endpoint Detection &amp; Response
          </div>
          <h1 className="text-5xl sm:text-6xl font-black tracking-[-0.04em] leading-none mb-5">
            <span className="text-white">Uç nokta</span><br />
            <span className="text-white/10">güvenliği,</span><br />
            <span className="bg-linear-to-r from-red-400 to-orange-400 bg-clip-text text-transparent">
              sıfır karmaşıklık.
            </span>
          </h1>
          <p className="text-white/30 text-sm leading-relaxed max-w-md">
            SolidTrace — Windows uç noktalarınızı gerçek zamanlı izler, tehditleri anında SOC panelinize raporlar.
          </p>
          {lastAlert && (
            <div className="mt-5 inline-flex items-center gap-2.5 px-4 py-2 bg-red-500/5 border border-red-500/15 rounded-xl text-[10px]">
              <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse shrink-0" />
              <span className="text-red-400 font-black">{lastAlert.severity}</span>
              <span className="text-white/35">{lastAlert.rule}</span>
              <span className="text-white/20">@{lastAlert.hostname}</span>
            </div>
          )}
        </div>

        {/* İKİ KOLON */}
        <div className="a2 grid sm:grid-cols-2 gap-4">

          {/* AGENT KARTI */}
          <div className={`pb border rounded-2xl overflow-hidden flex flex-col ${
            socOnline
              ? "bg-emerald-500/2.5 border-emerald-500/15"
              : "bg-white/1.5 border-white/5"
          }`}>
            <div className="p-5 border-b border-white/5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className={`w-8 h-8 rounded-xl flex items-center justify-center border ${
                    socOnline
                      ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                      : "bg-white/3 border-white/5 text-white/30"
                  }`}>
                    <Shield size={15} />
                  </div>
                  <div>
                    <p className="text-xs font-black text-white">SolidTrace Agent</p>
                    <p className={`text-[9px] ${socOnline ? "text-emerald-400" : "text-white/25"}`}>
                      {socOnline ? "● BACKEND AKTİF" : "Windows x64"}
                    </p>
                  </div>
                </div>
                <span className="text-[8px] font-mono text-white/25">
                  v{agentInfo?.version ?? "1.0.0"} · {agentInfo?.size_mb ?? "—"}MB
                </span>
              </div>
            </div>

            <div className="p-5 flex flex-col gap-4 flex-1">
              {socOnline && status && (
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { label: "Online Agent", val: status.agents_online },
                    { label: "Toplam Olay",  val: status.total_alerts },
                    { label: "Uptime",       val: fmtUptime(status.uptime_seconds) },
                  ].map(s => (
                    <div key={s.label} className="bg-black/30 border border-white/5 rounded-xl p-2.5 text-center">
                      <p className="text-[8px] text-white/25 mb-1">{s.label}</p>
                      <p className="text-xs font-black text-emerald-400">{s.val}</p>
                    </div>
                  ))}
                </div>
              )}

              <div className="flex flex-wrap gap-1.5">
                {FEATURES.map((f, i) => (
                  <div key={i} className="flex items-center gap-1 px-2 py-1 bg-white/2.5 border border-white/5 rounded-lg text-[8px] text-white/30">
                    <span className="text-white/20">{f.icon}</span>{f.label}
                  </div>
                ))}
              </div>

              {agentInfo?.sha256 && agentInfo.sha256 !== "—" && (
                <div className="flex items-center gap-2 bg-black/30 border border-white/5 rounded-xl px-3 py-2">
                  <span className="text-[8px] text-white/20 shrink-0">SHA256</span>
                  <code className="text-[8px] text-white/30 font-mono flex-1 truncate">{agentInfo.sha256}</code>
                  <button onClick={() => copy(agentInfo.sha256, "sha")} className="text-white/20 hover:text-white/50 transition shrink-0">
                    <span className="flex">{copied === "sha" ? <Check size={10} className="text-emerald-400" /> : <Copy size={10} />}</span>
                  </button>
                </div>
              )}

              <div className="mt-auto flex flex-col gap-2">
                <a
                  href={`${API}/api/agent/download`}
                  onClick={e => { if (!socOnline) { e.preventDefault(); alert("Backend çalışmıyor — önce backend'i başlatın."); }}}
                  className="flex items-center justify-center gap-2 py-3 bg-red-600 hover:bg-red-500 active:scale-95 text-white rounded-xl font-black text-[10px] uppercase tracking-widest transition-all group"
                >
                  <Download size={14} className="group-hover:-translate-y-0.5 transition-transform" />
                  Agent İndir (.zip)
                </a>
                <Link href="/soc" className="flex items-center justify-center gap-2 py-2.5 bg-white/2.5 hover:bg-white/5 border border-white/5 text-white/40 hover:text-white/70 rounded-xl font-black text-[10px] uppercase tracking-widest transition-all">
                  SOC Dashboard <ChevronRight size={11} />
                </Link>
              </div>
            </div>
          </div>

          {/* OSINT KARTI */}
          <div className="bg-white/1.5 border border-white/5 rounded-2xl overflow-hidden flex flex-col">
            <div className="p-5 border-b border-white/5">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 bg-blue-500/10 border border-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
                  <Search size={15} />
                </div>
                <div>
                  <p className="text-xs font-black text-white">OSINT &amp; Gizlilik Testi</p>
                  <p className="text-[9px] text-white/25">IP · WebRTC Sızıntısı · Parmak İzi</p>
                </div>
              </div>
            </div>

            <div className="p-5 flex flex-col gap-3 flex-1">
              {!osintData ? (
                <>
                  <p className="text-[10px] text-white/30 leading-relaxed">
                    Public IP adresinizi, <span className="text-blue-400">WebRTC sızıntısını</span> ve
                    tarayıcı parmak izinizi analiz edin. Veriler sunucuya gönderilmez.
                  </p>
                  {osintError && (
                    <div className="flex items-center gap-2 text-[10px] text-red-400 bg-red-500/5 border border-red-500/15 rounded-xl px-3 py-2">
                      <AlertCircle size={11} /> {osintError}
                    </div>
                  )}
                  <button
                    onClick={runOsint}
                    disabled={osintLoading}
                    className="mt-auto py-3 bg-blue-600/70 hover:bg-blue-500 active:scale-95 text-white rounded-xl font-black text-[10px] uppercase tracking-widest transition-all disabled:opacity-40 flex items-center justify-center gap-2"
                  >
                    {osintLoading && <RefreshCw size={13} className="animate-spin" />}
                    {!osintLoading && <Search size={13} />}
                    <span>{osintLoading ? "Taranıyor..." : "Tarama Başlat"}</span>
                  </button>
                </>
              ) : (
                <div className="flex flex-col gap-2.5 flex-1">
                  {[
                    { label: "IP Adresi",       val: osintData.ip,  color: "text-blue-400" },
                    { label: "Servis Sağlayıcı", val: osintData.isp, color: "text-white/50" },
                    { label: "Konum",            val: `${osintData.city}, ${osintData.country}`, color: "text-white/50" },
                    { label: "WebRTC Sızıntısı", val: osintData.webRTC_Leak,
                      color: osintData.webRTC_Leak.includes("EVET") ? "text-red-400" : "text-emerald-400" },
                  ].map(r => (
                    <div key={r.label} className="flex items-center justify-between bg-black/30 border border-white/5 rounded-xl px-3 py-2.5">
                      <span className="text-[9px] text-white/25 uppercase tracking-widest">{r.label}</span>
                      <span className={`text-xs font-black font-mono ${r.color}`}>{r.val}</span>
                    </div>
                  ))}
                  {osintData.fingerprint && (
                    <div className="bg-black/30 border border-white/5 rounded-xl px-3 py-2.5">
                      <p className="text-[8px] text-white/20 mb-1 uppercase tracking-widest">Parmak İzi</p>
                      <p className="text-[9px] text-white/30 font-mono break-all leading-relaxed">{osintData.fingerprint}</p>
                    </div>
                  )}
                  {osintData.webRTC_Leak.includes("EVET") && (
                    <div className="flex items-start gap-2 bg-red-500/5 border border-red-500/15 rounded-xl px-3 py-2.5 text-[9px] text-red-400">
                      <AlertCircle size={11} className="shrink-0 mt-0.5" />
                      VPN kullansanız bile gerçek IP'niz sızdı. Tarayıcı WebRTC ayarlarını kapatın.
                    </div>
                  )}
                  <button
                    onClick={() => { setOsintData(null); setOsintError(null); }}
                    className="mt-auto py-2 bg-white/2.5 hover:bg-white/5 border border-white/5 text-white/35 hover:text-white/65 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all"
                  >
                    Yeni Tarama
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* KURULUM ADIMLARI */}
        <div className="a3">
          <p className="text-[9px] text-white/20 uppercase tracking-widest mb-5 flex items-center gap-3">
            <span className="flex-1 h-px bg-white/5" />Kurulum — 4 Adım<span className="flex-1 h-px bg-white/5" />
          </p>
          <div className="grid sm:grid-cols-4 gap-2.5">
            {STEPS.map((step, i) => (
              <button
                key={i}
                onClick={() => setActiveStep(i)}
                className={`text-left p-4 rounded-xl border transition-all ${
                  activeStep === i
                    ? "bg-white/5 border-red-500/20 text-white"
                    : "bg-white/1 border-white/5 text-white/30 hover:border-white/10 hover:text-white/50"
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <span className={`text-[9px] font-black tracking-widest ${activeStep === i ? "text-red-400" : "text-white/20"}`}>{step.n}</span>
                  <span className={activeStep === i ? "text-red-400" : "text-white/20"}>{step.icon}</span>
                </div>
                <p className="text-xs font-black mb-1">{step.title}</p>
                <p className="text-[9px] leading-relaxed opacity-55">{step.desc}</p>
                {step.code && activeStep === i && (
                  <div className="mt-3 flex items-center gap-2 bg-black/50 border border-white/5 rounded-lg px-2.5 py-2">
                    <code className="text-[10px] text-emerald-400 flex-1 font-mono">{step.code}</code>
                    <button
                      onClick={e => { e.stopPropagation(); copy(step.code, `step-${i}`); }}
                      className="text-white/20 hover:text-white/55 transition"
                    >
                      <span className="flex">{copied === `step-${i}` ? <Check size={10} className="text-emerald-400" /> : <Copy size={10} />}</span>
                    </button>
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* SİSTEM DURUMU */}
        {status && (
          <div className="a4 bg-white/1 border border-white/5 rounded-2xl p-5">
            <div className="flex items-center justify-between mb-4">
              <p className="text-[9px] text-white/25 uppercase tracking-widest flex items-center gap-2">
                <Server size={10} /> Sistem Durumu
              </p>
              <div className="flex items-center gap-3">
                {status.uptime_seconds > 0 && (
                  <span className="text-[9px] text-white/20 font-mono flex items-center gap-1">
                    <Clock size={9} /> {fmtUptime(status.uptime_seconds)}
                  </span>
                )}
                <button onClick={fetchStatus} className="text-white/20 hover:text-white/50 transition">
                  <RefreshCw size={11} />
                </button>
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {[
                { label: "Backend API",  val: status.backend ? "Çalışıyor" : "Kapalı",       ok: status.backend },
                { label: "PostgreSQL",   val: status.db      ? "Bağlı"     : "Bağlantı yok", ok: status.db },
                { label: "Online Agent", val: `${status.agents_online} makine`,               ok: true },
                { label: "Toplam Olay",  val: status.total_alerts.toLocaleString("tr-TR"),    ok: true },
              ].map((s, i) => (
                <div key={i} className="bg-black/30 border border-white/5 rounded-xl p-3">
                  <p className="text-[8px] text-white/20 uppercase tracking-widest mb-2">{s.label}</p>
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.ok ? "bg-emerald-400" : "bg-red-500 animate-pulse"}`} />
                    <span className="text-xs font-black text-white/50">{s.val}</span>
                  </div>
                </div>
              ))}
            </div>
            {!status.backend && (
              <div className="mt-3 bg-red-500/5 border border-red-500/15 rounded-xl p-3">
                <p className="text-[8px] text-red-400 font-black uppercase tracking-widest mb-2 flex items-center gap-1.5">
                  <AlertCircle size={10} /> Backend başlatılmamış
                </p>
                <div className="flex items-center gap-2 bg-black/50 rounded-lg px-3 py-2 border border-white/5">
                  <code className="text-[9px] text-white/35 font-mono flex-1">cd backend && python api_advanced_v2.py</code>
                  <button onClick={() => copy("cd backend && python api_advanced_v2.py", "bcmd")} className="text-white/20 hover:text-white/55 transition">
                    <span className="flex">{copied === "bcmd" ? <Check size={10} className="text-emerald-400" /> : <Copy size={10} />}</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <footer className="border-t border-white/5 py-6">
        <div className="max-w-6xl mx-auto px-5 flex items-center justify-between text-[9px] text-white/15">
          <span className="font-black tracking-widest">SOLIDTRACE SOC © 2026</span>
          <Link href="/soc" className="flex items-center gap-1 hover:text-white/40 transition">
            SOC Paneli <ChevronRight size={9} />
          </Link>
        </div>
      </footer>
    </div>
  );
}

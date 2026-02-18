"use client";
import React, { useEffect, useState, useRef, useCallback } from 'react';
import { 
  ShieldAlert, Activity, Search, WifiOff, Wifi, XOctagon, Loader2, Bot, Zap, 
  Server, ShieldCheck, Lock, LogIn, Usb, FileWarning, Globe, LayoutDashboard, 
  RefreshCw, Trash2, Plus, Copy, PieChart, AlertTriangle, BarChart3
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';

interface Alert {
  id: string; 
  hostname: string; 
  rule: string; 
  severity: 'CRITICAL' | 'HIGH' | 'WARNING' | 'INFO';
  serial: string; 
  pid: number; 
  details: string; 
  created_at: string; 
  risk_score: number;
  username?: string; 
  command_line?: string; 
  type?: string;
}

interface Rule { 
  id?: string; 
  name: string; 
  keyword: string; 
  risk_score: number; 
  severity: string; 
}

const formatDate = (dateString: string) => {
  try { 
    return new Date(dateString).toLocaleString('tr-TR', { 
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    }); 
  } catch { 
    return dateString; 
  }
};

// ✅ DÜZELTİLDİ: Global kilit - Strict Mode'da çift bağlantıyı önler
let wsLock = false;

export default function SOCDashboard() {
  // --- 🔐 AUTH STATE ---
  const [token, setToken] = useState<string | null>(null);
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [loginError, setLoginError] = useState("");

  // --- 📊 DASHBOARD STATE ---
  const [searchTerm, setSearchTerm] = useState(""); 
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState({ total: 0, critical: 0, activeHosts: 0, last_24h: 0 });
  const [analyticsData, setAnalyticsData] = useState<any>({ 
    severity_distribution: [], 
    activity_trend: [] 
  });
  const [showCharts, setShowCharts] = useState(false);
  
  const [wsConnected, setWsConnected] = useState(false);
  const [selectedLog, setSelectedLog] = useState<Alert | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [aiAnalysisResult, setAiAnalysisResult] = useState<string | null>(null);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [newRule, setNewRule] = useState<Rule>({ 
    name: "", 
    keyword: "", 
    risk_score: 50, 
    severity: "WARNING" 
  });
  
  const wsRef = useRef<WebSocket | null>(null);
  // ✅ DÜZELTİLDİ: Yeniden bağlanma zamanlayıcısı için ref
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // ✅ DÜZELTİLDİ: Bileşen hâlâ mount'ta mı? Unmount sonrası yeniden bağlanmayı engeller
  const isMountedRef = useRef(false);

  // ✅ YENİ: Client-side filtreleme - backend aramadan bağımsız, anlık
  const filteredAlerts = searchTerm.trim()
    ? alerts.filter((alert) => {
        const q = searchTerm.toLowerCase();
        return (
          alert.rule?.toLowerCase().includes(q) ||
          alert.hostname?.toLowerCase().includes(q) ||
          alert.details?.toLowerCase().includes(q) ||
          alert.serial?.toLowerCase().includes(q) ||
          alert.command_line?.toLowerCase().includes(q) ||
          alert.username?.toLowerCase().includes(q) ||
          String(alert.pid).includes(q) ||
          alert.severity?.toLowerCase().includes(q)
        );
      })
    : alerts;

  // --- 🚪 LOGIN ---
  const handleLogin = async (e: React.FormEvent) => {
      e.preventDefault();
      setLoginError("");
      try {
          const formData = new FormData();
          formData.append("username", loginForm.username);
          formData.append("password", loginForm.password);
          
          const res = await fetch("http://localhost:8000/api/login", { 
              method: "POST", 
              body: formData 
          });

          if (res.ok) {
              const data = await res.json();
              setToken(data.access_token);
              localStorage.setItem('soc_token', data.access_token);
          } else {
              setLoginError("Kullanıcı adı veya şifre hatalı!");
          }
      } catch (err) {
          setLoginError("Sunucuya erişilemiyor.");
      }
  };

  // Token'ı hafızadan yükle
  useEffect(() => {
      const savedToken = localStorage.getItem('soc_token');
      if (savedToken) setToken(savedToken);
  }, []);

  const getHeaders = () => ({
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json"
  });

  // --- 📡 VERİ ÇEKME ---
  // ✅ DÜZELTİLDİ: Artık arama backend'e gitmiyor, sadece tüm veriyi çekiyor
  const fetchHistory = useCallback(async () => {
      if (!token) return;
      
      try {
          const [statsRes, logsRes, analyticsRes] = await Promise.all([
              fetch("http://localhost:8000/api/stats", { headers: getHeaders() }),
              fetch("http://localhost:8000/api/alerts", { headers: getHeaders() }),
              fetch("http://localhost:8000/api/analytics", { headers: getHeaders() })
          ]);
          
          if (statsRes.ok && logsRes.ok && analyticsRes.ok) {
              const sData = await statsRes.json();
              const lData = await logsRes.json();
              const aData = await analyticsRes.json();
              
              setStats({ 
                total: sData.total_logs || 0, 
                critical: sData.critical_count || 0,
                last_24h: sData.last_24h || 0,
                activeHosts: new Set(lData.map((a: Alert) => a.hostname)).size
              });
              setAlerts(lData);
              setAnalyticsData(aData);
          }
      } catch(e) { 
          console.error("Veri çekme hatası:", e); 
      }
  }, [token]);

  // --- 🔌 WEBSOCKET ---
  // ✅ DÜZELTİLDİ: Global kilit + unmount koruması ile disko ışığı sorunu çözüldü
  const connectWs = useCallback(() => {
      if (!token) return;
      if (!isMountedRef.current) return; // Unmount olduktan sonra bağlanma
      if (wsLock) return;                // Zaten başka bir bağlantı kurulmaya çalışıyor

      // Mevcut bağlantı açıksa yeni bağlantı kurma
      if (wsRef.current?.readyState === WebSocket.OPEN) return;

      wsLock = true; // Kilidi koy

      const ws = new WebSocket("ws://localhost:8000/ws/alerts");
      wsRef.current = ws;
      
      ws.onopen = () => {
          wsLock = false; // Bağlantı kuruldu, kilidi aç
          if (isMountedRef.current) {
              setWsConnected(true);
              console.log("✅ WebSocket bağlantısı kuruldu");
          }
      };
      
      ws.onmessage = (e) => {
        try {
            const msg = JSON.parse(e.data);
            
            if (msg.type === 'alert') {
                // ✅ DÜZELTİLDİ: Canlı akışı hiç durdurmuyoruz.
                // Yeni log her zaman state'e ekleniyor; filtreleme zaten client-side yapılıyor.
                setAlerts(prev => [msg.data, ...prev].slice(0, 200));
                setStats(prev => ({ 
                    ...prev, 
                    total: prev.total + 1, 
                    critical: msg.data.severity === 'CRITICAL' ? prev.critical + 1 : prev.critical 
                }));
            } else if (msg.type === 'ACTION_LOG') {
                if (msg.message.includes("AI RAPORU") || msg.message.includes("🧠")) {
                    setAiAnalysisResult(msg.message);
                    setLoadingAction(null);
                }
            }
        } catch (err) { 
            console.error("WebSocket mesaj hatası:", err); 
        }
      };
      
      ws.onerror = (err) => {
          console.error("WebSocket hatası:", err);
          wsLock = false; // Hata durumunda kilidi serbest bırak
          if (isMountedRef.current) setWsConnected(false);
      };
      
      ws.onclose = () => {
          wsLock = false; // Kapandı, kilidi serbest bırak
          if (isMountedRef.current) {
              setWsConnected(false);
              console.log("🔌 WebSocket kapandı, 3sn sonra yeniden denenecek...");
              // ✅ DÜZELTİLDİ: 2sn → 3sn "soğuma" süresi; saldırgan yeniden bağlanma önlendi
              reconnectTimerRef.current = setTimeout(() => {
                  if (isMountedRef.current) connectWs();
              }, 3000);
          }
      };
  }, [token]);

  useEffect(() => { 
      if (token) { 
          isMountedRef.current = true;
          fetchHistory(); 
          connectWs(); 
      }
      return () => {
          // ✅ DÜZELTİLDİ: Temiz cleanup - zamanlayıcıyı ve bağlantıyı düzgünce kapat
          isMountedRef.current = false;
          wsLock = false;
          if (reconnectTimerRef.current) {
              clearTimeout(reconnectTimerRef.current);
          }
          if (wsRef.current) {
              wsRef.current.close();
              wsRef.current = null;
          }
      };
  }, [token, fetchHistory, connectWs]);

  // --- 🎨 AKILLI DETAY FORMATLAMA ---
  const formatDetails = (details: string) => {
      if (details.includes("\\") || details.includes("/")) {
          const parts = details.split(/[/\\]/);
          const fileName = parts.pop();
          return (
              <div className="flex flex-col min-w-0">
                  <span className="text-white font-bold break-all">{fileName}</span>
                  <span className="text-[9px] text-slate-500 break-all">{details}</span>
              </div>
          );
      }
      
      return (
        <span className="text-yellow-400 font-bold tracking-wide text-xs wrap-break-word bg-yellow-400/5 px-2 py-1 rounded border border-yellow-400/20 shadow-[0_0_10px_rgba(250,204,21,0.1)] block">
            {details}
        </span>
      );
  };

  const getIconForType = (type: string) => {
      const t = type?.toLowerCase() || "";
      if (t.includes("usb")) return <Usb size={14} className="text-yellow-400"/>;
      if (t.includes("network")) return <Globe size={14} className="text-blue-400"/>;
      if (t.includes("file")) return <FileWarning size={14} className="text-orange-400"/>;
      return <Activity size={14} className="text-slate-400"/>;
  };

  // --- ⚡ AKSIYONLAR ---
  const sendCommand = async (cmd: string, target: Alert | null) => {
      if (!target && cmd !== "CLEAR_LOGS") return;
      
      setLoadingAction(cmd);
      
      const endpoint = `http://localhost:8000/api/actions/${cmd.toLowerCase()}`;
      const payload = cmd === "AI_ANALYZE" ? {
          hostname: target?.hostname,
          pid: target?.pid,
          rule: target?.rule,
          severity: target?.severity,
          details: target?.details,
          serial: target?.serial,
          risk_score: target?.risk_score
      } : {
          hostname: target?.hostname,
          pid: target?.pid
      };

      try {
          const url = cmd === "CLEAR_LOGS" 
              ? "http://localhost:8000/api/alerts/clear" 
              : (cmd === "AI_ANALYZE" ? "http://localhost:8000/api/actions/analyze" : endpoint);
          
          await fetch(url, {
              method: cmd === "CLEAR_LOGS" ? "DELETE" : "POST",
              headers: getHeaders(),
              body: cmd === "CLEAR_LOGS" ? null : JSON.stringify(payload)
          });
          
          if (cmd === "CLEAR_LOGS") {
              setAlerts([]);
              setStats({ total: 0, critical: 0, activeHosts: 0, last_24h: 0 });
          }
          
          if (cmd !== "AI_ANALYZE") {
              setTimeout(() => setLoadingAction(null), 500);
          }
      } catch(e) { 
          console.error("Komut gönderme hatası:", e);
          setLoadingAction(null); 
      }
  };

  const handleAddRule = async () => {
      if(!newRule.name || !newRule.keyword) {
          alert("Kural adı ve kelime zorunludur!");
          return;
      }
      
      try {
          const res = await fetch("http://localhost:8000/api/rules", { 
              method: "POST", 
              headers: getHeaders(), 
              body: JSON.stringify(newRule) 
          });
          
          if (res.ok) {
              setShowRuleModal(false);
              setNewRule({ name: "", keyword: "", risk_score: 50, severity: "WARNING" });
              alert("✅ Kural başarıyla eklendi!");
          } else {
              alert("❌ Kural eklenirken hata oluştu!");
          }
      } catch(e) { 
          alert("❌ Sunucu hatası!"); 
      }
  };

  // --- 🚪 LOGİN EKRANI ---
  if (!token) {
      return (
          <div className="min-h-screen bg-[#020202] text-white flex items-center justify-center relative overflow-hidden font-mono selection:bg-indigo-500/30">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(99,102,241,0.08),transparent_70%)] pointer-events-none"></div>
              <div className="absolute top-0 left-0 w-full h-1 bg-linear-to-r from-transparent via-indigo-500 to-transparent opacity-50"></div>

              <div className="w-full max-w-md bg-[#0a0a0a] border border-white/5 p-8 rounded-3xl backdrop-blur-xl shadow-2xl relative z-10 group">
                  <div className="text-center mb-8">
                      <div className="w-16 h-16 bg-indigo-500/10 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-indigo-500/20 text-indigo-400 group-hover:scale-110 transition-transform duration-500 shadow-[0_0_30px_rgba(99,102,241,0.2)]">
                          <ShieldCheck size={32}/>
                      </div>
                      <h1 className="text-2xl font-black tracking-tighter text-transparent bg-clip-text bg-linear-to-r from-white to-slate-500">SolidTrace SOC</h1>
                      <p className="text-[10px] text-slate-500 uppercase tracking-[0.3em] mt-2 font-bold">Güvenli Erişim Kapısı v6.0</p>
                  </div>

                  <form onSubmit={handleLogin} className="space-y-4">
                      <div className="space-y-1">
                          <label className="text-[9px] font-black text-indigo-400 uppercase tracking-widest ml-1">Kullanıcı Adı</label>
                          <input 
                              type="text" 
                              value={loginForm.username} 
                              onChange={e => setLoginForm({...loginForm, username: e.target.value})} 
                              className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3.5 text-sm focus:border-indigo-500/50 focus:bg-indigo-500/5 outline-none transition-all text-white font-mono placeholder:text-slate-700" 
                              placeholder="admin" 
                              required
                          />
                      </div>
                      <div className="space-y-1">
                          <label className="text-[9px] font-black text-indigo-400 uppercase tracking-widest ml-1">Şifre</label>
                          <input 
                              type="password" 
                              value={loginForm.password} 
                              onChange={e => setLoginForm({...loginForm, password: e.target.value})} 
                              className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3.5 text-sm focus:border-indigo-500/50 focus:bg-indigo-500/5 outline-none transition-all text-white font-mono placeholder:text-slate-700" 
                              placeholder="••••••••" 
                              required
                          />
                      </div>
                      
                      {loginError && (
                          <div className="text-red-400 text-xs font-bold text-center bg-red-500/5 border border-red-500/10 py-3 rounded-xl animate-in fade-in slide-in-from-top-1">
                              ⚠️ {loginError}
                          </div>
                      )}

                      <button type="submit" className="w-full py-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-2 mt-6 active:scale-95 shadow-lg shadow-indigo-900/20">
                          <LogIn size={16}/> GİRİŞ YAP
                      </button>
                  </form>
                  
                  <div className="mt-6 text-center">
                      <p className="text-[9px] text-slate-600">
                          Varsayılan: <span className="text-slate-400 font-bold">admin</span> / <span className="text-slate-400 font-bold">admin123</span>
                      </p>
                  </div>
              </div>
          </div>
      );
  }

  // --- 📊 DASHBOARD EKRANI ---
  return (
    <div className="min-h-screen bg-[#020202] text-white font-mono flex flex-col overflow-hidden relative selection:bg-red-500/50">
      
      <style jsx global>{`
        ::-webkit-scrollbar { display: none !important; }
        * { -ms-overflow-style: none !important; scrollbar-width: none !important; }
        .glass-panel {
          background: rgba(15, 23, 42, 0.4);
          backdrop-filter: blur(20px);
          border: 1px solid rgba(255, 255, 255, 0.05);
        }
      `}</style>
      
      <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_50%_-10%,rgba(180,0,0,0.15),transparent_60%)] pointer-events-none"></div>

      {/* HEADER */}
      <header className="h-14 border-b border-white/5 bg-black/40 backdrop-blur-xl flex items-center justify-between px-6 shrink-0 z-30">
        <h1 className="text-2xl font-black tracking-tighter text-transparent bg-clip-text bg-linear-to-r from-red-600 to-amber-500">
          SolidTrace <span className="text-white/20 text-[9px] tracking-[0.4em] ml-2 uppercase">Core_SOC_v6.0</span>
        </h1>
        <div className="flex items-center gap-4">
            <div className={`px-4 py-1.5 rounded-full border text-[9px] font-black ${wsConnected ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-red-500/10 border-red-500/30 text-red-500 animate-pulse'}`}>
                {wsConnected ? '● LIVE' : '○ OFFLINE'}
            </div>
            <button 
                onClick={() => {
                    setToken(null);
                    localStorage.removeItem('soc_token');
                }} 
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-red-500/20 bg-red-500/5 text-red-400 text-[10px] font-bold hover:bg-red-500/10 transition-all"
            >
                <Lock size={12} /> ÇIKIŞ
            </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        
        {/* SIDEBAR */}
        <aside className="w-52 border-r border-white/5 bg-black/40 p-4 flex flex-col gap-4 shrink-0 backdrop-blur-2xl z-20">
            <div className="space-y-3">
                <MetricCard title="KRİTİK RİSK" value={stats.critical} color="red" icon={<ShieldAlert size={16}/>} />
                <MetricCard title="TOPLAM OLAY" value={stats.total} color="indigo" icon={<Activity size={16}/>} />
                <MetricCard title="AKTİF AJAN" value={stats.activeHosts} color="emerald" icon={<Server size={16}/>} />
            </div>

            <div className="mt-auto space-y-2 pb-2">
                <button 
                    onClick={() => setShowRuleModal(true)} 
                    className="w-full py-2.5 bg-indigo-600/20 border border-indigo-500/30 text-indigo-400 hover:bg-indigo-600/30 text-[10px] font-black rounded-xl flex items-center justify-center gap-2 active:scale-95"
                >
                    <Plus size={14} /><span>KURAL EKLE</span>
                </button>
                <button 
                    onClick={() => { setSearchTerm(""); fetchHistory(); }} 
                    className="w-full py-2.5 glass-panel hover:bg-white/10 text-[10px] font-black rounded-xl flex items-center justify-center gap-2 active:scale-95 text-slate-300"
                >
                    <RefreshCw size={14} className={loadingAction === 'REFRESH' ? 'animate-spin' : ''} /><span>YENİLE</span>
                </button>
                <button 
                    onClick={() => {
                        if (confirm("Tüm loglar silinecek! Emin misiniz?")) {
                            sendCommand("CLEAR_LOGS", null);
                        }
                    }} 
                    className="w-full py-2.5 bg-red-950/20 border border-red-500/20 text-red-500 text-[10px] font-black rounded-xl flex items-center justify-center gap-2 active:scale-95"
                >
                    <Trash2 size={14} /><span>TEMİZLE</span>
                </button>
            </div>
        </aside>

        {/* MAIN CONTENT */}
        <main className="flex-1 min-w-0 bg-transparent relative flex flex-col p-4 gap-4">
            
            {/* GRAFİKLER */}
            {showCharts && (
                <div className="grid grid-cols-3 gap-4 h-40 shrink-0 animate-in slide-in-from-top-4 duration-300">
                    <div className="col-span-2 glass-panel rounded-3xl p-4 flex flex-col border border-white/5 relative overflow-hidden">
                        <h3 className="text-[10px] font-black text-slate-500 tracking-widest uppercase mb-2 flex items-center gap-2">
                            <Activity size={12}/> Aktivite Trendi (Saatlik)
                        </h3>
                        <div className="flex-1 w-full min-h-0">
                            <ResponsiveContainer width="100%" height="100%">
                                <LineChart data={analyticsData.activity_trend}>
                                    <Tooltip 
                                        contentStyle={{backgroundColor: '#000', border: '1px solid #333', fontSize:'10px'}} 
                                        itemStyle={{color:'#fff'}} 
                                    />
                                    <Line 
                                        type="monotone" 
                                        dataKey="count" 
                                        stroke="#6366f1" 
                                        strokeWidth={2} 
                                        dot={{fill:'#6366f1', r:2}} 
                                        activeDot={{r:4}} 
                                    />
                                    <XAxis dataKey="time" hide />
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                    
                    <div className="glass-panel rounded-3xl p-4 flex flex-col border border-white/5">
                        <h3 className="text-[10px] font-black text-slate-500 tracking-widest uppercase mb-2 flex items-center gap-2">
                            <PieChart size={12}/> Risk Dağılımı
                        </h3>
                        <div className="flex-1 w-full min-h-0">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={analyticsData.severity_distribution} layout="vertical" margin={{left: -20}}>
                                    <XAxis type="number" hide />
                                    <YAxis 
                                        dataKey="name" 
                                        type="category" 
                                        width={60} 
                                        tick={{fontSize: 9, fill: '#64748b'}} 
                                    />
                                    <Tooltip 
                                        cursor={{fill: 'transparent'}} 
                                        contentStyle={{backgroundColor: '#000', border: '1px solid #333', fontSize:'10px'}} 
                                    />
                                    <Bar dataKey="value" barSize={12} radius={[0, 4, 4, 0]}>
                                        {analyticsData.severity_distribution.map((entry: any, index: number) => (
                                            <Cell 
                                                key={`cell-${index}`} 
                                                fill={
                                                    entry.name === 'CRITICAL' ? '#ef4444' : 
                                                    entry.name === 'HIGH' ? '#f97316' : 
                                                    '#3b82f6'
                                                } 
                                            />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                </div>
            )}

            {/* LOG TABLOSU */}
            <div className="flex-1 glass-panel rounded-4xl overflow-hidden shadow-2xl relative border border-white/5">
                <div className="absolute inset-0 overflow-auto">
                    
                    {/* ARAMA BARI */}
                    <div className="p-4 border-b border-white/5 flex items-center gap-4 bg-[#020202] sticky top-0 z-30 shadow-lg">
                        <div className="relative flex-1 max-w-md group">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-indigo-400 transition-colors" size={16} />
                            <input 
                                type="text" 
                                placeholder="Anlık ara: kural, hostname, detay, PID, komut..." 
                                className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-xs font-mono text-slate-300 focus:outline-none focus:border-indigo-500/50 focus:bg-indigo-500/5 transition-all placeholder:text-slate-700"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                // ✅ DÜZELTİLDİ: Enter artık backend'e gitmiyor, client-side anlık zaten çalışıyor
                            />
                        </div>
                        {/* ✅ YENİ: Kaç sonuç gösterildiğini bildir */}
                        {searchTerm.trim() && (
                            <span className="text-[10px] text-slate-500 font-mono shrink-0">
                                {filteredAlerts.length} / {alerts.length} sonuç
                            </span>
                        )}
                        <div className="flex gap-2">
                            <button 
                                onClick={() => setShowCharts(!showCharts)} 
                                className={`px-3 py-1.5 rounded-lg border text-[10px] font-bold transition-all flex items-center gap-2 ${showCharts ? 'bg-indigo-500/20 border-indigo-500/30 text-indigo-400' : 'bg-white/5 border-white/10 text-slate-400 hover:bg-white/10'}`}
                            >
                                <LayoutDashboard size={14} />
                                {showCharts ? 'GİZLE' : 'GRAFİK'}
                            </button>
                            {/* ✅ DÜZELTİLDİ: KRİTİK butonu artık client-side filtreler */}
                            <button 
                                onClick={() => setSearchTerm("critical")} 
                                className="px-3 py-1.5 rounded-lg border border-red-500/20 bg-red-500/10 text-red-400 text-[10px] font-bold hover:bg-red-500/20 transition-all"
                            >
                                KRİTİK
                            </button>
                            <button 
                                onClick={() => setSearchTerm("")} 
                                className="px-3 py-1.5 rounded-lg border border-white/10 bg-white/5 text-slate-400 text-[10px] font-bold hover:bg-white/10 transition-all"
                            >
                                SIFIRLA
                            </button>
                        </div>
                    </div>

                    {/* TABLO */}
                    <table className="w-full text-left border-collapse table-fixed">       
                        <thead className="text-emerald-400 text-[13px] uppercase font-bold tracking-widest sticky top-18.25 z-20 border-b border-indigo-500/20 shadow-xl bg-[#020202]">
                            <tr>
                                <th className="p-4 w-12 text-center">!</th>
                                <th className="p-4 w-24 text-center">Zaman</th>
                                <th className="p-4 w-48">Algılama Kuralı</th>
                                <th className="p-4 w-32">Endpoint</th>
                                <th className="p-4 w-44">Hardware ID</th>
                                <th className="p-4">Detaylar</th>
                                <th className="p-4 w-12 text-right"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/3 text-[12px]">
                            {filteredAlerts.length === 0 ? (
                                <tr>
                                    <td colSpan={7} className="p-8 text-center text-slate-500">
                                        <AlertTriangle size={32} className="mx-auto mb-2 opacity-50" />
                                        <p>{searchTerm.trim() ? `"${searchTerm}" için sonuç bulunamadı` : "Henüz log kaydı yok"}</p>
                                    </td>
                                </tr>
                            ) : (
                                filteredAlerts.map((alert) => (
                                    <tr 
                                        key={alert.id} 
                                        onClick={() => { setSelectedLog(alert); setAiAnalysisResult(null); }} 
                                        className={`group hover:bg-white/4 transition-all cursor-pointer relative ${alert.severity === 'CRITICAL' ? 'bg-red-500/3' : ''}`}
                                    >
                                        <td className="p-4 text-center">
                                            <div className={`w-2 h-2 rounded-full mx-auto shadow-[0_0_10px_currentColor] ${alert.severity === 'CRITICAL' ? 'bg-red-500 text-red-500 animate-pulse' : 'bg-slate-600 text-slate-600'}`}></div>
                                        </td>
                                        <td className="p-4 text-slate-300 font-mono text-center italic">{formatDate(alert.created_at)}</td>
                                        <td className={`p-4 font-black tracking-tighter ${alert.severity === 'CRITICAL' ? 'text-red-400' : 'text-slate-200'}`}>
                                            <div className="flex items-center gap-2">
                                                {getIconForType(alert.rule)}
                                                <span>{alert.rule}</span>
                                            </div>
                                        </td>
                                        <td className="p-4 text-slate-400 font-mono truncate">{alert.hostname}</td>
                                        <td className="p-4">
                                            <span 
                                                title={alert.serial} 
                                                className="font-mono text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20 uppercase max-w-28 truncate block transition-all duration-300 hover:max-w-100 hover:bg-indigo-500/20 relative z-0 hover:z-20"
                                            >
                                                {alert.serial || "SYS_INTERNAL"}
                                            </span>
                                        </td>
                                        <td className="p-4">
                                            <div className="flex flex-col gap-0.5 font-mono leading-tight">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-orange-500 font-bold bg-orange-500/10 px-1.5 rounded text-[10px] shrink-0 border border-orange-500/10">
                                                        PID:{alert.pid || "0"}
                                                    </span>
                                                    {formatDetails(alert.details)}
                                                </div>
                                            </div>
                                        </td>
                                        <td className="p-4 text-right">
                                            <Search size={14} className="opacity-0 group-hover:opacity-100 text-emerald-400 transition-all scale-125" />
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
      </div>

      {/* KURAL EKLEME MODALI */}
      {showRuleModal && (
        <div className="fixed inset-0 bg-black/95 backdrop-blur-2xl z-50 flex items-center justify-center p-4">
            <div className="bg-[#080808] border border-white/10 rounded-3xl w-full max-w-md shadow-2xl overflow-hidden animate-in zoom-in-95">
                <div className="p-6 border-b border-white/5 bg-white/2 flex justify-between items-center">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
                            <ShieldCheck size={20} />
                        </div>
                        <h3 className="font-bold text-white tracking-tight">Yeni Tespit Kuralı</h3>
                    </div>
                    <button 
                        onClick={() => setShowRuleModal(false)} 
                        className="text-slate-500 hover:text-white transition"
                    >
                        ✕
                    </button>
                </div>
                
                <div className="p-6 space-y-4">
                    <div className="space-y-2">
                        <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Kural Adı</label>
                        <input 
                            value={newRule.name} 
                            onChange={e => setNewRule({...newRule, name: e.target.value})} 
                            className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-xs text-white focus:border-indigo-500/50 outline-none" 
                            placeholder="Örn: Mimikatz Tespiti" 
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Aranacak Kelime</label>
                        <input 
                            value={newRule.keyword} 
                            onChange={e => setNewRule({...newRule, keyword: e.target.value})} 
                            className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-xs text-white focus:border-indigo-500/50 outline-none" 
                            placeholder="Örn: mimikatz.exe" 
                        />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Risk Skoru</label>
                            <input 
                                type="number" 
                                min="0" 
                                max="100"
                                value={newRule.risk_score} 
                                onChange={e => setNewRule({...newRule, risk_score: parseInt(e.target.value)})} 
                                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-xs text-white focus:border-indigo-500/50 outline-none" 
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Şiddet</label>
                            <select 
                                value={newRule.severity} 
                                onChange={e => setNewRule({...newRule, severity: e.target.value})} 
                                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-xs text-white focus:border-indigo-500/50 outline-none"
                            >
                                <option value="INFO">INFO</option>
                                <option value="WARNING">WARNING</option>
                                <option value="HIGH">HIGH</option>
                                <option value="CRITICAL">CRITICAL</option>
                            </select>
                        </div>
                    </div>
                </div>

                <div className="p-6 border-t border-white/5 bg-black/40">
                    <button 
                        onClick={handleAddRule} 
                        className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-bold text-xs uppercase tracking-widest transition-all"
                    >
                        KURALI KAYDET
                    </button>
                </div>
            </div>
        </div>
      )}

      {/* OLAY DETAY MODALI */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/95 backdrop-blur-2xl z-50 flex items-center justify-center p-4" onClick={() => setSelectedLog(null)}>
            <div className="bg-[#080808] border border-white/10 rounded-4xl w-full max-w-4xl flex flex-col max-h-[90vh] overflow-hidden shadow-2xl" onClick={e => e.stopPropagation()}>
                
                {/* HEADER */}
                <div className="p-6 border-b border-white/5 flex justify-between items-center bg-white/2">
                    <div className="flex items-center gap-4">
                        <div className={`p-3 rounded-2xl glass-panel ${selectedLog.severity === 'CRITICAL' ? 'border-red-500/30 text-red-500 shadow-red-500/10' : 'text-indigo-500'}`}>
                            <Bot size={28} />
                        </div>
                        <div>
                            <h2 className="text-xl font-black text-white uppercase tracking-tight">Olay Analizi</h2>
                            <p className="text-[9px] text-slate-600 font-mono tracking-widest mt-1 uppercase">
                                EVENT_ID: {selectedLog.id.substring(0, 16)}
                            </p>
                        </div>
                    </div>
                    <button 
                        onClick={() => setSelectedLog(null)} 
                        className="p-2 hover:bg-white/10 rounded-full text-slate-500 hover:text-white transition"
                    >
                        ✕
                    </button>
                </div>

                {/* İÇERİK */}
                <div className="flex-1 overflow-y-auto p-8 space-y-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <MetricBox label="UÇ NOKTA" value={selectedLog.hostname} />
                        <div className="glass-panel p-5 rounded-3xl border border-white/5 group/id-modal">
                            <div className="flex justify-between items-center mb-1">
                                <p className="text-[8px] text-slate-600 font-black tracking-widest uppercase">HARDWARE_ID</p>
                                <button 
                                    onClick={() => {
                                        navigator.clipboard.writeText(selectedLog.serial || "");
                                        alert("✅ Kopyalandı!");
                                    }} 
                                    className="opacity-0 group-hover/id-modal:opacity-100 text-indigo-400 hover:text-white transition-opacity"
                                >
                                    <Copy size={10}/>
                                </button>
                            </div>
                            <p className="text-[10px] font-mono text-indigo-400 break-all leading-tight">
                                {selectedLog.serial || "SYSTEM_INTERNAL"}
                            </p>
                        </div>
                        <MetricBox 
                            label="RİSK SKORU" 
                            value={`${selectedLog.risk_score} / 100`} 
                            color={selectedLog.risk_score > 70 ? 'text-red-500' : 'text-emerald-500'} 
                            isBold 
                        />
                        <MetricBox label="PROCESS_ID" value={selectedLog.pid || "0"} />
                    </div>

                    <div className="glass-panel p-6 rounded-3xl font-mono">
                        <span className="text-[9px] text-orange-500 font-black block mb-3 tracking-widest uppercase">
                            Süreci Yürüten İmzalı Dosya Yolu
                        </span>
                        <code className="text-[11px] text-slate-300 block bg-black/40 p-4 rounded-xl border border-white/5 leading-relaxed break-all shadow-inner">
                            {selectedLog.details.replace('🚀 Yol: ', '')}
                        </code>
                    </div>

                    {/* ✅ YENİ: command_line varsa göster */}
                    {selectedLog.command_line && (
                        <div className="glass-panel p-6 rounded-3xl font-mono">
                            <span className="text-[9px] text-purple-400 font-black block mb-3 tracking-widest uppercase">
                                Komut Satırı
                            </span>
                            <code className="text-[11px] text-slate-300 block bg-black/40 p-4 rounded-xl border border-white/5 leading-relaxed break-all shadow-inner">
                                {selectedLog.command_line}
                            </code>
                        </div>
                    )}

                    {/* ✅ YENİ: username varsa göster */}
                    {selectedLog.username && (
                        <div className="glass-panel p-4 rounded-2xl font-mono flex items-center gap-3">
                            <span className="text-[9px] text-slate-500 font-black tracking-widest uppercase shrink-0">KULLANICI:</span>
                            <span className="text-sm text-amber-400 font-bold">{selectedLog.username}</span>
                        </div>
                    )}

                    {aiAnalysisResult && (
                        <div className="bg-indigo-600/5 border border-indigo-500/20 p-6 rounded-4xl animate-in zoom-in-95">
                            <div className="flex items-center gap-3 mb-4">
                                <Zap size={18} className="text-indigo-400" />
                                <h3 className="text-xs font-black text-indigo-300 uppercase tracking-widest">
                                    SolidTrace_AI_Report
                                </h3>
                            </div>
                            <div className="text-[12px] text-slate-300 leading-relaxed font-mono whitespace-pre-wrap">
                                {aiAnalysisResult}
                            </div>
                        </div>
                    )}
                </div>

                {/* FOOTER BUTONLAR */}
                <div className="p-6 border-t border-white/5 bg-black/80 flex flex-wrap gap-3">
                    <button 
                        onClick={() => sendCommand("AI_ANALYZE", selectedLog)} 
                        disabled={loadingAction === 'AI_ANALYZE'} 
                        className="flex-1 py-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-2xl font-black text-[10px] uppercase tracking-widest transition-all flex items-center justify-center gap-3 active:scale-95 disabled:opacity-30"
                    >
                        {loadingAction === 'AI_ANALYZE' ? <Loader2 size={16} className="animate-spin" /> : <Bot size={18} />}
                        <span>AI ANALİZ BAŞLAT</span>
                    </button>
                    
                    <div className="flex gap-2 flex-1">
                        <button 
                            onClick={() => sendCommand("ISOLATE", selectedLog)} 
                            disabled={loadingAction === 'ISOLATE'} 
                            className="flex-1 py-4 glass-panel border-orange-500/20 text-orange-500 hover:bg-orange-500/10 rounded-2xl font-black text-[10px] uppercase tracking-widest transition-all flex items-center justify-center gap-3 active:scale-95 disabled:opacity-30"
                        >
                            {loadingAction === 'ISOLATE' ? <Loader2 className="animate-spin" /> : <WifiOff size={18} />}
                            <span>İZOLE ET</span>
                        </button>
                        <button 
                            onClick={() => sendCommand("UNISOLATE", selectedLog)} 
                            disabled={loadingAction === 'UNISOLATE'} 
                            className="flex-1 py-4 glass-panel border-emerald-500/20 text-emerald-500 hover:bg-emerald-500/10 rounded-2xl font-black text-[10px] uppercase tracking-widest transition-all flex items-center justify-center gap-3 active:scale-95 disabled:opacity-30"
                        >
                            {loadingAction === 'UNISOLATE' ? <Loader2 className="animate-spin" /> : <Wifi size={18} />}
                            <span>KALDIR</span>
                        </button>
                    </div>

                    {selectedLog.pid !== 0 && (
                        <button 
                            onClick={() => sendCommand("KILL", selectedLog)} 
                            disabled={loadingAction === 'KILL'} 
                            className="w-full py-4 bg-red-600 hover:bg-red-500 text-white rounded-2xl font-black text-[11px] uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-3 shadow-lg shadow-red-900/40 active:scale-95"
                        >
                            {loadingAction === 'KILL' ? <Loader2 size={16} className="animate-spin" /> : <XOctagon size={20} />}
                            <span>SÜRECİ SONLANDIR (PID: {selectedLog.pid})</span>
                        </button>
                    )}
                </div>
            </div>
        </div>
      )}
    </div>
  );
}

// --- YARDIMCI BILEŞENLER ---
const MetricCard = ({ title, value, icon, color }: any) => {
    const colors: any = { 
        red: "text-red-500", 
        indigo: "text-indigo-500", 
        emerald: "text-emerald-500" 
    };
    
    return (
        <div className="glass-panel p-4 rounded-2xl hover:bg-white/5 transition-all group overflow-hidden relative">
            <div className="flex justify-between items-center mb-1 relative z-10">
                <span className="text-[8px] font-black text-slate-500 tracking-widest uppercase">{title}</span>
                <span className={`opacity-50 group-hover:opacity-100 transition-opacity ${colors[color]}`}>
                    {icon}
                </span>
            </div>
            <p className="text-3xl font-black tracking-tighter relative z-10">{value}</p>
            <div className={`absolute -right-4 -bottom-4 w-16 h-16 rounded-full blur-2xl opacity-10 group-hover:opacity-30 transition-all ${
                color === 'red' ? 'bg-red-600' : 
                color === 'indigo' ? 'bg-indigo-600' : 
                'bg-emerald-600'
            }`}></div>
        </div>
    );
};

const MetricBox = ({ label, value, color = "text-white", isBold = false }: any) => (
    <div className="glass-panel p-5 rounded-3xl">
        <p className="text-[8px] text-slate-600 font-black mb-2 tracking-widest uppercase">{label}</p>
        <p className={`text-sm font-mono truncate ${color} ${isBold ? 'font-black' : ''}`}>{value}</p>
    </div>
);
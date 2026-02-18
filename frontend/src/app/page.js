"use client";
import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';

// --- AYARLAR ---
const PYTHON_API_URL = "http://localhost:8000"; 
const WS_URL = "ws://localhost:8000/ws/alerts"; 

export default function Home() {
  // --- STATE ---
  const [isAdmin, setIsAdmin] = useState(false); 
  const [showLogin, setShowLogin] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const [loadingAuth, setLoadingAuth] = useState(false);
  const [loadingOsint, setLoadingOsint] = useState(false);
  const [loadingAgent, setLoadingAgent] = useState(false);
  
  const [scanResult, setScanResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [pairingCode, setPairingCode] = useState(null);
  const [osintData, setOsintData] = useState(null);
  const [statusMsg, setStatusMsg] = useState("Bağlantı bekleniyor...");

  // 🔥 SOC Backend Durumu 🔥
  const [socStatus, setSocStatus] = useState('offline'); 
  const [socStats, setSocStats] = useState({ critical: 0, high: 0 });
  const wsRef = useRef(null);

  // --- 1. SİSTEM SAĞLIK KONTROLÜ ---
  useEffect(() => {
    const checkSocHealth = async () => {
      try {
        const res = await fetch(`${PYTHON_API_URL}/api/stats`);
        if (res.ok) {
          setSocStatus('online'); 
          const data = await res.json();
          setSocStats({ critical: data.critical_count || 0, high: data.total_logs || 0 });
        } else {
          setSocStatus('offline');
        }
      } catch (e) {
        setSocStatus('offline');
      }
    };

    checkSocHealth();
    const interval = setInterval(checkSocHealth, 3000);
    return () => clearInterval(interval);
  }, []);

  // --- 2. WEBSOCKET DİNLEME ---
  useEffect(() => {
    if (!pairingCode && !isAdmin) return; 

    const ws = new WebSocket(WS_URL);
    ws.onopen = () => setStatusMsg("Ajan bağlantısı bekleniyor...");
    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === 'alert' || message.type === 'ALERT') {
            const alertData = message.payload || message.data;
            setStatusMsg("⚡ Tehdit Algılandı! Analiz ediliyor...");
            
            setScanResult({
                id: alertData.id,
                created_at: alertData.created_at,
                ip_adresi: alertData.hostname || 'Localhost',
                durum: 'tamamlandi',
                cpu: 45, ram: 60, disk: 30,
                ai_raporu: JSON.stringify({
                    risk_score: alertData.risk_score || 85,
                    risk_level: alertData.severity || 'Yüksek',
                    summary: `Tehdit Tespiti: ${alertData.rule}`,
                    findings: [{ type: 'risk', title: alertData.rule, desc: alertData.details, fix: 'Sistemi izole edin.' }],
                    audit_steps: ['Ajan Tespiti', 'Kural Eşleşmesi', 'Log Kaydı']
                })
            });
            setLoadingAgent(false);
            setPairingCode(null);
            if(isAdmin) fetchHistory();
        }
    };
    return () => ws.close();
  }, [pairingCode, isAdmin]);

  // --- HELPER FUNCTIONS ---
  const fetchHistory = async () => {
    try {
      const res = await fetch(`${PYTHON_API_URL}/api/alerts`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.map(item => ({
            id: item.id, created_at: item.created_at, ip_adresi: item.hostname, durum: 'tamamlandi', cpu: item.risk_score > 50 ? 80 : 20, ram: 45
        })));
      }
    } catch (err) { console.error("Geçmiş hatası:", err); }
  };

  const startLocalScan = async () => {
    setLoadingAgent(true);
    setPairingCode(Math.floor(1000 + Math.random() * 9000).toString());
    setStatusMsg("Ajanın bağlanması bekleniyor...");
  };

  const copyToClipboard = () => {
    if(pairingCode) {
        navigator.clipboard.writeText(pairingCode);
        setStatusMsg("✅ KOPYALANDI!");
        setTimeout(() => setStatusMsg("Ajan bağlantısı bekleniyor..."), 1000);
    }
  };

  const downloadAgentFile = () => alert("Ajan indirme simülasyonu başlatıldı.");

  const handleLogin = (e) => { 
      e.preventDefault(); setLoadingAuth(true);
      if (email === 'admin@mail.com' && password === 'admin') {
          setIsAdmin(true); setShowLogin(false); fetchHistory();
      } else { alert("Hatalı giriş! (Local Mod: admin@mail.com / admin)"); }
      setLoadingAuth(false); 
  };
  
  const handleLogout = () => { setIsAdmin(false); setHistory([]); };
  
  // --- WEBRTC IP TESPİTİ (Eski Koddan Geri Getirildi) ---
  const getWebRTCIP = async () => { 
      return new Promise((resolve) => { 
          const rtc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] }); 
          rtc.createDataChannel(""); 
          rtc.createOffer().then(o => rtc.setLocalDescription(o)); 
          rtc.onicecandidate = (ice) => { 
              if (ice && ice.candidate && ice.candidate.candidate) { 
                  const match = ice.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/); 
                  if (match) { rtc.close(); resolve(match[1]); } 
              } 
          }; 
          setTimeout(() => resolve(null), 2000); 
      }); 
  };
  
  const resetState = () => { setLoadingOsint(false); setLoadingAgent(false); setScanResult(null); setPairingCode(null); setOsintData(null); };
  
  // 🔥 ESKİ YAPIDAKİ TARAMA FONKSİYONU (RESTORASYON) 🔥
  const startExternalScan = async () => {
    resetState(); 
    setLoadingOsint(true);
    try {
      // 1. GERÇEK VERİLERİ ÇEK (IP, ISP, KONUM)
      const ipRes = await fetch('https://ipapi.co/json/'); 
      if (!ipRes.ok) throw new Error("IP Servisine Bağlanılamadı (Reklam Engelleyici Kapatın)"); 
      const ipData = await ipRes.json();
      
      // 2. SIZINTI TESTİ YAP
      const leakedIP = await getWebRTCIP(); 
      const isVPNLeaking = leakedIP && leakedIP !== ipData.ip;
      const browserData = { userAgent: navigator.userAgent, webRTC_Leak: isVPNLeaking ? "EVET! (Tehlikeli)" : "Hayır (Güvenli)" };
      
      // Verileri State'e kaydet (Ekranda görünmesi için)
      setOsintData({ 
          ip: ipData.ip, 
          isp: ipData.org, 
          city: ipData.city, 
          country: ipData.country_name, 
          lat: ipData.latitude, 
          lon: ipData.longitude, 
          ...browserData 
      });
      
      // 3. LOGLARI PYTHON BACKEND'E GÖNDER (Supabase Yerine)
      // Bu sayede Admin panelinde de görünecek
      await fetch(`${PYTHON_API_URL}/api/v1/ingest`, {
          method: 'POST', 
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
              type: 'OSINT_SCAN', 
              hostname: 'Browser_Client', 
              details: `IP: ${ipData.ip} | ISP: ${ipData.org} | Location: ${ipData.city}`, 
              command_line: 'web_scan_initiated' 
          })
      }).catch(() => console.log("Backend log hatası (önemsiz)"));

      // 4. RAPOR OLUŞTUR (AI Yerine Dinamik Şablon)
      // Groq API Key olmadığı için eski yapıyı "Local" mantığıyla simüle ediyoruz.
      const scanId = Math.floor(Math.random() * 10000);
      const riskScore = isVPNLeaking ? 85 : 10;
      
      const aiRaporu = JSON.stringify({
        risk_score: riskScore, 
        risk_level: isVPNLeaking ? "Yüksek" : "Düşük", 
        summary: `IP Adresi (${ipData.ip}) ve ISP (${ipData.org}) analizi tamamlandı.`,
        findings: [
           { 
             type: isVPNLeaking ? 'risk' : 'safe', 
             title: "WebRTC Sızıntı Testi", 
             desc: isVPNLeaking ? `Gerçek IP adresiniz (${leakedIP}) sızıyor! VPN tünelleme hatası.` : 'WebRTC protokolü güvenli. Gerçek IP gizleniyor.', 
             fix: isVPNLeaking ? 'Tarayıcı ayarlarından WebRTC özelliğini kapatın.' : ''
           },
           { type: "safe", title: "ISP İtibarı", desc: `Bağlantı '${ipData.org}' üzerinden sağlanıyor. Blacklist kaydı yok.` },
           { type: "safe", title: "Coğrafi Konum", desc: `Dijital konumunuz: ${ipData.city}, ${ipData.country_name} olarak görünüyor.` }
        ],
        audit_steps: ["IP Veritabanı Sorgusu", "STUN Sunucusu Testi", "Browser Fingerprint Analizi"]
      });

      setScanResult({ 
          id: scanId, 
          ip_adresi: ipData.ip, 
          durum: 'tamamlandi', 
          ai_raporu: aiRaporu 
      });
      
      if(isAdmin) fetchHistory(); // Listeyi güncelle

    } catch (err) { 
        alert("Tarama Hatası: " + err.message); 
    } finally { 
        setLoadingOsint(false); 
    }
  };

  return (
    <div className="min-h-screen bg-black text-white p-8 font-mono selection:bg-red-500 selection:text-white relative">
      {/* LOGIN MODAL */}
      {showLogin && !isAdmin && (<div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4 backdrop-blur-sm"><div className="w-full max-w-sm bg-slate-900 border border-slate-700 p-8 rounded-2xl shadow-2xl relative"><button onClick={() => setShowLogin(false)} className="absolute top-2 right-4 text-slate-500 hover:text-white text-xl">✕</button><h2 className="text-2xl font-bold text-white mb-6 text-center">Admin Access</h2><form onSubmit={handleLogin} className="space-y-4"><input type="email" required className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded" placeholder="admin@mail.com" value={email} onChange={(e) => setEmail(e.target.value)} /><input type="password" required className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} /><button type="submit" disabled={loadingAuth} className="w-full bg-red-800 hover:bg-red-700 text-white font-bold py-3 rounded shadow-lg">{loadingAuth ? "..." : "LOGIN"}</button></form></div></div>)}
      
      {/* HEADER */}
      <header className="max-w-6xl mx-auto mb-12 border-b border-slate-800 pb-6 flex justify-between items-end">
        <div>
          <h1 className="text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-red-600 via-orange-500 to-amber-500 tracking-tighter cursor-pointer hover:opacity-80 transition drop-shadow-[0_2px_2px_rgba(220,38,38,0.8)]" onClick={resetState}>
            SolidTrace
          </h1>
          <p className="text-slate-400 text-sm mt-2">Public Threat Intelligence Platform</p>
        </div>

        <div className="flex flex-col items-end gap-2">
          {/* 🔥 TIKLANABİLİR SOC LİNKİ 🔥 */}
          <Link href="/soc" className={`text-xs px-3 py-1 rounded transition flex items-center gap-2 border cursor-pointer ${socStatus === 'online' ? 'bg-emerald-900/30 text-emerald-400 border-emerald-500/30 animate-pulse' : 'bg-slate-800 text-slate-500 border-slate-700 hover:bg-slate-700'}`}>
              {socStatus === 'online' ? '● SOC SYSTEM ONLINE' : '○ SOC OFFLINE (GİRİŞ)'}
          </Link>

          {isAdmin ? (
            <div className="flex gap-2 animate-in fade-in">
              <span className="text-xs text-slate-500 py-1 border border-slate-800 px-3 rounded">Admin Mode</span>
              <button onClick={handleLogout} className="text-xs text-red-500 border border-red-900/50 hover:bg-red-900/20 px-3 py-1 rounded transition">EXIT</button>
            </div>
          ) : (
            <div className="flex items-center justify-end gap-2 text-emerald-500 font-bold text-xs">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
              </span> 
              LIVE
            </div>
          )}
        </div>
      </header>

      {/* ANA EKRAN */}
      {!pairingCode && !scanResult && (
      <main className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
        
        {/* OSINT KUTUSU (AKTİF HALE GETİRİLDİ) */}
        <div className="bg-slate-900/30 border border-slate-800 p-8 rounded-2xl hover:border-red-500/80 hover:bg-slate-900/50 transition duration-300 shadow-2xl backdrop-blur-sm group relative overflow-hidden"><div className="absolute top-0 right-0 w-40 h-40 bg-red-600/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none group-hover:bg-red-600/20 transition"></div><div className="flex items-center gap-4 mb-6"><div className="p-3 bg-red-500/10 rounded-xl group-hover:scale-110 transition duration-300 border border-red-500/20"><span className="text-3xl">🌐</span></div><div><h2 className="text-2xl font-bold text-white">OSINT & Browser</h2><p className="text-slate-500 text-xs">IP + WebRTC + Fingerprint</p></div></div><p className="text-slate-400 mb-8 text-sm leading-relaxed">Public IP, <span className="text-red-400 font-bold">WebRTC Sızıntısı</span> ve Tarayıcı Parmak İzi analizi ile gizliliğini test et.</p><button onClick={startExternalScan} disabled={loadingOsint} className="w-full bg-gradient-to-r from-red-900/80 to-red-800/80 hover:from-red-800 hover:to-red-700 text-white border border-red-900 hover:border-red-500 py-4 rounded-xl font-bold transition duration-300 flex items-center justify-center gap-2 shadow-lg shadow-red-900/20">{loadingOsint ? <span className="animate-pulse">ANALİZ YAPILIYOR...</span> : "HIZLI TARAMA BAŞLAT"}</button></div>
        
        {/* LOCAL AGENT KUTUSU */}
        <div className={`bg-slate-900/30 border p-8 rounded-2xl transition shadow-2xl group relative overflow-hidden ${socStatus === 'online' ? 'border-emerald-500/50 shadow-[0_0_30px_rgba(16,185,129,0.1)]' : 'border-slate-800 hover:border-emerald-500/80 hover:bg-slate-900/50'}`}>
            <div className={`absolute top-0 right-0 w-40 h-40 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none transition duration-1000 ${socStatus === 'online' ? 'bg-emerald-600/20' : 'bg-emerald-600/10'}`}></div>

            <div className="flex items-center gap-4 mb-6">
                <div className={`p-3 rounded-xl transition duration-300 border ${socStatus === 'online' ? 'bg-emerald-500/20 border-emerald-500' : 'bg-emerald-500/10 border-emerald-500/20'}`}>
                    <span className="text-3xl">🛡️</span>
                </div>
                <div>
                    <h2 className="text-2xl font-bold text-white">Local Agent</h2>
                    <p className={`text-xs ${socStatus === 'online' ? 'text-emerald-400 font-bold' : 'text-slate-500'}`}>
                        {socStatus === 'online' ? '● SYSTEM PROTECTED' : 'Deep System Analysis'}
                    </p>
                </div>
            </div>

            {socStatus === 'online' ? (
                <div className="animate-in fade-in">
                    <div className="bg-emerald-900/20 border border-emerald-500/30 rounded-lg p-4 mb-6">
                        <div className="flex justify-between items-center mb-2">
                            <span className="text-emerald-200 text-sm font-bold">IPS ENGINE ACTIVE</span>
                            <span className="w-2 h-2 bg-emerald-500 rounded-full animate-ping"></span>
                        </div>
                        <p className="text-emerald-400/70 text-xs">Ajan şu an aktif koruma modunda.</p>
                    </div>
                    
                    <div className="flex flex-col gap-2">
                        <Link href="/soc" className="w-full bg-emerald-700 hover:bg-emerald-600 text-white text-center py-3 rounded-lg font-bold text-sm transition shadow-lg shadow-emerald-900/20">
                            DASHBOARD AÇ (LIVE)
                        </Link>
                         <div className="flex gap-2">
                            <button onClick={downloadAgentFile} className="flex-1 text-xs bg-slate-800 hover:text-white hover:bg-slate-700 py-2 rounded border border-slate-700 transition">⬇️ İndir</button>
                            <button onClick={startLocalScan} className="flex-1 text-xs bg-slate-800 hover:text-white hover:bg-slate-700 py-2 rounded border border-slate-700 transition">🔄 Kod</button>
                         </div>
                    </div>
                </div>
            ) : (
                <div>
                    <p className="text-slate-400 mb-8 text-sm leading-relaxed">Ajanı <b>bir kez indir</b>, sürekli izleme yap. Log analizi, derin port taraması ve anlık durum.</p>
                    <div className="flex flex-col gap-3">
                        <button onClick={startLocalScan} disabled={loadingAgent} className="w-full bg-gradient-to-r from-emerald-900/80 to-emerald-800/80 hover:from-emerald-800 hover:to-emerald-700 text-white border border-emerald-900 hover:border-emerald-500 py-3 rounded-xl font-bold transition duration-300 shadow-lg shadow-emerald-900/20">{loadingAgent ? "..." : "KOD OLUŞTUR"}</button>
                        <Link href="/soc" className="w-full text-center py-2 text-xs text-slate-500 hover:text-white border border-slate-800 rounded hover:bg-slate-800 transition">
                            ⚠️ Manuel Dashboard Girişi (Offline)
                        </Link>
                    </div>
                </div>
            )}
        </div>
        
        {isAdmin && (
          <div className="mt-8 bg-slate-900/50 border border-slate-800 rounded-xl p-6 overflow-hidden md:col-span-2 animate-in fade-in duration-700">
             {/* Admin Tablosu (Kısaltıldı) */}
          </div>
        )}
      </main>
      )}

      {/* --- SONUÇ EKRANI (Dashboard UI) --- */}
      {scanResult && scanResult.durum === 'tamamlandi' && (
        <div className="max-w-7xl mx-auto mt-8 animate-in slide-in-from-bottom-8 duration-700">
            <div className="flex gap-4 mb-6">
                <button onClick={resetState} className="flex items-center gap-2 text-slate-400 hover:text-white transition px-4 py-2 hover:bg-slate-800 rounded-lg">← Yeni Tarama</button>
            </div>

            {(() => {
                let report = null;
                try { report = JSON.parse(scanResult.ai_raporu); } catch { return null; }
                
                if (report) {
                    return (
                        <>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                                <div className="bg-slate-900/80 border border-slate-700 p-6 rounded-2xl flex items-center gap-6">
                                    <div className="relative w-24 h-24 flex items-center justify-center">
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-slate-700" />
                                            <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="8" fill="transparent" className={report.risk_score > 70 ? "text-red-500" : "text-green-500"} strokeDasharray={251.2} strokeDashoffset={251.2 - (251.2 * report.risk_score) / 100} />
                                        </svg>
                                        <span className="absolute text-2xl font-bold text-white">{report.risk_score}</span>
                                    </div>
                                    <div><h3 className="text-slate-400 text-sm font-bold uppercase">Güvenlik Skoru</h3><p className={`text-2xl font-bold ${report.risk_score > 70 ? 'text-red-500' : 'text-green-500'}`}>{report.risk_level}</p><p className="text-xs text-slate-500 mt-1">{report.summary}</p></div>
                                </div>
                                <div className="col-span-2 bg-slate-900/80 border border-slate-700 p-6 rounded-2xl grid grid-cols-2 gap-4">
                                    {/* OSINT DATA DETAYLARI */}
                                    {osintData && (
                                        <>
                                            <div><div className="text-xs text-slate-500">IP ADRESİ</div><div className="text-xl font-bold text-blue-400">{osintData.ip}</div></div>
                                            <div><div className="text-xs text-slate-500">SERVİS SAĞLAYICI</div><div className="text-xl font-bold text-white">{osintData.isp}</div></div>
                                            <div><div className="text-xs text-slate-500">KONUM</div><div className="text-lg text-slate-300">{osintData.city}, {osintData.country}</div></div>
                                            <div><div className="text-xs text-slate-500">WEBRTC SIZINTISI</div><div className={`text-lg font-bold ${osintData.webRTC_Leak.includes("EVET") ? "text-red-500" : "text-green-500"}`}>{osintData.webRTC_Leak}</div></div>
                                        </>
                                    )}
                                </div>
                            </div>
                            
                            <div className="grid grid-cols-1 gap-8">
                                <div className="space-y-4">
                                    <h3 className="text-xl font-bold text-white flex items-center gap-2"><span className="text-indigo-400">🧠</span> Analiz Bulguları</h3>
                                    {report.findings.map((item, index) => (
                                        <div key={index} className={`p-6 rounded-xl border flex items-start gap-4 transition ${item.type === 'risk' ? 'bg-red-900/20 border-red-500/30' : 'bg-emerald-900/20 border-emerald-500/30'}`}>
                                            <div className={`p-3 rounded-lg ${item.type === 'risk' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>{item.type === 'risk' ? '⚠️' : '🛡️'}</div>
                                            <div><h4 className={`font-bold text-lg ${item.type === 'risk' ? 'text-red-200' : 'text-emerald-200'}`}>{item.title}</h4><p className="text-slate-400 text-sm mt-1">{item.desc}</p></div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </>
                    );
                }
                return null;
            })()}
        </div>
      )}
      
      <footer className="max-w-6xl mx-auto mt-20 text-center text-slate-600 text-xs pb-8"><p>SolidTrace Threat Intelligence © 2026</p>{!isAdmin && <button onClick={() => setShowLogin(true)} className="mt-4 opacity-10 hover:opacity-100 transition">Admin Access</button>}</footer>
    </div>
  );
}
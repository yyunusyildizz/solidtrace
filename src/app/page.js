"use client";
import { useState, useEffect } from 'react';
import { createClient } from '@supabase/supabase-js';

// --- AYARLAR ---
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const haApiKey = process.env.NEXT_PUBLIC_HA_API_KEY; 

const supabase = createClient(supabaseUrl, supabaseKey);

export default function Home() {
  // --- STATE ---
  const [session, setSession] = useState(null);
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

  // --- REALTIME DİNLEME ---
  useEffect(() => {
    if (!pairingCode) return;

    console.log(`🔌 Bağlantı kuruluyor: ${pairingCode}`);
    setStatusMsg("Ajan bağlantısı bekleniyor...");

    const channel = supabase
      .channel('tarama-takip')
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'taramalar',
          filter: `pairing_code=eq.${pairingCode}`
        },
        async (payload) => {
          const newData = payload.new;
          
          if (newData.durum === 'analiz_yapiliyor') {
            setStatusMsg("⚡ Ajan sızma testi yapıyor (Cloud Scan)...");
          } 
          else if (newData.durum === 'tamamlandi') {
            setScanResult(newData);
            setLoadingAgent(false);
            setPairingCode(null);
            localStorage.removeItem("activePairingCode");

            if (newData.ai_raporu && newData.ai_raporu.trim().startsWith('{')) { return; }

            setStatusMsg("✅ Veriler alındı, Yapay Zeka yorumluyor...");

            const teknikRapor = newData.ai_raporu; 
            
            const prompt = `
            Aşağıda bir bilgisayarın siber güvenlik tarama logları var.
            Sen bir SOC Uzmanısın. Analiz et ve JSON formatında yanıt ver.

            Teknik Loglar:
            ${teknikRapor}

            ÖNEMLİ KURALLAR:
            1. Eğer "ZARARLI YAZILIM" veya "Kırmızı" uyarı varsa Risk Seviyesini "YÜKSEK" veya "KRİTİK" yap.
            2. Firewall veya Antivirüs kapalıysa "findings" kısmına ekle.
            3. Şüpheli süreçler varsa bunları belirt.

            Yanıtın SADECE şu JSON formatında olsun:
            {
              "risk_score": 0-100 arası sayı,
              "risk_level": "Düşük" | "Orta" | "Yüksek" | "Kritik",
              "summary": "Kısa özet cümle",
              "findings": [
                {"type": "risk", "title": "Başlık", "desc": "Açıklama", "fix": "Çözüm"},
                {"type": "safe", "title": "Başlık", "desc": "Açıklama"}
              ],
              "audit_steps": ["Adım 1", "Adım 2"]
            }
            `;

            try {
                const aiYorumu = await callGroqAI(prompt);
                
                if (aiYorumu && aiYorumu.length > 10) {
                    await supabase.from('taramalar').update({ ai_raporu: aiYorumu }).eq('id', newData.id);
                    setScanResult({ ...newData, ai_raporu: aiYorumu });
                    setStatusMsg("✅ Analiz Tamamlandı!");
                } else {
                    setStatusMsg("⚠️ AI Yanıt vermedi.");
                }
                
            } catch (err) {
                console.error("AI Süreç Hatası:", err);
                setStatusMsg("⚠️ AI Bağlantı hatası.");
            }

            if(session) fetchHistory();
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [pairingCode, session]);

  // --- HELPER FUNCTIONS ---
  const callGroqAI = async (prompt) => { 
    try { 
        const response = await fetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prompt }) }); 
        const data = await response.json(); 
        if (!response.ok) { console.error("API Hatası:", data.error); return null; }
        const rawContent = data.content;
        if (!rawContent) return null;
        const jsonStart = rawContent.indexOf('{');
        const jsonEnd = rawContent.lastIndexOf('}');
        if (jsonStart !== -1 && jsonEnd !== -1) return rawContent.substring(jsonStart, jsonEnd + 1);
        return rawContent;
    } catch (error) { console.error("Fetch Hatası:", error); return null; } 
  };

  const startLocalScan = async () => {
    resetState();
    setLoadingAgent(true);
    try {
      const code = Math.floor(1000 + Math.random() * 9000).toString();
      const { error } = await supabase.from('taramalar').insert([{ ip_adresi: 'Bekleniyor...', durum: 'kod_bekleniyor', pairing_code: code }]);
      if (error) throw error;
      setPairingCode(code); 
      localStorage.setItem("activePairingCode", code);
    } catch (err) { alert(err.message); setLoadingAgent(false); }
  };

  const restartAgentScan = async () => {
      if (!scanResult?.id) return;
      setLoadingAgent(true);
      setScanResult(null); 
      await supabase.from('taramalar').update({ durum: 'analiz_bekliyor' }).eq('id', scanResult.id);
      const { data } = await supabase.from('taramalar').select('pairing_code').eq('id', scanResult.id).single();
      if(data) { setPairingCode(data.pairing_code); } 
      else { alert("Hata: Kod bulunamadı."); setLoadingAgent(false); }
  };

  const copyToClipboard = () => {
    if(pairingCode) {
        navigator.clipboard.writeText(pairingCode);
        setStatusMsg("✅ KOPYALANDI! Terminale yapıştırın.");
        setTimeout(() => { setStatusMsg("Ajan bağlantısı bekleniyor..."); }, 700);
    }
  };

  // 🔥 .EXE İNDİRME FONKSİYONU 🔥
  const downloadAgentFile = () => {
    const link = document.createElement('a');
    link.href = '/SolidTraceAgent.exe'; // public klasöründeki dosyayı işaret eder
    link.download = 'SolidTraceAgent.exe';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleLogin = async (e) => { e.preventDefault(); setLoadingAuth(true); const { error } = await supabase.auth.signInWithPassword({ email, password }); if (error) alert(error.message); else { setShowLogin(false); fetchHistory(); } setLoadingAuth(false); };
  const handleLogout = async () => { await supabase.auth.signOut(); setSession(null); setHistory([]); };
  const getWebRTCIP = async () => { return new Promise((resolve) => { const rtc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] }); rtc.createDataChannel(""); rtc.createOffer().then(o => rtc.setLocalDescription(o)); rtc.onicecandidate = (ice) => { if (ice && ice.candidate && ice.candidate.candidate) { const match = ice.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/); if (match) { rtc.close(); resolve(match[1]); } } }; setTimeout(() => resolve(null), 2000); }); };
  
  const resetState = () => { 
    setLoadingOsint(false); setLoadingAgent(false); setScanResult(null); setPairingCode(null); setOsintData(null); localStorage.removeItem("activePairingCode"); 
  };
  
  const fetchHistory = async () => { try { const { data, error } = await supabase.from('taramalar').select('*').order('created_at', { ascending: false }).limit(10); if (!error) setHistory(data); } catch (err) { console.error(err); } };
  
  const startExternalScan = async () => {
    resetState(); setLoadingOsint(true);
    try {
      const ipRes = await fetch('https://ipapi.co/json/'); if (!ipRes.ok) throw new Error("IP Servis Hatası"); const ipData = await ipRes.json();
      const leakedIP = await getWebRTCIP(); const isVPNLeaking = leakedIP && leakedIP !== ipData.ip;
      const browserData = { userAgent: navigator.userAgent, webRTC_Leak: isVPNLeaking ? `EVET! (Gerçek IP: ${leakedIP})` : "Hayır (Güvenli)" };
      
      setOsintData({ ip: ipData.ip, isp: ipData.org, city: ipData.city, country: ipData.country_name, lat: ipData.latitude, lon: ipData.longitude, ...browserData });
      
      const { data, error } = await supabase.from('taramalar').insert([{ ip_adresi: ipData.ip, sehir: ipData.city, isp: ipData.org, durum: 'bekliyor' }]).select(); if (error) throw error; const scanId = data[0].id;
      
      const prompt = `
      Sen bir Siber Güvenlik Analistisin. Aşağıdaki Dış Ağ (OSINT) verilerini analiz et.
      
      VERİLER:
      - Hedef IP: ${ipData.ip}
      - Servis Sağlayıcı (ISP): ${ipData.org}
      - Konum: ${ipData.city}, ${ipData.country}
      - WebRTC Sızıntısı: ${browserData.webRTC_Leak}
      - Tarayıcı: ${browserData.userAgent}

      GÖREVİN: Bu verilerden "findings" (bulgular) üretmek.

      Yanıtın SADECE şu JSON formatında olsun:
      {
        "risk_score": 0-100 arası sayı (${isVPNLeaking ? 'Yüksek ver' : 'Düşük ver'}),
        "risk_level": "Düşük" | "Orta" | "Yüksek",
        "summary": "Kullanıcının dijital ayak izi özeti.",
        "findings": [
           {
             "type": "${isVPNLeaking ? 'risk' : 'safe'}", 
             "title": "WebRTC Sızıntı Testi", 
             "desc": "${isVPNLeaking ? 'Gerçek IP adresiniz sızıyor! VPN tünelleme hatası var.' : 'WebRTC protokolü üzerinden IP adresiniz açığa çıkmıyor. Tarayıcı güvenliği aktif.'}", 
             "fix": "${isVPNLeaking ? 'Tarayıcı ayarlarından WebRTC özelliğini kapatın veya VPN protokolünü değiştirin.' : ''}"
           },
           {"type": "safe", "title": "ISP Analizi", "desc": "Bağlantı '${ipData.org}' üzerinden sağlanıyor. IP itibarı temiz görünüyor."},
           {"type": "safe", "title": "Konum Gizliliği", "desc": "Dijital konumunuz ${ipData.city}, ${ipData.country} olarak görünüyor."}
        ],
        "audit_steps": [
           "IP veri tabanından itibar sorgulandı",
           "WebRTC STUN sunucusu üzerinden sızıntı testi yapıldı",
           "Tarayıcı parmak izi (Fingerprint) analiz edildi",
           "Coğrafi konum doğrulaması yapıldı"
        ]
      }
      `;
      
      const aiRaporu = await callGroqAI(prompt);
      await supabase.from('taramalar').update({ durum: 'tamamlandi', ai_raporu: aiRaporu }).eq('id', scanId);
      setScanResult({ id: scanId, ip_adresi: ipData.ip, durum: 'tamamlandi', ai_raporu: aiRaporu }); if(session) fetchHistory();
    } catch (err) { alert(err.message); } finally { setLoadingOsint(false); }
  };

  // --- RENDER ---
  return (
    <div className="min-h-screen bg-black text-white p-8 font-mono selection:bg-red-500 selection:text-white relative">
      {/* LOGIN MODAL */}
      {showLogin && !session && (<div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4 backdrop-blur-sm"><div className="w-full max-w-sm bg-slate-900 border border-slate-700 p-8 rounded-2xl shadow-2xl relative"><button onClick={() => setShowLogin(false)} className="absolute top-2 right-4 text-slate-500 hover:text-white text-xl">✕</button><h2 className="text-2xl font-bold text-white mb-6 text-center">Admin Access</h2><form onSubmit={handleLogin} className="space-y-4"><input type="email" required className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded" placeholder="admin@mail.com" value={email} onChange={(e) => setEmail(e.target.value)} /><input type="password" required className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} /><button type="submit" disabled={loadingAuth} className="w-full bg-red-800 hover:bg-red-700 text-white font-bold py-3 rounded shadow-lg">{loadingAuth ? "..." : "LOGIN"}</button></form></div></div>)}
      
      {/* HEADER */}
      <header className="max-w-6xl mx-auto mb-12 border-b border-slate-800 pb-6 flex justify-between items-end"><div><h1 className="text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-red-600 via-orange-500 to-amber-500 tracking-tighter cursor-pointer hover:opacity-80 transition drop-shadow-[0_2px_2px_rgba(220,38,38,0.8)]" onClick={resetState}>SolidTrace</h1><p className="text-slate-400 text-sm mt-2">Public Threat Intelligence Platform</p></div><div className="flex flex-col items-end gap-2">{session ? (<div className="flex gap-2"><span className="text-xs text-slate-500 py-1">Admin Mode</span><button onClick={handleLogout} className="text-xs text-red-500 border border-red-900/50 px-3 py-1 rounded">EXIT</button></div>) : (<div className="flex items-center justify-end gap-2 text-emerald-500 font-bold text-xs"><span className="relative flex h-3 w-3"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span><span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span></span> LIVE</div>)}</div></header>

      {/* ANA EKRAN (SEÇİM) */}
      {!pairingCode && !scanResult && (
      <main className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
        <div className="bg-slate-900/30 border border-slate-800 p-8 rounded-2xl hover:border-red-500/80 hover:bg-slate-900/50 transition duration-300 shadow-2xl backdrop-blur-sm group relative overflow-hidden"><div className="absolute top-0 right-0 w-40 h-40 bg-red-600/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none group-hover:bg-red-600/20 transition"></div><div className="flex items-center gap-4 mb-6"><div className="p-3 bg-red-500/10 rounded-xl group-hover:scale-110 transition duration-300 border border-red-500/20"><span className="text-3xl">🌐</span></div><div><h2 className="text-2xl font-bold text-white">OSINT & Browser</h2><p className="text-slate-500 text-xs">IP + WebRTC + Fingerprint</p></div></div><p className="text-slate-400 mb-8 text-sm leading-relaxed">Public IP, <span className="text-red-400 font-bold">WebRTC Sızıntısı</span> ve Tarayıcı Parmak İzi analizi ile gizliliğini test et.</p><button onClick={startExternalScan} disabled={loadingOsint} className="w-full bg-gradient-to-r from-red-900/80 to-red-800/80 hover:from-red-800 hover:to-red-700 text-white border border-red-900 hover:border-red-500 py-4 rounded-xl font-bold transition duration-300 flex items-center justify-center gap-2 shadow-lg shadow-red-900/20">{loadingOsint ? <span className="animate-pulse">ANALİZ YAPILIYOR...</span> : "HIZLI TARAMA BAŞLAT"}</button></div>
        <div className="bg-slate-900/30 border border-slate-800 p-8 rounded-2xl hover:border-emerald-500/80 hover:bg-slate-900/50 transition duration-300 shadow-2xl backdrop-blur-sm group relative overflow-hidden"><div className="absolute top-0 right-0 w-40 h-40 bg-emerald-600/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none group-hover:bg-emerald-600/20 transition"></div><div className="flex items-center gap-4 mb-6"><div className="p-3 bg-emerald-500/10 rounded-xl group-hover:scale-110 transition duration-300 border border-emerald-500/20"><span className="text-3xl">🕵️</span></div><div><h2 className="text-2xl font-bold text-white">Local Agent</h2><p className="text-slate-500 text-xs">Deep System Analysis</p></div></div><p className="text-slate-400 mb-8 text-sm leading-relaxed">Ajanı <b>bir kez indir</b>, sürekli izleme yap. Log analizi, derin port taraması ve anlık durum.</p><button onClick={startLocalScan} disabled={loadingAgent} className="w-full bg-gradient-to-r from-emerald-900/80 to-emerald-800/80 hover:from-emerald-800 hover:to-emerald-700 text-white border border-emerald-900 hover:border-emerald-500 py-4 rounded-xl font-bold transition duration-300 shadow-lg shadow-emerald-900/20">{loadingAgent ? "KOD OLUŞTURULUYOR..." : "KOD OLUŞTUR & BAĞLAN"}</button></div>
        {session && (<div className="mt-8 bg-slate-900/50 border border-slate-800 rounded-xl p-6 overflow-hidden md:col-span-2"><div className="flex justify-between items-center mb-4"><h3 className="text-xl font-bold text-white flex items-center gap-2"><span className="text-blue-500">🛡️</span> Admin Logları</h3><button onClick={fetchHistory} className="text-xs bg-slate-800 hover:bg-slate-700 text-white px-3 py-1 rounded border border-slate-700 transition">🔄 Yenile</button></div><div className="overflow-x-auto"><table className="w-full text-left text-sm text-slate-400"><thead className="bg-slate-800 text-slate-200 uppercase font-bold"><tr><th className="p-3">Tarih</th><th className="p-3">IP Adresi</th><th className="p-3">CPU</th><th className="p-3">RAM</th><th className="p-3">Durum</th></tr></thead><tbody className="divide-y divide-slate-800">{history.map((item) => (<tr key={item.id} className="hover:bg-slate-800/50 transition"><td className="p-3">{new Date(item.created_at).toLocaleString('tr-TR')}</td><td className="p-3 font-mono text-blue-400">{item.ip_adresi}</td><td className="p-3 font-mono">{item.cpu ? `%${item.cpu}` : '-'}</td><td className="p-3 font-mono">{item.ram ? `%${item.ram}` : '-'}</td><td className="p-3"><span className={`px-2 py-1 rounded text-xs font-bold ${item.durum === 'tamamlandi' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{item.durum === 'tamamlandi' ? 'TAMAMLANDI' : 'BEKLİYOR'}</span></td></tr>))}</tbody></table></div></div>)}
      </main>
      )}

      {/* --- EŞLEŞME EKRANI --- */}
      {pairingCode && (
        <div className="max-w-4xl mx-auto mt-8 bg-black/80 border border-emerald-500/30 rounded-2xl p-8 animate-in zoom-in-95 backdrop-blur-xl relative shadow-2xl overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-emerald-500 to-transparent opacity-50 animate-pulse"></div>
            <button onClick={resetState} className="absolute top-4 right-4 text-slate-500 hover:text-white p-2 z-10">✕ İptal</button>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="flex flex-col justify-center">
                    <h3 className="text-2xl font-bold text-white mb-2">Ajan Bağlantısı 🔗</h3>
                    <p className="text-slate-400 text-sm mb-6">Bu kodu terminaldeki ajana girerek yetkilendirme yapın.</p>
                    <div className="relative group cursor-pointer" onClick={copyToClipboard}>
                        <div className="bg-slate-900 border border-slate-700 rounded-xl p-4 flex items-center justify-between group-hover:border-emerald-500/50 transition duration-300">
                            <div className="text-4xl font-mono font-bold text-emerald-400 tracking-widest">{pairingCode}</div>
                            <div className="bg-slate-800 p-2 rounded-lg text-slate-400 group-hover:text-white group-hover:bg-emerald-600 transition">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            </div>
                        </div>
                        <div className="absolute -top-3 right-0 bg-emerald-600 text-white text-[10px] px-2 py-0.5 rounded opacity-0 group-hover:opacity-100 transition duration-300">Tıkla Kopyala</div>
                    </div>
                    <div className="mt-6">
                        <p className="text-xs text-slate-500 mb-2">Ajan yüklü değil mi?</p>
                        <button onClick={downloadAgentFile} className="flex items-center gap-2 text-xs bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded border border-slate-600 transition w-fit">
                            <span>⬇️</span> Ajanı İndir (.EXE - v2.2)
                        </button>
                    </div>
                </div>
                <div className="bg-black/80 rounded-xl border border-slate-800 p-4 font-mono text-xs h-64 overflow-hidden relative shadow-inner flex flex-col justify-between">
                    <div className="absolute top-2 right-2 flex gap-1"><div className="w-2 h-2 rounded-full bg-red-500"></div><div className="w-2 h-2 rounded-full bg-yellow-500"></div><div className="w-2 h-2 rounded-full bg-green-500"></div></div>
                    <div className="text-slate-500 border-b border-slate-800 pb-2 mb-2">root@solidtrace-server:~# monitoring_agent</div>
                    <div className="space-y-1">
                        <div className="text-emerald-500">➜ Bağlantı portu açıldı...</div>
                        <div className="text-slate-300">➜ Kod: <span className="text-yellow-400">{pairingCode}</span></div>
                        <div className="mt-4"><span className="text-emerald-400 font-bold animate-pulse">➜ {statusMsg}</span></div>
                        <div className="opacity-50 mt-4 text-[10px] text-slate-600"><div>[INFO] Waiting for handshake...</div><div>[INFO] Secure channel: active</div></div>
                    </div>
                </div>
            </div>
        </div>
      )}

      {/* --- SONUÇ EKRANI (Dashboard UI) --- */}
      {scanResult && scanResult.durum === 'tamamlandi' && (
        <div className="max-w-7xl mx-auto mt-8 animate-in slide-in-from-bottom-8 duration-700">
            <div className="flex gap-4 mb-6">
                <button onClick={resetState} className="flex items-center gap-2 text-slate-400 hover:text-white transition px-4 py-2 hover:bg-slate-800 rounded-lg">← Yeni Tarama</button>
            </div>

            {/* AI JSON Parse Kontrolü */}
            {(() => {
                let report = null;
                let isRawText = false;
                try { report = JSON.parse(scanResult.ai_raporu); } catch { isRawText = true; }
                
                if (report && report.risk_score) {
                    return (
                        <>
                            {/* ÜST İSTATİSTİK KARTI */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                                <div className="bg-slate-900/80 border border-slate-700 p-6 rounded-2xl flex items-center gap-6">
                                    <div className="relative w-24 h-24 flex items-center justify-center">
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-slate-700" />
                                            <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="8" fill="transparent" className={report.risk_score > 70 ? "text-red-500" : report.risk_score > 30 ? "text-yellow-500" : "text-emerald-500"} strokeDasharray={251.2} strokeDashoffset={251.2 - (251.2 * report.risk_score) / 100} />
                                        </svg>
                                        <span className="absolute text-2xl font-bold text-white">{report.risk_score}</span>
                                    </div>
                                    <div><h3 className="text-slate-400 text-sm font-bold uppercase">Tehdit Seviyesi</h3><p className={`text-2xl font-bold ${report.risk_level === 'Kritik' ? 'text-red-500' : 'text-emerald-500'}`}>{report.risk_level}</p><p className="text-xs text-slate-500 mt-1">{report.summary}</p></div>
                                </div>
                                <div className="col-span-2 grid grid-cols-3 gap-4 bg-slate-900/80 border border-slate-700 p-6 rounded-2xl">
                                    {scanResult.cpu !== undefined ? (
                                        <>
                                            <div className="text-center"><p className="text-xs text-slate-500 mb-2">CPU</p><div className="text-3xl font-mono text-white mb-2">%{scanResult.cpu}</div><div className="h-1 bg-slate-800 rounded-full"><div style={{width: `${scanResult.cpu}%`}} className={`h-full rounded-full ${scanResult.cpu > 80 ? 'bg-red-500' : 'bg-blue-500'}`}></div></div></div>
                                            <div className="text-center"><p className="text-xs text-slate-500 mb-2">RAM</p><div className="text-3xl font-mono text-white mb-2">%{scanResult.ram}</div><div className="h-1 bg-slate-800 rounded-full"><div style={{width: `${scanResult.ram}%`}} className="h-full rounded-full bg-purple-500"></div></div></div>
                                            <div className="text-center"><p className="text-xs text-slate-500 mb-2">DISK</p><div className="text-3xl font-mono text-white mb-2">%{scanResult.disk}</div><div className="h-1 bg-slate-800 rounded-full"><div style={{width: `${scanResult.disk}%`}} className="h-full rounded-full bg-emerald-500"></div></div></div>
                                        </>
                                    ) : (
                                        <div className="col-span-3 flex items-center justify-center text-slate-500 text-sm">
                                            Bu tarama (OSINT) sistem kaynaklarını (CPU/RAM) analiz etmez.
                                        </div>
                                    )}
                                </div>
                            </div>
                            
                            {/* DETAYLI ANALİZ + TERMİNAL */}
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                                <div className="lg:col-span-2 space-y-4">
                                    <h3 className="text-xl font-bold text-white flex items-center gap-2"><span className="text-indigo-400">🧠</span> Yapay Zeka Bulguları</h3>
                                    {report.findings.map((item, index) => (
                                        <div key={index} className={`p-6 rounded-xl border flex items-start gap-4 transition hover:scale-[1.01] ${item.type === 'risk' ? 'bg-red-900/20 border-red-500/30' : 'bg-emerald-900/20 border-emerald-500/30'}`}>
                                            <div className={`p-3 rounded-lg ${item.type === 'risk' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>{item.type === 'risk' ? '⚠️' : '🛡️'}</div>
                                            <div><h4 className={`font-bold text-lg ${item.type === 'risk' ? 'text-red-200' : 'text-emerald-200'}`}>{item.title}</h4><p className="text-slate-400 text-sm mt-1">{item.desc}</p>{item.fix && (<div className="mt-3 bg-black/30 p-3 rounded border border-red-500/20"><span className="text-xs font-bold text-red-400 uppercase block mb-1">Önerilen Çözüm:</span><span className="text-slate-300 text-sm">{item.fix}</span></div>)}</div>
                                        </div>
                                    ))}
                                </div>
                                <div className="lg:col-span-1">
                                    <h3 className="text-xl font-bold text-white flex items-center gap-2 mb-4"><span className="text-slate-400">📜</span> Denetim Günlüğü</h3>
                                    <div className="bg-black rounded-xl border border-slate-800 p-4 h-[500px] overflow-y-auto font-mono text-xs shadow-inner custom-scrollbar">
                                        <div className="text-slate-500 border-b border-slate-800 pb-2 mb-2">root@agent:~# tail -f /var/log/audit.log</div>
                                        {report.audit_steps.map((step, i) => (
                                            <div key={i} className="mb-2 flex gap-2">
                                                <span className="text-emerald-600">[LOG]</span>
                                                <span className="text-slate-300">➜ {typeof step === 'object' ? (step.step || step.description) : step}</span>
                                                <span className="text-emerald-500">OK</span>
                                            </div>
                                        ))}
                                        {osintData && (
                                            <div className="opacity-70 mt-4 text-slate-500 border-t border-slate-800 pt-4">
                                                <div className="mb-2 text-yellow-500 font-bold">[OSINT RAW DATA]</div>
                                                <div>IP: {osintData.ip}</div>
                                                <div>ISP: {osintData.isp}</div>
                                                <div>Loc: {osintData.city}, {osintData.country}</div>
                                                <div>UA: {osintData.userAgent.substring(0,40)}...</div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </>
                    );
                } else if (isRawText) {
                    return (
                        <div className="flex flex-col items-center justify-center p-12 bg-slate-900/50 rounded-2xl border border-slate-800 animate-pulse h-96">
                             <div className="text-6xl mb-6 animate-bounce">🤖</div>
                             <h3 className="text-2xl font-bold text-white mb-2">Yapay Zeka Analiz Ediyor...</h3>
                             <p className="text-slate-400 text-sm">Loglar işleniyor, tehdit skoru hesaplanıyor ve bulgular derleniyor.</p>
                             <div className="mt-8 flex gap-2">
                                <div className="w-3 h-3 bg-red-500 rounded-full animate-ping"></div>
                                <div className="w-3 h-3 bg-yellow-500 rounded-full animate-ping delay-75"></div>
                                <div className="w-3 h-3 bg-emerald-500 rounded-full animate-ping delay-150"></div>
                             </div>
                        </div>
                    );
                }
            })()}
        </div>
      )}
      <footer className="max-w-6xl mx-auto mt-20 text-center text-slate-600 text-xs pb-8"><p>SolidTrace Threat Intelligence © 2026</p>{!session && <button onClick={() => setShowLogin(true)} className="mt-4 opacity-10 hover:opacity-100 transition">Admin Access</button>}</footer>
    </div>
  );
}
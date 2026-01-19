"use client";
import { useState, useRef, useEffect } from 'react';
import { createClient } from '@supabase/supabase-js';

// --- AYARLAR ---
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
// Groq Key artık backend'de, burada gerek yok ama config için dursun
const groqKey = process.env.NEXT_PUBLIC_GROQ_API_KEY; 

const supabase = createClient(supabaseUrl, supabaseKey);

export default function Home() {
  // --- STATE ---
  const [session, setSession] = useState(null);
  const [showLogin, setShowLogin] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  // 👇 YÜKLEME DURUMLARINI AYIRDIK 👇
  const [loadingAuth, setLoadingAuth] = useState(false);   // Giriş için
  const [loadingOsint, setLoadingOsint] = useState(false); // Hızlı Tarama için
  const [loadingAgent, setLoadingAgent] = useState(false); // Ajan için

  const [scanResult, setScanResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [pairingCode, setPairingCode] = useState(null);
  const [osintData, setOsintData] = useState(null);
  const pollInterval = useRef(null);

  // --- BAŞLANGIÇ ---
  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      if(session) fetchHistory();
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      if(session) fetchHistory();
    });

    const savedCode = localStorage.getItem("activePairingCode");
    if (savedCode) restoreSession(savedCode);

    return () => subscription.unsubscribe();
  }, []);

  // --- OTURUM KURTARMA ---
  const restoreSession = async (code) => {
      const { data } = await supabase.from('taramalar').select('*').eq('pairing_code', code).maybeSingle();
      
      if (data) {
          if (data.durum === 'tamamlandi') {
              setScanResult(data);
              localStorage.removeItem("activePairingCode");
          } else {
              setLoadingAgent(true); // Sadece Ajan yükleniyor
              setPairingCode(code);
              startPolling(code);
          }
      } else {
          localStorage.removeItem("activePairingCode");
      }
  };

  // --- DİNLEME MODU ---
  const startPolling = (code) => {
      if (pollInterval.current) clearInterval(pollInterval.current);
      pollInterval.current = setInterval(async () => {
          const { data: checkData } = await supabase.from('taramalar').select('*').eq('pairing_code', code).maybeSingle();
          
          if (checkData && checkData.durum === 'tamamlandi') {
              setScanResult(checkData);
              setLoadingAgent(false); // Ajan yüklemesi bitti
              setPairingCode(null);
              clearInterval(pollInterval.current);
              localStorage.removeItem("activePairingCode");
              if(session) fetchHistory();
          }
      }, 2000);
  };

  // --- YENİ EŞLEŞME BAŞLAT ---
  const startLocalScan = async () => {
    resetState();
    setLoadingAgent(true); // Sadece Ajan butonu dönsün
    try {
      const code = Math.floor(1000 + Math.random() * 9000).toString();
      const { error } = await supabase.from('taramalar').insert([{ 
          ip_adresi: 'Bekleniyor...', 
          durum: 'kod_bekleniyor',
          pairing_code: code 
      }]);
      
      if (error) throw error;
      
      setPairingCode(code);
      localStorage.setItem("activePairingCode", code);
      startPolling(code);

    } catch (err) { alert(err.message); setLoadingAgent(false); }
  };

  const restartAgentScan = async () => {
      if (!scanResult?.id) return;
      setLoadingAgent(true); // Tekrar tararken ajan butonu dönsün
      // Mevcut kodu bulmamız lazım, scanResult içinde pairing_code olmayabilir, veritabanından çekmek daha sağlıklı
      const { data } = await supabase.from('taramalar').select('pairing_code').eq('id', scanResult.id).single();
      
      if(data) {
          await supabase.from('taramalar').update({ durum: 'agent_bekliyor' }).eq('id', scanResult.id);
          setScanResult(null);
          setPairingCode(data.pairing_code);
          startPolling(data.pairing_code);
      } else {
           alert("Eski kod bulunamadı, lütfen yeni tarama başlatın.");
           setLoadingAgent(false);
      }
  };

  // --- AJAN İNDİRME ---
  const downloadAgentFile = () => {
    const code = getAgentCode(); 
    const element = document.createElement("a");
    const file = new Blob([code], {type: 'text/x-python'});
    element.href = URL.createObjectURL(file);
    element.download = "agent.py";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  // --- OSINT & AUTH ---
  const handleLogin = async (e) => { e.preventDefault(); setLoadingAuth(true); const { error } = await supabase.auth.signInWithPassword({ email, password }); if (error) alert(error.message); else { setShowLogin(false); fetchHistory(); } setLoadingAuth(false); };
  const handleLogout = async () => { await supabase.auth.signOut(); setSession(null); setHistory([]); };
  const getWebRTCIP = async () => { return new Promise((resolve) => { const rtc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] }); rtc.createDataChannel(""); rtc.createOffer().then(o => rtc.setLocalDescription(o)); rtc.onicecandidate = (ice) => { if (ice && ice.candidate && ice.candidate.candidate) { const match = ice.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/); if (match) { rtc.close(); resolve(match[1]); } } }; setTimeout(() => resolve(null), 2000); }); };
  
  const resetState = () => { 
      setLoadingOsint(false); 
      setLoadingAgent(false);
      setScanResult(null); 
      setPairingCode(null);
      setOsintData(null); 
      if (pollInterval.current) clearInterval(pollInterval.current); 
      localStorage.removeItem("activePairingCode"); 
  };

  // --- BACKEND API ÇAĞRISI ---
  const callGroqAI = async (prompt) => {
    try {
        const response = await fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prompt })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Sunucu Hatası");
        return data.content;
    } catch (error) {
        console.error("AI Hatası:", error);
        return "⚠️ AI Raporu Alınamadı: " + error.message;
    }
  };

  const fetchHistory = async () => { try { const { data, error } = await supabase.from('taramalar').select('*').order('created_at', { ascending: false }).limit(10); if (!error) setHistory(data); } catch (err) { console.error(err); } };

  // --- HIZLI TARAMA (OSINT) ---
  const startExternalScan = async () => {
    resetState(); 
    setLoadingOsint(true); // Sadece OSINT butonu dönsün
    try {
      const ipRes = await fetch('https://ipapi.co/json/'); if (!ipRes.ok) throw new Error("IP Servis Hatası"); const ipData = await ipRes.json();
      const leakedIP = await getWebRTCIP(); const isVPNLeaking = leakedIP && leakedIP !== ipData.ip;
      const browserData = { userAgent: navigator.userAgent, webRTC_Leak: isVPNLeaking ? `EVET! Sızıntı: ${leakedIP}` : "Güvenli" };
      setOsintData({ ip: ipData.ip, isp: ipData.org, city: ipData.city, country: ipData.country_name, lat: ipData.latitude, lon: ipData.longitude, ...browserData });
      const { data, error } = await supabase.from('taramalar').insert([{ ip_adresi: ipData.ip, sehir: ipData.city, isp: ipData.org, durum: 'bekliyor' }]).select(); if (error) throw error; const scanId = data[0].id;
      const prompt = `HEDEF IP: ${ipData.ip} (${ipData.org}). Tarayıcı: ${browserData.userAgent}. WebRTC Sızıntı: ${browserData.webRTC_Leak}. Dijital ayak izi raporu.`;
      const aiRaporu = await callGroqAI(prompt);
      await supabase.from('taramalar').update({ durum: 'tamamlandi', ai_raporu: aiRaporu }).eq('id', scanId);
      setScanResult({ id: scanId, ip_adresi: ipData.ip, durum: 'tamamlandi', ai_raporu: aiRaporu }); if(session) fetchHistory();
    } catch (err) { alert(err.message); } finally { setLoadingOsint(false); }
  };

  const getAgentCode = () => `
import os
import sys
import socket
import platform
import time
import warnings
import json

CONFIG = { "URL": "${supabaseUrl}", "KEY": "${supabaseKey}", "AI_KEY": "${groqKey}" }
warnings.filterwarnings("ignore")

try:
    import psutil
    import requests
    from supabase import create_client
except ImportError as e:
    print(f"\\n❌ EKSİK: {e.name}. Çalıştır: pip install psutil requests supabase")
    sys.exit(1)

def call_groq_ai(prompt):
    if not CONFIG["AI_KEY"] or "gsk_" not in CONFIG["AI_KEY"]: return "AI Key Yok."
    try:
        res = requests.post("https://api.groq.com/openai/v1/chat/completions", headers={"Authorization": f"Bearer {CONFIG['AI_KEY']}"}, json={"model": "llama-3.3-70b-versatile", "messages": [{"role":"user","content":prompt}]})
        return res.json()['choices'][0]['message']['content'] if res.status_code == 200 else f"Hata: {res.text}"
    except Exception as e: return str(e)

def scan_target_verbose(target_ip):
    ports = {21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080}
    open_p = []
    print(f"\\n🔥 Tarama: {target_ip}")
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            if s.connect_ex((target_ip, p)) == 0: open_p.append(str(p))
            s.close()
        except: pass
    return open_p

def main():
    print("-" * 50)
    print("🛡️  SolidTrace Agent v4.0 (Pairing Mode)")
    print("-" * 50)
    try:
        supa = create_client(CONFIG["URL"], CONFIG["KEY"])
        while True:
            code_input = input("\\n🔑 Sitedeki Eşleşme Kodunu Girin (Örn: 5821): ").strip()
            print("⏳ Kod aranıyor...")
            response = supa.table("taramalar").select("*").eq("pairing_code", code_input).execute()
            if response.data and len(response.data) > 0:
                target_row = response.data[0]
                scan_id = target_row['id']
                print(f"✅ EŞLEŞME BAŞARILI! (ID: {scan_id})")
                print("🚀 Analiz Başlıyor...")
                supa.table("taramalar").update({"durum": "analiz_yapiliyor"}).eq("id", scan_id).execute()
                break
            else:
                print("❌ Kod bulunamadı veya süresi dolmuş. Tekrar deneyin.")
        
        cpu = int(psutil.cpu_percent(interval=1))
        ram = int(psutil.virtual_memory().percent)
        disk = int(psutil.disk_usage('/').percent)
        try: pub_ip = requests.get('https://api.ipify.org', timeout=3).text
        except: pub_ip = "Bilinmiyor"
        local_ip = socket.gethostbyname(socket.gethostname())
        os_inf = f"{platform.system()} {platform.release()}"
        scan_res = scan_target_verbose(local_ip)
        scan_txt = ", ".join(scan_res) if scan_res else "Temiz"
        prompt = f"OS: {os_inf}, CPU: %{cpu}, RAM: %{ram}, Portlar: {scan_txt}. Risk raporu yaz."
        ai_msg = call_groq_ai(prompt)
        final = {"durum": "tamamlandi", "ip_adresi": pub_ip, "sehir": os_inf, "ai_raporu": ai_msg, "cpu": cpu, "ram": ram, "disk": disk}
        supa.table("taramalar").update(final).eq("id", scan_id).execute()
        print("\\n🎉 BİTTİ! Sonuçlar ekrana gönderildi.")
        print("💡 İpucu: Yeni bir tarama için agent'ı tekrar çalıştırıp yeni kodu girebilirsiniz.")
    except Exception as e: print(f"❌ HATA: {e}")

if __name__ == "__main__": main()
`;

  return (
    <div className="min-h-screen bg-black text-white p-8 font-mono selection:bg-red-500 selection:text-white relative">
      {showLogin && !session && (<div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4 backdrop-blur-sm"><div className="w-full max-w-sm bg-slate-900 border border-slate-700 p-8 rounded-2xl shadow-2xl relative"><button onClick={() => setShowLogin(false)} className="absolute top-2 right-4 text-slate-500 hover:text-white text-xl">✕</button><h2 className="text-2xl font-bold text-white mb-6 text-center">Admin Access</h2><form onSubmit={handleLogin} className="space-y-4"><input type="email" required className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded" placeholder="admin@mail.com" value={email} onChange={(e) => setEmail(e.target.value)} /><input type="password" required className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} /><button type="submit" disabled={loadingAuth} className="w-full bg-red-800 hover:bg-red-700 text-white font-bold py-3 rounded shadow-lg">{loadingAuth ? "..." : "LOGIN"}</button></form></div></div>)}
      <header className="max-w-6xl mx-auto mb-12 border-b border-slate-800 pb-6 flex justify-between items-end"><div><h1 className="text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-red-600 via-orange-500 to-amber-500 tracking-tighter cursor-pointer hover:opacity-80 transition drop-shadow-[0_2px_2px_rgba(220,38,38,0.8)]" onClick={resetState}>SolidTrace</h1><p className="text-slate-400 text-sm mt-2">Public Threat Intelligence Platform</p></div><div className="flex flex-col items-end gap-2">{session ? (<div className="flex gap-2"><span className="text-xs text-slate-500 py-1">Admin Mode</span><button onClick={handleLogout} className="text-xs text-red-500 border border-red-900/50 px-3 py-1 rounded">EXIT</button></div>) : (<div className="flex items-center justify-end gap-2 text-emerald-500 font-bold text-xs"><span className="relative flex h-3 w-3"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span><span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span></span> LIVE</div>)}</div></header>

      {!pairingCode && !scanResult && (
      <main className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
        <div className="bg-slate-900/30 border border-slate-800 p-8 rounded-2xl hover:border-red-500/80 hover:bg-slate-900/50 transition duration-300 shadow-2xl backdrop-blur-sm group relative overflow-hidden"><div className="absolute top-0 right-0 w-40 h-40 bg-red-600/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none group-hover:bg-red-600/20 transition"></div><div className="flex items-center gap-4 mb-6"><div className="p-3 bg-red-500/10 rounded-xl group-hover:scale-110 transition duration-300 border border-red-500/20"><span className="text-3xl">🌐</span></div><div><h2 className="text-2xl font-bold text-white">OSINT & Browser</h2><p className="text-slate-500 text-xs">IP + WebRTC + Fingerprint</p></div></div><p className="text-slate-400 mb-8 text-sm leading-relaxed">Public IP, <span className="text-red-400 font-bold">WebRTC Sızıntısı</span> ve Tarayıcı Parmak İzi analizi ile gizliliğini test et.</p><button onClick={startExternalScan} disabled={loadingOsint} className="w-full bg-gradient-to-r from-red-900/80 to-red-800/80 hover:from-red-800 hover:to-red-700 text-white border border-red-900 hover:border-red-500 py-4 rounded-xl font-bold transition duration-300 flex items-center justify-center gap-2 shadow-lg shadow-red-900/20">{loadingOsint ? <span className="animate-pulse">ANALİZ YAPILIYOR...</span> : "HIZLI TARAMA BAŞLAT"}</button></div>
        <div className="bg-slate-900/30 border border-slate-800 p-8 rounded-2xl hover:border-emerald-500/80 hover:bg-slate-900/50 transition duration-300 shadow-2xl backdrop-blur-sm group relative overflow-hidden"><div className="absolute top-0 right-0 w-40 h-40 bg-emerald-600/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none group-hover:bg-emerald-600/20 transition"></div><div className="flex items-center gap-4 mb-6"><div className="p-3 bg-emerald-500/10 rounded-xl group-hover:scale-110 transition duration-300 border border-emerald-500/20"><span className="text-3xl">🕵️</span></div><div><h2 className="text-2xl font-bold text-white">Local Agent</h2><p className="text-slate-500 text-xs">Deep System Analysis</p></div></div><p className="text-slate-400 mb-8 text-sm leading-relaxed">Ajanı <b>bir kez indir</b>, her taramada sadece kod gir. Güvenli, hızlı ve tek dosya.</p><button onClick={startLocalScan} disabled={loadingAgent} className="w-full bg-gradient-to-r from-emerald-900/80 to-emerald-800/80 hover:from-emerald-800 hover:to-emerald-700 text-white border border-emerald-900 hover:border-emerald-500 py-4 rounded-xl font-bold transition duration-300 shadow-lg shadow-emerald-900/20">{loadingAgent ? "KOD OLUŞTURULUYOR..." : "KOD OLUŞTUR & BAĞLAN"}</button></div>
        {session && (<div className="mt-8 bg-slate-900/50 border border-slate-800 rounded-xl p-6 overflow-hidden md:col-span-2"><div className="flex justify-between items-center mb-4"><h3 className="text-xl font-bold text-white flex items-center gap-2"><span className="text-blue-500">🛡️</span> Admin Logları</h3><button onClick={fetchHistory} className="text-xs bg-slate-800 hover:bg-slate-700 text-white px-3 py-1 rounded border border-slate-700 transition">🔄 Yenile</button></div><div className="overflow-x-auto"><table className="w-full text-left text-sm text-slate-400"><thead className="bg-slate-800 text-slate-200 uppercase font-bold"><tr><th className="p-3">Tarih</th><th className="p-3">IP Adresi</th><th className="p-3">CPU</th><th className="p-3">RAM</th><th className="p-3">Durum</th></tr></thead><tbody className="divide-y divide-slate-800">{history.map((item) => (<tr key={item.id} className="hover:bg-slate-800/50 transition"><td className="p-3">{new Date(item.created_at).toLocaleString('tr-TR')}</td><td className="p-3 font-mono text-blue-400">{item.ip_adresi}</td><td className="p-3 font-mono">{item.cpu ? `%${item.cpu}` : '-'}</td><td className="p-3 font-mono">{item.ram ? `%${item.ram}` : '-'}</td><td className="p-3"><span className={`px-2 py-1 rounded text-xs font-bold ${item.durum === 'tamamlandi' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{item.durum === 'tamamlandi' ? 'TAMAMLANDI' : 'BEKLİYOR'}</span></td></tr>))}</tbody></table></div></div>)}
      </main>
      )}

      {pairingCode && (
        <div className="max-w-4xl mx-auto mt-8 bg-black/80 border border-emerald-500/30 rounded-2xl p-8 animate-in zoom-in-95 backdrop-blur-xl relative shadow-2xl">
            <button onClick={resetState} className="absolute top-4 right-4 text-slate-500 hover:text-white p-2">✕</button>
            <div className="text-center mb-10"><h3 className="text-3xl font-bold text-white mb-2">Ajan Bağlantı Kodu 🔑</h3><p className="text-slate-400 text-sm">Aşağıdaki kodu terminalde çalışan ajana girin.</p></div>
            <div className="flex flex-col items-center justify-center gap-8">
                <div className="text-6xl font-mono font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-green-600 tracking-widest drop-shadow-[0_0_15px_rgba(16,185,129,0.5)] animate-pulse">{pairingCode}</div>
                <div className="text-sm text-slate-500">Terminal Komutu: <span className="font-mono text-emerald-400">python agent.py</span></div>
                <div className="mt-4 p-4 bg-slate-900/60 rounded-xl border border-slate-700 max-w-lg text-center"><p className="text-xs text-slate-400 mb-2">Henüz ajanı indirmediyseniz (Sadece 1 kez gerekir):</p><button onClick={downloadAgentFile} className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded text-xs font-bold border border-slate-600 transition">⬇️ AJANI İNDİR (İlk Kez)</button></div>
            </div>
            <div className="mt-8 text-center"><p className="text-slate-500 text-xs animate-pulse">Eşleşme bekleniyor...</p></div>
        </div>
      )}

      {scanResult && scanResult.durum === 'tamamlandi' && (
        <div className="max-w-6xl mx-auto mt-4 animate-in slide-in-from-bottom-8 duration-700">
           <button onClick={resetState} className="mb-6 flex items-center gap-2 text-slate-400 hover:text-white transition px-4 py-2 hover:bg-slate-800 rounded-lg">← Yeni Tarama</button>
           {osintData && (<div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6"><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">IP ADRESİ</div><div className="font-mono text-sm font-bold text-white">{osintData.ip}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">SERVİS SAĞLAYICI (ISP)</div><div className="font-bold text-red-400 text-sm truncate" title={osintData.isp}>{osintData.isp}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">KONUM</div><div className="text-white text-sm truncate">{osintData.city}, {osintData.country}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">KOORDİNATLAR</div><div className="text-slate-400 text-sm font-mono">{osintData.lat}, {osintData.lon}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl col-span-2"><div className="text-[10px] text-slate-500 tracking-widest mb-1">WEBRTC DURUMU</div><div className={`text-sm font-bold ${osintData.webRTC_Leak.includes("EVET") ? "text-red-500" : "text-emerald-500"}`}>{osintData.webRTC_Leak}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl col-span-2"><div className="text-[10px] text-slate-500 tracking-widest mb-1">TARAYICI İZİ</div><div className="text-slate-500 text-xs truncate" title={osintData.userAgent}>{osintData.userAgent}</div></div></div>)}
           {scanResult.cpu !== undefined && scanResult.cpu !== null && (<div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8"><div className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl relative overflow-hidden"><div className="text-xs text-slate-500 tracking-widest mb-2 font-bold">CPU YÜKÜ</div><div className="text-4xl font-mono text-white mb-2">%{scanResult.cpu}</div><div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-1000 ${scanResult.cpu > 80 ? 'bg-red-500' : 'bg-blue-500'}`} style={{width: `${scanResult.cpu}%`}}></div></div></div><div className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl relative overflow-hidden"><div className="text-xs text-slate-500 tracking-widest mb-2 font-bold">RAM KULLANIMI</div><div className="text-4xl font-mono text-white mb-2">%{scanResult.ram}</div><div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-1000 ${scanResult.ram > 80 ? 'bg-red-500' : 'bg-purple-500'}`} style={{width: `${scanResult.ram}%`}}></div></div></div><div className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl relative overflow-hidden"><div className="text-xs text-slate-500 tracking-widest mb-2 font-bold">DISK DOLULUK</div><div className="text-4xl font-mono text-white mb-2">%{scanResult.disk}</div><div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-1000 ${scanResult.disk > 90 ? 'bg-red-500' : 'bg-emerald-500'}`} style={{width: `${scanResult.disk}%`}}></div></div></div></div>)}
           <div className="bg-slate-900/80 border border-slate-700 rounded-2xl p-8 backdrop-blur-md shadow-2xl relative overflow-hidden"><div className="flex items-center gap-4 mb-8 pb-8 border-b border-slate-800/50"><div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-red-600 to-orange-600 flex items-center justify-center shadow-lg"><span className="text-2xl">🧠</span></div><div><h3 className="text-2xl font-bold text-white">SolidTrace Analiz Raporu</h3><div className="flex gap-4 text-xs text-slate-400 font-mono mt-1"><span>ID: {scanResult.id.slice(0, 8)}</span><span>MODEL: Llama 3 (Groq)</span></div></div></div><div className="prose prose-invert max-w-none"><p className="text-slate-300 whitespace-pre-line leading-relaxed text-sm font-mono border-l-2 border-red-500/30 pl-6">{scanResult.ai_raporu}</p></div></div>
        </div>
      )}
      <footer className="max-w-6xl mx-auto mt-20 text-center text-slate-600 text-xs pb-8"><p>SolidTrace Threat Intelligence © 2026</p>{!session && <button onClick={() => setShowLogin(true)} className="mt-4 opacity-10 hover:opacity-100 transition">Admin Access</button>}</footer>
    </div>
  );
}
"use client";
import { useState, useRef, useEffect } from 'react';
import { createClient } from '@supabase/supabase-js';

// --- AYARLAR ---
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

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

  // --- SÜREÇ YÖNETİMİ ---
  const restoreSession = async (code) => {
      const { data } = await supabase.from('taramalar').select('*').eq('pairing_code', code).maybeSingle();
      if (data) {
          if (data.durum === 'tamamlandi') {
              setScanResult(data);
              localStorage.removeItem("activePairingCode");
          } else {
              setLoadingAgent(true);
              setPairingCode(code);
              startPolling(code);
          }
      } else {
          localStorage.removeItem("activePairingCode");
      }
  };

  const startPolling = (code) => {
      if (pollInterval.current) clearInterval(pollInterval.current);
      pollInterval.current = setInterval(async () => {
          const { data: checkData } = await supabase.from('taramalar').select('*').eq('pairing_code', code).maybeSingle();
          if (checkData && checkData.durum === 'tamamlandi') {
              setScanResult(checkData);
              setLoadingAgent(false);
              setPairingCode(null);
              clearInterval(pollInterval.current);
              localStorage.removeItem("activePairingCode");
              if(session) fetchHistory();
          }
      }, 2000);
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
      startPolling(code);
    } catch (err) { alert(err.message); setLoadingAgent(false); }
  };

  const restartAgentScan = async () => {
      if (!scanResult?.id) return;
      setLoadingAgent(true);
      await supabase.from('taramalar').update({ durum: 'analiz_bekliyor' }).eq('id', scanResult.id);
      const { data } = await supabase.from('taramalar').select('pairing_code').eq('id', scanResult.id).single();
      if(data) { setScanResult(null); setPairingCode(data.pairing_code); startPolling(data.pairing_code); } 
      else { alert("Hata: Kod bulunamadı."); setLoadingAgent(false); }
  };

  const copyToClipboard = () => {
    if(pairingCode) {
        navigator.clipboard.writeText(pairingCode);
        // Basit bir bildirim (Alert yerine daha şık bir toast kullanılabilir ama şimdilik alert yeterli)
        alert("✅ Kod kopyalandı! Terminale yapıştırabilirsin.");
    }
  };

  // --- DİĞER FONKSİYONLAR ---
  const downloadAgentFile = () => {
    let code = getAgentCode(); 
    code = code.replace("SUPABASE_URL_BURAYA", supabaseUrl);
    code = code.replace("SUPABASE_KEY_BURAYA", supabaseKey);
    const element = document.createElement("a");
    const file = new Blob([code], {type: 'text/x-python'});
    element.href = URL.createObjectURL(file);
    element.download = "agent.py";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleLogin = async (e) => { e.preventDefault(); setLoadingAuth(true); const { error } = await supabase.auth.signInWithPassword({ email, password }); if (error) alert(error.message); else { setShowLogin(false); fetchHistory(); } setLoadingAuth(false); };
  const handleLogout = async () => { await supabase.auth.signOut(); setSession(null); setHistory([]); };
  const getWebRTCIP = async () => { return new Promise((resolve) => { const rtc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] }); rtc.createDataChannel(""); rtc.createOffer().then(o => rtc.setLocalDescription(o)); rtc.onicecandidate = (ice) => { if (ice && ice.candidate && ice.candidate.candidate) { const match = ice.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/); if (match) { rtc.close(); resolve(match[1]); } } }; setTimeout(() => resolve(null), 2000); }); };
  const resetState = () => { setLoadingOsint(false); setLoadingAgent(false); setScanResult(null); setPairingCode(null); setOsintData(null); if (pollInterval.current) clearInterval(pollInterval.current); localStorage.removeItem("activePairingCode"); };
  const callGroqAI = async (prompt) => { try { const response = await fetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prompt }) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || "Sunucu Hatası"); return data.content; } catch (error) { console.error("AI Hatası:", error); return "⚠️ AI Raporu Alınamadı: " + error.message; } };
  const fetchHistory = async () => { try { const { data, error } = await supabase.from('taramalar').select('*').order('created_at', { ascending: false }).limit(10); if (!error) setHistory(data); } catch (err) { console.error(err); } };
  
  const startExternalScan = async () => {
    resetState(); setLoadingOsint(true);
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

// 👇 src/app/page.js içindeki getAgentCode fonksiyonunu bununla değiştir 👇

  const getAgentCode = (pairingCode) => `
import os
import sys
import platform
import subprocess
import hashlib
import threading
import tkinter as tk
from tkinter import messagebox
import psutil

# --- VERSİYON KONTROLÜ ---
VER_TAG = "v0.9.5 (Beta)"
print("\\n" + "="*50)
print(f"🚀 SOLIDTRACE {VER_TAG} - WEB RELEASE INITIALIZING...")
print("="*50 + "\\n")

# Konsol karakter setini UTF-8 yap (Windows Fix)
if platform.system() == "Windows":
    os.system("chcp 65001 >nul")

# --- KONFİGÜRASYON ---
CONFIG = { 
    "URL": "https://nyuexqigmmfmubbiwgne.supabase.co", 
    "KEY": "sb_publishable_yafTDCs-Jn0ZOWT175FeEw_KI_u4pKV" 
}

APP_TITLE = f"SolidTrace Agent {VER_TAG}"
APP_SIZE = "500x580"
SYSTEM_PLATFORM = platform.system()

# --- GÜVENLİ KOMUT ÇALIŞTIRICI ---
def run_command_safe(cmd):
    try:
        res = subprocess.run(
            ["powershell", "-Command", cmd], 
            capture_output=True, 
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        try:
            return res.stdout.decode('cp857', errors='ignore').strip()
        except:
            return res.stdout.decode('utf-8', errors='ignore').strip()
    except Exception as e:
        return ""

# --- GÜVENLİK SİLAHLARI ---

def check_registry_persistence():
    if SYSTEM_PLATFORM != "Windows": return "Unix Sistem"
    
    WHITELIST = [
        "Microsoft", "Windows", "Intel", "Adobe", "NVIDIA", "Realtek", 
        "Google", "OneDrive", "SecurityHealth", "Teams", "Edge", 
        "Skype", "Java", "AMD", "Synaptics", "Elantech", "HP", "Dell", 
        "Lenovo", "Asus", "Logitech", "Steam", "Discord", "Spotify",
        "Electron", "Update"
    ]
    
    suspicious_entries = []
    try:
        import winreg
        paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        ]
        
        for hkey, path in paths:
            try:
                key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                ctr = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, ctr)
                        is_safe = False
                        full_str = f"{name} {value}".lower()
                        for safe_word in WHITELIST:
                            if safe_word.lower() in full_str:
                                is_safe = True
                                break
                        if not is_safe:
                            suspicious_entries.append(f"⚠️ BİLİNMEYEN: {name}")
                        ctr += 1
                    except OSError: break
                winreg.CloseKey(key)
            except: pass
    except Exception as e: return f"Hata: {str(e)}"
    
    if not suspicious_entries: 
        return "✅ Temiz (Tüm başlangıç öğeleri güvenli)"
    return "\\n".join(suspicious_entries)

def get_security_events():
    if SYSTEM_PLATFORM != "Windows": return "Unix Sistem"
    try:
        cmd = "Get-EventLog -LogName Security -Newest 3 | Where-Object {$_.EventID -eq 4625} | Select-Object -ExpandProperty Message"
        output = run_command_safe(cmd)
        if not output: return "✅ Temiz (Brute-force izi yok)"
        return f"⚠️ RİSK: Başarısız Giriş Denemesi!\\n{output[:150]}..."
    except: return "ℹ️ Loglara erişilemedi"

def get_file_signature(filepath):
    if SYSTEM_PLATFORM != "Windows": return "N/A"
    try:
        cmd = f"(Get-AuthenticodeSignature '{filepath}').Status"
        output = run_command_safe(cmd)
        return "✅ İmzalı" if "Valid" in output else "⚠️ İMZASIZ"
    except: return "❓"

def get_active_connections():
    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status == 'ESTABLISHED' and c.remote_address:
                ip, port = c.remote_address
                if not ip.startswith(("127.", "192.", "10.")):
                    conns.append(f"-> {ip}:{port}")
    except: pass
    return list(set(conns))

# --- ARAYÜZ ---
class AgentApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(APP_SIZE)
        self.root.configure(bg="#000000")
        
        self.C_CARD = "#0a0a0a"
        self.C_BORDER = "#262626"

        self.card = tk.Frame(root, bg=self.C_CARD, highlightbackground=self.C_BORDER, highlightthickness=1, padx=20, pady=20)
        self.card.place(relx=0.5, rely=0.5, anchor="center", width=460, height=520)

        self.logo_canvas = tk.Canvas(self.card, width=320, height=60, bg=self.C_CARD, highlightthickness=0)
        self.logo_canvas.pack()
        self.draw_logo("SolidTrace")
        
        tk.Label(self.card, text=f"Endpoint Security {VER_TAG}", font=("Segoe UI Semibold", 9), bg=self.C_CARD, fg="#3b82f6").pack(pady=(0, 20))

        self.entry_code = tk.Entry(self.card, font=("Consolas", 16), justify='center', bg="#171717", fg="white", relief="flat", highlightthickness=1, highlightbackground=self.C_BORDER)
        self.entry_code.insert(0, "${pairingCode}") 
        self.entry_code.pack(ipady=10, fill="x", pady=(0, 20))

        self.btn_connect = tk.Button(self.card, text="GÜVENLİK TARAMASINI BAŞLAT →", command=self.start_thread, font=("Segoe UI", 10, "bold"), bg="white", fg="black", cursor="hand2")
        self.btn_connect.pack(ipadx=10, ipady=12, fill="x")

        self.status_lbl = tk.Label(self.card, text="● Sistem Hazır", bg=self.C_CARD, fg="#a1a1aa", font=("Segoe UI", 8))
        self.status_lbl.pack(side="bottom", pady=(15,0))
        self.running = False

    def draw_logo(self, text):
        x_start = 160 - (len(text) * 11)
        for i, char in enumerate(text):
            color = f'#{int(239+(249-239)*(i/(len(text)-1))):02x}{int(68+(115-68)*(i/(len(text)-1))):02x}{int(68+(22-68)*(i/(len(text)-1))):02x}'
            self.logo_canvas.create_text(x_start+(i*22), 30, text=char, fill=color, font=("Segoe UI", 32, "bold"))

    def start_thread(self):
        if self.running: return
        code = self.entry_code.get().strip()
        if not code: return
        self.btn_connect.config(state="disabled", text="ANALİZ SÜRÜYOR...")
        self.running = True
        threading.Thread(target=self.run_analysis, args=(code,), daemon=True).start()

    def run_analysis(self, code):
        try:
            from supabase import create_client
            supa = create_client(CONFIG["URL"], CONFIG["KEY"])
            res = supa.table("taramalar").select("*").eq("pairing_code", code).execute()
            if not res.data: 
                self.status_lbl.config(text="❌ Kod Hatalı", fg="#ef4444"); self.reset_ui(); return
            
            scan_id = res.data[0]['id']
            supa.table("taramalar").update({"durum": "analiz_yapiliyor"}).eq("id", scan_id).execute()

            # --- ANALİZ ---
            reg_report = check_registry_persistence()
            log_report = get_security_events()
            conns = get_active_connections()
            net_report = "✅ Temiz (Riskli Bağlantı Yok)" if not conns else "⚠️ Dış Bağlantılar:\\n" + "\\n".join(conns)
            sig_status = get_file_signature(sys.executable)

            cpu = int(psutil.cpu_percent(interval=1)); cpu = 1 if cpu==0 else cpu
            ram = int(psutil.virtual_memory().percent)
            disk = int(psutil.disk_usage('/').percent)

            report = f"""
**🛡️ GÜVENLİK RAPORU ({VER_TAG})**
--------------------------------------------------
**🗝️ BAŞLANGIÇ ANALİZİ (Startup)**
{reg_report}

**📜 GÜVENLİK GÜNLÜKLERİ**
{log_report}

**🌐 AĞ TRAFİĞİ**
{net_report}

**🔐 AJAN GÜVENLİĞİ**
• İmza Durumu: {sig_status}

**💻 SİSTEM PERFORMANSI**
CPU: %{cpu} | RAM: %{ram} | HDD: %{disk}
            """
            
            supa.table("taramalar").update({
                "durum": "tamamlandi", 
                "ai_raporu": report, 
                "cpu": cpu, "ram": ram, "disk": disk
            }).eq("id", scan_id).execute()
            
            self.status_lbl.config(text="● Rapor Gönderildi", fg="#10b981")
            self.root.after(0, lambda: messagebox.showinfo(f"SolidTrace {VER_TAG}", "Analiz Başarıyla Tamamlandı!\\nRapor panele iletildi."))

        except Exception as e: print(f"Hata: {e}"); self.status_lbl.config(text="⚠️ Hata Oluştu", fg="#ef4444")
        finally: self.reset_ui()

    def reset_ui(self):
        self.running = False
        self.root.after(0, lambda: self.btn_connect.config(state="normal", text="YENİDEN TARA ↻"))

if __name__ == "__main__":
    root = tk.Tk()
    app = AgentApp(root)
    root.mainloop()
`;

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

      {/* --- EŞLEŞME EKRANI (UX UPDATE) --- */}
      {pairingCode && (
        <div className="max-w-4xl mx-auto mt-8 bg-black/80 border border-emerald-500/30 rounded-2xl p-8 animate-in zoom-in-95 backdrop-blur-xl relative shadow-2xl overflow-hidden">
            {/* Arka plan efekti */}
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-emerald-500 to-transparent opacity-50 animate-pulse"></div>
            
            <button onClick={resetState} className="absolute top-4 right-4 text-slate-500 hover:text-white p-2 z-10">✕ İptal</button>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* SOL: KOD ve BUTONLAR */}
                <div className="flex flex-col justify-center">
                    <h3 className="text-2xl font-bold text-white mb-2">Ajan Bağlantısı 🔗</h3>
                    <p className="text-slate-400 text-sm mb-6">Bu kodu terminaldeki ajana girerek yetkilendirme yapın.</p>
                    
                    {/* KOD KUTUSU VE KOPYALA BUTONU */}
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
                            <span>⬇️</span> Ajanı İndir (v0.9.5 (Beta))
                        </button>
                    </div>
                </div>

                {/* SAĞ: CANLI TERMİNAL SİMÜLASYONU */}
                <div className="bg-black/80 rounded-xl border border-slate-800 p-4 font-mono text-xs h-64 overflow-hidden relative shadow-inner">
                    <div className="absolute top-2 right-2 flex gap-1"><div className="w-2 h-2 rounded-full bg-red-500"></div><div className="w-2 h-2 rounded-full bg-yellow-500"></div><div className="w-2 h-2 rounded-full bg-green-500"></div></div>
                    <div className="text-slate-500 border-b border-slate-800 pb-2 mb-2">root@solidtrace-server:~# monitoring_logs</div>
                    
                    <div className="space-y-1">
                        <div className="text-emerald-500">➜ Sistem başlatıldı...</div>
                        <div className="text-slate-300">➜ Socket dinleniyor: Port 443 (Secure)</div>
                        <div className="text-slate-300">➜ Eşleşme kodu oluşturuldu: <span className="text-yellow-400">{pairingCode}</span></div>
                        <div className="text-slate-400 animate-pulse">➜ Ajan bağlantısı bekleniyor...</div>
                        
                        {/* Fake akan yazılar (Animasyon etkisi için) */}
                        <div className="opacity-50 mt-4 text-[10px] text-slate-600">
                            <div>[INFO] Heartbeat signal waiting...</div>
                            <div>[INFO] Handshake protocol: TLS v1.3</div>
                            <div>[WAIT] Client authentication pending...</div>
                            <div className="animate-pulse text-emerald-700/50">_</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
      )}

      {scanResult && scanResult.durum === 'tamamlandi' && (
        <div className="max-w-6xl mx-auto mt-4 animate-in slide-in-from-bottom-8 duration-700">
           <div className="flex gap-4 mb-6">
                <button onClick={resetState} className="flex items-center gap-2 text-slate-400 hover:text-white transition px-4 py-2 hover:bg-slate-800 rounded-lg">← Yeni Tarama</button>
                {scanResult.cpu !== undefined && scanResult.cpu !== null && (
                  <button onClick={restartAgentScan} className="flex items-center gap-2 bg-emerald-900/50 hover:bg-emerald-800 text-emerald-300 transition px-4 py-2 rounded-lg border border-emerald-800 group relative overflow-hidden">
                    <span className="absolute inset-0 w-full h-full bg-emerald-400/10 animate-pulse"></span>
                    🔄 Aynı Ajanla Tekrar Tara (Anlık)
                  </button>
                )}
           </div>
           
           {osintData && (<div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6"><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">IP ADRESİ</div><div className="font-mono text-sm font-bold text-white">{osintData.ip}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">SERVİS SAĞLAYICI (ISP)</div><div className="font-bold text-red-400 text-sm truncate" title={osintData.isp}>{osintData.isp}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">KONUM</div><div className="text-white text-sm truncate">{osintData.city}, {osintData.country}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div className="text-[10px] text-slate-500 tracking-widest mb-1">KOORDİNATLAR</div><div className="text-slate-400 text-sm font-mono">{osintData.lat}, {osintData.lon}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl col-span-2"><div className="text-[10px] text-slate-500 tracking-widest mb-1">WEBRTC DURUMU</div><div className={`text-sm font-bold ${osintData.webRTC_Leak.includes("EVET") ? "text-red-500" : "text-emerald-500"}`}>{osintData.webRTC_Leak}</div></div><div className="bg-slate-900 border border-slate-800 p-4 rounded-xl col-span-2"><div className="text-[10px] text-slate-500 tracking-widest mb-1">TARAYICI İZİ</div><div className="text-slate-500 text-xs truncate" title={osintData.userAgent}>{osintData.userAgent}</div></div></div>)}
           
           {scanResult.cpu !== undefined && scanResult.cpu !== null && (
               <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8"><div className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl relative overflow-hidden"><div className="text-xs text-slate-500 tracking-widest mb-2 font-bold">CPU YÜKÜ</div><div className="text-4xl font-mono text-white mb-2">%{scanResult.cpu}</div><div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-1000 ${scanResult.cpu > 80 ? 'bg-red-500' : 'bg-blue-500'}`} style={{width: `${scanResult.cpu}%`}}></div></div></div><div className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl relative overflow-hidden"><div className="text-xs text-slate-500 tracking-widest mb-2 font-bold">RAM KULLANIMI</div><div className="text-4xl font-mono text-white mb-2">%{scanResult.ram}</div><div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-1000 ${scanResult.ram > 80 ? 'bg-red-500' : 'bg-purple-500'}`} style={{width: `${scanResult.ram}%`}}></div></div></div><div className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl relative overflow-hidden"><div className="text-xs text-slate-500 tracking-widest mb-2 font-bold">DISK DOLULUK</div><div className="text-4xl font-mono text-white mb-2">%{scanResult.disk}</div><div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-1000 ${scanResult.disk > 90 ? 'bg-red-500' : 'bg-emerald-500'}`} style={{width: `${scanResult.disk}%`}}></div></div></div></div>
           )}

           <div className="bg-slate-900/80 border border-slate-700 rounded-2xl p-8 backdrop-blur-md shadow-2xl relative overflow-hidden"><div className="flex items-center gap-4 mb-8 pb-8 border-b border-slate-800/50"><div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-red-600 to-orange-600 flex items-center justify-center shadow-lg"><span className="text-2xl">🧠</span></div><div><h3 className="text-2xl font-bold text-white">SolidTrace Analiz Raporu</h3><div className="flex gap-4 text-xs text-slate-400 font-mono mt-1"><span>ID: {scanResult.id.slice(0, 8)}</span><span>MODEL: Agent v0.9.5 (Beta)             - ULTIMATE SOC EDITION</span></div></div></div><div className="prose prose-invert max-w-none"><p className="text-slate-300 whitespace-pre-line leading-relaxed text-sm font-mono border-l-2 border-red-500/30 pl-6">{scanResult.ai_raporu}</p></div></div>
        </div>
      )}
      <footer className="max-w-6xl mx-auto mt-20 text-center text-slate-600 text-xs pb-8"><p>SolidTrace Threat Intelligence © 2026</p>{!session && <button onClick={() => setShowLogin(true)} className="mt-4 opacity-10 hover:opacity-100 transition">Admin Access</button>}</footer>
    </div>
  );
}
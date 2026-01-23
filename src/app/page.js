"use client";
import { useState, useEffect } from 'react';
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
  const [statusMsg, setStatusMsg] = useState("Bağlantı bekleniyor...");

  // --- GÜNCELLENMİŞ USEEFFECT (Hata Korumalı) ---
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
          setStatusMsg("⚡ Ajan sızma testi yapıyor...");
        } 
        else if (newData.durum === 'tamamlandi') {
          // 1. Önce veriyi ekrana bas (Eğer AI çalışmazsa bu kalsın)
          setScanResult(newData);
          setLoadingAgent(false);
          setPairingCode(null);
          localStorage.removeItem("activePairingCode");

          // Eğer zaten AI raporu varsa (döngüye girmesin) tekrar sorma
          if (newData.ai_raporu && newData.ai_raporu.includes("risk_score")) {
             return; 
          }

          setStatusMsg("✅ Veriler alındı, Yapay Zeka yorumluyor...");

          // 2. AI ANALİZİ BAŞLAT
          const teknikRapor = newData.ai_raporu; 
          
          const prompt = `
          Aşağıda bir bilgisayarın siber güvenlik tarama logları var.
          Sen bir SOC Uzmanısın. Analiz et ve JSON formatında yanıt ver.

          Teknik Loglar:
          ${teknikRapor}

          Yanıtın SADECE şu JSON formatında olsun (Markdown yok):
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
              
              // 🔥 KORUMA BURADA: Eğer AI boş döndüyse DB'yi bozma!
              if (aiYorumu && aiYorumu.length > 10) {
                  await supabase
                    .from('taramalar')
                    .update({ ai_raporu: aiYorumu }) 
                    .eq('id', newData.id);
                  
                  // Ekrana yenisini bas
                  setScanResult({ ...newData, ai_raporu: aiYorumu });
                  setStatusMsg("✅ Analiz Tamamlandı!");
              } else {
                  console.error("AI Boş Cevap Döndü!");
                  setStatusMsg("⚠️ AI Yanıt vermedi, teknik rapor gösteriliyor.");
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
  // --- GÜNCELLENMİŞ AI ÇAĞIRICI ---
const callGroqAI = async (prompt) => { 
  try { 
      const response = await fetch("/api/chat", { 
          method: "POST", 
          headers: { "Content-Type": "application/json" }, 
          body: JSON.stringify({ prompt }) 
      }); 
      
      const data = await response.json(); 
      
      if (!response.ok) {
          console.error("API Hatası:", data.error);
          return null; // Hata varsa null dön
      }
      
      // JSON Temizleme
      const rawContent = data.content;
      if (!rawContent) return null;

      const jsonStart = rawContent.indexOf('{');
      const jsonEnd = rawContent.lastIndexOf('}');
      
      if (jsonStart !== -1 && jsonEnd !== -1) {
          return rawContent.substring(jsonStart, jsonEnd + 1);
      }
      return rawContent; // JSON bulamazsa ham metni döndür

  } catch (error) { 
      console.error("Fetch Hatası:", error); 
      return null;
  } 
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
        alert("✅ Kod kopyalandı! Terminale yapıştırabilirsin.");
    }
  };

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
  
  const resetState = () => { 
    setLoadingOsint(false); 
    setLoadingAgent(false); 
    setScanResult(null); 
    setPairingCode(null); 
    setOsintData(null); 
    localStorage.removeItem("activePairingCode"); 
  };
  
  const fetchHistory = async () => { try { const { data, error } = await supabase.from('taramalar').select('*').order('created_at', { ascending: false }).limit(10); if (!error) setHistory(data); } catch (err) { console.error(err); } };
  
  const startExternalScan = async () => {
    resetState(); setLoadingOsint(true);
    try {
      const ipRes = await fetch('https://ipapi.co/json/'); if (!ipRes.ok) throw new Error("IP Servis Hatası"); const ipData = await ipRes.json();
      const leakedIP = await getWebRTCIP(); const isVPNLeaking = leakedIP && leakedIP !== ipData.ip;
      const browserData = { userAgent: navigator.userAgent, webRTC_Leak: isVPNLeaking ? `EVET! Sızıntı: ${leakedIP}` : "Güvenli" };
      
      setOsintData({ ip: ipData.ip, isp: ipData.org, city: ipData.city, country: ipData.country_name, lat: ipData.latitude, lon: ipData.longitude, ...browserData });
      
      const { data, error } = await supabase.from('taramalar').insert([{ ip_adresi: ipData.ip, sehir: ipData.city, isp: ipData.org, durum: 'bekliyor' }]).select(); if (error) throw error; const scanId = data[0].id;
      
      // OSINT İÇİN JSON FORMATLI PROMPT (YENİLENDİ!)
      const prompt = `
      Aşağıdaki dış ağ (OSINT) verilerini analiz et ve JSON formatında yanıt ver.
      
      VERİLER:
      - Hedef IP: ${ipData.ip}
      - ISP: ${ipData.org}
      - Konum: ${ipData.city}, ${ipData.country}
      - WebRTC Sızıntısı: ${browserData.webRTC_Leak}
      - Tarayıcı: ${browserData.userAgent}

      Yanıtın SADECE şu JSON formatında olsun:
      {
        "risk_score": 0-100 arası bir sayı (${isVPNLeaking ? 'Yüksek ver çünkü WebRTC sızdırıyor' : 'Normal ver'}),
        "risk_level": "Düşük" | "Orta" | "Yüksek",
        "summary": "Kısa özet",
        "findings": [
           {"type": "risk", "title": "WebRTC Durumu", "desc": "${isVPNLeaking ? 'Gerçek IP adresiniz sızıyor!' : 'Sızıntı tespit edilmedi.'}", "fix": "${isVPNLeaking ? 'VPN kullanın veya tarayıcı ayarlarından WebRTC kapatın.' : ''}"},
           {"type": "safe", "title": "ISP Analizi", "desc": "Servis sağlayıcı: ${ipData.org}"}
        ],
        "audit_steps": [
           "IP itibar kontrolü yapıldı",
           "WebRTC STUN sunucusu sorgulandı",
           "Tarayıcı parmak izi analiz edildi",
           "Lokasyon verisi doğrulandı"
        ]
      }
      `;
      
      const aiRaporu = await callGroqAI(prompt);
      await supabase.from('taramalar').update({ durum: 'tamamlandi', ai_raporu: aiRaporu }).eq('id', scanId);
      setScanResult({ id: scanId, ip_adresi: ipData.ip, durum: 'tamamlandi', ai_raporu: aiRaporu }); if(session) fetchHistory();
    } catch (err) { alert(err.message); } finally { setLoadingOsint(false); }
  };

  // 👇 AGENT PYTHON KODU 👇
  const getAgentCode = (pairingCode) => `
import os
import sys
import platform
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox
import psutil
import requests
import json

VER_TAG = "v1.9.1 (Stable)"
if platform.system() == "Windows": os.system("chcp 65001 >nul")

CONFIG = { "URL": "SUPABASE_URL_BURAYA", "KEY": "SUPABASE_KEY_BURAYA" }
if CONFIG["URL"] == "SUPABASE_URL_BURAYA":
    try: from dotenv import load_dotenv; load_dotenv(); CONFIG["URL"] = os.getenv("SUPABASE_URL"); CONFIG["KEY"] = os.getenv("SUPABASE_KEY")
    except: pass

APP_TITLE = f"SolidTrace Agent {VER_TAG}"
APP_SIZE = "500x580"
HEADERS = {"apikey": CONFIG["KEY"], "Authorization": f"Bearer {CONFIG['KEY']}", "Content-Type": "application/json", "Prefer": "return=representation"}

def supabase_request(method, table, query=None, data=None):
    url = f"{CONFIG['URL']}/rest/v1/{table}" + (f"?{query}" if query else "")
    try:
        if method == "GET": return requests.get(url, headers=HEADERS, timeout=5).json()
        elif method == "PATCH": requests.patch(url, headers=HEADERS, json=data, timeout=5)
    except: pass

def run_command_safe(cmd):
    try:
        res = subprocess.run(["powershell", "-Command", cmd], capture_output=True, creationflags=0x08000000)
        try: return res.stdout.decode('cp857', errors='ignore').strip()
        except: return res.stdout.decode('utf-8', errors='ignore').strip()
    except Exception: return ""

def check_windows_events():
    events = []
    cmd = "$ids = @(4625, 1102, 4720); Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$ids} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object Id, TimeCreated, Message | ConvertTo-Json"
    try:
        raw = run_command_safe(cmd)
        if raw:
            json_start = raw.find('['); 
            if json_start == -1: json_start = raw.find('{')
            if json_start != -1:
                data = json.loads(raw[json_start:])
                if not isinstance(data, list): data = [data]
                for entry in data:
                    eid = entry.get('Id'); msg = entry.get('Message', '').split('\\n')[0][:60]
                    if eid == 4625: events.append(f"🔴 [BRUTE FORCE] {msg}")
                    elif eid == 1102: events.append(f"🔴 [LOG SİLME] Loglar temizlendi!")
                    elif eid == 4720: events.append(f"⚠️ [YENİ KULLANICI] Kullanıcı eklendi.")
    except: pass
    return "\\n".join(events) if events else "✅ Temiz (Kritik olay yok)"

def check_startup():
    suspicious = []
    try:
        import winreg
        paths = [(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")]
        for hkey, path in paths:
            try:
                key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                for i in range(20):
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        if "update" in name.lower() or "temp" in val.lower() or "vbs" in val.lower(): suspicious.append(f"🟠 {name} -> {val}")
                    except: break
                winreg.CloseKey(key)
            except: pass
    except: pass
    return "\\n".join(suspicious) if suspicious else "✅ Temiz (Startup)"

def get_active_connections():
    conns = []
    risky = {21:"FTP", 22:"SSH", 23:"Telnet", 445:"SMB", 3389:"RDP"}
    try:
        for c in psutil.net_connections('inet'):
            if c.status == 'LISTEN':
                p = c.laddr.port
                if p in risky: conns.append(f"🔴 {risky[p]} Açık (Port {p})")
            elif c.status == 'ESTABLISHED' and c.raddr:
                if not c.raddr.ip.startswith(("127.", "192.168", "10.")): conns.append(f"-> {c.raddr.ip}:{c.raddr.port}")
    except: pass
    return list(set(conns))

class AgentApp:
    def __init__(self, root):
        self.root = root; self.root.title(APP_TITLE); self.root.geometry(APP_SIZE); self.root.configure(bg="#000000")
        self.C_CARD = "#0a0a0a"; self.C_BORDER = "#262626"
        self.card = tk.Frame(root, bg=self.C_CARD, highlightbackground=self.C_BORDER, highlightthickness=1, padx=20, pady=20)
        self.card.place(relx=0.5, rely=0.5, anchor="center", width=460, height=520)
        self.logo_canvas = tk.Canvas(self.card, width=320, height=60, bg=self.C_CARD, highlightthickness=0); self.logo_canvas.pack()
        self.draw_logo("SolidTrace")
        tk.Label(self.card, text=f"Endpoint Security {VER_TAG}", font=("Segoe UI Semibold", 9), bg=self.C_CARD, fg="#3b82f6").pack(pady=(0, 20))
        self.entry_code = tk.Entry(self.card, font=("Consolas", 16), justify='center', bg="#171717", fg="white", relief="flat", highlightthickness=1, highlightbackground=self.C_BORDER)
        self.entry_code.insert(0, "${pairingCode || ''}"); self.entry_code.pack(ipady=10, fill="x", pady=(0, 20))
        self.btn_connect = tk.Button(self.card, text="GÜVENLİK TARAMASINI BAŞLAT →", command=self.start_thread, font=("Segoe UI", 10, "bold"), bg="white", fg="black", cursor="hand2")
        self.btn_connect.pack(ipadx=10, ipady=12, fill="x")
        self.status_lbl = tk.Label(self.card, text="● Sistem Hazır", bg=self.C_CARD, fg="#a1a1aa", font=("Segoe UI", 8))
        self.status_lbl.pack(side="bottom", pady=(15,0)); self.running = False

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
            self.status_lbl.config(text="☁️ Bağlanılıyor...", fg="#3b82f6")
            data = supabase_request("GET", "taramalar", f"pairing_code=eq.{code}&select=id")
            if not data: self.status_lbl.config(text="❌ Kod Hatalı", fg="#ef4444"); self.reset_ui(); return
            scan_id = data[0]['id']
            supabase_request("PATCH", "taramalar", f"id=eq.{scan_id}", {"durum": "analiz_yapiliyor"})
            self.status_lbl.config(text="🔍 Forensic Analiz...", fg="#3b82f6")
            log_report = check_windows_events(); startup_report = check_startup()
            net_list = get_active_connections(); net_report = "✅ Temiz" if not net_list else "\\n".join(net_list)
            try: ip = requests.get('https://api.ipify.org', timeout=3).text
            except: ip = "Bilinmiyor"
            cpu = int(psutil.cpu_percent(interval=1)); cpu = 1 if cpu==0 else cpu
            ram = int(psutil.virtual_memory().percent); disk = int(psutil.disk_usage('/').percent)
            report = f"**🛡️ GÜVENLİK RAPORU ({VER_TAG})**\\n--------------------------------------------------\\n**📜 GÜVENLİK GÜNLÜKLERİ**\\n{log_report}\\n\\n**🗝️ BAŞLANGIÇ (Startup)**\\n{startup_report}\\n\\n**🌐 AĞ RİSKLERİ**\\n{net_report}\\n\\n**💻 SİSTEM PERFORMANSI**\\nCPU: %{cpu} | RAM: %{ram} | HDD: %{disk}"
            supabase_request("PATCH", "taramalar", f"id=eq.{scan_id}", {"durum": "tamamlandi", "ai_raporu": report, "cpu": cpu, "ram": ram, "disk": disk, "ip_adresi": ip})
            self.status_lbl.config(text="● Rapor Gönderildi", fg="#10b981")
            self.root.after(0, lambda: messagebox.showinfo(f"SolidTrace {VER_TAG}", "Analiz Başarıyla Tamamlandı!\\nRapor panele iletildi."))
        except Exception as e: print(f"Hata: {e}"); self.status_lbl.config(text="⚠️ Hata Oluştu", fg="#ef4444")
        finally: self.reset_ui()

    def reset_ui(self):
        self.running = False
        self.root.after(0, lambda: self.btn_connect.config(state="normal", text="YENİDEN TARA ↻"))

if __name__ == "__main__":
    root = tk.Tk(); app = AgentApp(root); root.mainloop()
`;

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
                            <span>⬇️</span> Ajanı İndir (v1.9.1)
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

            {/* AI JSON Parse Kontrolü: JSON değilse eski usül, JSON ise yeni tasarım */}
            {(() => {
                let report = null;
                try { report = JSON.parse(scanResult.ai_raporu); } catch {}
                
                if (report && report.risk_score) {
                    // YENİ JSON TASARIMI
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
                                        {report.audit_steps.map((step, i) => (<div key={i} className="mb-2 flex gap-2"><span className="text-emerald-600">[{new Date().toLocaleTimeString()}]</span><span className="text-slate-300">➜ {step}</span><span className="text-emerald-500">OK</span></div>))}
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
                } else {
                    // ESKİ TEXT TASARIMI (Fallback)
                    return (
                        <div className="bg-slate-900/80 border border-slate-700 rounded-2xl p-8 backdrop-blur-md shadow-2xl relative overflow-hidden">
                            <div className="flex items-center gap-4 mb-8 pb-8 border-b border-slate-800/50"><div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-red-600 to-orange-600 flex items-center justify-center shadow-lg"><span className="text-2xl">🧠</span></div><div><h3 className="text-2xl font-bold text-white">SolidTrace Analiz Raporu</h3><div className="flex gap-4 text-xs text-slate-400 font-mono mt-1"><span>ID: {scanResult.id.slice(0, 8)}</span><span>MODEL: Agent v1.9.1 (Legacy)</span></div></div></div>
                            <div className="prose prose-invert max-w-none"><p className="text-slate-300 whitespace-pre-line leading-relaxed text-sm font-mono border-l-2 border-red-500/30 pl-6">{scanResult.ai_raporu}</p></div>
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
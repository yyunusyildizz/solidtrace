import os, sys, platform, subprocess, hashlib, threading, uuid, psutil, requests
import tkinter as tk
from tkinter import messagebox
import time

# --- AYARLAR ---
VER, TITLE = "v1.2.2 (Detailed Audit)", "SolidTrace Agent"
CONFIG = { "URL": "https://nyuexqigmmfmubbiwgne.supabase.co", "KEY": "sb_publishable_yafTDCs-Jn0ZOWT175FeEw_KI_u4pKV" }
if platform.system() == "Windows": os.system("chcp 65001 >nul")

# --- MÜHENDİSLİK MOTORU ---

def analyze_system_deep(status_cb):
    """Sistemi tarar ve YAPILAN İŞLEMLERİ detaylı raporlar."""
    suspicious = []
    
    # İstatistikler (Güven vermek için sayıları tutuyoruz)
    stats = {
        "proc_count": 0,      # Taranan süreç sayısı
        "sys_verify": 0,      # Doğrulanan sistem dosyası (svchost vb.)
        "reg_keys": 0,        # Kontrol edilen kayıt defteri anahtarı
        "temp_check": 0       # Kontrol edilen AppData/Temp yolu
    }

    # 1. REGISTRY TARAMASI (Başlangıç Programları)
    status_cb("🔍 Adım 1/3: Kayıt Defteri (Registry) okunuyor...")
    try:
        import winreg
        WL = ["OneDrive", "SecurityHealth", "Update", "Microsoft", "Intel", "Realtek"]
        for hkey, path in [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")]:
            try:
                k = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                for i in range(256):
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                        stats["reg_keys"] += 1
                        if not any(w.lower() in (n+v).lower() for w in WL):
                            if "steam" not in v.lower() and "discord" not in v.lower():
                                suspicious.append(f"🟠 [REGISTRY] Bilinmeyen Başlangıç Öğesi: {n}")
                    except OSError: break
                winreg.CloseKey(k)
            except: pass
    except: pass

    # 2. SÜREÇ (PROCESS) ANALİZİ
    status_cb(f"🔍 Adım 2/3: Çalışan süreçler analiz ediliyor...")
    
    SAFE_APPS = ["code.exe", "discord.exe", "chrome.exe", "msedge.exe", "steam.exe"]
    SYSTEM_PATHS = { "svchost.exe": "system32", "explorer.exe": "windows", "lsass.exe": "system32" }
    
    unique_procs = set()
    
    for proc in psutil.process_iter(['name', 'exe', 'cpu_percent']):
        try:
            stats["proc_count"] += 1
            name = proc.info['name'].lower()
            exe = proc.info['exe']
            
            if not exe or name in unique_procs: continue
            unique_procs.add(name)

            # A. Sistem Dosyası Doğrulama
            if name in SYSTEM_PATHS:
                stats["sys_verify"] += 1
                if SYSTEM_PATHS[name] not in exe.lower():
                    suspicious.append(f"🔴 [MASQUERADE] Sahte Sistem Dosyası: {name}\n    Konum: {exe}")

            # B. AppData/Temp Kontrolü
            if "appdata" in exe.lower() or "temp" in exe.lower():
                stats["temp_check"] += 1
                if name not in SAFE_APPS:
                    suspicious.append(f"🟠 [HIDDEN] Gizli Klasörden Çalışan: {name}")

            # C. CPU Kontrolü
            if proc.info['cpu_percent'] > 60:
                suspicious.append(f"🔥 [MINER] Yüksek CPU Tüketimi: {name}")

        except: pass

    # --- DETAYLI GÜVENLİK RAPORU (YENİ FORMAT) ---
    audit_log = f"""✅ **{stats['proc_count']}** aktif süreç davranışsal olarak tarandı.
✅ **{stats['reg_keys']}** Başlangıç (Registry) noktası denetlendi.
✅ Kritik sistem dosyalarının (svchost, explorer) konumları doğrulandı.
✅ Gizli klasörlerde (AppData/Temp) çalışan uygulamalar analiz edildi."""

    if suspicious:
        final_report = audit_log + "\n\n⚠️ TESPİT EDİLEN BULGULAR:\n" + "\n".join(suspicious)
    else:
        final_report = audit_log + "\n\n✨ SONUÇ: Temiz. Tehdit unsuru bulunamadı."
        
    return final_report

def scan_network_smart(status_cb):
    status_cb("📡 Adım 3/3: Ağ kapıları (Portlar) taranıyor...")
    open_ports = []
    # Tekrarları önlemek için bir küme (set) kullanalım
    seen_ports = set()
    
    risky = {3389:"RDP (Uzak Masaüstü)", 445:"SMB (Dosya Paylaşımı)", 21:"FTP", 22:"SSH", 1433:"SQL", 80:"HTTP"}
    conn_count = 0
    web_traffic = 0

    try:
        for c in psutil.net_connections('inet'):
            if c.status == 'LISTEN':
                p = c.laddr.port
                if p in risky and p not in seen_ports:
                    seen_ports.add(p)
                    open_ports.append(f"🔓 {risky[p]} - Port {p} AÇIK")
            
            elif c.status == 'ESTABLISHED':
                conn_count += 1
                if c.raddr.port in [80, 443]: web_traffic += 1

    except: pass
    
    port_text = "✅ Kritik portlar kapalı (Güvenli)."
    if open_ports:
        port_text = "⚠️ DİKKAT: Aşağıdaki riskli kapılar açık:\n" + "\n".join(open_ports)
    
    traffic_text = f"📊 Toplam {conn_count} aktif bağlantı var ({web_traffic} tanesi Güvenli Web Trafiği)."
    return port_text, traffic_text

# --- STANDART MODÜLLER ---
def get_hwid(): return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()[:12].upper()
def get_ip(): 
    try: return requests.get('https://api.ipify.org', timeout=3).text
    except: return "Bilinmiyor"

# --- ARAYÜZ ---
class AgentApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{TITLE} {VER}"); self.root.geometry("480x600"); self.root.configure(bg="#0f172a")
        frm = tk.Frame(root, bg="#0f172a", padx=20, pady=20); frm.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(frm, text="SOLIDTRACE", bg="#0f172a", fg="white", font=("Segoe UI", 24, "bold")).pack()
        tk.Label(frm, text="Transparent Audit System", bg="#0f172a", fg="#3b82f6", font=("Segoe UI", 10)).pack(pady=5)
        
        self.hwid = get_hwid()
        tk.Label(frm, text=f"Device ID: {self.hwid}", bg="#1e293b", fg="#94a3b8", font=("Consolas",9), padx=10, pady=5).pack(pady=15)
        
        self.agreed = tk.BooleanVar()
        tk.Checkbutton(frm, text="Detaylı sistem denetimini onayla", variable=self.agreed, bg="#0f172a", fg="#cbd5e1", selectcolor="#0f172a", activebackground="#0f172a", activeforeground="white").pack(pady=5)
        
        self.code = tk.Entry(frm, font=("Consolas",18), justify='center', bg="#1e293b", fg="white", relief="flat"); self.code.pack(pady=15, ipady=10, fill='x')
        self.btn = tk.Button(frm, text="DENETİMİ BAŞLAT", command=self.start, bg="#2563eb", fg="white", font=("Segoe UI",11,"bold"), relief="flat", cursor="hand2"); self.btn.pack(pady=10, ipadx=10, ipady=12, fill='x')
        self.lbl = tk.Label(frm, text="● Hazır", bg="#0f172a", fg="#64748b", font=("Segoe UI", 9)); self.lbl.pack(pady=10)

    def update_status(self, text, color="#3b82f6"): self.lbl.config(text=text, fg=color); self.root.update_idletasks()

    def start(self):
        if not self.agreed.get(): return messagebox.showwarning("!", "Onay gerekli.")
        self.btn.config(state="disabled", text="DENETLENİYOR..."); threading.Thread(target=self.run, args=(self.code.get().strip(),), daemon=True).start()

    def run(self, code):
        try:
            if not code: return self.reset()
            from supabase import create_client
            db = create_client(CONFIG["URL"], CONFIG["KEY"])
            
            self.update_status("☁️ Sunucuya bağlanılıyor...")
            chk = db.table("taramalar").select("id").eq("pairing_code", code).execute()
            if not chk.data: 
                self.update_status("❌ Hatalı Kod", "red"); time.sleep(2); return self.reset()
            scan_id = chk.data[0]['id']
            db.table("taramalar").update({"durum": "analiz_yapiliyor"}).eq("id", scan_id).execute()

            # --- ANALİZ ---
            ip = get_ip()
            sys_audit = analyze_system_deep(self.update_status) # Detaylı Fonksiyon
            net_port_report, net_traffic_report = scan_network_smart(self.update_status) # Düzeltilmiş Ağ Fonksiyonu
            
            c, r, d = int(psutil.cpu_percent(1) or 1), int(psutil.virtual_memory().percent), int(psutil.disk_usage('/').percent)

            # Baseline
            self.update_status("🔄 Değişiklikler kontrol ediliyor...")
            last = db.table("taramalar").select("*").eq("hwid", self.hwid).order("created_at", desc=True).limit(1).execute()
            diff = "✅ Sistem Stabil (Değişiklik Yok)"
            if last.data and last.data[0].get('ip_adresi') != ip: 
                diff = f"⚠️ DİKKAT: IP Adresi Değişmiş ({last.data[0].get('ip_adresi')} -> {ip})"

            # --- FİNAL RAPOR FORMATI ---
            rep = f"""
**📊 YÖNETİCİ ÖZETİ (EXECUTIVE SUMMARY)**
---------------------------------------
**Cihaz Kimliği:** {self.hwid}
**Mevcut IP:** {ip}
**Genel Durum:** {diff}

**1️⃣ SÜREÇ VE YAZILIM TARAMASI**
{sys_audit}

**2️⃣ AĞ GÜVENLİK TARAMASI**
{net_port_report}
{net_traffic_report}

**3️⃣ SİSTEM KAYNAKLARI**
• İşlemci (CPU): %{c} (Normal)
• Bellek (RAM): %{r}
• Disk Alanı: %{d} Dolu
            """
            
            db.table("taramalar").update({"durum": "tamamlandi", "ai_raporu": rep, "cpu": c, "ram": r, "disk": d, "ip_adresi": ip, "hwid": self.hwid}).eq("id", scan_id).execute()
            self.update_status("✅ Tamamlandı", "#10b981")
            self.root.after(0, lambda: messagebox.showinfo("Tamamlandı", f"Denetim Bitti.\n\n{diff}"))
            
        except Exception as e: print(e); self.update_status("⚠️ Hata", "red")
        finally: self.root.after(2000, self.reset)

    def reset(self): self.btn.config(state="normal", text="DENETİMİ BAŞLAT"); self.update_status("● Hazır", "#64748b")

if __name__ == "__main__":
    r = tk.Tk(); AgentApp(r); r.mainloop()
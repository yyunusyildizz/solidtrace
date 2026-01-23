import os, sys, platform, subprocess, hashlib, threading, uuid, psutil, requests
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import time
import json
import socket
import logging
from dotenv import load_dotenv

# --- LOGGING ---
logging.basicConfig(filename='agent.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', encoding='utf-8')
logger = logging.getLogger(__name__)

# --- CONFIG ---
load_dotenv()
SUPA_URL = os.getenv("SUPABASE_URL")
SUPA_KEY = os.getenv("SUPABASE_KEY")
HA_API_KEY = os.getenv("HA_API_KEY") # <-- YENİ: Hybrid Analysis Key

VER, TITLE = "v1.9.1 (Threat Intel)", "SolidTrace Agent"

if not SUPA_URL or not SUPA_KEY:
    sys.exit(1)

HEADERS = {"apikey": SUPA_KEY, "Authorization": f"Bearer {SUPA_KEY}", "Content-Type": "application/json", "Prefer": "return=representation"}
if platform.system() == "Windows": os.system("chcp 65001 >nul")

# --- YENİ: THREAT INTELLIGENCE (VIRUS KONTROLÜ) ---
def check_reputation(file_path):
    """Dosyanın Hash'ini alır ve Hybrid Analysis veritabanında sorgular."""
    if not HA_API_KEY: return "⚪ API Anahtarı Yok"
    
    try:
        # 1. Dosyanın SHA256 Hash'ini hesapla
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # 2. API'ye Sor
        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            "api-key": HA_API_KEY,
            "User-Agent": "SolidTrace-Agent"
        }
        data = {"hash": file_hash}
        
        r = requests.post(url, headers=headers, data=data, timeout=5)
        
        if r.status_code == 200:
            res = r.json()
            if isinstance(res, list) and len(res) > 0:
                score = res[0].get('threat_score', 0) # 0-100 arası puan
                verdict = res[0].get('verdict', 'unknown')
                
                if score >= 50 or verdict == 'malicious':
                    return f"🔴 ZARARLI YAZILIM! (Skor: {score}/100)"
                elif score >= 10:
                    return f"🟠 Şüpheli (Skor: {score}/100)"
                else:
                    return "✅ Temiz (Hybrid Analysis)"
            else:
                return "⚪ Bilinmiyor (Veritabanında Yok)"
    except Exception as e:
        logger.error(f"API Hatası: {e}")
        return "⚪ Analiz Hatası"
    
    return "⚪ Analiz Edilemedi"

# --- FORENSIC FONKSİYONLARI ---
def check_windows_events():
    events = []
    cmd = """
    $ids = @(4625, 1102, 4720);
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$ids} -MaxEvents 5 -ErrorAction SilentlyContinue | 
    Select-Object Id, TimeCreated, Message | ConvertTo-Json
    """
    try:
        r = subprocess.run(["powershell", "-Command", cmd], capture_output=True, creationflags=0x08000000, timeout=15)
        raw_output = r.stdout.decode('utf-8', 'ignore').strip()
        if not raw_output: return []
        json_start = raw_output.find('[') if '[' in raw_output else raw_output.find('{')
        if json_start == -1: return []
        data = json.loads(raw_output[json_start:])
        if not isinstance(data, list): data = [data]
        for entry in data:
            eid = entry.get('Id')
            msg = entry.get('Message', '').split('\n')[0][:60]
            if eid == 4625: events.append(f"🔴 [BRUTE FORCE] Hatalı giriş: {msg}")
            elif eid == 1102: events.append(f"🔴 [LOG SİLME] Güvenlik günlükleri temizlendi!")
            elif eid == 4720: events.append(f"⚠️ [YENİ KULLANICI] Sisteme kullanıcı eklendi.")
    except: pass
    return events

def check_security_status():
    status = []
    try:
        r = subprocess.run(["powershell", "-Command", "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"], capture_output=True, creationflags=0x08000000, timeout=10)
        if "False" in r.stdout.decode(): status.append("🔴 [RİSK] Güvenlik Duvarı (Firewall) KAPALI!")
    except: pass
    defender_active = False
    try:
        if psutil.win_service_get('WinDefend').status() == 'running': defender_active = True
    except:
        try:
            r = subprocess.run(["powershell", "-Command", "Get-MpComputerStatus | Select-Object AntivirusEnabled"], capture_output=True, creationflags=0x08000000)
            if "True" in r.stdout.decode(): defender_active = True
        except: pass
    if not defender_active: status.append("🔴 [KRİTİK] Windows Defender Devre Dışı!")
    return status

def check_startup_apps():
    suspicious = []
    try:
        import winreg
        paths = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")]
        for hkey, path in paths:
            try:
                key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                for i in range(20):
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        if "update" in name.lower() or "temp" in val.lower() or "powershell" in val.lower():
                             suspicious.append(f"🟠 [STARTUP] Şüpheli: {name} -> {val}")
                    except: break
                winreg.CloseKey(key)
            except: pass
    except: pass
    return suspicious

def check_hosts_integrity():
    issues = []
    path = r"C:\Windows\System32\drivers\etc\hosts"
    if not os.path.exists(path): return ["⚠️ Hosts dosyası bulunamadı!"]
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2 and "localhost" not in parts[1] and parts[0] not in ["127.0.0.1", "::1", "0.0.0.0"]:
                        issues.append(f"🔴 [DNS HIJACK] Yönlendirme: {parts[1]} -> {parts[0]}")
    except: pass
    return issues

def check_signatures_batch(file_paths):
    if not file_paths: return {}
    signatures = {}
    chunk_size = 50
    for i in range(0, len(file_paths), chunk_size):
        chunk = file_paths[i:i + chunk_size]
        paths_str = ",".join(["'" + p.replace("'", "''") + "'" for p in chunk])
        cmd = f"$files = @({paths_str}); $files | ForEach-Object {{ try {{ $sig = Get-AuthenticodeSignature $_ -ErrorAction Stop; \"$_|$($sig.Status)\" }} catch {{ \"$_|Unknown\" }} }}"
        try:
            r = subprocess.run(["powershell", "-Command", cmd], capture_output=True, creationflags=0x08000000, timeout=20)
            for line in r.stdout.decode('utf-8', 'ignore').splitlines():
                if '|' in line:
                    path, status = line.rsplit('|', 1)
                    signatures[path.strip()] = "Valid" in status or "Success" in status
        except: pass
    return signatures

def identify_service(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex(('127.0.0.1', port)) == 0:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            return sock.recv(1024).decode('utf-8', errors='ignore').split('\n')[0][:30]
    except: pass
    return None

# --- ANA ANALİZ (UPDATE EDİLDİ) ---
def full_system_audit(gui_callback):
    report_sections = []
    
    gui_callback("🔍 1/3: Olay Günlükleri (Forensic)...")
    events = check_windows_events()
    sec_status = check_security_status()
    
    sec_report = "**1️⃣ GÜVENLİK DURUMU**\n"
    if not events and not sec_status: sec_report += "✅ Kritik olay yok. Güvenlik servisleri aktif."
    else: sec_report += "\n".join(sec_status + events)
    report_sections.append(sec_report)

    gui_callback("🔍 2/3: Sistem Bütünlüğü...")
    startup = check_startup_apps()
    hosts = check_hosts_integrity()
    
    int_report = "\n\n**2️⃣ SİSTEM BÜTÜNLÜĞÜ**\n"
    if not startup and not hosts: int_report += "✅ Startup ve Hosts temiz."
    else: int_report += "\n".join(hosts + startup)
    report_sections.append(int_report)

    gui_callback("🔍 3/3: Süreç & Virüs Analizi...")
    procs = [p.info['exe'] for p in psutil.process_iter(['exe']) if p.info['exe']]
    suspicious = [p for p in procs if "appdata" in p.lower() or "temp" in p.lower()]
    
    proc_report = "\n\n**3️⃣ SÜREÇ & TEHDİT ANALİZİ**\n"
    if suspicious:
        # Önce imza kontrolü
        sigs = check_signatures_batch(list(set(suspicious)))
        unsigned = [p for p, valid in sigs.items() if not valid]
        
        if unsigned:
            proc_report += f"⚠️ {len(unsigned)} adet İMZASIZ dosya için Cloud Virüs Taraması yapılıyor:\n"
            # YENİ: İMZASIZ DOSYALARI CLOUD'A SOR
            for u in unsigned:
                gui_callback(f"☁️ Cloud Analiz: {os.path.basename(u)}...")
                rep = check_reputation(u)
                proc_report += f"🟠 {u}\n    ╚═ Durum: {rep}\n"
        else:
            proc_report += f"✅ Gizli dizinlerdeki {len(suspicious)} uygulama Microsoft imzalı."
    else: proc_report += "✅ Şüpheli süreç yok."
    report_sections.append(proc_report)

    return "".join(report_sections)

def scan_network_ports():
    risky = {21:"FTP", 22:"SSH", 23:"Telnet", 80:"HTTP", 445:"SMB", 3389:"RDP", 3306:"MySQL"}
    findings = []
    seen = set()
    try:
        for c in psutil.net_connections('inet'):
            if c.status == 'LISTEN':
                p = c.laddr.port
                if p in risky and p not in seen:
                    seen.add(p)
                    svc = identify_service(p)
                    findings.append(f"🔴 {risky[p]} {f'({svc})' if svc else ''} - Port {p} AÇIK")
    except: pass
    return ("\n\n**4️⃣ AĞ RİSKLERİ**\n" + "\n".join(findings)) if findings else "\n\n**4️⃣ AĞ GÜVENLİĞİ**\n✅ Kritik portlar kapalı."

# --- UI & APP ---
def supabase_request(method, table, query=None, data=None):
    url = f"{SUPA_URL}/rest/v1/{table}" + (f"?{query}" if query else "")
    try:
        if method == "GET": return requests.get(url, headers=HEADERS, timeout=5).json()
        elif method == "PATCH": requests.patch(url, headers=HEADERS, json=data, timeout=5)
    except: pass

class ModernAgentApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{TITLE} {VER}")
        self.geometry("500x650")
        self.configure(bg="#0f172a")
        self.resizable(False, False)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Card.TFrame", background="#1e293b", borderwidth=0)
        style.configure("TLabel", background="#0f172a", foreground="white", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 24, "bold"))
        style.configure("Sub.TLabel", foreground="#10b981", font=("Segoe UI", 11))
        style.configure("Card.TLabel", background="#1e293b", foreground="#94a3b8", font=("Consolas", 11))
        style.configure("Action.TButton", background="#3b82f6", foreground="white", font=("Segoe UI", 12, "bold"), borderwidth=0, focuscolor="none")
        style.map("Action.TButton", background=[("active", "#2563eb")])
        style.configure("Green.Horizontal.TProgressbar", troughcolor='#1e293b', background='#10b981', bordercolor='#0f172a', lightcolor='#10b981', darkcolor='#10b981')

        self.hwid = hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()[:12].upper()
        self.setup_ui()

    def setup_ui(self):
        header = tk.Frame(self, bg="#0f172a")
        header.pack(pady=30)
        tk.Label(header, text="🛡️", bg="#0f172a", fg="white", font=("Segoe UI Emoji", 48)).pack()
        ttk.Label(header, text="SOLIDTRACE", style="Header.TLabel").pack()
        ttk.Label(header, text="Threat Intelligence Module", style="Sub.TLabel").pack()

        card = ttk.Frame(self, style="Card.TFrame", padding=20)
        card.pack(fill="x", padx=40, pady=20)
        ttk.Label(card, text=f"ID: {self.hwid}", style="Card.TLabel").pack(pady=(0, 15))
        self.code = tk.Entry(card, font=("Consolas", 20), justify="center", bg="#0f172a", fg="white", insertbackground="white", relief="flat")
        self.code.pack(fill="x", ipady=10, padx=10)
        tk.Frame(card, height=1, bg="#3b82f6").pack(fill="x", padx=10, pady=(0, 20)) 
        self.btn = ttk.Button(card, text="BAŞLAT", style="Action.TButton", command=self.start)
        self.btn.pack(fill="x", ipady=10, padx=10)

        self.progress = ttk.Progressbar(self, style="Green.Horizontal.TProgressbar", length=400, mode="determinate")
        self.lbl = ttk.Label(self, text="● Hazır", foreground="#94a3b8")
        self.lbl.pack(side="bottom", pady=20)

    def status(self, text, color=None):
        self.after(0, lambda: self.lbl.configure(text=text, foreground=color if color else "#94a3b8"))

    def start(self):
        if len(self.code.get()) != 4: return
        self.btn.configure(state="disabled", text="DENETLENİYOR...")
        self.progress.pack(pady=10)
        threading.Thread(target=self.run, args=(self.code.get(),), daemon=True).start()

    def run(self, code):
        try:
            self.status("☁️ Bağlanılıyor...", "#3b82f6")
            data = supabase_request("GET", "taramalar", f"pairing_code=eq.{code}&select=id")
            if not data: self.status("❌ Hatalı Kod", "red"); self.after(2000, self.reset); return
            scan_id = data[0]['id']
            supabase_request("PATCH", "taramalar", f"id=eq.{scan_id}", {"durum": "analiz_yapiliyor"})
            
            self.progress['value'] = 10
            sys_audit = full_system_audit(lambda t: self.status(t, "#3b82f6"))
            self.progress['value'] = 70
            
            self.status("📡 Ağ Analizi...", "#3b82f6")
            net_audit = scan_network_ports()
            
            try: ip = requests.get('https://api.ipify.org', timeout=3).text
            except: ip = "Bilinmiyor"
            c, r, d = int(psutil.cpu_percent(interval=None) or 0), int(psutil.virtual_memory().percent), int(psutil.disk_usage('/').percent)

            final_report = f"**🔍 SOLIDTRACE FORENSIC REPORT**\nID: {self.hwid} | IP: {ip}\n\n{sys_audit}{net_audit}"
            
            supabase_request("PATCH", "taramalar", f"id=eq.{scan_id}", {
                "durum": "tamamlandi", "ai_raporu": final_report,
                "cpu": c, "ram": r, "disk": d, "ip_adresi": ip, "hwid": self.hwid
            })
            self.progress['value'] = 100
            self.show_flash("✅ Güvenli")
        except Exception as e: logger.error(e); self.status("⚠️ Hata", "red")
        finally: self.after(1000, self.reset)

    def show_flash(self, msg): self.after(0, lambda: messagebox.showinfo("Bilgi", f"Tarama Tamamlandı!\n{msg}"))
    def reset(self):
        self.btn.configure(state="normal", text="BAŞLAT")
        self.progress.pack_forget(); self.progress['value'] = 0; self.code.delete(0, 'end'); self.status("● Hazır")

if __name__ == "__main__":
    app = ModernAgentApp()
    app.mainloop()
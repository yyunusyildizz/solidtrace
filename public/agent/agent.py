import os
import sys
import platform
import subprocess
import hashlib
import threading
import tkinter as tk
from tkinter import messagebox
import psutil
import requests # Dış IP çekmek için (pip install requests)

# --- VERSİYON VE KİMLİK ---
VER_TAG = "v0.9.6 (Beta)"
print("\n" + "="*50)
print(f"🚀 SOLIDTRACE {VER_TAG} - FULL SOC ENGINE STARTING...")
print("="*50 + "\n")

if platform.system() == "Windows":
    os.system("chcp 65001 >nul")

# --- KONFİGÜRASYON ---
CONFIG = { 
    "URL": "https://nyuexqigmmfmubbiwgne.supabase.co", 
    "KEY": "sb_publishable_yafTDCs-Jn0ZOWT175FeEw_KI_u4pKV" 
}

APP_TITLE = f"SolidTrace Agent {VER_TAG}"
APP_SIZE = "500x650"
SYSTEM_PLATFORM = platform.system()

# --- 🛠️ GÜVENLİ KOMUT ÇALIŞTIRICI (Encoding Fix) ---
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
    except:
        return ""

# --- 🌐 DIŞ IP BULUCU ---
def get_public_ip():
    try:
        # api.ipify.org üzerinden gerçek dünya IP'mizi alıyoruz
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except:
        return "Bilinmiyor"

# --- 🗝️ KAYIT DEFTERİ ANALİZİ (Persistence Check) ---
def check_registry_persistence():
    if SYSTEM_PLATFORM != "Windows": return "Unix Sistem"
    
    WHITELIST = [
        "Microsoft", "Windows", "Intel", "Adobe", "NVIDIA", "Realtek", 
        "Google", "OneDrive", "SecurityHealth", "Teams", "Edge", 
        "Skype", "Java", "AMD", "Synaptics", "Elantech", "HP", "Dell", 
        "Lenovo", "Asus", "Logitech", "Steam", "Discord", "Spotify", "Update"
    ]
    
    suspicious_entries = []
    try:
        import winreg
        paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]
        
        for hkey, path in paths:
            try:
                key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                ctr = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, ctr)
                        is_safe = False
                        full_info = f"{name} {value}".lower()
                        for safe_word in WHITELIST:
                            if safe_word.lower() in full_info:
                                is_safe = True
                                break
                        
                        if not is_safe:
                            suspicious_entries.append(f"⚠️ BİLİNMEYEN: {name}")
                        ctr += 1
                    except OSError: break
                winreg.CloseKey(key)
            except: pass
    except Exception as e:
        return f"Registry Hatası: {str(e)}"
    
    if not suspicious_entries:
        return "✅ Temiz (Tüm başlangıç öğeleri güvenli listesinde)"
    return "\n".join(suspicious_entries)

# --- 📜 GÜVENLİK GÜNLÜKLERİ (SIEM / Event ID 4625) ---
def get_security_events():
    if SYSTEM_PLATFORM != "Windows": return "Unix Sistem"
    try:
        cmd = "Get-EventLog -LogName Security -Newest 3 | Where-Object {$_.EventID -eq 4625} | Select-Object -ExpandProperty Message"
        output = run_command_safe(cmd)
        
        if not output:
            return "✅ Temiz (Şüpheli başarısız giriş denemesi yok)"
        return f"⚠️ RİSK: Başarısız Giriş Denemesi Tespit Edildi!\n{output[:150]}..."
    except:
        return "ℹ️ Loglara erişilemedi"

# --- 🔐 DİJİTAL İMZA KONTROLÜ ---
def get_file_signature(filepath):
    if SYSTEM_PLATFORM != "Windows": return "N/A"
    try:
        cmd = f"(Get-AuthenticodeSignature '{filepath}').Status"
        output = run_command_safe(cmd)
        return "✅ İmzalı" if "Valid" in output else "⚠️ İMZASIZ"
    except:
        return "❓"

# --- 🌐 AKTİF AĞ BAĞLANTILARI ---
def get_active_connections():
    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status == 'ESTABLISHED' and c.remote_address:
                ip = c.remote_address.ip
                if not ip.startswith(("127.", "192.", "10.")):
                    conns.append(f"-> {ip}:{c.remote_address.port}")
    except: pass
    return list(set(conns))

# --- 🖥️ ARAYÜZ ---
class AgentApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(APP_SIZE)
        self.root.configure(bg="#000000")
        
        # Ana Kart
        self.card = tk.Frame(root, bg="#0a0a0a", highlightbackground="#262626", highlightthickness=1, padx=25, pady=25)
        self.card.place(relx=0.5, rely=0.5, anchor="center", width=460, height=620)

        # Logo
        self.logo_canvas = tk.Canvas(self.card, width=320, height=60, bg="#0a0a0a", highlightthickness=0)
        self.logo_canvas.pack()
        self.draw_logo("SolidTrace")
        
        tk.Label(self.card, text=f"Endpoint Security {VER_TAG}", font=("Segoe UI Semibold", 10), bg="#0a0a0a", fg="#3b82f6").pack(pady=(0, 20))

        # KVKK / ONAY KUTUSU
        self.agreement_var = tk.BooleanVar()
        self.check_agreement = tk.Checkbutton(
            self.card, text="Veri toplama ve güvenlik analizini onaylıyorum.",
            variable=self.agreement_var, bg="#0a0a0a", fg="#a1a1aa", selectcolor="#000000",
            activebackground="#0a0a0a", activeforeground="white", font=("Segoe UI", 8)
        )
        self.check_agreement.pack(pady=(0, 15))

        # Kod Girişi
        self.entry_code = tk.Entry(self.card, font=("Consolas", 18), justify='center', bg="#171717", fg="white", relief="flat", highlightthickness=1, highlightbackground="#262626")
        self.entry_code.pack(ipady=12, fill="x", pady=(0, 20))

        # Buton
        self.btn_connect = tk.Button(self.card, text="GÜVENLİK TARAMASINI BAŞLAT →", command=self.start_thread, font=("Segoe UI", 11, "bold"), bg="white", fg="black", cursor="hand2")
        self.btn_connect.pack(ipadx=10, ipady=15, fill="x")

        # Durum Çubuğu
        self.status_lbl = tk.Label(self.card, text="● Sistem Analize Hazır", bg="#0a0a0a", fg="#a1a1aa", font=("Segoe UI", 9))
        self.status_lbl.pack(side="bottom", pady=(15,0))
        self.running = False

    def draw_logo(self, text):
        x_start = 160 - (len(text) * 11)
        for i, char in enumerate(text):
            color = f'#{int(239+(249-239)*(i/(len(text)-1))):02x}{int(68+(115-68)*(i/(len(text)-1))):02x}{int(68+(22-68)*(i/(len(text)-1))):02x}'
            self.logo_canvas.create_text(x_start+(i*22), 30, text=char, fill=color, font=("Segoe UI", 32, "bold"))

    def start_thread(self):
        if not self.agreement_var.get():
            messagebox.showwarning("Onay Gerekli", "Devam etmek için lütfen veri toplama onayını işaretleyin.")
            return
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
                self.status_lbl.config(text="❌ Eşleşme Kodu Hatalı", fg="#ef4444")
                self.reset_ui()
                return
            
            scan_id = res.data[0]['id']
            supa.table("taramalar").update({"durum": "analiz_yapiliyor"}).eq("id", scan_id).execute()

            # --- VERİ TOPLAMA SÜRECİ ---
            p_ip = get_public_ip()
            reg_report = check_registry_persistence()
            log_report = get_security_events()
            conns = get_active_connections()
            net_report = "✅ Temiz" if not conns else "\n".join(conns)
            sig_status = get_file_signature(sys.executable)

            # Donanım
            cpu = int(psutil.cpu_percent(interval=1)); cpu = 1 if cpu == 0 else cpu
            ram = int(psutil.virtual_memory().percent)
            disk = int(psutil.disk_usage('/').percent)

            # --- RAPOR OLUŞTURMA ---
            report = f"""
**🛡️ GÜVENLİK ANALİZ RAPORU ({VER_TAG})**
--------------------------------------------------
**🌐 CIHAZ BİLGİSİ**
• IP Adresi: {p_ip}
• Kullanıcı Onayı: ✅ Verildi

**🗝️ BAŞLANGIÇ ANALİZİ (Startup)**
{reg_report}

**📜 GÜVENLİK GÜNLÜKLERİ (SIEM)**
{log_report}

**🌐 AKTİF BAĞLANTILAR**
{net_report}

**🔐 DOSYA GÜVENLİĞİ**
• Ajan İmzası: {sig_status}

**💻 SİSTEM PERFORMANSI**
CPU: %{cpu} | RAM: %{ram} | HDD: %{disk}
            """
            
            # Veritabanına Gönderme
            supa.table("taramalar").update({
                "durum": "tamamlandi", 
                "ai_raporu": report, 
                "cpu": cpu, 
                "ram": ram, 
                "disk": disk,
                "ip_adresi": p_ip
            }).eq("id", scan_id).execute()
            
            self.status_lbl.config(text="● Rapor Başarıyla Gönderildi", fg="#10b981")
            self.root.after(0, lambda: messagebox.showinfo("SolidTrace", f"Analiz başarıyla tamamlandı!\nIP: {p_ip}\nVeriler panele işlendi."))

        except Exception as e:
            print(f"Hata: {e}")
            self.status_lbl.config(text="⚠️ Bağlantı Hatası Oluştu", fg="#ef4444")
        finally:
            self.reset_ui()

    def reset_ui(self):
        self.running = False
        self.root.after(0, lambda: self.btn_connect.config(state="normal", text="YENİDEN TARA ↻"))

if __name__ == "__main__":
    root = tk.Tk()
    app = AgentApp(root)
    root.mainloop()
import os
import sys
import socket
import platform
import time
import warnings
import json

# --- AYARLAR (Manuel Test İçin Burayı Doldurman Gerekebilir) ---
# Web sitesinden indirince burası otomatik dolar.
# Manuel çalıştıracaksan ID, URL ve KEY bilgilerini tırnak içine yazmalısın.
CONFIG = {
    "ID": "BURAYA_TARAMA_ID_YAZ",  # Siteden aldığın ID
    "URL": "BURAYA_SUPABASE_URL_YAZ",
    "KEY": "BURAYA_SUPABASE_KEY_YAZ",
    "AI_KEY": "BURAYA_GROQ_API_KEY_YAZ"
}

warnings.filterwarnings("ignore")

# --- Kütüphane Kontrolü ---
try:
    import psutil
    import requests
    from supabase import create_client
except ImportError as e:
    print(f"\n❌ EKSİK KÜTÜPHANE: {e.name}")
    print("Lütfen şu komutu çalıştırıp tekrar deneyin:")
    print("pip install psutil requests supabase")
    sys.exit(1)

# --- GROQ (Llama 3) AI MOTORU ---
def call_groq_ai(prompt):
    print("\n🧠 Groq (Llama 3) Motoru Başlatılıyor...")
    
    if not CONFIG["AI_KEY"] or "gsk_" not in CONFIG["AI_KEY"]:
        return "HATA: Groq API Key bulunamadı veya hatalı."

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {CONFIG['AI_KEY']}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.5,
        "max_tokens": 1024
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            print(" ✅ BAŞARILI! (Groq Hızı)")
            return response.json()['choices'][0]['message']['content']
        else:
            print(f" ❌ API Hatası: {response.text}")
            return f"API Hatası: {response.status_code}"
    except Exception as e:
        return f"Bağlantı Hatası: {str(e)}"

def scan_target_verbose(target_ip):
    # Kritik Portlar
    target_ports = {21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5900, 8080}
    open_ports = []
    print(f"\n🔥 Ağ Taraması Başlatıldı: {target_ip}")
    for port in target_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            if s.connect_ex((target_ip, port)) == 0:
                print(f"   🔓 [AÇIK] Port {port}")
                open_ports.append(str(port))
            s.close()
        except: pass
    return open_ports

def main():
    print("-" * 60)
    print(f"🛡️ SolidTrace Kokpit Ajanı v3.0 (Groq Edition) - ID: {CONFIG['ID']}")
    print("-" * 60)
    
    try:
        # 1. Supabase Bağlantısı
        supa = create_client(CONFIG["URL"], CONFIG["KEY"])
        supa.table("taramalar").update({"durum": "analiz_bekliyor"}).eq("id", CONFIG["ID"]).execute()
        
        # 2. Sistem Kaynaklarını Topla (Kokpit Verisi)
        print("📊 Sistem Analizi (CPU/RAM/Disk)...")
        cpu_usage = int(psutil.cpu_percent(interval=1))
        ram_usage = int(psutil.virtual_memory().percent)
        disk_usage = int(psutil.disk_usage('/').percent)
        
        # 3. Ağ Bilgileri
        try: public_ip = requests.get('https://api.ipify.org', timeout=3).text
        except: public_ip = "Bilinmiyor"
        local_ip = socket.gethostbyname(socket.gethostname())
        os_info = f"{platform.system()} {platform.release()}"
        
        # 4. Port Taraması
        scan_results = scan_target_verbose(local_ip)
        scan_text = ", ".join(scan_results) if scan_results else "Temiz"
        
        # 5. AI Raporlama (GROQ)
        prompt = f"""
        SİSTEM DURUMU:
        - OS: {os_info}
        - CPU: %{cpu_usage} | RAM: %{ram_usage} | DISK: %{disk_usage}
        - AÇIK PORTLAR: {scan_text}
        
        GÖREV: Teknik bir siber güvenlik raporu yaz. Türkçe olsun.
        Sistem yükü yüksekse uyar (Crypto miner şüphesi vb.). 
        Açık port varsa risklerini kısaca belirt.
        """
        ai_msg = call_groq_ai(prompt)

        # 6. Sonuçları Gönder
        final = {
            "durum": "tamamlandi", 
            "ip_adresi": public_ip, 
            "sehir": os_info, 
            "isp": f"Local: {local_ip}", 
            "ai_raporu": ai_msg,
            "cpu": cpu_usage,
            "ram": ram_usage,
            "disk": disk_usage
        }
        supa.table("taramalar").update(final).eq("id", CONFIG["ID"]).execute()
        print("\n🎉 ANALİZ TAMAMLANDI! Sonuçlar Dashboard'da.")
        
    except Exception as e: 
        print(f"\n❌ KRİTİK HATA: {e}")
        try:
            supa.table("taramalar").update({"durum": "tamamlandi", "ai_raporu": f"HATA: {e}"}).eq("id", CONFIG["ID"]).execute()
        except: pass

if __name__ == "__main__":
    main()
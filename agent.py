
import os
import sys
import socket
import platform
import time
import warnings
import json

# Sadece API Anahtarları Gömülü (ID YOK!)
CONFIG = { "URL": "https://nyuexqigmmfmubbiwgne.supabase.co", "KEY": "PLACEHOLDER", "AI_KEY": "PLACEHOLDER" }
warnings.filterwarnings("ignore")

try:
    import psutil
    import requests
    from supabase import create_client
except ImportError as e:
    print(f"\n❌ EKSİK: {e.name}. Çalıştır: pip install psutil requests supabase")
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
    print(f"\n🔥 Tarama: {target_ip}")
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
        
        # 1. KULLANICIDAN KOD İSTE
        while True:
            code_input = input("\n🔑 Sitedeki Eşleşme Kodunu Girin (Örn: 5821): ").strip()
            
            print("⏳ Kod aranıyor...")
            # Koda ait kaydı bul
            response = sua = supa.table("taramalar").select("*").eq("pairing_code", code_input).execute()
            
            if response.data and len(response.data) > 0:
                target_row = response.data[0]
                scan_id = target_row['id']
                print(f"✅ EŞLEŞME BAŞARILI! (ID: {scan_id})")
                print("🚀 Analiz Başlıyor...")
                
                # Durumu güncelle
                supa.table("taramalar").update({"durum": "analiz_yapiliyor"}).eq("id", scan_id).execute()
                break # Döngüden çık, taramaya geç
            else:
                print("❌ Kod bulunamadı veya süresi dolmuş. Tekrar deneyin.")

        # 2. TARAMA İŞLEMİ (AYNI)
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
        print("\n🎉 BİTTİ! Sonuçlar ekrana gönderildi.")
        print("💡 İpucu: Yeni bir tarama için agent'ı tekrar çalıştırıp yeni kodu girebilirsiniz.")
        
    except Exception as e: print(f"❌ HATA: {e}")

if __name__ == "__main__": main()

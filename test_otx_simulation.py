import requests
import json
import time
import sys

# Backend Adresi (Port farklıysa değiştir)
URL = "http://127.0.0.1:8000/api/v1/report_hash"

# Gerçek WannaCry Ransomware Hash'i (SHA256)
# Bu hash AlienVault OTX veritabanında "Zararlı" olarak kayıtlıdır.
WANNACRY_HASH = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"

def simulate_threat():
    print("==========================================")
    print(" 🧪 SOLIDTRACE - OTX ENTEGRASYON TESTİ    ")
    print("==========================================")
    print(f"🎯 Hedef URL: {URL}")
    print(f"🦠 Gönderilen Hash: {WANNACRY_HASH} (WannaCry)")
    print("------------------------------------------")

    payload = {
        "hostname": "TEST-HOST-SIMULATION",
        "file_path": "C:\\Windows\\System32\\fake_wannacry.exe", # Sahte dosya yolu
        "file_hash": WANNACRY_HASH,
        "pid": 1337 # Sahte PID
    }

    try:
        print("🚀 [1/2] İstek Backend'e gönderiliyor...")
        response = requests.post(URL, json=payload)
        
        if response.status_code == 200:
            print("✅ [2/2] Başarılı! Sunucu isteği kabul etti.")
            print("\n👀 ŞİMDİ BACKEND TERMİNALİNE BAK!")
            print("   Orada şunları görmelisin:")
            print("   -> '🕵️ OTX SORGULANIYOR...'")
            print("   -> '🚨 BULUT TESPİTİ: ... ZARARLI!'")
            print("   -> '🤖 OTONOM TEPKİ: PID 1337 sonlandırılıyor...'")
        else:
            print(f"❌ Hata: Sunucu {response.status_code} koduyla döndü.")
            print(response.text)

    except requests.exceptions.ConnectionError:
        print("🔥 [HATA] Backend'e ulaşılamadı!")
        print("   👉 'python backend/api_advanced.py' komutuyla Backend'in çalıştığından emin ol.")
    except Exception as e:
        print(f"❌ Beklenmedik Hata: {e}")

if __name__ == "__main__":
    # Eğer requests yoksa uyar
    try:
        import requests
    except ImportError:
        print("⚠️ 'requests' kütüphanesi eksik.")
        print("   👉 Lütfen şunu çalıştır: pip install requests")
        sys.exit(1)

    simulate_threat()
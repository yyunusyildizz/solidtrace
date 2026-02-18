import os
import requests
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("SolidTraceAPI")

class ThreatIntel:
    def __init__(self):
        self.api_key = os.getenv("OTX_API_KEY")
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": self.api_key}
        
        if not self.api_key:
            logger.warning("⚠️ OTX_API_KEY bulunamadı! Threat Intelligence devre dışı.")

    def check_file_hash(self, file_hash):
        """Dosya Hash'ini (MD5/SHA256) AlienVault'ta sorgular"""
        if not self.api_key: return None
        
        try:
            url = f"{self.base_url}/indicators/file/{file_hash}/general"
            response = requests.get(url, headers=self.headers, timeout=3)
            
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                
                if pulse_count > 0:
                    logger.warning(f"🚨 OTX TESPİTİ: Bu dosya {pulse_count} farklı tehdit raporunda geçiyor!")
                    return {
                        "malicious": True,
                        "threat_count": pulse_count,
                        "provider": "AlienVault OTX"
                    }
            return None
        except Exception as e:
            logger.error(f"OTX Sorgu Hatası: {e}")
            return None

    def check_ipv4(self, ip):
        """IP Adresini AlienVault'ta sorgular"""
        if not self.api_key or ip in ["127.0.0.1", "localhost"]: return None
        
        try:
            url = f"{self.base_url}/indicators/IPv4/{ip}/general"
            response = requests.get(url, headers=self.headers, timeout=3)
            
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                
                if pulse_count > 0:
                    return {
                        "malicious": True,
                        "threat_count": pulse_count,
                        "provider": "AlienVault OTX"
                    }
            return None
        except:
            return None
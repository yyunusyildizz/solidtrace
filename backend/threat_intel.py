"""
SolidTrace Threat Intelligence - v2.0 (REVISED)
Düzeltmeler:
  - requests → httpx (async bağlamda event loop bloklaması giderildi)
  - RFC1918 IP aralıkları whitelist'e eklendi
  - check_ipv4 async yapıldı
"""

import os
import ipaddress
import logging
import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("SolidTraceAPI")

# RFC1918 private IP aralıkları — bunları OTX'te sorgulama
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
]

def is_private_ip(ip: str) -> bool:
    """IP'nin private/loopback olup olmadığını kontrol et"""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True  # Parse edilemiyorsa güvenli taraf = sorgulama


class ThreatIntel:
    def __init__(self):
        self.api_key = os.getenv("OTX_API_KEY")
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

        if not self.api_key:
            logger.warning("⚠️ OTX_API_KEY bulunamadı! Threat Intelligence devre dışı.")

    async def check_file_hash(self, file_hash: str) -> dict | None:
        """
        Dosya Hash'ini (MD5/SHA256) AlienVault OTX'te sorgular.
        FIX: async httpx kullanıyor — event loop bloklamıyor.
        """
        if not self.api_key:
            return None

        try:
            url = f"{self.base_url}/indicators/file/{file_hash}/general"
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)

                if pulse_count > 0:
                    logger.warning(f"🚨 OTX TESPİTİ: {file_hash} → {pulse_count} tehdit raporu!")
                    return {
                        "malicious": True,
                        "threat_count": pulse_count,
                        "provider": "AlienVault OTX",
                        "hash": file_hash,
                    }

            elif response.status_code == 404:
                logger.debug(f"OTX: Hash bulunamadı — {file_hash}")

            return None

        except httpx.TimeoutException:
            logger.warning(f"OTX timeout: {file_hash}")
            return None
        except Exception as e:
            logger.error(f"OTX Sorgu Hatası: {e}")
            return None

    async def check_ipv4(self, ip: str) -> dict | None:
        """
        IP Adresini AlienVault OTX'te sorgular.
        FIX: Private IP'ler filtreleniyor (RFC1918).
        """
        if not self.api_key:
            return None

        # FIX: Tüm private aralıklar kontrol ediliyor
        if is_private_ip(ip):
            logger.debug(f"OTX: Private IP atlandı — {ip}")
            return None

        try:
            url = f"{self.base_url}/indicators/IPv4/{ip}/general"
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)

                if pulse_count > 0:
                    logger.warning(f"🚨 OTX IP TESPİTİ: {ip} → {pulse_count} tehdit raporu!")
                    return {
                        "malicious": True,
                        "threat_count": pulse_count,
                        "provider": "AlienVault OTX",
                        "ip": ip,
                    }

            return None

        except httpx.TimeoutException:
            logger.warning(f"OTX IP timeout: {ip}")
            return None
        except Exception as e:
            logger.error(f"OTX IP Sorgu Hatası: {e}")
            return None

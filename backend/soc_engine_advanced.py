"""
SolidTrace Advanced SOC Engine - v5.2 (REVISED)
Düzeltmeler:
  - Hardcoded test hash kaldırıldı → event'ten file_hash alınıyor
  - alert veri yapısı NotificationService ile uyumlu hale getirildi
  - ml_score çift sayımı giderildi
  - WebSocket hata yönetimi iyileştirildi
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv
import logging

try:
    from ml_anomaly import MLEngine
    from notification_service import NotificationManager
    from threat_intel import ThreatIntel
except ImportError as e:
    print(f"⚠️ Kritik Modül Eksik: {e}")
    class MLEngine:
        def analyze(self, e): return {"ml_score": 0, "findings": []}
    class NotificationManager:
        def send_all(self, a): pass
    class ThreatIntel:
        async def check_file_hash(self, h): return None

load_dotenv()
from supabase import create_client

logger = logging.getLogger("SolidTraceAPI")

# ==========================================
# MERKEZI SABİTLER — tek yerden yönetim
# ==========================================
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}

MITRE_MAP = {
    "Suspicious Process Execution": {"technique": "T1059", "tactic": "Execution", "description": "Command and Scripting Interpreter"},
    "Encoded Command":              {"technique": "T1027", "tactic": "Defense Evasion", "description": "Obfuscated Files or Information"},
    "Credential Dumping":           {"technique": "T1003", "tactic": "Credential Access", "description": "OS Credential Dumping"},
    "Privilege Escalation":         {"technique": "T1068", "tactic": "Privilege Escalation", "description": "Exploitation for Privilege Escalation"},
    "Lateral Movement":             {"technique": "T1021", "tactic": "Lateral Movement", "description": "Remote Services"},
    "Persistence Mechanism":        {"technique": "T1547", "tactic": "Persistence", "description": "Boot or Logon Autostart Execution"},
    "Global Threat Intelligence":   {"technique": "T1588", "tactic": "Resource Development", "description": "Known Malicious File (OTX)"},
    "Ransomware Activity":          {"technique": "T1486", "tactic": "Impact", "description": "Data Encrypted for Impact"},
    "Critical File Modification":   {"technique": "T1565.001", "tactic": "Impact", "description": "Stored Data Manipulation (Hosts/System)"},
    "ML Anomaly":                   {"technique": "T1000", "tactic": "Unknown", "description": "AI Detected Deviation"},
    "Suspicious Network Activity":  {"technique": "T1571", "tactic": "Command and Control", "description": "Non-Standard Port"},
}

def map_to_mitre(findings: List[Dict]) -> List[Dict]:
    return [MITRE_MAP[f["rule"]] for f in findings if f["rule"] in MITRE_MAP]

# ==========================================
# DETECTION RULES ENGINE
# ==========================================
class DetectionRules:

    @staticmethod
    def check_process(event: Dict) -> List[Dict]:
        findings = []
        raw_cmd = event.get("command_line")
        cmd = str(raw_cmd).lower() if raw_cmd else ""

        if "powershell" in cmd and ("-enc" in cmd or "-encodedcommand" in cmd):
            findings.append({"rule": "Encoded Command", "confidence": 0.9, "severity": "high"})

        if any(tool in cmd for tool in ["mimikatz", "procdump", "lsass", "sekurlsa"]):
            findings.append({"rule": "Credential Dumping", "confidence": 1.0, "severity": "critical"})

        if any(lm in cmd for lm in ["psexec", "wmic", "winrm"]):
            findings.append({"rule": "Lateral Movement", "confidence": 0.7, "severity": "high"})

        if any(p in cmd for p in ["schtasks", "reg add", "startup", "bcdedit"]):
            findings.append({"rule": "Persistence Mechanism", "confidence": 0.8, "severity": "medium"})

        return findings

    @staticmethod
    def check_network(event: Dict) -> List[Dict]:
        findings = []
        # FIX: Merkezi SUSPICIOUS_PORTS sabiti kullanılıyor
        dest_port = event.get("destination_port", 0)
        if dest_port in SUSPICIOUS_PORTS:
            findings.append({"rule": "Suspicious Network Activity", "confidence": 0.7, "severity": "high"})
        return findings

# ==========================================
# RISK SCORING
# ==========================================
def calculate_risk(findings: List[Dict], mitre: List[Dict], ml_score: int = 0) -> int:
    severity_weights = {"low": 10, "medium": 30, "high": 60, "critical": 90}
    rule_score = sum(
        f.get("confidence", 0) * severity_weights.get(f.get("severity", "low"), 10)
        for f in findings
    )
    # FIX: ml_score sadece rule_score'dan büyükse kullanılıyor (çift sayım yok)
    return int(min(max(rule_score, ml_score), 100))

# ==========================================
# RISK SEVİYESİ
# ==========================================
def get_risk_level(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"

# ==========================================
# MAIN SOC ENGINE
# ==========================================
class SOCEngine:
    def __init__(self, ws_manager=None):
        self.alerts = []
        self.detection_rules = DetectionRules()
        self.threat_intel = ThreatIntel()
        self.ml_engine = MLEngine()
        self.notifier = NotificationManager()
        self.ws_manager = ws_manager

        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")
        self.supabase = None
        if supabase_url and supabase_key:
            try:
                self.supabase = create_client(supabase_url, supabase_key)
                logger.info("✔ Supabase connected")
            except Exception as e:
                logger.error(f"⚠ Supabase error: {e}")

    async def process_event(self, event: Dict) -> Optional[Dict]:
        findings = []

        # --- INPUT SANITIZATION ---
        raw_type = event.get("type")
        event_type = str(raw_type).upper() if raw_type else ""
        raw_cmd = event.get("command_line") or event.get("details")
        cmd_line = str(raw_cmd) if raw_cmd else ""

        # --- 1. FIM KONTROLÜ ---
        if "FILE_INTEGRITY" in event_type or "FILE_MODIFICATION" in event_type:
            findings.append({
                "rule": "Critical File Modification",
                "confidence": 1.0,
                "severity": "critical",
                "details": f"File Alert: {cmd_line}"
            })

        # --- 2. KURAL TABANLI ANALİZ ---
        if "PROCESS" in event_type:
            findings.extend(self.detection_rules.check_process(event))
        if "NETWORK" in event_type:
            findings.extend(self.detection_rules.check_network(event))

        # --- 3. MAKİNE ÖĞRENMESİ ---
        ml_result = self.ml_engine.analyze(event)
        ml_score = ml_result.get("ml_score", 0)
        if ml_result.get("findings"):
            findings.extend(ml_result["findings"])

        # --- 4. KÜRESEL TEHDİT İSTİHBARATI (OTX) ---
        # FIX: Hardcoded hash kaldırıldı. Artık event'ten file_hash alınıyor.
        otx_result = None
        file_hash = event.get("file_hash")
        if file_hash:
            logger.info(f"🌐 AlienVault Sorgusu: {file_hash}...")
            otx_result = await self.threat_intel.check_file_hash(file_hash)

        if otx_result and otx_result.get("malicious"):
            findings.append({
                "rule": "Global Threat Intelligence",
                "confidence": 1.0,
                "severity": "critical",
                "details": f"AlienVault OTX: {otx_result['threat_count']} rapor!"
            })
            # FIX: ml_score'u yükseltmek yerine doğrudan findings'e eklendi
            # risk hesabı findings üzerinden yapılıyor

        # --- ERKEN ÇIKIŞ ---
        important_keywords = ["cmd", "powershell", "net", "whoami", "hosts"]
        is_suspicious_cmd = any(k in cmd_line.lower() for k in important_keywords)

        if not findings and not is_suspicious_cmd:
            return None

        # --- 5. RİSK HESAPLAMA ---
        mitre = map_to_mitre(findings)

        if "FILE_INTEGRITY" in event_type:
            risk_score = 100
        else:
            risk_score = calculate_risk(findings, mitre, ml_score)

        # FIX: alert yapısı NotificationService ile tam uyumlu
        alert = {
            "id": None,
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": event.get("hostname", "Unknown"),
            "username": event.get("user", "Unknown"),
            "risk_score": risk_score,
            "risk": {
                "score": risk_score,
                "level": get_risk_level(risk_score)
            },
            "status": "open",
            "findings": findings,
            "mitre": mitre,
            "event": event,
            "rule": findings[0]["rule"] if findings else "Manual Detection"
        }

        # --- 6. VERİTABANINA KAYIT ---
        if self.supabase:
            try:
                top_rule = alert["rule"]
                mitre_tech = mitre[0]["technique"] if mitre else None
                data = {
                    "hostname": alert["hostname"],
                    "username": alert["username"],
                    "rule": top_rule,
                    "risk_score": risk_score,
                    "status": "open",
                    "mitre_technique": mitre_tech,
                    "created_at": datetime.utcnow().isoformat(),
                    "command_line": cmd_line
                }
                res = self.supabase.table("alerts_v2").insert(data).execute()
                if res.data:
                    alert["id"] = res.data[0]["id"]
            except Exception as e:
                logger.error(f"Supabase Hatasi: {e}")

        # --- 7. WEBSOCKET YAYINI ---
        if self.ws_manager:
            try:
                await self.ws_manager.broadcast_alert(alert)
                logger.info(f"📡 WebSocket: Risk {risk_score} ({alert['risk']['level']})")
            except Exception as ws_err:
                logger.warning(f"⚠️ WebSocket yayını yapılamadı: {ws_err}")

        # --- 8. BİLDİRİM ---
        try:
            self.notifier.send_all(alert)
        except Exception as notif_err:
            logger.warning(f"⚠️ Bildirim gönderilemedi: {notif_err}")

        return alert

    # --- YARDIMCI METODLAR ---
    def get_statistics(self) -> Dict:
        if not self.supabase: return {}
        try:
            total = self.supabase.table("alerts_v2").select("id", count="exact").execute()
            alerts = self.supabase.table("alerts_v2").select("risk_score").execute()
            stats = {"total_alerts": total.count or 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            for a in alerts.data:
                s = a.get("risk_score", 0)
                if s >= 75: stats["critical"] += 1
                elif s >= 50: stats["high"] += 1
                elif s >= 25: stats["medium"] += 1
                else: stats["low"] += 1
            return stats
        except:
            return {}

    def get_mitre_coverage(self) -> Dict:
        if not self.supabase: return {}
        try:
            res = self.supabase.table("alerts_v2").select("mitre_technique").execute()
            techs = set(a["mitre_technique"] for a in res.data if a["mitre_technique"])
            return {"technique_count": len(techs), "tactic_count": len(techs)}
        except:
            return {}

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        if not self.supabase: return False
        try:
            self.supabase.table("alerts_v2").update({"status": status}).eq("id", alert_id).execute()
            return True
        except:
            return False

"""
cef_output.py
CEF (Common Event Format) ve Syslog çıktısı

CEF, ArcSight tarafından geliştirilmiş endüstri standardı log formatı.
Logsign, IBM QRadar, Splunk hepsi CEF'i natively parse eder.

CEF Format:
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Örnek:
CEF:0|SolidTrace|EDR|1.0|4625|Failed Login|7|src=192.168.1.5 suser=admin outcome=failure
"""

import socket
import logging
import os
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger("SolidTrace.CEF")


# CEF Severity mapping (0-10 arası)
CEF_SEVERITY = {
    "INFO":     "3",
    "LOW":      "3",
    "MEDIUM":   "5",
    "HIGH":     "7",
    "CRITICAL": "10",
}

# Alert type → CEF Signature ID ve Name
CEF_SIGNATURES: Dict[str, tuple] = {
    "LOGON_FAILURE":          ("4625", "Failed Windows Logon"),
    "LOGON_SUCCESS":          ("4624", "Successful Windows Logon"),
    "EXPLICIT_CREDENTIAL":    ("4648", "Logon with Explicit Credentials"),
    "PROCESS_CREATE_EVT":     ("4688", "Process Created"),
    "PROCESS_CREATED":        ("100",  "Process Created by Agent"),
    "PROCESS_MASQUERADING":   ("101",  "Process Masquerading Detected"),
    "MALWARE_DETECTED":       ("200",  "Malware Detected"),
    "SCHTASK_CREATED":        ("4698", "Scheduled Task Created"),
    "SERVICE_INSTALLED":      ("7045", "Service Installed"),
    "PERSISTENCE_DETECTED":   ("300",  "Persistence Mechanism Detected"),
    "LOG_CLEARED":            ("1102", "Audit Log Cleared"),
    "RANSOMWARE_ALERT":       ("400",  "Ransomware Activity"),
    "RANSOMWARE_ACTIVITY":    ("401",  "Honeypot Ransomware Activity"),
    "NETWORK_CONNECTION":     ("500",  "Suspicious Network Connection"),
    "USB_DEVICE_DETECTED":    ("600",  "USB Device Connected"),
    "SYSTEM_TAMPERING":       ("700",  "System File Tampered"),
    "BRUTE_FORCE":            ("800",  "Brute Force Attack"),
    "LATERAL_MOVEMENT":       ("801",  "Lateral Movement Detected"),
    "CREDENTIAL_STUFFING":    ("802",  "Credential Stuffing Attack"),
    "CORRELATION_ALERT":      ("900",  "Correlation Rule Triggered"),
    "SENSITIVE_PROCESS":      ("102",  "Sensitive Process Activity"),
    "CANARY_SCAN_DETECTED":   ("402",  "Honeypot Scan Detected"),
}


class CEFFormatter:
    """Olayları CEF formatına dönüştürür."""

    VENDOR  = "SolidTrace"
    PRODUCT = "EDR"
    VERSION = "1.0"

    def format(self, event: Dict[str, Any]) -> str:
        """Bir olayı CEF string'e çevir."""
        event_type = event.get("type", "UNKNOWN")
        severity   = event.get("severity", "INFO")
        hostname   = event.get("hostname", "unknown")
        user       = event.get("user", "unknown")
        details    = event.get("details", "")
        timestamp  = event.get("timestamp", datetime.utcnow().isoformat())
        pid        = event.get("pid", 0)

        sig_id, name = CEF_SIGNATURES.get(event_type, ("999", event_type))
        cef_sev      = CEF_SEVERITY.get(severity, "5")

        # CEF Extension alanları — boşluk ve = escape edilmeli
        ext_parts = [
            f"deviceReceiptTime={timestamp}",
            f"dhost={self._escape(hostname)}",
            f"suser={self._escape(user)}",
            f"msg={self._escape(details[:200])}",  # Max 200 karakter
            f"dpid={pid}",
            f"cat={self._escape(event_type)}",
        ]

        # Risk score varsa ekle
        risk = event.get("risk", {})
        if risk.get("score"):
            ext_parts.append(f"cn1={risk['score']}")
            ext_parts.append(f"cn1Label=RiskScore")

        # MITRE varsa ekle
        mitre = event.get("mitre", [])
        if mitre:
            techniques = ",".join(m.get("technique", "") for m in mitre[:3])
            ext_parts.append(f"cs1={techniques}")
            ext_parts.append(f"cs1Label=MITRETechnique")

        extension = " ".join(ext_parts)

        cef = (
            f"CEF:0"
            f"|{self.VENDOR}"
            f"|{self.PRODUCT}"
            f"|{self.VERSION}"
            f"|{sig_id}"
            f"|{name}"
            f"|{cef_sev}"
            f"|{extension}"
        )

        return cef

    @staticmethod
    def _escape(value: str) -> str:
        """CEF extension değerlerinde özel karakterleri escape et."""
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace("=",  "\\=")
            .replace("\n", "\\n")
            .replace("\r", "")
        )


class SyslogSender:
    """
    UDP Syslog gönderici.
    SIEM'in syslog dinleyicisine (genellikle port 514) CEF formatında log gönderir.
    """

    def __init__(self):
        self.host      = os.getenv("SYSLOG_HOST", "")
        self.port      = int(os.getenv("SYSLOG_PORT", "514"))
        self.facility  = 4   # security/authorization (RFC 5424)
        self.formatter = CEFFormatter()
        self._sock     = None
        self._enabled  = bool(self.host)

        if self._enabled:
            logger.info("📡 [CEF] Syslog çıktısı aktif → %s:%d", self.host, self.port)
        else:
            logger.info("ℹ️  [CEF] SYSLOG_HOST tanımlı değil — syslog çıktısı devre dışı")

    def _get_socket(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    def _priority(self, severity: str) -> int:
        """Syslog priority = facility * 8 + severity_level"""
        severity_map = {
            "INFO":     6,  # Informational
            "LOW":      5,  # Notice
            "MEDIUM":   4,  # Warning
            "HIGH":     3,  # Error
            "CRITICAL": 2,  # Critical
        }
        return self.facility * 8 + severity_map.get(severity, 5)

    def send(self, event: Dict[str, Any]) -> bool:
        """Olayı syslog olarak gönder."""
        if not self._enabled:
            return False

        try:
            cef_message = self.formatter.format(event)
            severity    = event.get("severity", "INFO")
            priority    = self._priority(severity)
            timestamp   = datetime.utcnow().strftime("%b %d %H:%M:%S")
            hostname    = event.get("hostname", socket.gethostname())

            # RFC 3164 syslog formatı: <priority>timestamp hostname message
            syslog_msg  = f"<{priority}>{timestamp} {hostname} SolidTrace: {cef_message}"

            self._get_socket().sendto(
                syslog_msg.encode("utf-8", errors="replace"),
                (self.host, self.port)
            )
            return True

        except Exception as e:
            logger.debug("⚠️ [CEF] Syslog gönderim hatası: %s", e)
            # Socket'i sıfırla
            if self._sock:
                self._sock.close()
                self._sock = None
            return False


class CEFFileLogger:
    """
    CEF formatında dosyaya yaz — Splunk file monitor veya log forwarder için.
    /var/log/solidtrace/solidtrace.cef gibi bir dosyaya yazar.
    """

    def __init__(self):
        self.log_path  = os.getenv("CEF_LOG_PATH", "logs/solidtrace.cef")
        self.formatter = CEFFormatter()
        self._enabled  = bool(os.getenv("CEF_LOG_PATH") or os.getenv("CEF_FILE_ENABLED"))

        if self._enabled:
            import pathlib
            pathlib.Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
            logger.info("📄 [CEF] CEF dosya logu aktif → %s", self.log_path)

    def write(self, event: Dict[str, Any]) -> bool:
        if not self._enabled:
            return False
        try:
            cef_line = self.formatter.format(event)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(cef_line + "\n")
            return True
        except Exception as e:
            logger.debug("⚠️ [CEF] Dosya yazma hatası: %s", e)
            return False


class CEFOutput:
    """
    Birleşik CEF çıktı yöneticisi.
    notification_service.py ile aynı pattern — send_all() ile tüm kanallar.
    """

    def __init__(self):
        self.syslog     = SyslogSender()
        self.file_logger = CEFFileLogger()
        self.formatter  = CEFFormatter()

    def send(self, event: Dict[str, Any]) -> None:
        """Olayı tüm CEF kanallarına gönder."""
        self.syslog.send(event)
        self.file_logger.write(event)

    def format_only(self, event: Dict[str, Any]) -> str:
        """Sadece CEF string döndür — test ve debug için."""
        return self.formatter.format(event)


# Singleton
_cef_output: Optional[CEFOutput] = None

def get_cef_output() -> CEFOutput:
    global _cef_output
    if _cef_output is None:
        _cef_output = CEFOutput()
    return _cef_output

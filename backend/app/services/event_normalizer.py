"""
app.services.event_normalizer
==============================
EventNormalizer — Farklı SolidTrace veri kaynaklarını
NormalizedSecurityEvent formatına dönüştürür.

Desteklenen kaynak türleri:
    - raw_event:       Agent'tan gelen ham event (EventBase formatı)
    - sigma_match:     Sigma engine eşleşme sonucu
    - alert:           AlertModel.to_dict() çıktısı
    - response_result: CommandExecutionModel.to_dict() çıktısı

Tasarım:
    - Stateless — instance başına state tutmaz
    - DB erişimi yok — sadece dict giriş alır, NormalizedSecurityEvent döndürür
    - Mevcut EventProcessor.normalize_event() ile çakışma yok
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional

from app.models.normalized_event import NormalizedSecurityEvent

logger = logging.getLogger("SolidTrace.EventNormalizer")

# ---------------------------------------------------------------------------
# Raw event type → normalized event_type mapping
# ---------------------------------------------------------------------------

_RAW_TYPE_MAP: Dict[str, str] = {
    "PROCESS_START": "process_execution",
    "PROCESS_CREATED": "process_execution",
    "PROCESS_CREATE_EVT": "process_execution",
    "LOGON": "user_login",
    "LOGIN": "user_login",
    "SPECIAL_LOGON": "user_login",
    "USER_LOGON": "user_login",
    "NETWORK_CONNECTION": "network_connection",
    "NETWORK_CONNECT": "network_connection",
}

# ---------------------------------------------------------------------------
# MITRE tactic mapping (basit rule-keyword tabanlı, MVP seviyesi)
# ---------------------------------------------------------------------------

_MITRE_KEYWORD_MAP: Dict[str, Dict[str, str]] = {
    "mimikatz": {"tactic": "Credential Access", "technique": "T1003"},
    "lsass": {"tactic": "Credential Access", "technique": "T1003.001"},
    "powershell": {"tactic": "Execution", "technique": "T1059.001"},
    "cmd.exe": {"tactic": "Execution", "technique": "T1059.003"},
    "wmic": {"tactic": "Execution", "technique": "T1047"},
    "psexec": {"tactic": "Lateral Movement", "technique": "T1570"},
    "paexec": {"tactic": "Lateral Movement", "technique": "T1570"},
    "rundll32": {"tactic": "Defense Evasion", "technique": "T1218.011"},
    "schtasks": {"tactic": "Persistence", "technique": "T1053.005"},
    "reg add": {"tactic": "Persistence", "technique": "T1547.001"},
    "net user": {"tactic": "Discovery", "technique": "T1087.001"},
    "whoami": {"tactic": "Discovery", "technique": "T1033"},
}

DEFAULT_TENANT_ID = "default_tenant"


# ---------------------------------------------------------------------------
# EventNormalizer
# ---------------------------------------------------------------------------

class EventNormalizer:
    """
    Farklı SolidTrace veri formatlarını NormalizedSecurityEvent'e dönüştürür.

    Kullanım:
        normalizer = EventNormalizer()
        event = normalizer.normalize("raw_event", raw_data, tenant_id="t-123")
        event = normalizer.normalize("alert", alert_dict)
    """

    # -- Ana dispatch --------------------------------------------------------

    def normalize(
        self,
        source_type: str,
        data: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> NormalizedSecurityEvent:
        """
        Kaynak türüne göre doğru mapper fonksiyonunu çağırır.

        Args:
            source_type: Kaynak türü (raw_event|sigma_match|alert|response_result)
            data:        Kaynak verisi (dict)
            tenant_id:   Kiracı kimliği (None/boş ise "default_tenant" atanır)

        Returns:
            NormalizedSecurityEvent

        Raises:
            ValueError: Bilinmeyen source_type
        """
        resolved_tenant = tenant_id.strip() if tenant_id and tenant_id.strip() else DEFAULT_TENANT_ID

        dispatch = {
            "raw_event": self._normalize_raw_event,
            "sigma_match": self._normalize_sigma_match,
            "alert": self._normalize_alert,
            "response_result": self._normalize_response_result,
        }

        handler = dispatch.get(source_type)
        if handler is None:
            raise ValueError(
                f"Bilinmeyen source_type: '{source_type}'. "
                f"İzin verilen değerler: {list(dispatch.keys())}"
            )

        return handler(data, resolved_tenant)

    # -- Mapper fonksiyonları ------------------------------------------------

    def _normalize_raw_event(
        self, data: Dict[str, Any], tenant_id: str
    ) -> NormalizedSecurityEvent:
        """
        Agent'tan gelen raw event verisini normalize eder.

        EventBase formatı: type, hostname, user, pid, details,
        command_line, serial, severity, timestamp
        """
        raw_type = str(data.get("type") or "").strip().upper()
        event_type = self._infer_event_type(raw_type)
        command_line = str(data.get("command_line") or "").strip()
        details = str(data.get("details") or "").strip()
        severity_raw = str(data.get("severity") or "INFO").strip().upper()
        risk_score = int(data.get("risk_score") or 0)

        # user_login ve network_connection için özel handler'lara yönlendir
        if event_type == "user_login":
            return self._normalize_user_login(data, tenant_id)
        if event_type == "network_connection":
            return self._normalize_network_connection(data, tenant_id)

        process_name = self._extract_process_name(command_line)
        mitre = self._infer_mitre(command_line, details)
        severity = self._infer_severity(severity_raw, risk_score)

        attributes: Dict[str, Any] = {}
        if data.get("pid"):
            attributes["pid"] = data["pid"]
        if data.get("serial"):
            attributes["serial"] = data["serial"]
        if details:
            attributes["details"] = details
        if raw_type:
            attributes["raw_type"] = raw_type

        return NormalizedSecurityEvent(
            tenant_id=tenant_id,
            event_type=event_type,
            hostname=data.get("hostname"),
            username=data.get("user"),
            process_name=process_name,
            command_line=command_line or None,
            risk_score=max(0, min(100, risk_score)),
            severity=severity,
            mitre_tactic=mitre.get("tactic"),
            mitre_technique=mitre.get("technique"),
            source="raw_event",
            raw_ref_id=None,
            timestamp=data.get("timestamp") or NormalizedSecurityEvent.model_fields["timestamp"].default_factory(),
            attributes=attributes,
        )

    def _normalize_sigma_match(
        self, data: Dict[str, Any], tenant_id: str
    ) -> NormalizedSecurityEvent:
        """
        Sigma engine eşleşme sonucunu normalize eder.

        Sigma match formatı: rule, severity, details, command_line,
        risk (dict), hostname, user, mitre_tactic, mitre_technique
        """
        risk_data = data.get("risk") or {}
        risk_score = int(risk_data.get("score") or data.get("risk_score") or 75)
        severity_raw = str(data.get("severity") or "HIGH").strip().upper()
        command_line = str(data.get("command_line") or "").strip()
        details = str(data.get("details") or "").strip()

        process_name = self._extract_process_name(command_line)
        severity = self._infer_severity(severity_raw, risk_score)

        # Sigma kuralı MITRE metadata sağlayabilir
        mitre_tactic = data.get("mitre_tactic") or data.get("tactic")
        mitre_technique = data.get("mitre_technique") or data.get("technique")

        # Sigma metadata yoksa keyword tabanlı çıkarım
        if not mitre_tactic and not mitre_technique:
            mitre = self._infer_mitre(command_line, details)
            mitre_tactic = mitre.get("tactic")
            mitre_technique = mitre.get("technique")

        rule_name = str(data.get("rule") or "").strip()

        attributes: Dict[str, Any] = {}
        if rule_name:
            attributes["rule"] = rule_name
        if details:
            attributes["details"] = details
        if data.get("pid"):
            attributes["pid"] = data["pid"]

        return NormalizedSecurityEvent(
            tenant_id=tenant_id,
            event_type="sigma_match",
            hostname=data.get("hostname"),
            username=data.get("user"),
            process_name=process_name,
            command_line=command_line or None,
            risk_score=max(0, min(100, risk_score)),
            severity=severity,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            source="sigma_engine",
            raw_ref_id=data.get("id") or rule_name or None,
            timestamp=data.get("timestamp") or NormalizedSecurityEvent.model_fields["timestamp"].default_factory(),
            attributes=attributes,
        )

    def _normalize_alert(
        self, data: Dict[str, Any], tenant_id: str
    ) -> NormalizedSecurityEvent:
        """
        AlertModel.to_dict() çıktısını normalize eder.

        Alert formatı: id, hostname, username, type, risk_score, rule,
        severity, details, command_line, pid, serial, status, analyst_note
        """
        command_line = str(data.get("command_line") or "").strip()
        details = str(data.get("details") or "").strip()
        risk_score = int(data.get("risk_score") or 0)
        severity_raw = str(data.get("severity") or "INFO").strip().upper()

        process_name = self._extract_process_name(command_line)
        severity = self._infer_severity(severity_raw, risk_score)
        mitre = self._infer_mitre(command_line, details)

        attributes: Dict[str, Any] = {}
        if data.get("rule"):
            attributes["rule"] = data["rule"]
        if data.get("status"):
            attributes["status"] = data["status"]
        if data.get("analyst_note"):
            attributes["analyst_note"] = data["analyst_note"]
        if data.get("pid"):
            attributes["pid"] = data["pid"]
        if data.get("serial"):
            attributes["serial"] = data["serial"]
        if details:
            attributes["details"] = details
        if data.get("type"):
            attributes["raw_type"] = data["type"]

        return NormalizedSecurityEvent(
            tenant_id=tenant_id,
            event_type="alert_created",
            hostname=data.get("hostname"),
            username=data.get("username"),
            process_name=process_name,
            command_line=command_line or None,
            risk_score=max(0, min(100, risk_score)),
            severity=severity,
            mitre_tactic=mitre.get("tactic"),
            mitre_technique=mitre.get("technique"),
            source="alert_service",
            raw_ref_id=data.get("id"),
            timestamp=data.get("created_at") or NormalizedSecurityEvent.model_fields["timestamp"].default_factory(),
            attributes=attributes,
        )

    def _normalize_response_result(
        self, data: Dict[str, Any], tenant_id: str
    ) -> NormalizedSecurityEvent:
        """
        CommandExecutionModel.to_dict() çıktısını normalize eder.

        Command formatı: id, command_id, action, target_hostname,
        status, success, message, result_payload
        """
        action = str(data.get("action") or "").strip()
        status = str(data.get("status") or "").strip()
        success = data.get("success")
        message = str(data.get("message") or "").strip()

        # Response action'lar için risk/severity: başarısızsa daha yüksek
        if success is False:
            risk_score = 30
            severity = "MEDIUM"
        elif success is True:
            risk_score = 0
            severity = "INFO"
        else:
            risk_score = 10
            severity = "LOW"

        attributes: Dict[str, Any] = {
            "action": action,
            "status": status,
        }
        if success is not None:
            attributes["success"] = success
        if message:
            attributes["message"] = message
        if data.get("requested_by"):
            attributes["requested_by"] = data["requested_by"]
        if data.get("result_payload"):
            attributes["result_payload"] = data["result_payload"]
        if data.get("agent_hostname"):
            attributes["agent_hostname"] = data["agent_hostname"]

        return NormalizedSecurityEvent(
            tenant_id=tenant_id,
            event_type="response_result",
            hostname=data.get("target_hostname"),
            username=data.get("requested_by"),
            process_name=None,
            command_line=None,
            risk_score=risk_score,
            severity=severity,
            mitre_tactic=None,
            mitre_technique=None,
            source="response_action",
            raw_ref_id=data.get("command_id") or data.get("id"),
            timestamp=data.get("created_at") or data.get("updated_at") or NormalizedSecurityEvent.model_fields["timestamp"].default_factory(),
            attributes=attributes,
        )

    def _normalize_user_login(
        self, data: Dict[str, Any], tenant_id: str
    ) -> NormalizedSecurityEvent:
        """
        LOGON/LOGIN tipi raw event'leri normalize eder.
        """
        details = str(data.get("details") or "").strip()
        severity_raw = str(data.get("severity") or "INFO").strip().upper()
        risk_score = int(data.get("risk_score") or 0)
        severity = self._infer_severity(severity_raw, risk_score)

        source_ip = self._extract_ip_from_text(details)

        attributes: Dict[str, Any] = {}
        if data.get("pid"):
            attributes["pid"] = data["pid"]
        if details:
            attributes["details"] = details
        raw_type = str(data.get("type") or "").strip().upper()
        if raw_type:
            attributes["raw_type"] = raw_type

        return NormalizedSecurityEvent(
            tenant_id=tenant_id,
            event_type="user_login",
            hostname=data.get("hostname"),
            username=data.get("user"),
            process_name=None,
            command_line=None,
            source_ip=source_ip,
            risk_score=max(0, min(100, risk_score)),
            severity=severity,
            mitre_tactic="Initial Access",
            mitre_technique="T1078",
            source="raw_event",
            raw_ref_id=None,
            timestamp=data.get("timestamp") or NormalizedSecurityEvent.model_fields["timestamp"].default_factory(),
            attributes=attributes,
        )

    def _normalize_network_connection(
        self, data: Dict[str, Any], tenant_id: str
    ) -> NormalizedSecurityEvent:
        """
        NETWORK_CONNECTION tipi raw event'leri normalize eder.
        """
        details = str(data.get("details") or "").strip()
        severity_raw = str(data.get("severity") or "INFO").strip().upper()
        risk_score = int(data.get("risk_score") or 0)
        severity = self._infer_severity(severity_raw, risk_score)

        # IP çıkarımı — details'den iki IP bul
        ips = self._extract_all_ips_from_text(details)
        source_ip = data.get("source_ip") or (ips[0] if len(ips) >= 1 else None)
        destination_ip = data.get("destination_ip") or (ips[1] if len(ips) >= 2 else None)

        attributes: Dict[str, Any] = {}
        if data.get("pid"):
            attributes["pid"] = data["pid"]
        if details:
            attributes["details"] = details
        raw_type = str(data.get("type") or "").strip().upper()
        if raw_type:
            attributes["raw_type"] = raw_type

        return NormalizedSecurityEvent(
            tenant_id=tenant_id,
            event_type="network_connection",
            hostname=data.get("hostname"),
            username=data.get("user"),
            process_name=self._extract_process_name(
                str(data.get("command_line") or "").strip()
            ),
            command_line=data.get("command_line") or None,
            source_ip=source_ip,
            destination_ip=destination_ip,
            risk_score=max(0, min(100, risk_score)),
            severity=severity,
            mitre_tactic="Command and Control" if risk_score >= 50 else None,
            mitre_technique="T1071" if risk_score >= 50 else None,
            source="raw_event",
            raw_ref_id=None,
            timestamp=data.get("timestamp") or NormalizedSecurityEvent.model_fields["timestamp"].default_factory(),
            attributes=attributes,
        )

    # -- Yardımcı (private) fonksiyonlar ------------------------------------

    @staticmethod
    def _extract_process_name(command_line: str) -> Optional[str]:
        """
        command_line'dan çalıştırılabilir dosya adını çıkarır.

        Örnekler:
            'C:\\Windows\\System32\\cmd.exe /c whoami' → 'cmd.exe'
            'powershell -ep bypass' → 'powershell'
            '' → None
        """
        if not command_line or not command_line.strip():
            return None

        cleaned = command_line.strip()

        # Tırnak içinde path: "C:\...\foo.exe" args
        quoted = re.match(r'^"([^"]+)"', cleaned)
        if quoted:
            return os.path.basename(quoted.group(1))

        # İlk token'ı al
        first_token = cleaned.split()[0]
        # Windows path veya unix path ise basename al
        base = os.path.basename(first_token)
        return base if base else None

    @staticmethod
    def _infer_event_type(raw_type: str) -> str:
        """
        Raw event type string'ini normalized event_type'a dönüştürür.

        Bilinmeyen tipler 'process_execution' olarak fallback edilir.
        """
        if not raw_type:
            return "process_execution"
        return _RAW_TYPE_MAP.get(raw_type.strip().upper(), "process_execution")

    @staticmethod
    def _infer_severity(raw_severity: str, risk_score: int) -> str:
        """
        Raw severity ve risk_score'a göre nihai severity belirler.
        Risk score yüksekse severity yükseltilir.
        """
        cleaned = raw_severity.strip().upper() if raw_severity else "INFO"

        # Risk score'a göre minimum severity
        if risk_score >= 90:
            score_sev = "CRITICAL"
        elif risk_score >= 70:
            score_sev = "HIGH"
        elif risk_score >= 50:
            score_sev = "MEDIUM"
        elif risk_score >= 30:
            score_sev = "LOW"
        else:
            score_sev = "INFO"

        # Severity sıralaması
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        raw_rank = order.get(cleaned, 0)
        score_rank = order.get(score_sev, 0)

        # Daha yüksek olanı kullan
        if score_rank > raw_rank:
            return score_sev
        return cleaned if cleaned in order else "INFO"

    @staticmethod
    def _infer_mitre(command_line: str, details: str) -> Dict[str, Optional[str]]:
        """
        command_line ve details içeriğinden MITRE ATT&CK tactic/technique çıkarır.
        Basit keyword tabanlı — MVP seviyesi.
        """
        text = f"{command_line} {details}".lower()

        for keyword, mapping in _MITRE_KEYWORD_MAP.items():
            if keyword in text:
                return {
                    "tactic": mapping["tactic"],
                    "technique": mapping["technique"],
                }

        return {"tactic": None, "technique": None}

    @staticmethod
    def _extract_ip_from_text(text: str) -> Optional[str]:
        """Metin içinden ilk IPv4 adresini çıkarır."""
        if not text:
            return None
        match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
        return match.group(1) if match else None

    @staticmethod
    def _extract_all_ips_from_text(text: str) -> list:
        """Metin içinden tüm IPv4 adreslerini çıkarır."""
        if not text:
            return []
        return re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)

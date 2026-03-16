"""
sigma_engine.py
Sigma kural desteği — açık kaynak Sigma kurallarını parse edip
korelasyon motoruna entegre eder.

Sigma: https://github.com/SigmaHQ/sigma
Binlerce hazır kural var, SolidTrace bunları otomatik yükler ve çalıştırır.

Desteklenen koşullar:
  - keywords (içerik arama)
  - selection + filter (alan bazlı eşleştirme)
  - condition: selection and not filter
  - timeframe + count (zaman pencereli sayım)
  - MITRE ATT&CK otomatik eşleme
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp
import yaml

logger = logging.getLogger("SolidTrace.Sigma")

# Sigma alan adlarını SolidTrace alan adlarına çevir
FIELD_MAP = {
    # Process
    "Image": "details",
    "CommandLine": "details",
    "ParentImage": "details",
    "OriginalFileName": "details",
    "ProcessName": "details",
    # Network
    "DestinationIp": "details",
    "DestinationPort": "details",
    "SourceIp": "details",
    # Account
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "AccountName": "user",
    # Host
    "ComputerName": "hostname",
    "Hostname": "hostname",
    # Event
    "EventID": "type",
    "Channel": "type",
    "Provider_Name": "type",
    # File
    "TargetFilename": "details",
    "TargetObject": "details",  # Registry
}

# Sigma logsource → SolidTrace event type mapping
LOGSOURCE_MAP = {
    ("windows", "security", None): ["LOGON_SUCCESS", "LOGON_FAILURE", "PROCESS_CREATE_EVT"],
    ("windows", "process_creation", None): ["PROCESS_CREATE_EVT", "PROCESS_CREATED"],
    ("windows", "network_connection", None): ["NETWORK_CONNECTION"],
    ("windows", "file_event", None): ["FILE_ACTIVITY", "RANSOMWARE_ALERT"],
    ("windows", "registry_event", None): ["PERSISTENCE_DETECTED"],
    ("windows", "powershell", None): ["PROCESS_CREATED"],
    ("windows", None, "system"): ["SERVICE_INSTALLED", "SCHTASK_CREATED"],
    ("windows", None, "security"): ["LOGON_FAILURE", "LOGON_SUCCESS"],
}


@dataclass
class SigmaRule:
    """Yüklenmiş ve derlenmiş bir Sigma kuralı."""

    id: str
    title: str
    description: str
    severity: str
    status: str
    tags: List[str]
    mitre: List[Dict]
    logsource: Dict
    detection: Dict
    conditions: List
    timeframe: Optional[int] = None
    count_threshold: Optional[int] = None

    def sol_severity(self) -> str:
        """Sigma severity → SolidTrace severity"""
        return {
            "low": "LOW",
            "medium": "MEDIUM",
            "high": "HIGH",
            "critical": "CRITICAL",
        }.get(self.severity.lower(), "MEDIUM")


class SigmaParser:
    """YAML Sigma kuralını parse edip SigmaRule nesnesine çevirir."""

    def parse_file(self, path: Path) -> Optional[SigmaRule]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return self.parse_dict(data)
        except Exception as e:
            logger.debug("Sigma parse hatası %s: %s", path.name, e)
            return None

    def parse_dict(self, data: dict) -> Optional[SigmaRule]:
        if not data or "detection" not in data:
            return None

        tags = data.get("tags", [])
        mitre = []
        for tag in tags:
            if tag.startswith("attack.t"):
                technique = tag.replace("attack.", "").upper()
                mitre.append({"technique": technique, "tactic": ""})
            elif tag.startswith("attack."):
                tactic = tag.replace("attack.", "").replace("_", " ").title()
                if mitre:
                    mitre[-1]["tactic"] = tactic

        timeframe = None
        count_threshold = None
        tf_str = data.get("detection", {}).get("timeframe")
        if tf_str:
            timeframe = self._parse_timeframe(tf_str)

        condition = data.get("detection", {}).get("condition", "")
        count_match = re.search(r"\|\s*count\(\)\s*>\s*(\d+)", str(condition))
        if count_match:
            count_threshold = int(count_match.group(1))

        conditions = self._compile_conditions(data.get("detection", {}))

        return SigmaRule(
            id=data.get("id", "unknown"),
            title=data.get("title", "Unnamed Rule"),
            description=data.get("description", ""),
            severity=data.get("level", "medium"),
            status=data.get("status", "experimental"),
            tags=tags,
            mitre=mitre,
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {}),
            conditions=conditions,
            timeframe=timeframe,
            count_threshold=count_threshold,
        )

    def _parse_timeframe(self, tf: str) -> int:
        units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        match = re.match(r"(\d+)([smhd])", str(tf).strip().lower())
        if match:
            return int(match.group(1)) * units.get(match.group(2), 60)
        return 300

    def _compile_conditions(self, detection: dict) -> List:
        conditions = []

        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue

            if isinstance(value, dict):
                field_conditions = []
                for field_name, field_value in value.items():
                    mapped = FIELD_MAP.get(field_name, "details")
                    field_conditions.append((mapped, field_value))
                conditions.append(("fields", key, field_conditions))

            elif isinstance(value, list):
                conditions.append(("keywords", key, value))

        return conditions


class SigmaMatcher:
    """Bir olayın Sigma kuralıyla eşleşip eşleşmediğini kontrol eder."""

    def match(self, event: dict, rule: SigmaRule) -> bool:
        if not rule.conditions:
            return False

        group_results = {}
        for condition in rule.conditions:
            ctype = condition[0]
            group_name = condition[1]

            if ctype == "keywords":
                keywords = condition[2]
                group_results[group_name] = self._match_keywords(event, keywords)

            elif ctype == "fields":
                field_conditions = condition[2]
                group_results[group_name] = self._match_fields(event, field_conditions)

        if not group_results:
            return False

        condition_str = str(rule.detection.get("condition", ""))
        return self._evaluate_condition(condition_str, group_results)

    def _match_keywords(self, event: dict, keywords: List) -> bool:
        event_text = " ".join(str(v).lower() for v in event.values() if v)
        for kw in keywords:
            if isinstance(kw, str) and kw.lower() in event_text:
                return True
            elif isinstance(kw, list):
                if all(str(k).lower() in event_text for k in kw):
                    return True
        return False

    def _match_fields(self, event: dict, field_conditions: List) -> bool:
        for field_name, expected in field_conditions:
            actual = str(event.get(field_name, "")).lower()

            if isinstance(expected, list):
                if not any(self._value_match(actual, str(e)) for e in expected):
                    return False
            elif isinstance(expected, str):
                if not self._value_match(actual, expected):
                    return False
            elif isinstance(expected, bool):
                pass
        return True

    def _value_match(self, actual: str, expected: str) -> bool:
        expected_lower = expected.lower()

        if "*" in expected_lower or "?" in expected_lower:
            pattern = re.escape(expected_lower)
            pattern = pattern.replace(r"\*", ".*").replace(r"\?", ".")
            return bool(re.search(pattern, actual))

        if expected_lower.startswith("|contains|"):
            return expected_lower[10:] in actual
        if expected_lower.startswith("|startswith|"):
            return actual.startswith(expected_lower[12:])
        if expected_lower.startswith("|endswith|"):
            return actual.endswith(expected_lower[10:])

        return expected_lower in actual

    def _evaluate_condition(self, condition: str, results: Dict[str, bool]) -> bool:
        if not condition:
            return all(results.values())

        cond = condition.lower().strip()

        if cond in results:
            return results[cond]

        if "all of them" in cond:
            return all(results.values())

        if "1 of them" in cond or "any of them" in cond:
            return any(results.values())

        result = True
        op = "and"
        negate = False

        parts = re.split(r"\b(and|or|not)\b", cond)
        for part in parts:
            part = part.strip()
            if not part:
                continue

            if part == "and":
                op = "and"
                continue
            if part == "or":
                op = "or"
                continue
            if part == "not":
                negate = True
                continue

            if part in results:
                val = results[part]
                if negate:
                    val = not val
                    negate = False

                if op == "and":
                    result = result and val
                else:
                    result = result or val

        return result


class SigmaRuleLoader:
    """
    Sigma kurallarını disk veya GitHub'dan yükler.
    """

    RULE_SOURCES = [
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_sysinternals_psexec.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_net_user_add.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_whoami_execution.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_sc_create_service.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_susp_disable_av_tools.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_reg_add_run_key.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_net_recon.yml",
    ]

    BUILTIN_RULES = [
        {
            "title": "PowerShell Base64 Encoded Command",
            "id": "builtin-ps-base64",
            "status": "stable",
            "description": "Base64 encode edilmiş PowerShell komutu — malware imzası",
            "level": "high",
            "tags": ["attack.t1059.001", "attack.execution"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine": ["*-EncodedCommand*", "*-enc *", "*-e *"]},
                "condition": "selection",
            },
        },
        {
            "title": "Mimikatz Credential Dumping",
            "id": "builtin-mimikatz",
            "status": "stable",
            "description": "Mimikatz araç tespiti",
            "level": "critical",
            "tags": ["attack.t1003", "attack.credential_access"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "keywords": ["mimikatz", "sekurlsa", "lsadump", "kerberos::"],
                "condition": "keywords",
            },
        },
        {
            "title": "Net User Account Creation",
            "id": "builtin-net-user-add",
            "status": "stable",
            "description": "net user komutu ile yeni hesap oluşturma",
            "level": "high",
            "tags": ["attack.t1136", "attack.persistence"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine": ["*net user * /add*", "*net localgroup administrators*"]},
                "condition": "selection",
            },
        },
        {
            "title": "Scheduled Task Creation via Schtasks",
            "id": "builtin-schtasks",
            "status": "stable",
            "description": "schtasks ile kalıcılık kurma",
            "level": "medium",
            "tags": ["attack.t1053.005", "attack.persistence"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine": ["*schtasks*/create*", "*schtasks* /sc *"]},
                "condition": "selection",
            },
        },
        {
            "title": "PsExec Remote Execution",
            "id": "builtin-psexec",
            "status": "stable",
            "description": "PsExec ile uzak komut çalıştırma — lateral movement",
            "level": "high",
            "tags": ["attack.t1021.002", "attack.lateral_movement"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "keywords": ["psexec", "paexec", "\\admin$\\psexesvc"],
                "condition": "keywords",
            },
        },
        {
            "title": "Windows Defender Disabled",
            "id": "builtin-defender-disable",
            "status": "stable",
            "description": "Windows Defender devre dışı bırakma — defense evasion",
            "level": "high",
            "tags": ["attack.t1562.001", "attack.defense_evasion"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "keywords": ["DisableRealtimeMonitoring", "DisableAntiSpyware", "Set-MpPreference"],
                "condition": "keywords",
            },
        },
        {
            "title": "Registry Run Key Persistence",
            "id": "builtin-run-key",
            "status": "stable",
            "description": "Registry Run anahtarı ile kalıcılık",
            "level": "medium",
            "tags": ["attack.t1547.001", "attack.persistence"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "CommandLine": [
                        "*\\CurrentVersion\\Run*",
                        "*reg add*run*",
                        "*HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*",
                    ]
                },
                "condition": "selection",
            },
        },
        {
            "title": "WMI Remote Execution",
            "id": "builtin-wmi",
            "status": "stable",
            "description": "WMI ile uzak komut çalıştırma",
            "level": "high",
            "tags": ["attack.t1047", "attack.execution"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "keywords": ["wmiexec", "wmic * /node:", "Invoke-WmiMethod"],
                "condition": "keywords",
            },
        },
    ]

    def __init__(self, rules_dir: str = "sigma_rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(exist_ok=True)
        self.parser = SigmaParser()

    def load_local(self) -> List[SigmaRule]:
        rules = []
        for path in self.rules_dir.rglob("*.yml"):
            rule = self.parser.parse_file(path)
            if rule and rule.status in ("stable", "test"):
                rules.append(rule)
        logger.info("📄 [SIGMA] %d yerel kural yüklendi.", len(rules))
        return rules

    async def download_rules(self) -> int:
        downloaded = 0
        async with aiohttp.ClientSession() as session:
            for url in self.RULE_SOURCES:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            filename = url.split("/")[-1]
                            path = self.rules_dir / filename
                            path.write_text(content, encoding="utf-8")
                            downloaded += 1
                            logger.info("⬇️  [SIGMA] İndirildi: %s", filename)
                except Exception as e:
                    logger.debug("⚠️ [SIGMA] İndirme hatası %s: %s", url, e)
        logger.info("✅ [SIGMA] %d kural indirildi.", downloaded)
        return downloaded


class SigmaEngine:
    """
    Ana Sigma motoru.
    """

    def __init__(self, alert_callback=None, rules_dir: str = "sigma_rules"):
        self.rules: List[SigmaRule] = []
        self.matcher = SigmaMatcher()
        self.loader = SigmaRuleLoader(rules_dir)
        self.alert_callback = alert_callback
        self._suppress: Dict[str, datetime] = {}

    async def initialize(self):
        for rule_dict in self.loader.BUILTIN_RULES:
            rule = self.loader.parser.parse_dict(rule_dict)
            if rule:
                self.rules.append(rule)
        logger.info("📦 [SIGMA] %d yerleşik kural yüklendi.", len(self.rules))

        local = self.loader.load_local()
        existing_ids = {r.id for r in self.rules}
        for rule in local:
            if rule.id not in existing_ids:
                self.rules.append(rule)

        if not local:
            logger.info("🌐 [SIGMA] GitHub'dan ek kurallar indiriliyor...")
            try:
                await self.loader.download_rules()
                new_local = self.loader.load_local()
                for rule in new_local:
                    if rule.id not in {x.id for x in self.rules}:
                        self.rules.append(rule)
            except Exception as e:
                logger.warning("⚠️ [SIGMA] GitHub indirme başarısız, yerleşik kurallarla devam: %s", e)

        logger.info("✅ [SIGMA] Motor hazır. %d kural aktif.", len(self.rules))

    async def process_event(self, event: dict) -> list[dict]:
        """
        Gelen event'i tüm Sigma kurallarına karşı çalıştır.
        Dönüş: eşleşen Sigma alert dict listesi
        """
        matches: list[dict] = []

        for rule in self.rules:
            try:
                if self.matcher.match(event, rule):
                    alert = await self._emit(event, rule)
                    if alert:
                        matches.append(alert)
            except Exception as e:
                logger.debug("Kural çalıştırma hatası [%s]: %s", rule.title, e)

        return matches

    async def _emit(self, event: dict, rule: SigmaRule) -> dict | None:
        """Eşleşen kural için alarm üret, suppression uygula."""
        key = f"{rule.id}:{event.get('hostname', '')}:{event.get('user', '')}"
        now = datetime.utcnow()

        last = self._suppress.get(key)
        if last and (now - last).total_seconds() < 120:
            return None

        self._suppress[key] = now

        severity = rule.sol_severity()
        risk_score = {
            "CRITICAL": 90,
            "HIGH": 70,
            "MEDIUM": 50,
            "LOW": 30,
        }.get(severity, 70)

        alert = {
            "type": "SIGMA_ALERT",
            "rule": f"SIGMA:{rule.title}",
            "severity": severity,
            "description": f"[Sigma] {rule.title}",
            "hostname": event.get("hostname", "unknown"),
            "user": event.get("user", "unknown"),
            "details": f"Kural: {rule.title} | {rule.description[:200]}",
            "timestamp": now.isoformat() + "Z",
            "mitre": rule.mitre,
            "risk": {
                "score": risk_score,
                "level": severity,
            },
            "sigma_id": rule.id,
            "evidence": event,
        }

        logger.warning(
            "🎯 [SIGMA] Kural eşleşti: %s | %s | %s",
            rule.title,
            event.get("hostname"),
            event.get("user"),
        )

        if self.alert_callback:
            await self.alert_callback(alert)

        return alert

    async def update_rules(self) -> int:
        count = await self.loader.download_rules()
        self.rules = self.loader.load_local()
        logger.info("🔄 [SIGMA] Kurallar güncellendi. Aktif: %d", len(self.rules))
        return count

    def add_rule_from_yaml(self, yaml_str: str) -> bool:
        try:
            data = yaml.safe_load(yaml_str)
            rule = self.loader.parser.parse_dict(data)
            if rule:
                self.rules.append(rule)
                logger.info("✅ [SIGMA] Manuel kural eklendi: %s", rule.title)
                return True
        except Exception as e:
            logger.error("❌ [SIGMA] Manuel kural parse hatası: %s", e)
        return False

    def stats(self) -> dict:
        by_severity = {}
        for rule in self.rules:
            sev = rule.sol_severity()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {
            "total": len(self.rules),
            "by_severity": by_severity,
            "stable": sum(1 for r in self.rules if r.status == "stable"),
            "experimental": sum(1 for r in self.rules if r.status == "experimental"),
        }


_sigma_engine: Optional[SigmaEngine] = None


async def init_sigma(alert_callback, rules_dir: str = "sigma_rules") -> SigmaEngine:
    global _sigma_engine
    _sigma_engine = SigmaEngine(alert_callback=alert_callback, rules_dir=rules_dir)
    await _sigma_engine.initialize()
    return _sigma_engine


def get_sigma() -> Optional[SigmaEngine]:
    return _sigma_engine
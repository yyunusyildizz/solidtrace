from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp
import yaml

from app.detection.detection_policy import (
    NOISY_SIGMA_RULES,
    has_strong_attack_context,
    is_real_mimikatz,
    is_real_powershell_attack,
    is_sigma_generated_event,
    normalize_text,
)

logger = logging.getLogger("SolidTrace.Sigma")

ENABLE_RAW_SIGMA_CALLBACKS = os.getenv("ENABLE_RAW_SIGMA_CALLBACKS", "false").lower() == "true"

FIELD_MAP = {
    "Image": "details",
    "CommandLine": "command_line",
    "ParentImage": "details",
    "OriginalFileName": "details",
    "ProcessName": "details",
    "DestinationIp": "details",
    "DestinationPort": "details",
    "SourceIp": "details",
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "AccountName": "user",
    "ComputerName": "hostname",
    "Hostname": "hostname",
    "EventID": "type",
    "Channel": "type",
    "Provider_Name": "type",
    "TargetFilename": "details",
    "TargetObject": "details",
}

LOGSOURCE_MAP = {
    ("windows", "security", None): ["LOGON_SUCCESS", "LOGON_FAILURE", "PROCESS_CREATE_EVT", "SPECIAL_LOGON"],
    ("windows", "process_creation", None): ["PROCESS_CREATE_EVT", "PROCESS_CREATED", "PROCESS_START"],
    ("windows", "network_connection", None): ["NETWORK_CONNECTION"],
    ("windows", "file_event", None): ["FILE_ACTIVITY", "RANSOMWARE_ALERT"],
    ("windows", "registry_event", None): ["PERSISTENCE_DETECTED"],
    ("windows", "powershell", None): ["PROCESS_CREATED", "PROCESS_START"],
    ("windows", None, "system"): ["SERVICE_INSTALLED", "SCHTASK_CREATED"],
    ("windows", None, "security"): ["LOGON_FAILURE", "LOGON_SUCCESS", "SPECIAL_LOGON"],
}

EXTRA_BENIGN_MARKERS = [
    "rust-analyzer",
    "systemsettings.exe",
    "nvtmmon.exe",
    "rtkbtmanserv.exe",
    "installassistservice.exe",
    "immersivecontrolpanel",
]

TRUSTED_PATH_HINTS = [
    r"yol: c:\windows\\",
    r"yol: c:\program files\\",
    r"yol: c:\program files (x86)\\",
    r"c:\windows\\",
    r"c:\program files\\",
    r"c:\program files (x86)\\",
]

SUSPICIOUS_EXECUTION_HINTS = [
    "powershell",
    "cmd.exe",
    "wmic",
    "rundll32",
    "psexec",
    "paexec",
    "procdump",
    "mimikatz",
    "sekurlsa",
    "comsvcs.dll",
    "net.exe",
    "net user",
    "schtasks",
]


def _norm(*parts: object) -> str:
    return normalize_text(*parts)


def _contains_extra_benign(text: str) -> bool:
    t = _norm(text)
    return any(marker in t for marker in EXTRA_BENIGN_MARKERS)


def _looks_like_plain_path_event(text: str) -> bool:
    t = _norm(text)
    return t.startswith("yol: ") or t.startswith("yeni süreç:") or t.startswith("yeni surec:")


def _has_any_suspicious_execution_hint(text: str) -> bool:
    t = _norm(text)
    return any(token in t for token in SUSPICIOUS_EXECUTION_HINTS)


def _is_special_logon_noise(event_type: str, text: str) -> bool:
    t = _norm(text)
    return event_type == "SPECIAL_LOGON" and "eventid:4672" in t and "nt authority" in t and "system" in t


def should_suppress_sigma_event(*, rule_name: Optional[str], event_type: Optional[str], details: Optional[str], command_line: Optional[str]) -> bool:
    rule = str(rule_name or "").strip()
    et = str(event_type or "").upper()
    cmd = str(command_line or "").strip()
    text = _norm(details, command_line)

    if is_sigma_generated_event({"type": et, "rule": rule}):
        return True
    if not text:
        return True
    if _contains_extra_benign(text):
        return True
    if _is_special_logon_noise(et, text):
        return True
    if rule in NOISY_SIGMA_RULES and not cmd:
        return True
    if rule.endswith("Mimikatz Execution") and not is_real_mimikatz(text):
        return True
    if "PowerShell Download and Execution Cradles" in rule and not is_real_powershell_attack(text):
        return True
    if _looks_like_plain_path_event(text) and not _has_any_suspicious_execution_hint(text):
        return True
    if any(hint in text for hint in TRUSTED_PATH_HINTS) and not has_strong_attack_context(text):
        return True
    if et in {"PROCESS_START", "PROCESS_CREATED", "PROCESS_CREATE_EVT"}:
        if not cmd:
            return True
        if not _has_any_suspicious_execution_hint(text):
            return True
        if rule in NOISY_SIGMA_RULES and not has_strong_attack_context(text):
            return True
    if et in {"SPECIAL_LOGON", "LOGON_SUCCESS"} and rule in NOISY_SIGMA_RULES and not has_strong_attack_context(text):
        return True
    return False


@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    severity: str
    status: str
    tags: List[Dict]
    mitre: List[Dict]
    logsource: Dict
    detection: Dict
    conditions: List
    timeframe: Optional[int] = None
    count_threshold: Optional[int] = None

    def sol_severity(self) -> str:
        return {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}.get(self.severity.lower(), "MEDIUM")


class SigmaParser:
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
            tag = str(tag)
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
            tags=[],
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
    def match(self, event: dict, rule: SigmaRule) -> bool:
        if not rule.conditions:
            return False
        if not self._event_type_matches_logsource(event, rule.logsource):
            return False

        group_results = {}
        for condition in rule.conditions:
            ctype = condition[0]
            group_name = condition[1]
            if ctype == "keywords":
                group_results[group_name] = self._match_keywords(event, condition[2])
            elif ctype == "fields":
                group_results[group_name] = self._match_fields(event, condition[2])

        if not group_results:
            return False

        return self._evaluate_condition(str(rule.detection.get("condition", "")), group_results)

    def _event_type_matches_logsource(self, event: dict, logsource: dict) -> bool:
        product = (logsource.get("product") or "").lower() or None
        category = (logsource.get("category") or "").lower() or None
        service = (logsource.get("service") or "").lower() or None
        allowed = LOGSOURCE_MAP.get((product, category, service), None)
        if not allowed:
            return True
        return str(event.get("type") or "").upper() in {x.upper() for x in allowed}

    def _match_keywords(self, event: dict, keywords: List) -> bool:
        event_text = " ".join(str(v).lower() for v in event.values() if v)
        for kw in keywords:
            if isinstance(kw, str) and kw.lower() in event_text:
                return True
            if isinstance(kw, list) and all(str(k).lower() in event_text for k in kw):
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
        return True

    def _value_match(self, actual: str, expected: str) -> bool:
        expected_lower = expected.lower()
        if "*" in expected_lower or "?" in expected_lower:
            pattern = re.escape(expected_lower).replace(r"\*", ".*").replace(r"\?", ".")
            return bool(re.search(pattern, actual))
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
                result = (result and val) if op == "and" else (result or val)
        return result


class SigmaRuleLoader:
    RULE_SOURCES = [
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_sysinternals_psexec.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_net_user_add.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml",
        "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml",
    ]

    def __init__(self, rules_dir: str = "sigma_rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(exist_ok=True)
        self.parser = SigmaParser()

    def load_local(self) -> List[SigmaRule]:
        rules = []
        for path in list(self.rules_dir.glob("*.yml")) + list(self.rules_dir.glob("*.yaml")):
            rule = self.parser.parse_file(path)
            if rule:
                rules.append(rule)
        return rules

    async def update_rules(self) -> int:
        loaded = 0
        async with aiohttp.ClientSession() as session:
            for url in self.RULE_SOURCES:
                try:
                    async with session.get(url, timeout=10) as resp:
                        if resp.status != 200:
                            continue
                        text = await resp.text()
                        filename = url.rsplit("/", 1)[-1]
                        (self.rules_dir / filename).write_text(text, encoding="utf-8")
                        loaded += 1
                except Exception as exc:
                    logger.debug("Sigma rule download failed url=%s error=%s", url, exc)
        return loaded


class SigmaEngine:
    def __init__(self, alert_callback=None, rules_dir: str = "sigma_rules"):
        self.alert_callback = alert_callback
        self.loader = SigmaRuleLoader(rules_dir=rules_dir)
        self.matcher = SigmaMatcher()
        self.rules = self.loader.load_local()
        self._suppress: Dict[str, datetime] = {}
        logger.info("✅ [SIGMA] Motor hazır. %d kural aktif.", len(self.rules))

    async def process_event(self, event: dict) -> list[dict]:
        if is_sigma_generated_event(event):
            return []

        matches = []
        for rule in self.rules:
            try:
                if self.matcher.match(event, rule):
                    alert = await self._build_signal(event, rule)
                    if alert:
                        matches.append(alert)
            except Exception as exc:
                logger.debug("Sigma rule execution failed rule=%s error=%s", rule.title, exc)
        return matches

    async def _build_signal(self, event: dict, rule: SigmaRule) -> Optional[dict]:
        alert_rule_name = f"SIGMA:{rule.title}"
        command_line = str(event.get("command_line") or "").strip()
        details = str(event.get("details") or "").strip()

        if should_suppress_sigma_event(
            rule_name=alert_rule_name,
            event_type=event.get("type"),
            details=details,
            command_line=command_line,
        ):
            logger.info("sigma_suppressed rule=%s host=%s user=%s", alert_rule_name, event.get("hostname"), event.get("user"))
            return None

        key = f"{rule.id}:{event.get('hostname', '')}:{event.get('user', '')}:{alert_rule_name}"
        now = datetime.utcnow()
        last = self._suppress.get(key)
        if last and (now - last).total_seconds() < 180:
            return None
        self._suppress[key] = now

        severity = rule.sol_severity()
        risk_score = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 30}.get(severity, 70)

        signal = {
            "type": "SIGMA_SIGNAL",
            "rule": alert_rule_name,
            "severity": severity,
            "description": f"[Sigma] {rule.title}",
            "hostname": event.get("hostname", "unknown"),
            "user": event.get("user", "unknown"),
            "details": details,
            "command_line": command_line,
            "timestamp": now.isoformat() + "Z",
            "mitre": rule.mitre,
            "risk": {"score": risk_score, "level": severity},
            "sigma_id": rule.id,
            "evidence": event,
        }

        logger.warning("🎯 [SIGMA] Kural eşleşti: %s | %s | %s", rule.title, event.get("hostname"), event.get("user"))

        if ENABLE_RAW_SIGMA_CALLBACKS and self.alert_callback:
            await self.alert_callback(signal)

        return signal


_engine: Optional[SigmaEngine] = None


async def init_sigma(alert_callback=None) -> SigmaEngine:
    global _engine
    _engine = SigmaEngine(alert_callback=alert_callback)
    try:
        await _engine.loader.update_rules()
        _engine.rules = _engine.loader.load_local()
    except Exception as exc:
        logger.warning("Sigma rule update failed: %s", exc)
    logger.info("🎯 Sigma init tamam. Aktif kural sayısı=%s", len(_engine.rules))
    return _engine


def get_sigma() -> Optional[SigmaEngine]:
    return _engine

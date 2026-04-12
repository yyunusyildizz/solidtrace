from __future__ import annotations

import logging
import time
from typing import Iterable, Tuple, Optional

from app.database.db_manager import SessionLocal, RuleModel

logger = logging.getLogger("SolidTrace.RuleEngine")

EXECUTION_INDICATORS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "wmic",
    "procdump",
    "mimikatz",
    "psexec",
    "paexec",
]

STATIC_RULES = [
    {
        "name": "USB Device Activity",
        "severity": "HIGH",
        "risk_score": 90,
        "all_of": ["usb"],
        "any_of": [],
        "exclude": [],
        "require_process": [],
    },
    {
        "name": "Credential Dumping",
        "severity": "CRITICAL",
        "risk_score": 95,
        "all_of": [],
        "any_of": ["mimikatz", "sekurlsa", "procdump lsass", "lsass dump", "comsvcs.dll, minidump"],
        "exclude": [
            "installassistservice.exe",
            "audiodg.exe",
            "explorer.exe",
            "mscopilot_proxy.exe",
            "microsoftedgeupdate.exe",
            "7zfm.exe",
            "git-remote-https.exe",
            "notepad.exe",
            "smartscreen.exe",
            "python.exe",
            "uvicorn.exe",
            "pet.exe",
            "language_server_windows_x64.exe",
            "rtkbtmanserv.exe",
            "updater.exe",
            "easyduplicatefinder.exe",
        ],
        "require_process": ["powershell", "cmd.exe", "rundll32", "procdump", "mimikatz"],
    },
    {
        "name": "LSASS Access",
        "severity": "CRITICAL",
        "risk_score": 90,
        "all_of": ["lsass"],
        "any_of": ["procdump", "minidump", "sekurlsa", "readprocessmemory", "comsvcs.dll, minidump"],
        "exclude": [
            "audiodg.exe",
            "explorer.exe",
            "mscopilot_proxy.exe",
            "microsoftedgeupdate.exe",
            "7zfm.exe",
            "git-remote-https.exe",
            "notepad.exe",
            "smartscreen.exe",
            "python.exe",
            "uvicorn.exe",
            "pet.exe",
            "language_server_windows_x64.exe",
            "rtkbtmanserv.exe",
            "updater.exe",
            "easyduplicatefinder.exe",
        ],
        "require_process": ["powershell", "cmd.exe", "rundll32", "procdump"],
    },
    {
        "name": "Lateral Movement (PsExec)",
        "severity": "HIGH",
        "risk_score": 75,
        "all_of": [],
        "any_of": ["psexec", "paexec"],
        "exclude": [],
        "require_process": [],
    },
    {
        "name": "WMIC Remote Command Execution",
        "severity": "HIGH",
        "risk_score": 72,
        "all_of": ["wmic"],
        "any_of": ["process call create", "/node:", "remote"],
        "exclude": [],
        "require_process": [],
    },
    {
        "name": "PowerShell Download and Execution Cradles",
        "severity": "HIGH",
        "risk_score": 78,
        "all_of": ["powershell"],
        "any_of": ["invoke-webrequest", "downloadstring", "iex(", "invoke-expression", "frombase64string"],
        "exclude": [],
        "require_process": [],
    },
    {
        "name": "Ransomware Alert",
        "severity": "CRITICAL",
        "risk_score": 100,
        "all_of": [],
        "any_of": ["vssadmin delete shadows", "wbadmin delete catalog", "ransomware", "encrypting files"],
        "exclude": [],
        "require_process": [],
    },
]

_RULE_CACHE = []
_CACHE_EXPIRES_AT = 0.0
CACHE_TTL_SECONDS = 60.0


def _load_rules_from_db():
    db = SessionLocal()
    try:
        rules = db.query(RuleModel).all()
        logger.info("[RULE] DB'den %s rule yüklendi", len(rules))
        return rules
    finally:
        db.close()


def _get_rules():
    global _RULE_CACHE, _CACHE_EXPIRES_AT

    now = time.time()
    if _RULE_CACHE and _CACHE_EXPIRES_AT > now:
        return _RULE_CACHE

    try:
        _RULE_CACHE = _load_rules_from_db()
        _CACHE_EXPIRES_AT = now + CACHE_TTL_SECONDS
    except Exception as e:
        logger.error("[RULE] Cache refresh hatası: %s", e)
        if _RULE_CACHE:
            return _RULE_CACHE
        raise

    return _RULE_CACHE


def invalidate_rule_cache() -> None:
    global _CACHE_EXPIRES_AT
    _CACHE_EXPIRES_AT = 0.0
    logger.info("[RULE] Cache invalidated")


def _matches_static_rule(text: str, spec: dict) -> bool:
    all_of = spec.get("all_of") or []
    any_of = spec.get("any_of") or []
    exclude = spec.get("exclude") or []
    require_process = spec.get("require_process") or []

    if any(token in text for token in exclude):
        return False
    if all_of and not all(token in text for token in all_of):
        return False
    if any_of and not any(token in text for token in any_of):
        return False
    if require_process and not any(token in text for token in require_process):
        return False

    # Extra hardening: if this rule is driven by suspicious keywords,
    # require at least one real execution-context token to exist.
    if any_of and not any(proc in text for proc in EXECUTION_INDICATORS):
        return False

    if not all_of and not any_of:
        return False
    return True


def evaluate_rules(
    full_text: str,
    rules: Optional[Iterable] = None,
    default_sev: str = "INFO",
) -> Tuple[int, str, str, bool]:
    """
    Returns:
        score, rule_name, severity, matched
    """
    text = (full_text or "").lower()
    safe_default = (default_sev or "INFO").upper()

    active_rules = list(rules) if rules is not None else _get_rules()

    best_score = 0
    best_rule = "Normal Activity"
    best_sev = safe_default
    matched = False

    for rule in active_rules:
        keyword = (getattr(rule, "keyword", "") or "").strip().lower()
        if keyword and keyword in text:
            score = int(getattr(rule, "risk_score", 0) or 0)
            if score >= best_score:
                best_score = score
                best_rule = getattr(rule, "name", None) or "Custom Rule Match"
                best_sev = (getattr(rule, "severity", None) or safe_default).upper()
                matched = True

    for spec in STATIC_RULES:
        if _matches_static_rule(text, spec):
            score = int(spec["risk_score"])
            if score >= best_score:
                best_score = score
                best_rule = spec["name"]
                best_sev = spec["severity"]
                matched = True

    if not matched:
        return 10, "Normal Activity", safe_default, False

    return best_score, best_rule, best_sev, True

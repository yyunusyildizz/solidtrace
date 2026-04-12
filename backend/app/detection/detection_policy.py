from __future__ import annotations

from typing import Optional

BENIGN_PROCESS_MARKERS = [
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
    "solidtrace_agent.exe",
]

EXTRA_BENIGN_MARKERS = [
    "rust-analyzer",
    "systemsettings.exe",
    "nvtmmon.exe",
    "installassistservice.exe",
    "immersivecontrolpanel",
]

BENIGN_TEXT_MARKERS = BENIGN_PROCESS_MARKERS + EXTRA_BENIGN_MARKERS + [
    ".vscode",
    "codeium",
    "python-env",
    "node_modules",
]

TRUSTED_PATH_PREFIXES = [
    r"yol: c:\windows\\",
    r"yol: c:\program files\\",
    r"yol: c:\program files (x86)\\",
    r"c:\windows\\",
    r"c:\program files\\",
    r"c:\program files (x86)\\",
]

STRONG_ATTACK_COMBOS = [
    ("mimikatz", "sekurlsa"),
    ("mimikatz", "lsass"),
    ("procdump", "lsass"),
    ("comsvcs.dll", "minidump"),
    ("logonpasswords", "mimikatz"),
    ("powershell", "downloadstring"),
    ("powershell", "frombase64string"),
    ("powershell", "invoke-webrequest"),
    ("powershell", "-enc"),
    ("powershell", "iex("),
    ("powershell", "iex "),
    ("wmic", "process call create"),
    ("wmic", "/node:"),
    ("psexec", "cmd.exe"),
    ("net.exe", " user "),
    ("net user", "/add"),
    ("schtasks", "/create"),
]

NOISY_SIGMA_RULES = {
    "SIGMA:HackTool - Mimikatz Execution",
    "SIGMA:PowerShell Download and Execution Cradles",
    "SIGMA:WMIC Remote Command Execution",
    "SIGMA:New User Created Via Net.EXE",
}


def normalize_text(*parts: object) -> str:
    return " ".join(str(p or "") for p in parts if p).strip().lower()


def is_sigma_generated_event(event: dict) -> bool:
    rule = str(event.get("rule") or "")
    event_type = str(event.get("type") or "")
    return event_type == "SIGMA_ALERT" or rule.startswith("SIGMA:")


def is_benign_text(text: str) -> bool:
    t = normalize_text(text)
    return any(marker in t for marker in BENIGN_TEXT_MARKERS)


def is_trusted_path_text(text: str) -> bool:
    t = normalize_text(text)
    return any(prefix in t for prefix in TRUSTED_PATH_PREFIXES)


def has_strong_attack_context(text: str) -> bool:
    t = normalize_text(text)
    return any(all(token in t for token in combo) for combo in STRONG_ATTACK_COMBOS)


def is_real_mimikatz(text: str) -> bool:
    t = normalize_text(text)
    strong = [
        ("mimikatz", "sekurlsa"),
        ("mimikatz", "lsass"),
        ("procdump", "lsass"),
        ("comsvcs.dll", "minidump"),
        ("logonpasswords", "mimikatz"),
    ]
    return any(all(x in t for x in combo) for combo in strong)


def is_real_powershell_attack(text: str) -> bool:
    t = normalize_text(text)
    return any(x in t for x in [
        "-enc",
        "frombase64string",
        "downloadstring",
        "invoke-webrequest",
        "iex(",
        "iex ",
    ])


def is_special_logon_system_noise(text: str) -> bool:
    t = normalize_text(text)
    return "eventid:4672" in t and "nt authority" in t and "system" in t


def should_block_sigma_promotion(
    *,
    event_type: Optional[str],
    rule_name: Optional[str],
    text: str,
    command_line: Optional[str],
) -> bool:
    et = str(event_type or "").upper()
    rule = str(rule_name or "")
    cmd = str(command_line or "").strip()
    t = normalize_text(text)

    if is_sigma_generated_event({"type": et, "rule": rule}):
        return True

    if not t:
        return True

    if rule in NOISY_SIGMA_RULES:
        if not cmd:
            return True
        if is_benign_text(t):
            return True
        if rule.endswith("Mimikatz Execution") and not is_real_mimikatz(t):
            return True
        if "PowerShell Download and Execution Cradles" in rule and not is_real_powershell_attack(t):
            return True
        if et == "SPECIAL_LOGON" and is_special_logon_system_noise(t):
            return True
        if is_trusted_path_text(t) and not has_strong_attack_context(t):
            return True
        if et in {"PROCESS_START", "PROCESS_CREATED", "PROCESS_CREATE_EVT", "SPECIAL_LOGON", "LOGON_SUCCESS"}:
            if not has_strong_attack_context(t):
                return True

    return False

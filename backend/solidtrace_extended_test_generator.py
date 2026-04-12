#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

import requests


@dataclass
class Config:
    server: str
    agent_id: str
    agent_secret: str
    timeout: int
    verify_tls: bool
    signed: bool


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_request(agent_secret: str, method: str, path: str, body_obj: Any, agent_id: str) -> dict[str, str]:
    body_bytes = json.dumps(body_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    message = "\n".join(
        [
            method.upper(),
            path,
            sha256_hex(body_bytes),
            timestamp,
            nonce,
            agent_id,
        ]
    )
    signature = hmac.new(
        agent_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {
        "Content-Type": "application/json",
        "X-Agent-Id": agent_id,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature,
    }


def build_headers(cfg: Config, method: str, path: str, body_obj: Any) -> dict[str, str]:
    if cfg.signed:
        return sign_request(cfg.agent_secret, method, path, body_obj, cfg.agent_id)
    return {
        "Content-Type": "application/json",
        "X-Agent-Id": cfg.agent_id,
        "X-Agent-Key": cfg.agent_secret,
        "Authorization": f"Bearer {cfg.agent_secret}",
    }


def post_json(cfg: Config, path: str, payload: Any) -> requests.Response:
    url = cfg.server.rstrip("/") + path
    headers = build_headers(cfg, "POST", path, payload)
    return requests.post(
        url,
        headers=headers,
        data=json.dumps(payload, ensure_ascii=False),
        timeout=cfg.timeout,
        verify=cfg.verify_tls,
    )


def make_event(
    *,
    event_type: str,
    hostname: str,
    user: str,
    details: str,
    command_line: str = "",
    pid: int = 1000,
    severity: str = "INFO",
    serial: str = "",
) -> dict[str, Any]:
    return {
        "type": event_type,
        "hostname": hostname,
        "user": user,
        "details": details,
        "command_line": command_line,
        "pid": pid,
        "severity": severity,
        "serial": serial,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def benign_events(hostname: str, user: str) -> list[dict[str, Any]]:
    return [
        make_event(
            event_type="PROCESS_START",
            hostname=hostname,
            user=user,
            details=rf"C:\Windows\explorer.exe started normally",
            command_line=r"C:\Windows\explorer.exe",
            pid=4100,
            severity="INFO",
        ),
        make_event(
            event_type="PROCESS_START",
            hostname=hostname,
            user=user,
            details=rf"C:\Users\{user}\.vscode\extensions\rust-lang.rust-analyzer\server\rust-analyzer.exe",
            command_line=r"rust-analyzer.exe",
            pid=4101,
            severity="INFO",
        ),
        make_event(
            event_type="PROCESS_START",
            hostname=hostname,
            user=user,
            details=r"D:\Downloads\solidtrace-ultimate-main\.venv\Scripts\python.exe script.py",
            command_line=r"python.exe script.py",
            pid=4102,
            severity="INFO",
        ),
        make_event(
            event_type="SPECIAL_LOGON",
            hostname=hostname,
            user=r"NT AUTHORITY\SYSTEM",
            details=r"EventID:4672 Special privileges assigned to new logon for NT AUTHORITY\SYSTEM",
            command_line="",
            pid=4,
            severity="INFO",
        ),
    ]


def suspicious_execution_events(hostname: str, user: str) -> list[dict[str, Any]]:
    return [
        make_event(
            event_type="PROCESS_CREATE_EVT",
            hostname=hostname,
            user=user,
            details="wmic.exe /node:10.0.0.5 process call create cmd.exe /c whoami",
            command_line="wmic.exe /node:10.0.0.5 process call create cmd.exe /c whoami",
            pid=20002,
            severity="HIGH",
        ),
        make_event(
            event_type="PROCESS_CREATE_EVT",
            hostname=hostname,
            user=user,
            details="powershell.exe -nop -w hidden -enc SQBFAFgA",
            command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
            pid=20003,
            severity="HIGH",
        ),
        make_event(
            event_type="PROCESS_CREATE_EVT",
            hostname=hostname,
            user=user,
            details="rundll32.exe javascript:.. suspicious LOLBin execution",
            command_line="rundll32.exe javascript:.. suspicious LOLBin execution",
            pid=20004,
            severity="HIGH",
        ),
    ]


def credential_access_like_events(hostname: str, user: str) -> list[dict[str, Any]]:
    return [
        make_event(
            event_type="PROCESS_CREATE_EVT",
            hostname=hostname,
            user=user,
            details="powershell.exe sekurlsa::logonpasswords lsass dump simulation",
            command_line="powershell.exe sekurlsa::logonpasswords",
            pid=22001,
            severity="CRITICAL",
        ),
        make_event(
            event_type="PROCESS_CREATE_EVT",
            hostname=hostname,
            user=user,
            details=r"procdump.exe -ma lsass.exe C:\Temp\lsass.dmp",
            command_line=r"procdump.exe -ma lsass.exe C:\Temp\lsass.dmp",
            pid=22002,
            severity="CRITICAL",
        ),
    ]


def persistence_like_events(hostname: str, user: str) -> list[dict[str, Any]]:
    return [
        make_event(
            event_type="REGISTRY_MODIFIED",
            hostname=hostname,
            user=user,
            details=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater = C:\Users\Public\updater.exe",
            command_line="",
            pid=23001,
            severity="HIGH",
        ),
        make_event(
            event_type="TASK_CREATED",
            hostname=hostname,
            user=user,
            details=r"Scheduled task created: UpdaterTask => powershell.exe -nop -w hidden",
            command_line="powershell.exe -nop -w hidden",
            pid=23002,
            severity="HIGH",
        ),
    ]


def lateral_movement_like_events(hostname: str, user: str) -> list[dict[str, Any]]:
    return [
        make_event(
            event_type="PROCESS_CREATE_EVT",
            hostname=hostname,
            user=user,
            details=r"psexec.exe \\10.0.0.7 cmd.exe /c whoami",
            command_line=r"psexec.exe \\10.0.0.7 cmd.exe /c whoami",
            pid=24001,
            severity="HIGH",
        ),
        make_event(
            event_type="PROCESS_CREATE_EVT",
            hostname=hostname,
            user=user,
            details=r"wmiexec remote service execution against 10.0.0.9",
            command_line=r"wmiexec remote service execution against 10.0.0.9",
            pid=24002,
            severity="HIGH",
        ),
    ]


def eicar_file_hash() -> str:
    content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    return hashlib.sha256(content).hexdigest()


def hash_reports(hostname: str) -> list[dict[str, Any]]:
    return [
        {
            "hostname": hostname,
            "file_path": r"C:\Users\Public\eicar.com",
            "file_hash": eicar_file_hash(),
            "pid": 25001,
        },
        {
            "hostname": hostname,
            "file_path": r"C:\Users\Public\benign_demo.txt",
            "file_hash": hashlib.sha256(b"solidtrace benign sample").hexdigest(),
            "pid": 25002,
        },
    ]


def scenarios(hostname: str, user: str) -> dict[str, list[dict[str, Any]]]:
    return {
        "benign": benign_events(hostname, user),
        "suspicious": suspicious_execution_events(hostname, user),
        "credential": credential_access_like_events(hostname, user),
        "persistence": persistence_like_events(hostname, user),
        "lateral": lateral_movement_like_events(hostname, user),
    }


def send_events(cfg: Config, events: list[dict[str, Any]]) -> None:
    print(f"[+] Sending {len(events)} events to {cfg.server}/api/v1/ingest")
    resp = post_json(cfg, "/api/v1/ingest", events)
    print(f"[+] Status: {resp.status_code}")
    try:
        print(json.dumps(resp.json(), ensure_ascii=False, indent=2))
    except Exception:
        print(resp.text)


def send_hash_reports(cfg: Config, reports: list[dict[str, Any]]) -> None:
    for report in reports:
        print(f"[+] Reporting hash for {report['file_path']}")
        resp = post_json(cfg, "/api/v1/report_hash", report)
        print(f"[+] Status: {resp.status_code}")
        try:
            print(json.dumps(resp.json(), ensure_ascii=False, indent=2))
        except Exception:
            print(resp.text)


def run_suite(cfg: Config, hostname: str, user: str, selected: Iterable[str], include_hash: bool) -> None:
    all_scenarios = scenarios(hostname, user)
    for name in selected:
        print(f"\n=== Scenario: {name} ===")
        send_events(cfg, all_scenarios[name])
        print(expected_result(name))
    if include_hash:
        print("\n=== Scenario: hash_intel ===")
        send_hash_reports(cfg, hash_reports(hostname))
        print(expected_result("hash"))


def expected_result(name: str) -> str:
    expectations = {
        "benign": "\nExpected result:\n- explorer / rust-analyzer / python analyst-grade alert üretmemeli.\n- SPECIAL_LOGON 4672 by SYSTEM suppress edilmeli.\n",
        "suspicious": "\nExpected result:\n- WMIC / encoded PowerShell / LOLBin tarzı eventler sınırlı sayıda alert üretmeli.\n- Sigma spam flood olmamalı.\n",
        "credential": "\nExpected result:\n- Credential-access-like eventler HIGH/CRITICAL görünmeli.\n- Incident classification credential_access tarafına eğilmeli.\n",
        "persistence": "\nExpected result:\n- Run key / task benzeri eventler görünür olmalı ya da güvenli biçimde filtrelenmeli.\n",
        "lateral": "\nExpected result:\n- PsExec / remote execution pattern lateral movement veya malicious execution olarak işlenmeli.\n",
        "hash": "\nExpected result:\n- EICAR hash threat-intel akışını tetiklemeli.\n- Benign hash tek başına severe alert üretmemeli.\n",
    }
    return expectations.get(name, "")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SolidTrace extended synthetic test generator")
    parser.add_argument("--server", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--agent-secret", required=True)
    parser.add_argument("--hostname", default="DESKTOP-UI41CTM")
    parser.add_argument("--user", default="yunus")
    parser.add_argument("--mode", default="suite", choices=["suite", "benign", "suspicious", "credential", "persistence", "lateral", "hash"])
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--signed", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cfg = Config(
        server=args.server,
        agent_id=args.agent_id,
        agent_secret=args.agent_secret,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        signed=bool(args.signed),
    )

    if args.mode == "suite":
        run_suite(cfg, args.hostname, args.user, ["benign", "suspicious", "credential", "persistence", "lateral"], True)
        return 0

    if args.mode == "hash":
        send_hash_reports(cfg, hash_reports(args.hostname))
        print(expected_result("hash"))
        return 0

    run_suite(cfg, args.hostname, args.user, [args.mode], False)
    return 0


if __name__ == "__main__":
    sys.exit(main())

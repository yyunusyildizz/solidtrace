#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, List

import requests


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_request(agent_secret: str, method: str, path: str, body_obj: Any, agent_id: str) -> Dict[str, str]:
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
        "Authorization": f"SolidTrace-HMAC {signature}",
        "Content-Type": "application/json",
        "X-Agent-Id": agent_id,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
    }


def benign_events(hostname: str, user: str) -> List[Dict[str, Any]]:
    return [
        {
            "type": "PROCESS_START",
            "hostname": hostname,
            "user": user,
            "pid": 6764,
            "details": r"Yol: C:\Windows\ImmersiveControlPanel\SystemSettings.exe",
            "command_line": r"Yol: C:\Windows\ImmersiveControlPanel\SystemSettings.exe",
            "serial": "",
            "severity": "INFO",
        },
        {
            "type": "PROCESS_START",
            "hostname": hostname,
            "user": user,
            "pid": 5496,
            "details": r"Yol: C:\Windows\RtkBtManServ.exe",
            "command_line": r"Yol: C:\Windows\RtkBtManServ.exe",
            "serial": "",
            "severity": "INFO",
        },
        {
            "type": "PROCESS_CREATED",
            "hostname": hostname,
            "user": user,
            "pid": 13744,
            "details": "Yeni Süreç: NvTmMon.exe (PID: 13744)",
            "command_line": "Yeni Süreç: NvTmMon.exe (PID: 13744)",
            "serial": "",
            "severity": "INFO",
        },
        {
            "type": "SPECIAL_LOGON",
            "hostname": hostname,
            "user": user,
            "pid": 1000,
            "details": (
                "EventID:4672 | Özel ayrıcalıklarla oturum açma | Bilgisayar:DESKTOP-UI41CTM | "
                "Kullanıcı:N/A | Kanal:Security | Parametreler: Yeni oturuma özel ayrıcalıklar atandı. "
                "Konu: Hesap Adı:SYSTEM Hesap Etki Alanı:NT AUTHORITY"
            ),
            "command_line": (
                "EventID:4672 | Özel ayrıcalıklarla oturum açma | Bilgisayar:DESKTOP-UI41CTM | "
                "Kullanıcı:N/A | Kanal:Security | Parametreler: Yeni oturuma özel ayrıcalıklar atandı. "
                "Konu: Hesap Adı:SYSTEM Hesap Etki Alanı:NT AUTHORITY"
            ),
            "serial": "",
            "severity": "INFO",
        },
    ]


def suspicious_but_harmless_events(hostname: str, user: str) -> List[Dict[str, Any]]:
    return [
        {
            "type": "PROCESS_CREATE_EVT",
            "hostname": hostname,
            "user": user,
            "pid": 20001,
            "details": r"powershell.exe -nop -w hidden -enc SQBleAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwA=",
            "command_line": r"powershell.exe -nop -w hidden -enc SQBleAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwA=",
            "serial": "",
            "severity": "HIGH",
        },
        {
            "type": "PROCESS_CREATE_EVT",
            "hostname": hostname,
            "user": user,
            "pid": 20002,
            "details": r"wmic.exe /node:10.0.0.5 process call create cmd.exe /c whoami",
            "command_line": r"wmic.exe /node:10.0.0.5 process call create cmd.exe /c whoami",
            "serial": "",
            "severity": "HIGH",
        },
        {
            "type": "PROCESS_CREATE_EVT",
            "hostname": hostname,
            "user": user,
            "pid": 20003,
            "details": r"powershell.exe Invoke-Expression 'mimikatz sekurlsa::logonpasswords'",
            "command_line": r"powershell.exe Invoke-Expression 'mimikatz sekurlsa::logonpasswords'",
            "serial": "",
            "severity": "CRITICAL",
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--agent-secret", required=True)
    parser.add_argument("--hostname", default="DESKTOP-UI41CTM")
    parser.add_argument("--user", default="yunus")
    parser.add_argument("--mode", choices=["benign", "suspicious", "mixed"], default="mixed")
    args = parser.parse_args()

    path = "/api/v1/ingest"
    url = args.server.rstrip("/") + path

    if args.mode == "benign":
        events = benign_events(args.hostname, args.user)
    elif args.mode == "suspicious":
        events = suspicious_but_harmless_events(args.hostname, args.user)
    else:
        events = benign_events(args.hostname, args.user) + suspicious_but_harmless_events(args.hostname, args.user)

    headers = sign_request(args.agent_secret, "POST", path, events, args.agent_id)

    print(f"[+] Sending {len(events)} events to {url}")
    resp = requests.post(url, headers=headers, json=events, timeout=20)
    print(f"[+] Status: {resp.status_code}")
    try:
        print(json.dumps(resp.json(), ensure_ascii=False, indent=2))
    except Exception:
        print(resp.text)

    print("\nExpected result:")
    if args.mode in ("benign", "mixed"):
        print("- Benign process events should be suppressed or score very low.")
        print("- SPECIAL_LOGON 4672 / NT AUTHORITY SYSTEM should be suppressed.")
    if args.mode in ("suspicious", "mixed"):
        print("- Suspicious synthetic command_line strings may generate a small number of alerts.")
        print("- You should NOT see the old repeating 4x SIGMA spam pattern every cycle.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

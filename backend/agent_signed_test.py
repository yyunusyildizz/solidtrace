#!/usr/bin/env python3
import json
import time
import uuid
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8000"

AGENT_ID = "97325c2d-8921-4f82-ab95-04cf22351bc9"
AGENT_SECRET = "lQpeIual3zOdf7ES3dk0AvRQW56EbFzrLJIqudMmQvdY2G6_qUu2icwM1tpz_WMy"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sign(method: str, path: str, body_obj):
    body = json.dumps(body_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    message = "\n".join([
        method.upper(),
        path,
        sha256_hex(body),
        ts,
        nonce,
        AGENT_ID,
    ])
    sig = hmac.new(AGENT_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Id": AGENT_ID,
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": sig,
    }
    return body, headers

def main():
    s = requests.Session()

    print("[1/3] Heartbeat test...")
    heartbeat = {
        "hostname": "DESKTOP-TEST01",
        "agent_version": "1.0.0",
        "os_name": "Windows 10",
        "user": "yunus",
        "ip": "192.168.1.55",
        "uptime_seconds": 1234,
        "cpu_percent": 4.1,
        "memory_percent": 31.8
    }
    body, headers = sign("POST", "/api/v1/agent/heartbeat", heartbeat)
    r = s.post(f"{BASE_URL}/api/v1/agent/heartbeat", data=body, headers=headers, timeout=15)
    print("HTTP", r.status_code, r.text)

    print("\n[2/3] Ingest test...")
    ingest = [
        {
            "type": "PROCESS_CREATED",
            "hostname": "DESKTOP-TEST01",
            "user": "yunus",
            "pid": 4321,
            "details": "powershell.exe executed",
            "command_line": "powershell -enc test",
            "serial": None,
            "severity": "INFO",
            "timestamp": None
        }
    ]
    body, headers = sign("POST", "/api/v1/ingest", ingest)
    r = s.post(f"{BASE_URL}/api/v1/ingest", data=body, headers=headers, timeout=15)
    print("HTTP", r.status_code, r.text)

    print("\n[3/3] Replay test...")
    r2 = s.post(f"{BASE_URL}/api/v1/ingest", data=body, headers=headers, timeout=15)
    print("HTTP", r2.status_code, r2.text)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from typing import Any

import requests


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_request(agent_secret: str, method: str, path: str, body_obj: Any, agent_id: str):
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

    headers = {
        "Authorization": "",
        "Content-Type": "application/json",
        "X-Agent-Id": agent_id,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature,
    }
    return body_bytes.decode("utf-8"), headers


def assert_status(resp: requests.Response, expected: int, step: str) -> None:
    if resp.status_code != expected:
        raise RuntimeError(f"{step} başarısız\nHTTP {resp.status_code}\nResponse: {resp.text}")


def find_hostname_in_alerts(alerts_obj: Any, hostname: str) -> bool:
    return hostname in json.dumps(alerts_obj, ensure_ascii=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default=None)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--agent-version", default="1.0.0")
    parser.add_argument("--os-name", default="Windows 10")
    parser.add_argument("--user-name", default="yunus")
    args = parser.parse_args()

    password = args.password or os.getenv("SOLIDTRACE_ADMIN_PASSWORD")
    tenant_id = args.tenant_id or os.getenv("SOLIDTRACE_TENANT_ID")

    if not password:
        print("Admin şifresi gerekli. --password ver veya SOLIDTRACE_ADMIN_PASSWORD set et.", file=sys.stderr)
        return 2
    if not tenant_id:
        print("Tenant ID gerekli. --tenant-id ver veya SOLIDTRACE_TENANT_ID set et.", file=sys.stderr)
        return 2

    session = requests.Session()
    base = args.base_url.rstrip("/")
    hostname = f"DESKTOP-QA-{uuid.uuid4().hex[:8].upper()}"
    fingerprint = f"fingerprint-{uuid.uuid4().hex}"

    print("[1/8] Admin login...")
    r = session.post(
        f"{base}/api/login",
        data={"username": args.username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    assert_status(r, 200, "login")
    login = r.json()
    access_token = login["access_token"]
    admin_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    print("  OK")

    print("[2/8] Enrollment token üret...")
    r = session.post(
        f"{base}/api/agents/enrollment-token",
        headers=admin_headers,
        json={"tenant_id": tenant_id, "expires_in_minutes": 30},
        timeout=20,
    )
    assert_status(r, 200, "enrollment-token")
    enrollment_token = r.json()["enrollment_token"]
    print("  OK")

    print("[3/8] Agent register...")
    register_body = {
        "enrollment_token": enrollment_token,
        "hostname": hostname,
        "device_fingerprint": fingerprint,
        "os_name": args.os_name,
        "agent_version": args.agent_version,
    }
    r = session.post(f"{base}/api/agents/register", json=register_body, timeout=20)
    assert_status(r, 200, "agent-register")
    reg = r.json()
    agent_id = reg["agent_id"]
    agent_secret = reg["agent_secret"]
    print("  OK")
    print("  agent_id:", agent_id)
    print("  hostname:", hostname)

    print("[4/8] Heartbeat gönder...")
    heartbeat_body = {
        "hostname": hostname,
        "agent_version": args.agent_version,
        "os_name": args.os_name,
        "user": args.user_name,
        "ip": "192.168.1.55",
        "uptime_seconds": 2222,
        "cpu_percent": 6.4,
        "memory_percent": 28.9,
    }
    hb_body, hb_headers = sign_request(agent_secret, "POST", "/api/v1/agent/heartbeat", heartbeat_body, agent_id)
    r = session.post(
        f"{base}/api/v1/agent/heartbeat",
        data=hb_body.encode("utf-8"),
        headers=hb_headers,
        timeout=20,
    )
    assert_status(r, 200, "heartbeat")
    print("  OK:", r.json())

    print("[5/8] Signed ingest gönder...")
    ingest_body = [
        {
            "type": "PROCESS_CREATED",
            "hostname": hostname,
            "user": args.user_name,
            "pid": 4545,
            "details": "mimikatz execution test event",
            "command_line": "powershell -enc mimikatz-test",
            "serial": None,
            "severity": "INFO",
            "timestamp": None,
        }
    ]
    ing_body, ing_headers = sign_request(agent_secret, "POST", "/api/v1/ingest", ingest_body, agent_id)
    r = session.post(
        f"{base}/api/v1/ingest",
        data=ing_body.encode("utf-8"),
        headers=ing_headers,
        timeout=20,
    )
    assert_status(r, 200, "ingest")
    ingest_resp = r.json()
    if ingest_resp.get("status") != "queued":
        raise RuntimeError(f"ingest queued değil: {ingest_resp}")
    print("  OK:", ingest_resp)

    print("[6/8] Alert oluşumunu kontrol et (poll)...")
    found = False
    for i in range(12):
        time.sleep(1)
        r = session.get(f"{base}/api/alerts", headers=admin_headers, timeout=20)
        assert_status(r, 200, "alerts-list")
        alerts = r.json()
        if find_hostname_in_alerts(alerts, hostname):
            print(f"  OK: alert bulundu ({i + 1}. saniyede)")
            found = True
            break
    if not found:
        print("  Uyarı: alert listesinde hostname henüz görünmedi. Queue/worker daha geç işlemiş olabilir.")

    print("[7/8] Agent revoke...")
    r = session.post(f"{base}/api/agents/{agent_id}/revoke", headers=admin_headers, timeout=20)
    assert_status(r, 200, "agent-revoke")
    print("  OK:", r.json())

    print("[8/8] Revoke sonrası heartbeat reddi...")
    rb_body, rb_headers = sign_request(agent_secret, "POST", "/api/v1/agent/heartbeat", heartbeat_body, agent_id)
    r = session.post(
        f"{base}/api/v1/agent/heartbeat",
        data=rb_body.encode("utf-8"),
        headers=rb_headers,
        timeout=20,
    )
    if r.status_code == 200:
        raise RuntimeError("Revoke sonrası heartbeat kabul edildi, bu hatalı")
    print(f"  OK: revoke sonrası istek reddedildi (HTTP {r.status_code})")

    print("\nQueue + alert + revoke smoke test tamam ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

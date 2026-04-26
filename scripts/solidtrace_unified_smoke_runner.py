#!/usr/bin/env python3
"""
SolidTrace Unified Smoke Runner
===============================

Mevcut smoke/generator scriptlerini tek komuttan çalıştırır.

Varsayılan güvenli mod:
- dashboard_visibility_smoke_test.py
- alert_assignment_smoke_test.py

Opsiyonel:
- --response        unisolate_test.py çalıştırır.
- --agent-lifecycle solidtrace_queue_alert_test.py çalıştırır.
- --synthetic       solidtrace_extended_test_generator.py çalıştırır.
- --full            response hariç güvenli geniş seti çalıştırır.

Gerekli env:
PowerShell:
  $env:SOLIDTRACE_ADMIN_PASSWORD="GucluSifre123!"
  $env:SOLIDTRACE_TENANT_ID="default_tenant"

Synthetic için ayrıca:
  $env:SOLIDTRACE_AGENT_ID="..."
  $env:SOLIDTRACE_AGENT_SECRET="..."
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] if Path(__file__).resolve().parent.name == "scripts" else Path.cwd()


def find_script(name: str) -> Path | None:
    candidates = [
        ROOT / name,
        ROOT / "backend" / name,
        ROOT / "scripts" / name,
        ROOT / "scripts" / "smoke" / name,
        ROOT / "scripts" / "generators" / name,
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def run_cmd(label: str, cmd: list[str], cwd: Path | None = None, required: bool = True) -> bool:
    print("\n" + "=" * 72)
    print(f"▶ {label}")
    print("=" * 72)
    print(" ".join(cmd))

    result = subprocess.run(cmd, cwd=str(cwd or ROOT), text=True)

    if result.returncode == 0:
        print(f"✅ {label} geçti")
        return True

    print(f"❌ {label} başarısız. exit_code={result.returncode}")
    if required:
        raise SystemExit(result.returncode)
    return False


def require_password() -> str:
    password = os.getenv("SOLIDTRACE_ADMIN_PASSWORD", "")
    if not password:
        print("❌ SOLIDTRACE_ADMIN_PASSWORD boş.")
        print('PowerShell: $env:SOLIDTRACE_ADMIN_PASSWORD="GERCEK_ADMIN_SIFREN"')
        raise SystemExit(2)
    return password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.getenv("SOLIDTRACE_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--username", default=os.getenv("SOLIDTRACE_ADMIN_USER", "admin"))
    parser.add_argument("--tenant-id", default=os.getenv("SOLIDTRACE_TENANT_ID", "default_tenant"))
    parser.add_argument("--hostname", default=os.getenv("SOLIDTRACE_TEST_HOST", "DESKTOP-UI41CTM"))
    parser.add_argument("--user", default=os.getenv("SOLIDTRACE_TEST_USER", "yunus"))
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--response", action="store_true")
    parser.add_argument("--agent-lifecycle", action="store_true")
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    password = require_password()

    print("SolidTrace Unified Smoke Runner")
    print(f"ROOT      : {ROOT}")
    print(f"BASE_URL  : {args.base_url}")
    print(f"USERNAME  : {args.username}")
    print(f"TENANT_ID : {args.tenant_id}")
    print(f"HOSTNAME  : {args.hostname}")

    # 1) Dashboard visibility
    dashboard = find_script("dashboard_visibility_smoke_test.py")
    if dashboard:
        run_cmd(
            "Dashboard visibility smoke",
            [
                sys.executable,
                str(dashboard),
                "--base-url",
                args.base_url,
                "--username",
                args.username,
                "--password",
                password,
            ],
        )
    else:
        print("⚠️ dashboard_visibility_smoke_test.py bulunamadı, atlandı.")

    # 2) Alert workflow
    alert_workflow = find_script("alert_assignment_smoke_test.py")
    if alert_workflow:
        run_cmd(
            "Alert assignment/workflow smoke",
            [
                sys.executable,
                str(alert_workflow),
                "--base-url",
                args.base_url,
                "--username",
                args.username,
                "--password",
                password,
            ],
        )
    else:
        print("⚠️ alert_assignment_smoke_test.py bulunamadı, atlandı.")

    # 3) Optional response action: unisolate
    if args.response:
        unisolate = find_script("unisolate_test.py")
        if unisolate:
            run_cmd("Response smoke: unisolate", [sys.executable, str(unisolate)])
        else:
            print("⚠️ unisolate_test.py bulunamadı, atlandı.")

    # 4) Optional agent lifecycle
    if args.full or args.agent_lifecycle:
        queue = find_script("solidtrace_queue_alert_test.py")
        if queue:
            run_cmd(
                "Agent lifecycle + queue + alert + revoke smoke",
                [
                    sys.executable,
                    str(queue),
                    "--base-url",
                    args.base_url,
                    "--username",
                    args.username,
                    "--password",
                    password,
                    "--tenant-id",
                    args.tenant_id,
                    "--user-name",
                    args.user,
                ],
            )
        else:
            print("⚠️ solidtrace_queue_alert_test.py bulunamadı, atlandı.")

    # 5) Optional synthetic generator
    if args.full or args.synthetic:
        generator = find_script("solidtrace_extended_test_generator.py")
        agent_id = os.getenv("SOLIDTRACE_AGENT_ID", "")
        agent_secret = os.getenv("SOLIDTRACE_AGENT_SECRET", "")

        if not generator:
            print("⚠️ solidtrace_extended_test_generator.py bulunamadı, atlandı.")
        elif not agent_id or not agent_secret:
            print("⚠️ SOLIDTRACE_AGENT_ID / SOLIDTRACE_AGENT_SECRET boş. Synthetic test atlandı.")
        else:
            run_cmd(
                "Synthetic detection scenario generator",
                [
                    sys.executable,
                    str(generator),
                    "--server",
                    args.base_url,
                    "--agent-id",
                    agent_id,
                    "--agent-secret",
                    agent_secret,
                    "--hostname",
                    args.hostname,
                    "--user",
                    args.user,
                    "--mode",
                    "suite",
                    "--signed",
                ],
                required=False,
            )

    # 6) Optional builds/checks
    if not args.skip_build:
        frontend = ROOT / "frontend"
        agent = ROOT / "agent_rust"

        if frontend.exists():
            run_cmd("Frontend build", ["npm", "run", "build"], cwd=frontend, required=False)

        if agent.exists():
            run_cmd("Rust agent check", ["cargo", "check"], cwd=agent, required=False)

    print("\n✅ Unified smoke runner tamamlandı")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

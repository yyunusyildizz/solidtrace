#!/usr/bin/env python3
"""
Case Preview Smoke Test
========================

POST /api/cases/preview endpoint'ini smoke test eder.
Login → alerts fetch → hostname grouping → case preview → doğrulama.

Kullanım:
    python case_preview_smoke_test.py --password GucluSifre123!
    python case_preview_smoke_test.py --base-url http://127.0.0.1:8000 --password SIFRE
"""

import argparse
from collections import Counter

import requests


MAX_HOST_ALERTS = 30
FALLBACK_ALERT_COUNT = 10


def assert_status(resp, expected, step):
    if resp.status_code != expected:
        raise RuntimeError(
            f"{step} başarısız\nHTTP {resp.status_code}\nResponse: {resp.text}"
        )


def admin_login(base_url: str, username: str, password: str, timeout: int) -> str:
    r = requests.post(
        f"{base_url}/api/login",
        data={"username": username, "password": password},
        timeout=timeout,
    )
    assert_status(r, 200, "admin login")

    data = r.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"access_token alınamadı. Response: {data}")
    return token


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    timeout = args.timeout

    # --- Step 1/8: Login ---
    print("[1/8] Admin login...")
    token = admin_login(base_url, args.username, args.password, timeout)
    headers = auth_headers(token)
    print("  OK")

    # --- Step 2/8: Alerts fetch + grouping ---
    print("[2/8] Alerts fetch + hostname grouping...")
    r = requests.get(
        f"{base_url}/api/alerts?limit=100",
        headers=headers,
        timeout=timeout,
    )
    assert_status(r, 200, "alerts fetch")
    alerts = r.json()
    assert isinstance(alerts, list), f"alerts list değil: {type(alerts)}"
    assert len(alerts) >= 1, "DB'de en az 1 alert olmalı"

    host_counts = Counter(
        a.get("hostname") for a in alerts if a.get("hostname")
    )
    if host_counts:
        top_host = host_counts.most_common(1)[0][0]
        selected = [a for a in alerts if a.get("hostname") == top_host][
            :MAX_HOST_ALERTS
        ]
        print(f"  top_host: {top_host} ({len(selected)} alerts)")
    else:
        selected = alerts[:FALLBACK_ALERT_COUNT]
        print(f"  hostname yok, fallback: ilk {len(selected)} alert")
    print("  OK")

    # --- Step 3/8: Case preview — full request ---
    print("[3/8] Case preview — include_graph=true, consolidate=true...")
    payload = {
        "source_type": "alerts",
        "items": selected,
        "include_graph": True,
        "consolidate": True,
    }
    r = requests.post(
        f"{base_url}/api/cases/preview",
        json=payload,
        headers=headers,
        timeout=timeout,
    )
    assert_status(r, 200, "case preview")
    data = r.json()

    assert isinstance(data.get("case_drafts"), list), "case_drafts list değil"
    assert isinstance(data.get("attack_stories"), list), "attack_stories list değil"
    assert isinstance(data.get("story_graphs"), list), "story_graphs list değil"
    assert isinstance(data.get("summary"), dict), "summary dict değil"
    assert isinstance(data.get("warnings"), list), "warnings list değil"
    assert len(data["case_drafts"]) >= 1, "case_drafts boş"
    print(f"  case_drafts: {len(data['case_drafts'])}")
    print(f"  attack_stories: {len(data['attack_stories'])}")
    print(f"  story_graphs: {len(data['story_graphs'])}")
    print("  OK")

    # --- Step 4/8: Summary doğrulama ---
    print("[4/8] Summary doğrulama...")
    summary = data["summary"]
    assert summary["total_case_drafts"] == len(data["case_drafts"]), (
        f"total_case_drafts mismatch: {summary['total_case_drafts']} != {len(data['case_drafts'])}"
    )
    assert summary["total_stories"] == len(data["attack_stories"]), (
        f"total_stories mismatch: {summary['total_stories']} != {len(data['attack_stories'])}"
    )
    assert summary["total_graphs"] == len(data["story_graphs"]), (
        f"total_graphs mismatch: {summary['total_graphs']} != {len(data['story_graphs'])}"
    )
    print(f"  total_case_drafts : {summary['total_case_drafts']}")
    print(f"  total_stories     : {summary['total_stories']}")
    print(f"  total_graphs      : {summary['total_graphs']}")
    print(f"  highest_severity  : {summary.get('highest_severity', '?')}")
    print(f"  max_risk_score    : {summary.get('max_risk_score', '?')}")
    print("  OK")

    # --- Step 5/8: İlk CaseDraft doğrulama ---
    print("[5/8] İlk CaseDraft required fields...")
    cd = data["case_drafts"][0]

    assert cd.get("id"), "id boş"
    assert cd.get("title"), "title boş"
    assert cd.get("severity"), "severity boş"
    assert isinstance(cd.get("risk_score"), (int, float)), "risk_score int değil"
    assert cd.get("priority"), "priority boş"
    assert cd.get("status"), "status boş"
    assert isinstance(cd.get("affected_hosts"), list), "affected_hosts list değil"
    assert isinstance(cd.get("related_alert_ids"), list), "related_alert_ids list değil"
    assert isinstance(cd.get("evidence_items"), list), "evidence_items list değil"
    assert isinstance(cd.get("recommended_actions"), list), "recommended_actions list değil"
    assert isinstance(cd.get("tags"), list), "tags list değil"
    assert isinstance(cd.get("timeline_items"), list), "timeline_items list değil"
    assert cd.get("created_at"), "created_at boş"

    print(f"  id       : {cd['id'][:12]}...")
    print(f"  title    : {cd['title'][:60]}")
    print(f"  severity : {cd['severity']}")
    print(f"  risk     : {cd['risk_score']}")
    print(f"  priority : {cd['priority']}")
    print(f"  evidence : {len(cd['evidence_items'])} items")
    print(f"  timeline : {len(cd['timeline_items'])} items")
    print(f"  actions  : {len(cd['recommended_actions'])} items")
    print(f"  tags     : {cd['tags']}")
    print("  OK")

    # --- Step 6/8: include_graph=false varyasyonu ---
    print("[6/8] Case preview — include_graph=false...")
    payload_no_graph = {
        "source_type": "alerts",
        "items": selected,
        "include_graph": False,
        "consolidate": True,
    }
    r = requests.post(
        f"{base_url}/api/cases/preview",
        json=payload_no_graph,
        headers=headers,
        timeout=timeout,
    )
    assert_status(r, 200, "case preview (no graph)")
    data_ng = r.json()

    assert data_ng["story_graphs"] == [], f"story_graphs boş olmalı: {len(data_ng['story_graphs'])}"
    assert data_ng["summary"]["total_graphs"] == 0, "total_graphs 0 olmalı"
    assert len(data_ng["case_drafts"]) >= 1, "case_drafts boş (no graph)"
    print(f"  story_graphs: [] ✓")
    print(f"  case_drafts : {len(data_ng['case_drafts'])}")
    print("  OK")

    # --- Step 7/8: Empty input ---
    print("[7/8] Empty input — items=[]...")
    payload_empty = {
        "source_type": "alerts",
        "items": [],
    }
    r = requests.post(
        f"{base_url}/api/cases/preview",
        json=payload_empty,
        headers=headers,
        timeout=timeout,
    )
    assert_status(r, 200, "case preview (empty)")
    data_empty = r.json()

    assert data_empty["case_drafts"] == [], "case_drafts boş olmalı"
    assert data_empty["summary"]["total_case_drafts"] == 0, "total_case_drafts 0 olmalı"
    print("  case_drafts: [] ✓")
    print("  OK")

    # --- Step 8/8: Unsupported source_type ---
    print("[8/8] Unsupported source_type — 400 bekleniyor...")
    payload_bad = {
        "source_type": "invalid_type",
        "items": [{"foo": "bar"}],
    }
    r = requests.post(
        f"{base_url}/api/cases/preview",
        json=payload_bad,
        headers=headers,
        timeout=timeout,
    )
    assert_status(r, 400, "unsupported source_type")
    print("  HTTP 400 ✓")
    print("  OK")

    print("\nCase preview smoke test tamam ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

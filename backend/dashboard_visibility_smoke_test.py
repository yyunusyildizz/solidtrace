import argparse
import requests


def assert_status(resp, expected, step):
    if resp.status_code != expected:
        raise RuntimeError(
            f"{step} başarısız\nHTTP {resp.status_code}\nResponse: {resp.text}"
        )


def admin_login(base_url: str, username: str, password: str) -> str:
    r = requests.post(
        f"{base_url}/api/login",
        data={"username": username, "password": password},
        timeout=20,
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
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    print("[1/5] Admin login...")
    token = admin_login(base_url, args.username, args.password)
    headers = auth_headers(token)
    print("  OK")

    print("[2/5] Dashboard summary...")
    r = requests.get(
        f"{base_url}/api/dashboard/summary",
        headers=headers,
        timeout=20,
    )
    assert_status(r, 200, "dashboard summary")
    summary = r.json()
    print("  OK")
    print("   total_alerts   :", summary.get("total_alerts"))
    print("   critical_alerts:", summary.get("critical_alerts"))
    print("   total_assets   :", summary.get("total_assets"))
    print("   online_assets  :", summary.get("online_assets"))
    print("   top_hosts      :", len(summary.get("top_hosts", [])))
    print("   top_rules      :", len(summary.get("top_rules", [])))
    print("   latest_alerts  :", len(summary.get("latest_alerts", [])))

    print("[3/5] Recent activity...")
    r = requests.get(
        f"{base_url}/api/dashboard/recent-activity?limit=20",
        headers=headers,
        timeout=20,
    )
    assert_status(r, 200, "recent activity")
    recent = r.json()
    print("  OK")
    print("   recent_activity_count:", len(recent))
    if recent:
        print("   first_activity_type  :", recent[0].get("activity_type"))
        print("   first_title          :", recent[0].get("title"))

    print("[4/5] Sigma stats...")
    r = requests.get(
        f"{base_url}/api/v1/sigma/stats",
        headers=headers,
        timeout=20,
    )
    assert_status(r, 200, "sigma stats")
    sigma = r.json()
    print("  OK")
    print("   total_matches   :", sigma.get("total_matches"))
    print("   matches_last_24h:", sigma.get("matches_last_24h"))
    print("   engine_status   :", sigma.get("engine_status"))
    print("   top_rules       :", len(sigma.get("top_rules", [])))

    print("[5/5] UEBA profiles...")
    r = requests.get(
        f"{base_url}/api/v1/ueba/profiles",
        headers=headers,
        timeout=20,
    )
    assert_status(r, 200, "ueba profiles")
    ueba = r.json()
    print("  OK")
    print("   profile_count      :", ueba.get("profile_count"))
    print("   risky_profile_count:", ueba.get("risky_profile_count"))
    print("   baseline_ready     :", ueba.get("baseline_ready"))
    print("   profiles           :", len(ueba.get("profiles", [])))

    print("\nDashboard visibility smoke test tamam ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
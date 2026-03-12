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
        timeout=15,
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
    parser.add_argument("--assign-to", default="analyst")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    print("[1/9] Admin login...")
    token = admin_login(base_url, args.username, args.password)
    headers = auth_headers(token)
    print("  OK")

    print("[2/9] Alert listesi al...")
    r = requests.get(
        f"{base_url}/api/alerts?limit=20",
        headers=headers,
        timeout=15,
    )
    assert_status(r, 200, "alert list")
    alerts = r.json()
    if not alerts:
        raise RuntimeError("Hiç alert bulunamadı. Önce ingest ile bir alert üret.")
    alert = alerts[0]
    alert_id = alert["id"]
    print(f"  OK: alert_id={alert_id}")

    print("[3/9] Alert assign...")
    r = requests.patch(
        f"{base_url}/api/alerts/{alert_id}/assign",
        headers=headers,
        json={"assigned_to": args.assign_to},
        timeout=15,
    )
    assert_status(r, 200, "alert assign")
    print(f"  OK: {r.json()}")

    print("[4/9] Alert detail doğrula...")
    r = requests.get(
        f"{base_url}/api/alerts/{alert_id}",
        headers=headers,
        timeout=15,
    )
    assert_status(r, 200, "alert detail")
    detail = r.json()
    if detail.get("assigned_to") != args.assign_to:
        raise RuntimeError(
            f"assigned_to beklenen gibi değil: {detail.get('assigned_to')}"
        )
    print("  OK")

    print("[5/9] Alert note update...")
    r = requests.patch(
        f"{base_url}/api/alerts/{alert_id}/note",
        headers=headers,
        json={"note": "Smoke test note update"},
        timeout=15,
    )
    assert_status(r, 200, "alert note update")
    print(f"  OK: {r.json()}")

    print("[6/9] Alert resolve...")
    r = requests.patch(
        f"{base_url}/api/alerts/{alert_id}/resolve",
        headers=headers,
        json={"note": "Smoke test resolve"},
        timeout=15,
    )
    assert_status(r, 200, "alert resolve")
    print(f"  OK: {r.json()}")

    print("[7/9] Alert unassign...")
    r = requests.patch(
        f"{base_url}/api/alerts/{alert_id}/unassign",
        headers=headers,
        timeout=15,
    )
    assert_status(r, 200, "alert unassign")
    print(f"  OK: {r.json()}")

    print("[8/9] Alert reopen...")
    r = requests.patch(
        f"{base_url}/api/alerts/{alert_id}/reopen",
        headers=headers,
        timeout=15,
    )
    assert_status(r, 200, "alert reopen")
    print(f"  OK: {r.json()}")

    print("[9/9] Final detail kontrol...")
    r = requests.get(
        f"{base_url}/api/alerts/{alert_id}",
        headers=headers,
        timeout=15,
    )
    assert_status(r, 200, "final alert detail")
    final_detail = r.json()

    print("  status     :", final_detail.get("status"))
    print("  assigned_to:", final_detail.get("assigned_to"))
    print("  note       :", final_detail.get("analyst_note"))

    print("\nAlert assignment smoke test tamam ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
import requests
import sys

BASE_URL = "http://127.0.0.1:8000"
USERNAME = "admin"
PASSWORD = "GucluSifre123!"
HOSTNAME = "DESKTOP-UI41CTM"


def login() -> str:
    resp = requests.post(
        f"{BASE_URL}/api/login",
        data={
            "username": USERNAME,
            "password": PASSWORD,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"Login başarılı ama access_token dönmedi: {data}")
    return token


def isolate_host(token: str) -> dict:
    resp = requests.post(
        f"{BASE_URL}/api/actions/isolate",
        json={
            "hostname": HOSTNAME,
            "rule": "manual isolate smoke test",
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    try:
        print(f"[+] Login deneniyor: {USERNAME}")
        token = login()
        print("[+] Access token alındı")

        print(f"[!] Ağ izolasyonu gönderiliyor: {HOSTNAME}")
        result = isolate_host(token)

        print("[+] Sonuç:")
        print(result)
        print("\n[!] command_id değerini not et ve hemen unisolate scriptini hazır tut.")
    except Exception as exc:
        print(f"[X] Hata: {exc}")
        sys.exit(1)
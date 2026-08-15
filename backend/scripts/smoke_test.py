#!/usr/bin/env python
"""End-to-end API smoke test for CyberSentinel X.

Exercises: login -> dashboard -> simulate -> alerts -> incident ->
investigation -> attack graph -> risk -> recommendations -> approval ->
report -> PDF. Requires the backend to be running on BASE_URL.
"""
import sys
import time

import httpx

BASE = "http://127.0.0.1:8000"
PASS = 0
FAIL = 0


def check(name: str, condition: bool, extra: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {name} {extra}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} {extra}")


def main() -> int:
    client = httpx.Client(base_url=BASE, timeout=60)

    print("== Health ==")
    r = client.get("/health")
    check("GET /health", r.status_code == 200 and r.json().get("status") == "ok")
    r = client.get("/ready")
    check("GET /ready", r.status_code == 200 and r.json().get("database") == "connected")

    print("== Auth ==")
    r = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "Admin@2026"})
    check("login", r.status_code == 200, f"({r.status_code})")
    if r.status_code != 200:
        print(r.text)
        return 1
    tokens = r.json()["tokens"]
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    r = client.get("/api/auth/me", headers=headers)
    check("GET /api/auth/me", r.status_code == 200 and r.json()["email"] == "admin@cybersentinel.io")

    r = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "wrong-pass"})
    check("login rejects bad password", r.status_code == 401)

    print("== Dashboard ==")
    r = client.get("/api/dashboard/summary", headers=headers)
    check("GET /api/dashboard/summary", r.status_code == 200 and len(r.json()["kpis"]) == 6, f"({r.status_code})")

    print("== Events ==")
    r = client.get("/api/events", headers=headers, params={"page_size": 5})
    check("GET /api/events", r.status_code == 200 and r.json()["total"] >= 1, f"total={r.json().get('total')}")

    print("== Simulation ==")
    r = client.post("/api/simulations/account-takeover", headers=headers)
    check("simulate account-takeover", r.status_code == 200, f"({r.status_code}) {r.text[:200]}")
    sim = r.json()
    incident_ref = sim.get("incident_id")
    check("simulation created incident", bool(incident_ref), str(sim.get("message", "")))

    r = client.post("/api/simulations/brute-force", headers=headers)
    check("simulate brute-force", r.status_code == 200, f"({r.status_code})")
    r = client.post("/api/simulations/data-exfiltration", headers=headers)
    check("simulate data-exfiltration", r.status_code == 200, f"({r.status_code})")
    r = client.post("/api/simulations/malware", headers=headers)
    check("simulate malware", r.status_code == 200, f"({r.status_code})")
    r = client.post("/api/simulations/privilege-escalation", headers=headers)
    check("simulate privilege-escalation", r.status_code == 200, f"({r.status_code})")
    r = client.post("/api/simulations/unknown", headers=headers)
    check("unknown scenario rejected", r.status_code == 404)

    print("== Alerts / Incidents ==")
    r = client.get("/api/alerts", headers=headers)
    check("GET /api/alerts", r.status_code == 200 and r.json()["total"] >= 1, f"total={r.json().get('total')}")

    # Resolve the UUID id of the newest incident for detail endpoints
    r = client.get("/api/incidents", headers=headers)
    check("GET /api/incidents", r.status_code == 200 and r.json()["total"] >= 1, f"total={r.json().get('total')}")
    items = r.json().get("items", [])
    incident_id = None
    for it in items:
        if it.get("incident_id") == incident_ref:
            incident_id = it["id"]
            break
    if not incident_id and items:
        incident_id = items[0]["id"]
    check("resolved incident uuid", incident_id is not None)

    print("== Pipeline (waiting for agents) ==")
    investigation = None
    for _ in range(30):
        time.sleep(2)
        r = client.get(f"/api/investigations/{incident_id}", headers=headers)
        if r.status_code == 200:
            investigation = r.json()
            if investigation["investigation"]["status"] == "COMPLETED":
                break
    check("investigation completed", investigation is not None
          and investigation["investigation"]["status"] == "COMPLETED",
          f"status={investigation['investigation']['status'] if investigation else 'missing'}")

    r = client.get(f"/api/attack-graph/{incident_id}", headers=headers)
    check("attack graph", r.status_code == 200 and len(r.json()["nodes"]) >= 4,
          f"nodes={len(r.json().get('nodes', []))}")

    r = client.get(f"/api/risk/{incident_id}", headers=headers)
    check("risk score", r.status_code == 200 and 0 <= r.json()["score"] <= 100, f"score={r.json().get('score')}")

    r = client.get(f"/api/response-recommendations/{incident_id}", headers=headers)
    recs = r.json() if r.status_code == 200 else []
    check("recommendations", len(recs) >= 1, f"count={len(recs)}")

    r = client.get("/api/approvals", headers=headers, params={"status": "PENDING"})
    approvals = r.json()
    check("pending approvals", r.status_code == 200 and len(approvals) >= 1, f"count={len(approvals)}")

    print("== Approval flow ==")
    approved_any = False
    for a in approvals[:2]:
        r = client.post(f"/api/approvals/{a['id']}/approve", headers=headers, json={"reason": "Smoke test"})
        if r.status_code == 200:
            approved_any = True
            check(f"approve {a['recommendation_action'][:20]}...", True, f"status={r.json()['status']}")
        else:
            check(f"approve {a.get('recommendation_action', 'action')}", False, r.text[:120])
    check("at least one approval executed", approved_any)

    print("== Reports ==")
    r = client.post(f"/api/reports/{incident_id}/generate", headers=headers)
    check("generate report", r.status_code == 200, f"({r.status_code}) {r.text[:150]}")
    report = r.json() if r.status_code == 200 else {}
    report_id = report.get("report", {}).get("id")
    check("report has pdf", report.get("pdf_available") is True)
    if report_id:
        r = client.get(f"/api/reports/{report_id}/pdf", headers=headers)
        check("download pdf", r.status_code == 200 and r.headers.get("content-type", "").startswith("application/pdf"),
              f"({r.status_code})")

    print("== Threat intel ==")
    r = client.post("/api/threat-intelligence/search", headers=headers,
                    json={"query": "45.155.205.233"})
    check("threat intel search", r.status_code == 200 and len(r.json()["hits"]) >= 1, f"hits={len(r.json().get('hits', []))}")
    r = client.get("/api/threat-intelligence/mitre", headers=headers)
    check("mitre list", r.status_code == 200 and len(r.json()) >= 40, f"count={len(r.json())}")

    print("== Analytics & Actions ==")
    r = client.get("/api/analytics", headers=headers)
    check("analytics", r.status_code == 200 and r.json()["events_total"] >= 1)
    r = client.get("/api/actions-log", headers=headers)
    check("actions log", r.status_code == 200 and r.json()["total"] >= 1)

    print("== RBAC ==")
    r = client.post("/api/auth/login", json={"email": "viewer@cybersentinel.io", "password": "Viewer@2026"})
    viewer_headers = {"Authorization": f"Bearer {r.json()['tokens']['access_token']}"}
    r = client.post("/api/simulations/brute-force", headers=viewer_headers)
    check("viewer blocked from simulations", r.status_code == 403, f"({r.status_code})")
    r = client.get("/api/dashboard/summary", headers=viewer_headers)
    check("viewer can read dashboard", r.status_code == 200)

    print(f"\n===== SMOKE TEST: {PASS} passed, {FAIL} failed =====")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

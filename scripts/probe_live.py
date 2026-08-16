"""Probe the live Render backend: warm it up, login, and check endpoints.

Usage: python scripts/probe_live.py [--paths a,b,c] [--timeout 120]
"""
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "https://cybersentinel-backend-t5pv.onrender.com"
DEFAULT_PATHS = [
    "/api/dashboard/summary",
    "/api/dashboard/threat-space",
    "/api/dashboard/attack-distribution",
    "/api/dashboard/events-timeseries",
    "/api/analytics/judge-mode",
    "/api/campaigns/command-center",
    "/api/security/firewall",
    "/api/security/firewall/blocks",
    "/api/ueba/entity/ip/103.75.190.12",
    "/api/evidence/ledger",
    "/api/sbom",
    "/api/predictions",
    "/api/attack-dna",
    "/api/reports",
    "/api/alerts",
    "/api/incidents",
    "/api/malware/scan-dataset?limit=10",
    "/api/dataset/uploads",
    "/api/analytics/feedback-stats",
    "/api/ueba/profiles",
    "/api/approvals",
    "/api/actions-log",
]


def call(path, method="GET", payload=None, token=None, timeout=120):
    headers = {}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers=headers,
        method=method,
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200], time.time() - t0
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:150], time.time() - t0


def wait_until_up(attempts=20, sleep=15):
    for i in range(attempts):
        s, b, _ = call("/health", timeout=45)
        if s == 200:
            print(f"[warm] /health 200 after {i + 1} tries")
            return True
        print(f"[warm] try {i + 1}: {s} — waiting {sleep}s")
        time.sleep(sleep)
    return False


def login(max_tries=8):
    for i in range(max_tries):
        s, body, _ = call(
            "/api/auth/login",
            "POST",
            {"email": "admin@cybersentinel.io", "password": "Admin@2026"},
            timeout=90,
        )
        if s == 200:
            try:
                tok = json.loads(body).get("tokens", {}).get("access_token")
            except json.JSONDecodeError:
                # body was truncated for display; re-login without truncation
                req = urllib.request.Request(
                    BASE + "/api/auth/login",
                    data=json.dumps({"email": "admin@cybersentinel.io", "password": "Admin@2026"}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=90) as r:
                    tok = json.loads(r.read().decode()).get("tokens", {}).get("access_token")
            print(f"[login] ok (try {i + 1})")
            return tok
        print(f"[login] try {i + 1}: {s} — waiting 20s")
        time.sleep(20)
    return None


def main():
    paths = DEFAULT_PATHS
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        paths = args[0].split(",")

    if not wait_until_up():
        print("Backend never came up; aborting.")
        return 1
    tok = login()
    if not tok:
        print("Login failed after retries; aborting.")
        return 1

    fails = []
    for p in paths:
        s, b, dt = call(p, token=tok)
        ok = "OK" if s == 200 else f"!! {s}"
        print(f"{ok:8} {dt:6.1f}s  {p}")
        if s != 200:
            fails.append(p)
            if b:
                print("        ", b[:250])
    print("\nFAILURES:", fails if fails else "none")
    return 0 if not fails else 2


if __name__ == "__main__":
    sys.exit(main())

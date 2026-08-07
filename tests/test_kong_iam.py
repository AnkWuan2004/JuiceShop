#!/usr/bin/env python3
"""
Tuần 2 — Proof đầy đủ Agent IAM qua Kong.
Chạy: docker compose up -d  rồi  python tests/test_kong_iam.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))

try:
    import requests
except ImportError:
    print("[!] Cần: pip install requests")
    sys.exit(1)

KONG = "http://localhost:8000"
RECON_KEY = "recon-key-demo"
EXPLOIT_KEY = "exploit-key-demo"


def check(name: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    return ok


def main() -> int:
    print("[*] Test Kong IAM (localhost:8000)\n")
    passed = 0
    total = 0

    # 1) No key → 401
    total += 1
    try:
        r = requests.get(f"{KONG}/rest/products/search?q=apple", timeout=10)
        if check("GET không key → 401", r.status_code == 401, f"got {r.status_code}"):
            passed += 1
    except requests.RequestException as e:
        check("GET không key → 401", False, str(e))

    # 2) Recon GET → 2xx
    total += 1
    try:
        r = requests.get(
            f"{KONG}/rest/products/search?q=apple",
            headers={"apikey": RECON_KEY},
            timeout=10,
        )
        if check("Recon GET products → 2xx", 200 <= r.status_code < 300, f"got {r.status_code}"):
            passed += 1
    except requests.RequestException as e:
        check("Recon GET products → 2xx", False, str(e))

    # 3) Recon POST → 403 (ACL method)
    total += 1
    try:
        r = requests.post(
            f"{KONG}/api/Users",
            headers={"apikey": RECON_KEY, "Content-Type": "application/json"},
            json={"email": "recon@test.local", "password": "x", "passwordRepeat": "x"},
            timeout=10,
        )
        if check("Recon POST /api/Users → 403", r.status_code == 403, f"got {r.status_code}"):
            passed += 1
    except requests.RequestException as e:
        check("Recon POST /api/Users → 403", False, str(e))

    # 4) Exploit POST → không bị Kong 401/403
    total += 1
    try:
        r = requests.post(
            f"{KONG}/api/Users",
            headers={"apikey": EXPLOIT_KEY, "Content-Type": "application/json"},
            json={"email": "exploit-demo@test.local", "password": "x", "passwordRepeat": "x"},
            timeout=10,
        )
        ok = r.status_code not in (401, 403)
        if check("Exploit POST /api/Users → không 401/403 Kong", ok, f"got {r.status_code}"):
            passed += 1
    except requests.RequestException as e:
        check("Exploit POST /api/Users → không 401/403 Kong", False, str(e))

    # 5) Path deny: /rest/admin (recon)
    total += 1
    try:
        r = requests.get(
            f"{KONG}/rest/admin/application-configuration",
            headers={"apikey": RECON_KEY},
            timeout=10,
        )
        if check("Recon GET /rest/admin → 403 path deny", r.status_code == 403, f"got {r.status_code}"):
            passed += 1
    except requests.RequestException as e:
        check("Recon GET /rest/admin → 403 path deny", False, str(e))

    # 6) Path deny: /rest/admin (exploit cũng bị chặn)
    total += 1
    try:
        r = requests.get(
            f"{KONG}/rest/admin/application-configuration",
            headers={"apikey": EXPLOIT_KEY},
            timeout=10,
        )
        if check("Exploit GET /rest/admin → 403 path deny", r.status_code == 403, f"got {r.status_code}"):
            passed += 1
    except requests.RequestException as e:
        check("Exploit GET /rest/admin → 403 path deny", False, str(e))

    # 7) Client allowlist (Python tool) chặn trước khi gọi
    total += 1
    try:
        from kong_http_tool import kong_request

        try:
            kong_request("recon-agent", "POST", "/api/Users", json_body={})
            check("Tool deny recon POST (client)", False, "expected PermissionError")
        except PermissionError as e:
            if check("Tool deny recon POST (client)", "denied" in str(e).lower() or "method" in str(e).lower(), str(e)):
                passed += 1
    except Exception as e:
        check("Tool deny recon POST (client)", False, str(e))

    print(f"\n[*] Kết quả: {passed}/{total} PASS")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

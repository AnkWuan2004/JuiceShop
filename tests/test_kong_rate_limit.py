#!/usr/bin/env python3
"""
Tuần 2 — Proof rate-limit trên write route (exploit POST).
Chạy sau compose up. Kỳ vọng: một số request cuối → 429.
"""
from __future__ import annotations

import sys

try:
    import requests
except ImportError:
    print("[!] Cần: pip install requests")
    sys.exit(1)

KONG = "http://localhost:8000"
KEY = "exploit-key-demo"


def main() -> int:
    print("[*] Burst POST qua Kong (limit ~20/phút trên write)\n")
    codes: list[int] = []
    for i in range(25):
        try:
            r = requests.post(
                f"{KONG}/api/Users",
                headers={"apikey": KEY, "Content-Type": "application/json"},
                json={"email": f"rl{i}@test.local", "password": "x", "passwordRepeat": "x"},
                timeout=10,
            )
            codes.append(r.status_code)
            print(f"  #{i+1:02d} → {r.status_code}")
        except requests.RequestException as e:
            print(f"  #{i+1:02d} → ERR {e}")
            return 1

    has_429 = 429 in codes
    print(f"\n[*] Có 429: {has_429} (counts={ {c: codes.count(c) for c in sorted(set(codes))} })")
    if has_429:
        print("[PASS] Rate-limit hoạt động")
        return 0
    print("[FAIL] Không thấy 429 — kiểm tra kong.yml rate-limiting / đợi hết cửa sổ phút")
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Tuần 4 — Proof rate-limit trên read route (recon GET), khép lỗ hổng: trước đây chỉ
route write (POST) có rate-limiting, route read (GET) không giới hạn/phút.
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
KEY = "recon-key-demo"


def main() -> int:
    print("[*] Burst GET qua Kong (limit ~60/phút trên read)\n")
    codes: list[int] = []
    for i in range(65):
        try:
            r = requests.get(
                f"{KONG}/rest/products/search",
                headers={"apikey": KEY},
                params={"q": "apple"},
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
        print("[PASS] Rate-limit read hoạt động")
        return 0
    print("[FAIL] Không thấy 429 — kiểm tra kong.yml rate-limiting / đợi hết cửa sổ phút")
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Che dữ liệu nhạy cảm trước khi gửi tới LLM hoặc ghi log:
email / phone / SSN / token (Bearer, JWT) / API key / password.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# US-ish phone
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
# SSN-like ###-##-####
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# JWT: header.payload.signature (base64url x3)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
# Authorization: Bearer <token>
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-_.=]+")
# key: value / key=value cho token / api key / password (giá trị không chứa khoảng trắng)
TOKEN_KV_RE = re.compile(r"(?i)\btoken\s*[:=]\s*[\"']?[A-Za-z0-9\-_.]{6,}[\"']?")
APIKEY_KV_RE = re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*[\"']?[A-Za-z0-9\-_.]{6,}[\"']?")
APIKEY_PREFIX_RE = re.compile(r"\bsk-[A-Za-z0-9]{10,}\b")
PASSWORD_KV_RE = re.compile(r"(?i)\bpassword\s*[:=]\s*[\"']?\S+")


def redact(text: str) -> str:
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)
    text = SSN_RE.sub("[REDACTED_SSN]", text)
    text = JWT_RE.sub("[REDACTED_TOKEN]", text)
    text = BEARER_RE.sub("[REDACTED_TOKEN]", text)
    text = TOKEN_KV_RE.sub("[REDACTED_TOKEN]", text)
    text = APIKEY_PREFIX_RE.sub("[REDACTED_APIKEY]", text)
    text = APIKEY_KV_RE.sub("[REDACTED_APIKEY]", text)
    text = PASSWORD_KV_RE.sub("[REDACTED_PASSWORD]", text)
    return text


def redact_file(src: Path, dst: Path) -> None:
    raw = src.read_text(encoding="utf-8", errors="replace")
    dst.write_text(redact(raw), encoding="utf-8")


def demo() -> None:
    sample = (
        "User jane.doe@juiceshop.local phone 555-123-4567 SSN 123-45-6789 "
        "bought Apple Juice. Authorization: Bearer sk-abc123def456xyz "
        "api_key=abcd1234efgh5678 password=Sup3rSecret!"
    )
    after = redact(sample)
    print("BEFORE:", sample)
    print("AFTER: ", after)
    lake = Path(__file__).resolve().parent.parent / "data-lake"
    lake.mkdir(parents=True, exist_ok=True)
    (lake / "pii_before.txt").write_text(sample + "\n", encoding="utf-8")
    (lake / "pii_after.txt").write_text(after + "\n", encoding="utf-8")
    print(f"[+] Wrote {lake / 'pii_before.txt'} and pii_after.txt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--in", dest="infile", type=Path)
    parser.add_argument("--out", dest="outfile", type=Path)
    args = parser.parse_args()
    if args.demo or not args.infile:
        demo()
    else:
        out = args.outfile or args.infile.with_suffix(args.infile.suffix + ".redacted")
        redact_file(args.infile, out)
        print(f"[+] {args.infile} → {out}")

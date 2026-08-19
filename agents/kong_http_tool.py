#!/usr/bin/env python3
"""
Tuần 2/4 — Python HTTP tool gửi request an toàn qua Kong.
- Chỉ localhost
- Allowlist method/path theo agent (kong/allowlist.json)
- Timeout + cắt response
- Log KHÔNG ghi apikey (redact)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST_PATH = ROOT / "kong" / "allowlist.json"
LOG_PATH = ROOT / "data-lake" / "request_log.jsonl"

try:
    import requests
except ImportError:
    print("[!] Cần: pip install requests", file=sys.stderr)
    sys.exit(1)

# Payload an toàn (PDF tuần 4) — không phá hoại
SAFE_BODIES = {
    "empty": {},
    "long": {"q": "A" * 500},
    "special": {"q": "'\"<>&%"},
    "wrong_type": {"q": ["not", "a", "string"]},
}


def load_allowlist() -> dict:
    return json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))


def redact(text: str, secrets: list[str]) -> str:
    out = text
    for s in secrets:
        if s:
            out = out.replace(s, "***REDACTED***")
    # header-style
    out = re.sub(r"(?i)(apikey[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", r"\1***REDACTED***", out)
    return out


def resolve_key(agent_cfg: dict) -> str:
    env_name = agent_cfg.get("apikey_env") or ""
    return os.environ.get(env_name) or agent_cfg.get("default_key") or ""


def check_policy(agent: str, method: str, path: str, allowlist: dict) -> None:
    agents = allowlist.get("agents") or {}
    if agent not in agents:
        raise PermissionError(f"unknown agent: {agent}")
    cfg = agents[agent]
    method_u = method.upper()
    if method_u not in [m.upper() for m in cfg.get("methods") or []]:
        raise PermissionError(f"method {method_u} denied for {agent}")
    for deny in cfg.get("path_deny_prefixes") or []:
        if path.startswith(deny):
            raise PermissionError(f"path denied: {path} (prefix {deny})")
    prefixes = cfg.get("path_prefixes") or []
    if not any(path.startswith(p) for p in prefixes):
        raise PermissionError(f"path not in allowlist: {path}")


def append_log(entry: dict, secrets: list[str]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(entry, ensure_ascii=False)
    safe = redact(raw, secrets)
    # đảm bảo không còn key thô
    for s in secrets:
        if s and s in safe:
            safe = safe.replace(s, "***REDACTED***")
    # Tuần 5: che thêm PII chung (email/phone/token/apikey/password) có thể
    # xuất hiện trong response body thật (vd. profile user Juice Shop).
    try:
        from pii_redaction import redact as redact_pii

        safe = redact_pii(safe)
    except Exception:
        pass
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(safe + "\n")


def kong_request(
    agent: str,
    method: str,
    path: str,
    *,
    json_body: Any | None = None,
    allowlist: dict | None = None,
) -> dict:
    al = allowlist or load_allowlist()
    base = (al.get("gateway_base") or "http://localhost:8000").rstrip("/")
    host = urlparse(base).hostname or ""
    if host not in (al.get("allowed_hosts") or ["localhost", "127.0.0.1"]):
        raise PermissionError(f"host not allowed: {host}")

    path = path if path.startswith("/") else "/" + path
    check_policy(agent, method, path, al)

    cfg = al["agents"][agent]
    key = resolve_key(cfg)
    limits = al.get("limits") or {}
    timeout = float(limits.get("timeout_seconds") or 10)
    max_bytes = int(limits.get("max_response_bytes") or 4096)

    url = base + path
    headers = {"apikey": key, "Content-Type": "application/json"}
    try:
        r = requests.request(
            method.upper(),
            url,
            headers=headers,
            json=json_body,
            timeout=timeout,
        )
        body = r.text[:max_bytes]
        truncated = len(r.text) > max_bytes
        result = {
            "ok": True,
            "agent": agent,
            "method": method.upper(),
            "path": path,
            "status": r.status_code,
            "truncated": truncated,
            "body_preview": body,
            "error": None,
            "at": datetime.now(timezone.utc).isoformat(),
        }
    except requests.Timeout:
        result = {
            "ok": False,
            "agent": agent,
            "method": method.upper(),
            "path": path,
            "status": None,
            "truncated": False,
            "body_preview": "",
            "error": "timeout",
            "at": datetime.now(timezone.utc).isoformat(),
        }
    except requests.RequestException as e:
        result = {
            "ok": False,
            "agent": agent,
            "method": method.upper(),
            "path": path,
            "status": None,
            "truncated": False,
            "body_preview": "",
            "error": f"connection: {e.__class__.__name__}",
            "at": datetime.now(timezone.utc).isoformat(),
        }

    append_log(result, secrets=[key])
    return result


def main() -> int:
    p = argparse.ArgumentParser(description="Safe HTTP via Kong (Agent IAM)")
    p.add_argument("--agent", choices=["recon-agent", "exploit-agent"], default="recon-agent")
    p.add_argument("--method", default="GET")
    p.add_argument("--path", default="/rest/products/search?q=apple")
    p.add_argument("--body", choices=list(SAFE_BODIES.keys()), default=None, help="POST body an toàn có sẵn")
    p.add_argument("--json", default=None, help="JSON body thô (chỉ khi --body không dùng)")
    args = p.parse_args()

    body = None
    if args.method.upper() in ("POST", "PUT", "PATCH"):
        if args.body:
            body = SAFE_BODIES[args.body]
        elif args.json:
            body = json.loads(args.json)
        else:
            body = SAFE_BODIES["empty"]

    try:
        result = kong_request(args.agent, args.method, args.path, json_body=body)
    except PermissionError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False, indent=2))
        return 2

    # In ra đã redact
    printable = json.loads(redact(json.dumps(result), [resolve_key(load_allowlist()["agents"][args.agent])]))
    print(json.dumps(printable, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

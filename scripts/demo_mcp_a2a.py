#!/usr/bin/env python3
"""
Tuần 2 — Demo MCP + A2A (chạy nhanh, không cần Docker).
Usage:
  python agents/mcp_server.py          # terminal 1
  python scripts/demo_mcp_a2a.py       # terminal 2
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))

from a2a import append_a2a, wrap  # noqa: E402
from mcp_client import MCPClient  # noqa: E402


def main() -> int:
    print("[*] MCP + A2A demo\n")
    try:
        c = MCPClient(timeout=3.0)
        tools = c.list_tools()
    except Exception as e:
        print(f"[FAIL] MCP không chạy: {e}")
        print("       Chạy: python agents/mcp_server.py")
        return 1

    names = [t["name"] for t in tools]
    print(f"  [PASS] tools/list → {names}")

    scan = c.call("get_scan_results", {"limit": 3})
    ok_scan = bool(scan.get("ok")) or "results" in scan
    print(f"  [{'PASS' if ok_scan else 'FAIL'}] tools/call get_scan_results → count={scan.get('count', 'n/a')}")

    # Unknown tool = fail closed ở tầng tool IAM
    unknown = c.call("run_shell", {})
    denied = unknown.get("ok") is False or "unknown" in str(unknown.get("error", "")).lower()
    print(f"  [{'PASS' if denied else 'FAIL'}] tools/call run_shell → denied ({unknown.get('error')})")

    env = wrap(
        "supervisor",
        "recon-agent",
        "week2_demo",
        {"note": "A2A envelope demo", "tools": names},
    )
    path = append_a2a(env)
    print(f"  [PASS] A2A append → {path}")
    print(f"         messageId={env['messageId']}")

    out = ROOT / "data-lake" / "week2_mcp_a2a_demo.json"
    out.write_text(
        json.dumps({"tools": names, "scan_ok": ok_scan, "unknown_denied": denied, "a2a": env}, indent=2),
        encoding="utf-8",
    )
    print(f"\n[*] Evidence: {out}")
    return 0 if ok_scan and denied else 1


if __name__ == "__main__":
    sys.exit(main())

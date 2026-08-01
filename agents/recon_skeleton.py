#!/usr/bin/env python3
"""
Tuần 4 skeleton — Recon đọc data lake qua MCP → draft Attack Surface Map.
Không cần LLM. Chạy MCP server trước (hoặc fallback SQLite).
  python agents/recon_skeleton.py
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))
DB = ROOT / "data-lake" / "vuln_data.db"
OUT = ROOT / "data-lake" / "attack_surface_map.draft.json"

PATH_RE = re.compile(r"(/(?:api|rest|ftp)/[a-zA-Z0-9_\-./{}]*)")


def load_vulns(limit: int = 50) -> list[dict]:
    try:
        from mcp_client import try_mcp_call

        mcp = try_mcp_call("get_scan_results", {"limit": limit})
        if mcp and mcp.get("results") is not None:
            return list(mcp["results"])
    except Exception:
        pass
    if not DB.exists():
        return []
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT tool, severity, name, description, path_or_url FROM vulnerabilities "
        "ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def guess_path(row: dict) -> str | None:
    raw = (row.get("path_or_url") or "") + " " + (row.get("name") or "")
    m = PATH_RE.search(raw.replace("\\", "/"))
    if m:
        return m.group(1).split("?")[0]
    lower = raw.lower()
    if "search" in lower:
        return "/rest/products/search"
    if "login" in lower:
        return "/rest/user/login"
    if "feedback" in lower:
        return "/api/Feedbacks"
    return None


def build_map(vulns: list[dict]) -> dict:
    by_path: dict[str, list] = defaultdict(list)
    for v in vulns:
        p = guess_path(v) or "/unknown"
        by_path[p].append(
            {
                "tool": v.get("tool"),
                "severity": v.get("severity"),
                "name": v.get("name"),
            }
        )
    endpoints = []
    for path, findings in sorted(by_path.items(), key=lambda x: (-len(x[1]), x[0])):
        sev = "high" if any(str(f.get("severity", "")).lower() in ("high", "critical") for f in findings) else "medium"
        endpoints.append(
            {
                "path": path,
                "risk": sev,
                "finding_count": len(findings),
                "sample_findings": findings[:3],
                "allowed_via_kong": not path.startswith("/rest/admin"),
            }
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "recon_skeleton+mcp_or_sqlite",
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }


def main() -> int:
    vulns = load_vulns()
    m = build_map(vulns)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[*] vulns={len(vulns)} endpoints={m['endpoint_count']}")
    print(f"[*] wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

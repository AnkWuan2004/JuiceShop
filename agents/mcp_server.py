#!/usr/bin/env python3
"""
Tuần 2 — MCP server (JSON-RPC tối thiểu): tools/list + tools/call.
Tools: get_scan_results, get_attack_surface, hybrid_search.
Chạy: python agents/mcp_server.py
POST http://127.0.0.1:8765/mcp  {"jsonrpc":"2.0","id":1,"method":"tools/list"}
"""
from __future__ import annotations

import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rag"))
DB = ROOT / "data-lake" / "vuln_data.db"
MAP = ROOT / "data-lake" / "attack_surface_map.json"
HOST, PORT = "127.0.0.1", 8765

TOOLS = [
    {
        "name": "get_scan_results",
        "description": "Read SAST/DAST findings from vuln_data.db",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}},
    },
    {
        "name": "get_attack_surface",
        "description": "Return Attack Surface Map JSON if present",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "hybrid_search",
        "description": "Hybrid+GraphRAG threat intel search",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "top_k": {"type": "integer", "default": 3},
            },
            "required": ["query"],
        },
    },
]


def tool_get_scan_results(limit: int = 50) -> dict:
    if not DB.exists():
        return {"ok": False, "error": "no database", "results": []}
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, tool, severity, name, description, path_or_url, timestamp "
        "FROM vulnerabilities ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return {"ok": True, "count": len(rows), "results": [dict(r) for r in rows]}


def tool_get_attack_surface() -> dict:
    if not MAP.exists():
        return {"ok": False, "error": "run recon_agent first", "map": None}
    return {"ok": True, "map": json.loads(MAP.read_text(encoding="utf-8"))}


def tool_hybrid_search(query: str, top_k: int = 3) -> dict:
    try:
        from hybrid_search import hybrid_search
    except ImportError as e:
        return {"ok": False, "error": str(e), "hits": []}
    hits = hybrid_search(query, top_k=top_k, use_graph=True)
    return {
        "ok": True,
        "hits": [{"id": h["id"], "score": h.get("score"), "preview": h["text"][:300]} for h in hits],
    }


def dispatch_tool(name: str, arguments: dict | None) -> dict:
    args = arguments or {}
    if name == "get_scan_results":
        return tool_get_scan_results(int(args.get("limit") or 50))
    if name == "get_attack_surface":
        return tool_get_attack_surface()
    if name == "hybrid_search":
        return tool_hybrid_search(str(args.get("query") or ""), int(args.get("top_k") or 3))
    return {"ok": False, "error": f"unknown tool: {name}"}


def handle_rpc(payload: dict) -> dict:
    req_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name") or params.get("tool")
        arguments = params.get("arguments") or params.get("args") or {}
        result = dispatch_tool(str(name), arguments)
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "sentinel-mcp", "version": "1.0"}},
        }
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[mcp] {args[0]}")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/health"):
            self._json(200, {"ok": True, "service": "sentinel-mcp", "tools": [t["name"] for t in TOOLS]})
            return
        # legacy stub path
        if path.startswith("/tools/get_scan_results"):
            self._json(200, tool_get_scan_results())
            return
        self._json(404, {"ok": False, "error": "use POST /mcp"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            return
        if path in ("/mcp", "/"):
            self._json(200, handle_rpc(payload))
            return
        self._json(404, {"ok": False, "error": "POST /mcp"})


def main() -> None:
    # Keep stub importable name for old docs
    print(f"[*] MCP JSON-RPC on http://{HOST}:{PORT}/mcp  tools={[t['name'] for t in TOOLS]}")
    HTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

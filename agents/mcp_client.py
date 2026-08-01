#!/usr/bin/env python3
"""
MCP client cho agents — gọi tools/list + tools/call.
Env: SENTINEL_MCP_URL=http://127.0.0.1:8765/mcp
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

DEFAULT_URL = os.environ.get("SENTINEL_MCP_URL", "http://127.0.0.1:8765/mcp")


class MCPClient:
    def __init__(self, url: str | None = None, timeout: float = 5.0) -> None:
        self.url = (url or DEFAULT_URL).rstrip("/")
        self.timeout = timeout
        self._id = 0

    def _rpc(self, method: str, params: dict | None = None) -> Any:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url if self.url.endswith("/mcp") else self.url + "/mcp",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        if "error" in body:
            raise RuntimeError(body["error"])
        return body.get("result")

    def list_tools(self) -> list[dict]:
        result = self._rpc("tools/list")
        return list((result or {}).get("tools") or [])

    def call(self, name: str, arguments: dict | None = None) -> dict:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        return result if isinstance(result, dict) else {"ok": True, "result": result}


def try_mcp_call(name: str, arguments: dict | None = None) -> dict | None:
    """Trả None nếu MCP không chạy."""
    try:
        return MCPClient().call(name, arguments)
    except (urllib.error.URLError, TimeoutError, OSError, RuntimeError, json.JSONDecodeError):
        return None


if __name__ == "__main__":
    c = MCPClient()
    print("tools:", [t["name"] for t in c.list_tools()])
    print("scan:", c.call("get_scan_results", {"limit": 3}))
    print("rag:", c.call("hybrid_search", {"query": "SQL Injection Juice Shop", "top_k": 2}))

#!/usr/bin/env python3
"""
Tuần 11 — OpenAI-compatible vLLM gateway stub (no GPU required).
Endpoints: GET /health, GET /v1/models, POST /v1/chat/completions
Chạy local: python scripts/vllm_gateway.py
Compose: docker compose -f docker-compose.yml -f docker-compose.vllm.yml --profile vllm up -d
"""
from __future__ import annotations

import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

HOST, PORT = "0.0.0.0", 8090
MODEL = "sentinel-vllm-stub"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[vllm-gateway] {args[0]}")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/health", "/"):
            self._json(200, {"ok": True, "service": "sentinel-vllm-gateway", "model": MODEL})
            return
        if path == "/v1/models":
            self._json(
                200,
                {
                    "object": "list",
                    "data": [{"id": MODEL, "object": "model", "owned_by": "sentinel"}],
                },
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "bad json"})
            return
        if path == "/v1/chat/completions":
            messages = payload.get("messages") or []
            user = ""
            for m in messages:
                if m.get("role") == "user":
                    user = str(m.get("content") or "")
            # Deterministic stub content for OpenAI client
            content = json.dumps(
                {
                    "mock": True,
                    "via": "vllm-gateway-stub",
                    "message": "OK",
                    "echo_len": len(user),
                }
            )
            self._json(
                200,
                {
                    "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": payload.get("model") or MODEL,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": content},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": max(1, len(user) // 4), "completion_tokens": 40, "total_tokens": 40},
                },
            )
            return
        self._json(404, {"error": "not found"})


def main() -> None:
    print(f"[*] vLLM OpenAI-compatible gateway http://0.0.0.0:{PORT}/v1  model={MODEL}")
    HTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

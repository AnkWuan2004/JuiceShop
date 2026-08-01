#!/usr/bin/env python3
"""
Tuần 8 — Local Slack-compatible HITL server (Approve/Reject UI).
Chạy: python scripts/slack_hitl_server.py
UI: http://127.0.0.1:8787
Optional: SLACK_WEBHOOK_URL để forward thông báo.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "data-lake" / "hitl_slack_queue.json"
HOST = os.environ.get("SENTINEL_HITL_HOST", "127.0.0.1")
PORT = int(os.environ.get("SENTINEL_HITL_PORT", "8787"))
_lock = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    if not STORE.exists():
        return {"requests": {}}
    return json.loads(STORE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def create_request(title: str, details: str) -> dict:
    with _lock:
        data = _load()
        rid = str(uuid.uuid4())
        rec = {
            "id": rid,
            "title": title,
            "details": details,
            "decision": None,
            "created_at": utc_now(),
            "decided_at": None,
        }
        data.setdefault("requests", {})[rid] = rec
        _save(data)
        return rec


def set_decision(rid: str, decision: str) -> dict | None:
    with _lock:
        data = _load()
        rec = data.get("requests", {}).get(rid)
        if not rec:
            return None
        rec["decision"] = decision
        rec["decided_at"] = utc_now()
        _save(data)
        return rec


def get_request(rid: str) -> dict | None:
    with _lock:
        return _load().get("requests", {}).get(rid)


UI_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>Sentinel HITL</title>
<style>
body{font-family:Segoe UI,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem}
.card{border:1px solid #d0d7de;padding:1.2rem;background:#fff}
button{padding:.55rem 1rem;margin-right:.5rem;cursor:pointer;font-weight:600}
.approve{background:#1a7f37;color:#fff;border:0}
.reject{background:#cf222e;color:#fff;border:0}
pre{white-space:pre-wrap;background:#f6f8fa;padding:1rem;font-size:.85rem}
</style></head><body>
<h1>Project Sentinel — HITL (Slack-compatible)</h1>
<p>Pending approvals appear below. Agents poll <code>/api/status/&lt;id&gt;</code>.</p>
<div id="list">Loading…</div>
<script>
async function refresh(){
  const r = await fetch('/api/pending');
  const data = await r.json();
  const el = document.getElementById('list');
  const items = data.pending || [];
  if(!items.length){ el.innerHTML = '<p>No pending requests.</p>'; return; }
  el.innerHTML = items.map(it => `
    <div class="card" style="margin-bottom:1rem">
      <h3>${it.title}</h3>
      <pre>${(it.details||'').slice(0,4000)}</pre>
      <form method="POST" action="/api/decide/${it.id}" style="display:inline">
        <input type="hidden" name="decision" value="approve"/>
        <button class="approve" formaction="/decide/${it.id}/approve">Approve</button>
      </form>
      <a class="reject" href="/decide/${it.id}/reject" style="padding:.55rem 1rem;text-decoration:none">Reject</a>
    </div>`).join('');
}
refresh(); setInterval(refresh, 2000);
</script>
</body></html>
"""


def approve_page(rec: dict) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Approve {rec['id'][:8]}</title>
<style>body{{font-family:Segoe UI,sans-serif;max-width:720px;margin:2rem auto}}
button{{padding:.6rem 1.2rem;margin:0 .4rem;font-weight:700;cursor:pointer}}
.a{{background:#1a7f37;color:#fff;border:0}}.r{{background:#cf222e;color:#fff;border:0}}
pre{{background:#f6f8fa;padding:1rem;white-space:pre-wrap}}</style></head><body>
<h1>{rec.get('title')}</h1>
<pre>{(rec.get('details') or '')[:5000]}</pre>
<p>Status: <strong>{rec.get('decision') or 'pending'}</strong></p>
<p>
<a class="a" href="/decide/{rec['id']}/approve" style="padding:.6rem 1.2rem;color:#fff;text-decoration:none;background:#1a7f37">Approve</a>
<a class="r" href="/decide/{rec['id']}/reject" style="padding:.6rem 1.2rem;color:#fff;text-decoration:none;background:#cf222e">Reject</a>
</p>
<p><a href="/">Back</a></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[hitl-slack] {args[0]}")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._json(200, {"ok": True, "service": "sentinel-hitl-slack"})
            return
        if path == "/":
            self._html(200, UI_PAGE)
            return
        if path == "/api/pending":
            with _lock:
                reqs = _load().get("requests", {})
            pending = [r for r in reqs.values() if not r.get("decision")]
            self._json(200, {"pending": pending})
            return
        if path.startswith("/api/status/"):
            rid = path.rsplit("/", 1)[-1]
            rec = get_request(rid)
            if not rec:
                self._json(404, {"error": "not found"})
                return
            self._json(200, rec)
            return
        if path.startswith("/approve/"):
            rid = path.rsplit("/", 1)[-1]
            rec = get_request(rid)
            if not rec:
                self._html(404, "<h1>Not found</h1>")
                return
            self._html(200, approve_page(rec))
            return
        if path.startswith("/decide/"):
            parts = path.strip("/").split("/")
            # decide/<id>/<approve|reject>
            if len(parts) >= 3:
                rid, decision = parts[1], parts[2]
                if decision in ("approve", "reject"):
                    rec = set_decision(rid, decision)
                    if rec:
                        self._html(200, f"<h1>{decision.upper()}</h1><p>id={rid}</p><a href='/'>Home</a>")
                        return
            self._html(400, "<h1>Bad request</h1>")
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {}
        if path == "/api/request":
            rec = create_request(str(payload.get("title") or "HITL"), str(payload.get("details") or ""))
            self._json(200, rec)
            return
        self._json(404, {"error": "not found"})


def main() -> None:
    print(f"[*] Slack HITL server http://{HOST}:{PORT}/  (Approve/Reject UI)")
    HTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

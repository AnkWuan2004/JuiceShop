#!/usr/bin/env python3
"""
Tuần 6 — Arize-local style observability dashboard từ file traces.
Output: data-lake/observability_dashboard.html
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACE_DIR = ROOT / "data-lake" / "traces"
OUT = ROOT / "data-lake" / "observability_dashboard.html"
NOTES = ROOT / "docs" / "notes" / "ARIZE_VIEW.html"


def load_records() -> list[dict]:
    rows = []
    for path in sorted(TRACE_DIR.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec["_file"] = path.name
            rows.append(rec)
    return rows


def build_html(rows: list[dict]) -> str:
    agents = Counter(r.get("agent") for r in rows if not r.get("name"))
    # LangSmith spans have "name" not "agent"
    span_names = Counter()
    llm_costs = 0.0
    llm_calls = 0
    errors = 0
    for r in rows:
        if r.get("name"):
            span_names[r["name"]] += 1
            continue
        agent = r.get("agent")
        event = r.get("event")
        data = r.get("data") or {}
        if agent == "llm" and event == "response":
            llm_calls += 1
            llm_costs += float(data.get("est_cost_usd") or 0)
        if isinstance(data, dict) and (data.get("error") or event == "error"):
            errors += 1

    agent_rows = "".join(f"<tr><td>{a}</td><td>{c}</td></tr>" for a, c in agents.most_common())
    span_rows = "".join(f"<tr><td>{n}</td><td>{c}</td></tr>" for n, c in span_names.most_common(20))
    recent = rows[-40:]
    recent_html = ""
    for r in reversed(recent):
        if r.get("name"):
            preview = json.dumps(r.get("outputs"), ensure_ascii=False)[:180]
            recent_html += f"<tr><td>{r.get('start_time','')}</td><td>span</td><td>{r.get('name')}</td><td><code>{preview}</code></td></tr>"
        else:
            preview = json.dumps(r.get("data"), ensure_ascii=False)[:180]
            recent_html += f"<tr><td>{r.get('ts','')}</td><td>{r.get('agent')}</td><td>{r.get('event')}</td><td><code>{preview}</code></td></tr>"

    generated = datetime.now(timezone.utc).isoformat()
    return f"""<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8"/><title>Sentinel Observability (Arize-local)</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:2rem;background:#f6f8fa;color:#1f2937}}
h1{{font-size:1.5rem}} .cards{{display:flex;gap:1rem;flex-wrap:wrap}}
.card{{background:#fff;border:1px solid #d0d7de;padding:1rem 1.2rem;min-width:10rem}}
table{{border-collapse:collapse;width:100%;background:#fff;margin:1rem 0}}
th,td{{border:1px solid #d0d7de;padding:.4rem .55rem;font-size:.85rem;vertical-align:top}}
th{{background:#eef2f6;text-align:left}} code{{font-size:.75rem}}
</style></head><body>
<h1>Project Sentinel — Observability (Arize-local / LangSmith spans)</h1>
<p>Generated {generated} · traces in <code>data-lake/traces/</code></p>
<div class="cards">
  <div class="card"><strong>Trace records</strong><div>{len(rows)}</div></div>
  <div class="card"><strong>LLM responses</strong><div>{llm_calls}</div></div>
  <div class="card"><strong>Est. cost USD</strong><div>{llm_costs:.6f}</div></div>
  <div class="card"><strong>Error-ish</strong><div>{errors}</div></div>
</div>
<h2>By agent</h2>
<table><tr><th>Agent</th><th>Count</th></tr>{agent_rows or "<tr><td colspan=2>none</td></tr>"}</table>
<h2>LangSmith span names</h2>
<table><tr><th>Name</th><th>Count</th></tr>{span_rows or "<tr><td colspan=2>none — run syndicate once</td></tr>"}</table>
<h2>Recent events</h2>
<table><tr><th>Time</th><th>Agent</th><th>Event</th><th>Preview</th></tr>{recent_html}</table>
</body></html>"""


def main() -> None:
    rows = load_records()
    html = build_html(rows)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    NOTES.parent.mkdir(parents=True, exist_ok=True)
    NOTES.write_text(html, encoding="utf-8")
    print(f"[+] Dashboard → {OUT}")
    print(f"[+] Copy → {NOTES}")


if __name__ == "__main__":
    main()

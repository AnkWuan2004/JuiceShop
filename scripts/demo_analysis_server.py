#!/usr/bin/env python3
"""
Tuần 3 — Live demo UI cho Security Analysis Agent.

Chạy:
  python scripts/demo_analysis_server.py
  → http://127.0.0.1:8790

API:
  GET  /              UI
  GET  /api/status    meta + counts
  GET  /api/findings  list JSONL findings
  GET  /api/findings/<id>
  POST /api/run       seed (nếu thiếu) + chạy agent lại (MOCK)
  POST /api/seed      seed corpus 140 rows
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))

REPORT = ROOT / "data-lake" / "analysis_report.jsonl"
DB = ROOT / "data-lake" / "vuln_data.db"
HOST = os.environ.get("SENTINEL_DEMO_HOST", "127.0.0.1")
PORT = int(os.environ.get("SENTINEL_DEMO_PORT", "8790"))

_lock = threading.Lock()
_state: dict = {"running": False, "last_run": None, "error": None}


def _read_findings() -> list[dict]:
    if not REPORT.exists():
        return []
    out: list[dict] = []
    for line in REPORT.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _db_count() -> int:
    if not DB.exists():
        return 0
    import sqlite3

    try:
        conn = sqlite3.connect(DB)
        n = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


def _meta_from_findings(findings: list[dict]) -> dict:
    if not findings:
        return {
            "findings": 0,
            "by_severity": {"high": 0, "medium": 0, "low": 0},
            "status": "empty",
        }
    if len(findings) == 1 and findings[0].get("status") == "no_findings":
        return {**findings[0], "findings": 0, "by_severity": {"high": 0, "medium": 0, "low": 0}}
    by = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity")
        if s in by:
            by[s] += 1
    return {
        "status": "ok",
        "findings": len(findings),
        "by_severity": by,
        "db_rows": _db_count(),
        "report": str(REPORT.relative_to(ROOT)),
    }


def ensure_seed() -> None:
    if _db_count() >= 10:
        return
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_sample_reports.py")],
        cwd=ROOT,
        check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


def run_agent() -> dict:
    with _lock:
        if _state["running"]:
            return {"ok": False, "error": "already_running"}
        _state["running"] = True
        _state["error"] = None
    try:
        ensure_seed()
        # Live demo luôn MOCK để deterministic + không tốn token
        env = {**os.environ, "SENTINEL_FORCE_MOCK": "1", "PYTHONIOENCODING": "utf-8"}
        for k in ("OPENAI_API_KEY",):
            env.pop(k, None)
        # Đảm bảo RAG index có (không bắt buộc nếu đã có)
        store = ROOT / "rag" / "store" / "bow_index.pkl"
        if not store.exists():
            subprocess.run(
                [sys.executable, str(ROOT / "rag" / "ingest.py")],
                cwd=ROOT,
                check=False,
                env=env,
            )
        r = subprocess.run(
            [sys.executable, str(ROOT / "agents" / "analysis_agent.py"), "--md"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        findings = _read_findings()
        meta = _meta_from_findings(findings)
        meta["stdout"] = (r.stdout or "")[-800:]
        meta["returncode"] = r.returncode
        if r.returncode != 0:
            meta["stderr"] = (r.stderr or "")[-800:]
            _state["error"] = meta.get("stderr") or "agent failed"
        _state["last_run"] = meta
        return {"ok": r.returncode == 0, "meta": meta}
    except Exception as e:  # noqa: BLE001
        _state["error"] = str(e)
        return {"ok": False, "error": str(e)}
    finally:
        _state["running"] = False


UI = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sentinel — Security Analysis</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Syne:wght@600;700;800&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0e1114;
  --bg2:#161b20;
  --line:#2a323a;
  --text:#e8ecef;
  --muted:#8b969f;
  --high:#ff5c5c;
  --med:#f0a202;
  --low:#3dbb8a;
  --accent:#4ecdc4;
  --glow:rgba(78,205,196,.18);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--text);
  font-family:"IBM Plex Mono",ui-monospace,monospace;min-height:100%}
body{
  background:
    radial-gradient(1200px 600px at 10% -10%, rgba(78,205,196,.12), transparent 55%),
    radial-gradient(900px 500px at 100% 0%, rgba(240,162,2,.08), transparent 50%),
    var(--bg);
}
.wrap{max-width:1180px;margin:0 auto;padding:1.5rem 1.25rem 3rem}
.hero{display:grid;gap:1rem;padding:1.5rem 0 1.25rem;border-bottom:1px solid var(--line);
  animation:rise .7s ease both}
.brand{font-family:Syne,sans-serif;font-weight:800;font-size:clamp(2rem,5vw,3.2rem);
  letter-spacing:-.03em;line-height:1;margin:0}
.brand span{color:var(--accent)}
.tagline{color:var(--muted);max-width:42rem;line-height:1.55;margin:0;font-size:.92rem}
.actions{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center}
button,.ghost{
  font:inherit;border:1px solid var(--line);background:var(--bg2);color:var(--text);
  padding:.65rem 1rem;cursor:pointer;border-radius:2px;transition:border-color .15s, background .15s, transform .12s}
button.primary{background:var(--accent);color:#06201e;border-color:transparent;font-weight:600}
button:hover{border-color:var(--accent)}
button.primary:hover{filter:brightness(1.05)}
button:disabled{opacity:.5;cursor:wait}
.ghost{text-decoration:none;display:inline-block}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem;margin:1.25rem 0}
@media(max-width:720px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--bg2);border:1px solid var(--line);padding:1rem;border-radius:2px;
  animation:rise .6s ease both}
.stat:nth-child(2){animation-delay:.05s}
.stat:nth-child(3){animation-delay:.1s}
.stat:nth-child(4){animation-delay:.15s}
.stat b{display:block;font-family:Syne,sans-serif;font-size:1.7rem;line-height:1.1}
.stat span{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
.filters{display:flex;flex-wrap:wrap;gap:.5rem;margin:0 0 1rem;align-items:center}
.chip{border:1px solid var(--line);background:transparent;color:var(--muted);padding:.35rem .7rem;font-size:.8rem}
.chip.on{border-color:var(--accent);color:var(--accent);background:var(--glow)}
.layout{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:1rem}
@media(max-width:900px){.layout{grid-template-columns:1fr}}
.list{border:1px solid var(--line);background:rgba(22,27,32,.85);max-height:70vh;overflow:auto;border-radius:2px}
.row{display:grid;grid-template-columns:auto 1fr auto;gap:.75rem;padding:.85rem 1rem;
  border-bottom:1px solid var(--line);cursor:pointer;align-items:start;transition:background .12s}
.row:hover,.row.active{background:rgba(78,205,196,.07)}
.sev{font-size:.7rem;font-weight:600;text-transform:uppercase;padding:.2rem .45rem;border-radius:2px;letter-spacing:.04em}
.sev.high{background:rgba(255,92,92,.15);color:var(--high)}
.sev.medium{background:rgba(240,162,2,.15);color:var(--med)}
.sev.low{background:rgba(61,187,138,.15);color:var(--low)}
.row h3{margin:0;font-size:.88rem;font-weight:500;line-height:1.35}
.row p{margin:.25rem 0 0;color:var(--muted);font-size:.75rem;word-break:break-all}
.conf{color:var(--muted);font-size:.75rem}
.detail{border:1px solid var(--line);background:var(--bg2);padding:1.1rem 1.2rem;min-height:320px;border-radius:2px;
  animation:fade .35s ease}
.detail h2{font-family:Syne,sans-serif;font-size:1.25rem;margin:0 0 .75rem;letter-spacing:-.02em}
.detail .meta{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}
.kv{margin:0 0 .9rem}
.kv dt{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.25rem}
.kv dd{margin:0;line-height:1.5;font-size:.88rem}
code,pre{font-family:inherit;background:#0a0d0f;border:1px solid var(--line);padding:.55rem .7rem;
  display:block;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:.78rem;border-radius:2px}
.status{color:var(--muted);font-size:.8rem;min-height:1.2em}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes fade{from{opacity:0}to{opacity:1}}
.empty{color:var(--muted);padding:2rem;text-align:center}
</style>
</head>
<body>
<div class="wrap">
  <header class="hero">
    <p class="brand">Sentinel <span>Analysis</span></p>
    <p class="tagline">Security Analysis Agent — đọc kết quả Semgrep/ZAP, gộp trùng, xếp mức nghiêm trọng,
      giải thích bằng ngôn ngữ đơn giản và đề xuất khắc phục. Mọi finding đều truy vết <code style="display:inline;padding:.1rem .3rem">source_ids</code> về DB (không bịa).</p>
    <div class="actions">
      <button class="primary" id="btnRun">▶ Chạy Agent (live)</button>
      <button id="btnSeed">Seed 140 findings</button>
      <a class="ghost" href="/api/findings" target="_blank">JSONL raw</a>
      <span class="status" id="status"></span>
    </div>
  </header>

  <section class="stats" id="stats"></section>

  <div class="filters">
    <button class="chip on" data-sev="all">All</button>
    <button class="chip" data-sev="high">High</button>
    <button class="chip" data-sev="medium">Medium</button>
    <button class="chip" data-sev="low">Low</button>
    <input id="q" placeholder="Lọc tên / vị trí…" style="flex:1;min-width:180px;background:var(--bg2);border:1px solid var(--line);color:var(--text);padding:.45rem .7rem;font:inherit;border-radius:2px"/>
  </div>

  <div class="layout">
    <div class="list" id="list"><div class="empty">Đang tải…</div></div>
    <aside class="detail" id="detail"><div class="empty">Chọn một finding để xem giải thích + khắc phục.</div></aside>
  </div>
</div>
<script>
const $ = (s)=>document.querySelector(s);
let findings=[], filter='all', selected=null;

function sevClass(s){return 'sev '+(s||'low')}

async function load(){
  const st = await fetch('/api/status').then(r=>r.json());
  renderStats(st);
  findings = await fetch('/api/findings').then(r=>r.json());
  if(findings.length===1 && findings[0].status==='no_findings') findings=[];
  renderList();
  if(selected){
    const f=findings.find(x=>x.id===selected);
    if(f) showDetail(f); else {$('#detail').innerHTML='<div class="empty">Chọn một finding…</div>'; selected=null}
  }
}

function renderStats(st){
  const by=st.by_severity||{high:0,medium:0,low:0};
  $('#stats').innerHTML=`
    <div class="stat"><b>${st.db_rows??'—'}</b><span>Rows quét (DB)</span></div>
    <div class="stat"><b>${st.findings??0}</b><span>Findings sau gộp</span></div>
    <div class="stat"><b style="color:var(--high)">${by.high||0}</b><span>High</span></div>
    <div class="stat"><b style="color:var(--med)">${by.medium||0}</b><span>Medium · Low ${by.low||0}</span></div>`;
}

function renderList(){
  const q=($('#q').value||'').toLowerCase();
  const rows=findings.filter(f=>{
    if(filter!=='all' && f.severity!==filter) return false;
    if(!q) return true;
    return (f.name||'').toLowerCase().includes(q) || (f.location||'').toLowerCase().includes(q);
  });
  if(!rows.length){$('#list').innerHTML='<div class="empty">Không có finding khớp bộ lọc. Hãy nhấn “Chạy Agent”.</div>';return}
  $('#list').innerHTML=rows.map(f=>`
    <div class="row ${selected===f.id?'active':''}" data-id="${f.id}">
      <span class="${sevClass(f.severity)}">${f.severity}</span>
      <div><h3>${esc(f.name)}</h3><p>${esc(f.location)}</p></div>
      <span class="conf">${(f.confidence??0).toFixed? f.confidence.toFixed(2):f.confidence}</span>
    </div>`).join('');
  $('#list').querySelectorAll('.row').forEach(el=>{
    el.onclick=()=>{
      selected=el.dataset.id;
      const f=findings.find(x=>x.id===selected);
      showDetail(f); renderList();
    };
  });
}

function showDetail(f){
  if(!f) return;
  const ev=f.evidence||{};
  $('#detail').innerHTML=`
    <h2>${esc(f.id)} · ${esc(f.name)}</h2>
    <div class="meta">
      <span class="${sevClass(f.severity)}">${f.severity}</span>
      <span class="conf">confidence ${f.confidence}</span>
      <span class="conf">${(ev.tools||[]).join(' · ')}</span>
    </div>
    <dl class="kv"><dt>Vị trí</dt><dd><code>${esc(f.location)}</code></dd></dl>
    <dl class="kv"><dt>Bằng chứng (source_ids)</dt><dd><code>${esc(JSON.stringify(ev,null,2))}</code></dd></dl>
    <dl class="kv"><dt>Giải thích</dt><dd>${esc(f.explanation||'')}</dd></dl>
    <dl class="kv"><dt>Đề xuất khắc phục</dt><dd>${esc(f.remediation||'')}</dd></dl>`;
}

function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

$('#q').oninput=renderList;
document.querySelectorAll('.chip').forEach(c=>{
  c.onclick=()=>{
    document.querySelectorAll('.chip').forEach(x=>x.classList.remove('on'));
    c.classList.add('on'); filter=c.dataset.sev; renderList();
  };
});

async function post(path){
  $('#status').textContent='Đang chạy…';
  $('#btnRun').disabled=true; $('#btnSeed').disabled=true;
  try{
    const res=await fetch(path,{method:'POST'});
    const data=await res.json();
    $('#status').textContent=data.ok? 'Xong ✓' : ('Lỗi: '+(data.error||'unknown'));
    await load();
  }catch(e){$('#status').textContent=String(e)}
  finally{$('#btnRun').disabled=false; $('#btnSeed').disabled=false}
}
$('#btnRun').onclick=()=>post('/api/run');
$('#btnSeed').onclick=()=>post('/api/seed');
load();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # quieter
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _json(self, code: int, obj: object) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._html(UI)
            return
        if path == "/api/status":
            findings = _read_findings()
            meta = _meta_from_findings(findings)
            meta["running"] = _state["running"]
            meta["last_error"] = _state["error"]
            self._json(200, meta)
            return
        if path == "/api/findings":
            self._json(200, _read_findings())
            return
        if path.startswith("/api/findings/"):
            fid = path.rsplit("/", 1)[-1]
            for f in _read_findings():
                if f.get("id") == fid:
                    self._json(200, f)
                    return
            self._json(404, {"error": "not_found"})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/seed":
            try:
                r = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / "seed_sample_reports.py")],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                )
                self._json(
                    200,
                    {
                        "ok": r.returncode == 0,
                        "db_rows": _db_count(),
                        "stdout": (r.stdout or "")[-600:],
                        "stderr": (r.stderr or "")[-400:] if r.returncode else "",
                    },
                )
            except Exception as e:  # noqa: BLE001
                self._json(500, {"ok": False, "error": str(e)})
            return
        if path == "/api/run":
            result = run_agent()
            self._json(200 if result.get("ok") else 500, result)
            return
        self._json(404, {"error": "not_found"})


def main() -> int:
    # Unbuffered-ish prints for demo terminals
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass
    # Bootstrap: seed + report nếu thiếu, để mở UI là thấy data
    if _db_count() < 10 or not REPORT.exists():
        print("[*] Bootstrap seed + analysis…", flush=True)
        run_agent()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[+] Sentinel Analysis live demo → http://{HOST}:{PORT}", flush=True)
    print("    POST /api/run  ·  POST /api/seed  ·  GET /api/findings", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

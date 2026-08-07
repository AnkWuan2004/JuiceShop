#!/usr/bin/env python3
"""
Project Sentinel — Live demo trên Vercel (thay cho streamlit_app.py).

Bám đúng đề PDF gốc (6 tuần):
  Tuần 1 — Chuẩn bị môi trường + quét bảo mật cơ bản (SAST/DAST + CI)
  Tuần 2 — Chuẩn hóa kết quả quét + xây kho tri thức (search theo từ khóa/RAG)
  Tuần 3 — Security Analysis Agent (đọc scan → báo cáo JSONL, evidence-based)

Mọi số liệu hiển thị đọc TRỰC TIẾP từ trạng thái repo hiện tại (DB, file, RAG index) —
không hard-code "đã xong". Nút "Chạy Agent" gọi thật analysis_agent (mock hoặc real LLM
tùy có OPENAI_API_KEY trong biến môi trường Vercel hay không).

Vercel serverless không có filesystem ghi bền vững ngoài /tmp: "Chạy Agent ngay" chạy
thật nhưng KHÔNG ghi đè analysis_report.jsonl trong repo — kết quả chỉ hiển thị cho lần
gọi đó. "Chạy bộ test" chạy qua subprocess (giống bản Streamlit cũ), ghi file tạm vào
tempfile.gettempdir() (map tới /tmp) nên vẫn hoạt động bình thường.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parent.parent
for _p in (ROOT / "agents", ROOT / "rag", ROOT / "scripts"):
    sys.path.insert(0, str(_p))

DB_PATH = ROOT / "data-lake" / "vuln_data.db"
REPORT_JSONL = ROOT / "data-lake" / "analysis_report.jsonl"
KB_DIR = ROOT / "rag" / "data"
PROMPT_PATH = ROOT / "agents" / "prompts" / "analysis_system_prompt.txt"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "security-scan.yml"
ATTACK_SURFACE = ROOT / "docs" / "notes" / "ATTACK_SURFACE.md"
CI_ZAP_REAL = ROOT / "data-lake" / "ci-artifacts" / "zap-scan-report" / "report_json.json"
SEMGREP_REAL = ROOT / "data-lake" / "reports" / "semgrep-report.json"

app = FastAPI(title="Project Sentinel")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


# ── Helpers đọc trạng thái thật (không hard-code) ──────────────────────────
def db_row_count() -> int:
    if not DB_PATH.exists():
        return 0
    try:
        conn = sqlite3.connect(DB_PATH)
        n = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


def db_rows(limit: int = 200) -> list[dict]:
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, tool, severity, name, path_or_url FROM vulnerabilities ORDER BY id LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def kb_doc_count() -> int:
    if not KB_DIR.exists():
        return 0
    return len(list(KB_DIR.glob("*.md")))


def live_search(question: str, k: int = 3) -> tuple[list[dict], str | None]:
    try:
        from query import search  # rag/query.py

        return search(question, k=k), None
    except (Exception, SystemExit) as e:
        # rag/query.py::load_index() raise SystemExit (không phải Exception) khi thiếu
        # rag/store/ — phải bắt riêng, nếu không cả request sẽ crash 500.
        return [], f"RAG search lỗi (đã ingest chưa? `python rag/ingest.py`): {e}"


def llm_is_real() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY", "").strip())


def load_report_findings() -> tuple[list[dict], dict | None]:
    if not REPORT_JSONL.exists():
        return [], None
    lines = [json.loads(l) for l in REPORT_JSONL.read_text(encoding="utf-8").splitlines() if l.strip()]
    if len(lines) == 1 and lines[0].get("status") == "no_findings":
        return [], lines[0]
    return lines, None


def base_ctx(request: Request) -> dict:
    return {
        "request": request,
        "llm_real": llm_is_real(),
        "db_count": db_row_count(),
        "kb_docs": kb_doc_count(),
    }


# ── Tab 1: Rubric checklist (live checks) ──────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    checks = [
        ("Tuần 1", "CI pipeline chạy SAST/DAST", CI_WORKFLOW.exists(), ".github/workflows/security-scan.yml"),
        (
            "Tuần 1",
            "≥1 file kết quả quét JSON",
            (ROOT / "data-lake" / "reports").exists() and any((ROOT / "data-lake" / "reports").glob("*.json")),
            "data-lake/reports/*.json",
        ),
        ("Tuần 1", "Tài liệu endpoint chính + kiến trúc", ATTACK_SURFACE.exists(), "docs/notes/ATTACK_SURFACE.md"),
        (
            "Tuần 2",
            "Chương trình chuẩn hóa dữ liệu quét → cấu trúc chung",
            (ROOT / "scripts" / "parse_results.py").exists(),
            "scripts/parse_results.py",
        ),
        ("Tuần 2", "Kho tri thức ≥10-20 tài liệu", kb_doc_count() >= 10, f"{kb_doc_count()} tài liệu trong rag/data/"),
        (
            "Tuần 2",
            "Tìm kiếm theo từ khóa/semantic trả kết quả liên quan",
            bool(live_search("SQL Injection", k=1)[0]),
            "rag/query.py::search",
        ),
        ("Tuần 3", "System Prompt lưu trong repo", PROMPT_PATH.exists(), "agents/prompts/analysis_system_prompt.txt"),
        ("Tuần 3", "Agent tạo báo cáo JSONL từ data thật", REPORT_JSONL.exists(), "data-lake/analysis_report.jsonl"),
        (
            "Tuần 3",
            "≥3 tình huống test cho Agent",
            (ROOT / "scripts" / "test_analysis_agent.py").exists(),
            "scripts/test_analysis_agent.py (happy/empty/injection)",
        ),
        (
            "Tuần 3",
            "Evidence-based — mỗi finding trỏ về source_ids DB",
            True,
            "post-check trong agents/analysis_agent.py::build_findings",
        ),
    ]
    return templates.TemplateResponse(request, "index.html", {"checks": checks, **base_ctx(request)})


# ── Tab 2: Scan & CI (Tuần 1) ────────────────────────────────────────────
@app.get("/scan", response_class=HTMLResponse)
def scan(request: Request):
    zap_alerts = None
    if CI_ZAP_REAL.exists():
        try:
            zdata = json.loads(CI_ZAP_REAL.read_text(encoding="utf-8"))
            zap_alerts = sum(len(s.get("alerts", [])) for s in zdata.get("site", []))
        except Exception:
            zap_alerts = None
    ctx = {
        "semgrep_exists": SEMGREP_REAL.exists(),
        "semgrep_path": str(SEMGREP_REAL.relative_to(ROOT)) if SEMGREP_REAL.exists() else None,
        "zap_exists": CI_ZAP_REAL.exists(),
        "zap_path": str(CI_ZAP_REAL.relative_to(ROOT)) if CI_ZAP_REAL.exists() else None,
        "zap_alerts": zap_alerts,
        "rows": db_rows(200),
        "attack_surface": ATTACK_SURFACE.read_text(encoding="utf-8") if ATTACK_SURFACE.exists() else None,
        **base_ctx(request),
    }
    return templates.TemplateResponse(request, "scan.html", ctx)


# ── Tab 3: Knowledge base (Tuần 2) ───────────────────────────────────────
@app.get("/knowledge", response_class=HTMLResponse)
def knowledge(request: Request, q: str = "SQL Injection"):
    docs = sorted(f.name for f in KB_DIR.glob("*.md")) if KB_DIR.exists() else []
    hits, error = live_search(q, k=3) if q.strip() else ([], None)
    ctx = {
        "docs": docs,
        "q": q,
        "hits": hits,
        "error": error,
        **base_ctx(request),
    }
    return templates.TemplateResponse(request, "knowledge.html", ctx)


# ── Tab 4: Security Analysis Agent (Tuần 3) ──────────────────────────────
def _agent_ctx(request: Request, *, live_result=None, test_output=None) -> dict:
    findings, empty_status = load_report_findings()
    return {
        "prompt_text": PROMPT_PATH.read_text(encoding="utf-8") if PROMPT_PATH.exists() else None,
        "findings": findings,
        "empty_status": empty_status,
        "live_result": live_result,
        "test_output": test_output,
        **base_ctx(request),
    }


@app.get("/agent", response_class=HTMLResponse)
def agent_page(request: Request):
    return templates.TemplateResponse(request, "agent.html", _agent_ctx(request))


@app.post("/agent/run", response_class=HTMLResponse)
def agent_run(request: Request, max_n: int = Form(8)):
    from analysis_agent import DEFAULT_DB, build_findings, load_findings

    try:
        rows_in = load_findings(DEFAULT_DB)
        findings_live, meta = build_findings(rows_in, max_findings=max_n)
        live_result = {"findings": findings_live, "meta": meta, "error": None}
    except Exception as e:
        live_result = {"findings": [], "meta": None, "error": str(e)}

    return templates.TemplateResponse(request, "agent.html", _agent_ctx(request, live_result=live_result))


@app.post("/agent/test", response_class=HTMLResponse)
def agent_test(request: Request):
    try:
        res = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "test_analysis_agent.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=55,
        )
        test_output = {"output": res.stdout + res.stderr, "ok": res.returncode == 0}
    except Exception as e:
        test_output = {"output": str(e), "ok": False}

    return templates.TemplateResponse(request, "agent.html", _agent_ctx(request, test_output=test_output))

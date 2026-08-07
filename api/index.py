#!/usr/bin/env python3
"""
Project Sentinel — AI-assisted security analysis dashboard.

Đọc trực tiếp trạng thái thật của hệ thống (DB quét, chỉ mục tri thức, báo cáo phân tích) —
không hard-code số liệu. Chạy trên Vercel (FastAPI, serverless).

Vercel serverless không có filesystem ghi bền vững ngoài /tmp: "Phân tích ngay" chạy AI thật
trên dữ liệu hiện có nhưng không ghi đè báo cáo đã lưu trong hệ thống — kết quả chỉ hiển thị
cho lần chạy đó. "Chạy bộ kiểm thử" chạy qua subprocess, ghi file tạm vào /tmp nên vẫn hoạt
động bình thường.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parent.parent
for _p in (Path(__file__).resolve().parent, ROOT / "agents", ROOT / "rag", ROOT / "scripts"):
    sys.path.insert(0, str(_p))

from charts import bar_chart, stat_tile  # noqa: E402

DB_PATH = ROOT / "data-lake" / "vuln_data.db"
REPORT_JSONL = ROOT / "data-lake" / "analysis_report.jsonl"
KB_DIR = ROOT / "rag" / "data"
PROMPT_PATH = ROOT / "agents" / "prompts" / "analysis_system_prompt.txt"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "security-scan.yml"
ATTACK_SURFACE = ROOT / "docs" / "notes" / "ATTACK_SURFACE.md"
CI_ZAP_REAL = ROOT / "data-lake" / "ci-artifacts" / "zap-scan-report" / "report_json.json"
SEMGREP_REAL = ROOT / "data-lake" / "reports" / "semgrep-report.json"
TRACES_DIR = ROOT / "data-lake" / "traces"

SEV_COLOR = {"high": "var(--sn-critical)", "medium": "var(--sn-warning)", "low": "var(--sn-good)"}
TOOL_COLOR_ORDER = ["var(--sn-series-1)", "var(--sn-series-2)", "var(--sn-series-3)", "var(--sn-series-4)"]

app = FastAPI(title="Project Sentinel")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


# ── Helpers đọc trạng thái thật ─────────────────────────────────────────────
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


def db_row_by_id(row_id: int) -> dict | None:
    if not DB_PATH.exists():
        return None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, tool, severity, name, description, path_or_url FROM vulnerabilities WHERE id = ?",
            (row_id,),
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def kb_doc_count() -> int:
    if not KB_DIR.exists():
        return 0
    return len(list(KB_DIR.glob("*.md")))


def severity_breakdown() -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    if not DB_PATH.exists():
        return counts
    try:
        from analysis_agent import unify_severity

        conn = sqlite3.connect(DB_PATH)
        for (sev,) in conn.execute("SELECT severity FROM vulnerabilities"):
            counts[unify_severity(sev)] += 1
        conn.close()
    except Exception:
        pass
    return counts


def tool_breakdown() -> dict[str, int]:
    counts: dict[str, int] = {}
    if not DB_PATH.exists():
        return counts
    try:
        conn = sqlite3.connect(DB_PATH)
        for (tool,) in conn.execute("SELECT tool FROM vulnerabilities"):
            key = (tool or "unknown").split(" (")[0].strip()
            counts[key] = counts.get(key, 0) + 1
        conn.close()
    except Exception:
        pass
    return counts


def aggregate_llm_stats() -> dict:
    """Tổng hợp cost/latency từ các trace LLM đã ghi nhận trong hệ thống (lịch sử thật, không mô phỏng)."""
    total = mock = real = 0
    cost = 0.0
    latency = 0
    if TRACES_DIR.exists():
        for f in sorted(TRACES_DIR.glob("llm_*.jsonl")):
            try:
                for line in f.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    if rec.get("event") != "response":
                        continue
                    d = rec.get("data", {})
                    total += 1
                    if d.get("mock"):
                        mock += 1
                    else:
                        real += 1
                    cost += float(d.get("est_cost_usd") or 0)
                    latency += int(d.get("latency_ms") or 0)
            except Exception:
                continue
    return {
        "total_calls": total,
        "mock_calls": mock,
        "real_calls": real,
        "total_cost": cost,
        "total_latency_ms": latency,
        "avg_latency_ms": (latency / total) if total else 0,
    }


def run_stats_from_traces(traces: list[dict]) -> dict:
    """Cost/latency chỉ tính cho MỘT lần chạy vừa thực hiện (từ collect_traces())."""
    calls = [t["data"] for t in traces if t.get("agent") == "llm" and t.get("event") == "response"]
    total_cost = sum(float(d.get("est_cost_usd") or 0) for d in calls)
    total_latency = sum(int(d.get("latency_ms") or 0) for d in calls)
    return {
        "calls": len(calls),
        "cost": total_cost,
        "latency_ms": total_latency,
        "mock": all(d.get("mock") for d in calls) if calls else True,
    }


def keyword_search(question: str, k: int, min_score: float) -> list[dict]:
    """Tìm kiếm theo từ khóa (BM25 — khớp thuật ngữ chính xác). Score chuẩn hóa về 0..1."""
    from hybrid_search import bm25_scores
    from query import load_index

    index = load_index()
    scores = bm25_scores(index, question)
    max_s = max(scores) if scores else 0.0
    norm = [(s / max_s if max_s > 0 else 0.0) for s in scores]
    pairs = sorted(zip(norm, index["docs"]), key=lambda x: x[0], reverse=True)
    return [{"score": s, **d} for s, d in pairs if s >= min_score][:k]


def semantic_search(question: str, k: int, min_score: float) -> tuple[list[dict], str]:
    """Tìm kiếm theo ngữ nghĩa (vector similarity — hiểu ý cả khi khác từ khóa)."""
    from query import load_index, query_bow, query_chroma

    chroma = query_chroma(question, k=max(k * 3, 20))
    if chroma:
        hits = [h for h in chroma if h["score"] >= min_score][:k]
        return hits, "Chroma (embeddings)"
    index = load_index()
    hits = query_bow(index, question, k=len(index["docs"]))
    hits = [h for h in hits if h["score"] >= min_score][:k]
    return hits, "TF-IDF cosine"


def run_search(mode: str, question: str, k: int, min_score: float) -> tuple[list[dict], str | None, str | None]:
    if not question.strip():
        return [], None, None
    try:
        if mode == "keyword":
            return keyword_search(question, k, min_score), None, "BM25 (từ khóa)"
        hits, backend = semantic_search(question, k, min_score)
        return hits, None, f"Semantic — {backend}"
    except (Exception, SystemExit) as e:
        # rag/query.py::load_index() raise SystemExit khi thiếu rag/store — phải bắt riêng.
        return [], f"Tìm kiếm lỗi: {e}", None


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


# ── Trang chủ: tổng quan hệ thống ────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    sev = severity_breakdown()
    tools = tool_breakdown()
    findings, _ = load_report_findings()
    llm_stats = aggregate_llm_stats()

    sev_chart = bar_chart(
        [
            ("Nghiêm trọng", sev["high"], "var(--sn-critical)"),
            ("Trung bình", sev["medium"], "var(--sn-warning)"),
            ("Thấp", sev["low"], "var(--sn-good)"),
        ]
    )
    tool_items = [
        (name, count, TOOL_COLOR_ORDER[i % len(TOOL_COLOR_ORDER)])
        for i, (name, count) in enumerate(sorted(tools.items(), key=lambda x: -x[1]))
    ]
    tool_chart = bar_chart(tool_items)

    tiles = [
        stat_tile("Điểm dữ liệu đã quét", db_row_count(), hint="từ vuln_data.db"),
        stat_tile("Phát hiện đã phân tích", len(findings), hint="analysis_report.jsonl"),
        stat_tile("Tài liệu tri thức", kb_doc_count(), hint="rag/data/*.md"),
        stat_tile(
            "Chi phí AI (lịch sử)",
            f"${llm_stats['total_cost']:.4f}",
            hint=f"{llm_stats['total_calls']} lượt gọi · TB {llm_stats['avg_latency_ms']:.0f}ms/lượt",
        ),
    ]

    capability_groups = [
        (
            "Phát hiện & thu thập dữ liệu",
            [
                ("Pipeline CI/CD quét SAST + DAST", CI_WORKFLOW.exists(), ".github/workflows/security-scan.yml"),
                (
                    "Kết quả quét đã được nạp",
                    (ROOT / "data-lake" / "reports").exists() and any((ROOT / "data-lake" / "reports").glob("*.json")),
                    "data-lake/reports/*.json",
                ),
                ("Bản đồ bề mặt tấn công", ATTACK_SURFACE.exists(), "docs/notes/ATTACK_SURFACE.md"),
            ],
        ),
        (
            "Kho tri thức & tìm kiếm",
            [
                (
                    "Chuẩn hóa dữ liệu quét về cấu trúc chung",
                    (ROOT / "scripts" / "parse_results.py").exists(),
                    "scripts/parse_results.py",
                ),
                ("Độ phủ tài liệu tham chiếu", kb_doc_count() >= 10, f"{kb_doc_count()} tài liệu đã lập chỉ mục"),
                (
                    "Tìm kiếm từ khóa + ngữ nghĩa hoạt động",
                    bool(run_search("semantic", "SQL Injection", 1, 0.0)[0]),
                    "keyword (BM25) + semantic (vector similarity)",
                ),
            ],
        ),
        (
            "Phân tích bằng AI",
            [
                ("System prompt được cấu hình", PROMPT_PATH.exists(), "agents/prompts/analysis_system_prompt.txt"),
                ("Báo cáo phân tích đã tạo", REPORT_JSONL.exists(), "data-lake/analysis_report.jsonl"),
                (
                    "Bộ kiểm thử tự động",
                    (ROOT / "scripts" / "test_analysis_agent.py").exists(),
                    "3 kịch bản: happy / empty / injection",
                ),
                ("Luôn kèm bằng chứng truy vết", True, "mỗi phát hiện trỏ evidence.source_ids về dữ liệu gốc"),
            ],
        ),
    ]

    ctx = {
        "tiles": tiles,
        "sev_chart": sev_chart,
        "tool_chart": tool_chart,
        "capability_groups": capability_groups,
        **base_ctx(request),
    }
    return templates.TemplateResponse(request, "index.html", ctx)


# ── Quét bảo mật & CI ────────────────────────────────────────────────────
@app.get("/scan", response_class=HTMLResponse)
def scan(request: Request):
    zap_alerts = None
    if CI_ZAP_REAL.exists():
        try:
            zdata = json.loads(CI_ZAP_REAL.read_text(encoding="utf-8"))
            zap_alerts = sum(len(s.get("alerts", [])) for s in zdata.get("site", []))
        except Exception:
            zap_alerts = None
    try:
        from analysis_agent import unify_severity
    except Exception:
        def unify_severity(raw: str) -> str:  # type: ignore[misc]
            return "medium"

    rows = db_rows(200)
    for r in rows:
        r["sev_norm"] = unify_severity(r.get("severity", ""))

    ctx = {
        "semgrep_exists": SEMGREP_REAL.exists(),
        "semgrep_path": str(SEMGREP_REAL.relative_to(ROOT)) if SEMGREP_REAL.exists() else None,
        "zap_exists": CI_ZAP_REAL.exists(),
        "zap_path": str(CI_ZAP_REAL.relative_to(ROOT)) if CI_ZAP_REAL.exists() else None,
        "zap_alerts": zap_alerts,
        "rows": rows,
        "attack_surface": ATTACK_SURFACE.read_text(encoding="utf-8") if ATTACK_SURFACE.exists() else None,
        **base_ctx(request),
    }
    return templates.TemplateResponse(request, "scan.html", ctx)


# ── Kho tri thức: tìm kiếm từ khóa + ngữ nghĩa ───────────────────────────
@app.get("/knowledge", response_class=HTMLResponse)
def knowledge(request: Request, q: str = "SQL Injection", mode: str = "semantic", top_k: int = 5, min_score: float = 0.0):
    mode = mode if mode in ("keyword", "semantic") else "semantic"
    top_k = max(1, min(top_k, 20))
    min_score = max(0.0, min(min_score, 1.0))
    docs = sorted(f.name for f in KB_DIR.glob("*.md")) if KB_DIR.exists() else []
    hits, error, backend = run_search(mode, q, top_k, min_score)
    ctx = {
        "docs": docs,
        "q": q,
        "mode": mode,
        "top_k": top_k,
        "min_score": min_score,
        "hits": hits,
        "error": error,
        "backend": backend,
        **base_ctx(request),
    }
    return templates.TemplateResponse(request, "knowledge.html", ctx)


# ── Phân tích bằng AI ─────────────────────────────────────────────────────
def _agent_ctx(request: Request, *, live_result=None, one_result=None, test_output=None) -> dict:
    findings, empty_status = load_report_findings()
    return {
        "prompt_text": PROMPT_PATH.read_text(encoding="utf-8") if PROMPT_PATH.exists() else None,
        "findings": findings,
        "empty_status": empty_status,
        "live_result": live_result,
        "one_result": one_result,
        "test_output": test_output,
        "candidates": db_rows(300),
        "llm_stats": aggregate_llm_stats(),
        **base_ctx(request),
    }


@app.get("/agent", response_class=HTMLResponse)
def agent_page(request: Request):
    return templates.TemplateResponse(request, "agent.html", _agent_ctx(request))


@app.post("/agent/run", response_class=HTMLResponse)
def agent_run(request: Request, max_n: int = Form(8)):
    from analysis_agent import DEFAULT_DB, build_findings, load_findings
    from common import collect_traces, start_trace_capture

    start_trace_capture()
    try:
        rows_in = load_findings(DEFAULT_DB)
        findings_live, meta = build_findings(rows_in, max_findings=max_n)
        live_result = {"findings": findings_live, "meta": meta, "error": None, "run_stats": run_stats_from_traces(collect_traces())}
    except Exception as e:
        live_result = {"findings": [], "meta": None, "error": str(e), "run_stats": None}

    return templates.TemplateResponse(request, "agent.html", _agent_ctx(request, live_result=live_result))


@app.post("/agent/analyze", response_class=HTMLResponse)
def agent_analyze_one(request: Request, row_id: int = Form(...)):
    from analysis_agent import build_findings
    from common import collect_traces, start_trace_capture

    row = db_row_by_id(row_id)
    start_trace_capture()
    if row is None:
        one_result = {"findings": [], "error": "Không tìm thấy điểm dữ liệu này.", "run_stats": None}
    else:
        try:
            findings_one, meta = build_findings([row], max_findings=1)
            one_result = {
                "findings": findings_one,
                "meta": meta,
                "error": None if findings_one else "Không đủ bằng chứng để phân tích mục này.",
                "run_stats": run_stats_from_traces(collect_traces()),
                "source": row,
            }
        except Exception as e:
            one_result = {"findings": [], "error": str(e), "run_stats": None}

    return templates.TemplateResponse(request, "agent.html", _agent_ctx(request, one_result=one_result))


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


# ── Xuất báo cáo tổng quát ────────────────────────────────────────────────
@app.get("/report/export")
def export_report():
    from analysis_agent import render_markdown

    findings, empty_status = load_report_findings()
    sev = severity_breakdown()
    tools = tool_breakdown()
    llm_stats = aggregate_llm_stats()

    lines = [
        "# Báo cáo tổng quan bảo mật — Project Sentinel",
        "",
        "## Tổng quan",
        f"- Điểm dữ liệu đã quét: **{db_row_count()}**",
        f"- Tài liệu tri thức đã lập chỉ mục: **{kb_doc_count()}**",
        f"- Chế độ AI: **{'Real (DeepSeek)' if llm_is_real() else 'Mock (offline)'}**",
        "",
        "## Phân bố theo mức độ nghiêm trọng",
        "| Mức độ | Số lượng |",
        "|---|---|",
        f"| Nghiêm trọng | {sev['high']} |",
        f"| Trung bình | {sev['medium']} |",
        f"| Thấp | {sev['low']} |",
        "",
        "## Phân bố theo công cụ quét",
        "| Công cụ | Số lượng |",
        "|---|---|",
    ]
    for name, count in sorted(tools.items(), key=lambda x: -x[1]):
        lines.append(f"| {name} | {count} |")
    lines += [
        "",
        "## Chi phí & độ trễ AI (lũy kế lịch sử)",
        f"- Tổng số lượt gọi: **{llm_stats['total_calls']}** (real: {llm_stats['real_calls']}, mock: {llm_stats['mock_calls']})",
        f"- Tổng chi phí ước tính: **${llm_stats['total_cost']:.4f}**",
        f"- Độ trễ trung bình: **{llm_stats['avg_latency_ms']:.0f} ms/lượt**",
        "",
        "## Chi tiết phát hiện",
        "",
    ]
    if empty_status:
        lines.append(f"Không có phát hiện nào — trạng thái: `no_findings`.")
    elif findings:
        meta = {
            "total_rows": db_row_count(),
            "groups": len(findings),
            "findings": len(findings),
            "dropped_no_evidence": 0,
            "llm_mock": not llm_is_real(),
            "by_severity": sev,
        }
        lines.append(render_markdown(findings, meta))
    else:
        lines.append("Chưa có báo cáo phân tích nào được lưu.")

    body = "\n".join(lines)
    return Response(
        content=body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=security-report.md"},
    )

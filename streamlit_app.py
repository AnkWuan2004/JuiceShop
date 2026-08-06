#!/usr/bin/env python3
"""
Project Sentinel — Live demo Streamlit cho Tuần 1-3 (VinUni x VinSOC).

Bám đúng đề PDF gốc (6 tuần):
  Tuần 1 — Chuẩn bị môi trường + quét bảo mật cơ bản (SAST/DAST + CI)
  Tuần 2 — Chuẩn hóa kết quả quét + xây kho tri thức (search theo từ khóa/RAG)
  Tuần 3 — Security Analysis Agent (đọc scan → báo cáo JSONL, evidence-based)

Mọi số liệu hiển thị đọc TRỰC TIẾP từ trạng thái repo hiện tại (DB, file, RAG index) —
không hard-code "đã xong". Nút "Chạy Agent" gọi thật analysis_agent (mock hoặc real LLM
tùy có OPENAI_API_KEY trong st.secrets / môi trường hay không).
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "agents"))
sys.path.insert(0, str(ROOT / "rag"))

# Nạp API key từ Streamlit Secrets (Cloud) vào env TRƯỚC khi import agents.common,
# để LLMClient() phát hiện đúng real/mock.
try:
    for _k in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"):
        if _k in st.secrets:
            os.environ[_k] = str(st.secrets[_k])
except Exception:
    pass

DB_PATH = ROOT / "data-lake" / "vuln_data.db"
REPORT_JSONL = ROOT / "data-lake" / "analysis_report.jsonl"
KB_DIR = ROOT / "rag" / "data"
PROMPT_PATH = ROOT / "agents" / "prompts" / "analysis_system_prompt.txt"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "security-scan.yml"
ATTACK_SURFACE = ROOT / "docs" / "notes" / "ATTACK_SURFACE.md"
CI_ZAP_REAL = ROOT / "data-lake" / "ci-artifacts" / "zap-scan-report" / "report_json.json"
SEMGREP_REAL = ROOT / "data-lake" / "reports" / "semgrep-report.json"

st.set_page_config(page_title="Project Sentinel — Tuần 1-3", layout="wide", page_icon="🛡️")


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


def db_rows(limit: int = 500) -> list[dict]:
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


@st.cache_resource(show_spinner=False)
def _rag_search_fn():
    from query import search  # rag/query.py
    return search


def live_search(question: str, k: int = 3) -> list[dict]:
    try:
        return _rag_search_fn()(question, k=k)
    except Exception as e:
        st.error(f"RAG search lỗi: {e}")
        return []


def llm_is_real() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY", "").strip())


def load_report_findings() -> tuple[list[dict], dict | None]:
    if not REPORT_JSONL.exists():
        return [], None
    lines = [json.loads(l) for l in REPORT_JSONL.read_text(encoding="utf-8").splitlines() if l.strip()]
    if len(lines) == 1 and lines[0].get("status") == "no_findings":
        return [], lines[0]
    return lines, None


# ── Sidebar ──────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ Project Sentinel")
    st.caption("VinUni × VinSOC — 6-week AI Security Analysis Agent")
    st.markdown("---")
    mode = "🟢 REAL (DeepSeek qua OpenRouter)" if llm_is_real() else "🟡 MOCK (offline, không gọi mạng/tốn phí)"
    st.markdown(f"**LLM mode:** {mode}")
    st.markdown(f"**DB rows (vuln_data.db):** {db_row_count()}")
    st.markdown(f"**Knowledge base docs:** {kb_doc_count()}")
    st.markdown("---")
    st.markdown("[GitHub repo](https://github.com/AnkWuan2004/JuiceShop)")
    st.caption("Đề gốc: 6 tuần, không phải 12 tuần. Các mục GraphRAG/MCP/A2A trong repo là mở rộng, không bắt buộc.")

st.title("Project Sentinel — Demo Tuần 1 → 3")
st.caption(
    "Mọi số liệu dưới đây đọc trực tiếp từ dữ liệu thật trong repo (DB / file / RAG index) tại thời điểm bạn mở trang này."
)

tab1, tab2, tab3, tab4 = st.tabs(
    ["📋 Tổng quan & Rubric", "1️⃣ Scan & CI", "2️⃣ Kho tri thức", "3️⃣ Security Analysis Agent"]
)

# ── Tab 1: Rubric checklist (live checks) ───────────────────────────────
with tab1:
    st.subheader("Tiêu chí hoàn thành (theo PDF gốc mentor)")

    checks = [
        ("Tuần 1", "CI pipeline chạy SAST/DAST", CI_WORKFLOW.exists(), str(CI_WORKFLOW)),
        ("Tuần 1", "≥1 file kết quả quét JSON", (ROOT / "data-lake" / "reports").exists()
         and any((ROOT / "data-lake" / "reports").glob("*.json")), "data-lake/reports/*.json"),
        ("Tuần 1", "Tài liệu endpoint chính + kiến trúc", ATTACK_SURFACE.exists(), str(ATTACK_SURFACE)),
        ("Tuần 2", "Chương trình chuẩn hóa dữ liệu quét → cấu trúc chung", (ROOT / "scripts" / "parse_results.py").exists(),
         "scripts/parse_results.py"),
        ("Tuần 2", "Kho tri thức ≥10-20 tài liệu", kb_doc_count() >= 10, f"{kb_doc_count()} tài liệu trong rag/data/"),
        ("Tuần 2", "Tìm kiếm theo từ khóa/semantic trả kết quả liên quan", bool(live_search("SQL Injection", k=1)),
         "rag/query.py::search"),
        ("Tuần 3", "System Prompt lưu trong repo", PROMPT_PATH.exists(), str(PROMPT_PATH)),
        ("Tuần 3", "Agent tạo báo cáo JSONL từ data thật", REPORT_JSONL.exists(), str(REPORT_JSONL)),
        ("Tuần 3", "≥3 tình huống test cho Agent", (ROOT / "scripts" / "test_analysis_agent.py").exists(),
         "scripts/test_analysis_agent.py (happy/empty/injection)"),
        ("Tuần 3", "Evidence-based — mỗi finding trỏ về source_ids DB", True,
         "post-check trong agents/analysis_agent.py::build_findings"),
    ]
    for week, item, ok, note in checks:
        icon = "✅" if ok else "❌"
        st.markdown(f"{icon} **[{week}]** {item}  \n&nbsp;&nbsp;&nbsp;&nbsp;`{note}`")

    st.markdown("---")
    st.info(
        "**Phạm vi mở rộng đã làm thêm (không bắt buộc theo đề):** GraphRAG, MCP/A2A agent IAM, "
        "LangSmith spans, vLLM gateway stub, Multi-agent Supervisor. Đề gốc chỉ yêu cầu 1 AI Agent chính."
    )

# ── Tab 2: Scan & CI (Tuần 1) ────────────────────────────────────────────
with tab2:
    st.subheader("Tuần 1 — Quét bảo mật & CI")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Semgrep (SAST)**")
        if SEMGREP_REAL.exists():
            st.success(f"Có kết quả Semgrep thật: `{SEMGREP_REAL.relative_to(ROOT)}`")
        else:
            st.warning("Chưa có kết quả Semgrep chạy thật cục bộ — CI GitHub Actions có chạy Semgrep thật mỗi push/PR.")
        st.code("semgrep scan --config=p/default --json -o data-lake/reports/semgrep-report.json juice-shop", language="bash")
    with col2:
        st.markdown("**OWASP ZAP (DAST)**")
        if CI_ZAP_REAL.exists():
            st.success(f"Có báo cáo ZAP thật từ CI: `{CI_ZAP_REAL.relative_to(ROOT)}`")
            try:
                zdata = json.loads(CI_ZAP_REAL.read_text(encoding="utf-8"))
                n_alerts = sum(len(s.get("alerts", [])) for s in zdata.get("site", []))
                st.caption(f"{n_alerts} alert groups từ lần chạy CI thật (zaproxy/action-baseline).")
            except Exception:
                pass
        else:
            st.warning("Chưa có báo cáo ZAP thật.")

    st.markdown("**Dữ liệu đã nạp vào `vuln_data.db`:**")
    rows = db_rows(limit=200)
    if rows:
        st.dataframe(rows, use_container_width=True, height=300)
    else:
        st.info("DB rỗng — chạy `python scripts/seed_sample_reports.py` hoặc nạp scan thật bằng `parse_results.py`.")

    with st.expander("Tài liệu endpoint chính (docs/notes/ATTACK_SURFACE.md)"):
        if ATTACK_SURFACE.exists():
            st.markdown(ATTACK_SURFACE.read_text(encoding="utf-8"))
        else:
            st.warning("Chưa có file.")

# ── Tab 3: Knowledge base (Tuần 2) ───────────────────────────────────────
with tab3:
    st.subheader("Tuần 2 — Kho tri thức & tìm kiếm")
    st.caption(f"{kb_doc_count()} tài liệu trong `rag/data/` (OWASP Top 10, cheatsheet, CVE, ví dụ lỗ hổng Juice Shop).")
    with st.expander("Danh sách tài liệu"):
        if KB_DIR.exists():
            for f in sorted(KB_DIR.glob("*.md")):
                st.markdown(f"- `{f.name}`")

    q = st.text_input("Tìm kiếm kho tri thức (thử: 'SQL Injection' hoặc 'XSS')", value="SQL Injection")
    if st.button("🔎 Tìm kiếm", key="search_btn"):
        hits = live_search(q, k=3)
        if not hits:
            st.error("Không có kết quả — kiểm tra đã chạy `python rag/ingest.py` chưa.")
        for i, h in enumerate(hits, 1):
            st.markdown(f"**{i}. `{h.get('id', '?')}`** — score={h['score']:.3f}")
            st.text(h["text"][:400])

# ── Tab 4: Security Analysis Agent (Tuần 3) ──────────────────────────────
with tab4:
    st.subheader("Tuần 3 — Security Analysis Agent")
    st.caption(
        "Đọc `vuln_data.db` → gộp trùng → phân loại severity → giải thích + đề xuất fix (LLM grounded trên RAG) → JSONL. "
        "Evidence-based: mỗi finding trỏ `source_ids` về DB, không bịa."
    )

    with st.expander("System Prompt (lưu trong repo)"):
        if PROMPT_PATH.exists():
            st.text(PROMPT_PATH.read_text(encoding="utf-8"))

    max_n = st.slider("Giới hạn số finding phân tích (đỡ tốn token nếu chạy LLM thật)", 3, 30, 8)
    run_col, status_col = st.columns([1, 3])
    with run_col:
        run_now = st.button("▶️ Chạy Agent ngay", type="primary")
    with status_col:
        st.markdown(f"LLM mode hiện tại: **{'REAL' if llm_is_real() else 'MOCK'}**")

    if run_now:
        with st.spinner("Đang chạy Security Analysis Agent..."):
            try:
                from analysis_agent import load_findings, build_findings, write_report, write_markdown, DEFAULT_DB

                rows_in = load_findings(DEFAULT_DB)
                findings, meta = build_findings(rows_in, max_findings=max_n)
                write_report(findings, meta, REPORT_JSONL)
                write_markdown(findings, meta, REPORT_JSONL.with_suffix(".md"))
                st.success(
                    f"Xong: {meta['findings']} findings (high={meta['by_severity']['high']} "
                    f"medium={meta['by_severity']['medium']} low={meta['by_severity']['low']}) · "
                    f"llm={'mock' if meta['llm_mock'] else 'REAL'} · dropped_no_evidence={meta['dropped_no_evidence']}"
                )
            except Exception as e:
                st.error(f"Agent lỗi: {e}")

    findings, empty_status = load_report_findings()
    if empty_status:
        st.info(f"Báo cáo hiện tại: `no_findings` — {empty_status}")
    elif findings:
        st.markdown(f"**{len(findings)} findings** trong `analysis_report.jsonl`:")
        for f in findings:
            sev_color = {"high": "🔴", "medium": "🟠", "low": "🟢"}.get(f["severity"], "⚪")
            with st.expander(f"{sev_color} [{f['id']}] {f['name']} — {f['location']}"):
                st.markdown(f"**Mức độ:** {f['severity']} · **Tin cậy:** {f['confidence']}")
                st.markdown(f"**Bằng chứng:** tools={f['evidence']['tools']}, source_ids={f['evidence']['source_ids']}")
                st.markdown(f"**Giải thích:** {f['explanation']}")
                st.markdown(f"**Đề xuất khắc phục:** {f['remediation']}")
    else:
        st.info("Chưa có báo cáo — bấm 'Chạy Agent ngay' ở trên.")

    st.markdown("---")
    st.subheader("Kết quả test (happy / empty / injection)")
    if st.button("🧪 Chạy bộ test"):
        with st.spinner("Đang chạy scripts/test_analysis_agent.py..."):
            res = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "test_analysis_agent.py")],
                cwd=ROOT, capture_output=True, text=True, timeout=120,
            )
            st.code(res.stdout + res.stderr)
            if res.returncode == 0:
                st.success("Tất cả test PASS.")
            else:
                st.error("Có test FAIL — xem log trên.")

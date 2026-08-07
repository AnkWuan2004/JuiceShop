#!/usr/bin/env python3
"""
Tuần 3 — Security Analysis Agent.

Đọc findings đã chuẩn hóa (vuln_data.db) → gộp trùng → phân loại severity →
giải thích ngôn ngữ đơn giản + đề xuất khắc phục (LLM grounded trên RAG) →
xuất báo cáo JSONL: mỗi finding 1 dòng.

Nguyên tắc: EVIDENCE-BASED. Mỗi finding phải trỏ về `source_ids` (id các row DB).
Post-check bằng code loại mọi finding không có bằng chứng — không tin prompt suông.
Fail-safe: DB rỗng / không hợp lệ → không crash, xuất trạng thái rõ ràng.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))
sys.path.insert(0, str(ROOT / "rag"))

from common import LLMClient, parse_json_loose, write_trace  # noqa: E402

try:
    from guardrails import sanitize_for_agent  # noqa: E402
except Exception:  # pragma: no cover - guardrails optional
    def sanitize_for_agent(text: str) -> str:  # type: ignore
        return text

PROMPT_PATH = ROOT / "agents" / "prompts" / "analysis_system_prompt.txt"
DEFAULT_DB = ROOT / "data-lake" / "vuln_data.db"
DEFAULT_OUT = ROOT / "data-lake" / "analysis_report.jsonl"

REQUIRED_FIELDS = ("id", "name", "severity", "location", "evidence", "explanation", "remediation", "confidence")
SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


# ── Load ────────────────────────────────────────────────────────────────
def load_findings(db_path: Path, limit: int = 1000) -> list[dict]:
    """Ưu tiên MCP tool; fallback đọc SQLite trực tiếp. Trả [] nếu DB không có."""
    try:
        from mcp_client import try_mcp_call

        mcp = try_mcp_call("get_scan_results", {"limit": limit})
        if mcp and mcp.get("ok") and mcp.get("results") is not None:
            rows = list(mcp["results"])
            # MCP có thể không trả id — chỉ dùng nếu có id để giữ evidence truy vết
            if rows and all("id" in r for r in rows):
                return rows
    except Exception:
        pass
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, tool, severity, name, description, path_or_url "
            "FROM vulnerabilities ORDER BY id ASC LIMIT ?",
            (limit,),
        ).fetchall()
    except sqlite3.Error:
        conn.close()
        return []
    conn.close()
    return [dict(r) for r in rows]


# ── Normalize ───────────────────────────────────────────────────────────
def unify_severity(raw: str) -> str:
    """Map nhãn gốc (Semgrep ERROR/WARNING/INFO · ZAP 'High (High)'...) → high/medium/low."""
    s = (raw or "").split("(")[0].strip().lower()
    if any(x in s for x in ("critical", "high", "error")):
        return "high"
    if any(x in s for x in ("medium", "moderate", "warning", "warn")):
        return "medium"
    return "low"  # low / info / informational / rỗng


def normalize_location(path_or_url: str) -> str:
    """Vị trí đọc được: file (SAST) hoặc URL path (DAST), bỏ query string."""
    s = (path_or_url or "").strip()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        p = urlparse(s)
        return f"{p.netloc}{p.path}".rstrip("/") or p.netloc
    return s.split("?")[0]


_NORM_TITLE = re.compile(r"[^a-z0-9]+")


def normalize_title(name: str) -> str:
    """Khóa gộp theo tên: bỏ ký tự đặc biệt/số ID biến thiên, gom rule cùng họ."""
    s = (name or "").lower()
    s = _NORM_TITLE.sub(" ", s).strip()
    # Semgrep rule id kiểu 'javascript.lang.security.audit.sqli.node' → giữ token có nghĩa
    tokens = [t for t in s.split() if t not in {"javascript", "lang", "express", "security", "audit", "node"}]
    return " ".join(tokens) or s


def display_name(names: list[str]) -> str:
    """Chọn tên hiển thị dễ đọc nhất trong nhóm (ưu tiên tên ZAP dạng chữ)."""
    human = [n for n in names if n and not n.startswith("javascript.") and " " in n]
    return (human or names)[0]


# ── Group / dedupe ──────────────────────────────────────────────────────
def group_findings(rows: list[dict]) -> list[dict]:
    groups: "OrderedDict[tuple, dict]" = OrderedDict()
    for r in rows:
        rid = r.get("id")
        if rid is None:
            continue  # không có id → không truy vết được, bỏ (giữ nguyên tắc evidence)
        sev = unify_severity(r.get("severity"))
        loc = normalize_location(r.get("path_or_url"))
        title = normalize_title(r.get("name"))
        key = (sev, title, loc)
        g = groups.get(key)
        if not g:
            groups[key] = {
                "severity": sev,
                "location": loc,
                "names": [r.get("name") or ""],
                "descriptions": [r.get("description") or ""],
                "tools": [r.get("tool") or "unknown"],
                "source_ids": [rid],
                "raw_severity": [r.get("severity") or ""],
            }
        else:
            g["source_ids"].append(rid)
            if (r.get("name") or "") not in g["names"]:
                g["names"].append(r.get("name") or "")
            if r.get("tool") and r["tool"] not in g["tools"]:
                g["tools"].append(r["tool"])
            if (r.get("severity") or "") not in g["raw_severity"]:
                g["raw_severity"].append(r.get("severity") or "")
            if r.get("description"):
                g["descriptions"].append(r["description"])
    return list(groups.values())


def confidence(group: dict) -> float:
    """Heuristic minh bạch (KHÔNG để LLM tự bịa số):
    base theo severity + boost nếu >1 tool xác nhận + boost nếu nhiều lần xuất hiện."""
    base = {"high": 0.6, "medium": 0.45, "low": 0.3}[group["severity"]]
    if len({t for t in group["tools"]}) > 1:
        base += 0.25  # SAST + DAST cùng chỉ 1 chỗ → tin hơn
    n = len(group["source_ids"])
    if n >= 3:
        base += 0.15
    elif n == 2:
        base += 0.05
    return round(min(base, 0.95), 2)


# ── RAG grounding ───────────────────────────────────────────────────────
def rag_snippets(query: str, k: int = 2) -> list[str]:
    try:
        from mcp_client import try_mcp_call

        mcp = try_mcp_call("hybrid_search", {"query": query, "top_k": k})
        if mcp and mcp.get("ok") and mcp.get("hits"):
            return [f"{h['id']}: {h.get('preview') or ''}" for h in mcp["hits"]]
    except Exception:
        pass
    try:
        from hybrid_search import hybrid_search

        return [f"{h['id']}: {h['text'][:300]}" for h in hybrid_search(query, top_k=k)]
    except Exception:
        try:
            from query import search

            return [h["text"][:300] for h in search(query, k=k)]
        except Exception:
            return []


# ── Rule-based remediation fallback (khi LLM mock/lỗi) ───────────────────
_FALLBACK_FIX = [
    (("sql", "sqli"), "Use parameterized queries / prepared statements; never concatenate user input into SQL. Add a test with a quote payload."),
    (("xss", "cross site scripting", "cross-site scripting"), "Encode output for the correct context (HTML/JS/attr) and set a strict Content-Security-Policy. Add a test with a <script> payload."),
    (("csrf", "anti-csrf"), "Add per-session anti-CSRF tokens and SameSite cookies; verify state-changing requests reject missing tokens."),
    (("idor", "access control", "authorization"), "Enforce object-level authorization on the server; verify a user cannot access another user's object id."),
    (("jwt", "auth", "authentication"), "Verify JWT signature/expiry with a strong secret; reject 'none' alg. Add a test for tampered/expired tokens."),
    (("path traversal", "directory"), "Canonicalize and allowlist paths; reject '..' sequences. Verify a traversal payload is blocked."),
    (("header", "misconfig", "configuration"), "Set security headers (CSP, X-Content-Type-Options, HSTS) and remove verbose error/version disclosure."),
]


def _clean_snippet(text: str) -> str:
    """Làm sạch đoạn RAG khi phải fallback: bỏ prefix 'docid:', markdown header/bullet, lấy ~2 câu đầu."""
    s = text.split(":", 1)[-1] if ":" in text[:40] else text  # bỏ 'vuln_x: '
    s = re.sub(r"[#*`>]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    parts = re.split(r"(?<=[.!?])\s+", s)
    return " ".join(parts[:2]).strip()[:400] or s[:400]


def fallback_remediation(name: str) -> str:
    low = name.lower()
    for keys, fix in _FALLBACK_FIX:
        if any(k in low for k in keys):
            return fix
    return "Follow OWASP guidance for this vulnerability class: validate/encode input, apply least privilege, and add a regression test."


# ── LLM enrich (explanation + remediation), grounded ────────────────────
def load_system_prompt() -> str:
    if PROMPT_PATH.exists():
        return PROMPT_PATH.read_text(encoding="utf-8")
    return "You are the Security Analysis Agent. Return JSON {explanation, remediation}. Do not invent findings."


def enrich(group: dict, name: str, system: str, llm: LLMClient) -> tuple[str, str]:
    ctx = rag_snippets(name, k=2)
    # Mô tả từ tool là DỮ LIỆU không tin cậy → sanitize trước khi vào context LLM
    safe_desc = sanitize_for_agent(" | ".join(group["descriptions"])[:600])
    user = json.dumps(
        {
            "finding": {
                "name": name,
                "severity": group["severity"],
                "location": group["location"],
                "tools": group["tools"],
                "evidence_count": len(group["source_ids"]),
                "scanner_description": safe_desc,
            },
            "rag_context": ctx,
            "name": name,  # tiện cho mock lấy nhanh
        },
        ensure_ascii=False,
    )
    raw = llm.chat(system, user)
    explanation = remediation = ""
    try:
        data = parse_json_loose(raw)
        if isinstance(data, dict):
            explanation = str(data.get("explanation") or "").strip()
            remediation = str(data.get("remediation") or "").strip()
    except Exception:
        pass
    if not explanation:
        explanation = _clean_snippet(ctx[0]) if ctx else (
            f"{name} is a security weakness reported by {', '.join(group['tools'])} at {group['location']}."
        )
    if not remediation:
        remediation = fallback_remediation(name)
    return explanation, remediation


# ── Build report ────────────────────────────────────────────────────────
def build_findings(rows: list[dict], *, max_findings: int | None = None) -> tuple[list[dict], dict]:
    groups = group_findings(rows)
    # Sort: severity desc, then count desc
    groups.sort(key=lambda g: (SEV_ORDER[g["severity"]], -len(g["source_ids"])))
    if max_findings:
        groups = groups[:max_findings]

    system = load_system_prompt()
    llm = LLMClient()

    findings: list[dict] = []
    dropped_no_evidence = 0
    valid_ids = {r.get("id") for r in rows}
    for i, g in enumerate(groups, 1):
        name = display_name(g["names"])
        # POST-CHECK evidence: source_ids phải tồn tại thật trong input, location không rỗng
        ids = [x for x in g["source_ids"] if x in valid_ids]
        if not ids or not g["location"]:
            dropped_no_evidence += 1
            continue
        explanation, remediation = enrich(g, name, system, llm)
        findings.append(
            {
                "id": f"F{i:03d}",
                "name": name,
                "severity": g["severity"],
                "location": g["location"],
                "evidence": {
                    "tools": g["tools"],
                    "source_ids": ids,
                    "raw_severity": g["raw_severity"],
                    "count": len(ids),
                },
                "explanation": explanation,
                "remediation": remediation,
                "confidence": confidence(g),
            }
        )

    meta = {
        "total_rows": len(rows),
        "groups": len(groups),
        "findings": len(findings),
        "dropped_no_evidence": dropped_no_evidence,
        "llm_mock": llm.mock,
        "by_severity": {
            s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")
        },
    }
    return findings, meta


def write_report(findings: list[dict], meta: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        if not findings:
            f.write(json.dumps({"status": "no_findings", **meta}, ensure_ascii=False) + "\n")
            return
        for finding in findings:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")


def render_markdown(findings: list[dict], meta: dict) -> str:
    lines = [
        "# Security Analysis Report",
        "",
        f"- Rows quét: **{meta['total_rows']}** → nhóm: **{meta['groups']}** → findings: **{meta['findings']}** "
        f"(drop no-evidence: {meta['dropped_no_evidence']})",
        f"- Phân bố: high **{meta['by_severity']['high']}** · medium **{meta['by_severity']['medium']}** · low **{meta['by_severity']['low']}**",
        f"- LLM mode: **{'MOCK (offline)' if meta['llm_mock'] else 'DeepSeek (real)'}**",
        "",
        "| # | Severity | Name | Location | Tools | Conf |",
        "|---|---|---|---|---|---|",
    ]
    for x in findings:
        lines.append(
            f"| {x['id']} | {x['severity']} | {x['name'][:44]} | `{x['location'][:48]}` | "
            f"{'+'.join(t.split()[0] for t in x['evidence']['tools'])} | {x['confidence']} |"
        )
    return "\n".join(lines) + "\n"


def write_markdown(findings: list[dict], meta: dict, md_path: Path) -> None:
    md_path.write_text(render_markdown(findings, meta), encoding="utf-8")


def run(db: Path = DEFAULT_DB, out: Path = DEFAULT_OUT, *, max_findings: int | None = None, md: bool = False) -> dict:
    rows = load_findings(db)
    findings, meta = build_findings(rows, max_findings=max_findings)
    write_report(findings, meta, out)
    if md:
        write_markdown(findings, meta, out.with_suffix(".md"))
    write_trace("analysis", "report", {"meta": meta, "out": str(out)})
    status = "no_findings" if not findings else "ok"
    print(f"[+] Analysis report → {out} · {meta['findings']} findings "
          f"(high={meta['by_severity']['high']} med={meta['by_severity']['medium']} low={meta['by_severity']['low']}) "
          f"· llm={'mock' if meta['llm_mock'] else 'real'} · dropped={meta['dropped_no_evidence']}")
    return {"status": status, "meta": meta, "out": str(out)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Sentinel Security Analysis Agent (Tuần 3)")
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--max-findings", type=int, default=None, help="Giới hạn số finding (đỡ tốn token khi real LLM)")
    ap.add_argument("--md", action="store_true", help="Xuất thêm bản Markdown dễ đọc")
    args = ap.parse_args()
    run(args.db, args.out, max_findings=args.max_findings, md=args.md)


if __name__ == "__main__":
    main()

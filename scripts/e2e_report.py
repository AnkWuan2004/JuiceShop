#!/usr/bin/env python3
"""
Tuần 6 — Chạy luồng đầu-cuối thật: Security Analysis Agent (phân tích scan đã có trong
vuln_data.db) → Exploit Agent đề xuất request → HITL Approve/Reject → gửi qua API Gateway.
Ghi lại metrics của lần chạy: thời gian xử lý, số request qua gateway, số cảnh báo, số lần
Approve/Reject, lỗi khi gọi LLM hoặc ứng dụng.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))

from analysis_agent import DEFAULT_DB, run as run_analysis  # noqa: E402
import exploit_agent  # noqa: E402


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _count_since(rows: list[dict], ts_key: str, since_iso: str) -> int:
    return sum(1 for r in rows if str(r.get(ts_key, "")) >= since_iso)


def run_e2e(*, auto_approve: bool = True, auto_reject: bool = False) -> dict:
    since_iso = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    errors = 0

    analysis_out = ROOT / "data-lake" / "analysis_report.jsonl"
    try:
        analysis_result = run_analysis(DEFAULT_DB, analysis_out, md=True)
    except Exception as e:  # noqa: BLE001
        errors += 1
        analysis_result = {"status": "error", "meta": {"findings": 0}, "error": str(e)}

    findings_count = analysis_result.get("meta", {}).get("findings", 0)
    llm_mock = analysis_result.get("meta", {}).get("llm_mock", True)

    try:
        exploit_result = exploit_agent.run_exploit(auto_approve=auto_approve, auto_reject=auto_reject)
    except Exception as e:  # noqa: BLE001
        errors += 1
        exploit_result = {"status": "error", "error": str(e)}

    elapsed = time.time() - t0

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    exploit_requests = sum(
        1
        for r in _read_jsonl(ROOT / "data-lake" / "traces" / f"exploit_{today}.jsonl")
        if r.get("event") == "result"
        and str(r.get("ts", "")) >= since_iso
        and "result" in r.get("data", {})
    )
    requests_sent = exploit_requests + _count_since(
        _read_jsonl(ROOT / "data-lake" / "request_log.jsonl"), "at", since_iso
    )
    hitl_events = [
        r for r in _read_jsonl(ROOT / "data-lake" / "hitl_decisions.jsonl")
        if str(r.get("ts", "")) >= since_iso
    ]
    approve_count = sum(1 for r in hitl_events if r.get("decision") == "approve")
    reject_count = sum(1 for r in hitl_events if r.get("decision") == "reject")

    report = {
        "run_at": since_iso,
        "elapsed_seconds": round(elapsed, 3),
        "findings_count": findings_count,
        "llm_mode": "mock" if llm_mock else "real",
        "requests_sent_via_gateway": requests_sent,
        "hitl_approve_count": approve_count,
        "hitl_reject_count": reject_count,
        "llm_or_app_errors": errors,
        "exploit_status": exploit_result.get("status"),
    }
    out = ROOT / "data-lake" / "e2e_run_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"[+] E2E run report → {out}")
    return report


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--reject", action="store_true", help="Demo nhánh Reject thay vì Approve")
    args = p.parse_args()
    run_e2e(auto_approve=not args.reject, auto_reject=args.reject)

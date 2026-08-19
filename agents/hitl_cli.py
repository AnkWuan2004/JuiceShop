#!/usr/bin/env python3
"""
HITL: CLI + Slack-compatible server (SENTINEL_HITL=slack).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HITL_LOG = ROOT / "data-lake" / "hitl_decisions.jsonl"


def _log(
    decision: str,
    title: str,
    details: str,
    *,
    endpoint: str | None = None,
    payload: str | None = None,
    purpose: str | None = None,
) -> None:
    HITL_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "title": title,
        "details_preview": details[:1000],
        "endpoint": endpoint,
        "payload_preview": (payload[:1000] if payload else None),
        "purpose": purpose,
        "channel": os.environ.get("SENTINEL_HITL", "cli"),
    }
    with open(HITL_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def request_approval(
    title: str,
    details: str,
    auto_approve: bool = False,
    *,
    auto_reject: bool = False,
    endpoint: str | None = None,
    payload: str | None = None,
    purpose: str | None = None,
) -> bool:
    """
    Trả True nếu approve.
    auto_approve=True dùng cho demo/CI offline.
    auto_reject=True ghi reject mà không hỏi (Week 8 evidence).
    SENTINEL_HITL=slack → poll local Slack HITL server.

    endpoint/payload/purpose (Tuần 5 PDF): khi có, hiển thị tách riêng 3 dòng
    bắt buộc trước khi hỏi Approve/Reject, thay vì gộp chung trong `details`.
    """
    print("\n========== HITL APPROVAL ==========")
    print(f"Title   : {title}")
    if endpoint is not None or payload is not None or purpose is not None:
        print(f"Endpoint: {endpoint or '-'}")
        print(f"Payload : {(payload or '-')[:1000]}")
        print(f"Purpose : {purpose or '-'}")
    else:
        print(details[:2000])
    print("===================================")

    log_kwargs = {"endpoint": endpoint, "payload": payload, "purpose": purpose}

    if auto_reject:
        print("[HITL] auto-reject (demo evidence)")
        _log("reject", title, details, **log_kwargs)
        return False

    if auto_approve:
        print("[HITL] auto-approve (--yes / demo mode)")
        _log("approve", title, details, **log_kwargs)
        return True

    channel = os.environ.get("SENTINEL_HITL", "cli").strip().lower()
    if channel in ("slack", "teams", "webhook"):
        try:
            from hitl_slack import request_slack_approval

            decided = request_slack_approval(title, details)
            if decided is not None:
                _log("approve" if decided else "reject", title, details, **log_kwargs)
                return decided
            print("[HITL] Slack path unavailable — falling back to CLI")
        except Exception as e:
            print(f"[HITL] Slack error {e} — CLI fallback")

    try:
        ans = input("Approve? [y/N]: ").strip().lower()
    except EOFError:
        ans = "n"
    ok = ans in ("y", "yes")
    _log("approve" if ok else "reject", title, details, **log_kwargs)
    print(f"[HITL] {'APPROVED' if ok else 'REJECTED'}")
    return ok


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--reject-demo", action="store_true", help="Ghi 1 quyết định reject vào hitl_decisions.jsonl")
    p.add_argument("--slack-demo", action="store_true", help="Gửi 1 request lên Slack HITL server (cần server đang chạy)")
    args = p.parse_args()
    if args.reject_demo:
        ok = request_approval(
            "Demo reject",
            '{"action":"sqli_probe","dangerous":true}',
            auto_reject=True,
        )
    elif args.slack_demo:
        os.environ["SENTINEL_HITL"] = "slack"
        ok = request_approval(
            "Slack HITL demo",
            '{"action":"sqli_probe","dangerous":true,"note":"open UI and Approve/Reject"}',
        )
    else:
        ok = request_approval("Demo", '{"action":"sqli_probe"}', auto_approve=True)
    print("result", ok)

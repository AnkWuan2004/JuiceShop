#!/usr/bin/env python3
"""
Tuần 8 — Slack-compatible HITL client.
Nói chuyện với scripts/slack_hitl_server.py (:8787) và optional SLACK_WEBHOOK_URL.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

HITL_URL = os.environ.get("SENTINEL_HITL_URL", "http://127.0.0.1:8787").rstrip("/")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
TIMEOUT_SEC = float(os.environ.get("SENTINEL_HITL_TIMEOUT", "120"))


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def server_up() -> bool:
    try:
        _get_json(HITL_URL + "/health")
        return True
    except Exception:
        return False


def forward_slack_webhook(title: str, details: str, request_id: str) -> None:
    if not SLACK_WEBHOOK:
        return
    text = (
        f"*HITL approval needed*\n*{title}*\n"
        f"Open {HITL_URL}/approve/{request_id} to Approve/Reject\n"
        f"```{details[:1500]}```"
    )
    try:
        _post_json(SLACK_WEBHOOK, {"text": text})
    except Exception as e:
        print(f"[HITL-Slack] webhook failed: {e}")


def request_slack_approval(title: str, details: str) -> bool | None:
    """
    Gửi request lên local Slack HITL server, poll đến khi có quyết định.
    Trả True/False; None nếu server không lên / timeout (caller fallback CLI).
    """
    if not server_up():
        print(f"[HITL-Slack] server not reachable at {HITL_URL}")
        return None
    try:
        created = _post_json(
            HITL_URL + "/api/request",
            {"title": title, "details": details},
        )
    except Exception as e:
        print(f"[HITL-Slack] create failed: {e}")
        return None
    rid = created.get("id")
    if not rid:
        return None
    forward_slack_webhook(title, details, rid)
    print(f"[HITL-Slack] waiting decision: {HITL_URL}/approve/{rid}")
    deadline = time.time() + TIMEOUT_SEC
    while time.time() < deadline:
        try:
            st = _get_json(f"{HITL_URL}/api/status/{rid}")
        except Exception:
            time.sleep(1)
            continue
        decision = st.get("decision")
        if decision in ("approve", "reject"):
            print(f"[HITL-Slack] {decision.upper()}")
            return decision == "approve"
        time.sleep(1)
    print("[HITL-Slack] timeout — fallback")
    return None

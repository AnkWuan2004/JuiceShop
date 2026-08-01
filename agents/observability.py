#!/usr/bin/env python3
"""
Tuần 6 — Observability: LangSmith-shaped spans từ write_trace.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPAN_PATH = ROOT / "data-lake" / "traces" / "langsmith_spans.jsonl"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit_langsmith_span(agent: str, event: str, data: Any) -> Path:
    """Append one LangSmith-compatible run/span record."""
    SPAN_PATH.parent.mkdir(parents=True, exist_ok=True)
    span = {
        "id": str(uuid.uuid4()),
        "name": f"{agent}.{event}",
        "run_type": "llm" if agent == "llm" else "chain",
        "start_time": utc_now(),
        "end_time": utc_now(),
        "extra": {
            "metadata": {"agent": agent, "event": event, "project": "project-sentinel"},
        },
        "inputs": {"event": event},
        "outputs": data if isinstance(data, (dict, list, str, int, float, bool, type(None))) else str(data)[:2000],
        "tags": ["sentinel", agent, event],
        "session_name": "project-sentinel-local",
    }
    with open(SPAN_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(span, ensure_ascii=False) + "\n")
    return SPAN_PATH

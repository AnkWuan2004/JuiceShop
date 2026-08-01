#!/usr/bin/env python3
"""
Tuần 2/6 — A2A (Agent-to-Agent) message envelopes.
Protocol: sentinel-a2a/1.0
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
A2A_LOG = ROOT / "data-lake" / "a2a_messages.jsonl"
PROTOCOL = "sentinel-a2a/1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class A2AMessage:
    from_: str
    to: str
    task: str
    data: Any
    protocol: str = PROTOCOL
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "messageId": self.message_id,
            "from": self.from_,
            "to": self.to,
            "task": self.task,
            "data": self.data,
            "createdAt": self.created_at,
        }


def wrap(from_: str, to: str, task: str, data: Any) -> dict:
    return A2AMessage(from_=from_, to=to, task=task, data=data).to_dict()


def append_a2a(envelope: dict) -> Path:
    A2A_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(A2A_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(envelope, ensure_ascii=False) + "\n")
    return A2A_LOG


def from_legacy(msg: dict) -> dict:
    """Nâng message {from,to,task,data} lên A2A envelope."""
    return wrap(msg.get("from", ""), msg.get("to", ""), msg.get("task", ""), msg.get("data"))

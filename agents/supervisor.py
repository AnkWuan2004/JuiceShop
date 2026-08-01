#!/usr/bin/env python3
"""
Tuần 6 — Supervisor: chia việc Recon → Fuzz → Exploit qua A2A envelopes.
Message format: {protocol, messageId, from, to, task, data, createdAt}
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))

from a2a import append_a2a, wrap  # noqa: E402
from common import write_trace  # noqa: E402


class Supervisor:
    def __init__(self) -> None:
        self.inbox: list[dict] = []

    def send(self, from_: str, to: str, task: str, data: Any) -> dict:
        envelope = wrap(from_, to, task, data)
        self.inbox.append(envelope)
        append_a2a(envelope)
        write_trace("supervisor", "a2a_message", envelope)
        print(f"  A2A {envelope['from']} → {envelope['to']} | {envelope['task']} | {envelope['messageId'][:8]}")
        return envelope

    def run_pipeline(self, auto_approve: bool = True) -> dict:
        from fuzz_agent import run_fuzz
        from exploit_agent import run_exploit
        from recon_agent import run_recon

        self.send("supervisor", "recon", "map_attack_surface", {"source": "data-lake"})
        surface = run_recon()
        self.send("recon", "supervisor", "attack_surface_done", surface)

        self.send("supervisor", "fuzz", "fuzz_from_surface", {"map": "attack_surface_map.json"})
        findings = run_fuzz(max_requests=6)
        self.send("fuzz", "supervisor", "fuzz_done", {"count": len(findings)})

        self.send("supervisor", "exploit", "prove_finding", {"need_hitl": True})
        exploit = run_exploit(auto_approve=auto_approve)
        self.send("exploit", "supervisor", "exploit_done", exploit.get("status"))

        summary = {
            "protocol": "sentinel-a2a/1.0",
            "messages": self.inbox,
            "surface_endpoints": len(surface.get("endpoints", [])),
            "fuzz_count": len(findings),
            "exploit_status": exploit.get("status"),
        }
        path = ROOT / "data-lake" / "syndicate_summary.json"
        path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Syndicate summary → {path}")
        print(f"[+] A2A log → {ROOT / 'data-lake' / 'a2a_messages.jsonl'}")
        return summary


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--interactive-hitl", action="store_true")
    args = parser.parse_args()
    Supervisor().run_pipeline(auto_approve=not args.interactive_hitl)


if __name__ == "__main__":
    main()

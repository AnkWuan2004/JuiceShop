#!/usr/bin/env python3
"""
Tuần 11 — Monitor latency / error rate / token cost từ LLM traces + alert.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACE_DIR = ROOT / "data-lake" / "traces"
OUT = ROOT / "data-lake" / "monitor_report.json"

ALERT_USD = float(os.environ.get("SENTINEL_COST_ALERT_USD", "5.0"))
ALERT_LATENCY_MS = float(os.environ.get("SENTINEL_LATENCY_ALERT_MS", "10000"))
ALERT_ERROR_RATE = float(os.environ.get("SENTINEL_ERROR_ALERT_RATE", "0.25"))


def main() -> int:
    responses = []
    errors = 0
    for path in sorted(TRACE_DIR.glob("llm_*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event") == "error":
                errors += 1
                continue
            if rec.get("event") != "response":
                continue
            data = rec.get("data") or {}
            responses.append(data)
            if data.get("error"):
                errors += 1

    n = len(responses)
    latencies = [float(r.get("latency_ms") or 0) for r in responses]
    costs = [float(r.get("est_cost_usd") or 0) for r in responses]
    tokens = [int(r.get("est_tokens_in") or 0) + int(r.get("est_tokens_out") or 0) for r in responses]
    total_cost = sum(costs)
    avg_latency = (sum(latencies) / n) if n else 0.0
    max_latency = max(latencies) if latencies else 0.0
    error_rate = (errors / max(1, n + errors)) if (n or errors) else 0.0

    alerts = []
    if total_cost > ALERT_USD:
        alerts.append(f"cost ${total_cost:.4f} > ${ALERT_USD}")
    if max_latency > ALERT_LATENCY_MS:
        alerts.append(f"max_latency_ms {max_latency:.0f} > {ALERT_LATENCY_MS:.0f}")
    if error_rate > ALERT_ERROR_RATE and (n + errors) >= 3:
        alerts.append(f"error_rate {error_rate:.2f} > {ALERT_ERROR_RATE}")

    report = {
        "llm_responses": n,
        "errors": errors,
        "error_rate": error_rate,
        "total_est_tokens": sum(tokens),
        "total_est_cost_usd": total_cost,
        "avg_latency_ms": avg_latency,
        "max_latency_ms": max_latency,
        "alerts": alerts,
        "thresholds": {
            "cost_usd": ALERT_USD,
            "latency_ms": ALERT_LATENCY_MS,
            "error_rate": ALERT_ERROR_RATE,
        },
    }
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"[+] Wrote {OUT}")
    if alerts:
        print("[!] ALERTS:", "; ".join(alerts))
        return 2
    print("[*] No alerts")
    return 0


if __name__ == "__main__":
    sys.exit(main())

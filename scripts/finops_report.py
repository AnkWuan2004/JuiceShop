#!/usr/bin/env python3
"""
Tuần 11 — Gom LLM traces → CSV FinOps + cảnh báo ngưỡng chi phí.
"""
from __future__ import annotations

import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACE_DIR = ROOT / "data-lake" / "traces"
OUT_CSV = ROOT / "data-lake" / "finops_weekly.csv"
ALERT_USD = float(os.environ.get("SENTINEL_COST_ALERT_USD", "5.0"))


def main() -> int:
    rows = []
    total_cost = 0.0
    total_tokens = 0
    latencies = []
    for path in sorted(TRACE_DIR.glob("llm_*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            data = rec.get("data") or {}
            if rec.get("event") != "response":
                continue
            cost = float(data.get("est_cost_usd") or 0)
            tin = int(data.get("est_tokens_in") or 0)
            tout = int(data.get("est_tokens_out") or 0)
            lat = data.get("latency_ms")
            total_cost += cost
            total_tokens += tin + tout
            if lat is not None:
                latencies.append(float(lat))
            rows.append(
                {
                    "ts": rec.get("ts"),
                    "mock": data.get("mock"),
                    "model": data.get("model"),
                    "base_url": data.get("base_url"),
                    "est_tokens_in": tin,
                    "est_tokens_out": tout,
                    "est_cost_usd": cost,
                    "latency_ms": lat if lat is not None else "",
                }
            )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "ts",
                "mock",
                "model",
                "base_url",
                "est_tokens_in",
                "est_tokens_out",
                "est_cost_usd",
                "latency_ms",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    avg_lat = (sum(latencies) / len(latencies)) if latencies else 0.0
    print(f"[+] {len(rows)} LLM responses → {OUT_CSV}")
    print(f"    total_est_tokens={total_tokens} total_est_cost_usd={total_cost:.6f} avg_latency_ms={avg_lat:.1f}")
    if total_cost > ALERT_USD:
        print(f"[!] ALERT: estimated cost ${total_cost:.4f} > threshold ${ALERT_USD}")
        return 2
    print(f"[*] Under alert threshold ${ALERT_USD} (MOCK usually $0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

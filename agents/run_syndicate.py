#!/usr/bin/env python3
"""
End-to-end Syndicate runner (Tuần 6+).
Mock LLM nếu không có OPENAI_API_KEY. Traffic chỉ localhost Kong.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))
sys.path.insert(0, str(ROOT / "rag"))


def ensure_seed() -> None:
    db = ROOT / "data-lake" / "vuln_data.db"
    if not db.exists():
        print("[*] Seed sample reports…")
        import subprocess

        subprocess.run([sys.executable, str(ROOT / "scripts" / "seed_sample_reports.py")], check=False)


def ensure_rag() -> None:
    idx = ROOT / "rag" / "store" / "bow_index.pkl"
    if not idx.exists():
        print("[*] Ingest RAG…")
        from ingest import main as ingest_main

        ingest_main()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Project Sentinel syndicate E2E")
    parser.add_argument("--interactive-hitl", action="store_true")
    parser.add_argument("--skip-rag", action="store_true")
    args = parser.parse_args()

    ensure_seed()
    if not args.skip_rag:
        ensure_rag()

    from supervisor import Supervisor

    print("[*] Supervisor pipeline (Recon → Fuzz → Exploit)")
    from common import LLMClient

    print("    LLM mode: " + ("MOCK (offline)" if LLMClient().mock else "DeepSeek V4 Flash"))
    Supervisor().run_pipeline(auto_approve=not args.interactive_hitl)
    print("[*] Done. Xem data-lake/traces/ và syndicate_summary.json")


if __name__ == "__main__":
    main()

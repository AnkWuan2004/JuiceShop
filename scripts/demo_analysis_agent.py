#!/usr/bin/env python3
"""
Tuần 3 — One-shot live demo: seed → RAG ingest (nếu cần) → Analysis Agent → mở UI.

Usage:
  python scripts/demo_analysis_agent.py
  python scripts/demo_analysis_agent.py --no-browser   # chỉ in URL
  python scripts/demo_analysis_agent.py --cli-only     # không mở server, chỉ chạy pipeline
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data-lake" / "vuln_data.db"
REPORT = ROOT / "data-lake" / "analysis_report.jsonl"
HOST = os.environ.get("SENTINEL_DEMO_HOST", "127.0.0.1")
PORT = int(os.environ.get("SENTINEL_DEMO_PORT", "8790"))


def run(cmd: list[str], *, env: dict | None = None) -> int:
    print(f"\n$ {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=ROOT, env=env or os.environ)
    return r.returncode


def summarize() -> None:
    if not REPORT.exists():
        print("[!] Chưa có analysis_report.jsonl")
        return
    lines = [json.loads(l) for l in REPORT.read_text(encoding="utf-8").splitlines() if l.strip()]
    if len(lines) == 1 and lines[0].get("status") == "no_findings":
        print("[*] no_findings")
        return
    by = {"high": 0, "medium": 0, "low": 0}
    for f in lines:
        if f.get("severity") in by:
            by[f["severity"]] += 1
    print("\n=== Security Analysis Report ===")
    print(f"  Findings: {len(lines)}")
    print(f"  Severity: high={by['high']} medium={by['medium']} low={by['low']}")
    print(f"  File:     {REPORT}")
    print("  Top 5:")
    for f in lines[:5]:
        print(f"    [{f['severity']:6}] {f['id']} {f['name'][:48]} @ {f['location'][:40]}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Live demo — Security Analysis Agent")
    ap.add_argument("--cli-only", action="store_true", help="Chỉ seed+analyze, không mở UI server")
    ap.add_argument("--no-browser", action="store_true", help="Mở server nhưng không auto-open browser")
    ap.add_argument("--skip-seed", action="store_true", help="Bỏ qua seed nếu DB đã có")
    ap.add_argument("--skip-rag", action="store_true", help="Bỏ qua rag/ingest.py")
    args = ap.parse_args()

    env = {**os.environ, "SENTINEL_FORCE_MOCK": "1", "PYTHONIOENCODING": "utf-8"}
    # Demo deterministic
    env.pop("OPENAI_API_KEY", None)

    print("╔══════════════════════════════════════════════╗")
    print("║  Sentinel — Security Analysis Agent LIVE DEMO ║")
    print("╚══════════════════════════════════════════════╝")

    need_seed = True
    if args.skip_seed and DB.exists():
        import sqlite3

        try:
            n = sqlite3.connect(DB).execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            need_seed = n < 10
        except Exception:
            need_seed = True

    if need_seed:
        if run([sys.executable, "scripts/seed_sample_reports.py"], env=env) != 0:
            return 1
    else:
        print("[*] Skip seed (DB đã có dữ liệu)")

    store = ROOT / "rag" / "store" / "bow_index.pkl"
    if not args.skip_rag and not store.exists():
        run([sys.executable, "rag/ingest.py"], env=env)
    elif args.skip_rag:
        print("[*] Skip RAG ingest")

    if run([sys.executable, "agents/analysis_agent.py", "--md"], env=env) != 0:
        return 1
    summarize()

    if run([sys.executable, "scripts/test_analysis_agent.py"], env=env) != 0:
        print("[!] Tests chưa PASS — kiểm tra lại")
        return 1

    if args.cli_only:
        print("\n[*] CLI-only xong. Xem: data-lake/analysis_report.jsonl (+ .md)")
        return 0

    url = f"http://{HOST}:{PORT}"
    print(f"\n[*] Starting live UI → {url}")
    # Server blocks; open browser shortly after start via child... we open before serve
    # Launch server as this process's main work via exec-like call
    if not args.no_browser:
        # delay open so bind succeeds
        def _open() -> None:
            time.sleep(0.8)
            try:
                webbrowser.open(url)
            except Exception:
                pass

        import threading

        threading.Thread(target=_open, daemon=True).start()

    # Re-exec server in-process
    sys.path.insert(0, str(ROOT / "scripts"))
    from demo_analysis_server import main as server_main  # type: ignore

    return server_main()


if __name__ == "__main__":
    raise SystemExit(main())

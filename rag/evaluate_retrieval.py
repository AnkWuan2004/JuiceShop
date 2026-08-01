#!/usr/bin/env python3
"""
Đo retrieval: accuracy, Precision@3, MRR trên 10 câu hỏi gold.
"""
from __future__ import annotations

import json
from pathlib import Path

from hybrid_search import hybrid_search
from query import search

ROOT = Path(__file__).resolve().parent

GOLD = [
    ("SQL Injection là gì và cách phòng?", {"owasp_sqli_cheatsheet", "pentest_juice_sqli", "cve_sqli_rce"}),
    ("Juice Shop search endpoint SQLi", {"pentest_juice_sqli", "owasp_sqli_cheatsheet"}),
    ("XSS prevention cheat sheet", {"owasp_xss_cheatsheet", "pentest_juice_xss"}),
    ("Log4Shell CVE-2021-44228", {"cve_log4shell"}),
    ("Apache Struts RCE Content-Type", {"cve_struts"}),
    ("Broken access control admin Juice Shop", {"pentest_juice_access", "owasp_auth_cheatsheet"}),
    ("JWT authentication best practices", {"owasp_auth_cheatsheet", "pentest_juice_access"}),
    ("Stored XSS trong feedback", {"pentest_juice_xss", "owasp_xss_cheatsheet"}),
    ("Union SQL injection Users table", {"pentest_juice_sqli", "cve_sqli_rce"}),
    ("Vulnerable outdated components Log4j", {"cve_log4shell"}),
]


def precision_at_k(got: list[str], expected: set[str], k: int) -> float:
    top = got[:k]
    if not top:
        return 0.0
    return sum(1 for g in top if g in expected) / len(top)


def mrr_score(got: list[str], expected: set[str]) -> float:
    for i, g in enumerate(got, 1):
        if g in expected:
            return 1.0 / i
    return 0.0


def eval_one(*, mode: str, k: int = 3) -> dict:
    hits = 0
    p_sum = 0.0
    mrr_sum = 0.0
    details = []
    for q, expected in GOLD:
        if mode == "vector_or_bow":
            results = search(q, k=k)
        elif mode == "hybrid":
            results = hybrid_search(q, top_k=k, use_graph=False)
        else:
            results = hybrid_search(q, top_k=k, use_graph=True)
        ids = [r["id"] for r in results]
        id_set = set(ids)
        ok = bool(id_set & expected)
        hits += int(ok)
        p = precision_at_k(ids, expected, k)
        m = mrr_score(ids, expected)
        p_sum += p
        mrr_sum += m
        details.append(
            {
                "q": q,
                "got": ids,
                "expected": sorted(expected),
                "ok": ok,
                "precision_at_k": p,
                "mrr": m,
            }
        )
    n = len(GOLD)
    return {
        "mode": mode,
        "correct": hits,
        "total": n,
        "accuracy": hits / n,
        "precision_at_3": p_sum / n,
        "mrr": mrr_sum / n,
        "details": details,
    }


def main() -> None:
    if not (ROOT / "store" / "bow_index.pkl").exists():
        from ingest import main as ingest_main

        ingest_main()
    else:
        from graphrag import build_graph, GRAPH_PATH

        if not GRAPH_PATH.exists():
            build_graph()

    bow = eval_one(mode="vector_or_bow")
    hyb = eval_one(mode="hybrid")
    graph = eval_one(mode="hybrid_graphrag")
    report = {"bow_or_chroma": bow, "hybrid": hyb, "hybrid_graphrag": graph}
    out = ROOT / "store" / "retrieval_eval.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"BOW/Chroma:      {bow['correct']}/{bow['total']} = {bow['accuracy']:.0%}  P@3={bow['precision_at_3']:.2f} MRR={bow['mrr']:.2f}")
    print(f"Hybrid:          {hyb['correct']}/{hyb['total']} = {hyb['accuracy']:.0%}  P@3={hyb['precision_at_3']:.2f} MRR={hyb['mrr']:.2f}")
    print(f"Hybrid+GraphRAG: {graph['correct']}/{graph['total']} = {graph['accuracy']:.0%}  P@3={graph['precision_at_3']:.2f} MRR={graph['mrr']:.2f}")
    print(f"[+] Wrote {out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Tuần 3 — GraphRAG: entity/relation graph từ threat-intel docs + 1-hop retrieval.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
STORE_DIR = ROOT / "store"
GRAPH_PATH = STORE_DIR / "knowledge_graph.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
CWE_RE = re.compile(r"CWE-\d+", re.I)
PATH_RE = re.compile(r"(/rest/[^\s`)'\"]+|/api/[^\s`)'\"]+|/ftp/[^\s`)'\"]*)")
TOPIC_KEYWORDS = {
    "sqli": ["sql injection", "sqli", "union select", "owasp_sqli"],
    "xss": ["xss", "cross-site scripting", "script>"],
    "auth": ["authentication", "jwt", "access control", "broken access"],
    "rce": ["rce", "remote code", "log4j", "log4shell", "struts"],
    "juice": ["juice shop", "juice-shop"],
}


def _norm(s: str) -> str:
    return s.strip().lower()


def extract_from_doc(doc_id: str, text: str) -> tuple[list[dict], list[dict]]:
    """Trả (nodes, edges) gắn với doc_id."""
    nodes: list[dict] = [{"id": f"doc:{doc_id}", "type": "document", "label": doc_id}]
    edges: list[dict] = []
    lower = text.lower()

    for m in CVE_RE.finditer(text):
        eid = _norm(m.group(0))
        nodes.append({"id": f"cve:{eid}", "type": "cve", "label": m.group(0).upper()})
        edges.append({"from": f"doc:{doc_id}", "to": f"cve:{eid}", "rel": "mentions"})

    for m in CWE_RE.finditer(text):
        eid = _norm(m.group(0))
        nodes.append({"id": f"cwe:{eid}", "type": "cwe", "label": m.group(0).upper()})
        edges.append({"from": f"doc:{doc_id}", "to": f"cwe:{eid}", "rel": "mentions"})

    for m in PATH_RE.finditer(text):
        path = m.group(1).rstrip(".,;")
        eid = f"endpoint:{path}"
        nodes.append({"id": eid, "type": "endpoint", "label": path})
        edges.append({"from": f"doc:{doc_id}", "to": eid, "rel": "covers"})

    for topic, kws in TOPIC_KEYWORDS.items():
        if any(kw in lower for kw in kws):
            tid = f"topic:{topic}"
            nodes.append({"id": tid, "type": "topic", "label": topic})
            edges.append({"from": f"doc:{doc_id}", "to": tid, "rel": "about"})

    # Link CVE/topic co-occurrence lightly
    cves = [n["id"] for n in nodes if n["type"] == "cve"]
    topics = [n["id"] for n in nodes if n["type"] == "topic"]
    for c in cves:
        for t in topics:
            edges.append({"from": c, "to": t, "rel": "related"})

    return nodes, edges


def build_graph(docs: list[dict] | None = None) -> dict:
    if docs is None:
        docs = []
        for path in sorted(DATA_DIR.glob("*.md")):
            docs.append({"id": path.stem, "text": path.read_text(encoding="utf-8")})

    node_map: dict[str, dict] = {}
    edges: list[dict] = []
    doc_ids: list[str] = []

    for d in docs:
        doc_ids.append(d["id"])
        ns, es = extract_from_doc(d["id"], d["text"])
        for n in ns:
            node_map[n["id"]] = n
        edges.extend(es)

    # Deduplicate edges
    seen = set()
    uniq_edges = []
    for e in edges:
        key = (e["from"], e["to"], e["rel"])
        if key in seen:
            continue
        seen.add(key)
        uniq_edges.append(e)

    graph = {
        "nodes": list(node_map.values()),
        "edges": uniq_edges,
        "doc_ids": doc_ids,
        "stats": {"nodes": len(node_map), "edges": len(uniq_edges), "docs": len(doc_ids)},
    }
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    GRAPH_PATH.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    return graph


def load_graph() -> dict:
    if not GRAPH_PATH.exists():
        return build_graph()
    return json.loads(GRAPH_PATH.read_text(encoding="utf-8"))


def _adjacency(graph: dict) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = defaultdict(set)
    for e in graph.get("edges") or []:
        adj[e["from"]].add(e["to"])
        adj[e["to"]].add(e["from"])
    return adj


def seed_nodes(graph: dict, question: str) -> list[str]:
    q = question.lower()
    seeds: list[str] = []
    for n in graph.get("nodes") or []:
        label = str(n.get("label") or "").lower()
        nid = str(n.get("id") or "").lower()
        if label and label in q:
            seeds.append(n["id"])
        elif n["type"] == "topic" and any(kw in q for kw in TOPIC_KEYWORDS.get(label, [label])):
            seeds.append(n["id"])
        elif n["type"] == "cve" and label.lower() in q:
            seeds.append(n["id"])
        elif n["type"] == "endpoint" and label in q:
            seeds.append(n["id"])
        elif n["type"] == "document" and any(tok in q for tok in nid.replace("doc:", "").split("_") if len(tok) > 3):
            seeds.append(n["id"])
    # Topic fallback from keywords
    for topic, kws in TOPIC_KEYWORDS.items():
        if any(kw in q for kw in kws):
            seeds.append(f"topic:{topic}")
    # Unique preserve order
    out, seen = [], set()
    for s in seeds:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def graph_rank_docs(question: str, top_k: int = 5) -> list[tuple[str, float]]:
    """1-hop từ seed → score document nodes."""
    graph = load_graph()
    adj = _adjacency(graph)
    seeds = seed_nodes(graph, question)
    scores: dict[str, float] = defaultdict(float)

    if not seeds:
        # weak: match doc id tokens in question
        for did in graph.get("doc_ids") or []:
            if any(tok in question.lower() for tok in did.split("_") if len(tok) > 3):
                scores[did] += 0.5
    else:
        for seed in seeds:
            scores_local = {seed: 1.0}
            for nb in adj.get(seed, ()):
                scores_local[nb] = scores_local.get(nb, 0.0) + 0.7
                for nb2 in adj.get(nb, ()):
                    scores_local[nb2] = scores_local.get(nb2, 0.0) + 0.35
            for nid, sc in scores_local.items():
                if nid.startswith("doc:"):
                    scores[nid[4:]] += sc
                # endpoints/topics pull connected docs
                for nb in adj.get(nid, ()):
                    if nb.startswith("doc:"):
                        scores[nb[4:]] += sc * 0.5

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return ranked[:top_k]


def graph_doc_order(question: str, id_to_i: dict[str, int]) -> list[int]:
    ranked = graph_rank_docs(question, top_k=len(id_to_i) or 10)
    order = []
    for doc_id, _ in ranked:
        if doc_id in id_to_i:
            order.append(id_to_i[doc_id])
    return order


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--query", default="")
    args = parser.parse_args()
    if args.build or not GRAPH_PATH.exists():
        g = build_graph()
        print(f"[+] Graph → {GRAPH_PATH} nodes={g['stats']['nodes']} edges={g['stats']['edges']}")
    if args.query:
        for doc_id, score in graph_rank_docs(args.query):
            print(f"  {doc_id}  score={score:.2f}")


if __name__ == "__main__":
    main()

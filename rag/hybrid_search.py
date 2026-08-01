#!/usr/bin/env python3
"""
Hybrid search: vector/BOW + BM25 đơn giản (stdlib).
"""
from __future__ import annotations

import argparse
import math
import re
from collections import Counter

from query import load_index, query_bow, query_chroma, tokenize

_TOKEN = re.compile(r"[a-z0-9_]+", re.I)


def bm25_scores(index: dict, question: str, k1: float = 1.5, b: float = 0.75) -> list[float]:
    docs = index["docs"]
    idf = index["idf"]
    # độ dài trung bình
    lengths = [sum(1 for _ in tokenize(d["text"])) for d in docs]
    avgdl = sum(lengths) / (len(lengths) or 1)
    q_tokens = tokenize(question)
    scores = []
    for i, d in enumerate(docs):
        tf = Counter(tokenize(d["text"]))
        dl = lengths[i] or 1
        s = 0.0
        for t in q_tokens:
            if t not in tf:
                continue
            freq = tf[t]
            idf_t = idf.get(t, 0.0)
            denom = freq + k1 * (1 - b + b * dl / avgdl)
            s += idf_t * (freq * (k1 + 1)) / (denom or 1e-9)
        scores.append(s)
    return scores


def rrf_fuse(rank_lists: list[list[int]], k: int = 60) -> list[tuple[int, float]]:
    """Reciprocal Rank Fusion trên danh sách thứ hạng (index doc)."""
    scores: dict[int, float] = {}
    for ranks in rank_lists:
        for rank, doc_i in enumerate(ranks):
            scores[doc_i] = scores.get(doc_i, 0.0) + 1.0 / (k + rank + 1)
    return sorted(scores.items(), key=lambda x: x[1], reverse=True)


def hybrid_search(question: str, top_k: int = 3, *, use_graph: bool = True) -> list[dict]:
    index = load_index()
    n = len(index["docs"])

    # Nhánh 1: BOW cosine (hoặc chroma map về id)
    bow_hits = query_bow(index, question, k=n)
    bow_order = []
    id_to_i = {d["id"]: i for i, d in enumerate(index["docs"])}
    for h in bow_hits:
        bow_order.append(id_to_i[h["id"]])

    chroma = query_chroma(question, k=min(top_k * 2, n))
    chroma_order = []
    if chroma:
        for h in chroma:
            if h["id"] in id_to_i:
                chroma_order.append(id_to_i[h["id"]])

    # Nhánh 2: BM25
    bm25 = bm25_scores(index, question)
    bm25_order = sorted(range(n), key=lambda i: bm25[i], reverse=True)

    lists = [bow_order, bm25_order]
    if chroma_order:
        lists.append(chroma_order)

    # Nhánh 3: GraphRAG 1-hop
    if use_graph:
        try:
            from graphrag import graph_doc_order

            graph_order = graph_doc_order(question, id_to_i)
            if graph_order:
                lists.append(graph_order)
        except Exception:
            pass

    fused = rrf_fuse(lists)
    results = []
    for doc_i, score in fused[:top_k]:
        d = index["docs"][doc_i]
        results.append({"score": score, **d, "graphrag": use_graph})
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("question", nargs="?", default="XSS trên Juice Shop search")
    parser.add_argument("-k", type=int, default=3)
    parser.add_argument("--no-graph", action="store_true")
    args = parser.parse_args()
    for i, h in enumerate(hybrid_search(args.question, top_k=args.k, use_graph=not args.no_graph), 1):
        print(f"{i}. {h['id']} (rrf={h['score']:.4f})")


if __name__ == "__main__":
    main()

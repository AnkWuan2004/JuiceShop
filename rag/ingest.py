#!/usr/bin/env python3
"""
Tuần 3 — Ingest tài liệu threat intel vào store local.
Ưu tiên ChromaDB nếu cài được; fallback bag-of-words + cosine (stdlib).
"""
from __future__ import annotations

import json
import math
import os
import pickle
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
STORE_DIR = ROOT / "store"
INDEX_PATH = STORE_DIR / "bow_index.pkl"

_TOKEN = re.compile(r"[a-z0-9_]+", re.I)


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def load_documents() -> list[dict]:
    docs = []
    for path in sorted(DATA_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        docs.append({"id": path.stem, "path": str(path), "text": text})
    return docs


def build_bow(docs: list[dict]) -> dict:
    """TF bag-of-words + IDF cho cosine similarity."""
    df: dict[str, int] = {}
    doc_tfs: list[dict[str, float]] = []
    for d in docs:
        tokens = tokenize(d["text"])
        tf: dict[str, float] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0.0) + 1.0
        # normalize tf
        n = float(len(tokens) or 1)
        tf = {k: v / n for k, v in tf.items()}
        doc_tfs.append(tf)
        for t in tf:
            df[t] = df.get(t, 0) + 1

    n_docs = len(docs)
    idf = {t: math.log((n_docs + 1) / (c + 1)) + 1.0 for t, c in df.items()}
    return {"docs": docs, "doc_tfs": doc_tfs, "idf": idf}


def try_chroma(docs: list[dict]) -> bool:
    """Chroma chỉ khi SENTINEL_USE_CHROMA=1 — tránh tải model embedding khi demo offline."""
    if os.environ.get("SENTINEL_USE_CHROMA", "").strip() not in ("1", "true", "yes"):
        print("[*] BOW fallback (set SENTINEL_USE_CHROMA=1 để dùng chromadb)")
        return False
    try:
        import chromadb  # type: ignore
    except ImportError:
        print("[*] chromadb không có — dùng BOW fallback")
        return False

    STORE_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(STORE_DIR / "chroma"))
    coll = client.get_or_create_collection("sentinel_threats")
    existing = coll.count()
    if existing:
        print(f"[*] Chroma đã có {existing} docs — skip re-add")
        return True
    coll.add(
        ids=[d["id"] for d in docs],
        documents=[d["text"] for d in docs],
        metadatas=[{"path": d["path"]} for d in docs],
    )
    print(f"[+] Chroma ingest {len(docs)} documents")
    return True


def main() -> None:
    docs = load_documents()
    if not docs:
        print("[!] Không có file .md trong rag/data/")
        return

    STORE_DIR.mkdir(parents=True, exist_ok=True)
    used_chroma = try_chroma(docs)

    index = build_bow(docs)
    index["backend"] = "chroma" if used_chroma else "bow"
    with open(INDEX_PATH, "wb") as f:
        pickle.dump(index, f)

    from graphrag import build_graph

    graph = build_graph(docs)
    meta = {
        "count": len(docs),
        "backend": index["backend"],
        "ids": [d["id"] for d in docs],
        "graphrag": graph.get("stats"),
    }
    (STORE_DIR / "ingest_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[+] BOW index → {INDEX_PATH} ({len(docs)} docs, backend={index['backend']})")
    print(f"[+] GraphRAG → store/knowledge_graph.json ({graph['stats']})")


if __name__ == "__main__":
    main()

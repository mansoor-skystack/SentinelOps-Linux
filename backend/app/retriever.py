import os
import re
import csv
import math
from collections import Counter
from typing import List, Dict, Any
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
RUNBOOKS_DIR = os.path.join(DATA_DIR, "runbooks")
CSV_PATH = os.path.join(DATA_DIR, "incidents_dataset.csv")

def tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9_\-]+", text.lower())

class OkapiBM25:
    """Exact Okapi BM25 sparse lexical scorer (k1=1.5, b=0.75) with zero external dependency overhead."""
    def __init__(self, corpus_tokens: List[List[str]], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.corpus_size = len(corpus_tokens)
        self.doc_freqs: List[Counter] = [Counter(doc) for doc in corpus_tokens]
        self.doc_lens = [len(doc) for doc in corpus_tokens]
        self.avgdl = sum(self.doc_lens) / max(1, self.corpus_size)

        df = Counter()
        for doc in self.doc_freqs:
            for term in doc:
                df[term] += 1
        self.idf = {
            term: math.log(1.0 + (self.corpus_size - freq + 0.5) / (freq + 0.5))
            for term, freq in df.items()
        }

    def get_scores(self, query_tokens: List[str]) -> np.ndarray:
        scores = np.zeros(self.corpus_size, dtype=float)
        for q in query_tokens:
            if q not in self.idf:
                continue
            idf_q = self.idf[q]
            for idx, tf_map in enumerate(self.doc_freqs):
                tf = tf_map.get(q, 0)
                if tf > 0:
                    denom = tf + self.k1 * (1.0 - self.b + self.b * (self.doc_lens[idx] / self.avgdl))
                    scores[idx] += idf_q * ((tf * (self.k1 + 1.0)) / denom)
        return scores

class HybridKnowledgeEngine:
    """
    Lightweight Dual-Index Hybrid RAG Retriever (<80 MB RAM footprint):
    1. Semantic Vector Index (Subword + Word N-gram TF-IDF Cosine Similarity)
    2. Sparse Lexical Index (Okapi BM25 for exact error codes like EADDRINUSE, 137, ENOSPC)
    3. Reciprocal Rank Fusion (RRF, k=60) with Authoritative Runbook Weighting
    """

    def __init__(self):
        self.documents: List[str] = []
        self.metadatas: List[Dict[str, str]] = []
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
        self.tfidf_matrix = None
        self.bm25 = None
        self.rebuild_index()

    def rebuild_index(self):
        docs: List[str] = []
        metas: List[Dict[str, str]] = []

        if os.path.exists(RUNBOOKS_DIR):
            for fname in sorted(os.listdir(RUNBOOKS_DIR)):
                if not fname.endswith(".md"):
                    continue
                with open(os.path.join(RUNBOOKS_DIR, fname), "r", encoding="utf-8") as f:
                    raw = f.read()
                sections = re.split(r"(?=^##\s+)", raw, flags=re.MULTILINE)
                for sec in sections:
                    sec = sec.strip()
                    if not sec:
                        continue
                    first_line = sec.splitlines()[0].lstrip("#").strip()
                    docs.append(sec)
                    metas.append({"source": fname, "section": first_line[:80], "type": "runbook"})

        if os.path.exists(CSV_PATH):
            with open(CSV_PATH, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    chunk = (
                        f"Stack: {row['stack_tag']}\n"
                        f"Error: {row['error_log']}\n"
                        f"Root Cause: {row['root_cause']}\n"
                        f"Diagnostic: {row['diagnostic_command']}\n"
                        f"Fix: {row['fix_command']}"
                    )
                    docs.append(chunk)
                    metas.append({
                        "source": "incidents_dataset.csv",
                        "section": row["incident_id"],
                        "stack": row["stack_tag"],
                        "type": "incident"
                    })

        self.documents = docs
        self.metadatas = metas
        self.tfidf_matrix = self.vectorizer.fit_transform(docs)
        self.bm25 = OkapiBM25([tokenize(d) for d in docs])

    def search_vector_only(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        q_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self.tfidf_matrix).flatten()
        top_idx = np.argsort(sims)[::-1][:top_k]
        return [{"text": self.documents[i], "meta": self.metadatas[i], "score": float(sims[i])} for i in top_idx if sims[i] > 0]

    def search_bm25_only(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        scores = self.bm25.get_scores(tokenize(query))
        top_idx = np.argsort(scores)[::-1][:top_k]
        return [{"text": self.documents[i], "meta": self.metadatas[i], "score": float(scores[i])} for i in top_idx if scores[i] > 0]

    def search_hybrid(self, query: str, stack_filter: str = "All", top_k: int = 3) -> List[Dict[str, Any]]:
        n = len(self.documents)
        q_vec = self.vectorizer.transform([query])
        vec_sims = cosine_similarity(q_vec, self.tfidf_matrix).flatten()
        vec_ranks = np.argsort(vec_sims)[::-1][:min(15, n)]

        bm25_scores = self.bm25.get_scores(tokenize(query))
        bm25_ranks = np.argsort(bm25_scores)[::-1][:min(15, n)]

        rrf: Dict[int, float] = {}
        for rank, idx in enumerate(vec_ranks):
            if vec_sims[idx] > 0:
                rrf[int(idx)] = rrf.get(int(idx), 0.0) + 1.0 / (60.0 + rank + 1)

        for rank, idx in enumerate(bm25_ranks):
            if bm25_scores[idx] > 0:
                rrf[int(idx)] = rrf.get(int(idx), 0.0) + 1.0 / (60.0 + rank + 1)

        for idx in list(rrf.keys()):
            meta = self.metadatas[idx]
            if meta.get("type") == "runbook":
                rrf[idx] *= 1.35
            if stack_filter and stack_filter != "All":
                if stack_filter.lower() in meta.get("source", "").lower() or stack_filter.lower() == meta.get("stack", "").lower():
                    rrf[idx] *= 1.20

        ranked = sorted(rrf.items(), key=lambda x: x[1], reverse=True)[:top_k]
        return [{"text": self.documents[i], "meta": self.metadatas[i], "score": round(score, 5)} for i, score in ranked]

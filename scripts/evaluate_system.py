#!/usr/bin/env python3
"""
SentinelOps Quantitative RAG Evaluation & Statistical Hypothesis Testing Script
Generates empirical metrics (Hit Rate @ 3, MRR, Latency, PII Sanitizer Recall, Paired t-test)
for Chapter 4 of the Amity University Online MCA Dissertation.
"""
import os
import sys
import json
import time
import numpy as np
from scipy import stats

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.retriever import HybridKnowledgeEngine
from app.sanitizer import LogSanitizer

BENCHMARK_PATH = os.path.join(os.path.dirname(__file__), "..", "backend", "data", "eval_benchmark.json")

def reciprocal_rank(retrieved_sources, expected_source):
    for rank, src in enumerate(retrieved_sources, start=1):
        if src == expected_source:
            return 1.0 / rank
    return 0.0

def main():
    engine = HybridKnowledgeEngine()
    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    vec_rr, bm25_rr, hyb_rr = [], [], []
    latencies_ms = []

    for item in dataset:
        q = item["query"]
        exp = item["expected_source"]

        v_res = [r["meta"]["source"] for r in engine.search_vector_only(q, top_k=3)]
        b_res = [r["meta"]["source"] for r in engine.search_bm25_only(q, top_k=3)]

        t0 = time.perf_counter()
        h_res = [r["meta"]["source"] for r in engine.search_hybrid(q, stack_filter=item["stack"], top_k=3)]
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        vec_rr.append(reciprocal_rank(v_res, exp))
        bm25_rr.append(reciprocal_rank(b_res, exp))
        hyb_rr.append(reciprocal_rank(h_res, exp))

    vec_hit3 = np.mean([1 if x > 0 else 0 for x in vec_rr]) * 100
    bm25_hit3 = np.mean([1 if x > 0 else 0 for x in bm25_rr]) * 100
    hyb_hit3 = np.mean([1 if x > 0 else 0 for x in hyb_rr]) * 100

    t_stat, p_val = stats.ttest_rel(hyb_rr, vec_rr)

    pii_samples = [
        "Error from 192.168.1.45 using AWS key AKIAIOSFODNN7EXAMPLE",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def",
        "DB password=MySecretPassword123! connection failed on 10.24.0.9"
    ]
    masked_ok = 0
    for s in pii_samples:
        cleaned, redactions, _ = LogSanitizer.filter_and_sanitize(s)
        if len(redactions) > 0 and "192.168" not in cleaned and "AKIA" not in cleaned and "MySecret" not in cleaned:
            masked_ok += 1

    print("=================================================================")
    print("  SENTINELOPS EMPIRICAL EVALUATION & HYPOTHESIS TEST RESULTS")
    print("=================================================================")
    print(f"Benchmark Queries (N)         : {len(dataset)}")
    print(f"Dense Vector Only Hit@3 / MRR : {vec_hit3:.2f}%  | MRR = {np.mean(vec_rr):.4f}")
    print(f"Sparse BM25 Only  Hit@3 / MRR : {bm25_hit3:.2f}%  | MRR = {np.mean(bm25_rr):.4f}")
    print(f"Hybrid RRF (Ours) Hit@3 / MRR : {hyb_hit3:.2f}%  | MRR = {np.mean(hyb_rr):.4f}")
    print(f"Paired t-test (Hybrid vs Vec) : t = {t_stat:.4f}, p = {p_val:.4f}")
    print(f"Mean Hybrid Retrieval Latency : {np.mean(latencies_ms):.2f} ms (SD = {np.std(latencies_ms):.2f} ms)")
    print(f"Regex PII Sanitizer Recall    : {(masked_ok/len(pii_samples))*100:.2f}% ({masked_ok}/{len(pii_samples)})")
    print("=================================================================")

if __name__ == "__main__":
    main()

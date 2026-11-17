#!/usr/bin/env python3
"""Evaluate retrieval quality, index-build cost, query latency, and sanitizer coverage."""
import json
import os
import sys
import time

import numpy as np
from scipy import stats

REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(REPOSITORY_ROOT, "backend")
sys.path.insert(0, REPOSITORY_ROOT)
sys.path.insert(0, BACKEND_DIR)
from app.retriever import HybridKnowledgeEngine
from app.sanitizer import LogSanitizer

DATA_DIR = os.path.join(BACKEND_DIR, "data")
BENCHMARKS = (
    ("Development", os.path.join(DATA_DIR, "eval_benchmark.json")),
    ("Held-out", os.path.join(DATA_DIR, "eval_benchmark_holdout.json")),
)

SANITIZER_SAMPLES = (
    {"raw": "ERROR peer=192.0.2.10 password=SamplePass-19", "forbidden": ["192.0.2.10", "SamplePass-19"]},
    {"raw": "ERROR token=synthetic-token-123", "forbidden": ["synthetic-token-123"]},
    {"raw": "ERROR Authorization: Bearer abc.def.synthetic", "forbidden": ["abc.def.synthetic"]},
    {"raw": "ERROR AWS key AKIAIOSFODNN7EXAMPLE rejected", "forbidden": ["AKIAIOSFODNN7EXAMPLE"]},
    {"raw": "ERROR URL https://user:syntheticpass@example.invalid/db", "forbidden": ["syntheticpass"]},
    {"raw": "ERROR secret='example-secret-value'", "forbidden": ["example-secret-value"]},
    {"raw": "ERROR api_key=fake-api-key-value", "forbidden": ["fake-api-key-value"]},
    {"raw": "ERROR passwd:sample-pass-77", "forbidden": ["sample-pass-77"]},
    {
        "raw": "ERROR key -----BEGIN RSA PRIVATE KEY-----\nsynthetic-private-key-material\n-----END RSA PRIVATE KEY-----",
        "forbidden": ["synthetic-private-key-material"],
    },
    {"raw": "ERROR peer 203.0.113.8 disconnected", "forbidden": ["203.0.113.8"]},
    {"raw": "ERROR bind 0.0.0.0:80; upstream 127.0.0.1:8000", "preserve": ["0.0.0.0", "127.0.0.1"]},
)


def reciprocal_rank(retrieved_sources, expected_sources):
    expected = set(expected_sources) if isinstance(expected_sources, list) else {expected_sources}
    for rank, source in enumerate(retrieved_sources, start=1):
        if source in expected:
            return 1.0 / rank
    return 0.0


def evaluate_dataset(engine, dataset):
    vector_rr, bm25_rr, hybrid_rr, latencies_ms = [], [], [], []
    for item in dataset:
        query = item["query"]
        expected = item.get("expected_sources", item["expected_source"])
        vector_sources = [row["meta"]["source"] for row in engine.search_vector_only(query, top_k=3)]
        bm25_sources = [row["meta"]["source"] for row in engine.search_bm25_only(query, top_k=3)]
        started = time.perf_counter()
        hybrid_sources = [
            row["meta"]["source"]
            for row in engine.search_hybrid(query, stack_filter=item["stack"], top_k=3)
        ]
        latencies_ms.append((time.perf_counter() - started) * 1000.0)
        vector_rr.append(reciprocal_rank(vector_sources, expected))
        bm25_rr.append(reciprocal_rank(bm25_sources, expected))
        hybrid_rr.append(reciprocal_rank(hybrid_sources, expected))
    return {
        "count": len(dataset),
        "vector_rr": vector_rr,
        "bm25_rr": bm25_rr,
        "hybrid_rr": hybrid_rr,
        "latencies_ms": latencies_ms,
    }


def sanitizer_coverage():
    passed = 0
    for sample in SANITIZER_SAMPLES:
        sanitized, _, _ = LogSanitizer.filter_and_sanitize(sample["raw"])
        secrets_removed = all(value not in sanitized for value in sample.get("forbidden", []))
        local_addresses_preserved = all(value in sanitized for value in sample.get("preserve", []))
        passed += int(secrets_removed and local_addresses_preserved)
    return passed, len(SANITIZER_SAMPLES)


def report_dataset(name, result):
    hybrid_rr = result["hybrid_rr"]
    latencies = result["latencies_ms"]
    hit_at_3 = np.mean([rank > 0 for rank in hybrid_rr]) * 100.0
    print(
        f"{name:12} N={result['count']:2} | "
        f"Hybrid Hit@3={hit_at_3:6.2f}% | MRR={np.mean(hybrid_rr):.4f} | "
        f"mean={np.mean(latencies):.2f} ms | p95={np.percentile(latencies, 95):.2f} ms"
    )
    print(
        f"             Vector MRR={np.mean(result['vector_rr']):.4f} | "
        f"BM25 MRR={np.mean(result['bm25_rr']):.4f}"
    )


def main():
    build_started = time.perf_counter()
    engine = HybridKnowledgeEngine()
    build_seconds = time.perf_counter() - build_started
    datasets = []
    for name, path in BENCHMARKS:
        with open(path, "r", encoding="utf-8") as benchmark_file:
            dataset = json.load(benchmark_file)
        datasets.append((name, evaluate_dataset(engine, dataset)))

    development = datasets[0][1]
    t_stat, p_value = stats.ttest_rel(development["hybrid_rr"], development["vector_rr"])
    sanitizer_passed, sanitizer_total = sanitizer_coverage()
    print("=" * 84)
    print("SENTINELOPS RETRIEVAL AND SAFETY EVALUATION")
    print("=" * 84)
    print(f"Indexed chunks             : {len(engine.documents)}")
    print(f"Index build time           : {build_seconds:.2f} seconds")
    for name, result in datasets:
        report_dataset(name, result)
    print(f"Development paired t-test  : t={t_stat:.4f}, p={p_value:.4f}")
    print(
        f"Sanitizer cases passed     : {sanitizer_passed}/{sanitizer_total} "
        "(synthetic secret removal and local-address preservation)"
    )
    print("=" * 84)


if __name__ == "__main__":
    main()

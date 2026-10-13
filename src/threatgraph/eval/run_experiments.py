"""Run both RAG systems over data/eval_queries.json and save raw outputs.

For every question this records the question, reference answer, both
systems' generated answers, retrieved evidence from each system, latency
breakdown, token/cost accounting, and any error -- raw per-question records,
not just aggregates (results/raw_experiment_results.json). Aggregated CSVs
(baseline_results.csv, graphrag_results.csv, comparison.csv) are derived
from this file by threatgraph.eval.stats_analysis.

Benchmark-leakage note: expected_answer from eval_queries.json is NEVER
passed into either RAG system's prompt or retrieval query -- it is attached
to the output record only after both systems have already answered, purely
for downstream scoring.

Requires a working LLM provider (ANTHROPIC_API_KEY / OPENAI_API_KEY) for the
generation step. Use --dry-run to exercise only the retrieval layers (vector
search + graph traversal) against Neo4j without calling the LLM, which is
useful for smoke-testing the pipeline before a key is available.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from threatgraph.config import DATA_DIR, RESULTS_DIR
from threatgraph.embeddings import get_embedder
from threatgraph.graph.neo4j_client import Neo4jClient
from threatgraph.rag.baseline_rag import BaselineRAG
from threatgraph.rag.common import RAGResult
from threatgraph.rag.graphrag import ThreatGraphRAG
from threatgraph.rag.llm_provider import LLMProvider


def _result_to_record(result: RAGResult) -> dict:
    d = asdict(result)
    # Keep full chunk text: both the "save retrieved evidence" requirement
    # and RAGAS (faithfulness/context precision/recall) need the actual
    # retrieved text, not just chunk identifiers.
    d["retrieved_chunks"] = [
        {"chunk_id": c["chunk_id"], "entity_attack_id": c["entity_attack_id"],
         "entity_name": c["entity_name"], "text": c["text"], "score": round(c["score"], 4)}
        for c in d["retrieved_chunks"]
    ]
    return d


def run(dry_run: bool = False, limit: int | None = None) -> list[dict]:
    queries = json.loads((DATA_DIR / "eval_queries.json").read_text(encoding="utf-8"))
    if limit:
        queries = queries[:limit]

    client = Neo4jClient()
    embedder = get_embedder()
    provider = None if dry_run else LLMProvider()

    baseline = BaselineRAG(client=client, embedder=embedder, provider=provider)
    graphrag = ThreatGraphRAG(client=client, embedder=embedder, provider=provider)

    RESULTS_DIR.mkdir(exist_ok=True)
    out_path = RESULTS_DIR / "raw_experiment_results.json"

    def _is_quota_error(result: RAGResult) -> bool:
        return bool(result.error) and any(
            s in result.error for s in ("RESOURCE_EXHAUSTED", "429", "quota")
        )

    records = []
    consecutive_quota_errors = 0
    for q in queries:
        print(f"[{q['id']}] {q['question'][:80]}...")
        if dry_run:
            b_result = RAGResult(system="baseline", question=q["question"], answer="[dry-run: no LLM call]")
            g_result = RAGResult(system="threatgraph", question=q["question"], answer="[dry-run: no LLM call]")
        else:
            t0 = time.time()
            b_result = baseline.answer(q["question"])
            g_result = graphrag.answer(q["question"])
            print(f"  baseline={b_result.total_latency_seconds:.2f}s "
                  f"threatgraph={g_result.total_latency_seconds:.2f}s "
                  f"(+{time.time()-t0:.2f}s wall)")

        records.append({
            "question_id": q["id"],
            "category": q.get("category"),
            "question": q["question"],
            "reference_answer": q["expected_answer"],
            "required_hops": q["required_hops"],
            "graph_path": q["graph_path"],
            "baseline_answer": b_result.answer,
            "threatgraph_answer": g_result.answer,
            "baseline": _result_to_record(b_result),
            "threatgraph": _result_to_record(g_result),
        })

        # Write after every question so a crash, interrupt, or exhausted
        # quota never discards real results already obtained.
        out_path.write_text(json.dumps(records, indent=2, default=str), encoding="utf-8")

        if not dry_run and (_is_quota_error(b_result) or _is_quota_error(g_result)):
            consecutive_quota_errors += 1
            if consecutive_quota_errors >= 2:
                print(f"Stopping early: provider quota appears exhausted after "
                      f"{len(records)}/{len(queries)} questions. Partial results saved.")
                break
        else:
            consecutive_quota_errors = 0

    baseline.close()
    graphrag.close()
    client.close()

    print(f"Wrote {len(records)} records to {out_path}")
    return records


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true", help="Skip LLM calls; test retrieval wiring only.")
    p.add_argument("--limit", type=int, default=None)
    args = p.parse_args()
    run(dry_run=args.dry_run, limit=args.limit)

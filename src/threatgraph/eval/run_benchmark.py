"""Run the 30-question multi-hop benchmark through both systems and score
the answers with the deterministic metrics in eval.answer_metrics.

Answers are stored with the other UI runs (results/ui_evaluations.json, so
the GraphRAG tab shows them) and summarized in results/benchmark_results.json
for the report. LLM calls go through threatgraph.llm_cache, so re-running an
unchanged configuration is instant.

    python -m threatgraph.eval.run_benchmark [--limit N]
"""
from __future__ import annotations

import argparse
import json

from threatgraph.config import LLM, RESULTS_DIR, RETRIEVAL
from threatgraph.eval import answer_metrics, ui_eval

OUT_PATH = RESULTS_DIR / "benchmark_results.json"


def summarize_benchmark(bench: dict) -> dict:
    store = ui_eval.load_store()
    items = {q["id"]: q for q in ui_eval.load_benchmark()}
    per_q, scores = [], {"baseline": [], "threatgraph": []}
    for qid, it in sorted(bench["items"].items()):
        row = {"question_id": qid, "category": it.get("category"), "hops": it.get("required_hops")}
        for s in scores:
            sc = answer_metrics.score(store["runs"][it[s]], items[qid])
            scores[s].append(sc)
            row[s] = sc
        per_q.append(row)
    return {
        "benchmark_id": bench["id"], "finished_at": bench.get("finished_at"),
        "llm": f"{LLM.provider}/{LLM.model}", "seed": LLM.seed, "temperature": LLM.temperature,
        "top_k_chunks": RETRIEVAL.top_k_chunks, "max_graph_facts": RETRIEVAL.max_graph_facts,
        "summary": {s: answer_metrics.summarize(v) for s, v in scores.items()},
        "per_question": per_q,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=None, help="only the first N questions")
    args = p.parse_args()

    from threatgraph.embeddings import get_embedder
    from threatgraph.graph.neo4j_client import Neo4jClient
    from threatgraph.rag.baseline_rag import BaselineRAG
    from threatgraph.rag.graphrag import ThreatGraphRAG

    questions = ui_eval.load_benchmark()[: args.limit]
    client, embedder = Neo4jClient(), get_embedder()
    baseline = BaselineRAG(client=client, embedder=embedder)
    graphrag = ThreatGraphRAG(client=client, embedder=embedder)
    bench = ui_eval.start_benchmark([q["id"] for q in questions], with_ragas=False)

    def progress(done, total, qid, _item):
        if qid:
            print(f"[{done + 1}/{total}] {qid}", flush=True)

    try:
        stopped = ui_eval.run_benchmark(bench["id"], baseline, graphrag, progress)
    finally:
        client.close()
    if stopped:
        raise SystemExit(f"Benchmark stopped: {stopped}")

    out = summarize_benchmark(ui_eval.get_benchmark(bench["id"]))
    OUT_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    for s in ("baseline", "threatgraph"):
        print(s, {k: round(v["mean"], 3) for k, v in out["summary"][s].items() if v["mean"] is not None})


if __name__ == "__main__":
    main()

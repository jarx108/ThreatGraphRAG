"""Export results/raw_experiment_results.json into the three required flat
CSVs: baseline_results.csv, graphrag_results.csv (one row per question, per
system), and comparison.csv (one row per question with both systems'
values side by side plus their differences). RAGAS per-record scores are
merged in when results/ragas_metrics.per_record.csv exists.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from threatgraph.config import RESULTS_DIR

RAGAS_METRIC_COLS = ["faithfulness", "answer_relevancy", "context_precision", "context_recall"]


def _load_ragas_scores() -> pd.DataFrame | None:
    path = RESULTS_DIR / "ragas_metrics.per_record.csv"
    if not path.exists():
        return None
    df = pd.read_csv(path)
    keep = [c for c in ("question_id", "system") + tuple(RAGAS_METRIC_COLS) if c in df.columns]
    return df[keep]


def _system_rows(raw: list[dict], system: str) -> pd.DataFrame:
    rows = []
    for r in raw:
        sys_rec = r[system]
        rows.append({
            "question_id": r["question_id"],
            "category": r.get("category"),
            "required_hops": r["required_hops"],
            "question": r["question"],
            "answer": sys_rec["answer"],
            "total_latency_seconds": sys_rec["total_latency_seconds"],
            "retrieval_latency_seconds": sys_rec["retrieval_latency_seconds"],
            "generation_latency_seconds": sys_rec["generation_latency_seconds"],
            "input_tokens": sys_rec["input_tokens"],
            "output_tokens": sys_rec["output_tokens"],
            "estimated_cost_usd": sys_rec["estimated_cost_usd"],
            "context_chars": sys_rec["context_chars"],
            "n_retrieved_chunks": len(sys_rec["retrieved_chunks"]),
            "n_graph_facts": len(sys_rec["graph_facts"]),
            "error": sys_rec["error"],
        })
    df = pd.DataFrame(rows)
    ragas = _load_ragas_scores()
    if ragas is not None:
        df = df.merge(ragas[ragas["system"] == system].drop(columns="system"), on="question_id", how="left")
    return df


def export(raw_path: Path | None = None) -> None:
    raw_path = raw_path or (RESULTS_DIR / "raw_experiment_results.json")
    raw = json.loads(Path(raw_path).read_text(encoding="utf-8"))

    baseline_df = _system_rows(raw, "baseline")
    threatgraph_df = _system_rows(raw, "threatgraph")

    baseline_df.to_csv(RESULTS_DIR / "baseline_results.csv", index=False)
    threatgraph_df.to_csv(RESULTS_DIR / "graphrag_results.csv", index=False)

    compare_cols = ["total_latency_seconds", "context_chars", "n_retrieved_chunks",
                     "n_graph_facts", "input_tokens", "output_tokens"] + \
        [c for c in RAGAS_METRIC_COLS if c in baseline_df.columns]
    comparison = baseline_df[["question_id", "category", "required_hops", "question"]].copy()
    for col in compare_cols:
        comparison[f"baseline_{col}"] = baseline_df[col]
        comparison[f"threatgraph_{col}"] = threatgraph_df[col]
        comparison[f"diff_{col}"] = threatgraph_df[col] - baseline_df[col]
    comparison.to_csv(RESULTS_DIR / "comparison.csv", index=False)

    print(f"Wrote baseline_results.csv ({len(baseline_df)} rows), "
          f"graphrag_results.csv ({len(threatgraph_df)} rows), "
          f"comparison.csv ({len(comparison)} rows)")


if __name__ == "__main__":
    export()

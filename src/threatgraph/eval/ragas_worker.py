"""Per-record RAGAS scoring for the Streamlit UI.

Runs in the isolated .venv-ragas interpreter (see ragas_eval.py's module
docstring for why), invoked as a subprocess by threatgraph.eval.ui_eval.
Unlike ragas_eval.run_ragas (which reports dataset means for the batch
pipeline), this returns one score per metric per record, so the UI can show
individual-question scores and compute its own averages.

Input JSON: list of {"user_input", "response", "retrieved_contexts": [...],
"reference": str | null}.
Output JSON: {"judge_model", "judge_provider", "embedding_model",
"ragas_version", "scores": [{"faithfulness", "answer_relevancy",
"context_precision", "context_recall"}, ...]} in input order.

A score is null when it could not be calculated:
  - Context Precision / Context Recall are only computed for records with a
    verified `reference` (they are reference-based); records without one are
    never sent to those metrics.
  - A judge call that RAGAS scores as NaN (timeout, parse failure) is
    reported as null rather than a number.
"""
from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path

from threatgraph.eval.ragas_eval import _judge_embeddings, _judge_llm

METRIC_KEYS = ("faithfulness", "answer_relevancy", "context_precision", "context_recall")


def _clean(value) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(f) else f


def score_records(records: list[dict]) -> dict:
    from datasets import Dataset
    from ragas import evaluate
    from ragas.metrics import AnswerRelevancy, ContextPrecision, ContextRecall, Faithfulness
    from ragas.run_config import RunConfig

    llm = _judge_llm()
    embeddings = _judge_embeddings()
    run_config = RunConfig(
        max_workers=int(os.environ.get("RAGAS_MAX_WORKERS", "2")),
        timeout=int(os.environ.get("RAGAS_TIMEOUT_SECONDS", "300")),
        max_retries=int(os.environ.get("RAGAS_MAX_RETRIES", "15")),
        max_wait=int(os.environ.get("RAGAS_MAX_WAIT_SECONDS", "90")),
    )

    scores: list[dict] = [{k: None for k in METRIC_KEYS} for _ in records]
    with_ref = [i for i, r in enumerate(records) if r.get("reference") and r.get("retrieved_contexts")]
    without_ref = [i for i, r in enumerate(records) if not r.get("reference") and r.get("retrieved_contexts")]

    groups = [
        (with_ref, [Faithfulness(llm=llm), AnswerRelevancy(llm=llm, embeddings=embeddings),
                    ContextPrecision(llm=llm), ContextRecall(llm=llm)], True),
        (without_ref, [Faithfulness(llm=llm), AnswerRelevancy(llm=llm, embeddings=embeddings)], False),
    ]
    for idxs, metrics, include_ref in groups:
        if not idxs:
            continue
        rows = []
        for i in idxs:
            row = {
                "user_input": records[i]["user_input"],
                "response": records[i]["response"],
                "retrieved_contexts": records[i]["retrieved_contexts"],
            }
            if include_ref:
                row["reference"] = records[i]["reference"]
            rows.append(row)
        df = evaluate(Dataset.from_list(rows), metrics=metrics, run_config=run_config,
                      show_progress=False).to_pandas()
        for pos, i in enumerate(idxs):
            for key in METRIC_KEYS:
                if key in df.columns:
                    scores[i][key] = _clean(df.iloc[pos][key])

    return {
        "judge_provider": os.environ.get("RAGAS_JUDGE_PROVIDER", os.environ.get("LLM_PROVIDER", "anthropic")),
        "judge_model": os.environ.get("RAGAS_JUDGE_MODEL", os.environ.get("LLM_MODEL", "claude-sonnet-5")),
        "embedding_model": (
            "text-embedding-3-small" if os.environ.get("RAGAS_EMBEDDING_PROVIDER", "local") == "openai"
            else os.environ.get("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
        ),
        "ragas_version": __import__("ragas").__version__,
        "scores": scores,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python -m threatgraph.eval.ragas_worker <input.json> <output.json>")
    records = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = score_records(records)
    Path(sys.argv[2]).write_text(json.dumps(out, indent=2), encoding="utf-8")

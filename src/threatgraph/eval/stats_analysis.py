"""Paired statistical comparison of System A (baseline) vs System B (ThreatGraph).

Both systems answer the exact same questions from the same eval_queries.json,
so every comparison here is a PAIRED comparison (one baseline observation and
one ThreatGraph observation per question, per metric), not an independent
two-sample comparison. This matters for both the significance test chosen
(paired t-test / Wilcoxon signed-rank, not an independent-samples t-test)
and for computing per-question differences directly.

With a benchmark this small (<=30 questions), a non-significant paired test
should NOT be read as "no difference" -- it mostly reflects limited
statistical power. This is stated explicitly in every output this module
produces rather than left implicit, per the project's evaluation-methodology
requirements.

Inputs: results/raw_experiment_results.json (System A/B answers + latency,
from run_experiments.py) and, if present, results/ragas_metrics.per_record.csv
(RAGAS per-record scores, from ragas_eval.py) joined on question_id+system.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from scipy import stats

from threatgraph.config import RESULTS_DIR


def paired_ci_95(diffs: np.ndarray) -> tuple[float, float]:
    """95% CI for the mean paired difference, via the t-distribution.
    Returned as (low, high); both NaN if fewer than 2 paired observations."""
    n = len(diffs)
    if n < 2:
        return float("nan"), float("nan")
    mean = diffs.mean()
    sem = diffs.std(ddof=1) / math.sqrt(n)
    t_crit = stats.t.ppf(0.975, df=n - 1)
    return float(mean - t_crit * sem), float(mean + t_crit * sem)


def paired_test(a: np.ndarray, b: np.ndarray) -> dict:
    """Paired t-test and Wilcoxon signed-rank test for b vs a (b - a).
    Both are reported since the t-test assumes approximately normal
    differences (often violated with n<30) while Wilcoxon is distribution-free
    but less powerful; with a small sample, neither should be over-trusted."""
    diffs = b - a
    n = len(diffs)
    result = {
        "n": n,
        "mean_a": float(np.mean(a)) if n else float("nan"),
        "mean_b": float(np.mean(b)) if n else float("nan"),
        "std_a": float(np.std(a, ddof=1)) if n > 1 else float("nan"),
        "std_b": float(np.std(b, ddof=1)) if n > 1 else float("nan"),
        "mean_diff_b_minus_a": float(np.mean(diffs)) if n else float("nan"),
        "relative_pct_change": (
            float(np.mean(diffs) / np.mean(a) * 100) if n and np.mean(a) != 0 else float("nan")
        ),
    }
    ci_low, ci_high = paired_ci_95(diffs)
    result["ci_95_low"], result["ci_95_high"] = ci_low, ci_high

    if n >= 2 and not np.all(diffs == diffs[0]):
        t_stat, t_p = stats.ttest_rel(b, a)
        result["paired_ttest_statistic"], result["paired_ttest_p_value"] = float(t_stat), float(t_p)
    else:
        result["paired_ttest_statistic"], result["paired_ttest_p_value"] = float("nan"), float("nan")

    nonzero = diffs[diffs != 0]
    if len(nonzero) >= 2:
        try:
            w_stat, w_p = stats.wilcoxon(nonzero)
            result["wilcoxon_statistic"], result["wilcoxon_p_value"] = float(w_stat), float(w_p)
        except ValueError:
            result["wilcoxon_statistic"], result["wilcoxon_p_value"] = float("nan"), float("nan")
    else:
        result["wilcoxon_statistic"], result["wilcoxon_p_value"] = float("nan"), float("nan")

    result["note"] = (
        f"n={n} paired questions. With n<30, treat p-values as indicative, not "
        "confirmatory; a non-significant result here does not establish equivalence."
    )
    return result


def load_raw_results(path: Optional[Path] = None) -> pd.DataFrame:
    path = path or (RESULTS_DIR / "raw_experiment_results.json")
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = []
    for r in records:
        for system in ("baseline", "threatgraph"):
            sys_rec = r[system]
            rows.append({
                "question_id": r["question_id"],
                "category": r.get("category"),
                "required_hops": r["required_hops"],
                "system": system,
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
    return pd.DataFrame(rows)


def compare_metric(df: pd.DataFrame, metric: str, by: Optional[str] = None) -> dict:
    """Paired comparison of `metric` between systems, optionally grouped by
    a column (e.g. 'category' or 'required_hops')."""
    pivot = df.pivot(index="question_id" if by is None else ["question_id", by],
                      columns="system", values=metric)
    if by is None:
        a, b = pivot["baseline"].dropna().values, pivot["threatgraph"].dropna().values
        return {"overall": paired_test(a, b)}

    out = {}
    for group_val, sub in pivot.groupby(level=by):
        a, b = sub["baseline"].dropna().values, sub["threatgraph"].dropna().values
        if len(a) and len(b):
            out[str(group_val)] = paired_test(a, b)
    return out


def full_analysis(raw_path: Optional[Path] = None, ragas_csv: Optional[Path] = None) -> dict:
    df = load_raw_results(raw_path)
    analysis = {
        "latency_overall": compare_metric(df, "total_latency_seconds"),
        "latency_by_category": compare_metric(df, "total_latency_seconds", by="category"),
        "latency_by_hops": compare_metric(df, "total_latency_seconds", by="required_hops"),
        "context_chars_overall": compare_metric(df, "context_chars"),
        "n_retrieved_chunks_overall": compare_metric(df, "n_retrieved_chunks"),
    }

    ragas_path = ragas_csv or (RESULTS_DIR / "ragas_metrics.per_record.csv")
    if ragas_path.exists():
        ragas_df = pd.read_csv(ragas_path)
        # Expect columns: question_id (or user_input join key), system, faithfulness,
        # answer_relevancy, context_precision, context_recall -- produced by
        # whatever script assembles ragas input records with these identifiers preserved.
        for metric in ("faithfulness", "answer_relevancy", "context_precision", "context_recall"):
            if metric in ragas_df.columns and "system" in ragas_df.columns:
                analysis[f"ragas_{metric}_overall"] = compare_metric(ragas_df, metric)
                if "category" in ragas_df.columns:
                    analysis[f"ragas_{metric}_by_category"] = compare_metric(ragas_df, metric, by="category")
    else:
        analysis["ragas_note"] = (
            f"{ragas_path} not found -- RAGAS metrics were not available for statistical "
            "comparison. Run scripts/run_ragas_eval.sh first."
        )

    return analysis


if __name__ == "__main__":
    out = full_analysis()
    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "statistical_analysis.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, indent=2, default=str))

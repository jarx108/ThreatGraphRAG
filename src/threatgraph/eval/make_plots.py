"""Generate static comparison figures for the paper/results directory.

Color/series conventions (static, non-interactive matplotlib PNGs -- the
hover/tooltip/table-view guidance for interactive charts does not apply
here, but the color-assignment and single-axis rules do):
  - System A (baseline, text-only RAG): blue  (#2a78d6), fixed slot 1.
  - System B (ThreatGraph, graph-augmented RAG): orange (#eb6834), fixed slot 2.
  - A chart never mixes two y-scales (no dual axes); paired measures on
    different scales get separate subplots instead.
  - Per-question signed differences use the blue<->red diverging pair with a
    neutral gray zero-line, not a rainbow.
Only real measurements already written to results/*.json|csv are plotted;
if an input file is missing, that figure is skipped (not faked).
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from threatgraph.config import RESULTS_DIR

BLUE = "#2a78d6"     # System A (baseline)
ORANGE = "#eb6834"   # System B (ThreatGraph)
RED = "#e34948"
GRAY = "#8a8a86"
FIGURES_DIR = RESULTS_DIR / "figures"

plt.rcParams.update({
    "font.size": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.edgecolor": "#52514e",
    "axes.labelcolor": "#0b0b0b",
    "text.color": "#0b0b0b",
    "xtick.color": "#52514e",
    "ytick.color": "#52514e",
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


def _save(fig, name: str) -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    path = FIGURES_DIR / name
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {path}")


def plot_ragas_comparison(ragas_json: Path) -> None:
    if not ragas_json.exists():
        print(f"Skipping RAGAS comparison plot: {ragas_json} not found.")
        return
    summary = json.loads(ragas_json.read_text(encoding="utf-8"))
    # Expect per-system mean scores to have been merged in by the caller;
    # this function also tolerates a single combined mean_scores block.
    metrics = list(summary.get("baseline", summary.get("mean_scores", {})).keys())
    if not metrics:
        print("Skipping RAGAS comparison plot: no metrics found.")
        return

    baseline_vals = [summary.get("baseline", {}).get(m, np.nan) for m in metrics]
    threatgraph_vals = [summary.get("threatgraph", {}).get(m, np.nan) for m in metrics]

    x = np.arange(len(metrics))
    width = 0.32
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(x - width / 2, baseline_vals, width, label="System A: Baseline RAG", color=BLUE)
    ax.bar(x + width / 2, threatgraph_vals, width, label="System B: ThreatGraph", color=ORANGE)
    ax.set_xticks(x)
    ax.set_xticklabels([m.replace("_", " ").title() for m in metrics], rotation=15, ha="right")
    ax.set_ylabel("Score (0-1)")
    ax.set_ylim(0, 1.05)
    ax.set_title("RAGAS Metrics: Baseline vs. ThreatGraph")
    ax.legend(frameon=False)
    _save(fig, "ragas_comparison.png")


def plot_extraction_metrics(extraction_json: Path) -> None:
    if not extraction_json.exists():
        print(f"Skipping extraction metrics plot: {extraction_json} not found.")
        return
    data = json.loads(extraction_json.read_text(encoding="utf-8"))
    metrics = data.get("metrics", data)
    labels = ["Precision", "Recall", "F1"]
    values = [metrics.get("precision", np.nan), metrics.get("recall", np.nan), metrics.get("f1", np.nan)]

    fig, ax = plt.subplots(figsize=(4.5, 4))
    ax.bar(labels, values, color=BLUE, width=0.5)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Triple Extraction Performance")
    for i, v in enumerate(values):
        if not np.isnan(v):
            ax.text(i, v + 0.02, f"{v:.2f}", ha="center")
    _save(fig, "extraction_metrics.png")


def plot_latency_comparison(raw_results_json: Path) -> None:
    if not raw_results_json.exists():
        print(f"Skipping latency plot: {raw_results_json} not found.")
        return
    records = json.loads(raw_results_json.read_text(encoding="utf-8"))
    stages = ["retrieval_latency_seconds", "generation_latency_seconds", "total_latency_seconds"]
    stage_labels = ["Retrieval", "Generation", "Total"]

    baseline_means = [np.mean([r["baseline"][s] for r in records]) for s in stages]
    threatgraph_means = [np.mean([r["threatgraph"][s] for r in records]) for s in stages]

    x = np.arange(len(stages))
    width = 0.32
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(x - width / 2, baseline_means, width, label="System A: Baseline RAG", color=BLUE)
    ax.bar(x + width / 2, threatgraph_means, width, label="System B: ThreatGraph", color=ORANGE)
    ax.set_xticks(x)
    ax.set_xticklabels(stage_labels)
    ax.set_ylabel("Mean latency (seconds)")
    ax.set_title("Latency by Pipeline Stage")
    ax.legend(frameon=False)
    _save(fig, "latency_comparison.png")


def plot_by_reasoning_depth(raw_results_json: Path, metric_key: str = "total_latency_seconds") -> None:
    if not raw_results_json.exists():
        print(f"Skipping by-depth plot: {raw_results_json} not found.")
        return
    records = json.loads(raw_results_json.read_text(encoding="utf-8"))
    df = pd.DataFrame([{
        "hops": r["required_hops"],
        "baseline": r["baseline"][metric_key],
        "threatgraph": r["threatgraph"][metric_key],
    } for r in records])
    grouped = df.groupby("hops")[["baseline", "threatgraph"]].mean().sort_index()

    x = np.arange(len(grouped))
    width = 0.32
    fig, ax = plt.subplots(figsize=(5.5, 4))
    ax.bar(x - width / 2, grouped["baseline"], width, label="System A: Baseline RAG", color=BLUE)
    ax.bar(x + width / 2, grouped["threatgraph"], width, label="System B: ThreatGraph", color=ORANGE)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{h}-hop" for h in grouped.index])
    ax.set_ylabel(metric_key.replace("_", " ").title())
    ax.set_title(f"{metric_key.replace('_', ' ').title()} by Reasoning Depth")
    ax.legend(frameon=False)
    _save(fig, f"by_reasoning_depth_{metric_key}.png")


def plot_per_question_diff(raw_results_json: Path, metric_key: str = "total_latency_seconds") -> None:
    if not raw_results_json.exists():
        print(f"Skipping per-question diff plot: {raw_results_json} not found.")
        return
    records = json.loads(raw_results_json.read_text(encoding="utf-8"))
    diffs = sorted(
        [(r["question_id"], r["threatgraph"][metric_key] - r["baseline"][metric_key]) for r in records],
        key=lambda t: t[1],
    )
    labels = [d[0] for d in diffs]
    values = [d[1] for d in diffs]
    colors = [RED if v > 0 else BLUE for v in values]

    fig, ax = plt.subplots(figsize=(7, max(4, 0.22 * len(labels))))
    ax.barh(labels, values, color=colors)
    ax.axvline(0, color=GRAY, linewidth=1)
    ax.set_xlabel(f"ThreatGraph - Baseline ({metric_key.replace('_', ' ')})")
    ax.set_title("Per-Question Difference (ThreatGraph vs. Baseline)")
    _save(fig, f"per_question_diff_{metric_key}.png")


def main() -> None:
    plot_extraction_metrics(RESULTS_DIR / "extraction_metrics.json")
    plot_latency_comparison(RESULTS_DIR / "raw_experiment_results.json")
    plot_by_reasoning_depth(RESULTS_DIR / "raw_experiment_results.json")
    plot_per_question_diff(RESULTS_DIR / "raw_experiment_results.json")
    plot_ragas_comparison(RESULTS_DIR / "ragas_metrics.json")


if __name__ == "__main__":
    main()

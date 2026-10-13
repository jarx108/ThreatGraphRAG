#!/usr/bin/env bash
# Runs the full real-data evaluation pipeline end to end:
# extraction eval -> both RAG systems over all benchmark questions ->
# statistics -> plots -> human-eval rubric. Requires a working LLM provider
# key already set in .env (or exported) and Neo4j already populated.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== 1/5: Real LLM extraction eval ==="
python3 -m threatgraph.eval.run_extraction_eval --sample-size 30

echo "=== 2/5: Full RAG experiments (both systems, all benchmark questions) ==="
python3 -m threatgraph.eval.run_experiments

echo "=== 3/5: Statistical analysis ==="
python3 -m threatgraph.eval.stats_analysis

echo "=== 4/5: Plots ==="
python3 -m threatgraph.eval.make_plots

echo "=== 5/5: Human eval rubric (blank, for manual rating) ==="
python3 -m threatgraph.eval.human_eval

echo "=== Experiment config snapshot ==="
python3 -m threatgraph.eval.write_experiment_config

echo "Done. See results/ for all outputs."

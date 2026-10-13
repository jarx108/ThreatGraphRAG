#!/usr/bin/env bash
# Run RAGAS evaluation in its isolated virtualenv (see
# src/threatgraph/eval/ragas_eval.py for why this is isolated).
# Usage: scripts/run_ragas_eval.sh <records.json> <output.json>
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv-ragas ]; then
  echo "Setting up .venv-ragas (one-time)..."
  scripts/setup.sh
fi

.venv-ragas/bin/python -m threatgraph.eval.ragas_eval "$1" "$2"

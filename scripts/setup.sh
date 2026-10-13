#!/usr/bin/env bash
# One-command, reproducible environment setup for ThreatGraph.
#
# Creates:
#   .venv/        main environment, Python 3.13, exact pins from requirements.lock
#   .venv-ragas/  optional isolated RAGAS environment, Python 3.11, exact pins
#                 from requirements-ragas.txt (see src/threatgraph/eval/ragas_eval.py)
# copies .env.example -> .env if .env does not exist yet, and pulls the pinned
# local LLM with Ollama (the default LLM_PROVIDER; no API key needed).
#
# Neo4j requirements: Neo4j 2026.09 / 5.x with the Graph Data Science plugin
# (APOC optional). `make neo4j-up` starts one in Docker with the plugins; in
# Neo4j Desktop use: instance > Plugins > Graph Data Science Library > Install.
#
# Usage: scripts/setup.sh [--skip-ragas] [--skip-ollama] [--recreate]
#
# Overridable via environment variables:
#   PYTHON=python3.13        RAGAS_PYTHON=python3.11
#   VENV_DIR=.venv           RAGAS_VENV_DIR=.venv-ragas
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3.13}"
RAGAS_PYTHON="${RAGAS_PYTHON:-python3.11}"
VENV_DIR="${VENV_DIR:-.venv}"
RAGAS_VENV_DIR="${RAGAS_VENV_DIR:-.venv-ragas}"
SKIP_RAGAS=0
SKIP_OLLAMA=0
RECREATE=0
for arg in "$@"; do
  case "$arg" in
    --skip-ragas) SKIP_RAGAS=1 ;;
    --skip-ollama) SKIP_OLLAMA=1 ;;
    --recreate) RECREATE=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

require_python() {  # $1 = interpreter, $2 = required major.minor
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: $1 not found. Install Python $2 (python.org, pyenv, or Homebrew)," >&2
    echo "       or point to it with ${3}=/path/to/python$2" >&2
    exit 1
  fi
  local got
  got="$("$1" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  if [ "$got" != "$2" ]; then
    echo "ERROR: $1 is Python $got, but Python $2 is required (the pinned versions were resolved for it)." >&2
    exit 1
  fi
}

make_venv() {  # $1 = python, $2 = venv dir, $3 = requirements file, $4 = extra pip flags
  if [ "$RECREATE" = 1 ] && [ -d "$2" ]; then
    rm -rf "$2"
  fi
  if [ ! -d "$2" ]; then
    "$1" -m venv "$2"
  fi
  "$2/bin/python" -m pip install --quiet --upgrade pip
  # shellcheck disable=SC2086
  "$2/bin/python" -m pip install --quiet ${4:-} -r "$3"
  # --no-deps: every dependency is already pinned by the requirements file.
  "$2/bin/python" -m pip install --quiet -e . --no-deps
}

echo "==> Main environment ($VENV_DIR, Python 3.13, requirements.lock)"
require_python "$PYTHON" 3.13 PYTHON
make_venv "$PYTHON" "$VENV_DIR" requirements.lock

if [ "$SKIP_RAGAS" = 0 ]; then
  echo "==> RAGAS environment ($RAGAS_VENV_DIR, Python 3.11, requirements-ragas.txt)"
  require_python "$RAGAS_PYTHON" 3.11 RAGAS_PYTHON
  # --no-deps: install the exact frozen set; see the header of requirements-ragas.txt.
  make_venv "$RAGAS_PYTHON" "$RAGAS_VENV_DIR" requirements-ragas.txt --no-deps
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Created .env from .env.example. Fill in NEO4J_PASSWORD (LLM API keys are only needed for hosted providers)."
fi

env_value() {  # value of $1 in .env (comment stripped), or $2 when unset
  local v
  v="$(grep -E "^$1=" .env 2>/dev/null | head -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*//; s/[[:space:]]*$//')"
  echo "${v:-$2}"
}

LLM_PROVIDER_VALUE="$(env_value LLM_PROVIDER ollama)"
if [ "$SKIP_OLLAMA" = 0 ] && [ "$LLM_PROVIDER_VALUE" = "ollama" ]; then
  MODEL="$(env_value LLM_MODEL llama3.1:8b)"
  echo "==> Local LLM via Ollama ($MODEL)"
  if ! command -v ollama >/dev/null 2>&1; then
    echo "ERROR: ollama not found. Install it from https://ollama.com/download" >&2
    echo "       (macOS: brew install ollama; Linux: curl -fsSL https://ollama.com/install.sh | sh)," >&2
    echo "       or set LLM_PROVIDER=gemini|openai|anthropic in .env, or pass --skip-ollama." >&2
    exit 1
  fi
  if ! ollama list >/dev/null 2>&1; then
    echo "ERROR: the Ollama server is not running. Start it (open the Ollama app, or run 'ollama serve')." >&2
    exit 1
  fi
  ollama pull "$MODEL"
fi

echo "==> Verifying imports and pre-downloading the pinned embedding model"
"$VENV_DIR/bin/python" - <<'PY'
import schemas, threatgraph  # noqa: F401  (fails fast if packaging is broken)
from threatgraph.config import EMBEDDING
from threatgraph.embeddings import get_embedder
get_embedder()
print(f"    embedding model {EMBEDDING.model_name} @ {EMBEDDING.revision}: OK")
PY
if [ "$SKIP_RAGAS" = 0 ]; then
  "$RAGAS_VENV_DIR/bin/python" -c "import ragas, schemas, threatgraph.eval.ragas_worker; print('    ragas', ragas.__version__, ': OK')"
fi

cat <<EOF

Setup complete. Next steps:
  source $VENV_DIR/bin/activate
  make neo4j-up        # or your own Neo4j 2026.09 / 5.x with the GDS plugin
  make pipeline        # populate -> GDS analytics -> extraction -> text ingestion -> NED eval -> benchmark
  make verify          # check the pipeline reproduces reproducibility/manifest.json
  make test && make app   # web UI at http://localhost:8000
EOF

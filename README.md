# ThreatGraph

**A knowledge graph + LLM system for multi-hop cyber threat intelligence (CTI) question answering**

CS 6338 Knowledge Engineering project. MITRE ATT&CK (structured STIX) and
free-text threat descriptions (unstructured, via a local LLM) are integrated
into one Neo4j property graph with per-edge provenance; Neo4j Graph Data
Science analyzes it; and a GraphRAG pipeline answers multi-hop questions from
the exact subgraph a question needs, with traceable citations. It is compared
against a text-only RAG baseline that uses the same LLM, prompt and text
retrieval.

## Where each required capability lives

| Rubric pillar | Implementation | Run | Web UI tab |
|---|---|---|---|
| **Schema & data ingestion**: structured + unstructured, edge provenance/timestamps/confidence | `ingestion/stix_loader.py`, `graph/populate.py` (STIX, `r.source`, `r.created`, `r.modified`, `r.confidence`, `r.stix_relationship_id`); `ingestion/text_ingest.py` (LLM-extracted facts, `source='llm_extraction'`, confidence, evidence, `verified`) | `make populate`, `make ingest-text` | 1 · Schema & Ingestion |
| **Graph analytics & reasoning**: GDS algorithms | `cypher/gds_analytics.cypher` (PageRank, Louvain, WCC, degree; shortest path; mitigation-coverage path counts), run by `graph/analytics.py` | `make analytics` | 2 · Graph Analytics |
| **LLM integration & NED**: structured extraction + disambiguation | `extraction/extractor.py` (Ollama decoding constrained to the Pydantic JSON Schema in `src/schemas.py`, then re-validated), `entity_resolution.py` (ID / alias / normalized name / embedding similarity; `find_mentions` for free text), `eval/ned_eval.py` | `make extraction-eval`, `make ned-eval` | 3 · Extraction & NED |
| **GraphRAG & interpretability**: multi-hop subgraph + GDS outputs in the prompt | `rag/graphrag.py` (NED → asked-for type → typed multi-hop traversal in `graph/traversal.py` → GDS signals → generation), `eval/answer_metrics.py` | `make benchmark` | 4 · GraphRAG |

## Repository layout

```
Makefile                          One-word entry points for every task (`make help`)
docker-compose.yml                Pinned Neo4j 2026.09.0 with the GDS (+ APOC) plugins
requirements.lock                 Exact pins for the main environment (Python 3.13)
requirements.txt                  Direct dependencies only (human-readable)
requirements-ragas.txt            Optional isolated RAGAS environment (Python 3.11)
reproducibility/manifest.json     Expected fingerprints of every deterministic pipeline stage
.github/workflows/                CI: rebuild + verify the pipeline from scratch on Linux
schema.cypher                     Neo4j constraints + lookup indexes
cypher/gds_analytics.cypher       Graph Data Science + path-reasoning statements (runnable with cypher-shell)
src/schemas.py                    Pydantic ontology (entities, relationships, provenance)
prompts/extraction_prompt.txt     LLM extraction prompt
scripts/setup.sh                  One-command setup: venv from the lock file, .env, Ollama model
src/threatgraph/
  config.py                       All configuration (env-var driven, no hardcoded secrets) + pins
  ingestion/stix_loader.py        Download + hash-verify + parse MITRE ATT&CK STIX (incl. edge timestamps)
  ingestion/chunking.py           Entity-description chunking with provenance
  ingestion/text_ingest.py        Unstructured source: LLM-extracted facts -> Neo4j edges with provenance
  extraction/extractor.py         Prompt -> LLM (schema-constrained) -> Pydantic validation -> NED
  entity_resolution.py            Named Entity Disambiguation against canonical ATT&CK nodes
  graph/populate.py               Structured source -> Neo4j (idempotent MERGE, edge provenance)
  graph/analytics.py              Runs cypher/gds_analytics.cypher, writes results/graph_analytics.json
  graph/traversal.py              Vector search, question-focused multi-hop traversal, GDS context
  rag/llm_provider.py             Ollama (default, local) / Gemini / OpenAI / Anthropic, cached
  rag/baseline_rag.py             Text-only RAG baseline
  rag/graphrag.py                 GraphRAG
  eval/answer_metrics.py          Deterministic answer accuracy / precision / hallucination / traceability
  eval/run_benchmark.py           30-question benchmark -> results/benchmark_results.json
  eval/ned_eval.py                NED accuracy vs exact-name lookup -> results/ned_evaluation.json
  eval/run_extraction_eval.py     Extraction P/R/F1 vs gold triples -> results/extraction_metrics.json
  api/app.py, api/pillars.py      FastAPI backend for the web UI
  llm_cache.py                    Response cache (data/cache/llm_responses.sqlite)
  repro.py                        Reproducibility verifier (`make verify`)
frontend/                         Web UI (React + TypeScript): Introduction + one tab per pillar
app/streamlit_app.py              Legacy Streamlit UI (make ui-streamlit)
data/gold_triples.json            60 gold triples derived from MITRE ATT&CK Enterprise v19.2
data/eval_queries.json            30 multi-hop questions with verified answers (2- and 3-hop)
paper/                            IEEE-format LaTeX manuscript
results/                          Pipeline outputs (analytics, extraction, NED, benchmark)
```

## Setup

Requirements: Python 3.13, [Ollama](https://ollama.com/download) (local LLM,
no API key), Neo4j 2026.09 / 5.x **with the Graph Data Science plugin**
(APOC optional; n10s is not used), and Node >= 18.17 for the web UI.

```bash
scripts/setup.sh        # or: make setup
#   creates .venv from requirements.lock (+ optional .venv-ragas), copies .env.example -> .env,
#   pre-downloads the pinned embedding model, and runs `ollama pull llama3.1:8b`
#   options: --skip-ragas, --skip-ollama, --recreate; PYTHON=/path/to/python3.13
source .venv/bin/activate
# edit .env: NEO4J_PASSWORD (no LLM key needed with the default LLM_PROVIDER=ollama)
make neo4j-up           # Docker Neo4j with GDS + APOC (docker-compose.yml), or:
                        # Neo4j Desktop -> instance -> Plugins -> Graph Data Science Library -> Install
```

The LLM is `llama3.1:8b` served by Ollama at temperature 0 with a fixed seed
(`LLM_SEED=13`) and a 16k context. Embeddings are a local, revision-pinned
`sentence-transformers/all-MiniLM-L6-v2`. Hosted LLMs remain available with
`LLM_PROVIDER=gemini|openai|anthropic` and the matching API key.

## Running the pipeline

```bash
make populate         # [1] MITRE ATT&CK STIX -> Neo4j (entities, 18.6k edges with provenance, chunks, embeddings)
make analytics        # [2] GDS PageRank / Louvain / WCC / degree, written back to nodes
make extraction-eval  # [3] Ollama extraction over 60 MITRE descriptions, scored against gold triples
make ingest-text      # [3] extracted facts -> Neo4j as the unstructured source (cross-checked vs MITRE)
make ned-eval         # [3] NED accuracy on 4,968 MITRE names/aliases/IDs
make benchmark        # [4] 30 multi-hop questions through text-only RAG and GraphRAG
make pipeline         #     all of the above, in order
make verify           # reproducibility check against reproducibility/manifest.json
make test             # test suite
make app              # web UI + API at http://localhost:8000
```

## Web UI

`frontend/` is a React + TypeScript (Vite) app served by FastAPI
(`src/threatgraph/api/`). It has five tabs:

0. **Introduction**: problem statement, why CTI, the pipeline, headline results.
1. **Schema & Ingestion**: both sources, the live schema with counts, the STIX → label
   mapping, one real edge with all provenance properties, and LLM-extracted facts with
   their confidence and MITRE confirmation.
2. **Graph Analytics**: topology, PageRank leaders per type, Louvain communities, and
   path reasoning (mitigation coverage, shortest path). Can re-run GDS.
3. **Extraction & NED**: run schema-constrained extraction on any text, link entities
   in any text, NED accuracy vs exact-name lookup, and extraction precision/recall.
4. **GraphRAG**: ask both systems; see GraphRAG's linked entities, asked-for type,
   multi-hop subgraph (with STIX relationship IDs), GDS signals and graded citations;
   benchmark results.

Development with hot reload: `make api` + `make dev` (http://localhost:5173).

## Response cache (fewer API calls)

Every LLM call (answer generation, extraction) and every RAGAS judgement is
cached in `data/cache/llm_responses.sqlite` (`src/threatgraph/llm_cache.py`).
An identical request -- same provider, model, system prompt, user prompt
(which includes the full retrieved evidence), temperature and max tokens --
is answered from the cache instead of calling the provider. RAGAS scores are
reused when the question, answer, contexts, reference answer and judge
configuration are all identical; incomplete score sets (failed judge calls)
are never cached, so they are retried.

A cached answer is flagged (`generation_cached`, a "Cached answer" badge in
the UI) and reports the latency, tokens and cost **measured when it was
originally generated**, so latency statistics are not distorted by ~0 s
cache reads.

```bash
python -m threatgraph.llm_cache stats
python -m threatgraph.llm_cache import-experiments  # reuse results/raw_experiment_results.json answers
python -m threatgraph.llm_cache clear [--namespace llm|ragas]
```

`import-experiments` only imports an earlier answer when today's retrieval
returns exactly the evidence it was generated from (and the same model and
settings), i.e. when today's prompt is identical. Turn the cache off with
`LLM_CACHE=0`, or untick "Reuse cached answers" on the Ask page for a fresh call.

## Reproducibility

Everything upstream of the LLM is deterministic and pinned, and
`make verify` proves it against `reproducibility/manifest.json`:

| Stage | How it is pinned | What `make verify` checks |
|---|---|---|
| Dependencies | `requirements.lock` / `requirements-ragas.txt`: every package, exact version | (installed by `scripts/setup.sh`) |
| Source data | ATT&CK v19.2 STIX, SHA-256 of its canonical JSON in `config.ATTACK_STIX_SHA256`; the loader refuses any other content | content hash |
| Benchmark | `scripts/build_benchmarks.py` uses only sorted selections; re-running it reproduces `data/*.json` byte for byte | file hashes |
| Parsing + chunking | pure functions of the verified bundle | entity/relationship/chunk hashes |
| Embeddings | model + exact Hugging Face commit (`EMBEDDING_MODEL_REVISION`) | probe vectors, tolerance 1e-4 |
| Graph | idempotent `MERGE` load; Neo4j version pinned in `docker-compose.yml` | node/relationship counts, full edge-list hash, stored embeddings vs. recomputed |
| Retrieval | every Cypher query that uses `LIMIT` or `collect()` has an explicit `ORDER BY`; vector-search ties are broken by `chunk_id`; APOC is opt-in (`GRAPH_TRAVERSAL_USE_APOC`) so plugin availability cannot change results | both systems' retrieved chunks and graph facts for all 30 benchmark questions, run twice |
| LLM | `temperature=0`, `LLM_SEED=13` (OpenAI and Gemini; Anthropic has no seed), model name recorded | not asserted (see below) |

Hosted LLMs are only best-effort deterministic even at temperature 0 with a
seed, so generated answers and LLM-judged scores are **recorded** per run
(`results/raw_experiment_results.json`, `results/ui_evaluations.json`) rather
than asserted to be identical across runs. `make config` writes
`results/experiment_config.json` with the git commit, lock-file hash, STIX
hash, model names/revisions, seed and every retrieval parameter for each run.

Verified so far: the manifest was generated on macOS (arm64, Python 3.13);
the full check passes after wiping and re-populating Neo4j, and in a fresh
copy of the repository built only with `scripts/setup.sh` from empty
package, STIX and model caches. `.github/workflows/reproducibility.yml`
repeats the whole build + verification on Linux with the pinned Neo4j
container on every push to GitHub (not yet run at the time of writing).

Only regenerate the manifest (`make manifest`) when an input is changed on
purpose (new ATT&CK version, embedding model, chunking parameters, ...).

## Legacy experiments (hosted LLM + RAGAS)

The earlier evaluation in `results/raw_experiment_results.json`,
`results/ragas_metrics.json` and `results/statistical_analysis.json` was run
with `gemini-3.1-flash-lite` and a RAGAS judge, before the question-focused
GraphRAG traversal and the switch to Ollama. It is kept for reference
(`make experiments`, `make ragas`, `python -m threatgraph.eval.stats_analysis`);
the current headline numbers come from `make benchmark`
(`results/benchmark_results.json`).

## Why RAGAS runs in an isolated virtualenv

`ragas` (as of the latest PyPI release available when this project was
built) unconditionally imports `langchain_community.chat_models.vertexai`,
a module removed from current `langchain-community` releases. Resolving
that forces a pre-1.0 `langchain`/`langchain-core`/`langchain-community`
stack that conflicts with this project's other dependencies. Rather than
downgrade the whole project's environment for one evaluation step,
`scripts/run_ragas_eval.sh` uses `.venv-ragas/` (built by `scripts/setup.sh`
from the exact pins in `requirements-ragas.txt`, installed with `--no-deps`
because that working set's declared metadata is not mutually satisfiable --
see the file header) and invokes `threatgraph.eval.ragas_eval` through
that interpreter. That module only reads/writes JSON and has no dependency
on `threatgraph.graph`/`threatgraph.embeddings` (so it needs neither Neo4j
driver nor sentence-transformers/torch installed there).

## Credentials this project needs (and never hardcodes)

| Variable | Needed for |
|---|---|
| `NEO4J_PASSWORD` (+ `NEO4J_URI`/`NEO4J_USER`) | the knowledge graph |
| none (default `LLM_PROVIDER=ollama`) | extraction and answer generation run locally |
| `GEMINI_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | only when `LLM_PROVIDER` is a hosted provider |
| key for `RAGAS_JUDGE_PROVIDER` | only for the optional legacy RAGAS evaluation |

Gemini note: `threatgraph.rag.llm_provider` disables "thinking" for Gemini
calls (`thinking_config.thinking_budget=0`) -- with it left on, a model like
`gemini-3.8-flash` spent most of `max_output_tokens` on internal reasoning
tokens and truncated structured-JSON extraction output mid-string. Per-model
pricing for cost estimation lives in `config/pricing.json`; a model released
after this project's knowledge cutoff (e.g. `gemini-3.8-flash`) is
deliberately left out rather than given a guessed price, so
`estimated_cost_usd` reports `null` for it until a verified price is added.

All are read from the environment via `threatgraph.config` / `.env`; none are
committed to this repository.

## Benchmark design and leakage prevention

`gold_triples.json` (60 triples) and `eval_queries.json` (30 multi-hop QA
records) are both derived programmatically from the official MITRE
Enterprise ATT&CK v19.2 STIX bundle (`scripts/build_benchmarks.py`), not
hand-written. Three reasoning-path categories are covered:

| Category | Hops | Graph path | Count |
|---|---|---|---|
| `group_technique_mitigation` | 2 | ThreatGroup -USES-> Technique <-MITIGATES- Mitigation | 14 |
| `group_software_technique` | 2 | ThreatGroup -USES-> Software -USES-> Technique | 8 |
| `group_software_technique_mitigation` | 3 | ThreatGroup -USES-> Software -USES-> Technique <-MITIGATES- Mitigation | 8 |

`expected_answer` is attached to result records only *after* both RAG
systems have already answered -- it is never passed into a prompt or a
retrieval query (see `threatgraph/eval/run_experiments.py`).

## Evaluation metrics (definitions in the eval modules' docstrings)

- **Answer quality** (`eval/answer_metrics.py`, no judge LLM): every benchmark
  question has a verified answer made of ATT&CK IDs. *Answer accuracy* = share
  of expected IDs the answer names; *precision* = share of the answer's IDs of
  the asked-for type that are correct; *fully correct* = all expected IDs
  named; *hallucinated IDs* = cited IDs absent from the system's retrieved
  evidence; *traceable citations* = cited IDs backed by a retrieved graph fact
  with a STIX relationship ID; plus end-to-end latency.
- **NED** (`eval/ned_eval.py`): accuracy of linking 4,968 mentions (canonical
  names, aliases, lower-cased aliases, ATT&CK IDs) to the right node, against
  an exact-name-lookup baseline.
- **Extraction** (`eval/extraction_metrics.py`): triple precision / recall /
  F1 against `data/gold_triples.json` after NED, plus precision verified
  against the full ATT&CK relationship set.
- **Graph analytics** (`graph/analytics.py`): topology (density, degree,
  components), PageRank, Louvain communities and modularity.

## Data source

MITRE ATT&CK STIX Data: https://github.com/mitre-attack/attack-stix-data
Pinned release: Enterprise ATT&CK v19.2.
This project makes use of MITRE ATT&CK(R).

# Evaluation Summary

Status as of this writing. Everything under "Completed" reflects real
measurements from this repository's actual code run against live services
(MITRE ATT&CK STIX, a local Neo4j instance, and the Gemini API). Nothing
here is fabricated or extrapolated; see `raw_experiment_results.json`,
`extraction_metrics.json`, `extraction_raw_records.json`, and
`statistical_analysis.json` for the underlying per-record data.

## Infrastructure (completed)

- **MITRE ATT&CK STIX ingestion**: live download and parse of Enterprise
  ATT&CK v19.2. 1,798 active entities (176 ThreatGroup, 697 Technique, 825
  Software, 56 Campaign, 44 Mitigation), 18,613 relationships.
- **Neo4j knowledge graph**: schema initialized, full bundle loaded --
  1,798 entity nodes, 18,613 relationship edges, 3,079 text chunks with
  384-dim local embeddings, vector index ONLINE. Population is idempotent
  (parameterized `MERGE`).
- **Benchmark generation**: `gold_triples.json` (60 triples, one per unique
  subject entity after a round-robin diversity fix -- see "Bugs found and
  fixed" below) and `eval_queries.json` (30 multi-hop QA records: 14
  two-hop ThreatGroup-Technique-Mitigation, 8 two-hop
  ThreatGroup-Software-Technique, 8 three-hop
  ThreatGroup-Software-Technique-Mitigation), all derived programmatically
  from live STIX data.
- **Streamlit UI**: boots and connects to Neo4j successfully (verified via
  HTTP request to a running instance).
- **Test suite**: 28/28 tests pass (`python -m pytest tests/ -v`).

## Experiments executed with a real LLM (gemini-3.1-flash-lite)

- **Full RAG experiment**: both systems answered all 30 benchmark
  questions (60 real generation calls). Results in
  `raw_experiment_results.json`, `baseline_results.csv`,
  `graphrag_results.csv`, `comparison.csv`. No errors in the final run.
- **Extraction evaluation**: real LLM extraction run against all 60
  gold-triple subject entities (60 real extraction calls). Results in
  `extraction_metrics.json` and `extraction_raw_records.json`.
- **RAGAS evaluation**: Faithfulness, Answer Relevancy, Context Precision,
  Context Recall, judged by `gpt-4o-mini` (switched from Gemini after
  RAGAS's per-metric call fan-out exhausted Gemini's daily quota -- see
  "Infrastructure blockers" below), computed in an isolated virtualenv
  (`.venv-ragas/`) with local (no-API-key) embeddings for Answer Relevancy.
  All 60/60 records succeeded for all 4 metrics (0 failures). Folded into
  `comparison.csv` and `statistical_analysis.json`.
- **Statistical analysis**: paired t-test, Wilcoxon signed-rank, 95% CIs,
  breakdowns by category and reasoning depth, computed on the full
  30-question dataset (`statistical_analysis.json`).

## Key findings (real, measured)

- **RAGAS (n=30 paired, 60 judged answers, gpt-4o-mini judge)**:
  - Answer Relevancy: baseline 0.000 -> ThreatGraph 0.430 (paired t(29),
    p=3.4e-6; Wilcoxon p=3.1e-5). Baseline very frequently produces a
    refusal-style non-answer ("the provided context does not contain
    information linking..."), which RAGAS's relevancy metric correctly
    scores as unrelated to the specific question asked.
  - Context Recall: baseline 0.067 -> ThreatGraph 0.644 (+866% relative;
    paired t(29)=7.88, p=1.1e-8). Baseline's 5 text chunks rarely happen to
    state the specific technique-mitigation pairing a question asks about;
    ThreatGraph's graph facts supply it directly.
  - Context Precision: baseline 0.296 -> ThreatGraph 0.415 (+40.5%), not
    significant at n=30 (p=0.068 paired-t, p=0.098 Wilcoxon) -- directional
    but not conclusive.
  - Faithfulness: baseline 0.958 vs ThreatGraph 0.887, not significant
    (p=0.162/0.183) -- no credible claim that either system is less
    grounded in its own retrieved evidence.
  - By reasoning depth: ThreatGraph's Answer Relevancy gain is concentrated
    entirely in 2-hop questions (0.586 mean); on 3-hop questions BOTH
    systems score 0.000 on Answer Relevancy even though ThreatGraph's
    Context Recall still improves (0.000 -> 0.275) -- the bottleneck for
    the hardest questions appears to be answer synthesis, not retrieval.
- **Context volume**: System B (ThreatGraph) adds 1,164.8 characters of
  context on average (+66.6%, paired t(29)=51.3, p=5.1e-30) -- this is the
  intended manipulation, not a side effect.
- **Latency**: no statistically significant difference between systems
  (paired-t p=0.24, Wilcoxon p=0.42, n=30); both show high variance
  dominated by a handful of multi-second outliers consistent with
  provider-side rate-limit backoff, not a systematic architectural
  difference. Retrieval latency itself is negligible for both systems
  (<0.1s mean); generation dominates total latency for both.
- **Extraction**: strict precision/recall against the 60-triple sample are
  low (0.115 / 0.050), but a large majority of "false positives" (15 of 23,
  65%) are verified-real STIX relationships simply outside the narrow
  sample, not fabrications -- adjusted precision crediting those is 0.692.
  See `extraction_metrics.json`'s `false_positive_breakdown` field and the
  paper's Limitations section for the full explanation.
- A worked example (`T1055` / Process Injection) during manual verification
  showed System A (baseline) could not identify any threat group using the
  technique from its top-5 retrieved chunks, while System B correctly
  identified 7 real ATT&CK threat groups via graph traversal -- a concrete,
  qualitative illustration of the hypothesized GraphRAG advantage, directly
  consistent with the formal Answer Relevancy/Context Recall results above.

## Bugs found and fixed during this evaluation (real engineering findings)

1. **Reversed relationship direction** in the APOC-free bounded-traversal
   fallback: an undirected `(n)-[r]-(m)` match reported `src`/`tgt` based on
   which side matched the seed node, not the edge's actual stored
   direction, silently inverting facts like "Software USES Technique" into
   "Technique USES Software."
2. **Dedup key mismatch**: `GraphFact` construction read `src_id`/`tgt_id`
   keys that didn't exist in the traversal query's result dicts (which used
   `src`/`tgt`), collapsing nearly all facts together during
   deduplication and silently dropping real graph evidence.
3. **Cypher aggregation grouping bug**: including an unaggregated variable
   (`m1`) alongside a `collect(DISTINCT ...)` in the same `WITH` clause
   silently grouped the aggregation per-`m1`, splitting one intended list
   into many single-item rows.
4. **Hub-node fact starvation**: capping graph facts to the first N from
   Cypher's arbitrary collection order let one high-volume relationship
   type (e.g. dozens of Software-USES edges on a common technique) crowd
   out rarer, more directly relevant types (ThreatGroup/Mitigation edges).
   Fixed with a two-phase (1-hop before 2-hop) round-robin across
   (hop-distance, entity-type) buckets.
5. **Chunk text silently dropped** from saved experiment results (only
   chunk IDs were kept), which would have broken both the "save retrieved
   evidence" requirement and RAGAS (which needs the actual retrieved text).
6. **Benchmark sampling bias**: `gold_triples.json`'s original selection
   sorted by subject before capping each relation-shape's quota, so one
   prolific subject could fill an entire shape's 20-triple quota alone --
   leaving only 6 of 60 triples with unique subjects reachable by
   entity-level extraction evaluation. Fixed with round-robin selection
   across distinct subjects within each shape (now 60/60 unique subjects).
7. **Extraction prompt gaps**: the model extracted MITRE's inline
   bibliographic citation markers (e.g. "(Citation: ...)") as spurious
   Document entities, and frequently proposed relationship shapes outside
   the ontology (e.g. Software-USES-Software, reversed
   ATTRIBUTED_TO direction). Fixed by adding an explicit
   ignore-citations rule and an explicit table of every allowed
   (subject-type, predicate, object-type) shape to the prompt.
8. **All-or-nothing extraction validation**: the original Pydantic
   validation rejected an LLM's *entire* extraction output if even one
   relationship had a disallowed shape, discarding otherwise-valid
   entities/relationships and artificially depressing measured recall.
   Fixed with per-item lenient validation
   (`threatgraph.extraction.extractor._validate_leniently`) that keeps
   valid entities/relationships and records rejected ones separately.
9. **Pointless retries on exhausted quota**: the LLM provider's retry logic
   treated all 429 errors as short transient failures and retried with a
   30s backoff, which is useless against a quota with a 20-hour reset and
   just wastes more of an already-exhausted quota. Fixed to parse the
   provider's actual suggested retry delay and only retry when it's short
   (<=120s); genuinely long delays are raised immediately so the caller can
   stop and save partial results instead of blocking for hours.
10. **Lost partial results on crash**: both `run_extraction_eval.py` and
    `run_experiments.py` originally wrote output only once, at the very
    end -- a crash or exhausted quota partway through (which happened
    twice during this evaluation) discarded all real results already
    obtained. Fixed to write incrementally after each item/question.

## Infrastructure blockers encountered and resolved

Google's Gemini free tier enforces per-model request quotas, hit twice:

1. An initial model choice (`gemini-3.8-flash`) hit a 20-requests/day cap
   (shared across exploratory testing and the first batch run) with a
   ~20-hour reset; generation/extraction were completed instead on
   `gemini-3.1-flash-lite`, which has a separate, much more workable
   15-requests/minute quota.
2. RAGAS evaluation hit a *different* quota wall on the same
   `gemini-3.1-flash-lite` model: a single RAGAS metric does not map to one
   LLM call per record (Faithfulness alone issues a claim-extraction call
   plus one verification call per claim; Context Precision/Recall issue a
   call per retrieved context item), so evaluating 60 records x 4 metrics
   fanned out into several hundred real calls and exhausted a
   500-requests/day limit, independent of the per-minute limit above. A
   first RAGAS attempt with default concurrency (16 parallel workers)
   additionally caused most individual judge calls to time out waiting
   behind the rate limit (only 3-19 of 60 records got real scores per
   metric); throttling concurrency to 2-4 workers fixed the timeout problem
   but didn't fix the daily quota. RAGAS judging was switched to a separate
   provider/model (`gpt-4o-mini`, OpenAI) to get complete, reliable scores
   for all 60 records across all 4 metrics.

Both are documented as real constraints in the paper's Limitations section,
not hidden, along with the concurrency fix
(`threatgraph.eval.ragas_eval`'s `RunConfig`) and the judge-provider
decoupling (`RAGAS_JUDGE_PROVIDER`, separate from `LLM_PROVIDER`).

## Not yet done

- Human evaluation: the blank 1-5 rubric CSV
  (`results/human_eval_rubric.csv`, 60 rows) is generated; no human has
  rated any answers yet, and none are reported here.
- Expanding Related Work with additional verified academic citations beyond
  the three already in `paper/main.tex` (Lewis et al. 2020 on RAG, Es et
  al. 2024 on RAGAS, MITRE ATT&CK) -- adding more without the ability to
  verify them against their real sources risks citation fabrication, which
  the project's instructions explicitly prohibit.
- PDF compilation of `paper/main.tex` (no LaTeX distribution installed in
  this environment; brace/environment balance was checked manually, not by
  a real compiler).

## Reproducing this evaluation

```bash
export GEMINI_API_KEY=...   # or put it in .env
python -m threatgraph.eval.run_extraction_eval --sample-size 60
python -m threatgraph.eval.run_experiments
python -m threatgraph.eval.build_ragas_records
scripts/run_ragas_eval.sh results/ragas_input_records.json results/ragas_metrics.json
python -m threatgraph.eval.stats_analysis
python -m threatgraph.eval.export_csv
python -m threatgraph.eval.make_plots
python -m threatgraph.eval.human_eval
```

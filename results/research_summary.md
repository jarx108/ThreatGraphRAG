# ThreatGraph Research Summary

Based on real measurements from a 30-question multi-hop benchmark (both
systems, all questions answered, 60 total judged answers) and a 60-triple
extraction benchmark (all 60 subjects attempted). Generation and extraction
used `gemini-3.1-flash-lite`; RAGAS judging used `gpt-4o-mini` (switched
providers after Gemini's daily quota was exhausted by RAGAS's per-metric
call fan-out -- see `evaluation_summary.md`). Underlying data:
`results/raw_experiment_results.json`, `results/extraction_metrics.json`,
`results/ragas_metrics.json` (+ `.per_record.csv`),
`results/statistical_analysis.json`, `results/comparison.csv`.

## 1. Did ThreatGraph outperform traditional RAG?

Yes, on the two RAGAS metrics that most directly measure whether the system
answers the question with the right information:

- **Answer Relevancy**: 0.000 -> 0.430 (paired t(29), p=3.4e-6; Wilcoxon
  p=3.1e-5).
- **Context Recall**: 0.067 -> 0.644, +866% relative (paired t(29)=7.88,
  p=1.1e-8; Wilcoxon p=2.1e-5).

No significant difference in Faithfulness (p=0.162) and a directionally
positive but non-significant difference in Context Precision (p=0.068).
Infrastructure metrics (latency, retrieval cost) showed no significant
penalty for ThreatGraph despite retrieving substantially more context.

## 2. Which metrics improved, and by how much?

| Metric | System A | System B | Relative change | Paired p (t / Wilcoxon) |
|---|---|---|---|---|
| Answer Relevancy | 0.000 | 0.430 | n/a (from zero) | 3.4e-6 / 3.1e-5 |
| Context Recall | 0.067 | 0.644 | +866.6% | 1.1e-8 / 2.1e-5 |
| Context Precision | 0.296 | 0.415 | +40.5% | 0.068 / 0.098 (n.s.) |
| Context length (chars) | 1748.9 | 2913.8 | +66.6% | 5.1e-30 / 1.7e-6 |

## 3. Which metrics declined, if any?

Faithfulness was nominally lower for ThreatGraph (0.958 vs. 0.887) but not
significantly (p=0.162 paired-t, p=0.183 Wilcoxon). Qualitatively, System
A's short refusal-style non-answers ("the context does not contain...")
are trivially faithful to whatever little they cite, which plausibly
inflates System A's Faithfulness score without reflecting genuinely better
grounding. No RAGAS or infrastructure metric showed a statistically
significant decline for ThreatGraph.

## 4. Did graph retrieval improve multi-hop question answering?

Yes overall (Answer Relevancy, Context Recall above), but with a specific,
important caveat by reasoning depth -- see question 5.

## 5. Were improvements different for two-hop vs. three-hop questions?

Yes, substantially. Breaking Answer Relevancy down by `required_hops`:

- **2-hop (n=22)**: System A 0.000, System B 0.586.
- **3-hop (n=8)**: System A 0.000, System B 0.000.

ThreatGraph's Answer Relevancy advantage is concentrated entirely in 2-hop
questions. For 3-hop questions, Context Recall still improved for
ThreatGraph (0.000 -> 0.275), meaning more of the needed facts *were*
retrieved, but this did not translate into an answer RAGAS judged as
relevant to the specific 3-entity question asked. This points to a
generation/synthesis bottleneck for the hardest reasoning-depth category in
this evaluation, not a retrieval bottleneck -- plausibly a capability limit
of the small (`-lite`) generation model used, not necessarily a property of
graph-augmented retrieval in general.

## 6. Did graph retrieval introduce irrelevant context?

Not conclusively either way. Context Precision was directionally higher for
ThreatGraph (+40.5%) but did not reach p<0.05 at n=30 (p=0.068). The
bounded-traversal round-robin fix (built during development specifically to
stop one high-volume relationship type from crowding out rarer, more
relevant facts -- see `evaluation_summary.md`) was not isolated as a
separate ablation, so its specific effect on Context Precision is unmeasured
here and would be a natural follow-up experiment.

## 7. Did additional graph retrieval increase latency?

No measurable systematic increase. Retrieval itself (vector search + bounded
graph traversal) averaged under 0.1s for both systems. Total latency,
dominated by LLM generation (shared by both systems), showed no significant
paired difference (p=0.238 paired-t, p=0.416 Wilcoxon); both systems showed
high variance consistent with occasional provider-side rate-limit backoff.

## 8. Most interesting unexpected findings

- **Answer Relevancy of exactly 0.000 for every single baseline answer.**
  Not a metric bug: System A genuinely, consistently fails to answer these
  multi-hop questions at all ("the provided context does not contain
  information linking..."), which RAGAS correctly scores as unrelated to
  the specific question. This is a strong, concrete illustration of why
  multi-hop CTI questions are a meaningful test case for GraphRAG.
- **The 2-hop/3-hop split in Answer Relevancy** (0.586 vs. 0.000 for
  ThreatGraph) shows graph retrieval and answer synthesis can succeed or
  fail independently -- Context Recall improved for 3-hop questions even
  though Answer Relevancy did not, meaning "did retrieval get better
  evidence" and "did the model produce a good answer from it" need to be
  measured separately, not conflated into one score.
- **Extraction precision was 6x higher than it first appeared**: most
  "false positives" (15 of 23, 65%) were verified-real STIX facts simply
  outside the 60-triple gold sample, not fabrications -- raising adjusted
  precision from 0.115 to 0.692.
- **RAGAS's own infrastructure cost was a bigger practical obstacle than
  any algorithmic question in this project**: evaluating 60 records across
  4 metrics required several hundred real LLM calls (not 240), which blew
  through a daily quota that the main generation/extraction workload never
  came close to hitting, and needed both a concurrency fix and a
  provider switch to get reliable, complete scores.

## 9. Limitations affecting these conclusions

- n=30 questions limits statistical power; non-significant results (e.g.
  Context Precision, Faithfulness, latency) should not be read as
  equivalence between systems.
- A single, small ("lite") generation model was used throughout for
  generation/extraction, chosen for quota reasons rather than capability;
  the 3-hop synthesis bottleneck observed here may not hold for a larger
  generation model.
- The RAGAS judge (gpt-4o-mini) differs from the generation model
  (gemini-3.1-flash-lite); cross-provider judge/generator pairing is common
  practice but is a further source of variance not isolated here.
- Human-rated answer quality is not yet available (blank rubric CSV only).
- The extraction benchmark's recall ceiling is structurally tied to the
  benchmark's diversity-balanced sampling, not purely extraction quality
  (see `evaluation_summary.md` and the paper's Limitations section).

## 10. Suitable for conference-paper development?

Yes, with the caveats above addressed before submission. The core empirical
result -- graph-augmented retrieval significantly improves both whether the
system answers the question (Answer Relevancy) and whether it retrieves
what's needed to answer correctly (Context Recall), concentrated in simpler
reasoning-depth questions -- is a real, statistically supported, non-trivial
finding, not an assumed one; the paper explicitly reports where the effect
did *not* reach significance (Faithfulness, Context Precision, latency,
3-hop Answer Relevancy) rather than only the positive results. Before
submission: expand the Related Work section with properly verified
citations, ideally expand the benchmark beyond n=30 for more statistical
power on the currently-non-significant metrics, and consider an ablation
isolating the round-robin graph-traversal fix's effect on Context
Precision. The honest, documented bug-finding-and-fixing process during
development (reversed relationship direction, hub-node fact starvation,
all-or-nothing extraction validation, RAGAS's call-fan-out quota blind
spot) is itself a credible, citable methodological contribution for a
systems-track venue.

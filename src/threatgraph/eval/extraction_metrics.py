"""Triple-level extraction evaluation: Precision, Recall, F1.

Definitions
-----------
A "triple" is the canonical tuple (subject_attack_id, predicate, object_attack_id).
Canonical ATT&CK identifiers (e.g. "G0016", "T1055") are used for matching,
never raw entity-name strings, so "APT29" vs "Cozy Bear" vs "apt29" are all
treated as the same subject once entity resolution has mapped them to the
same attack_id. The predicate is normalized to the fixed enum vocabulary in
schemas.Predicate (upper-cased exact match; there is no fuzzy predicate
matching).

Given:
  - gold:      the set of canonical (subject_id, predicate, object_id) triples
               from data/gold_triples.json.
  - predicted: the set of canonical triples recovered by the extraction
               pipeline, AFTER entity resolution has mapped extracted
               mentions to attack_ids (an extracted entity that cannot be
               resolved to a canonical attack_id cannot be matched to any
               gold triple and is scored as a false positive).

True Positive  (TP): a triple present in both predicted and gold (exact
                      match on all three canonical fields).
False Positive (FP): a predicted triple with no matching gold triple
                      (includes triples built from unresolved entities,
                      hallucinated relationships, or correct facts not in
                      the 60-triple gold sample).
False Negative (FN): a gold triple with no matching predicted triple
                      (missed extractions).

Precision = TP / (TP + FP) = TP / |predicted|
Recall    = TP / (TP + FN) = TP / |gold|
F1        = 2 * Precision * Recall / (Precision + Recall)

Both sets are de-duplicated before comparison (a predicted triple extracted
twice counts once), which is a documented simplification: this is not a
multiset/count-based metric.

Sample-adjusted precision
--------------------------
gold_triples.json is a 60-triple SAMPLE of MITRE ATT&CK's full relationship
set, not an exhaustive list of every true fact -- a "false positive" under
the strict definition above includes both genuine extraction errors
(hallucinated/incorrect relationships) and triples that are factually
correct, real STIX relationships that simply weren't drawn into the 60-triple
sample. Conflating these understates true precision. `classify_false_positives`
checks each false positive against the full parsed STIX relationship set
(threatgraph.ingestion.stix_loader) to separate the two cases, and
`adjusted_precision` recomputes precision crediting sample-outside-but-real
facts as correct. This adjustment does not apply to recall: gold_triples.json
IS the intended recall target by construction (it answers "of the specific
facts we selected as the benchmark, how many did the pipeline recover"),
so recall is not adjusted.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

Triple = tuple[str, str, str]


@dataclass
class ExtractionMetrics:
    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int
    n_gold: int
    n_predicted: int
    fp_triples: list[Triple]
    fn_triples: list[Triple]

    def to_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "n_gold": self.n_gold,
            "n_predicted": self.n_predicted,
        }


def load_gold_triples(path: Path) -> set[Triple]:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    triples = set()
    for r in records:
        subj_id = r["subject"].get("attack_id")
        obj_id = r["object"].get("attack_id")
        if subj_id and obj_id:
            triples.add((subj_id, r["predicate"], obj_id))
    return triples


def score_extractions(gold: set[Triple], predicted: set[Triple]) -> ExtractionMetrics:
    tp_set = gold & predicted
    fp_set = predicted - gold
    fn_set = gold - predicted

    tp, fp, fn = len(tp_set), len(fp_set), len(fn_set)
    precision = tp / len(predicted) if predicted else 0.0
    recall = tp / len(gold) if gold else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return ExtractionMetrics(
        precision=precision, recall=recall, f1=f1,
        true_positives=tp, false_positives=fp, false_negatives=fn,
        n_gold=len(gold), n_predicted=len(predicted),
        fp_triples=sorted(fp_set), fn_triples=sorted(fn_set),
    )


@dataclass
class FalsePositiveBreakdown:
    n_total: int
    n_genuine_fact_outside_sample: int  # real STIX relationship, just not in the 60-triple sample
    n_hallucinated: int                 # does not exist in STIX at all
    adjusted_precision: float           # credits genuine-outside-sample triples as correct
    genuine_outside_sample_triples: list[Triple]
    hallucinated_triples: list[Triple]

    def to_dict(self) -> dict:
        return {
            "n_total": self.n_total,
            "n_genuine_fact_outside_sample": self.n_genuine_fact_outside_sample,
            "n_hallucinated": self.n_hallucinated,
            "adjusted_precision": round(self.adjusted_precision, 4),
        }


def classify_false_positives(fp_triples: list[Triple], true_positives: int,
                              n_predicted: int) -> FalsePositiveBreakdown:
    """Check each false-positive triple against the FULL parsed STIX
    relationship set (not just the 60-triple sample) to separate genuine
    extraction errors from triples that are correct but simply weren't
    sampled into gold_triples.json."""
    from threatgraph.ingestion.stix_loader import load_parsed_bundle

    pb = load_parsed_bundle()
    attack_id_to_stix_id = {pe.entity.attack_id: stix_id for stix_id, pe in pb.entities.items()}
    full_relationship_set = {(r.source_stix_id, r.predicate, r.target_stix_id) for r in pb.relationships}

    genuine, hallucinated = [], []
    for subj, pred, obj in fp_triples:
        stix_key = (attack_id_to_stix_id.get(subj), pred, attack_id_to_stix_id.get(obj))
        (genuine if stix_key in full_relationship_set else hallucinated).append((subj, pred, obj))

    adjusted_correct = true_positives + len(genuine)
    adjusted_precision = adjusted_correct / n_predicted if n_predicted else 0.0
    return FalsePositiveBreakdown(
        n_total=len(fp_triples), n_genuine_fact_outside_sample=len(genuine),
        n_hallucinated=len(hallucinated), adjusted_precision=adjusted_precision,
        genuine_outside_sample_triples=genuine, hallucinated_triples=hallucinated,
    )


if __name__ == "__main__":
    import argparse

    from threatgraph.config import DATA_DIR

    p = argparse.ArgumentParser(description="Score a predicted-triples JSON file against gold_triples.json.")
    p.add_argument("predicted_json", help="JSON list of [subject_attack_id, predicate, object_attack_id] triples")
    p.add_argument("--gold", default=str(DATA_DIR / "gold_triples.json"))
    args = p.parse_args()

    gold = load_gold_triples(Path(args.gold))
    predicted_raw = json.loads(Path(args.predicted_json).read_text(encoding="utf-8"))
    predicted = {tuple(t) for t in predicted_raw}

    metrics = score_extractions(gold, predicted)
    print(json.dumps(metrics.to_dict(), indent=2))

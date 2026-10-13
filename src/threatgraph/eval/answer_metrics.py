"""Deterministic answer-quality metrics for the RAG benchmark.

Every benchmark question (data/eval_queries.json) has a verified answer
built from MITRE ATT&CK: the ATT&CK IDs the answer must contain (e.g. the
mitigations for a technique). Answers are scored by the ATT&CK IDs they
cite, so no judge LLM is needed and scores are exactly reproducible.

  gold          expected answer IDs, minus the entities named in the question
  cited         ATT&CK IDs appearing in the generated answer
  answered      cited IDs of the asked-for type (same ID prefix as gold),
                excluding the question's own entities

  Answer accuracy   |answered ∩ gold| / |gold|              (recall)
  Answer precision  |answered ∩ gold| / |answered|          (0 if nothing answered)
  Answer F1         harmonic mean of the two
  Fully correct     gold ⊆ cited
  Hallucination     |cited − evidence IDs| / |cited|: IDs the answer cites
                    that appear nowhere in the evidence the system retrieved
                    (chunk text, chunk entities, graph facts)
  Traceable         share of cited IDs that appear in a retrieved graph fact
                    carrying a source relationship id (provenance); 0 for a
                    system without graph evidence
"""
from __future__ import annotations

import re
import statistics

ATTACK_ID_RE = re.compile(r"\b([GTSMC]\d{4}(?:\.\d{3})?)\b")
QUESTION_ENTITY_KEYS = ("threat_group", "technique", "software")

METRICS = [
    ("accuracy", "Answer accuracy", True),
    ("precision", "Answer precision", True),
    ("f1", "Answer F1", True),
    ("fully_correct", "Fully correct", True),
    ("hallucination", "Hallucinated IDs", False),
    ("traceable", "Traceable citations", True),
    ("total_latency_seconds", "Latency (s)", False),
]


def _ids(x) -> set[str]:
    if isinstance(x, dict):
        out = {x["attack_id"]} if x.get("attack_id") else set()
        for v in x.values():
            out |= _ids(v)
        return out
    if isinstance(x, list):
        out = set()
        for v in x:
            out |= _ids(v)
        return out
    return set()


def gold_ids(item: dict) -> set[str]:
    exp = item["expected_answer"]
    given = {exp[k]["attack_id"] for k in QUESTION_ENTITY_KEYS if isinstance(exp.get(k), dict)}
    return _ids(exp) - given


def question_ids(item: dict) -> set[str]:
    exp = item["expected_answer"]
    return {exp[k]["attack_id"] for k in QUESTION_ENTITY_KEYS if isinstance(exp.get(k), dict)}


def evidence_ids(run: dict) -> set[str]:
    text = " ".join(f"{c.get('entity_attack_id') or ''} {c.get('text', '')}" for c in run.get("retrieved_chunks", []))
    ids = set(ATTACK_ID_RE.findall(text))
    for f in run.get("graph_facts", []):
        ids |= {f.get("src_id"), f.get("tgt_id")} - {None}
    return ids


def traceable_ids(run: dict) -> set[str]:
    out = set()
    for f in run.get("graph_facts", []):
        if f.get("stix_relationship_id"):
            out |= {f.get("src_id"), f.get("tgt_id")} - {None}
    return out


def score(run: dict, item: dict) -> dict:
    """Per-answer metrics; every value is None when the answer errored."""
    if run.get("error"):
        return {k: None for k, _, _ in METRICS} | {"cited": [], "gold": sorted(gold_ids(item)),
                                                  "correct": [], "missing": sorted(gold_ids(item)), "unsupported": []}
    gold = gold_ids(item)
    cited = set(ATTACK_ID_RE.findall(run.get("answer", "")))
    prefixes = {g[0] for g in gold}
    answered = {c for c in cited if c[0] in prefixes} - question_ids(item)
    hit = answered & gold
    acc = len(hit) / len(gold) if gold else None
    prec = len(hit) / len(answered) if answered else 0.0
    f1 = 2 * acc * prec / (acc + prec) if acc and prec else 0.0
    unsupported = cited - evidence_ids(run)
    return {
        "accuracy": acc, "precision": prec, "f1": f1,
        "fully_correct": 1.0 if gold and gold <= cited else 0.0,
        "hallucination": len(unsupported) / len(cited) if cited else 0.0,
        "traceable": len(cited & traceable_ids(run)) / len(cited) if cited else 0.0,
        "total_latency_seconds": run.get("total_latency_seconds"),
        "cited": sorted(cited), "gold": sorted(gold), "correct": sorted(hit),
        "missing": sorted(gold - cited), "unsupported": sorted(unsupported),
    }


def summarize(scores: list[dict]) -> dict:
    out = {}
    for key, _, _ in METRICS:
        vals = [s[key] for s in scores if s.get(key) is not None]
        out[key] = {
            "mean": statistics.fmean(vals) if vals else None,
            "std": statistics.stdev(vals) if len(vals) > 1 else None,
            "n": len(vals),
        }
    return out

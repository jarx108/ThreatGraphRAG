"""Run the real LLM extraction pipeline over source text tied to the gold
triples, then score Precision/Recall/F1 against data/gold_triples.json.

Requires ANTHROPIC_API_KEY (or OPENAI_API_KEY with LLM_PROVIDER=openai) to
be set, since this calls the configured LLM for every sampled entity
description. This is the one extraction-evaluation step that cannot run
without a live LLM credential; threatgraph.eval.extraction_metrics itself
is pure and credential-free.

For each gold triple's subject entity, the STIX description text is run
through threatgraph.extraction.extractor.extract(), every extracted
relationship's source/target is resolved to a canonical attack_id via
EntityResolver, and the resulting (subject_id, predicate, object_id) triples
are compared against the full gold set (not just the triples derived from
that one entity, since one description can support multiple gold triples
and the extractor should be scored on everything it emits).
"""
from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

from threatgraph.config import DATA_DIR, RESULTS_DIR
from threatgraph.entity_resolution import EntityResolver
from threatgraph.extraction.extractor import ExtractionError, extract
from threatgraph.eval.extraction_metrics import classify_false_positives, load_gold_triples, score_extractions
from threatgraph.ingestion.stix_loader import load_parsed_bundle
from threatgraph.rag.llm_provider import LLMProvider


def run(sample_size: int = 60, seed: int = 13) -> dict:
    gold = load_gold_triples(DATA_DIR / "gold_triples.json")
    gold_subject_ids = sorted({t[0] for t in gold})

    pb = load_parsed_bundle()
    from threatgraph.embeddings import get_embedder
    resolver = EntityResolver(pb.entities, embedder=get_embedder())  # all four NED steps incl. semantic
    provider = LLMProvider()

    # Sample subject entities that actually appear in the gold set, so the
    # evaluated text has a chance of producing gold-matching triples.
    candidates = [pe for pe in pb.entities.values() if pe.entity.attack_id in gold_subject_ids and pe.description]
    random.Random(seed).shuffle(candidates)
    sample = candidates[:sample_size]

    predicted: set[tuple[str, str, str]] = set()
    raw_records = []
    errors = []
    quota_exhausted = False
    n_attempted = 0
    for pe in sample:
        n_attempted += 1
        try:
            resolved = extract(pe.description, provider=provider, resolver=resolver)
        except ExtractionError as exc:
            errors.append({"entity": pe.entity.attack_id, "error": str(exc)})
            continue
        except Exception as exc:
            # A quota/rate-limit error (e.g. Gemini free-tier daily cap)
            # means every subsequent call will fail the same way -- stop
            # attempting more calls, but keep (and write) whatever real
            # results were already collected rather than losing them to an
            # uncaught exception.
            if any(s in str(exc) for s in ("RESOURCE_EXHAUSTED", "429", "quota")):
                errors.append({"entity": pe.entity.attack_id, "error": f"QUOTA EXHAUSTED: {exc}"})
                quota_exhausted = True
                break
            errors.append({"entity": pe.entity.attack_id, "error": f"API error: {exc}"})
            continue

        triples = []
        for rel in resolved.extraction.relationships:
            src_res = resolved.resolutions.get(rel.source)
            tgt_res = resolved.resolutions.get(rel.target)
            if src_res and src_res.matched and tgt_res and tgt_res.matched:
                predicted.add((src_res.attack_id, rel.predicate.value, tgt_res.attack_id))
                triples.append({
                    "subject": src_res.attack_id, "predicate": rel.predicate.value, "object": tgt_res.attack_id,
                    "subject_mention": rel.source, "object_mention": rel.target,
                    "subject_ned": src_res.method, "object_ned": tgt_res.method,
                    "evidence_text": rel.evidence_text, "confidence": rel.confidence_score,
                })

        raw_records.append({
            "source_entity": pe.entity.attack_id,
            "n_entities_extracted": len(resolved.extraction.entities),
            "n_relationships_extracted": len(resolved.extraction.relationships),
            "n_rejected": len(resolved.rejected),
            "triples": triples,
            "mentions": [
                {"mention": e.name, "type": e.entity_type.value,
                 "attack_id": resolved.resolutions[e.name].attack_id if e.name in resolved.resolutions else None,
                 "method": resolved.resolutions[e.name].method if e.name in resolved.resolutions else None}
                for e in resolved.extraction.entities
            ],
            "rejected": resolved.rejected,
            "input_tokens": resolved.llm_response.input_tokens,
            "output_tokens": resolved.llm_response.output_tokens,
            "latency_seconds": round(resolved.llm_response.latency_seconds, 3),
            "estimated_cost_usd": resolved.llm_response.estimated_cost_usd,
        })

    metrics = score_extractions(gold, predicted)
    fp_breakdown = classify_false_positives(metrics.fp_triples, metrics.true_positives, metrics.n_predicted)
    summary = {
        "sample_size_requested": len(sample),
        "sample_size_attempted": n_attempted,
        "sample_size_succeeded": len(raw_records),
        "quota_exhausted_before_completion": quota_exhausted,
        "errors": errors,
        "metrics": metrics.to_dict(),
        "false_positive_breakdown": fp_breakdown.to_dict(),
        "false_positive_triples": metrics.fp_triples,
        "false_negative_triples": metrics.fn_triples,
        "model": provider.model,
    }
    if quota_exhausted:
        summary["note"] = (
            f"Stopped after {n_attempted}/{len(sample)} samples due to a provider quota/rate "
            "limit, not a code error. Metrics above reflect only the samples that actually "
            "succeeded -- re-run with a higher quota or after the quota resets to get the full "
            f"{len(sample)}-sample result."
        )

    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "extraction_metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (RESULTS_DIR / "extraction_raw_records.json").write_text(json.dumps(raw_records, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--sample-size", type=int, default=60)
    args = p.parse_args()
    out = run(sample_size=args.sample_size)
    print(json.dumps(out["metrics"], indent=2))

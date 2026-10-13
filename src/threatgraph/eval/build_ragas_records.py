"""Convert results/raw_experiment_results.json into the flat record format
RAGAS expects: one row per (question, system) pair with question/answer/
contexts/reference, plus question_id/system/category/required_hops carried
through so threatgraph.eval.stats_analysis can join RAGAS scores back onto
the rest of the per-question data.

`reference` (used by the reference-based metrics Context Precision and
Context Recall) is a natural-language rendering of eval_queries.json's
`expected_answer`, built here -- never shown to either RAG system before it
answers (see the benchmark-leakage note in run_experiments.py).
"""
from __future__ import annotations

import json
from pathlib import Path

from threatgraph.config import RESULTS_DIR


def render_reference(category: str, expected: dict) -> str:
    if category == "group_technique_mitigation":
        mits = ", ".join(f"{m['name']} ({m['attack_id']})" for m in expected["mitigations"])
        return (f"{expected['threat_group']['name']} uses {expected['technique']['name']} "
                f"({expected['technique']['attack_id']}). Mitigations: {mits}.")
    if category == "group_software_technique":
        techs = ", ".join(f"{t['name']} ({t['attack_id']})" for t in expected["techniques"])
        return (f"{expected['software']['name']} ({expected['software']['attack_id']}), used by "
                f"{expected['threat_group']['name']}, implements: {techs}.")
    if category == "group_software_technique_mitigation":
        parts = []
        for tm in expected["techniques_and_mitigations"]:
            mits = ", ".join(f"{m['name']} ({m['attack_id']})" for m in tm["mitigations"])
            parts.append(f"{tm['technique']['name']} ({tm['technique']['attack_id']}): {mits}")
        return (f"{expected['software']['name']}, used by {expected['threat_group']['name']}, "
                f"implements these techniques and their mitigations: " + "; ".join(parts))
    return json.dumps(expected)


def build_contexts(sys_rec: dict) -> list[str]:
    """RAGAS `retrieved_contexts` for one system's result: every retrieved
    chunk plus every graph fact, rendered as text exactly as the evaluation
    sees them."""
    contexts = [
        f"[{c['entity_attack_id'] or '?'}] {c['entity_name'] or ''}: {c['text']}"
        for c in sys_rec["retrieved_chunks"]
    ]
    for f in sys_rec.get("graph_facts", []):
        contexts.append(
            f"({f['src_id']} {f['src_name']}:{f['src_type']}) -{f['predicate']}-> "
            f"({f['tgt_id']} {f['tgt_name']}:{f['tgt_type']})"
        )
    return contexts


def build_records(raw_results: list[dict]) -> list[dict]:
    records = []
    for r in raw_results:
        reference = render_reference(r.get("category", ""), r["reference_answer"])
        for system_key, answer_key in (("baseline", "baseline_answer"), ("threatgraph", "threatgraph_answer")):
            sys_rec = r[system_key]
            if sys_rec.get("error"):
                continue  # a failed call has no answer to judge
            contexts = build_contexts(sys_rec)
            if not contexts:
                continue  # RAGAS metrics are undefined with no retrieved context
            records.append({
                "question_id": r["question_id"],
                "category": r.get("category"),
                "required_hops": r["required_hops"],
                "system": system_key,
                "user_input": r["question"],
                "response": r[answer_key],
                "retrieved_contexts": contexts,
                "reference": reference,
            })
    return records


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--raw", default=str(RESULTS_DIR / "raw_experiment_results.json"))
    p.add_argument("--out", default=str(RESULTS_DIR / "ragas_input_records.json"))
    args = p.parse_args()

    raw = json.loads(Path(args.raw).read_text(encoding="utf-8"))
    records = build_records(raw)
    Path(args.out).write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(f"Wrote {len(records)} RAGAS input records to {args.out}")

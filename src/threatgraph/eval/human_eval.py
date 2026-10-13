"""Generate a human-evaluation rubric CSV from experiment results.

Produces one row per (question, system) pair with blank score columns for a
human rater to fill in by hand. No scores are invented here -- every
Factuality / Completeness / Coherence cell is left empty until a human
actually rates it. Run after threatgraph.eval.run_experiments.

Rubric (1-5 scale, each dimension rated independently):
  Factuality:   Are the claims in the answer accurate per MITRE ATT&CK, with
                no fabricated techniques/groups/mitigations/relationships?
                1 = mostly fabricated/incorrect, 5 = fully accurate.
  Completeness: Does the answer cover everything the reference answer does
                (e.g. all expected mitigations, not just one)?
                1 = missing most required facts, 5 = fully complete.
  Coherence:    Is the answer well-organized and readable as a standalone
                response, independent of correctness?
                1 = incoherent/garbled, 5 = clear and well-structured.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path


def build_human_eval_csv(raw_results_path: Path, output_csv_path: Path) -> int:
    records = json.loads(Path(raw_results_path).read_text(encoding="utf-8"))
    fieldnames = [
        "question_id", "system", "question", "reference_answer", "generated_answer",
        "required_hops", "graph_path",
        "factuality_1_5", "completeness_1_5", "coherence_1_5", "rater_notes",
    ]
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        n = 0
        for rec in records:
            for system_key, answer_key in (("baseline", "baseline_answer"), ("threatgraph", "threatgraph_answer")):
                writer.writerow({
                    "question_id": rec["question_id"],
                    "system": system_key,
                    "question": rec["question"],
                    "reference_answer": json.dumps(rec["reference_answer"], ensure_ascii=False),
                    "generated_answer": rec.get(answer_key, ""),
                    "required_hops": rec.get("required_hops"),
                    "graph_path": rec.get("graph_path"),
                    "factuality_1_5": "",
                    "completeness_1_5": "",
                    "coherence_1_5": "",
                    "rater_notes": "",
                })
                n += 1
    return n


if __name__ == "__main__":
    import argparse

    from threatgraph.config import RESULTS_DIR

    p = argparse.ArgumentParser()
    p.add_argument("--raw", default=str(RESULTS_DIR / "raw_experiment_results.json"))
    p.add_argument("--out", default=str(RESULTS_DIR / "human_eval_rubric.csv"))
    args = p.parse_args()
    n = build_human_eval_csv(Path(args.raw), Path(args.out))
    print(f"Wrote {n} rows to {args.out}")

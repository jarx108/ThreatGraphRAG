"""Named Entity Disambiguation (NED) evaluation, no LLM involved.

Test set, built from MITRE ATT&CK itself: every entity's canonical name,
each of its aliases (e.g. "Cozy Bear" -> APT29 / G0016), the alias in lower
case, and its ATT&CK ID, each embedded in a question template. Aliases
shared by more than one entity are reported separately as ambiguous.

Two linkers are compared on the same mentions:
  * exact-name baseline: links a mention only if it equals a canonical node
    name exactly (what a plain `MATCH (n {name: $mention})` lookup does);
  * ThreatGraph NED (EntityResolver.find_mentions): ID, alias and
    normalized-name matching with deterministic tie-breaking.

    python -m threatgraph.eval.ned_eval
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from threatgraph.config import RESULTS_DIR
from threatgraph.entity_resolution import EntityResolver, normalize
from threatgraph.ingestion.stix_loader import load_parsed_bundle

OUT_PATH = RESULTS_DIR / "ned_evaluation.json"
TEMPLATE = "Which techniques are associated with {} in recent intrusions?"
VARIANTS = ["canonical name", "alias", "alias (lower case)", "ATT&CK ID"]


def build_cases(entities) -> tuple[list[dict], int]:
    owners: dict[str, set[str]] = defaultdict(set)
    for pe in entities.values():
        e = pe.entity
        if e.attack_id:
            for surface in [e.name, *e.aliases]:
                owners[normalize(surface)].add(e.attack_id)
    cases, ambiguous = [], 0
    for pe in sorted(entities.values(), key=lambda p: p.entity.attack_id or ""):
        e = pe.entity
        if not e.attack_id:
            continue
        cases.append({"variant": "canonical name", "mention": e.name, "expected": e.attack_id,
                      "type": e.entity_type.value})
        cases.append({"variant": "ATT&CK ID", "mention": e.attack_id, "expected": e.attack_id,
                      "type": e.entity_type.value})
        for alias in sorted(set(e.aliases)):
            if normalize(alias) == normalize(e.name):
                continue
            if len(owners[normalize(alias)]) > 1:
                ambiguous += 1
                continue
            cases.append({"variant": "alias", "mention": alias, "expected": e.attack_id, "type": e.entity_type.value})
            cases.append({"variant": "alias (lower case)", "mention": alias.lower(), "expected": e.attack_id,
                          "type": e.entity_type.value})
    return cases, ambiguous


def run() -> dict:
    pb = load_parsed_bundle()
    resolver = EntityResolver(pb.entities)
    by_name = {pe.entity.name: pe.entity.attack_id for pe in pb.entities.values() if pe.entity.attack_id}
    cases, ambiguous = build_cases(pb.entities)

    tallies = {sys: defaultdict(Counter) for sys in ("baseline", "ned")}
    failures = []
    for c in cases:
        text = TEMPLATE.format(c["mention"])
        start = text.index(c["mention"])
        base = by_name.get(c["mention"])
        hits = [m for m in resolver.find_mentions(text) if m.start == start and m.text == c["mention"]]
        ned = hits[0].attack_id if hits else None
        for sys, pred in (("baseline", base), ("ned", ned)):
            t = tallies[sys][c["variant"]]
            t["n"] += 1
            t["correct"] += pred == c["expected"]
            t["wrong"] += pred is not None and pred != c["expected"]
            t["unlinked"] += pred is None
        if ned != c["expected"] and len(failures) < 25:
            failures.append({**c, "predicted": ned})

    def pack(t: dict[str, Counter]) -> dict:
        per = {v: {"n": t[v]["n"], "accuracy": t[v]["correct"] / t[v]["n"] if t[v]["n"] else None,
                   "wrong_link": t[v]["wrong"], "unlinked": t[v]["unlinked"]} for v in VARIANTS}
        n = sum(t[v]["n"] for v in VARIANTS)
        per["overall"] = {"n": n, "accuracy": sum(t[v]["correct"] for v in VARIANTS) / n,
                          "wrong_link": sum(t[v]["wrong"] for v in VARIANTS),
                          "unlinked": sum(t[v]["unlinked"] for v in VARIANTS)}
        return per

    summary = {
        "n_cases": len(cases), "n_entities": len({c["expected"] for c in cases}),
        "ambiguous_aliases_excluded": ambiguous, "template": TEMPLATE,
        "baseline_exact_name": pack(tallies["baseline"]), "threatgraph_ned": pack(tallies["ned"]),
        "failures_sample": failures,
    }
    RESULTS_DIR.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def load() -> dict | None:
    return json.loads(OUT_PATH.read_text(encoding="utf-8")) if OUT_PATH.exists() else None


if __name__ == "__main__":
    s = run()
    for sys in ("baseline_exact_name", "threatgraph_ned"):
        print(sys, {v: round(x["accuracy"], 4) for v, x in s[sys].items() if x["accuracy"] is not None})
    print("cases:", s["n_cases"], "ambiguous excluded:", s["ambiguous_aliases_excluded"])

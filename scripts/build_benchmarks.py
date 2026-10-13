"""Build gold_triples.json and eval_queries.json from official Enterprise ATT&CK STIX.

Pinned dataset: Enterprise ATT&CK v19.2.
This script deliberately derives benchmark facts instead of hand-writing them.
It is deterministic: the input bundle is hash-verified (see
threatgraph.ingestion.stix_loader) and every selection step is sorted, so
re-running it reproduces the committed data/*.json byte for byte.
"""
import json
from collections import defaultdict
from pathlib import Path

from threatgraph.ingestion.stix_loader import fetch_bundle

OUT = Path(__file__).resolve().parents[1] / "data"

TYPE_MAP = {
    "intrusion-set": "ThreatGroup",
    "attack-pattern": "Technique",
    "malware": "Software",
    "tool": "Software",
    "course-of-action": "Mitigation",
    "campaign": "Campaign",
}

def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None

def active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)

def main():
    OUT.mkdir(exist_ok=True)
    print("Loading Enterprise ATT&CK v19.2 (cached, hash-verified)...")
    bundle = fetch_bundle()

    objects = {o["id"]: o for o in bundle["objects"] if active(o)}
    relationships = [
        o for o in bundle["objects"]
        if o.get("type") == "relationship" and active(o)
    ]

    triples = []
    seen = set()
    for r in relationships:
        src, tgt = objects.get(r.get("source_ref")), objects.get(r.get("target_ref"))
        if not src or not tgt:
            continue
        st, tt = TYPE_MAP.get(src.get("type")), TYPE_MAP.get(tgt.get("type"))
        pred = None
        if r.get("relationship_type") == "uses" and st in {"ThreatGroup","Software"} and tt in {"Technique","Software"}:
            pred = "USES"
        elif r.get("relationship_type") == "mitigates" and st == "Mitigation" and tt == "Technique":
            pred = "MITIGATES"
        if not pred:
            continue
        key = (src["id"], pred, tgt["id"])
        if key in seen:
            continue
        seen.add(key)
        triples.append({
            "subject": {"name": src.get("name"), "attack_id": attack_id(src), "type": st},
            "predicate": pred,
            "object": {"name": tgt.get("name"), "attack_id": attack_id(tgt), "type": tt},
            "stix_relationship_id": r["id"],
            "source": "MITRE ATT&CK Enterprise v19.2"
        })

    # Select a varied set of 60 gold triples, balanced across relation
    # shapes (subject_type, predicate, object_type) AND across distinct
    # subject entities within each shape. A naive "sort then take the first
    # 20 per shape" sort groups triples by subject first, so one prolific
    # subject (e.g. a Mitigation with 20+ MITIGATES edges) alone fills an
    # entire shape's quota -- leaving extraction-pipeline evaluation (which
    # samples by subject entity) almost no distinct subjects to test
    # against. Round-robining across subjects within each shape avoids that.
    triples.sort(key=lambda x: (
        x["subject"]["type"], x["subject"]["attack_id"] or "",
        x["predicate"], x["object"]["attack_id"] or ""
    ))
    by_shape: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for t in triples:
        shape = (t["subject"]["type"], t["predicate"], t["object"]["type"])
        by_shape[shape][t["subject"]["attack_id"]].append(t)

    selected = []
    for shape, by_subject in by_shape.items():
        subject_queues = list(by_subject.values())  # already attack_id-ordered from the sort above
        taken_for_shape = 0
        while taken_for_shape < 20 and any(subject_queues) and len(selected) < 60:
            for queue in subject_queues:
                if queue:
                    selected.append(queue.pop(0))
                    taken_for_shape += 1
                    if taken_for_shape >= 20 or len(selected) >= 60:
                        break
        if len(selected) >= 60:
            break

    if len(selected) < 60:
        keys = {(x["subject"]["attack_id"], x["predicate"], x["object"]["attack_id"]) for x in selected}
        for t in triples:
            k = (t["subject"]["attack_id"], t["predicate"], t["object"]["attack_id"])
            if k not in keys:
                selected.append(t); keys.add(k)
            if len(selected) >= 60: break

    (OUT/"gold_triples.json").write_text(
        json.dumps(selected, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Build genuine multi-hop QA records from three graph-path shapes:
    #   A) ThreatGroup --USES--> Technique <--MITIGATES-- Mitigation        (2-hop)
    #   B) ThreatGroup --USES--> Software --USES--> Technique              (2-hop, software relationship)
    #   C) ThreatGroup --USES--> Software --USES--> Technique <--MITIGATES-- Mitigation (3-hop)
    group_uses_tech = defaultdict(list)
    group_uses_software = defaultdict(list)
    software_uses_tech = defaultdict(list)
    mitigates = defaultdict(list)
    for t in triples:
        if t["subject"]["type"] == "ThreatGroup" and t["predicate"] == "USES" and t["object"]["type"] == "Technique":
            group_uses_tech[t["subject"]["attack_id"]].append(t)
        if t["subject"]["type"] == "ThreatGroup" and t["predicate"] == "USES" and t["object"]["type"] == "Software":
            group_uses_software[t["subject"]["attack_id"]].append(t)
        if t["subject"]["type"] == "Software" and t["predicate"] == "USES" and t["object"]["type"] == "Technique":
            software_uses_tech[t["subject"]["attack_id"]].append(t)
        if t["subject"]["type"] == "Mitigation" and t["predicate"] == "MITIGATES" and t["object"]["type"] == "Technique":
            mitigates[t["object"]["attack_id"]].append(t)

    qas = []

    def next_id():
        return f"Q{len(qas) + 1:02d}"

    # Category A: 2-hop, threat-group-to-technique-to-mitigation.
    for gid in sorted(group_uses_tech):
        for u in sorted(group_uses_tech[gid], key=lambda x: x["object"]["attack_id"] or ""):
            mids = mitigates.get(u["object"]["attack_id"], [])
            if not mids:
                continue
            group, tech = u["subject"], u["object"]
            answers = sorted(
                [{"name": m["subject"]["name"], "attack_id": m["subject"]["attack_id"]} for m in mids],
                key=lambda x: x["attack_id"] or ""
            )
            qas.append({
                "id": next_id(),
                "category": "group_technique_mitigation",
                "question": f"Which mitigations address the ATT&CK technique {tech['name']} ({tech['attack_id']}) used by {group['name']} ({group['attack_id']})?",
                "expected_answer": {
                    "threat_group": {"name": group["name"], "attack_id": group["attack_id"]},
                    "technique": {"name": tech["name"], "attack_id": tech["attack_id"]},
                    "mitigations": answers
                },
                "required_hops": 2,
                "graph_path": "ThreatGroup -USES-> Technique <-MITIGATES- Mitigation",
                "source": "MITRE ATT&CK Enterprise v19.2"
            })
            if sum(1 for q in qas if q["category"] == "group_technique_mitigation") >= 14:
                break
        if sum(1 for q in qas if q["category"] == "group_technique_mitigation") >= 14:
            break

    # Category B: 2-hop, software relationship (no mitigation hop).
    b_count = 0
    for gid in sorted(group_uses_software):
        for gs in sorted(group_uses_software[gid], key=lambda x: x["object"]["attack_id"] or ""):
            group, software = gs["subject"], gs["object"]
            techs = software_uses_tech.get(software["attack_id"], [])
            if not techs:
                continue
            answers = sorted(
                [{"name": s["object"]["name"], "attack_id": s["object"]["attack_id"]} for s in techs],
                key=lambda x: x["attack_id"] or ""
            )
            qas.append({
                "id": next_id(),
                "category": "group_software_technique",
                "question": f"Which ATT&CK techniques does {software['name']} ({software['attack_id']}), software used by {group['name']} ({group['attack_id']}), implement?",
                "expected_answer": {
                    "threat_group": {"name": group["name"], "attack_id": group["attack_id"]},
                    "software": {"name": software["name"], "attack_id": software["attack_id"]},
                    "techniques": answers
                },
                "required_hops": 2,
                "graph_path": "ThreatGroup -USES-> Software -USES-> Technique",
                "source": "MITRE ATT&CK Enterprise v19.2"
            })
            b_count += 1
            if b_count >= 8:
                break
        if b_count >= 8:
            break

    # Category C: 3-hop, group -> software -> technique <- mitigation.
    c_count = 0
    for gid in sorted(group_uses_software):
        for gs in sorted(group_uses_software[gid], key=lambda x: x["object"]["attack_id"] or ""):
            group, software = gs["subject"], gs["object"]
            techs = software_uses_tech.get(software["attack_id"], [])
            tech_mitigations = []
            for s in sorted(techs, key=lambda x: x["object"]["attack_id"] or ""):
                tech = s["object"]
                mids = mitigates.get(tech["attack_id"], [])
                if not mids:
                    continue
                tech_mitigations.append({
                    "technique": {"name": tech["name"], "attack_id": tech["attack_id"]},
                    "mitigations": sorted(
                        [{"name": m["subject"]["name"], "attack_id": m["subject"]["attack_id"]} for m in mids],
                        key=lambda x: x["attack_id"] or ""
                    ),
                })
            if not tech_mitigations:
                continue
            qas.append({
                "id": next_id(),
                "category": "group_software_technique_mitigation",
                "question": (
                    f"For {software['name']} ({software['attack_id']}), software used by "
                    f"{group['name']} ({group['attack_id']}), which mitigations address each "
                    f"ATT&CK technique it implements?"
                ),
                "expected_answer": {
                    "threat_group": {"name": group["name"], "attack_id": group["attack_id"]},
                    "software": {"name": software["name"], "attack_id": software["attack_id"]},
                    "techniques_and_mitigations": tech_mitigations
                },
                "required_hops": 3,
                "graph_path": "ThreatGroup -USES-> Software -USES-> Technique <-MITIGATES- Mitigation",
                "source": "MITRE ATT&CK Enterprise v19.2"
            })
            c_count += 1
            if c_count >= 8:
                break
        if c_count >= 8:
            break

    if len(qas) < 20:
        raise RuntimeError(f"Only {len(qas)} multi-hop QA records could be generated.")
    (OUT/"eval_queries.json").write_text(
        json.dumps(qas, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Wrote {len(selected)} gold triples and {len(qas)} multi-hop QA records.")

if __name__ == "__main__":
    main()

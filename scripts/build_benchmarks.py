"""Build gold_triples.json and eval_queries.json from official Enterprise ATT&CK STIX.

Pinned dataset: Enterprise ATT&CK v19.2.
This script deliberately derives benchmark facts instead of hand-writing them.
"""
import json
import urllib.request
from collections import defaultdict
from pathlib import Path

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
       "master/enterprise-attack/enterprise-attack-19.2.json")
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
    print("Downloading Enterprise ATT&CK v19.2...")
    with urllib.request.urlopen(URL) as response:
        bundle = json.load(response)

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

    # Stable sort, then select a varied set of 60 gold triples.
    triples.sort(key=lambda x: (
        x["subject"]["type"], x["subject"]["attack_id"] or "",
        x["predicate"], x["object"]["attack_id"] or ""
    ))
    selected = []
    per_kind = defaultdict(int)
    # Balance common relation shapes before filling remainder.
    for t in triples:
        shape = (t["subject"]["type"], t["predicate"], t["object"]["type"])
        if per_kind[shape] < 20:
            selected.append(t); per_kind[shape] += 1
        if len(selected) >= 60:
            break
    if len(selected) < 60:
        keys = {(x["subject"]["attack_id"],x["predicate"],x["object"]["attack_id"]) for x in selected}
        for t in triples:
            k=(t["subject"]["attack_id"],t["predicate"],t["object"]["attack_id"])
            if k not in keys:
                selected.append(t); keys.add(k)
            if len(selected) >= 60: break

    (OUT/"gold_triples.json").write_text(
        json.dumps(selected, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Build genuine multi-hop QA records from graph paths:
    # ThreatGroup --USES--> Technique <--MITIGATES-- Mitigation
    uses = defaultdict(list)
    mitigates = defaultdict(list)
    for t in triples:
        if t["subject"]["type"] == "ThreatGroup" and t["predicate"] == "USES" and t["object"]["type"] == "Technique":
            uses[t["subject"]["attack_id"]].append(t)
        if t["subject"]["type"] == "Mitigation" and t["predicate"] == "MITIGATES" and t["object"]["type"] == "Technique":
            mitigates[t["object"]["attack_id"]].append(t)

    qas = []
    for gid in sorted(uses):
        for u in sorted(uses[gid], key=lambda x: x["object"]["attack_id"] or ""):
            mids = mitigates.get(u["object"]["attack_id"], [])
            if not mids:
                continue
            group = u["subject"]
            tech = u["object"]
            answers = sorted(
                [{"name": m["subject"]["name"], "attack_id": m["subject"]["attack_id"]} for m in mids],
                key=lambda x: x["attack_id"] or ""
            )
            qas.append({
                "id": f"Q{len(qas)+1:02d}",
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
            if len(qas) >= 24:
                break
        if len(qas) >= 24:
            break

    if len(qas) < 20:
        raise RuntimeError(f"Only {len(qas)} multi-hop QA records could be generated.")
    (OUT/"eval_queries.json").write_text(
        json.dumps(qas, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Wrote {len(selected)} gold triples and {len(qas)} multi-hop QA records.")

if __name__ == "__main__":
    main()

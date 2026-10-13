Run `python scripts/build_benchmarks.py` from the repository root to
(re)create `gold_triples.json` and `eval_queries.json` from the official
MITRE Enterprise ATT&CK v19.2 STIX bundle. Nothing in either file is
hand-invented; every record traces back to a STIX relationship ID.

- `gold_triples.json`: 60 `(subject, predicate, object)` triples for
  extraction evaluation (Precision/Recall/F1), each carrying its
  `stix_relationship_id` and canonical ATT&CK IDs.
- `eval_queries.json`: 30 multi-hop QA records across three reasoning-path
  categories (`category` field):
  - `group_technique_mitigation` (2-hop, 14 records): `ThreatGroup -USES->
    Technique <-MITIGATES- Mitigation`.
  - `group_software_technique` (2-hop, 8 records): `ThreatGroup -USES->
    Software -USES-> Technique`.
  - `group_software_technique_mitigation` (3-hop, 8 records): `ThreatGroup
    -USES-> Software -USES-> Technique <-MITIGATES- Mitigation`.

`cache/` holds the downloaded raw STIX bundle (gitignored) so repeated runs
of the ingestion/population pipeline don't re-download it.

The same `eval_queries.json` is used, unmodified, for both the text-only RAG
baseline and the ThreatGraph system; `expected_answer` is withheld from both
systems at answer time and attached to result records only for scoring (see
`src/threatgraph/eval/run_experiments.py`).

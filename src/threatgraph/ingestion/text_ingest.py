"""Ingest LLM-extracted facts from unstructured text into Neo4j.

Second data source next to the structured STIX bundle (graph.populate):
free-text CTI descriptions are run through the extraction pipeline
(extraction.extractor: prompt -> Ollama with the Pydantic JSON Schema ->
Pydantic validation -> NED against canonical nodes) by
eval.run_extraction_eval, which records every resolved triple in
results/extraction_raw_records.json. This module writes those triples as
edges with their own provenance:

    source            'llm_extraction'
    model             the extraction LLM
    confidence        the LLM's confidence for the relationship
    evidence_text     the sentence the LLM cited
    source_entity     whose description the text came from (the document)
    subject_ned / object_ned   how each mention was linked (alias, ...)
    verified          true when MITRE asserts the same triple (a STIX edge)

They never overwrite STIX edges (different MERGE key), and GraphRAG does
not use them as answer evidence (traversal.TRUSTED_SOURCES); they show how
unstructured text extends and is cross-checked against the curated graph.

    python -m threatgraph.ingestion.text_ingest
"""
from __future__ import annotations

import json
from collections import Counter

from threatgraph.config import RESULTS_DIR
from threatgraph.graph.neo4j_client import Neo4jClient

RAW_PATH = RESULTS_DIR / "extraction_raw_records.json"
METRICS_PATH = RESULTS_DIR / "extraction_metrics.json"
OUT_PATH = RESULTS_DIR / "text_ingestion.json"

_LABEL = {"G": "ThreatGroup", "T": "Technique", "S": "Software", "M": "Mitigation", "C": "Campaign"}

REMOVE_QUERY = "MATCH ()-[r]->() WHERE r.source = 'llm_extraction' DELETE r"


def _write_query(predicate: str, src_label: str, tgt_label: str) -> str:
    return f"""
    UNWIND $rows AS row
    MATCH (s:{src_label} {{attack_id: row.subject}})
    MATCH (t:{tgt_label} {{attack_id: row.object}})
    MERGE (s)-[r:{predicate} {{source: 'llm_extraction', source_entity: row.source_entity}}]->(t)
    SET r.model = $model, r.confidence = row.confidence, r.evidence_text = row.evidence_text,
        r.subject_ned = row.subject_ned, r.object_ned = row.object_ned,
        r.verified = EXISTS {{ MATCH (s)-[v:{predicate}]->(t) WHERE v.source = 'mitre_attack_stix' }}
    """


def run(client: Neo4jClient | None = None) -> dict:
    if not RAW_PATH.exists():
        raise RuntimeError("No extraction results yet. Run `python -m threatgraph.eval.run_extraction_eval` first.")
    records = json.loads(RAW_PATH.read_text(encoding="utf-8"))
    model = json.loads(METRICS_PATH.read_text(encoding="utf-8")).get("model") if METRICS_PATH.exists() else None

    rows_by_shape: dict[tuple, list[dict]] = {}
    for rec in records:
        for t in rec.get("triples", []):
            src, tgt = _LABEL.get(t["subject"][0]), _LABEL.get(t["object"][0])
            if not src or not tgt:
                continue
            rows_by_shape.setdefault((t["predicate"], src, tgt), []).append(
                {**t, "source_entity": rec["source_entity"]})

    owns = client is None
    client = client or Neo4jClient()
    try:
        client.run(REMOVE_QUERY)  # idempotent: rebuild this source from the saved extraction run
        for (pred, src, tgt), rows in sorted(rows_by_shape.items()):
            client.run_write_batch(_write_query(pred, src, tgt), rows, params={"model": model})
        stats = client.run("""
            MATCH (s)-[r]->(t) WHERE r.source = 'llm_extraction'
            RETURN count(r) AS edges, sum(CASE WHEN r.verified THEN 1 ELSE 0 END) AS verified,
                   avg(r.confidence) AS mean_confidence, count(DISTINCT r.source_entity) AS documents
        """)[0]
        by_type = client.run("""
            MATCH ()-[r]->() WHERE r.source = 'llm_extraction'
            RETURN type(r) AS predicate, count(*) AS n ORDER BY predicate
        """)
    finally:
        if owns:
            client.close()

    ned = Counter()
    for rec in records:
        for t in rec.get("triples", []):
            ned[t.get("subject_ned")] += 1
            ned[t.get("object_ned")] += 1
    summary = {
        "documents_processed": len(records),
        "triples_resolved": sum(len(r.get("triples", [])) for r in records),
        "edges_written": stats["edges"],
        "edges_verified_by_stix": stats["verified"],
        "verified_share": round(stats["verified"] / stats["edges"], 4) if stats["edges"] else None,
        "mean_confidence": round(stats["mean_confidence"], 4) if stats["mean_confidence"] is not None else None,
        "by_predicate": {r["predicate"]: r["n"] for r in by_type},
        "ned_methods": dict(sorted((k or "unresolved", v) for k, v in ned.items())),
        "model": model,
    }
    OUT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def load() -> dict | None:
    return json.loads(OUT_PATH.read_text(encoding="utf-8")) if OUT_PATH.exists() else None


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))

"""Populate Neo4j from the parsed MITRE ATT&CK STIX bundle: entity nodes,
typed relationships, a Document provenance node, Chunk nodes with
embeddings, and MENTIONED_IN edges from every entity to its source document.

All writes are parameterized (UNWIND $rows ...), batched, and idempotent via
MERGE on the uniqueness-constrained key (attack_id / chunk_id / document_id).
Re-running this script against an unchanged STIX version is a safe no-op
beyond re-setting properties.
"""
from __future__ import annotations

import time

from threatgraph.config import ATTACK_STIX_VERSION
from threatgraph.embeddings import get_embedder
from threatgraph.graph.neo4j_client import Neo4jClient
from threatgraph.graph.schema_init import init_schema
from threatgraph.ingestion.chunking import chunk_all
from threatgraph.ingestion.stix_loader import ParsedBundle, load_parsed_bundle

ENTITY_LABELS = {
    "ThreatGroup": "ThreatGroup",
    "Technique": "Technique",
    "Software": "Software",
    "Campaign": "Campaign",
    "Mitigation": "Mitigation",
}


def _load_entities(client: Neo4jClient, pb: ParsedBundle) -> None:
    by_label: dict[str, list[dict]] = {label: [] for label in ENTITY_LABELS.values()}
    for pe in pb.entities.values():
        e = pe.entity
        label = ENTITY_LABELS.get(e.entity_type.value)
        if not label:
            continue
        by_label[label].append({
            "attack_id": e.attack_id,
            "name": e.name,
            "aliases": e.aliases,
            "description": pe.description,
            "source_url": pe.provenance.source_url,
        })

    for label, rows in by_label.items():
        if not rows:
            continue
        client.run_write_batch(
            f"""
            UNWIND $rows AS row
            MERGE (n:{label} {{attack_id: row.attack_id}})
            SET n.name = row.name,
                n.aliases = row.aliases,
                n.description = row.description,
                n.source_url = row.source_url
            """,
            rows,
        )


def _load_document(client: Neo4jClient, pb: ParsedBundle) -> None:
    client.run(
        "MERGE (d:Document {document_id: $doc_id}) "
        "SET d.source_type = 'mitre_attack_stix', d.source_url = $url",
        {"doc_id": pb.document_id,
         "url": "https://github.com/mitre-attack/attack-stix-data"},
    )
    rows = [{"attack_id": pe.entity.attack_id, "label": ENTITY_LABELS[pe.entity.entity_type.value],
             "doc_id": pb.document_id}
            for pe in pb.entities.values() if pe.entity.entity_type.value in ENTITY_LABELS]
    for label in ENTITY_LABELS.values():
        label_rows = [r for r in rows if r["label"] == label]
        if not label_rows:
            continue
        client.run_write_batch(
            f"""
            UNWIND $rows AS row
            MATCH (n:{label} {{attack_id: row.attack_id}})
            MATCH (d:Document {{document_id: row.doc_id}})
            MERGE (n)-[:MENTIONED_IN]->(d)
            """,
            label_rows,
        )


def _load_relationships(client: Neo4jClient, pb: ParsedBundle) -> None:
    label_of = {stix_id: ENTITY_LABELS.get(pe.entity.entity_type.value)
                for stix_id, pe in pb.entities.items()}
    attack_id_of = {stix_id: pe.entity.attack_id for stix_id, pe in pb.entities.items()}

    by_shape: dict[tuple[str, str, str], list[dict]] = {}
    for rel in pb.relationships:
        src_label = label_of.get(rel.source_stix_id)
        tgt_label = label_of.get(rel.target_stix_id)
        if not src_label or not tgt_label:
            continue
        shape = (src_label, rel.predicate, tgt_label)
        by_shape.setdefault(shape, []).append({
            "src": attack_id_of[rel.source_stix_id],
            "tgt": attack_id_of[rel.target_stix_id],
            "stix_relationship_id": rel.stix_relationship_id,
            "description": rel.description,
            "created": rel.created or None,
            "modified": rel.modified or None,
        })

    for (src_label, predicate, tgt_label), rows in by_shape.items():
        client.run_write_batch(
            f"""
            UNWIND $rows AS row
            MATCH (s:{src_label} {{attack_id: row.src}})
            MATCH (t:{tgt_label} {{attack_id: row.tgt}})
            MERGE (s)-[r:{predicate} {{stix_relationship_id: row.stix_relationship_id}}]->(t)
            SET r.evidence_text = row.description,
                r.source = 'mitre_attack_stix',
                r.source_version = $version,
                r.created = datetime(row.created),
                r.modified = datetime(row.modified),
                r.confidence = 1.0
            """,
            rows,
            params={"version": ATTACK_STIX_VERSION},
        )


def _load_chunks(client: Neo4jClient, pb: ParsedBundle) -> int:
    chunks = chunk_all(pb.entities)
    if not chunks:
        return 0
    embedder = get_embedder()
    texts = [c.text for c in chunks]
    vectors = embedder.embed(texts)

    rows = []
    for chunk, vector in zip(chunks, vectors):
        rows.append({
            "chunk_id": chunk.chunk_id,
            "document_id": chunk.document_id,
            "entity_attack_id": chunk.entity_attack_id,
            "entity_name": chunk.entity_name,
            "entity_type": chunk.entity_type.value if chunk.entity_type else None,
            "text": chunk.text,
            "chunk_index": chunk.chunk_index,
            "embedding": vector,
        })

    client.run_write_batch(
        """
        UNWIND $rows AS row
        MERGE (c:Chunk {chunk_id: row.chunk_id})
        SET c.document_id = row.document_id,
            c.entity_attack_id = row.entity_attack_id,
            c.entity_name = row.entity_name,
            c.entity_type = row.entity_type,
            c.text = row.text,
            c.chunk_index = row.chunk_index,
            c.embedding = row.embedding
        WITH c, row
        MATCH (d:Document {document_id: row.document_id})
        MERGE (c)-[:MENTIONED_IN]->(d)
        """,
        rows,
        batch_size=200,
    )

    entity_label_rows: dict[str, list[dict]] = {}
    for chunk in chunks:
        if not chunk.entity_type:
            continue
        label = ENTITY_LABELS.get(chunk.entity_type.value)
        if not label:
            continue
        entity_label_rows.setdefault(label, []).append(
            {"chunk_id": chunk.chunk_id, "attack_id": chunk.entity_attack_id}
        )
    for label, link_rows in entity_label_rows.items():
        client.run_write_batch(
            f"""
            UNWIND $rows AS row
            MATCH (c:Chunk {{chunk_id: row.chunk_id}})
            MATCH (n:{label} {{attack_id: row.attack_id}})
            MERGE (c)-[:DESCRIBES]->(n)
            """,
            link_rows,
        )
    return len(chunks)


def populate(refresh_stix: bool = False) -> dict:
    client = Neo4jClient()
    try:
        if not client.verify_connectivity():
            raise RuntimeError(
                "Cannot connect to Neo4j. Check NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD."
            )
        t0 = time.time()
        init_schema(client)
        pb = load_parsed_bundle(refresh=refresh_stix)
        _load_entities(client, pb)
        _load_document(client, pb)
        _load_relationships(client, pb)
        n_chunks = _load_chunks(client, pb)
        elapsed = time.time() - t0
        counts = client.run(
            "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY label"
        )
        return {
            "entities": len(pb.entities),
            "relationships": len(pb.relationships),
            "chunks": n_chunks,
            "elapsed_seconds": round(elapsed, 1),
            "node_counts": {row["label"]: row["n"] for row in counts},
        }
    finally:
        client.close()


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser()
    p.add_argument("--refresh", action="store_true")
    args = p.parse_args()
    summary = populate(refresh_stix=args.refresh)
    print(json.dumps(summary, indent=2))

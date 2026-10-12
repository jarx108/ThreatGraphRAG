"""Chunk entity descriptions into overlapping text windows for retrieval.

Chunking parameters (see README for documented defaults):
  chunk_size:    750 characters
  chunk_overlap: 100 characters
A character-based splitter is used (not token-based) to avoid a tokenizer
dependency in the ingestion path; this is documented as a limitation in the
evaluation write-up.
"""
from __future__ import annotations

from schemas import ProvenanceRecord, TextChunk

from threatgraph.config import CHUNKING
from threatgraph.ingestion.stix_loader import ParsedEntity


def split_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= chunk_size:
        return [text]
    chunks = []
    start = 0
    step = max(chunk_size - overlap, 1)
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(text):
            break
        start += step
    return chunks


def chunk_entity(parsed_entity: ParsedEntity) -> list[TextChunk]:
    """Build TextChunk records from one entity's description, preserving
    provenance back to the source STIX document and object."""
    pieces = split_text(parsed_entity.description, CHUNKING.chunk_size, CHUNKING.chunk_overlap)
    entity = parsed_entity.entity
    chunks = []
    for i, piece in enumerate(pieces):
        chunks.append(TextChunk(
            chunk_id=f"{entity.attack_id}-chunk-{i}",
            document_id=parsed_entity.provenance.document_id,
            entity_attack_id=entity.attack_id,
            entity_name=entity.name,
            entity_type=entity.entity_type,
            text=piece,
            chunk_index=i,
            provenance=ProvenanceRecord(
                document_id=parsed_entity.provenance.document_id,
                source_type=parsed_entity.provenance.source_type,
                source_url=parsed_entity.provenance.source_url,
                stix_id=parsed_entity.stix_id,
                retrieved_at=parsed_entity.provenance.retrieved_at,
            ),
        ))
    return chunks


def chunk_all(parsed_entities: dict[str, ParsedEntity]) -> list[TextChunk]:
    all_chunks: list[TextChunk] = []
    for pe in parsed_entities.values():
        all_chunks.extend(chunk_entity(pe))
    return all_chunks


if __name__ == "__main__":
    from threatgraph.ingestion.stix_loader import load_parsed_bundle

    pb = load_parsed_bundle()
    chunks = chunk_all(pb.entities)
    print(f"Built {len(chunks)} text chunks from {len(pb.entities)} entities.")
    lengths = [len(c.text) for c in chunks]
    if lengths:
        print(f"  avg length={sum(lengths)/len(lengths):.0f} chars, max={max(lengths)}")

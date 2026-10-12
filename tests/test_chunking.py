from schemas import Entity, EntityType, ProvenanceRecord

from threatgraph.ingestion.chunking import chunk_entity, split_text
from threatgraph.ingestion.stix_loader import ParsedEntity

PROV = ProvenanceRecord(document_id="doc1", source_type="mitre_attack_stix")


def test_split_text_short_text_single_chunk():
    assert split_text("short text", chunk_size=750, overlap=100) == ["short text"]


def test_split_text_empty_returns_no_chunks():
    assert split_text("   ", chunk_size=750, overlap=100) == []


def test_split_text_respects_overlap_and_covers_full_text():
    text = "x" * 2000
    chunks = split_text(text, chunk_size=750, overlap=100)
    assert len(chunks) >= 3
    # last chunk should reach the end of the text
    assert text.endswith(chunks[-1])


def test_chunk_entity_preserves_provenance():
    pe = ParsedEntity(
        entity=Entity(name="APT29", entity_type=EntityType.THREAT_GROUP, attack_id="G0016",
                      aliases=[], confidence_score=1.0),
        description="APT29 is a Russian threat group. " * 50,
        stix_id="intrusion-set--abc",
        provenance=PROV,
    )
    chunks = chunk_entity(pe)
    assert len(chunks) > 1
    for c in chunks:
        assert c.entity_attack_id == "G0016"
        assert c.provenance.stix_id == "intrusion-set--abc"
        assert c.chunk_id.startswith("G0016-chunk-")

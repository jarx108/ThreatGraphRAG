"""Pydantic data model for ThreatGraph's CTI ontology.

This is the single source of truth for entity/relationship vocabulary used
across the LLM extraction prompt (prompts/extraction_prompt.txt), the
extraction validator (scripts/parse_extraction.py), the Neo4j schema
(schema.cypher), and the ingestion/graph-population code
(src/threatgraph/ingestion, src/threatgraph/graph). If you add a new entity
type, relationship predicate, or allowed (subject_type, predicate,
object_type) triple, update all four places together or extraction output
will fail validation / graph loads will be rejected.

Adapted from the course-suggested Pydantic extraction schema pattern, with
entity/relationship types restricted to the MITRE ATT&CK-aligned CTI
ontology this project uses.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class EntityType(str, Enum):
    THREAT_GROUP = "ThreatGroup"
    TECHNIQUE = "Technique"
    SOFTWARE = "Software"
    CAMPAIGN = "Campaign"
    MITIGATION = "Mitigation"
    VULNERABILITY = "Vulnerability"
    DOCUMENT = "Document"


class Predicate(str, Enum):
    USES = "USES"
    MITIGATES = "MITIGATES"
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    EXPLOITS = "EXPLOITS"
    MENTIONED_IN = "MENTIONED_IN"


# Mirrors the "Intended relationship vocabulary" comment block in schema.cypher.
# Used to reject relationships between entity types ATT&CK/our ontology does
# not support, even if the predicate name itself is valid.
ALLOWED_TRIPLES: set[tuple[EntityType, Predicate, EntityType]] = {
    (EntityType.THREAT_GROUP, Predicate.USES, EntityType.TECHNIQUE),
    (EntityType.THREAT_GROUP, Predicate.USES, EntityType.SOFTWARE),
    (EntityType.SOFTWARE, Predicate.USES, EntityType.TECHNIQUE),
    (EntityType.MITIGATION, Predicate.MITIGATES, EntityType.TECHNIQUE),
    (EntityType.CAMPAIGN, Predicate.ATTRIBUTED_TO, EntityType.THREAT_GROUP),
    (EntityType.THREAT_GROUP, Predicate.EXPLOITS, EntityType.VULNERABILITY),
    (EntityType.SOFTWARE, Predicate.EXPLOITS, EntityType.VULNERABILITY),
    (EntityType.THREAT_GROUP, Predicate.MENTIONED_IN, EntityType.DOCUMENT),
    (EntityType.TECHNIQUE, Predicate.MENTIONED_IN, EntityType.DOCUMENT),
    (EntityType.SOFTWARE, Predicate.MENTIONED_IN, EntityType.DOCUMENT),
    (EntityType.CAMPAIGN, Predicate.MENTIONED_IN, EntityType.DOCUMENT),
    (EntityType.MITIGATION, Predicate.MENTIONED_IN, EntityType.DOCUMENT),
    (EntityType.VULNERABILITY, Predicate.MENTIONED_IN, EntityType.DOCUMENT),
}

ATTACK_ID_PREFIX = {
    EntityType.THREAT_GROUP: "G",
    EntityType.TECHNIQUE: "T",
    EntityType.SOFTWARE: "S",
    EntityType.CAMPAIGN: "C",
    EntityType.MITIGATION: "M",
}


MAX_ENTITIES = 25
MAX_RELATIONSHIPS = 25


class Entity(BaseModel):
    """A single extracted CTI entity, as produced by the LLM extraction prompt."""

    name: str = Field(..., min_length=1)
    entity_type: EntityType
    attack_id: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)
    confidence_score: float = Field(..., ge=0.0, le=1.0)

    @field_validator("attack_id")
    @classmethod
    def _validate_attack_id_prefix(cls, v: Optional[str], info) -> Optional[str]:
        if v is None:
            return v
        entity_type = info.data.get("entity_type")
        expected = ATTACK_ID_PREFIX.get(entity_type)
        if expected and not v.upper().startswith(expected):
            raise ValueError(
                f"attack_id {v!r} does not match expected prefix {expected!r} "
                f"for entity_type {entity_type}"
            )
        return v


class Relationship(BaseModel):
    """A single extracted CTI relationship with required supporting evidence."""

    source: str = Field(..., min_length=1, max_length=120)
    predicate: Predicate
    target: str = Field(..., min_length=1, max_length=120)
    evidence_text: str = Field(..., min_length=1, max_length=400)
    confidence_score: float = Field(..., ge=0.0, le=1.0)


class ExtractionResult(BaseModel):
    """Top-level shape returned by the LLM extraction pipeline."""

    # Bounded so schema-constrained decoding (Ollama `format`) cannot loop:
    # a description supports a handful of facts, never hundreds.
    entities: list[Entity] = Field(..., max_length=MAX_ENTITIES)
    relationships: list[Relationship] = Field(..., max_length=MAX_RELATIONSHIPS)

    @model_validator(mode="after")
    def _validate_relationship_references(self) -> "ExtractionResult":
        by_name = {e.name: e for e in self.entities}
        for i, rel in enumerate(self.relationships):
            if rel.source not in by_name:
                raise ValueError(f"relationship[{i}].source {rel.source!r} is not a declared entity")
            if rel.target not in by_name:
                raise ValueError(f"relationship[{i}].target {rel.target!r} is not a declared entity")
            src_type = by_name[rel.source].entity_type
            tgt_type = by_name[rel.target].entity_type
            if (src_type, rel.predicate, tgt_type) not in ALLOWED_TRIPLES:
                raise ValueError(
                    f"relationship[{i}] ({src_type}-{rel.predicate.value}->{tgt_type}) "
                    "is not an allowed triple shape for this ontology"
                )
        return self


class ProvenanceRecord(BaseModel):
    """Source-document metadata attached to every ingested chunk and every
    extracted/ingested relationship, so claims remain traceable."""

    document_id: str
    source_type: str  # "mitre_attack_stix" | "cisa_advisory"
    source_url: Optional[str] = None
    stix_id: Optional[str] = None
    stix_relationship_id: Optional[str] = None
    retrieved_at: Optional[str] = None


class TextChunk(BaseModel):
    """A chunk of natural-language CTI text with its embedding provenance."""

    chunk_id: str
    document_id: str
    entity_attack_id: Optional[str] = None
    entity_name: Optional[str] = None
    entity_type: Optional[EntityType] = None
    text: str = Field(..., min_length=1)
    chunk_index: int = 0
    provenance: ProvenanceRecord


class GoldTriple(BaseModel):
    """One row of data/gold_triples.json, used for extraction evaluation."""

    subject: dict
    predicate: Predicate
    object: dict
    stix_relationship_id: str
    source: str


class MultiHopQuery(BaseModel):
    """One row of data/eval_queries.json, used for RAG system evaluation."""

    id: str
    category: Optional[str] = None
    question: str
    expected_answer: dict
    required_hops: int = Field(..., ge=1)
    graph_path: str
    source: str

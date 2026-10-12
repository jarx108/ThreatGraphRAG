"""LLM-based CTI knowledge extraction pipeline.

Flow: raw text -> prompts/extraction_prompt.txt (filled) -> configured LLM
provider -> scripts.parse_extraction (strict JSON/shape validation) ->
schemas.ExtractionResult (Pydantic: enum + allowed-triple validation) ->
entity resolution against canonical ATT&CK entities (dedupe).

Malformed JSON, unsupported entity types/predicates, out-of-range confidence
scores, or relationships between disallowed entity-type pairs are rejected
(raise ExtractionValidationError / pydantic.ValidationError) rather than
silently coerced. Evidence text is preserved verbatim from the source.

This is for ingesting free-form CTI text (e.g. CISA advisories) where
ground truth isn't already structured, unlike the STIX ingestion path in
threatgraph.ingestion, which parses already-structured MITRE data directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import ValidationError
from schemas import ALLOWED_TRIPLES, Entity, ExtractionResult, Relationship

from threatgraph.config import LLM, REPO_ROOT
from threatgraph.entity_resolution import EntityResolver, ResolutionResult
from threatgraph.rag.llm_provider import LLMProvider, LLMResponse

import sys
sys.path.insert(0, str(REPO_ROOT))
from scripts.parse_extraction import ExtractionValidationError, parse_extraction  # noqa: E402

PROMPT_PATH = REPO_ROOT / "prompts" / "extraction_prompt.txt"


def _bounded_schema() -> dict:
    """The ExtractionResult JSON Schema sent to the LLM, with extra size
    bounds on the entity fields. Schema-constrained decoding (Ollama
    `format`) then cannot loop on an ever-growing alias list or name. The
    bounds live only here because schemas.Entity also validates MITRE's own
    entities, some of which legitimately have more aliases."""
    schema = ExtractionResult.model_json_schema()
    props = schema["$defs"]["Entity"]["properties"]
    props["name"]["maxLength"] = 120
    props["aliases"]["maxItems"] = 10
    props["aliases"]["items"]["maxLength"] = 80
    # Constrained decoding only emits required keys; the validator
    # (scripts/parse_extraction.py) expects every field, with attack_id null
    # when the text gives no ID.
    schema["$defs"]["Entity"]["required"] = ["name", "entity_type", "attack_id", "aliases", "confidence_score"]
    return schema


EXTRACTION_JSON_SCHEMA = _bounded_schema()


@dataclass
class ResolvedExtraction:
    extraction: ExtractionResult
    llm_response: LLMResponse
    resolutions: dict[str, ResolutionResult]  # entity name -> resolution
    rejected: list[dict] = field(default_factory=list)  # per-item rejections, see _validate_leniently


class ExtractionError(Exception):
    pass


def build_prompt(text: str) -> str:
    template = PROMPT_PATH.read_text(encoding="utf-8")
    return template.replace("{{text}}", text)


def _validate_leniently(raw: dict) -> tuple[ExtractionResult, list[dict]]:
    """Validate entities and relationships individually rather than the
    whole batch at once (schemas.ExtractionResult's own model_validator is
    strict/all-or-nothing, appropriate when a caller wants a hard failure on
    any invalid input). One malformed relationship in an LLM response that
    otherwise extracted five good ones should not discard all five -- that
    conflates "did the model get every single fact in this batch right" with
    "how good is the model at extracting individual facts," which is what
    the extraction P/R/F1 metric is actually meant to measure. Each rejected
    entity/relationship is still recorded (not silently dropped) so
    rejection rates remain visible."""
    rejected: list[dict] = []

    entities: list[Entity] = []
    for e in raw.get("entities", []):
        try:
            entities.append(Entity.model_validate(e))
        except ValidationError as exc:
            rejected.append({"kind": "entity", "data": e, "error": str(exc)})

    by_name = {e.name: e for e in entities}
    relationships: list[Relationship] = []
    for r in raw.get("relationships", []):
        try:
            rel = Relationship.model_validate(r)
        except ValidationError as exc:
            rejected.append({"kind": "relationship", "data": r, "error": str(exc)})
            continue
        src, tgt = by_name.get(rel.source), by_name.get(rel.target)
        if src is None or tgt is None:
            rejected.append({"kind": "relationship", "data": r,
                              "error": "references an entity that was not validly declared"})
            continue
        if (src.entity_type, rel.predicate, tgt.entity_type) not in ALLOWED_TRIPLES:
            rejected.append({"kind": "relationship", "data": r,
                              "error": f"disallowed triple shape: "
                                       f"{src.entity_type}-{rel.predicate.value}->{tgt.entity_type}"})
            continue
        relationships.append(rel)

    return ExtractionResult(entities=entities, relationships=relationships), rejected


def extract(text: str, provider: LLMProvider | None = None,
            resolver: EntityResolver | None = None) -> ResolvedExtraction:
    """Run one document/chunk through the extraction pipeline."""
    provider = provider or LLMProvider()
    prompt = build_prompt(text)
    # The prompt's own system framing is embedded in the template; no
    # separate system message is needed beyond a thin instruction wrapper.
    # Schema enforcement happens twice: the Pydantic model's JSON Schema is
    # sent to the LLM (Ollama constrains decoding to it), and the output is
    # validated again below, so a non-conforming provider still can't sneak
    # malformed facts into the graph.
    def call(max_tokens: int) -> LLMResponse:
        return provider.complete(
            system="You are a precise, schema-constrained information extraction system.",
            user=prompt, max_tokens=max_tokens, json_schema=EXTRACTION_JSON_SCHEMA,
        )

    response = call(LLM.max_tokens)
    if response.output_tokens >= LLM.max_tokens:
        # Hit the output limit, so the JSON is cut off: retry once with room
        # for the largest output the bounded schema allows.
        response = call(LLM.max_tokens * 3)

    try:
        # Per-relationship reference checks happen in _validate_leniently.
        raw = parse_extraction(response.text, check_references=False)
    except ExtractionValidationError as exc:
        raise ExtractionError(f"LLM output failed shape validation: {exc}") from exc

    result, rejected = _validate_leniently(raw)

    resolutions: dict[str, ResolutionResult] = {}
    if resolver is not None:
        for entity in result.entities:
            resolutions[entity.name] = resolver.resolve(
                entity.name, entity.entity_type, entity.attack_id
            )

    return ResolvedExtraction(extraction=result, llm_response=response,
                               resolutions=resolutions, rejected=rejected)

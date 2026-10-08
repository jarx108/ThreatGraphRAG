"""Validate structured output from the ThreatGraph LLM extractor."""
import json
from typing import Any

ENTITY_TYPES = {
    "ThreatGroup", "Technique", "Software", "Campaign",
    "Mitigation", "Vulnerability", "Document"
}
PREDICATES = {"USES", "MITIGATES", "ATTRIBUTED_TO", "EXPLOITS", "MENTIONED_IN"}

class ExtractionValidationError(ValueError):
    pass

def _confidence(value: Any, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ExtractionValidationError(f"{field} must be numeric")
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ExtractionValidationError(f"{field} must be in [0, 1]")
    return value

def parse_extraction(raw: str) -> dict:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExtractionValidationError(f"Malformed JSON: {exc}") from exc

    if set(obj) != {"entities", "relationships"}:
        raise ExtractionValidationError("Top-level keys must be entities and relationships")
    if not isinstance(obj["entities"], list) or not isinstance(obj["relationships"], list):
        raise ExtractionValidationError("entities and relationships must be arrays")

    names = set()
    for i, entity in enumerate(obj["entities"]):
        required = {"name", "entity_type", "attack_id", "aliases", "confidence_score"}
        if set(entity) != required:
            raise ExtractionValidationError(f"Entity {i} has incorrect fields")
        if not isinstance(entity["name"], str) or not entity["name"].strip():
            raise ExtractionValidationError(f"Entity {i} requires a name")
        if entity["entity_type"] not in ENTITY_TYPES:
            raise ExtractionValidationError(f"Entity {i} has unsupported entity_type")
        if entity["attack_id"] is not None and not isinstance(entity["attack_id"], str):
            raise ExtractionValidationError(f"Entity {i} attack_id must be string or null")
        if not isinstance(entity["aliases"], list) or not all(isinstance(x, str) for x in entity["aliases"]):
            raise ExtractionValidationError(f"Entity {i} aliases must be a string array")
        entity["confidence_score"] = _confidence(entity["confidence_score"], f"entity {i} confidence")
        names.add(entity["name"])

    for i, rel in enumerate(obj["relationships"]):
        required = {"source", "predicate", "target", "evidence_text", "confidence_score"}
        if set(rel) != required:
            raise ExtractionValidationError(f"Relationship {i} has incorrect fields")
        if rel["predicate"] not in PREDICATES:
            raise ExtractionValidationError(f"Relationship {i} has unsupported predicate")
        if rel["source"] not in names or rel["target"] not in names:
            raise ExtractionValidationError(f"Relationship {i} references an undeclared entity")
        if not isinstance(rel["evidence_text"], str) or not rel["evidence_text"].strip():
            raise ExtractionValidationError(f"Relationship {i} requires evidence_text")
        rel["confidence_score"] = _confidence(rel["confidence_score"], f"relationship {i} confidence")

    return obj

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("json_file")
    args = p.parse_args()
    with open(args.json_file, encoding="utf-8") as f:
        parsed = parse_extraction(f.read())
    print(f"Valid extraction: {len(parsed['entities'])} entities, "
          f"{len(parsed['relationships'])} relationships")
